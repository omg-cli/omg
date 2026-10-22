import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { spawnSync } from "node:child_process";
import { lstat, mkdir, readFile, realpath, writeFile, chmod, chown, open } from "node:fs/promises";
import path from "node:path";
import { Schema } from "effect";
import { preparePortable, runPortable } from "./runner/portable-process.mjs";
import {
    discoverRustTestArtifact,
    parseRustCatalog,
    parseRustExecution,
    rustProfile,
    rustReport,
} from "./runner/rust-evidence.mjs";
import { assertRustSourceChange } from "../../scripts/rust-source-policy.mjs";
import { freezeRustInputs } from "./runner/frozen-rust-inputs.mjs";

const text = (max) => Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(max));
const sha40 = Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/));
const sha64 = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/));

const positive = Schema.Number.check(
    Schema.makeFilter(Number.isSafeInteger),
    Schema.isGreaterThan(0),
);

const sourcePath = text(240).check(
    Schema.isPattern(/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/),
);

const testPath = text(240).check(
    Schema.isPattern(/^tests\/ai-review-[a-f0-9]{16}-[a-f0-9]{12}\.rs$/),
);

const identity = {
    repository: Schema.Literal("omg-cli/omg"),
    branch: Schema.Literal("main"),
    baseSha: sha40,
};

const proposalSchema = Schema.Struct({
    ...identity,
    finding: Schema.Struct({
        key: sha64,
        title: text(160),
        summary: text(4000),
        path: text(240),
        line: positive,
        sourceQuote: text(4000),
        reproduction: text(4000),
    }),
    changes: Schema.Array(
        Schema.Struct({
            path: Schema.Union([sourcePath, testPath]),
            originalBlobSha: Schema.NullOr(sha40),
            oldContentQuote: Schema.String.check(Schema.isMaxLength(4000)),
            newContent: text(64000),
            sha256: sha64,
        }),
    ).check(Schema.isMinLength(2), Schema.isMaxLength(8)),
});

const contextSchema = Schema.Struct({
    ...identity,
    verifierRevision: sha40,
    runId: positive,
    runAttempt: positive,
    workspace: text(1000),
    gitDirectory: text(1000),
    reportDirectory: text(1000),
    regression: Schema.Struct({
        path: testPath,
        testName: text(200).check(Schema.isPattern(/^[A-Za-z_][A-Za-z0-9_]*$/)),
    }),
});

const parse = (schema, value) =>
    Schema.decodeUnknownSync(schema, { onExcessProperty: "error" })(value);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

const blobSha = (value) =>
    createHash("sha1")
        .update(`blob ${Buffer.byteLength(value)}\0`)
        .update(value)
        .digest("hex");

const canonical = (value) =>
    JSON.stringify(value, (_, item) =>
        Schema.is(Schema.Record(Schema.String, Schema.Unknown))(item)
            ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)))
            : item,
    );

export function git(directory, args) {
    const result = spawnSync(
        "git",
        ["-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", directory, ...args],
        {
            encoding: "utf8",
            timeout: 30000,
            maxBuffer: 4 * 1024 * 1024,
            windowsHide: true,
        },
    );

    if (result.status !== 0 || result.error) throw new Error("Trusted source Git query failed.");

    return result.stdout;
}

export async function confinedFile(workspace, relative) {
    const resolved = path.resolve(workspace, relative);

    if (!resolved.startsWith(`${workspace}${path.sep}`))
        throw new Error("Patch path escaped workspace.");
    const components = path.relative(workspace, path.dirname(resolved)).split(path.sep);
    let current = workspace;

    for (const component of components) {
        current = path.join(current, component);
        const info = await lstat(current);

        if (!info.isDirectory() || info.isSymbolicLink())
            throw new Error("Patch parent is not a real workspace directory.");
    }

    return resolved;
}

export async function executeRustRegression({
    workspace,
    file,
    testName,
    home,
    reportFile,
    trackedPaths,
    existingTest = false,
    target = "",
}) {
    const context = preparePortable(workspace, trackedPaths, { home });
    const phase = path.basename(reportFile, ".json");
    const args = [
        "test",
        ...(existingTest && target === "lib" ? ["--lib"] : ["--test", file.split("/").at(-1).slice(0, -3)]),
        "--no-run",
        "--message-format=json",
        "--no-default-features",
        "--features",
        rustProfile.features,
        "--locked",
        "--offline",
    ];
    const compiler = await runPortable(
        context,
        "cargo",
        args,
        {},
        {
            maxOutput: 32 * 1024 * 1024,
            timeoutMs: 900000,
            label: `${phase}:compile`,
        },
    );
    const artifact = discoverRustTestArtifact(compiler.stdout, file, { existingTest, target });
    await confinedFile(workspace, path.relative(workspace, artifact.executable));
    const info = await lstat(artifact.executable);
    if (!info.isFile() || info.isSymbolicLink())
        throw new Error("Cargo executable is not a regular owned artifact");
    const executableSha256 = sha256(await readFile(artifact.executable));
    const frozenInputs = await freezeRustInputs(workspace);
    const listing = await runPortable(
        context,
        artifact.executable,
        ["--list", "--format", "terse"],
        {},
        { label: `${phase}:catalog` },
    );
    const catalog = parseRustCatalog(listing.stdout, testName, { existingTest });
    await frozenInputs.assertUnchanged();
    const execution = await runPortable(
        context,
        artifact.executable,
        [testName, "--exact", "--nocapture", "--test-threads=1"],
        {},
        {
            timeoutMs: 30000,
            maxOutput: 1024 * 1024,
            allowedExitCodes: [0, 101],
            label: `${phase}:execute`,
        },
    );
    if (sha256(await readFile(artifact.executable)) !== executableSha256)
        throw new Error("Executed Rust artifact changed");
    await frozenInputs.assertUnchanged();
    const source = await readFile(path.join(workspace, file), "utf8");
    const parsed = parseRustExecution({ ...execution, testName, file, source, catalog });
    const recipe = {
        args,
        profile: rustProfile,
        rustc: spawnSync("rustc", ["-vV"], { encoding: "utf8" }).stdout,
        cargo: spawnSync("cargo", ["--version"], { encoding: "utf8" }).stdout,
    };
    if (!recipe.rustc.includes("release: 1.95.0") || !recipe.cargo.startsWith("cargo 1.95.0"))
        throw new Error("Unexpected Rust compiler recipe");
    const result = {
        ...parsed,
        executableSha256,
        compilerMessagesSha256: artifact.compilerMessagesSha256,
        sourceSha256: sha256(source),
        recipeSha256: sha256(canonical(recipe)),
    };
    const report = rustReport(result, { artifact, recipe, catalog, listing, compiler, execution });
    await writeFile(reportFile, report.content, { flag: "wx", mode: 0o600 });
    return report.result;
}

export async function verifyRegression({ proposal: rawProposal, context: rawContext }) {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error(
            "Regression verification requires the disposable Linux container controller.",
        );
    const proposal = parse(proposalSchema, rawProposal);
    const context = parse(contextSchema, rawContext);

    for (const field of ["repository", "branch", "baseSha"])
        if (proposal[field] !== context[field]) throw new Error("Verifier identity mismatch.");
    const workspace = await realpath(context.workspace);
    const gitDirectory = await realpath(context.gitDirectory);
    const reportDirectory = path.resolve(context.reportDirectory);

    if (
        gitDirectory.startsWith(`${workspace}${path.sep}`) ||
        reportDirectory.startsWith(`${workspace}${path.sep}`)
    )
        throw new Error("Trusted source and reports must be outside candidate workspace.");

    if (git(gitDirectory, ["rev-parse", "HEAD"]).trim() !== context.baseSha)
        throw new Error("Actual source HEAD differs from requested base.");
    const sourceInfo = await lstat(gitDirectory);

    if (sourceInfo.uid !== 0 || (sourceInfo.mode & 0o022) !== 0)
        throw new Error(
            "Trusted source directory must be root-owned and immutable to candidate user.",
        );
    await mkdir(reportDirectory, { recursive: true, mode: 0o700 });
    await chmod(reportDirectory, 0o700);
    const testChanges = proposal.changes.filter((change) => change.path.startsWith("tests/"));

    if (
        testChanges.length !== 1 ||
        testChanges[0].originalBlobSha !== null ||
        testChanges[0].path !== context.regression.path ||
        context.regression.path !==
            `tests/ai-review-${proposal.finding.key.slice(0, 16)}-${proposal.baseSha.slice(0, 12)}.rs`
    )
        throw new Error("Exactly one designated new regression is required.");

    const tracked = git(gitDirectory, ["ls-tree", "-r", "-z", context.baseSha])
        .split("\0")
        .filter(Boolean)
        .map((entry) => {
            const [metadata, file] = entry.split("\t");
            const [mode, type, sha] = metadata.split(" ");

            return { mode, type, sha, path: file };
        });

    await chown(workspace, 0, 0);
    await chmod(workspace, 0o755);

    for (const entry of tracked) {
        const file = await confinedFile(workspace, entry.path);
        const info = await lstat(file);

        if (!info.isFile() || info.isSymbolicLink())
            throw new Error("Tracked files must be regular workspace files.");
        await chown(file, 0, 0);
        await chmod(file, entry.mode === "100755" ? 0o555 : 0o444);
        let parent = path.dirname(file);

        while (parent !== workspace) {
            await chown(parent, 0, 0);
            await chmod(parent, 0o755);
            parent = path.dirname(parent);
        }
    }

    const verifyTracked = async (expectedChanges) => {
        for (const entry of tracked) {
            if (entry.type !== "blob") continue;
            const file = await confinedFile(workspace, entry.path);
            const info = await lstat(file);

            if (!info.isFile() || info.isSymbolicLink())
                throw new Error("Workspace tracked source is not a regular file.");
            const content = await readFile(file);
            const change = expectedChanges.get(entry.path);

            if (change ? sha256(content) !== change.sha256 : blobSha(content) !== entry.sha)
                throw new Error("Workspace changed outside the declared patch.");
        }
    };

    await verifyTracked(new Map());
    const paths = new Set();

    for (const change of proposal.changes) {
        if (
            paths.has(change.path) ||
            sha256(change.newContent) !== change.sha256 ||
            change.newContent.includes("\0")
        )
            throw new Error("Invalid patch content identity.");
        paths.add(change.path);
        const entry = tracked.find((item) => item.path === change.path);

        if (change.path.startsWith("tests/")) {
            if (entry) throw new Error("Regression test already exists.");
        } else if (
            !entry ||
            entry.mode !== "100644" ||
            entry.sha !== change.originalBlobSha ||
            !git(gitDirectory, ["show", `${context.baseSha}:${change.path}`]).includes(
                change.oldContentQuote,
            ) ||
            !change.oldContentQuote
        )
            throw new Error("Patch original source identity mismatch.");
    }

    for (const change of proposal.changes.filter((item) => !item.path.startsWith("tests/")))
        assertRustSourceChange(
            change.path,
            git(gitDirectory, ["show", `${context.baseSha}:${change.path}`]),
            change.newContent,
        );
    const testFile = await confinedFile(workspace, context.regression.path);
    await writeFile(testFile, testChanges[0].newContent, { flag: "wx", mode: 0o644 });

    const run = async (phase) => {
        const home = `/tmp/omg-review-${randomUUID()}`;
        await mkdir(home, { mode: 0o700 });
        await chown(home, 10001, 10001);

        return executeRustRegression({
            workspace,
            file: context.regression.path,
            testName: context.regression.testName,
            home,
            reportFile: path.join(reportDirectory, `${phase}.json`),
            trackedPaths: [...tracked.map((entry) => entry.path), context.regression.path, ".git"],
        });
    };

    const baseline = await run("baseline");

    if (baseline.exitCode === 0) throw new Error("Regression already passes on the base.");
    await verifyTracked(new Map());

    if (sha256(await readFile(testFile)) !== testChanges[0].sha256)
        throw new Error("Baseline changed its regression source.");

    for (const change of proposal.changes.filter((change) => !change.path.startsWith("tests/"))) {
        const file = await confinedFile(workspace, change.path);
        const handle = await open(
            file,
            constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW,
        );

        try {
            await handle.writeFile(change.newContent);
        } finally {
            await handle.close();
        }
    }

    const patched = await run("patched");

    if (patched.exitCode !== 0 || patched.failures !== 0)
        throw new Error("Patched regression does not pass.");
    await verifyTracked(new Map(proposal.changes.map((change) => [change.path, change])));

    if (sha256(await readFile(testFile)) !== testChanges[0].sha256)
        throw new Error("Patched execution changed its regression source.");

    return {
        repository: context.repository,
        branch: context.branch,
        baseSha: context.baseSha,
        proposalSha256: sha256(canonical(proposal)),
        verifierRevision: context.verifierRevision,
        runId: context.runId,
        runAttempt: context.runAttempt,
        baseline,
        patched,
        protectedPathsUnchanged: true,
        changedPaths: [...paths].sort((first, second) => first.localeCompare(second)),
        fileHashes: proposal.changes.map((change) => ({
            path: change.path,
            sha256: change.sha256,
        })),
    };
}

async function main() {
    if (process.env.OMG_CI_VERIFIER_SANDBOX !== "1")
        throw new Error("Verifier is available only in its disposable sandbox.");
    const files = process.argv.slice(2);

    if (files.length !== 3)
        throw new Error("Usage: verifier.mjs proposal.json trusted-context.json receipt.json");

    const readDocument = async (file) => {
        if ((await lstat(file)).size > 256 * 1024)
            throw new Error("Verifier input exceeds its byte budget.");

        return JSON.parse(await readFile(file, "utf8"));
    };

    const proposal = await readDocument(files[0]);
    const context = parse(contextSchema, await readDocument(files[1]));

    if (
        context.workspace !== "/workspace" ||
        context.gitDirectory !== "/tmp/ci-source" ||
        !path.resolve(context.reportDirectory).startsWith("/tmp/ci-review-reports/")
    )
        throw new Error("Verifier context does not use fixed sandbox roots.");
    const result = await verifyRegression({ proposal, context });
    await writeFile(files[2], JSON.stringify(result), { flag: "wx", mode: 0o600 });
}

if (import.meta.main) await main();

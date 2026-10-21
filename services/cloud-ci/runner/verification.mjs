import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, readFile, mkdir, open, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { Schema } from "effect";
import { assertRustSourceChange } from "../../../scripts/rust-source-policy.mjs";
import { testAuditPhasesFor } from "./test-audit.mjs";
import { decodeVerificationEnvironment } from "./verification-envelope.mjs";

const hash = (content) => createHash("sha256").update(content).digest("hex");

const blob = (content) =>
    createHash("sha1")
        .update(`blob ${Buffer.byteLength(content)}\0`)
        .update(content)
        .digest("hex");

const sourcePath = /^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/;

const regressionPath = /^tests\/ai-review-[a-f0-9]{16}-[a-f0-9]{12}\.rs$/;

function git(directory, args) {
    const result = spawnSync(
        "git",
        ["-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", directory, ...args],
        {
            encoding: "utf8",
            maxBuffer: 16 * 1024 * 1024,
        },
    );

    if (result.status !== 0) throw new Error("Cannot inspect trusted Git source");

    return result.stdout;
}

async function confined(workspace, relative) {
    const segments = relative.split("/");

    if (segments.some((part) => !part || part === "." || part === ".."))
        throw new Error("Unsafe patch path");
    let current = path.resolve(workspace);
    const root = await lstat(current);

    if (!root.isDirectory() || root.isSymbolicLink()) throw new Error("Unsafe workspace root");

    for (const segment of segments.slice(0, -1)) {
        current = path.join(current, segment);
        const info = await lstat(current);

        if (!info.isDirectory() || info.isSymbolicLink())
            throw new Error("Patch parent is not a regular directory");
    }

    return path.join(current, segments.at(-1));
}

export async function applyValidatedProposal(proposal, context) {
    if (
        !/^[a-f0-9]{40}$/.test(context.baseSha) ||
        !/^[a-f0-9]{64}$/.test(proposal.finding.key) ||
        proposal.repository !== "omg-cli/omg" ||
        context.branch !== "main" ||
        proposal.repository !== context.repository ||
        proposal.branch !== context.branch ||
        proposal.baseSha !== context.baseSha ||
        git(context.gitDirectory, ["rev-parse", "HEAD"]).trim() !== context.baseSha
    )
        throw new Error("Patch source identity mismatch");
    const expectedTest = `tests/ai-review-${proposal.finding.key.slice(0, 16)}-${context.baseSha.slice(0, 12)}.rs`;

    if (
        context.regression.path !== expectedTest ||
        !Array.isArray(proposal.changes) ||
        proposal.changes.length < 2 ||
        proposal.changes.length > 8
    )
        throw new Error("Designated regression is missing");

    const tracked = new Map(
        git(context.gitDirectory, ["ls-tree", "-r", "-z", context.baseSha])
            .split("\0")
            .filter(Boolean)
            .map((entry) => {
                const [metadata, filename] = entry.split("\t");
                const [mode, type, sha] = metadata.split(" ");

                return [filename, { mode, type, sha }];
            }),
    );

    const seen = new Set();
    const files = [];
    let tests = 0;

    for (const change of proposal.changes) {
        if (
            (!sourcePath.test(change.path) && !regressionPath.test(change.path)) ||
            seen.has(change.path) ||
            !Schema.is(Schema.String)(change.newContent) ||
            !change.newContent ||
            change.newContent.length > 64000 ||
            change.newContent.includes("\0") ||
            hash(change.newContent) !== change.sha256
        )
            throw new Error("Invalid declared patch bytes");
        seen.add(change.path);
        const file = await confined(context.workspace, change.path);
        const original = tracked.get(change.path);

        if (change.path.startsWith("tests/")) {
            tests++;

            if (change.path !== expectedTest || change.originalBlobSha !== null || original)
                throw new Error("Invalid new regression source");

            try {
                await lstat(file);
                throw new Error("Regression path already exists");
            } catch (error) {
                if (error.code !== "ENOENT") throw error;
            }
        } else {
            const info = await lstat(file);

            if (
                !original ||
                original.mode !== "100644" ||
                original.type !== "blob" ||
                original.sha !== change.originalBlobSha ||
                !info.isFile() ||
                info.isSymbolicLink() ||
                blob(await readFile(file)) !== original.sha ||
                !Schema.is(Schema.String)(change.oldContentQuote) ||
                !change.oldContentQuote ||
                !git(context.gitDirectory, ["show", `${context.baseSha}:${change.path}`]).includes(
                    change.oldContentQuote,
                )
            )
                throw new Error("Patch original blob mismatch");
        }

        if (original)
            assertRustSourceChange(change.path, await readFile(file, "utf8"), change.newContent);
        files.push({ file, change });
    }

    if (tests !== 1) throw new Error("Exactly one regression file is required");

    for (const { file, change } of files) {
        const flags =
            constants.O_WRONLY |
            (process.platform === "linux" ? constants.O_NOFOLLOW : 0) |
            (change.originalBlobSha === null
                ? constants.O_CREAT | constants.O_EXCL
                : constants.O_TRUNC);

        const handle = await open(
            file,
            process.platform === "linux" ? flags : change.originalBlobSha === null ? "wx" : "w",
            0o644,
        );

        try {
            await handle.writeFile(change.newContent);
        } finally {
            await handle.close();
        }
    }

    return {
        changedPaths: [...seen].sort((left, right) => left.localeCompare(right)),
        fileHashes: proposal.changes.map(({ path: filename, sha256 }) => ({
            path: filename,
            sha256,
        })),
    };
}

export function verificationRequest() {
    const request = decodeVerificationEnvironment(process.env);
    if (!request) return null;

    if (
        (!request.verification && !request.testAudit) ||
        (request.verification && request.testAudit) ||
        request.sha !== process.env.OMG_EXPECTED_SHA ||
        !Number.isSafeInteger(Number(request.runId)) ||
        Number(request.runId) <= 0 ||
        !Number.isSafeInteger(Number(request.attempt)) ||
        Number(request.attempt) <= 0
    )
        throw new Error("Invalid trusted verification payload");

    return request;
}

export function verificationContext(request) {
    return {
        repository: request.repository,
        branch: request.ref.slice(11),
        baseSha: request.sha,
        verifierRevision: (request.testAudit ?? request.verification).verifierRevision,
        runId: Number(request.runId),
        runAttempt: Number(request.attempt),
        workspace: "/workspace",
        gitDirectory: "/tmp/ci-source",
        reportDirectory: `/tmp/ci-review-reports/${randomUUID()}`,
        ...(request.verification ? { regression: request.verification.regression } : {}),
    };
}

export async function runRegression(request) {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error("Verifier requires root controller in disposable Linux sandbox");
    const directory = `/tmp/ci-review-inputs-${randomUUID()}`;
    await mkdir(directory, { mode: 0o700 });
    const proposalFile = path.join(directory, "proposal.json");
    const contextFile = path.join(directory, "context.json");
    const receiptFile = path.join(directory, "receipt.json");
    await writeFile(proposalFile, JSON.stringify((request.testAudit ?? request.verification).proposal), {
        flag: "wx",
        mode: 0o600,
    });
    const context = verificationContext(request);
    await writeFile(contextFile, JSON.stringify(context), { flag: "wx", mode: 0o600 });

    const result = spawnSync(
        process.execPath,
        [request.testAudit ? "/opt/omg-ci/runner/audit-verifier.mjs" : "/opt/omg-ci/verifier.mjs", proposalFile, contextFile, receiptFile],
        {
            env: { ...process.env, OMG_CI_VERIFIER_SANDBOX: "1" },
            stdio: "inherit",
            timeout: request.testAudit ? 3_800_000 : 1_900_000,
        },
    );

    if (result.error) throw result.error;

    if (result.status !== 0) throw new Error(`Regression verifier exited ${result.status}`);
    const receipt = await readFile(receiptFile, "utf8");

    if (Buffer.byteLength(receipt) > 65536)
        throw new Error("Verifier receipt exceeds its byte budget");

    for (const phase of request.testAudit ? testAuditPhasesFor(request.testAudit.proposal) : ["baseline", "patched"])
        console.log(
            `OMG_REPORT=${JSON.stringify({ name: `${request.testAudit ? "test-audit" : "regression"}-${phase}.json`, content: await readFile(path.join(context.reportDirectory, `${phase}.json`), "utf8") })}`,
        );
    console.log(`${request.testAudit ? "OMG_TEST_AUDIT" : "OMG_VERIFICATION"}=${JSON.stringify(JSON.parse(receipt))}`);
}

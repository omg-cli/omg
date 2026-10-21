import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, readFile, writeFile, mkdir, chmod, chown, realpath, open } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertRustSourceChange } from "../../../scripts/rust-source-policy.mjs";
import { auditHash, validateTestAuditProposal, runTestAuditStates, testAuditPhaseSource } from "./test-audit.mjs";

const verifierRelative = path.basename(path.dirname(fileURLToPath(import.meta.url))) === "runner" ? "../verifier.mjs" : "./verifier.mjs";
const { executeRustRegression, git, confinedFile } = await import(new URL(verifierRelative, import.meta.url).href);

const canonical = (value) => JSON.stringify(value, (_, item) => item && typeof item === "object" && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
const blob = (value) => createHash("sha1").update(`blob ${Buffer.byteLength(value)}\0`).update(value).digest("hex");

export async function inspectAuditSource(proposal, context) {
    validateTestAuditProposal(proposal);
    if (context.repository !== proposal.repository || context.branch !== proposal.branch || context.baseSha !== proposal.baseSha ||
        !/^[a-f0-9]{40}$/.test(context.verifierRevision) || !Number.isSafeInteger(context.runId) || context.runId <= 0 ||
        !Number.isSafeInteger(context.runAttempt) || context.runAttempt <= 0 ||
        git(context.gitDirectory, ["rev-parse", "HEAD"]).trim() !== proposal.baseSha)
        throw new Error("Existing-test audit source identity mismatch");
    const tracked = git(context.gitDirectory, ["ls-tree", "-r", "-z", proposal.baseSha]).split("\0").filter(Boolean).map((row) => {
        const [metadata, file] = row.split("\t");
        const [mode, type, sha] = metadata.split(" ");
        return { path: file, mode, type, sha };
    });
    for (const file of [proposal.test, proposal.fault]) {
        const entry = tracked.find((row) => row.path === file.path);
        if (!entry || entry.mode !== "100644" || entry.type !== "blob" || entry.sha !== file.originalBlobSha)
            throw new Error("Audit test or fault original Git blob mismatch");
    }
    const originalTest = git(context.gitDirectory, ["show", `${proposal.baseSha}:${proposal.test.path}`]);
    const originalFault = git(context.gitDirectory, ["show", `${proposal.baseSha}:${proposal.fault.path}`]);
    if (originalTest !== proposal.test.originalContent || !originalFault.includes(proposal.fault.oldContentQuote) ||
        originalFault === proposal.fault.newContent)
        throw new Error("Audit original source bytes or fault anchor mismatch");
    assertRustSourceChange(proposal.fault.path, originalFault, proposal.fault.newContent);
    if (proposal.test.path === proposal.fault.path &&
        (proposal.test.target !== "lib" || originalFault.split("\n").length !== proposal.fault.newContent.split("\n").length))
        throw new Error("Same-file fault must preserve test line positions and use the library target");
    return { tracked, originalFault };
}

export async function applyTestAudit(proposal, context) {
    const { tracked } = await inspectAuditSource(proposal, context);
    for (const entry of tracked) {
        if (entry.type !== "blob") throw new Error("Audit source must contain only regular tracked files");
        const file = await confinedFile(context.workspace, entry.path);
        const info = await lstat(file);
        if (!info.isFile() || info.isSymbolicLink() || blob(await readFile(file)) !== entry.sha)
            throw new Error("Audit source workspace differs from immutable base");
    }
    const file = await confinedFile(context.workspace, proposal.test.path);
    const handle = await open(file, process.platform === "linux" ? constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW : "w");
    try { await handle.writeFile(proposal.test.newContent); }
    finally { await handle.close(); }
}

export async function verifyTestAudit({ proposal, context }) {
    if (process.platform !== "linux" || process.getuid() !== 0)
        throw new Error("Existing-test audit requires disposable Linux root controller");
    const workspace = await realpath(context.workspace);
    const gitDirectory = await realpath(context.gitDirectory);
    const reportDirectory = path.resolve(context.reportDirectory);
    if (gitDirectory.startsWith(`${workspace}${path.sep}`) || reportDirectory.startsWith(`${workspace}${path.sep}`))
        throw new Error("Trusted audit source and reports must be outside candidate workspace");
    const sourceInfo = await lstat(gitDirectory);
    if (sourceInfo.uid !== 0 || (sourceInfo.mode & 0o022) !== 0)
        throw new Error("Trusted audit source must be immutable to candidate user");
    const { tracked, originalFault } = await inspectAuditSource(proposal, { ...context, workspace, gitDirectory });
    await mkdir(reportDirectory, { recursive: true, mode: 0o700 });
    await chmod(reportDirectory, 0o700);
    await chown(workspace, 0, 0);
    await chmod(workspace, 0o755);
    for (const entry of tracked) {
        if (entry.type !== "blob") throw new Error("Audit tracked source must be regular files");
        const file = await confinedFile(workspace, entry.path);
        const info = await lstat(file);
        if (!info.isFile() || info.isSymbolicLink()) throw new Error("Unsafe tracked audit source");
        await chown(file, 0, 0);
        await chmod(file, entry.mode === "100755" ? 0o555 : 0o444);
        let parent = path.dirname(file);
        while (parent !== workspace) { await chown(parent, 0, 0); await chmod(parent, 0o755); parent = path.dirname(parent); }
    }
    const write = async (relative, content) => {
        const handle = await open(await confinedFile(workspace, relative), constants.O_WRONLY | constants.O_TRUNC | constants.O_NOFOLLOW);
        try { await handle.writeFile(content); }
        finally { await handle.close(); }
    };
    const verify = async (phase) => {
        for (const entry of tracked) {
            const file = await confinedFile(workspace, entry.path);
            const info = await lstat(file);
            const expected = entry.path === proposal.test.path
                ? blob(testAuditPhaseSource(proposal, phase))
                : entry.path === proposal.fault.path && phase.endsWith("Fault")
                    ? blob(proposal.fault.newContent) : entry.sha;
            if (!info.isFile() || info.isSymbolicLink() || blob(await readFile(file)) !== expected)
                throw new Error("Audit execution changed protected source or comparison bytes");
        }
    };
    await verify("oldIntact");
    const states = await runTestAuditStates(proposal, {
        writeTest: (content) => write(proposal.test.path, content),
        writeFault: (active, phase) => write(proposal.fault.path, proposal.test.path === proposal.fault.path
            ? testAuditPhaseSource(proposal, phase ?? "strongerIntact") : active ? proposal.fault.newContent : originalFault),
        verify,
        run: async (phase) => {
            const home = `/tmp/omg-test-audit-${randomUUID()}`;
            await mkdir(home, { mode: 0o700 }); await chown(home, 10001, 10001);
            return executeRustRegression({ workspace, file: proposal.test.path, testName: proposal.test.testName,
                home, reportFile: path.join(reportDirectory, `${phase}.json`),
                trackedPaths: [...tracked.map((entry) => entry.path), ".git"], existingTest: true, target: proposal.test.target });
        },
    });
    await verify("strongerIntact");
    return { purpose: proposal.purpose, repository: proposal.repository, branch: proposal.branch, baseSha: proposal.baseSha,
        proposalSha256: auditHash(canonical(proposal)), verifierRevision: context.verifierRevision,
        runId: context.runId, runAttempt: context.runAttempt, ...states, protectedPathsUnchanged: true, faultRestored: true,
        changedPaths: proposal.purpose === "existing-test-sensitivity" ? [] : [proposal.test.path],
        fileHashes: proposal.purpose === "existing-test-sensitivity" ? [] : [{ path: proposal.test.path, sha256: proposal.test.sha256 }] };
}

if (import.meta.main) {
    if (process.env.OMG_CI_VERIFIER_SANDBOX !== "1" || process.argv.length !== 5)
        throw new Error("Audit verifier requires trusted sandbox invocation");
    const read = async (file) => {
        if ((await lstat(file)).size > 1024 * 1024) throw new Error("Audit input exceeds byte budget");
        return JSON.parse(await readFile(file, "utf8"));
    };
    const proposal = await read(process.argv[2]);
    const context = await read(process.argv[3]);
    if (context.workspace !== "/workspace" || context.gitDirectory !== "/tmp/ci-source" ||
        !path.resolve(context.reportDirectory).startsWith("/tmp/ci-review-reports/"))
        throw new Error("Audit verifier requires fixed sandbox roots");
    await writeFile(process.argv[4], JSON.stringify(await verifyTestAudit({ proposal, context })), { flag: "wx", mode: 0o600 });
}

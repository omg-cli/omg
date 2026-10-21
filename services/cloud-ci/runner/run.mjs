import { parseStringPromise } from "xml2js";
import { summarizeUnitFailures } from "./unit-report.mjs";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, writeFileSync, lstatSync } from "node:fs";
import { pruneRestoredSource } from "./source-tree.mjs";
import { runServiceCheck, rustProfiles, rustTimeouts, toolchain } from "./plan.mjs";
import { preparePortable, runPortable } from "./portable-process.mjs";
import { applyTestAudit } from "./audit-verifier.mjs";
import {
    applyValidatedProposal,
    verificationContext,
    verificationRequest,
    runRegression,
} from "./verification.mjs";
const query = (args) => {
    const result = spawnSync(
        "git",
        ["-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", "/tmp/ci-source", ...args],
        { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
    );
    if (result.status !== 0 || result.error)
        throw new Error("Trusted source identity query failed");
    return result.stdout;
};
const sha = query(["rev-parse", "HEAD"]).trim();
if (
    !/^[a-f0-9]{40}$/.test(sha) ||
    (process.argv[2] !== "install" && sha !== process.env.OMG_EXPECTED_SHA)
)
    throw new Error("Checkout does not match requested SHA");
if (
    spawnSync("bun", ["--revision"], { encoding: "utf8" }).stdout.trim() !== toolchain.bun ||
    process.version !== toolchain.node
)
    throw new Error("Pinned CI toolchain mismatch");
const tracked = query(["ls-tree", "--name-only", "-r", "-z", "HEAD"]).split("\0").filter(Boolean);
pruneRestoredSource("/workspace", tracked);
// A read-only gitdir pointer permits existing source-identity helpers without leaking GIT_DIR into their subprocess fixtures.
writeFileSync("/workspace/.git", "gitdir: /tmp/ci-source/.git\n", { flag: "wx", mode: 0o444 });
const request = process.argv[2] === "install" ? null : verificationRequest();
if (request && !["regression-red-green", "test-audit-four-state", "test-audit-sensitivity"].includes(process.argv[2])) {
    if (request.testAudit) await applyTestAudit(request.testAudit.proposal, verificationContext(request));
    else await applyValidatedProposal(request.verification.proposal, verificationContext(request));
}
const portable =
    ["regression-red-green", "test-audit-four-state", "test-audit-sensitivity"].includes(process.argv[2])
        ? null
        : preparePortable("/workspace", [
              ...tracked,
              ".git",
              ...(request?.verification?.proposal.changes
                  .filter((change) => change.originalBlobSha === null)
                  .map((change) => change.path) ?? []),
          ]);
const run = async (command, args, env = {}) =>
    runPortable(portable, command, args, env, {
        timeoutMs: process.argv[2] === "rust-portable-tests" ? rustTimeouts.child : 1_170_000,
        onOutput: (name, chunk) => process[name].write(chunk),
    });
const report = (name, file) => {
    const info = lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 20_000_000)
        throw new Error("Invalid bounded report artifact");
    const content = readFileSync(file, "utf8");
    console.log(`OMG_REPORT=${JSON.stringify({ name, content })}`);
    return content;
};
console.log(
    JSON.stringify({
        executedSha: sha,
        platform: process.platform,
        plan: "omg-rust-portable",
        rust: toolchain.rust,
    }),
);
switch (process.argv[2]) {
    case "install":
        await run("cargo", ["fetch", "--locked"]);
        await run("bun", ["install", "--frozen-lockfile", "--ignore-scripts"]);
        for (const directory of [
            "services/cloud-ci",
            "services/ci-coder",
            "services/ci-inspector",
        ]) {
            if (!existsSync(`/workspace/${directory}/package.json`))
                throw new Error("Required service package absent");
            await run("bun", [
                "install",
                "--cwd",
                directory,
                "--frozen-lockfile",
                "--ignore-scripts",
            ]);
        }
        break;
    case "source-format":
        await run("cargo", ["fmt", "--all", "--", "--check"]);
        break;
    case "rust-portable-tests":
        for (const { features, platform } of rustProfiles) {
            const label = features.replaceAll(",", "-");
            const surface = `/workspace/target/cloud-rust-${label}`;
            try {
                await run("python3", ["scripts/run-native-contracts.py", "--features", features], {
                    GITHUB_RUN_ID: process.env.OMG_RUN_ID,
                    GITHUB_RUN_ATTEMPT: process.env.OMG_RUN_ATTEMPT,
                    OMG_CONTRACT_SOURCE_SHA: sha,
                    OMG_CONTRACT_PLATFORM: platform,
                    OMG_CONTRACT_SURFACE_OUT: surface,
                });
            } catch (error) {
                try {
                    const content = report(`rust-${label}-junit.xml`, `${surface}/execution/junit.xml`);
                    console.error(`OMG_RUST_FAILURES=${JSON.stringify(summarizeUnitFailures(await parseStringPromise(content)))}`);
                } catch (reportError) {
                    console.error(`Rust failure report unavailable: ${String(reportError).slice(0, 500)}`);
                }
                throw error;
            }
            report(`rust-${label}-junit.xml`, `${surface}/execution/junit.xml`);
        }
        break;
    case "script-contracts":
        await run("make", ["check-shell-syntax"]);
        await run("python3", ["-B", "/opt/omg-ci/script-contracts.py"]);
        for (const file of [
            "tests/test_benchmark_records.py",
            "tests/test_terminal_update_notice.py",
            "tests/test_audit_repair_shell.py",
        ])
            await run("python3", ["-B", file]);
        break;
    case "cloud-ci-service":
    case "ci-coder-service":
    case "ci-inspector-service":
        await runServiceCheck(process.argv[2], { exists: existsSync, run });
        break;
    case "regression-red-green":
    case "test-audit-four-state":
    case "test-audit-sensitivity":
        if (!request) throw new Error("Regression request required");
        await runRegression(request);
        break;
    default:
        throw new Error("Unknown trusted OMG check");
}

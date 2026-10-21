import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { validateTestAuditProposal, runTestAuditStates, testAuditPhaseSource } from "../runner/test-audit.mjs";
import { inspectAuditSource, applyTestAudit } from "../runner/audit-verifier.mjs";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseStart, runIdentity, parseVerificationEvidence } from "../src/contract";
import { parseTestAuditEvidence, testAuditDigest } from "../src/test-audit-contract";
import { parseRustCatalog, parseRustExecution, discoverRustTestArtifact } from "../runner/rust-evidence.mjs";

test("existing targets admit one exact executed test while accounting for other catalog cases", () => {
    const catalog = parseRustCatalog("checks_value: test\nother: test\n", "checks_value", { existingTest: true });
    const result = parseRustExecution({ stdout: "running 1 test\ntest checks_value ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\n",
        stderr: "", exitCode: 0, testName: "checks_value", file: "tests/value.rs", source: original, catalog });
    expect(result.tests).toBe(1);
    expect(() => parseRustCatalog("checks_value: test\nother: test\n", "checks_value")).toThrow();
    expect(() => parseRustCatalog("other: test\n", "checks_value", { existingTest: true })).toThrow();
    expect(() => parseRustExecution({ stdout: "running 1 test\ntest checks_value ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99999 filtered out; finished in 0.00s\n",
        stderr: "", exitCode: 0, testName: "checks_value", file: "tests/value.rs", source: original,
        catalog: { ...catalog, filtered: 99999 } })).toThrow();
});

const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const blob = (value: string) => createHash("sha1").update(`blob ${Buffer.byteLength(value)}\0${value}`).digest("hex");
const original = "#[test]\nfn checks_value() {\n    let actual = value();\n    assert!(actual > 0);\n}\n";
const stronger = original.replace("}\n", "    assert_eq!(actual, 2);\n}\n");
const proposal = {
    purpose: "existing-test-strengthening" as const, repository: "omg-cli/omg" as const, branch: "main" as const, baseSha: "a".repeat(40),
    test: { path: "tests/value.rs", testName: "checks_value", originalBlobSha: blob(original), originalContent: original,
        newContent: stronger, sha256: hash(stronger), assertionLine: 5 },
    fault: { path: "src/value.rs", originalBlobSha: blob("pub fn value() -> u32 { 2 }\n"),
        oldContentQuote: "2", newContent: "pub fn value() -> u32 { 1 }\n", sha256: hash("pub fn value() -> u32 { 1 }\n") },
};

const request = { repository: "omg-cli/omg", sha: proposal.baseSha, ref: "refs/heads/main", runId: "123", attempt: "1",
    testAudit: { verifierRevision: "d".repeat(40), proposal } };
test("admits separate audit requests with digest-bound identity and rejects repair proof credit", () => {
    expect(parseStart(request).testAudit?.proposal.test.path).toBe("tests/value.rs");
    expect(runIdentity(parseStart(request))).toContain(`-ta-${testAuditDigest(proposal).slice(0, 16)}`);
    expect(() => parseStart({ ...request, verification: {} })).toThrow();
    expect(() => parseVerificationEvidence(parseStart(request), {})).toThrow();
});

test("receipt admission binds all four states, exact run, assertion and evidence-only fault", () => {
    const common = { testName: "checks_value", exitCode: 0, failures: 0, tests: 1, errors: 0, skipped: 0,
        reportSha256: hash("report"), stdoutSha256: hash("stdout"), stderrSha256: hash("stderr"), catalogSha256: hash("catalog"),
        executableSha256: hash("exe"), compilerMessagesSha256: hash("compiler"), sourceSha256: hash(original), recipeSha256: hash("recipe") };
    const receipt = { purpose: "existing-test-strengthening", repository: request.repository, branch: "main", baseSha: request.sha,
        proposalSha256: testAuditDigest(proposal), verifierRevision: request.testAudit.verifierRevision, runId: 123, runAttempt: 1,
        oldIntact: common, oldFault: common,
        strongerFault: { ...common, exitCode: 101, failures: 1, sourceSha256: hash(stronger), assertionFailure: "assertion `left == right` failed",
            assertionFile: "tests/value.rs", assertionLine: 5, assertionSourceSha256: hash("    assert_eq!(actual, 2);") },
        strongerIntact: { ...common, sourceSha256: hash(stronger) }, protectedPathsUnchanged: true, faultRestored: true,
        changedPaths: ["tests/value.rs"], fileHashes: [{ path: "tests/value.rs", sha256: hash(stronger) }] };
    expect(parseTestAuditEvidence(request, receipt).purpose).toBe("existing-test-strengthening");
    for (const change of [
        { runAttempt: 2 }, { proposalSha256: hash("other") }, { faultRestored: false },
        { oldFault: { ...common, exitCode: 101, failures: 1 } },
        { strongerFault: { ...receipt.strongerFault, assertionLine: 4 } },
        { strongerIntact: { ...receipt.strongerIntact, recipeSha256: hash("other") } },
        { changedPaths: ["tests/value.rs", "src/value.rs"] },
    ]) expect(() => parseTestAuditEvidence(request, { ...receipt, ...change })).toThrow();
});

test("existing-test proposal preserves old assertions and binds one additional assertion", () => {
    expect(validateTestAuditProposal(proposal)).toEqual(proposal);
    for (const changed of [
        { ...proposal.test, newContent: stronger.replace("assert!(actual > 0);", "assert!(true);") },
        { ...proposal.test, newContent: stronger.replace("assert_eq!(actual, 2);", "return;\n    assert_eq!(actual, 2);") },
        { ...proposal.test, assertionLine: 4 },
        { ...proposal.test, originalBlobSha: "b".repeat(40) },
        { ...proposal.test, path: "tests/../Cargo.toml" },
    ]) expect(() => validateTestAuditProposal({ ...proposal, test: { ...changed, sha256: hash(changed.newContent) } })).toThrow();
    const beforeOldAssertion = original.replace("    assert!(actual > 0);", "    assert_eq!(actual, 2);\n    assert!(actual > 0);");
    expect(validateTestAuditProposal({ ...proposal, test: { ...proposal.test, newContent: beforeOldAssertion,
        sha256: hash(beforeOldAssertion), assertionLine: 4 } }).test.assertionLine).toBe(4);
});

test("four states compare the same old and stronger bytes against the same bounded fault", async () => {
    const writes: string[] = [];
    const states: string[] = [];
    const result = await runTestAuditStates(proposal, {
        writeTest: async (content: string) => { writes.push(content); },
        writeFault: async (active: boolean) => { states.push(active ? "fault" : "intact"); },
        verify: async () => {},
        run: async (phase: string) => ({ phase, exitCode: phase === "strongerFault" ? 101 : 0,
            failures: phase === "strongerFault" ? 1 : 0, tests: 1, errors: 0, skipped: 0,
            assertionLine: 5, assertionFile: "tests/value.rs", assertionSourceSha256: hash("    assert_eq!(actual, 2);"),
            sourceSha256: hash(phase.startsWith("old") ? original : stronger), recipeSha256: "c".repeat(64),
            testName: "checks_value" }),
    });
    expect(Object.keys(result)).toEqual(["oldIntact", "oldFault", "strongerFault", "strongerIntact"]);
    expect(writes).toEqual([original, original, stronger, stronger]);
    expect(states).toEqual(["intact", "fault", "fault", "intact", "intact"]);
});

test("adequate existing tests receive only two real sensitivity states and no strengthening credit", async () => {
    const adequate = { ...proposal, purpose: "existing-test-sensitivity" as const,
        test: { ...proposal.test, newContent: original, sha256: hash(original), assertionLine: 4 } };
    const phases: string[] = [];
    const states = await runTestAuditStates(adequate, {
        writeTest: async (content) => { expect(content).toBe(original); }, writeFault: async () => {}, verify: async () => {},
        run: async (phase) => { phases.push(phase); return { testName: "checks_value", tests: 1, errors: 0, skipped: 0,
            exitCode: phase === "oldFault" ? 101 : 0, failures: phase === "oldFault" ? 1 : 0,
            assertionFile: "tests/value.rs", assertionLine: 4, assertionSourceSha256: hash("    assert!(actual > 0);"),
            sourceSha256: hash(original), recipeSha256: hash("recipe") }; },
    });
    expect(phases).toEqual(["oldIntact", "oldFault"]);
    expect(Object.keys(states)).toEqual(phases);
    expect(() => validateTestAuditProposal({ ...adequate, test: proposal.test })).toThrow();
    const common = { ...states.oldIntact, reportSha256: hash("report"), stdoutSha256: hash("out"), stderrSha256: hash("err"),
        catalogSha256: hash("catalog"), executableSha256: hash("exe"), compilerMessagesSha256: hash("compiler") };
    const receipt = { purpose: adequate.purpose, repository: adequate.repository, branch: adequate.branch, baseSha: adequate.baseSha,
        proposalSha256: testAuditDigest(adequate), verifierRevision: request.testAudit.verifierRevision, runId: 123, runAttempt: 1,
        oldIntact: common, oldFault: { ...common, ...states.oldFault, assertionFailure: "assertion failed: actual > 0" },
        protectedPathsUnchanged: true, faultRestored: true, changedPaths: [], fileHashes: [] };
    const auditRequest = { ...request, testAudit: { ...request.testAudit, proposal: adequate } };
    expect(parseTestAuditEvidence(auditRequest, receipt).purpose).toBe("existing-test-sensitivity");
    for (const changed of [
        { strongerIntact: common }, { oldFault: common }, { purpose: "existing-test-strengthening" }, { changedPaths: [adequate.test.path] },
    ]) expect(() => parseTestAuditEvidence(auditRequest, { ...receipt, ...changed })).toThrow();
});

for (const failedState of ["oldIntact", "oldFault", "strongerFault", "strongerIntact"]) {
    test(`rejects wrong ${failedState} outcome and restores intact source`, async () => {
        const restored: boolean[] = [];
        await expect(runTestAuditStates(proposal, {
            writeTest: async () => {}, writeFault: async (active: boolean) => { restored.push(active); }, verify: async () => {},
            run: async (phase: string) => ({ exitCode: phase === failedState ? 2 : phase === "strongerFault" ? 101 : 0,
                failures: phase === "strongerFault" ? 1 : 0, tests: 1, errors: 0, skipped: 0,
                assertionLine: 5, assertionFile: "tests/value.rs", assertionSourceSha256: hash("    assert_eq!(actual, 2);"),
                sourceSha256: hash(phase.startsWith("old") ? original : stronger), recipeSha256: "c".repeat(64), testName: "checks_value" }),
        })).rejects.toThrow();
        expect(restored.at(-1)).toBe(false);
    });
}

test("inline library audit composes a same-file production fault without losing the stronger test", async () => {
    const source = `pub fn value() -> u32 { 2 }\n#[cfg(test)]\nmod tests {\n${original}}\n`;
    const strong = source.replace("    assert!(actual > 0);", "    assert!(actual > 0);\n    assert_eq!(actual, 2);");
    const faulty = source.replace("u32 { 2 }", "u32 { 1 }");
    const inline = { ...proposal, test: { ...proposal.test, path: "src/value.rs", target: "lib" as const, testName: "tests::checks_value",
        originalContent: source, originalBlobSha: blob(source), newContent: strong, sha256: hash(strong), assertionLine: 8 },
        fault: { ...proposal.fault, originalBlobSha: blob(source), newContent: faulty, sha256: hash(faulty) } };
    expect(validateTestAuditProposal(inline)).toEqual(inline);
    expect(testAuditPhaseSource(inline, "oldFault")).toBe(faulty);
    expect(testAuditPhaseSource(inline, "strongerFault")).toBe(strong.replace("u32 { 2 }", "u32 { 1 }"));
    expect(testAuditPhaseSource(inline, "strongerIntact")).toBe(strong);
    const sourceBeforeTest = source.replace("pub fn value() -> u32 { 2 }", "pub fn value() -> u32 { assert!(true); 2 }");
    expect(() => validateTestAuditProposal({ ...inline, test: { ...inline.test, newContent: sourceBeforeTest, sha256: hash(sourceBeforeTest), assertionLine: 1 } })).toThrow();
    const messages = JSON.stringify({ reason: "compiler-artifact", profile: { test: true }, target: { name: "omg_lib", kind: ["lib"], src_path: "/workspace/src/lib.rs" },
        executable: "/workspace/target/debug/deps/omg_lib-123", features: ["license", "pgp", "sequoia-openpgp"], package_id: "path+file:///workspace#omg@0.1.0" }) +
        '\n{"reason":"build-finished","success":true}\n';
    expect(discoverRustTestArtifact(messages, "src/value.rs", { existingTest: true, target: "lib" }).target).toBe("omg_lib");
    expect(() => discoverRustTestArtifact(messages, "src/value.rs")).toThrow();
});

test("real Git admission binds old inline source, restores fault identity, and applies only the stronger test", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "omg-test-audit-"));
    const gitDirectory = path.join(root, "trusted");
    const workspace = path.join(root, "workspace");
    const source = `pub fn value() -> u32 { 2 }\n#[cfg(test)]\nmod tests {\n${original}}\n`;
    const strong = source.replace("    assert!(actual > 0);", "    assert!(actual > 0);\n    assert_eq!(actual, 2);");
    const faulty = source.replace("u32 { 2 }", "u32 { 1 }");
    const git = (args: string[]) => {
        const result = spawnSync("git", ["-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", gitDirectory, ...args], { encoding: "utf8", windowsHide: true });
        if (result.status !== 0) throw new Error(result.stderr);
        return result.stdout.trim();
    };
    try {
        for (const directory of [gitDirectory, workspace]) {
            await mkdir(path.join(directory, "src"), { recursive: true });
            await writeFile(path.join(directory, "src/value.rs"), source);
            await writeFile(path.join(directory, "protected.bin"), Buffer.from([0, 255, 128, 10]));
        }
        git(["init", "-q"]); git(["add", "."]);
        git(["-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-qm", "base"]);
        const candidate = { ...proposal, baseSha: git(["rev-parse", "HEAD"]),
            test: { ...proposal.test, path: "src/value.rs", target: "lib" as const, testName: "tests::checks_value", originalContent: source,
                originalBlobSha: blob(source), newContent: strong, sha256: hash(strong), assertionLine: 8 },
            fault: { ...proposal.fault, originalBlobSha: blob(source), newContent: faulty, sha256: hash(faulty) } };
        const context = { repository: "omg-cli/omg", branch: "main", baseSha: candidate.baseSha, verifierRevision: "b".repeat(40), runId: 123, runAttempt: 1, workspace, gitDirectory };
        expect((await inspectAuditSource(candidate, context)).originalFault).toBe(source);
        for (const changed of [
            { ...candidate, baseSha: "d".repeat(40) },
            { ...candidate, fault: { ...candidate.fault, originalBlobSha: "d".repeat(40) } },
            { ...candidate, fault: { ...candidate.fault, oldContentQuote: "absent" } },
            { ...candidate, fault: { ...candidate.fault, newContent: faulty.replace("assert!(actual > 0)", "assert!(true)"), sha256: hash(faulty.replace("assert!(actual > 0)", "assert!(true)")) } },
            { ...candidate, fault: { ...candidate.fault, newContent: `\n${faulty}`, sha256: hash(`\n${faulty}`) } },
        ]) await expect(inspectAuditSource(changed, context)).rejects.toThrow();
        await applyTestAudit(candidate, context);
        expect(await readFile(path.join(workspace, "src/value.rs"), "utf8")).toBe(strong);
        expect(await readFile(path.join(workspace, "protected.bin"))).toEqual(Buffer.from([0, 255, 128, 10]));
        await expect(applyTestAudit(candidate, context)).rejects.toThrow();
    } finally { await rm(root, { recursive: true, force: true }); }
});

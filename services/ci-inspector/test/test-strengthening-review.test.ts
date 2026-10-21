import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { patchReviewInputSchema, patchReviewDigest, admitPatchReview } from "../src/patch-review-contract";
import { testAuditDigest, testAuditSchema } from "../../cloud-ci/src/test-audit-contract";
import { handlePatchReview } from "../src/patch-review-http";

const hash = (text: string) => createHash("sha256").update(text).digest("hex");
const original = "#[test]\nfn value() {\n let actual = read_value();\n assert!(actual > 0);\n}\n";
const stronger = original.replace("}\n", " assert_eq!(actual, 2);\n}\n");
const proposal = testAuditSchema.shape.proposal.parse({ purpose: "existing-test-strengthening", repository: "omg-cli/omg", branch: "main", baseSha: "a".repeat(40),
    test: { path: "tests/value.rs", testName: "value", originalBlobSha: createHash("sha1").update(`blob ${Buffer.byteLength(original)}\0${original}`).digest("hex"),
        originalContent: original, newContent: stronger, sha256: hash(stronger), assertionLine: 5 },
    fault: { path: "src/value.rs", originalBlobSha: "f".repeat(40), oldContentQuote: "2", newContent: "pub const VALUE:u32=1;", sha256: hash("pub const VALUE:u32=1;") } });
const common = { testName: "value", exitCode: 0, tests: 1, failures: 0, errors: 0, skipped: 0,
    reportSha256: hash("report"), stdoutSha256: hash("out"), stderrSha256: hash("err"), catalogSha256: hash("catalog"),
    executableSha256: hash("exe"), compilerMessagesSha256: hash("compiler"), sourceSha256: hash(original), recipeSha256: hash("recipe") };
const receipt = { purpose: proposal.purpose, repository: proposal.repository, branch: proposal.branch, baseSha: proposal.baseSha,
    proposalSha256: testAuditDigest(proposal), verifierRevision: "e".repeat(40), runId: 123, runAttempt: 1,
    oldIntact: common, oldFault: common, strongerIntact: { ...common, sourceSha256: hash(stronger) },
    strongerFault: { ...common, sourceSha256: hash(stronger), exitCode: 101, failures: 1, assertionFile: proposal.test.path, assertionLine: 5,
        assertionSourceSha256: hash(" assert_eq!(actual, 2);"), assertionFailure: "assertion `left == right` failed" },
    protectedPathsUnchanged: true, faultRestored: true, changedPaths: [proposal.test.path], fileHashes: [{ path: proposal.test.path, sha256: proposal.test.sha256 }] };
const { originalContent, newContent, ...testIdentity } = proposal.test;
const input = { purpose: "test-strengthening-approval", repository: proposal.repository, branch: proposal.branch, baseSha: proposal.baseSha,
    headSha: "b".repeat(40), headTreeSha: "c".repeat(40), proposalSha256: testAuditDigest(proposal),
    patch: [{ path: proposal.test.path, before: originalContent, after: newContent }], audit: { test: testIdentity, fault: proposal.fault, receipt } };

test("strengthening review admits only a complete additive test patch with digest-bound four-state evidence", () => {
    expect(patchReviewInputSchema.parse(input).purpose).toBe("test-strengthening-approval");
    for (const changed of [
        { purpose: "fix-approval" }, { proposalSha256: hash("other") },
        { patch: [{ ...input.patch[0], after: stronger.replace("assert!(actual > 0)", "assert!(true)") }] },
        { audit: { ...input.audit, receipt: { ...receipt, oldFault: { ...common, exitCode: 101, failures: 1 } } } },
        { audit: { ...input.audit, fault: { ...proposal.fault, newContent: "different" } } },
    ]) expect(patchReviewInputSchema.safeParse({ ...input, ...changed }).success).toBe(false);
});

test("Inspector receipt retains strengthening purpose and cannot be replayed as fix approval", async () => {
    const parsed = patchReviewInputSchema.parse(input);
    const response = await handlePatchReview(new Request("https://inspector/patch-review", { method: "POST",
        headers: { authorization: "Bearer secret", "content-type": "application/json" }, body: JSON.stringify(input) }),
        { CI_INSPECTOR_TOKEN: "secret" }, async () => ({ model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017", readCompletePatch: true, codeExecutions: 1,
            result: { verdict: "approved", reason: "The added assertion distinguishes the controlled faulty value from the intact value.", findings: [] } }));
    expect(response.status).toBe(200);
    const reviewed = await response.json();
    expect(reviewed.purpose).toBe("test-strengthening-approval");
    expect(reviewed.inputSha256).toBe(patchReviewDigest(parsed));
    expect(admitPatchReview(parsed, reviewed).verdict).toBe("approved");
    expect(() => admitPatchReview(parsed, { ...reviewed, purpose: "fix-approval" })).toThrow();
});

test("only strengthening review receives the bounded large-source envelope", async () => {
    const prefix = "// retained original context\n".repeat(7000);
    const before = prefix + original;
    const after = prefix + stronger;
    const audit = { ...proposal, test: { ...proposal.test, originalContent: before, newContent: after,
        originalBlobSha: createHash("sha1").update(`blob ${Buffer.byteLength(before)}\0${before}`).digest("hex"),
        sha256: hash(after), assertionLine: 7005 } };
    const proof = { ...receipt, proposalSha256: testAuditDigest(audit),
        oldIntact: { ...receipt.oldIntact, sourceSha256: hash(before) }, oldFault: { ...receipt.oldFault, sourceSha256: hash(before) },
        strongerFault: { ...receipt.strongerFault, sourceSha256: hash(after), assertionLine: 7005 },
        strongerIntact: { ...receipt.strongerIntact, sourceSha256: hash(after) }, fileHashes: [{ path: audit.test.path, sha256: hash(after) }] };
    const { originalContent: old, newContent: updated, ...identity } = audit.test;
    const large = { ...input, proposalSha256: testAuditDigest(audit), patch: [{ path: audit.test.path, before: old, after: updated }],
        audit: { test: identity, fault: audit.fault, receipt: proof } };
    const respond = (body: string) => handlePatchReview(new Request("https://inspector/patch-review", { method: "POST",
        headers: { authorization: "Bearer secret", "content-type": "application/json" }, body }), { CI_INSPECTOR_TOKEN: "secret" },
        async () => ({ model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017", readCompletePatch: true, codeExecutions: 1,
            result: { verdict: "insufficient-evidence", reason: "Transport fixture does not grant audit credit.", findings: [] } }));
    expect(Buffer.byteLength(JSON.stringify(large))).toBeGreaterThan(128 * 1024);
    expect((await respond(JSON.stringify(large))).status).toBe(200);
    const fix = { purpose: "fix-approval", repository: input.repository, branch: input.branch, baseSha: input.baseSha,
        headSha: input.headSha, headTreeSha: input.headTreeSha, proposalSha256: input.proposalSha256,
        finding: { summary: "Wrong value", reproduction: "Read VALUE", path: "src/value.rs", line: 1, sourceQuote: "1" },
        regression: { testName: "value", assertionFailure: "assertion failed", assertionFile: "tests/ai-review-value.rs", assertionLine: 1,
            assertionSourceSha256: hash("assert!(false);"), baselineExitCode: 101, patchedExitCode: 0 },
        patch: [{ path: "src/value.rs", before: "pub const VALUE:u32=1;", after: "pub const VALUE:u32=2;" }] };
    expect((await respond(JSON.stringify(fix) + " ".repeat(128 * 1024))).status).toBe(413);
    expect((await respond(JSON.stringify(large) + " ".repeat(1024 * 1024))).status).toBe(413);
});

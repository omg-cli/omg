import { test, expect, mock } from "bun:test";
import { createHash } from "node:crypto";

let structuredMessages;
let sourceRequest;
let sourceWindowContent;
let patchSystem;
const reviewEnv = {
    AI: {}, LOADER: {}, CI_INSPECTOR_TOKEN: "unused",
    MODEL_PACER: { getByName() { return { async admit() { return { granted: true }; } }; } },
};
mock.module("@cloudflare/codemode", () => ({ DynamicWorkerExecutor: class {} }));
mock.module("@cloudflare/codemode/ai", () => ({ createCodeTool: ({ tools }) => tools }));
mock.module("workers-ai-provider", () => ({ createWorkersAI: () => () => ({}) }));
mock.module("ai", () => ({
    stepCountIs: () => () => false,
    Output: { object: (value) => value },
    generateText: async (request) => {
        if (request.tools) {
            if (request.tools.codemode.readCompletePatch) {
                patchSystem = request.system;
                await request.tools.codemode.readCompletePatch.execute();
            } else {
                sourceRequest = request;
                const window = JSON.parse(request.prompt).sourceWindows[0];
                sourceWindowContent = await request.tools.codemode.readSource.execute(window);
            }
            return { steps: [{ toolResults: [{ output: "OK" }] }],
                responseMessages: [{ role: "assistant", content: "OK" }] };
        }
        structuredMessages = request.messages;
        if (request.output.name === "source_review_selection")
            return { output: { kind: "no-findings", summary: "The historical runtime lead remains uncorroborated." } };
        return { output: { verdict: "approved", reason: "Independent review accepted the patch.", findings: [] } };
    },
}));

test("structured independent review receives the whole actual patch when CodeMode discards its retrieved result", async () => {
    const { reviewPatch } = await import("../../services/ci-inspector/src/review.ts");
    const input = { purpose: "fix-approval", repository: "omg-cli/omg", branch: "main",
        baseSha: "a".repeat(40), headSha: "b".repeat(40), headTreeSha: "c".repeat(40), proposalSha256: "d".repeat(64),
        finding: { summary: "Incorrect public value.", reproduction: "Read public VALUE.", path: "src/value.rs", line: 1, sourceQuote: "pub const VALUE: u8 = 1;" },
        regression: { testName: "value_returns_two", assertionFailure: "left 1 right 2", assertionFile: "tests/ai-review-value.rs", assertionLine: 1,
            assertionSourceSha256: "e".repeat(64), baselineExitCode: 101, patchedExitCode: 0 },
        patch: [{ path: "src/value.rs", before: "pub const VALUE: u8 = 1;", after: "pub const VALUE: u8 = 2;" },
            { path: "tests/ai-review-value.rs", before: null, after: "#[test] fn value_returns_two() { assert_eq!(omg::VALUE, 2); }" }],
    };
    const result = await reviewPatch(input, reviewEnv);
    expect(result.readCompletePatch).toBe(true);
    expect(JSON.parse(structuredMessages.at(-1).content).retrievedPatch).toEqual(input);
});

test("strengthening semantic review sees the controlled fault and all four states even when CodeMode discards them", async () => {
    const { reviewPatch } = await import("../../services/ci-inspector/src/review.ts");
    const { testAuditDigest } = await import("../../services/cloud-ci/src/test-audit-contract.ts");
    const hash = (content) => createHash("sha256").update(content).digest("hex");
    const before = "#[test]\nfn value() {\n let actual = read_value();\n assert!(actual > 0);\n}\n";
    const after = before.replace("}\n", " assert_eq!(actual, 2);\n}\n");
    const proposal = { purpose: "existing-test-strengthening", repository: "omg-cli/omg", branch: "main", baseSha: "a".repeat(40),
        test: { path: "tests/value.rs", testName: "value", originalBlobSha: createHash("sha1").update(`blob ${Buffer.byteLength(before)}\0${before}`).digest("hex"),
            originalContent: before, newContent: after, sha256: hash(after), assertionLine: 5 },
        fault: { path: "src/value.rs", originalBlobSha: "f".repeat(40), oldContentQuote: "2", newContent: "pub const VALUE:u32=1;", sha256: hash("pub const VALUE:u32=1;") } };
    const common = { testName: "value", exitCode: 0, tests: 1, failures: 0, errors: 0, skipped: 0,
        reportSha256: hash("report"), stdoutSha256: hash("out"), stderrSha256: hash("err"), catalogSha256: hash("catalog"),
        executableSha256: hash("exe"), compilerMessagesSha256: hash("compiler"), sourceSha256: hash(before), recipeSha256: hash("recipe") };
    const receipt = { purpose: proposal.purpose, repository: proposal.repository, branch: proposal.branch, baseSha: proposal.baseSha,
        proposalSha256: testAuditDigest(proposal), verifierRevision: "e".repeat(40), runId: 123, runAttempt: 1,
        oldIntact: common, oldFault: common, strongerIntact: { ...common, sourceSha256: hash(after) },
        strongerFault: { ...common, sourceSha256: hash(after), exitCode: 101, failures: 1, assertionFile: proposal.test.path, assertionLine: 5,
            assertionSourceSha256: hash(" assert_eq!(actual, 2);"), assertionFailure: "assertion `left == right` failed" },
        protectedPathsUnchanged: true, faultRestored: true, changedPaths: [proposal.test.path], fileHashes: [{ path: proposal.test.path, sha256: proposal.test.sha256 }] };
    const { originalContent, newContent, ...testIdentity } = proposal.test;
    const input = { purpose: "test-strengthening-approval", repository: proposal.repository, branch: proposal.branch, baseSha: proposal.baseSha,
        headSha: "b".repeat(40), headTreeSha: "c".repeat(40), proposalSha256: testAuditDigest(proposal),
        patch: [{ path: proposal.test.path, before: originalContent, after: newContent }], audit: { test: testIdentity, fault: proposal.fault, receipt } };
    await reviewPatch(input, reviewEnv);
    expect(JSON.parse(structuredMessages.at(-1).content).retrievedPatch).toEqual(input);
    expect(patchSystem).toContain("old/fault GREEN");
    expect(patchSystem).toContain("evidence-only");
    expect(patchSystem).toContain("never certification of an entire test suite");
});

test("actual source-model request includes historical runtime error types and frame-centered current source", async () => {
    const { reviewSource } = await import("../../services/ci-inspector/src/review.ts");
    const runtimeEvidence = [{ kind: "sentry-runtime", organization: "omg", projectId: "1", eventId: "a".repeat(32),
        issueId: "2", bodySha256: "b".repeat(64), sourceSha: "c".repeat(40), release: "v0.1.224", environment: "production",
        errorTypes: ["CacheError"], frames: [{ path: "src/value.rs", line: 120 }] }];
    const input = { repository: "omg-cli/omg", sha: "d".repeat(40), branch: "main", changedPaths: [], auditPaths: ["src/value.rs"],
        diff: "", ciFailures: [], runtimeEvidence,
        sourceFiles: [{ path: "src/value.rs", blobSha: "e".repeat(40),
            content: Array.from({ length: 160 }, (_, index) => `pub const LINE_${index + 1}: usize = ${index + 1};`).join("\n") }] };
    await reviewSource(input, reviewEnv);
    const prompt = JSON.parse(sourceRequest.prompt);
    expect(prompt.runtimeEvidence).toEqual(runtimeEvidence);
    expect(prompt.sourceWindows[0].line).toBe(120);
    expect(sourceWindowContent.lineStart).toBe(81);
    expect(sourceWindowContent.lineEnd).toBe(160);
    expect(sourceWindowContent.numberedLines).toContainEqual({line: 120, text: "pub const LINE_120: usize = 120;"});
    expect(JSON.parse(structuredMessages[0].content).runtimeEvidence).toEqual(runtimeEvidence);
    expect(sourceRequest.system).toMatch(/historical.*uncorroborated/i);

    input.runtimeEvidence[0].frames[0].line = 99999;
    await reviewSource(input, reviewEnv);
    const historical = JSON.parse(sourceRequest.prompt);
    expect(historical.sourceWindows[0].line).toBe(160);
    expect(sourceWindowContent.lineEnd).toBe(160);
    expect(sourceWindowContent.numberedLines).toHaveLength(80);
    expect(historical.runtimeFrameContext[0].outsideCurrentSource).toBe(true);
});

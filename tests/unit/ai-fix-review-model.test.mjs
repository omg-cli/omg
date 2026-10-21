import { test, expect, mock } from "bun:test";

let structuredMessages;
let sourceRequest;
let sourceWindowContent;
mock.module("@cloudflare/codemode", () => ({ DynamicWorkerExecutor: class {} }));
mock.module("@cloudflare/codemode/ai", () => ({ createCodeTool: ({ tools }) => tools }));
mock.module("workers-ai-provider", () => ({ createWorkersAI: () => () => ({}) }));
mock.module("ai", () => ({
    stepCountIs: () => () => false,
    Output: { object: (value) => value },
    generateText: async (request) => {
        if (request.tools) {
            if (request.tools.codemode.readCompletePatch) {
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
        if (request.output.name === "source_review_proposal")
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
    const result = await reviewPatch(input, { AI: {}, LOADER: {}, CI_INSPECTOR_TOKEN: "unused" });
    expect(result.readCompletePatch).toBe(true);
    expect(JSON.parse(structuredMessages.at(-1).content).retrievedPatch).toEqual(input);
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
    await reviewSource(input, { AI: {}, LOADER: {}, CI_INSPECTOR_TOKEN: "unused" });
    const prompt = JSON.parse(sourceRequest.prompt);
    expect(prompt.runtimeEvidence).toEqual(runtimeEvidence);
    expect(prompt.sourceWindows[0].lineStart).toBeLessThanOrEqual(120);
    expect(prompt.sourceWindows[0].lineEnd).toBeGreaterThanOrEqual(120);
    expect(sourceWindowContent.content).toContain("pub const LINE_120: usize = 120;");
    expect(JSON.parse(structuredMessages[0].content).runtimeEvidence).toEqual(runtimeEvidence);
    expect(sourceRequest.system).toMatch(/historical.*uncorroborated/i);

    input.runtimeEvidence[0].frames[0].line = 99999;
    await reviewSource(input, { AI: {}, LOADER: {}, CI_INSPECTOR_TOKEN: "unused" });
    const historical = JSON.parse(sourceRequest.prompt);
    expect(historical.sourceWindows[0].lineEnd).toBe(160);
    expect(historical.runtimeFrameContext[0].outsideCurrentSource).toBe(true);
});

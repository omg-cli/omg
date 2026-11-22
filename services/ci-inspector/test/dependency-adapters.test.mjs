import { expect, mock, test } from "bun:test";
import { generateText, Output, stepCountIs } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import { snapshotSchema } from "../src/snapshot";
import { snapshotTools } from "../src/tools";

mock.module("cloudflare:workers", () => ({ WorkerEntrypoint: class {} }));

test("AI SDK routes a code-mode snapshot read and parses structured output", async () => {
  const { createCodeTool } = await import("@cloudflare/codemode/ai");
  const snapshot = snapshotSchema.parse({
    repository: "omg-cli/omg", runId: 1, branch: "main", sha: "a".repeat(40), prompt: "Explain",
    jobs: [{
      id: 2, name: "Tests", status: "completed", conclusion: "failure",
      failedSteps: [{ name: "Unit", log: "fixture failure" }],
    }],
  });
  let reads = 0;
  const codemode = createCodeTool({
    tools: snapshotTools(snapshot, () => { reads++; }),
    executor: {
      async execute(code, providers) {
        expect(code).toContain("codemode.readFailedStep");
        const read = providers?.find((provider) => provider.name === "codemode")?.fns.readFailedStep;
        if (!read) throw new Error("Snapshot tool was not registered");
        return { result: await read({ jobId: 2, step: "Unit" }) };
      },
    },
  });
  const usage = {
    inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
    outputTokens: { total: 1, text: 1, reasoning: 0 },
  };
  const model = new MockLanguageModelV4({
    doGenerate: [
      {
        content: [{
          type: "tool-call", toolCallId: "fixture-read", toolName: "codemode",
          input: JSON.stringify({ code: 'async () => codemode.readFailedStep({jobId: 2, step: "Unit"})' }),
        }],
        finishReason: { unified: "tool-calls", raw: undefined }, usage, warnings: [],
      },
      {
        content: [{ type: "text", text: '{"summary":"Unit failed"}' }],
        finishReason: { unified: "stop", raw: undefined }, usage, warnings: [],
      },
    ],
  });
  const result = await generateText({
    model, tools: { codemode }, prompt: "Summarize the supplied fixture",
    output: Output.object({ schema: z.object({ summary: z.string() }) }),
    stopWhen: stepCountIs(2), maxRetries: 0,
  });
  expect(reads).toBe(1);
  expect(result.steps[0]?.toolResults[0]?.output).toEqual({
    result: { jobId: 2, step: "Unit", log: "fixture failure" },
  });
  expect(result.output).toEqual({ summary: "Unit failed" });
});

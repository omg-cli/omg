import { test, expect } from "bun:test";
import { patchReviewInputSchema, patchReviewDigest, admitPatchReview } from "../src/patch-review-contract";
import { handlePatchReview, type PatchReviewInference } from "../src/patch-review-http";

const input = {
  purpose: "fix-approval" as const, repository: "omg-cli/omg" as const, branch: "main" as const,
  baseSha: "a".repeat(40), headSha: "b".repeat(40), headTreeSha: "c".repeat(40),
  proposalSha256: "d".repeat(64),
  finding: { summary: "Public VALUE returns 1 instead of 2.", reproduction: "Read omg::VALUE.", path: "src/value.rs", line: 1, sourceQuote: "pub const VALUE: u8 = 1;" },
  regression: { testName: "value", assertionFailure: "assertion left == right failed: left 1 right 2", assertionFile: "tests/ai-review-value.rs", assertionLine: 1,
    assertionSourceSha256: "e".repeat(64), baselineExitCode: 101 as const, patchedExitCode: 0 as const },
  patch: [{ path: "src/value.rs", before: "pub const VALUE: u8 = 1;\n", after: "pub const VALUE: u8 = 2;\n" },
    { path: "tests/ai-review-value.rs", before: null, after: "#[test] fn value() { assert_eq!(omg::VALUE, 2); }\n" }],
};
const result = { verdict: "approved" as const, reason: "The public observable value and literal regression match the stated defect.", findings: [] };
const inference = { result, model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017", readCompletePatch: true, codeExecutions: 1 } satisfies PatchReviewInference;
const request = (body: unknown = input, token = "secret") => new Request("https://inspector/patch-review", {
  method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify(body),
});

test("independent patch verdict binds the complete exact patch and current head", async () => {
  const response = await handlePatchReview(request(), { CI_INSPECTOR_TOKEN: "secret" }, async () => inference);
  expect(response.status).toBe(200);
  const receipt = await response.json();
  expect(admitPatchReview(input, receipt).verdict).toBe("approved");
  expect(receipt.inputSha256).toBe(await patchReviewDigest(input));
  expect(() => admitPatchReview({ ...input, headSha: "f".repeat(40) }, receipt)).toThrow();
  expect(() => admitPatchReview({ ...input, finding: { ...input.finding, summary: "A different claimed defect." } }, receipt)).toThrow();
  expect(() => admitPatchReview({ ...input, regression: { ...input.regression, assertionFailure: "Different failure." } }, receipt)).toThrow();
});

test("model cannot approve without actually retrieving the full patch", async () => {
  const response = await handlePatchReview(request(), { CI_INSPECTOR_TOKEN: "secret" }, async () => ({ ...inference, readCompletePatch: false }));
  expect(response.status).toBe(502);
});

test("insufficient evidence stays distinct from an approval", async () => {
  const response = await handlePatchReview(request(), { CI_INSPECTOR_TOKEN: "secret" }, async () => ({
    ...inference, result: { ...result, verdict: "insufficient-evidence" },
  }));
  expect(response.status).toBe(200);
  expect(admitPatchReview(input, await response.json()).verdict).toBe("insufficient-evidence");
});

test("patch endpoint refuses unauthenticated inference and forged input digest", async () => {
  let calls = 0;
  const response = await handlePatchReview(request(input, "wrong"), { CI_INSPECTOR_TOKEN: "secret" }, async () => { calls++; return inference; });
  expect(response.status).toBe(401);
  expect(calls).toBe(0);
  const good = await handlePatchReview(request(), { CI_INSPECTOR_TOKEN: "secret" }, async () => inference);
  const receipt = await good.json();
  expect(() => admitPatchReview(input, { ...receipt, inputSha256: "0".repeat(64) })).toThrow();
});

test("existing tests and oversized patches cannot enter automatic review", () => {
  expect(patchReviewInputSchema.safeParse({ ...input, patch: [{ path: "tests/existing.rs", before: "assert!(false)", after: "assert!(true)" }] }).success).toBe(false);
  expect(patchReviewInputSchema.safeParse({ ...input, patch: [{ path: "src/value.rs", before: "x".repeat(64000), after: "y".repeat(64000) }] }).success).toBe(false);
});

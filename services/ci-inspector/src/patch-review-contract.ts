import { createHash } from "node:crypto";
import { z } from "zod";

const sha40 = z.string().regex(/^[a-f0-9]{40}$/);
const sha64 = z.string().regex(/^[a-f0-9]{64}$/);
const change = z.strictObject({
  path: z.string().regex(/^(?:src\/[A-Za-z0-9_/-]+\.rs|tests\/ai-review-[a-z0-9-]+\.rs)$/),
  before: z.string().max(64000).nullable(),
  after: z.string().min(1).max(64000),
});

export const patchReviewInputSchema = z.strictObject({
  purpose: z.literal("fix-approval"), repository: z.literal("omg-cli/omg"), branch: z.literal("main"),
  baseSha: sha40, headSha: sha40, headTreeSha: sha40, proposalSha256: sha64,
  finding: z.strictObject({ summary: z.string().min(1).max(4000), reproduction: z.string().min(1).max(4000),
    path: z.string().min(1).max(300), line: z.number().int().positive(), sourceQuote: z.string().min(1).max(4000) }),
  regression: z.strictObject({ testName: z.string().min(1).max(500), assertionFailure: z.string().min(1).max(4000),
    assertionFile: z.string().min(1).max(300), assertionLine: z.number().int().positive(), assertionSourceSha256: sha64,
    baselineExitCode: z.literal(101), patchedExitCode: z.literal(0) }),
  patch: z.array(change).min(1).max(8),
}).superRefine((input, context) => {
  if (Buffer.byteLength(JSON.stringify(input.patch)) > 64000 ||
      new Set(input.patch.map((file) => file.path)).size !== input.patch.length ||
      input.patch.some((file) => file.path.split("/").includes("..") ||
        (file.path.startsWith("tests/") && file.before !== null) || file.before === file.after))
    context.addIssue({ code: "custom", message: "Patch must be complete, bounded, unique and preserve existing tests" });
});
export type PatchReviewInput = z.infer<typeof patchReviewInputSchema>;

const finding = z.strictObject({ path: z.string().min(1).max(300), quote: z.string().min(1).max(2000), reason: z.string().min(1).max(2000) });
export const patchReviewResultSchema = z.strictObject({
  verdict: z.enum(["approved", "insufficient-evidence", "findings"]),
  reason: z.string().min(1).max(4000), findings: z.array(finding).max(3),
}).superRefine((result, context) => {
  if ((result.verdict === "findings") !== (result.findings.length > 0))
    context.addIssue({ code: "custom", message: "Only a findings verdict may contain findings" });
});
export const patchReviewReceiptSchema = z.strictObject({
  purpose: z.literal("fix-approval"), inputSha256: sha64,
  baseSha: sha40, headSha: sha40, headTreeSha: sha40, proposalSha256: sha64,
  model: z.literal("@cf/deepseek-ai/deepseek-v4.1-flash-1017"),
  readCompletePatch: z.literal(true), codeExecutions: z.number().int().min(1).max(4),
  result: patchReviewResultSchema,
});

export const patchReviewDigest = (input: PatchReviewInput) =>
  createHash("sha256").update(JSON.stringify(patchReviewInputSchema.parse(input))).digest("hex");

export function admitPatchReview(rawInput: PatchReviewInput, rawReceipt: unknown) {
  const input = patchReviewInputSchema.parse(rawInput);
  const receipt = patchReviewReceiptSchema.parse(rawReceipt);
  if (receipt.inputSha256 !== patchReviewDigest(input) ||
      ["baseSha", "headSha", "headTreeSha", "proposalSha256"].some((field) =>
        Reflect.get(receipt, field) !== Reflect.get(input, field)))
    throw new Error("Independent patch review identity mismatch");
  for (const finding of receipt.result.findings) {
    const file = input.patch.find((file) => file.path === finding.path);
    if (!file || (!file.after.includes(finding.quote) && !file.before?.includes(finding.quote)))
      throw new Error("Independent finding lacks exact patch evidence");
  }
  return receipt.result;
}

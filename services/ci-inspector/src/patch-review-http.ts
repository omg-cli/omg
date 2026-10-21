import { authorized, readBoundedJson, type InspectionRequest } from "./http";
import { patchReviewInputSchema, patchReviewDigest, patchReviewReceiptSchema, admitPatchReview,
  type PatchReviewInput } from "./patch-review-contract";
import type { z } from "zod";

export type PatchReviewInference = Pick<z.infer<typeof patchReviewReceiptSchema>, "result" | "model" | "codeExecutions"> & { readCompletePatch: boolean };

export async function handlePatchReview(request: InspectionRequest, env: { CI_INSPECTOR_TOKEN: string },
  infer: (input: PatchReviewInput) => Promise<PatchReviewInference>) {
  const respond = (data: unknown, status = 200) => Response.json(data, { status, headers: { "cache-control": "no-store" } });
  if (new URL(request.url).pathname !== "/patch-review") return respond({ error: "Not found" }, 404);
  if (request.method !== "POST") return respond({ error: "Method not allowed" }, 405);
  if (!await authorized(request, env.CI_INSPECTOR_TOKEN)) return respond({ error: "Unauthorized" }, 401);
  if (!request.headers.get("content-type")?.startsWith("application/json")) return respond({ error: "Expected application/json" }, 415);
  const body = await readBoundedJson(request, 1024 * 1024);
  if (body.kind === "error") return respond({ error: body.error }, body.status);
  const parsed = patchReviewInputSchema.safeParse(body.value);
  if (!parsed.success) return respond({ error: "Invalid complete patch" }, 400);
  if (parsed.data.purpose === "fix-approval" && body.byteLength > 128 * 1024)
    return respond({ error: "Complete patch too large" }, 413);
  try {
    const input = parsed.data;
    const inference = await infer(input);
    const receipt = patchReviewReceiptSchema.parse({ purpose: input.purpose,
      inputSha256: patchReviewDigest(input), baseSha: input.baseSha, headSha: input.headSha,
      headTreeSha: input.headTreeSha, proposalSha256: input.proposalSha256, ...inference });
    admitPatchReview(input, receipt);
    return respond(receipt);
  } catch {
    return respond({ error: "Independent patch review failed" }, 502);
  }
}

import { z } from "zod";
import { runtimeReviewRefSchema } from "./runtime-evidence";

const reference = z.strictObject({
  projectId: z.string().regex(/^[1-9][0-9]{0,19}$/),
  eventId: z.string().regex(/^[a-f0-9]{32}$/),
  bodySha256: z.string().regex(/^[a-f0-9]{64}$/),
});
const empty = z.array(z.unknown()).length(0);

export const runtimePreInferenceReportSchema = z.object({
  repository: z.literal("omg-cli/omg"), branch: z.literal("main"),
  sha: runtimeReviewRefSchema.shape.sha,
  controllerRevision: runtimeReviewRefSchema.shape.controllerRevision,
  status: z.literal("format-blocked"), formatting: z.object({ status: z.literal("blocked") }),
  sourceRange: z.object({ intake: z.literal("sentry-runtime") }),
  publishRequested: z.literal(true),
  modelInferencePerformed: z.literal(false), nativeVerificationPerformed: z.literal(false),
  publications: empty, batches: empty, candidateOutcomes: empty, readPaths: empty,
  runtimeEvents: z.array(reference).length(1), runtimeUnresolved: z.literal(false).optional(),
});

export function canRecoverRuntimeBeforeInference(raw: unknown,
  activeReview: z.infer<typeof runtimeReviewRefSchema>, event: z.infer<typeof reference>) {
  const parsed = runtimePreInferenceReportSchema.safeParse(raw);
  if (!parsed.success) return false;
  const report = parsed.data;
  const stored = report.runtimeEvents[0];
  return report.sha === activeReview.sha && report.controllerRevision === activeReview.controllerRevision &&
    stored.projectId === event.projectId && stored.eventId === event.eventId && stored.bodySha256 === event.bodySha256;
}

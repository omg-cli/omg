import { z } from "zod";

const numericId = z.string().regex(/^[1-9][0-9]{0,19}$/);
const frame = z.strictObject({
  path: z.string().max(300).regex(/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.rs$/),
  line: z.number().int().min(1).max(10000000),
});

export const runtimeEvidenceSchema = z.strictObject({
  kind: z.literal("sentry-runtime"),
  organization: z.string().min(1).max(100).regex(/^[a-zA-Z0-9_-]+$/),
  projectId: numericId,
  eventId: z.string().regex(/^[a-f0-9]{32}$/),
  issueId: numericId,
  bodySha256: z.string().regex(/^[a-f0-9]{64}$/),
  sourceSha: z.string().regex(/^[a-f0-9]{40}$/).nullable(),
  release: z.string().min(1).max(200).regex(/^[a-zA-Z0-9._+@:/-]+$/).nullable(),
  environment: z.string().min(1).max(80).regex(/^[a-zA-Z0-9._-]+$/).nullable(),
  errorTypes: z.array(z.string().min(1).max(120).regex(/^[A-Za-z_][A-Za-z0-9_:.<>-]*$/)).max(8).default([]),
  frames: z.array(frame).max(30),
});

export type RuntimeEvidence = z.infer<typeof runtimeEvidenceSchema>;

export const runtimeReviewRefSchema = z.strictObject({
  runId: numericId,
  attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
  sha: z.string().regex(/^[a-f0-9]{40}$/),
  controllerRevision: z.string().regex(/^[a-f0-9]{40}$/),
});

export const runtimeEvidencePageSchema = z.strictObject({
  events: z.array(runtimeEvidenceSchema.extend({ activeReview: runtimeReviewRefSchema.optional() })).max(50),
  cursor: z.string().min(1).max(2048).nullable(),
});

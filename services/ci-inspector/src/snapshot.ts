import { z } from "zod";

export const snapshotSchema = z
  .strictObject({
    repository: z.literal("omg-cli/omg"),
    runId: z.number().int().positive().safe(),
    branch: z.string().min(1).max(200),
    sha: z.string().regex(/^[a-f0-9]{40}$/i),
    prompt: z.string().min(1).max(2000),
    jobs: z
      .array(
        z.strictObject({
          id: z.number().int().positive().safe(),
          name: z.string().min(1).max(200),
          status: z.enum(["queued", "in_progress", "completed", "waiting", "pending", "requested"]),
          conclusion: z.string().max(40).nullable(),
          failedSteps: z
            .array(z.strictObject({ name: z.string().min(1).max(200), log: z.string().max(12000) }))
            .max(6),
        }),
      )
      .max(20),
  })
  .superRefine((snapshot, ctx) => {
    if (new Set(snapshot.jobs.map((job) => job.id)).size !== snapshot.jobs.length)
      ctx.addIssue({ code: "custom", message: "Duplicate job identifiers" });
  });

export type Snapshot = z.infer<typeof snapshotSchema>;

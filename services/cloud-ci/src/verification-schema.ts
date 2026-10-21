import { z } from "zod";

export const boundedText = (maximum: number) => z.string().min(1).max(maximum);
export const sha40 = z.string().regex(/^[a-f0-9]{40}$/);
export const sha64 = z.string().regex(/^[a-f0-9]{64}$/);

export const regressionPath = z.string().regex(/^tests\/ai-review-[a-f0-9]{16}-[a-f0-9]{12}\.rs$/);

export const sourcePath = z
    .string()
    .max(240)
    .regex(/^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.rs$/);

export const verificationSchema = z.strictObject({
    verifierRevision: sha40,
    regression: z.strictObject({
        path: regressionPath,
        testName: z
            .string()
            .regex(/^[A-Za-z_][A-Za-z0-9_]*$/)
            .max(200),
    }),
    proposal: z.strictObject({
        repository: z.literal("omg-cli/omg"),
        branch: z.literal("main"),
        baseSha: sha40,
        finding: z.strictObject({
            key: sha64,
            title: boundedText(160),
            summary: boundedText(4000),
            path: boundedText(240),
            line: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
            sourceQuote: boundedText(4000),
            reproduction: boundedText(4000),
        }),
        changes: z
            .array(
                z.strictObject({
                    path: z.union([sourcePath, regressionPath]),
                    originalBlobSha: sha40.nullable(),
                    oldContentQuote: z.string().max(4000),
                    newContent: boundedText(64000),
                    sha256: sha64,
                }),
            )
            .min(2)
            .max(8),
    }),
});

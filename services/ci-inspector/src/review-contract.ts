import { z } from "zod";

const sha = z.string().regex(/^[a-f0-9]{40}$/);

const path = z
    .string()
    .min(1)
    .max(300)
    .refine(
        (value) =>
            !value.startsWith("/") &&
            !value.includes("\\") &&
            Array.from(value).every(
                (character) => character.charCodeAt(0) > 31 && character.charCodeAt(0) !== 127,
            ) &&
            value
                .split("/")
                .every((segment) => segment !== "" && segment !== "." && segment !== ".."),
        "Invalid repository path",
    );

export const sourceReviewInputSchema = z
    .strictObject({
        repository: z.literal("omg-cli/omg"),
        sha,
        branch: z.string().min(1).max(200),
        changedPaths: z.array(path).min(1).max(30),
        diff: z.string().max(64000),
        sourceFiles: z
            .array(z.strictObject({ path, blobSha: sha, content: z.string().max(24000) }))
            .min(1)
            .max(12),
        ciFailures: z
            .array(
                z.strictObject({
                    job: z.string().min(1).max(200),
                    step: z.string().min(1).max(200),
                    log: z.string().max(8000),
                }),
            )
            .max(6)
            .default([]),
    })
    .superRefine((input, context) => {
        const paths = input.sourceFiles.map((file) => file.path);

        if (
            new Set(paths).size !== paths.length ||
            new Set(input.changedPaths).size !== input.changedPaths.length
        )
            context.addIssue({ code: "custom", message: "Duplicate paths" });
    });

const evidence = z.strictObject({
    path,
    blobSha: sha,
    lineStart: z.number().int().positive().safe(),
    lineEnd: z.number().int().positive().safe(),
    quote: z.string().min(1).max(4000),
});

const proposedFix = z.strictObject({
    edits: z
        .array(
            z.strictObject({
                path,
                oldText: z.string().min(1).max(4000),
                newText: z.string().max(6000),
            }),
        )
        .min(1)
        .max(3),
    regressionTest: z.strictObject({
        path,
        content: z.string().min(1).max(12000),
        expectedTestName: z.string().min(1).max(200),
    }),
});

const candidate = z.strictObject({
    title: z.string().min(1).max(160),
    impact: z.string().min(1).max(2000),
    evidence: z.array(evidence).min(1).max(3),
    proposedFix: proposedFix.nullable(),
});

export const sourceReviewProposalSchema = z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("no-findings"), summary: z.string().min(1).max(2000) }),
    z.strictObject({
        kind: z.literal("candidates"),
        summary: z.string().min(1).max(2000),
        candidates: z.array(candidate).min(1).max(3),
    }),
]);

export type SourceReviewInput = z.infer<typeof sourceReviewInputSchema>;

export type SourceReviewProposal = z.infer<typeof sourceReviewProposalSchema>;

export class SourceReviewFailure extends Error {
    constructor(
        readonly code:
            | "TOOL_MODEL_FAILED"
            | "SOURCE_READ_MISSING"
            | "STRUCTURED_MODEL_FAILED"
            | "EVIDENCE_REJECTED",
    ) {
        super(code);
    }
}

export function validateReviewProposal(
    input: SourceReviewInput,
    value: Parameters<typeof sourceReviewProposalSchema.parse>[0],
): SourceReviewProposal {
    const proposal = sourceReviewProposalSchema.parse(value);

    if (proposal.kind === "no-findings") return proposal;

    for (const [index, candidate] of proposal.candidates.entries()) {
        if (!candidate.evidence.some((item) => input.changedPaths.includes(item.path)))
            throw new Error("Evidence must include a changed path");

        for (const item of candidate.evidence) {
            const file = input.sourceFiles.find((source) => source.path === item.path);

            if (!file || file.blobSha !== item.blobSha)
                throw new Error("Evidence identity mismatch");

            const lines = file.content.split("\n");

            if (
                item.lineEnd < item.lineStart ||
                item.lineEnd > lines.length ||
                item.lineEnd - item.lineStart > 79 ||
                lines.slice(item.lineStart - 1, item.lineEnd).join("\n") !== item.quote
            )
                throw new Error("Evidence quote mismatch");
        }

        const fix = candidate.proposedFix;

        if (!fix) continue;

        const modified = new Map(input.sourceFiles.map((file) => [file.path, file.content]));

        for (const edit of fix.edits) {
            const content = modified.get(edit.path);

            if (
                content === undefined ||
                !/\.(?:mjs|js|jsx|ts|tsx|svelte|css|rs)$/.test(edit.path) ||
                edit.path.startsWith("tests/") ||
                edit.path.includes("/test/") ||
                edit.path.includes("/tests/") ||
                /(?:^|\/)(?:vite|vitest|eslint|oxlint|tsconfig)[^/]*$/.test(edit.path)
            )
                throw new Error("Edit path is not admitted source");

            const position = content.indexOf(edit.oldText);

            if (
                position === -1 ||
                content.indexOf(edit.oldText, position + 1) !== -1 ||
                edit.oldText === edit.newText
            )
                throw new Error("Edit must replace one exact source occurrence");

            modified.set(
                edit.path,
                content.slice(0, position) +
                    edit.newText +
                    content.slice(position + edit.oldText.length),
            );
        }

        const test = fix.regressionTest;
        const rust = fix.edits.every((edit) => edit.path.endsWith(".rs"));
        const expectedPath = rust
            ? `tests/ci-review-${input.sha.slice(0, 12)}-${index + 1}.rs`
            : `tests/unit/ci-review-${input.sha.slice(0, 12)}-${index + 1}.test.mjs`;

        if (
            test.path !== expectedPath ||
            input.sourceFiles.some((file) => file.path === test.path) ||
            input.changedPaths.includes(test.path) ||
            !test.content.includes(test.expectedTestName)
        )
            throw new Error("Regression test must use a new designated path and named case");
    }

    return proposal;
}

export async function verifySourceBlobs(input: SourceReviewInput) {
    const encoder = new TextEncoder();

    for (const file of input.sourceFiles) {
        const content = encoder.encode(file.content);
        const header = encoder.encode(`blob ${content.byteLength}\0`);
        const bytes = new Uint8Array(header.length + content.length);

        bytes.set(header);
        bytes.set(content, header.length);

        const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", bytes));
        const hash = Array.from(digest, (value) => value.toString(16).padStart(2, "0")).join("");

        if (hash !== file.blobSha) return false;
    }

    return true;
}

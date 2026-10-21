import { expect, test } from "bun:test";
import { sourceReviewInputSchema, validateReviewProposal } from "../src/review-contract";

const source = {
    repository: "omg-cli/omg",
    sha: "a".repeat(40),
    branch: "main",
    changedPaths: ["src/core/config.rs"],
    diff: "bounded Rust source review",
    sourceFiles: [
        {
            path: "src/core/config.rs",
            blobSha: "b".repeat(40),
            content: "pub fn value() -> u8 { 1 }",
        },
    ],
};

test("OMG inspector admits its Rust source and rejects CodeLoud source identity", () => {
    expect(sourceReviewInputSchema.safeParse(source).success).toBe(true);
    expect(
        sourceReviewInputSchema.safeParse({ ...source, repository: "CodeLoud/codeloud-desktop" })
            .success,
    ).toBe(false);
});

test("Rust review accepts a production repair and a new standalone regression", () => {
    const proposal = {
        kind: "candidates" as const,
        summary: "Candidate requires real Rust verification.",
        candidates: [
            {
                title: "Wrong config value",
                impact: "Callers receive one instead of two.",
                evidence: [
                    {
                        path: source.changedPaths[0],
                        blobSha: "b".repeat(40),
                        lineStart: 1,
                        lineEnd: 1,
                        quote: source.sourceFiles[0].content,
                    },
                ],
                proposedFix: {
                    edits: [{ path: source.changedPaths[0], oldText: "{ 1 }", newText: "{ 2 }" }],
                    regressionTest: {
                        path: `tests/ci-review-${source.sha.slice(0, 12)}-1.rs`,
                        expectedTestName: "config_value",
                        content: "#[test]\nfn config_value() { assert_eq!(omg_lib::value(), 2); }",
                    },
                },
            },
        ],
    };
    expect(validateReviewProposal(sourceReviewInputSchema.parse(source), proposal)).toEqual(
        proposal,
    );
});

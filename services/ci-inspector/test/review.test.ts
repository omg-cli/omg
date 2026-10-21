import { expect, test } from "bun:test";
import {
  sourceReviewInputSchema,
  sourceReviewProposalSchema,
  validateReviewProposal,
  verifySourceBlobs,
  type SourceReviewProposal,
} from "../src/review-contract";

const input = sourceReviewInputSchema.parse({
  repository: "omg-cli/omg",
  sha: "a".repeat(40),
  branch: "main",
  changedPaths: ["src/value.mjs"],
  diff: "+export const value = 0;",
  sourceFiles: [
    { path: "src/value.mjs", blobSha: "b".repeat(40), content: "export const value = 0;\n" },
  ],
});

const candidate = {
  title: "Wrong default",
  impact: "Consumers receive zero.",
  evidence: [
    {
      path: "src/value.mjs",
      blobSha: "b".repeat(40),
      lineStart: 1,
      lineEnd: 1,
      quote: "export const value = 0;",
    },
  ],
  proposedFix: {
    edits: [{ path: "src/value.mjs", oldText: "value = 0", newText: "value = 1" }],
    regressionTest: {
      path: `tests/unit/ci-review-${input.sha.slice(0, 12)}-1.test.mjs`,
      content: 'import { test } from "bun:test";\ntest("default is one", () => {});',
      expectedTestName: "default is one",
    },
  },
};

test("source audits preserve honest input identity and accept only exact audited source evidence", () => {
  const audit = { ...input, changedPaths: [], diff: "", auditPaths: ["src/value.mjs"] };
  expect(sourceReviewInputSchema.parse(audit)).toEqual(audit);
  expect(validateReviewProposal(sourceReviewInputSchema.parse(audit), proposal())).toEqual(proposal());
  expect(sourceReviewInputSchema.safeParse({ ...audit, auditPaths: ["src/other.mjs"] }).success).toBe(false);
  expect(sourceReviewInputSchema.safeParse({ ...audit, changedPaths: ["src/value.mjs"] }).success).toBe(false);
  expect(sourceReviewInputSchema.safeParse({ ...audit, diff: "+fabricated" }).success).toBe(false);
  expect(sourceReviewInputSchema.safeParse({ ...input, changedPaths: [] }).success).toBe(false);
  expect(sourceReviewInputSchema.parse(input)).toEqual(input);
  expect(sourceReviewInputSchema.parse(input)).not.toHaveProperty("auditPaths");
  expect(() => validateReviewProposal(sourceReviewInputSchema.parse(audit), proposal({
    evidence: [{ ...candidate.evidence[0], quote: "fabricated source" }],
  }))).toThrow("Evidence quote");
});

function proposal(update: Partial<typeof candidate> = {}) {
  return {
    kind: "candidates",
    summary: "Candidate only.",
    candidates: [{ ...candidate, ...update }],
  } satisfies SourceReviewProposal;
}

test("review accepts exact evidence and preserves an uncorroborated proposal", () => {
  expect(validateReviewProposal(input, proposal())).toEqual(proposal());
  expect(
    validateReviewProposal(input, { kind: "no-findings", summary: "No supported finding." }),
  ).toEqual({ kind: "no-findings", summary: "No supported finding." });
});

test("review rejects invented quote, line and blob identities", () => {
  for (const evidence of [
    [{ ...candidate.evidence[0], quote: "invented code" }],
    [{ ...candidate.evidence[0], lineStart: 2, lineEnd: 2 }],
    [{ ...candidate.evidence[0], blobSha: "c".repeat(40) }],
  ])
    expect(() => validateReviewProposal(input, proposal({ evidence }))).toThrow("Evidence");
});

test("review rejects edits not present in a supplied source file", () => {
  expect(() =>
    validateReviewProposal(
      input,
      proposal({
        proposedFix: {
          ...candidate.proposedFix,
          edits: [{ path: "src/value.mjs", oldText: "imaginary", newText: "replacement" }],
        },
      }),
    ),
  ).toThrow("Edit");
});

test("review rejects regression tests that overwrite existing files or escape naming", () => {
  expect(() =>
    validateReviewProposal(
      input,
      proposal({
        proposedFix: {
          ...candidate.proposedFix,
          regressionTest: { ...candidate.proposedFix.regressionTest, path: "src/value.mjs" },
        },
      }),
    ),
  ).toThrow("Regression");
});

test("review rejects source content with a fabricated Git blob hash", async () => {
  expect(await verifySourceBlobs(input)).toBe(false);
});

test("review limits candidate count and rejects model publication commands", () => {
  expect(
    sourceReviewProposalSchema.safeParse({
      kind: "candidates",
      summary: "Too many",
      candidates: [candidate, candidate, candidate, candidate],
    }).success,
  ).toBe(false);
  expect(
    sourceReviewProposalSchema.safeParse({ ...proposal(), commands: ["git push"] }).success,
  ).toBe(false);
});

test("review input admits no traversal source paths", () => {
  expect(
    sourceReviewInputSchema.safeParse({
      ...input,
      sourceFiles: [{ ...input.sourceFiles[0], path: "../secret.mjs" }],
    }).success,
  ).toBe(false);
});

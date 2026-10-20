import { test, expect } from "bun:test";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { proposalDigest, sha256 } from "../../../scripts/ai-review-publication.mjs";
import type { SourceReviewProposal } from "../../ci-inspector/src/review-contract";
import { createCoderProposal, type CoderProposalRequest } from "../src/proposal";

function fixture() {
  const content = "pub const VALUE: u32 = 1;\n";
  const sha = "a".repeat(40);

  const request: CoderProposalRequest = {
    repository: "omg-cli/omg",
    sha,
    branch: "main",
    runId: "42",
    attempt: "1",
    source: {
      repository: "omg-cli/omg",
      sha,
      branch: "main",
      changedPaths: ["src/value.rs"],
      diff: "-pub const VALUE: u32 = 1;\n+pub const VALUE: u32 = 2;\n",
      sourceFiles: [{ path: "src/value.rs", blobSha: gitBlobSha(content), content }],
      ciFailures: [],
    },
  };

  const candidate: SourceReviewProposal = {
    kind: "candidates",
    summary: "A value regression candidate.",
    candidates: [
      {
        title: "Wrong exported value",
        impact: "Consumers receive one instead of two.",
        evidence: [
          {
            path: "src/value.rs",
            blobSha: gitBlobSha(content),
            lineStart: 1,
            lineEnd: 1,
            quote: "pub const VALUE: u32 = 1;",
          },
        ],
        proposedFix: {
          edits: [{ path: "src/value.rs", oldText: "VALUE: u32 = 1", newText: "VALUE: u32 = 2" }],
          regressionTest: {
            path: `tests/ci-review-${sha.slice(0, 12)}-1.rs`,
            content:
              '#[path = "../src/value.rs"] mod value; #[test] fn value_is_two() { assert_eq!(value::VALUE, 2); }\n',
            expectedTestName: "value_is_two",
          },
        },
      },
    ],
  };

  return { request, candidate };
}

test("coder proposal binds declared source and complete replacement bytes without executing or formatting them", () => {
  const { request, candidate } = fixture();
  const original = JSON.stringify({ request, candidate });
  const result = createCoderProposal(request, candidate);

  expect(result.proposal.baseSha).toBe(request.sha);
  expect(result.proposal.branch).toBe("main");
  expect(result.proposal.changes[0].newContent).toBe("pub const VALUE: u32 = 2;\n");
  expect(result.proposal.changes[0].sha256).toBe(sha256("pub const VALUE: u32 = 2;\n"));
  expect(result.proposalSha256).toBe(proposalDigest(result.proposal));
  expect(result.regression.testName).toBe("value_is_two");
  expect(result.regression.path).toMatch(
    /^tests\/ai-review-[a-f0-9]{16}-aaaaaaaaaaaa\.rs$/,
  );
  expect(JSON.stringify({ request, candidate })).toBe(original);
});

test("coder proposal rejects wrapper repository, branch, commit and run identity substitutions", () => {
  for (const replacement of [
    { repository: "attacker/fork" },
    { sha: "b".repeat(40) },
    { branch: "unauthorized" },
    { sha: "main" },
    { runId: "0" },
    { attempt: "1/other" },
  ]) {
    const { request, candidate } = fixture();
    expect(() => createCoderProposal({ ...request, ...replacement }, candidate)).toThrow();
  }
});

test("coder proposal rejects forged Git blob contents and source evidence quotes", () => {
  const { request, candidate } = fixture();
  request.source.sourceFiles[0].content = "pub const VALUE: u32 = 7;\n";
  expect(() => createCoderProposal(request, candidate)).toThrow();
  const altered = fixture();

  if (altered.candidate.kind !== "candidates") throw new Error("Fixture requires one candidate");
  altered.candidate.candidates[0].evidence[0].quote = "invented source";
  expect(() => createCoderProposal(altered.request, altered.candidate)).toThrow();
});

test("coder proposal rejects multiple or missing fixes and protected source targets", () => {
  const { request, candidate } = fixture();

  if (candidate.kind !== "candidates") throw new Error("Fixture requires one candidate");
  expect(() =>
    createCoderProposal(request, {
      ...candidate,
      candidates: [candidate.candidates[0], candidate.candidates[0]],
    }),
  ).toThrow();
  expect(() => createCoderProposal(request, { kind: "no-findings", summary: "No fix" })).toThrow();
  const item = candidate.candidates[0];
  expect(() =>
    createCoderProposal(request, { ...candidate, candidates: [{ ...item, proposedFix: null }] }),
  ).toThrow();
  const fix = item.proposedFix;

  if (!fix) throw new Error("Fixture requires a fix");

  for (const path of [
    ".github/workflows/ci.yml",
    "services/ci-coder/src/proposal.ts",
    "tests/unit/existing.test.mjs",
  ]) {
    expect(() =>
      createCoderProposal(request, {
        ...candidate,
        candidates: [{ ...item, proposedFix: { ...fix, edits: [{ ...fix.edits[0], path }] } }],
      }),
    ).toThrow();
  }
});

test("coder proposal rejects a regression test already supplied in the snapshot", () => {
  const { request, candidate } = fixture();

  if (candidate.kind !== "candidates" || !candidate.candidates[0].proposedFix)
    throw new Error("Fixture requires a fix");
  const regression = candidate.candidates[0].proposedFix.regressionTest;
  request.source.sourceFiles.push({
    path: regression.path,
    content: regression.content,
    blobSha: gitBlobSha(regression.content),
  });
  expect(() => createCoderProposal(request, candidate)).toThrow();
});

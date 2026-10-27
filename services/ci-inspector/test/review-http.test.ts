import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { handleSourceReview } from "../src/review-http";
import { sourceReviewProposalSchema } from "../src/review-contract";

const content = "export const value = 0;\n";

const blobSha = createHash("sha1")
  .update(`blob ${Buffer.byteLength(content)}\0${content}`)
  .digest("hex");

const payload = {
  repository: "omg-cli/omg",
  sha: "a".repeat(40),
  branch: "main",
  changedPaths: ["src/value.mjs"],
  diff: "+export const value = 0;",
  sourceFiles: [{ path: "src/value.mjs", blobSha, content }],
};

const env = { CI_INSPECTOR_TOKEN: "owner-secret" };

const proposal = sourceReviewProposalSchema.parse({
  kind: "no-findings",
  summary: "No supported finding.",
});

test("reported issue cannot become no-findings without its exact evidence read receipt", async () => {
  const body = {...payload, ciFailures: [{job: "GitHub issue #1011", step: "untrusted issue report", log: "Inspect src/value.mjs:1"}]};
  const inference = {proposal, model: "fixture", usage: {}, codeExecutions: 1,
    sourceToolCalls: 1, readPaths: ["src/value.mjs"], readDiff: true};
  for (const readCiFailures of [undefined, [], [1], [0, 0]]) {
    const response = await handleSourceReview(request(body), env, async () => ({...inference, readCiFailures}));
    expect(response.status).toBe(502);
  }
  const response = await handleSourceReview(request(body), env, async () => ({...inference, readCiFailures: [0]}));
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({kind: "no-findings", readCiFailures: [0]});
});

function request(
  body: Parameters<typeof JSON.stringify>[0] = payload,
  token = env.CI_INSPECTOR_TOKEN,
) {
  return new Request("https://worker.example/review", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("review authenticates before invoking a model", async () => {
  let calls = 0;

  const response = await handleSourceReview(request(payload, "wrong"), env, async () => {
    calls++;

    return {
      proposal,
      model: "fixture",
      usage: {},
      codeExecutions: 1,
      sourceToolCalls: 1,
      readPaths: ["src/value.mjs"],
      readDiff: true,
    };
  });

  expect(response.status).toBe(401);
  expect(calls).toBe(0);
});

test("review rejects different repositories and fabricated source blobs before inference", async () => {
  let calls = 0;

  const inference = async () => {
    calls++;

    return {
      proposal,
      model: "fixture",
      usage: {},
      codeExecutions: 1,
      sourceToolCalls: 1,
      readPaths: ["src/value.mjs"],
      readDiff: true,
    };
  };

  expect(
    (await handleSourceReview(request({ ...payload, repository: "other/repo" }), env, inference))
      .status,
  ).toBe(400);
  expect(
    (
      await handleSourceReview(
        request({
          ...payload,
          sourceFiles: [{ ...payload.sourceFiles[0], blobSha: "b".repeat(40) }],
        }),
        env,
        inference,
      )
    ).status,
  ).toBe(400);
  expect(calls).toBe(0);
});

test("review returns structured uncorroborated output with exact request identity", async () => {
  const response = await handleSourceReview(request(), env, async () => ({
    proposal,
    model: "fixture",
    usage: { outputTokens: 10 },
    codeExecutions: 1,
    sourceToolCalls: 1,
    readPaths: ["src/value.mjs"],
    readDiff: true,
  }));

  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({
    repository: payload.repository,
    sha: payload.sha,
    branch: "main",
    ...proposal,
    publication: "requires-verifier",
    suppliedPaths: ["src/value.mjs"],
    model: "fixture",
    usage: { outputTokens: 10 },
    codeExecutions: 1,
    sourceToolCalls: 1,
    readPaths: ["src/value.mjs"],
    readDiff: true,
    readCiFailures: [],
  });
});

test("review rejects oversized input before inference", async () => {
  let calls = 0;

  const response = await handleSourceReview(
    request({ ...payload, diff: "x".repeat(530000) }),
    env,
    async () => {
      calls++;

      return {
        proposal,
        model: "fixture",
        usage: {},
        codeExecutions: 1,
        sourceToolCalls: 1,
        readPaths: ["src/value.mjs"],
        readDiff: true,
      };
    },
  );

  expect(response.status).toBe(413);
  expect(calls).toBe(0);
});

test("review rejects summaries without actual source tool execution", async () => {
  const response = await handleSourceReview(request(), env, async () => ({
    proposal,
    model: "fixture",
    usage: {},
    codeExecutions: 1,
    sourceToolCalls: 0,
    readPaths: [],
    readDiff: false,
  }));

  expect(response.status).toBe(502);
});

test("review never returns an invented finding as a validated candidate", async () => {
  const invented = sourceReviewProposalSchema.parse({
    kind: "candidates",
    summary: "Uncorroborated",
    candidates: [
      {
        title: "Bug",
        impact: "Bad result",
        evidence: [
          { path: "src/value.mjs", blobSha, lineStart: 1, lineEnd: 1, quote: "imaginary code" },
        ],
        proposedFix: null,
      },
    ],
  });

  const response = await handleSourceReview(request(), env, async () => ({
    proposal: invented,
    model: "fixture",
    usage: {},
    codeExecutions: 1,
    sourceToolCalls: 1,
    readPaths: ["src/value.mjs"],
    readDiff: true,
  }));

  expect(response.status).toBe(502);
  expect(await response.json()).toEqual({ error: "Source review failed", code: "REVIEW_REJECTED" });
});

test("review marks exact source candidates uncorroborated and requires external proof", async () => {
  const found = sourceReviewProposalSchema.parse({
    kind: "candidates",
    summary: "Uncorroborated",
    candidates: [
      {
        title: "Bug",
        impact: "Bad result",
        evidence: [
          {
            path: "src/value.mjs",
            blobSha,
            lineStart: 1,
            lineEnd: 1,
            quote: "export const value = 0;",
          },
        ],
        proposedFix: null,
      },
    ],
  });

  const response = await handleSourceReview(request(), env, async () => ({
    proposal: found,
    model: "fixture",
    usage: {},
    codeExecutions: 1,
    sourceToolCalls: 1,
    readPaths: ["src/value.mjs"],
    readDiff: true,
  }));

  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    publication: "requires-verifier",
    suppliedPaths: ["src/value.mjs"],
    kind: "candidates",
    candidates: [{ verification: "uncorroborated" }],
  });
});

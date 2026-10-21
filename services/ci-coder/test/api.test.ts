import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import type { SourceReviewProposal } from "../../ci-inspector/src/review-contract";
import {
  handleCoderRequest,
  parseCodingRequest,
  operationIdentity,
  storedOperationIdentity,
} from "../src/request";

const sourceText = "pub const VALUE: u32 = 1;";

const blobSha = createHash("sha1")
  .update(`blob ${Buffer.byteLength(sourceText)}\0`)
  .update(sourceText)
  .digest("hex");

const input = {
  repository: "omg-cli/omg",
  sha: "a".repeat(40),
  branch: "main",
  runId: "123",
  attempt: "1",
  source: {
    repository: "omg-cli/omg",
    sha: "a".repeat(40),
    branch: "main",
    changedPaths: ["src/bug.rs"],
    diff: "diff",
    sourceFiles: [{ path: "src/bug.rs", blobSha, content: sourceText }],
  },
};

test("coding requests bind source identity and reject arbitrary instructions", () => {
  const request = parseCodingRequest(input);
  expect(operationIdentity(request)).toMatch(new RegExp(`^cl-123-1-${input.sha}-s-[a-f0-9]{64}$`));
  expect(() => parseCodingRequest({ ...input, instruction: "run shell" })).toThrow();
  expect(() =>
    parseCodingRequest({ ...input, source: { ...input.source, sha: "c".repeat(40) } }),
  ).toThrow();
  expect(() => parseCodingRequest({ ...input, runId: "99999999999999999999" })).toThrow();
  expect(() => parseCodingRequest({ ...input, repository: "CodeLoud/codeloud-desktop" })).toThrow();
  expect(() => parseCodingRequest({ ...input, branch: "attacker-branch" })).toThrow();
});

test("missing mandatory skills blocks API admission before any durable operation starts", async () => {
  let starts = 0;

  const env = {
    CODER_API_TOKEN: "fixture-token",
    CODER: {
      getByName: () => ({
        start: async () => {
          starts++;

          return { accepted: true, id: "unexpected" };
        },
        status: async () => ({ id: "unused", status: "queued" }),
      }),
    },
  };

  const response = await handleCoderRequest(
    new Request("https://coder.test/operations", {
      method: "POST",
      headers: { Authorization: "Bearer fixture-token" },
      body: JSON.stringify(input),
    }),
    env,
    () => {
      throw new Error("Missing mandatory skill bundle");
    },
  );

  expect(response.status).toBe(503);
  expect(starts).toBe(0);
  expect(await response.text()).not.toContain("Missing mandatory skill bundle");
});

test("authentication and bounded JSON precede operation dispatch", async () => {
  let starts = 0;

  const env = {
    CODER_API_TOKEN: "fixture-token",
    CODER: {
      getByName: (id: string) => ({
        start: async () => {
          starts++;

          return { accepted: true, id };
        },
        status: async () => ({ id, status: "queued" }),
      }),
    },
  };

  const send = (body: string, token = "fixture-token") =>
    handleCoderRequest(
      new Request("https://coder.test/operations", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body,
      }),
      env,
      () => {},
    );

  expect((await send(JSON.stringify(input), "wrong")).status).toBe(401);
  expect((await send(" ".repeat(512 * 1024 + 1))).status).toBe(413);
  expect(
    (
      await send(
        JSON.stringify({
          ...input,
          source: {
            ...input.source,
            sourceFiles: input.source.sourceFiles.map((file) => ({
              ...file,
              blobSha: "b".repeat(40),
            })),
          },
        }),
      )
    ).status,
  ).toBe(400);
  const response = await send(JSON.stringify(input));
  expect(response.status).toBe(202);
  expect(await response.json()).toMatchObject({
    id: operationIdentity(parseCodingRequest(input)),
    accepted: true,
  });
  expect(starts).toBe(1);
});

test("operation identities distinguish source batches and hypotheses without altering the real run", () => {
  const first = parseCodingRequest(input);
  const repeated = parseCodingRequest(JSON.parse(JSON.stringify(input)));

  const anotherBatch = parseCodingRequest({
    ...input,
    source: { ...input.source, diff: "another batch" },
  });

  const hypothesis = { kind: "no-findings", summary: "Inspect this source again" };
  const anotherHypothesis = parseCodingRequest({ ...input, hypothesis });
  expect(operationIdentity(first)).toBe(operationIdentity(repeated));
  expect(operationIdentity(first)).not.toBe(operationIdentity(anotherBatch));
  expect(operationIdentity(first)).not.toBe(operationIdentity(anotherHypothesis));
  expect(anotherHypothesis.runId).toBe(input.runId);
  expect(() =>
    parseCodingRequest({ ...input, hypothesis: { ...hypothesis, command: "shell" } }),
  ).toThrow();
});

test("hypothesis source evidence must match the admitted exact snapshot", () => {
  const hypothesis: SourceReviewProposal = {
    kind: "candidates",
    summary: "Fixture hypothesis",
    candidates: [
      {
        title: "Fixture",
        impact: "Fixture impact",
        proposedFix: null,
        evidence: [{ path: "src/bug.rs", blobSha, lineStart: 1, lineEnd: 1, quote: sourceText }],
      },
    ],
  };

  expect(parseCodingRequest({ ...input, hypothesis, candidateIndex: 0 }).hypothesis).toEqual(
    hypothesis,
  );
  expect(() =>
    parseCodingRequest({
      ...input,
      hypothesis: {
        ...hypothesis,
        candidates: [
          {
            ...hypothesis.candidates[0],
            evidence: [{ ...hypothesis.candidates[0].evidence[0], quote: "forged" }],
          },
        ],
      },
    }),
  ).toThrow();
});

test("status retrieves only the snapshot-specific operation identity", async () => {
  const id = operationIdentity(parseCodingRequest(input));
  let lookups = 0;

  const env = {
    CODER_API_TOKEN: "fixture-token",
    CODER: {
      getByName: (name: string) => {
        lookups++;

        return {
          start: async () => ({ id: name, accepted: true }),
          status: async () => ({ id: name, status: "queued" }),
        };
      },
    },
  };

  const get = (identity: string) =>
    handleCoderRequest(
      new Request(`https://coder.test/operations/${identity}`, {
        headers: { Authorization: "Bearer fixture-token" },
      }),
      env,
      () => {},
    );

  expect((await get(`cl-123-1-${input.sha}`)).status).toBe(404);
  const response = await get(id);
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ id, status: "queued" });
  expect(lookups).toBe(1);
});

test("second-candidate hypotheses preserve their original regression path and exact selected identity", () => {
  const hypothesis: SourceReviewProposal = {
    kind: "candidates",
    summary: "Two source-supported fixture candidates",
    candidates: [0, 1].map((index) => ({
      title: `Candidate ${index + 1}`,
      impact: "Fixture impact",
      evidence: [{ path: "src/bug.rs", blobSha, lineStart: 1, lineEnd: 1, quote: sourceText }],
      proposedFix: {
        edits: [{ path: "src/bug.rs", oldText: sourceText, newText: "pub const VALUE: u32 = 2;" }],
        regressionTest: {
          path: `tests/ci-review-${input.sha.slice(0, 12)}-${index + 1}.rs`,
          content: '#[test] fn regression() { assert_eq!(2, 2); }',
          expectedTestName: "regression",
        },
      },
    })),
  };

  const first = parseCodingRequest({ ...input, hypothesis, candidateIndex: 0 });
  const second = parseCodingRequest({ ...input, hypothesis, candidateIndex: 1 });
  expect(second.candidateIndex).toBe(1);
  expect(second.hypothesis).toEqual(hypothesis);
  expect(operationIdentity(first)).not.toBe(operationIdentity(second));
  expect(() => parseCodingRequest({ ...input, hypothesis })).toThrow();
  expect(() => parseCodingRequest({ ...input, hypothesis, candidateIndex: 2 })).toThrow();
  expect(() => parseCodingRequest({ ...input, hypothesis, candidateIndex: -1 })).toThrow();
  expect(() => parseCodingRequest({ ...input, hypothesis, candidateIndex: 0.5 })).toThrow();
  expect(() => parseCodingRequest({ ...input, candidateIndex: 0 })).toThrow();
  expect(() =>
    parseCodingRequest({
      ...input,
      hypothesis: { kind: "no-findings", summary: "Fixture" },
      candidateIndex: 0,
    }),
  ).toThrow();
});

test("named durable status retains the submitted operation across identity algorithm revisions", () => {
  const request = parseCodingRequest(input);
  const previousName = `cl-${request.runId}-${request.attempt}-${request.sha}-s-${"d".repeat(64)}`;
  expect(storedOperationIdentity(previousName, request)).toBe(previousName);
  expect(() => storedOperationIdentity(undefined, request)).toThrow();
  expect(() => storedOperationIdentity("unnamed", request)).toThrow();
  expect(() =>
    storedOperationIdentity(previousName.replace("cl-123-", "cl-124-"), request),
  ).toThrow();
});

import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import { runtimeServer } from "./fixtures/runtime-server.mjs";
import { collectRuntimeSources } from "../../scripts/sentry-review-input.mjs";
import { runReviewFlow } from "../../scripts/ai-review-flow.mjs";

const sha = "a".repeat(40);
const reviewRef = { runId: "123", attempt: "1", sha, controllerRevision: "e".repeat(40) };
const content = "pub fn value() -> u8 { 1 }\n";
const blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex");

function eventPayload(eventId) {
  return { action: "triggered", data: { event: {
    event_id: eventId, issue_id: "12345", project: 789,
    url: `https://sentry.io/api/0/projects/omg-org/omg/events/${eventId}/`,
    environment: "production", release: "omg@0.1.223",
    exception: { values: [{ type: "CacheError", stacktrace: {
      frames: [{ filename: "src/value.rs", lineno: 1 }],
    } }] },
  } } };
}

function githubSource(onRequest = () => {}, activeReview, onMetadata = () => {}) {
  return { async request(_method, route) {
    if (activeReview && route === `/repos/omg-cli/omg/actions/runs/${activeReview.runId}/attempts/${activeReview.attempt}`) {
      onMetadata();
      return { id: Number(activeReview.runId), run_attempt: Number(activeReview.attempt), status: "in_progress",
        repository: { full_name: "omg-cli/omg" }, path: ".github/workflows/ai-review.yml",
        head_branch: "main", head_sha: activeReview.sha };
    }
    onRequest();
    if (route.endsWith(`/git/commits/${sha}`)) return { tree: { sha: "f".repeat(40) } };
    if (route.includes("/git/trees/")) return { truncated: false, tree: [{
      path: "src/value.rs", mode: "100644", type: "blob", sha: blobSha, size: Buffer.byteLength(content),
    }] };
    if (route.endsWith(`/git/blobs/${blobSha}`)) return { encoding: "base64", content: Buffer.from(content).toString("base64") };
    throw new Error("Unexpected GitHub source route");
  } };
}

test("actual signed intake, durable poll and helper reservation move past stale work without reinference", async () => {
  const server = runtimeServer();
  const firstId = "b".repeat(32);
  const secondId = "c".repeat(32);
  expect((await server.signedSend(eventPayload(firstId))).status).toBe(202);
  const first = await server.request(new URL(`/sentry/events/789/${firstId}`, server.endpoint), server.token);
  const activeReview = { ...reviewRef, runId: "99", sha: "d".repeat(40) };
  await server.request(new URL(`/sentry/events/789/${firstId}/reserve`, server.endpoint), server.token,
    JSON.stringify({ bodySha256: first.bodySha256, activeReview, expectedActiveReview: null }));
  expect((await server.signedSend(eventPayload(secondId))).status).toBe(202);
  let sourceCalls = 0;
  let metadataCalls = 0;
  const options = { ...server, sha, reviewRef,
    github: githubSource(() => { sourceCalls++; }, activeReview, () => { metadataCalls++; }) };
  const held = await collectRuntimeSources(options);
  expect(held.replayRef).toEqual(activeReview);
  expect(sourceCalls).toBe(0);
  expect(metadataCalls).toBe(1);
  const fresh = await collectRuntimeSources(options);
  expect(fresh.runtimeEvents[0].eventId).toBe(secondId);
  expect(fresh.entries).toEqual([{ path: "src/value.rs", blobSha, content }]);
  expect(fresh.runtimeEvidence[0]).not.toHaveProperty("activeReview");
  const secondPending = JSON.parse(server.objects.get(`sentry/pending/789/${secondId}.json`));
  expect(secondPending.activeReview).toEqual(reviewRef);
  const wrapped = await collectRuntimeSources(options);
  expect(wrapped.replayRef).toEqual(activeReview);
  expect(server.objects.has(`sentry/events/789/${firstId}.json`)).toBe(true);
  expect(server.requests.some(({ path, method }) => path === "/sentry/poll" && method === "POST")).toBe(true);
});

test("runtime preview reads evidence without claiming work or moving the durable poll cursor", async () => {
  const server = runtimeServer();
  const eventId = "b".repeat(32);
  await server.signedSend(eventPayload(eventId));
  const preview = await collectRuntimeSources({ ...server, github: githubSource(), sha, reviewRef, reserve: false });
  expect(preview.entries).toEqual([{ path: "src/value.rs", blobSha, content }]);
  expect(JSON.parse(server.objects.get(`sentry/pending/789/${eventId}.json`))).not.toHaveProperty("activeReview");
  expect(server.objects.has("sentry/poll-cursor.json")).toBe(false);
  expect(server.requests.some(({ method }) => method === "POST")).toBe(false);
  await runReviewFlow({ target: { branch: "main", sha, publish: false, range: { kind: "runtime" } }, io: {
    head: async () => sha,
    collect: (_sha, _branch, _range, options) => collectRuntimeSources({ ...server, github: githubSource(), sha, reviewRef, ...options }),
    format: async () => ({ status: "blocked", reason: "formatting unavailable" }),
  } });
  expect(JSON.parse(server.objects.get(`sentry/pending/789/${eventId}.json`))).not.toHaveProperty("activeReview");
  expect(server.objects.has("sentry/poll-cursor.json")).toBe(false);
  const claimed = await collectRuntimeSources({ ...server, github: githubSource(), sha, reviewRef });
  expect(claimed.runtimeEvents).toEqual(preview.runtimeEvents);
});

test("an exact completed pre-inference format block can be reclaimed without deleting its durable record", async () => {
  const server = runtimeServer();
  const eventId = "b".repeat(32);
  await server.signedSend(eventPayload(eventId));
  const blocked = await runReviewFlow({ target: { branch: "main", sha, publish: true, range: { kind: "runtime" } }, io: {
    head: async () => sha,
    collect: (_sha, _branch, _range, options) => collectRuntimeSources({ ...server, github: githubSource(), sha, reviewRef, ...options }),
    format: async () => ({ status: "blocked", reason: "formatting unavailable" }),
  } });
  expect(blocked.runtimeEvents).toHaveLength(1);
  expect(blocked.modelInferencePerformed).toBe(false);
  blocked.controllerRevision = reviewRef.controllerRevision;
  await server.request(new URL("/review-records/123-1", server.endpoint), server.token,
    JSON.stringify({ repository: "omg-cli/omg", runId: "123", attempt: "1", report: blocked }));
  const originalRecord = server.objects.get("reviews/123-1/review.json");
  const source = githubSource();
  let metadataCalls = 0;
  const github = { request: (method, route) => {
    if (route === "/repos/omg-cli/omg/actions/runs/123/attempts/1") {
      metadataCalls++;
      return Promise.resolve({ id: 123, run_attempt: 1, status: "completed", conclusion: "success",
        repository: { full_name: "omg-cli/omg" }, path: ".github/workflows/ai-review.yml", head_branch: "main", head_sha: sha });
    }
    return source.request(method, route);
  } };
  const nextRef = { ...reviewRef, runId: "124" };
  const recovered = await collectRuntimeSources({ ...server, github, sha, reviewRef: nextRef });
  expect(metadataCalls).toBe(1);
  expect(recovered.entries).toEqual([{ path: "src/value.rs", blobSha, content }]);
  expect(JSON.parse(server.objects.get(`sentry/pending/789/${eventId}.json`)).activeReview).toEqual(nextRef);
  expect(server.objects.get("reviews/123-1/review.json")).toBe(originalRecord);
  expect(server.objects.has(`sentry/events/789/${eventId}.json`)).toBe(true);
});

test("a source-provider crash leaves a real reservation that another run cannot silently replace", async () => {
  const server = runtimeServer();
  const eventId = "b".repeat(32);
  await server.signedSend(eventPayload(eventId));
  const options = { ...server, sha, reviewRef, github: githubSource(() => { throw new Error("GitHub unavailable"); }) };
  await expect(collectRuntimeSources(options)).rejects.toThrow("GitHub unavailable");
  const pendingKey = `sentry/pending/789/${eventId}.json`;
  expect(JSON.parse(server.objects.get(pendingKey)).activeReview).toEqual(reviewRef);
  const nextOwner = { ...reviewRef, runId: "124" };
  let metadataCalls = 0;
  let sourceCalls = 0;
  const retry = await collectRuntimeSources({ ...options, reviewRef: nextOwner,
    github: githubSource(() => { sourceCalls++; throw new Error("Must not re-infer or read source for another active owner"); },
      reviewRef, () => { metadataCalls++; }),
  });
  expect(metadataCalls).toBe(1);
  expect(sourceCalls).toBe(0);
  expect(retry.replayRef).toEqual(reviewRef);
  expect(JSON.parse(server.objects.get(pendingKey)).activeReview).toEqual(reviewRef);
});

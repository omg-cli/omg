import { expect, test } from "bun:test";
import { fetchCi } from "../src/http";
import { runtimeEvidenceSchema, runtimeEvidencePageSchema } from "../../ci-inspector/src/runtime-evidence";

const secret = "fixture-sentry-webhook-secret-32-characters";
const eventId = "b".repeat(32);
const payload = {
  action: "triggered",
  installation: { uuid: "11111111-1111-4111-8111-111111111111" },
  data: {
    event: {
      event_id: eventId,
      issue_id: "12345",
      project: 789,
      url: `https://sentry.io/api/0/projects/omg-org/omg/events/${eventId}/`,
      release: "v0.1.223",
      environment: "production",
      tags: [["source_sha", "a".repeat(40)]],
      exception: { values: [{
        type: "panic",
        value: "private-token-must-not-leave-intake",
        stacktrace: { frames: [
          { filename: "src/core/cache.rs", lineno: 12, vars: { token: "private-value" } },
          { filename: "/home/private/src/lib.rs", lineno: 2 },
          { filename: "src/../../private.rs", lineno: 3 },
        ] },
      }] },
      user: { email: "private@example.test" },
      request: { url: "https://attacker.test/do-not-fetch", headers: { Authorization: "secret" } },
      extra: { command: "do-not-execute" },
    },
  },
};

async function signed(body: string) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)))]
    .map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function fixture() {
  const objects = new Map<string, string>();
  const env = {
    CI_API_TOKEN: "owner-api-token",
    SENTRY_WEBHOOK_SECRET: secret,
    SENTRY_ORG_SLUG: "omg-org",
    SENTRY_PROJECT_SLUG: "omg",
    SENTRY_PROJECT_ID: "789",
    SENTRY_ENVIRONMENT: "production",
    BACKUP_BUCKET: {
      async delete(key: string) { objects.delete(key); },
      async list(options: { prefix: string; limit: number; cursor?: string }) {
        const keys = [...objects.keys()].filter((key) => key.startsWith(options.prefix)).sort();
        const remaining = keys.filter((key) => !options.cursor || key > options.cursor);
        const selected = remaining.slice(0, options.limit);
        const truncated = selected.length < remaining.length;
        return { objects: selected.map((key) => ({ key })), truncated,
          ...(truncated ? { cursor: selected.at(-1) } : {}) };
      },
      async get(key: string) {
        const text = objects.get(key);
        return text === undefined ? null : { text: async () => text, body: text, etag: text };
      },
      async put(key: string, value: string, options?: { onlyIf?: unknown }) {
        const condition = options?.onlyIf;
        if (condition && typeof condition === "object") {
          if ("etagDoesNotMatch" in condition && objects.has(key)) return null;
          if ("etagMatches" in condition && objects.get(key) !== condition.etagMatches) return null;
        }
        objects.set(key, value);
        return {};
      },
    },
    ARTIFACTS: { async get() { throw new Error("Unexpected artifact access"); } },
    CI_WORKFLOW: {
      async create() { throw new Error("Unexpected CI start"); },
      async get() { throw new Error("Unexpected CI status"); },
    },
  };
  return {
    env, objects,
    async poll(token = env.CI_API_TOKEN) {
      return fetchCi(new Request("https://ci.test/sentry/poll", {
        method: "POST", body: "{}", headers: { Authorization: `Bearer ${token}` },
      }), env);
    },
    async reserve(value: unknown) {
      return fetchCi(new Request(`https://ci.test/sentry/events/789/${eventId}/reserve`, {
        method: "POST", body: JSON.stringify(value),
        headers: { Authorization: `Bearer ${env.CI_API_TOKEN}` },
      }), env);
    },
    async acknowledge(value: unknown, token = env.CI_API_TOKEN) {
      return fetchCi(new Request(`https://ci.test/sentry/events/789/${eventId}/ack`, {
        method: "POST", body: JSON.stringify(value),
        headers: { Authorization: `Bearer ${token}` },
      }), env);
    },
    async read(path = "/sentry/events", token = env.CI_API_TOKEN) {
      return fetchCi(new Request(`https://ci.test${path}`, {
        headers: { Authorization: `Bearer ${token}` },
      }), env);
    },
    async send(body = JSON.stringify(payload), signature?: string) {
      return fetchCi(new Request("https://ci.test/sentry/events", {
        method: "POST", body,
        headers: {
          "Content-Type": "application/json",
          "Sentry-Hook-Resource": "event_alert",
          "Sentry-Hook-Signature": signature ?? await signed(body),
        },
      }), env);
    },
  };
}

test("a signed Sentry event is queued privately and readable by the trusted runtime consumer", async () => {
  const state = fixture();
  expect((await state.send()).status).toBe(202);
  const listed = runtimeEvidencePageSchema.parse(await (await state.read()).json());
  expect(listed.events).toHaveLength(1);
  expect(listed.cursor).toBeNull();
  expect(listed.events[0]).toMatchObject({
    kind: "sentry-runtime", organization: "omg-org",
    projectId: "789", eventId, issueId: "12345", sourceSha: "a".repeat(40),
    release: "v0.1.223", environment: "production",
    frames: [{ path: "src/core/cache.rs", line: 12 }],
  });
  const stored = [...state.objects.values()].join("\n");
  for (const privateValue of ["private-token", "private@example", "private-value", "attacker.test", "do-not-execute", "/home/private"])
    expect(stored).not.toContain(privateValue);
  expect((await state.read("/sentry/events", "wrong-token")).status).toBe(401);
  const exact = await state.read(`/sentry/events/789/${eventId}`);
  expect(exact.status).toBe(200);
  expect(await exact.json()).toEqual(listed.events[0]);
});

test("signature verification covers the original request bytes before parsing or dispatch", async () => {
  const state = fixture();
  const body = JSON.stringify(payload);
  expect((await state.send(body + " ", await signed(body))).status).toBe(401);
  expect((await state.send(body, "00")).status).toBe(401);
  expect(state.objects.size).toBe(0);
});

test("unknown Sentry organizations, projects and environments cannot dispatch runtime review", async () => {
  for (const event of [
    { ...payload.data.event, project: 790 },
    { ...payload.data.event, url: payload.data.event.url.replace("omg-org", "another-org") },
    { ...payload.data.event, environment: "private-environment" },
    { ...payload.data.event, url: "https://attacker.test/event" },
  ]) {
    const state = fixture();
    const body = JSON.stringify({ ...payload, data: { event } });
    expect((await state.send(body)).status).toBe(403);
    expect(state.objects.size).toBe(0);
  }
});

test("Sentry test-notification sample tags cannot bypass the production environment policy", async () => {
  // Sentry get_test_notification_event_data loads a platform sample and adds sample_event=yes,
  // but neither its native sample nor the JavaScript fallback sets an environment.
  const sample = { ...payload.data.event, environment: undefined,
    tags: [["sample_event", "yes"]],
    exception: { values: [{ type: "TestError", stacktrace: {
      frames: [{ filename: "sample.rs", lineno: null, in_app: true }],
    } }] },
  };
  for (const environment of [undefined, null, "staging"]) {
    const state = fixture();
    expect((await state.send(JSON.stringify({ ...payload,
      data: { event: { ...sample, environment } },
    }))).status).toBe(403);
    expect(state.objects.size).toBe(0);
  }
  const state = fixture();
  const response = await state.send(JSON.stringify({ ...payload,
    data: { event: { ...sample, tags: [["environment", "production"]] } },
  }));
  expect(response.status).toBe(202);
  expect(await response.json()).toMatchObject({ status: "queued", holdReason: "missing-rust-frames" });
  const listed = runtimeEvidencePageSchema.parse(await (await state.read()).json());
  expect(listed.events[0]).toMatchObject({ environment: "production", frames: [] });
});

test("Sentry intake fails closed without account configuration and bounds streamed payloads", async () => {
  const state = fixture();
  state.env.SENTRY_WEBHOOK_SECRET = "";
  expect((await state.send()).status).toBe(503);
  const bounded = fixture();
  expect((await bounded.send("x".repeat(262145))).status).toBe(413);
  expect(bounded.objects.size).toBe(0);
});

test("duplicate signed events retain one immutable evidence envelope", async () => {
  const state = fixture();
  expect((await state.send()).status).toBe(202);
  expect((await state.send()).status).toBe(200);
  expect([...state.objects.keys()].filter((key) => key.startsWith("sentry/events/"))).toHaveLength(1);
  const changed = JSON.stringify({ ...payload, actor: { name: "changed" } });
  expect((await state.send(changed)).status).toBe(409);
  expect([...state.objects.keys()].filter((key) => key.startsWith("sentry/events/"))).toHaveLength(1);
});

test("signed events without Rust frames are retained with an explicit hold reason", async () => {
  const state = fixture();
  const body = JSON.stringify({ ...payload, data: { event: { ...payload.data.event,
    exception: { values: [{ stacktrace: { frames: [{ filename: "third-party.js", lineno: 9 }] } }] },
  } } });
  const response = await state.send(body);
  expect(response.status).toBe(202);
  expect(await response.json()).toMatchObject({ status: "queued", holdReason: "missing-rust-frames" });
  const listed = runtimeEvidencePageSchema.parse(await (await state.read()).json());
  expect(listed.events[0].frames).toEqual([]);
});

test("acknowledgement requires the exact event digest in its durable review record", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  const ack = { bodySha256: event.bodySha256, reviewRunId: "876", attempt: "1" };
  expect((await state.acknowledge(ack)).status).toBe(409);
  const record = { repository: "omg-cli/omg", runId: "876", attempt: "1", report: {
    repository: "omg-cli/omg", branch: "main", sha: "a".repeat(40),
    runtimeEvents: [{ projectId: "789", eventId, bodySha256: "0".repeat(64) }],
  } };
  state.objects.set("reviews/876-1/review.json", JSON.stringify(record));
  expect((await state.acknowledge(ack)).status).toBe(409);
  record.report.runtimeEvents[0].bodySha256 = event.bodySha256;
  state.objects.set("reviews/876-1/review.json", JSON.stringify(record));
  expect((await state.acknowledge(ack, "wrong-token")).status).toBe(401);
  expect((await state.acknowledge(ack)).status).toBe(200);
  expect((await state.acknowledge(ack)).status).toBe(200);
  state.objects.set("reviews/877-1/review.json", JSON.stringify({ ...record, runId: "877" }));
  expect((await state.acknowledge({ ...ack, reviewRunId: "877" })).status).toBe(409);
  const pending = runtimeEvidencePageSchema.parse(await (await state.read()).json());
  expect(pending.events).toEqual([]);
  expect((await state.read(`/sentry/events/789/${eventId}`)).status).toBe(200);
});

test("missing or historic source attribution stays separate from current-main review identity", async () => {
  for (const tags of [[], [["source_sha", "d".repeat(40)]]]) {
    const state = fixture();
    const response = await state.send(JSON.stringify({ ...payload,
      data: { event: { ...payload.data.event, tags } },
    }));
    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({ status: "queued", holdReason: null });
    const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
    expect(event.sourceSha).toBe(tags.length ? "d".repeat(40) : null);
  }
});

test("pending event pagination advances past acknowledged events", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  state.objects.set("sentry/acks/789/" + eventId + ".json", JSON.stringify({
    bodySha256: event.bodySha256, reviewRunId: "876", attempt: "1",
  }));
  const nextId = "c".repeat(32);
  const next = { ...event, eventId: nextId };
  state.objects.set(`sentry/events/789/${nextId}.json`, JSON.stringify(next));
  state.objects.set(`sentry/pending/789/${nextId}.json`, JSON.stringify({
    projectId: "789", eventId: nextId, bodySha256: next.bodySha256,
  }));
  const first = runtimeEvidencePageSchema.parse(await (await state.read("/sentry/events?limit=1")).json());
  expect(first.events).toEqual([]);
  expect(first.cursor).not.toBeNull();
  const second = runtimeEvidencePageSchema.parse(await (await state.read(`/sentry/events?limit=1&cursor=${first.cursor}`)).json());
  expect(second.events).toEqual([next]);
  expect(second.cursor).toBeNull();
});

test("more than 125 acknowledged historical events cannot starve a fresh pending event", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  for (let index = 1; index <= 130; index++) {
    const historicalId = index.toString(16).padStart(32, "0");
    state.objects.set(`sentry/events/789/${historicalId}.json`, JSON.stringify({ ...event, eventId: historicalId }));
    state.objects.set(`sentry/acks/789/${historicalId}.json`, JSON.stringify({
      bodySha256: event.bodySha256, reviewRunId: String(index), attempt: "1",
    }));
  }
  const page = runtimeEvidencePageSchema.parse(await (await state.read()).json());
  expect(page.events.map((entry) => entry.eventId)).toEqual([eventId]);
  expect(page.cursor).toBeNull();
});

test("native thread traces and Rust tracing locations preserve only owned repository frame candidates", async () => {
  const state = fixture();
  const event = { ...payload.data.event,
    exception: { values: [{ type: "CacheError", value: "private-token", stacktrace: null }] },
    threads: { values: [{ stacktrace: { frames: [
      { filename: "cache.rs", abs_path: "/home/private/build/src/core/cache.rs", lineno: 12,
        in_app: true, package: "omg_lib", function: "omg_lib::core::cache::lookup" },
      { filename: "lib.rs", abs_path: "/home/private/dependency/src/lib.rs", lineno: 999,
        in_app: true, package: "foreign_crate" },
      { filename: "core.rs", abs_path: "/home/private/build/src/core.rs", lineno: 33,
        in_app: false, package: "omg_lib" },
    ] } }] },
    contexts: { "Rust Tracing Location": {
      module_path: "omgd::main", file: "src/bin/omgd.rs", line: 88,
    } },
  };
  const response = await state.send(JSON.stringify({ ...payload, data: { event } }));
  expect(response.status).toBe(202);
  expect(await response.json()).toMatchObject({ holdReason: null });
  const stored = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  expect(stored.frames).toEqual([
    { path: "src/core/cache.rs", line: 12 }, { path: "src/bin/omgd.rs", line: 88 },
  ]);
  expect(stored.errorTypes).toEqual(["CacheError"]);
  expect(JSON.stringify(stored)).not.toContain("private");
});

test("pending insertion recovers on retry and acknowledgement races cannot resurrect reviewed events", async () => {
  const state = fixture();
  const put = state.env.BACKUP_BUCKET.put;
  let failPending = true;
  state.env.BACKUP_BUCKET.put = async (key, value, options) => {
    if (failPending && key.startsWith("sentry/pending/")) {
      failPending = false;
      throw new Error("private storage failure");
    }
    return put(key, value, options);
  };
  expect((await state.send()).status).toBe(503);
  expect((await state.send()).status).toBe(200);
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  state.objects.set("reviews/876-1/review.json", JSON.stringify({
    repository: "omg-cli/omg", runId: "876", attempt: "1", report: {
      repository: "omg-cli/omg", branch: "main", sha: "a".repeat(40),
      runtimeEvents: [{ projectId: "789", eventId, bodySha256: event.bodySha256 }],
    },
  }));
  const ack = { bodySha256: event.bodySha256, reviewRunId: "876", attempt: "1" };
  const responses = await Promise.all([state.send(), state.acknowledge(ack)]);
  expect(responses.map((response) => response.status)).toEqual([200, 200]);
  expect((await state.send()).status).toBe(200);
  expect([...state.objects.keys()].filter((key) => key.startsWith("sentry/pending/"))).toEqual([]);
  expect((await state.read()).status).toBe(200);
  expect(runtimeEvidencePageSchema.parse(await (await state.read()).json()).events).toEqual([]);
});

test("runtime review reservations persist before inference and duplicate delivery preserves the active reference", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  const activeReview = { runId: "876", attempt: "1", sha: "a".repeat(40), controllerRevision: "d".repeat(40) };
  const request = { bodySha256: event.bodySha256, activeReview, expectedActiveReview: null };
  const reserved = await state.reserve(request);
  expect(reserved.status).toBe(200);
  expect(await reserved.json()).toEqual({ activeReview });
  expect((await state.reserve(request)).status).toBe(200);
  expect((await state.send()).status).toBe(200);
  const page = await (await state.read()).json();
  expect(page).toMatchObject({ events: [{ activeReview }] });
  const exact = await (await state.read(`/sentry/events/789/${eventId}`)).json();
  expect(exact).not.toHaveProperty("activeReview");
  const otherReview = { ...activeReview, runId: "877" };
  expect((await state.reserve({ ...request, activeReview: otherReview })).status).toBe(409);
  state.objects.set("reviews/876-1/review.json", JSON.stringify({ report: { publications: [{ verified: true }] } }));
  expect((await state.reserve({ ...request, activeReview: otherReview, expectedActiveReview: activeReview })).status).toBe(409);
});

test("concurrent initial runtime reservations admit only one review owner", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  const activeReview = { runId: "876", attempt: "1", sha: "a".repeat(40), controllerRevision: "d".repeat(40) };
  const request = { bodySha256: event.bodySha256, activeReview, expectedActiveReview: null };
  const responses = await Promise.all([state.reserve(request), state.reserve({ ...request,
    activeReview: { ...activeReview, runId: "877" },
  })]);
  expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
});

test("reclaiming a format-blocked reservation requires exact pre-inference evidence and preserves the immutable report", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  const activeReview = { runId: "876", attempt: "1", sha: "a".repeat(40), controllerRevision: "d".repeat(40) };
  await state.reserve({ bodySha256: event.bodySha256, activeReview, expectedActiveReview: null });
  const report = { repository: "omg-cli/omg", branch: "main", sha: activeReview.sha,
    controllerRevision: activeReview.controllerRevision, status: "format-blocked", formatting: { status: "blocked" },
    sourceRange: { intake: "sentry-runtime" }, publishRequested: true,
    modelInferencePerformed: false, nativeVerificationPerformed: false,
    publications: [], batches: [], candidateOutcomes: [], readPaths: [],
    runtimeEvents: [{ projectId: event.projectId, eventId, bodySha256: event.bodySha256 }] };
  const request = { bodySha256: event.bodySha256, activeReview: { ...activeReview, runId: "877" }, expectedActiveReview: activeReview };
  for (const change of [
    { publications: [{ verified: true }] }, { modelInferencePerformed: undefined }, { modelInferencePerformed: true },
    { nativeVerificationPerformed: true }, { batches: [{}] }, { status: "reviewed" }, { publishRequested: false },
    { controllerRevision: "f".repeat(40) }, { runtimeEvents: [{ ...report.runtimeEvents[0], bodySha256: "f".repeat(64) }] },
  ]) {
    state.objects.set("reviews/876-1/review.json", JSON.stringify({ repository: "omg-cli/omg", runId: "876", attempt: "1",
      report: { ...report, ...change } }));
    expect((await state.reserve(request)).status).toBe(409);
    expect(runtimeEvidencePageSchema.parse(await (await state.read()).json()).events[0].activeReview).toEqual(activeReview);
  }
  const encoded = JSON.stringify({ repository: "omg-cli/omg", runId: "876", attempt: "1", report });
  state.objects.set("reviews/876-1/review.json", encoded);
  const responses = await Promise.all([state.reserve(request), state.reserve({ ...request,
    activeReview: { ...activeReview, runId: "878" },
  })]);
  expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
  expect(state.objects.get("reviews/876-1/review.json")).toBe(encoded);
  expect(state.objects.has(`sentry/events/789/${eventId}.json`)).toBe(true);
});

async function addSecondEvent(state: Awaited<ReturnType<typeof fixture>>) {
  const nextId = "c".repeat(32);
  await state.send(JSON.stringify({ ...payload, data: { event: { ...payload.data.event,
    event_id: nextId, url: payload.data.event.url.replace(eventId, nextId),
  } } }));
  return nextId;
}

test("durable runtime polling moves beyond a stale active review without deleting its outbox", async () => {
  const state = fixture();
  await state.send();
  const event = runtimeEvidenceSchema.parse(await (await state.read(`/sentry/events/789/${eventId}`)).json());
  const activeReview = { runId: "876", attempt: "1", sha: "d".repeat(40), controllerRevision: "e".repeat(40) };
  await state.reserve({ bodySha256: event.bodySha256, activeReview, expectedActiveReview: null });
  const nextId = await addSecondEvent(state);
  expect((await state.poll("wrong-token")).status).toBe(401);
  const firstResponse = await state.poll();
  expect(firstResponse.status).toBe(200);
  const first = runtimeEvidencePageSchema.parse(await firstResponse.json());
  expect(first.events.map((item) => item.eventId)).toEqual([eventId]);
  expect(first.events[0].activeReview).toEqual(activeReview);
  const second = runtimeEvidencePageSchema.parse(await (await state.poll()).json());
  expect(second.events.map((item) => item.eventId)).toEqual([nextId]);
  const wrapped = runtimeEvidencePageSchema.parse(await (await state.poll()).json());
  expect(wrapped.events.map((item) => item.eventId)).toEqual([eventId]);
  expect(state.objects.has(`sentry/pending/789/${eventId}.json`)).toBe(true);
  expect(state.objects.has(`sentry/events/789/${eventId}.json`)).toBe(true);
});

test("a failed cursor write or crash after polling does not lose pending runtime events", async () => {
  const state = fixture();
  await state.send();
  const nextId = await addSecondEvent(state);
  const put = state.env.BACKUP_BUCKET.put;
  let fail = true;
  state.env.BACKUP_BUCKET.put = async (key, value, options) => {
    if (fail && key === "sentry/poll-cursor.json") { fail = false; throw new Error("private cursor write failed"); }
    return put(key, value, options);
  };
  expect((await state.poll()).status).toBe(503);
  const retried = runtimeEvidencePageSchema.parse(await (await state.poll()).json());
  expect(retried.events.map((item) => item.eventId)).toEqual([eventId]);
  const afterCrash = runtimeEvidencePageSchema.parse(await (await state.poll()).json());
  expect(afterCrash.events.map((item) => item.eventId)).toEqual([nextId]);
  const wrapped = runtimeEvidencePageSchema.parse(await (await state.poll()).json());
  expect(wrapped.events.map((item) => item.eventId)).toEqual([eventId]);
  expect([...state.objects.keys()].filter((key) => key.startsWith("sentry/pending/"))).toHaveLength(2);
});

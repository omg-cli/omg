import { z } from "zod";
import type * as Workers from "@cloudflare/workers-types/index.ts";
import { runtimeEvidenceSchema, runtimeReviewRefSchema, type RuntimeEvidence } from "../../ci-inspector/src/runtime-evidence";
import { canRecoverRuntimeBeforeInference, runtimePreInferenceReportSchema } from "../../ci-inspector/src/runtime-recovery";

type Request = globalThis.Request | Workers.Request;
type Response = Workers.Response;
declare const Response: typeof Workers.Response;

type Bucket = {
  delete?(key: string): Promise<void>;
  get(key: string): Promise<{ text(): Promise<string>; etag?: string } | null>;
  put(key: string, value: string, options?: R2PutOptions): Promise<object | null>;
  list?(options: { prefix: string; limit: number; cursor?: string }):
    Promise<{ objects: { key: string }[]; truncated: boolean; cursor?: string }>;
};

export type SentryBindings = {
  SENTRY_WEBHOOK_SECRET?: string;
  SENTRY_ORG_SLUG?: string;
  SENTRY_PROJECT_SLUG?: string;
  SENTRY_PROJECT_ID?: string;
  SENTRY_ENVIRONMENT?: string;
  BACKUP_BUCKET: Bucket;
};

const json = <T>(value: T, status = 200) =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
const numericId = z.string().regex(/^[1-9][0-9]{0,19}$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const ackSchema = z.strictObject({
  bodySha256: digest,
  reviewRunId: numericId,
  attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
});
const reviewSchema = z.object({
  repository: z.literal("omg-cli/omg"), runId: numericId,
  attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
  report: z.object({
    repository: z.literal("omg-cli/omg"), branch: z.literal("main"),
    sha: z.string().regex(/^[a-f0-9]{40}$/),
    runtimeEvents: z.array(z.object({
      projectId: numericId, eventId: z.string().regex(/^[a-f0-9]{32}$/), bodySha256: digest,
    })).max(50),
  }),
});
const frameSchema = z.object({
  filename: z.string().max(500).nullable().optional(),
  abs_path: z.string().max(1000).nullable().optional(),
  lineno: z.number().int().positive().safe().nullable().optional(),
  in_app: z.boolean().nullable().optional(),
  package: z.string().max(200).nullable().optional(),
  module: z.string().max(500).nullable().optional(),
  function: z.string().max(1000).nullable().optional(),
});
const stacktraceSchema = z.object({ frames: z.array(frameSchema).max(128) });
const eventSchema = z.object({
  action: z.literal("triggered"),
  data: z.object({ event: z.object({
    event_id: z.string().regex(/^[a-f0-9]{32}$/),
    issue_id: numericId,
    project: z.union([numericId, z.number().int().positive().safe()]),
    url: z.string().max(500),
    release: z.string().max(200).nullable().optional(),
    environment: z.string().max(64).nullable().optional(),
    tags: z.array(z.tuple([z.string().max(100), z.string().max(300)])).max(100).optional(),
    stacktrace: stacktraceSchema.nullable().optional(),
    threads: z.object({ values: z.array(z.object({
      stacktrace: stacktraceSchema.nullable().optional(),
    })).max(32) }).nullable().optional(),
    contexts: z.object({ "Rust Tracing Location": z.object({
      module_path: z.string().max(500).optional(), file: z.string().max(1000).optional(),
      line: z.number().int().positive().safe().optional(),
    }).optional() }).nullable().optional(),
    exception: z.object({ values: z.array(z.object({
      type: z.string().max(200).nullable().optional(),
      stacktrace: stacktraceSchema.nullable().optional(),
    })).max(16) }).nullable().optional(),
  }) }),
});

class PayloadTooLarge extends Error {}

async function readBytes(request: Request, limit: number) {
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > limit) {
          await reader.cancel();
          throw new PayloadTooLarge();
        }
        chunks.push(chunk.value);
      }
    } finally {
      reader.releaseLock();
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)]
  .map((byte) => byte.toString(16).padStart(2, "0")).join("");
const eventKey = (project: string, event: string) => `sentry/events/${project}/${event}.json`;
const ackKey = (project: string, event: string) => `sentry/acks/${project}/${event}.json`;
const pendingKey = (project: string, event: string) => `sentry/pending/${project}/${event}.json`;
const referenceSchema = z.strictObject({
  projectId: numericId, eventId: z.string().regex(/^[a-f0-9]{32}$/), bodySha256: digest,
  activeReview: runtimeReviewRefSchema.optional(),
});
const reservationSchema = z.strictObject({
  bodySha256: digest, activeReview: runtimeReviewRefSchema,
  expectedActiveReview: runtimeReviewRefSchema.nullable(),
});
const cursorSchema = z.strictObject({ cursor: z.string().min(1).max(2048).nullable() });

async function removePending(bucket: Bucket, event: RuntimeEvidence) {
  if (!bucket.delete) throw new Error("Sentry pending index deletion is unavailable");
  await bucket.delete(pendingKey(event.projectId, event.eventId));
}

async function acknowledged(bucket: Bucket, event: RuntimeEvidence) {
  const ack = await bucket.get(ackKey(event.projectId, event.eventId));
  if (!ack) return false;
  if (ackSchema.parse(JSON.parse(await ack.text())).bodySha256 !== event.bodySha256)
    throw new Error("Stored Sentry acknowledgement mismatch");
  return true;
}

function projectEvent(raw: unknown, env: SentryBindings, bodySha256: string): RuntimeEvidence {
  const { data: { event } } = eventSchema.parse(raw);
  const expectedUrl = `https://sentry.io/api/0/projects/${env.SENTRY_ORG_SLUG}/${env.SENTRY_PROJECT_SLUG}/events/${event.event_id}/`;
  const tags = new Map(event.tags ?? []);
  const environment = event.environment ?? tags.get("environment") ?? null;
  if (String(event.project) !== env.SENTRY_PROJECT_ID || event.url !== expectedUrl ||
      environment !== env.SENTRY_ENVIRONMENT)
    throw new Error("Sentry project policy mismatch");

  const candidates = [
    ...(event.exception?.values ?? []).flatMap((exception) => exception.stacktrace?.frames ?? []),
    ...(event.threads?.values ?? []).flatMap((thread) => thread.stacktrace?.frames ?? []),
    ...(event.stacktrace?.frames ?? []),
  ];
  const location = event.contexts?.["Rust Tracing Location"];
  if (location?.module_path && /^(?:omg|omgd|omg_lib)(?:::|$)/.test(location.module_path))
    candidates.push({ filename: location.file, lineno: location.line,
      module: location.module_path, in_app: true });
  const frames: RuntimeEvidence["frames"] = [];
  for (const frame of candidates) {
    const path = repositoryFramePath(frame);
    if (!path || !frame.lineno || frame.lineno > 10000000) continue;
    if (!frames.some((existing) => existing.path === path && existing.line === frame.lineno))
      frames.push({ path, line: frame.lineno });
    if (frames.length === 12) break;
  }
  const errorTypes = [...new Set((event.exception?.values ?? []).flatMap((exception) =>
    exception.type && /^[A-Za-z_][A-Za-z0-9_:]{0,79}$/.test(exception.type) ? [exception.type] : []))].slice(0, 8);
  const sourceSha = tags.get("source_sha");
  const release = event.release;
  return runtimeEvidenceSchema.parse({
    kind: "sentry-runtime",
    organization: env.SENTRY_ORG_SLUG, projectId: String(event.project),
    eventId: event.event_id, issueId: event.issue_id, bodySha256,
    sourceSha: sourceSha && /^[a-f0-9]{40}$/.test(sourceSha) ? sourceSha : null,
    release: release && /^(?:omg[d]?@)?v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,80})?$/.test(release) ? release : null,
    environment, frames, errorTypes,
  });
}

function repositoryFramePath(frame: z.infer<typeof frameSchema>) {
  if (frame.in_app === false) return null;
  const repositoryPath = /^src\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\.rs$/;
  if (frame.filename && frame.filename.length <= 300 && repositoryPath.test(frame.filename))
    return frame.filename;
  const owned = /^(?:omg|omgd|omg_lib)(?:::|$)/;
  if (frame.in_app !== true || ![frame.package, frame.module, frame.function]
    .some((value) => value && owned.test(value))) return null;
  const absolute = (frame.abs_path ?? frame.filename ?? "").replaceAll("\\", "/");
  if (!/^(?:\/|[A-Za-z]:\/)/.test(absolute) || absolute.split("/").some((part) => part === "." || part === ".."))
    return null;
  const offset = absolute.lastIndexOf("/src/");
  const path = offset >= 0 ? absolute.slice(offset + 1) : "";
  // Owned absolute frames are source candidates; the consumer must resolve their actual Git blobs.
  return path.length <= 300 && repositoryPath.test(path) ? path : null;
}

export async function receiveSentry(request: Request, env: SentryBindings): Promise<Response> {
  if (request.method !== "POST") return json({ error: "Not found" }, 404);
  if (!env.SENTRY_WEBHOOK_SECRET || env.SENTRY_WEBHOOK_SECRET.length < 32 ||
      !/^[a-z0-9][a-z0-9-]{0,99}$/.test(env.SENTRY_ORG_SLUG ?? "") ||
      !/^[a-z0-9][a-z0-9-]{0,99}$/.test(env.SENTRY_PROJECT_SLUG ?? "") ||
      !numericId.safeParse(env.SENTRY_PROJECT_ID).success ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(env.SENTRY_ENVIRONMENT ?? ""))
    return json({ error: "Sentry intake is not configured" }, 503);
  try {
    const bytes = await readBytes(request, 262144);
    const signature = request.headers.get("Sentry-Hook-Signature") ?? "";
    if (!/^[a-f0-9]{64}$/.test(signature)) return json({ error: "Unauthorized" }, 401);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.SENTRY_WEBHOOK_SECRET),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const signatureBytes = Uint8Array.from(signature.match(/../g) ?? [], (pair) => parseInt(pair, 16));
    if (!await crypto.subtle.verify("HMAC", key, signatureBytes, bytes))
      return json({ error: "Unauthorized" }, 401);
    if (request.headers.get("Sentry-Hook-Resource") !== "event_alert")
      return json({ error: "Unsupported Sentry resource" }, 400);

    let event: RuntimeEvidence;
    try {
      const raw: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
      event = projectEvent(raw, env, hex(await crypto.subtle.digest("SHA-256", bytes)));
    } catch {
      return json({ error: "Sentry event does not match the admitted project policy" }, 403);
    }
    const encoded = JSON.stringify(event);
    const keyName = eventKey(event.projectId, event.eventId);
    const written = await env.BACKUP_BUCKET.put(keyName, encoded, {
      onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" },
    });
    if (!written) {
      const previous = await env.BACKUP_BUCKET.get(keyName);
      if (!previous || JSON.stringify(runtimeEvidenceSchema.parse(JSON.parse(await previous.text()))) !== encoded)
        return json({ error: "Sentry event identity conflict" }, 409);
    }
    if (!await acknowledged(env.BACKUP_BUCKET, event)) {
      const reference = JSON.stringify({ projectId: event.projectId, eventId: event.eventId,
        bodySha256: event.bodySha256 });
      const pending = await env.BACKUP_BUCKET.put(pendingKey(event.projectId, event.eventId), reference, {
        onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" },
      });
      if (!pending) {
        const previous = await env.BACKUP_BUCKET.get(pendingKey(event.projectId, event.eventId));
        const prior = previous ? referenceSchema.parse(JSON.parse(await previous.text())) : null;
        if (!prior || prior.projectId !== event.projectId || prior.eventId !== event.eventId || prior.bodySha256 !== event.bodySha256)
          throw new Error("Stored Sentry pending identity mismatch");
      }
    }
    // An ACK may have committed between the first check and pending-index creation.
    if (await acknowledged(env.BACKUP_BUCKET, event)) {
      await removePending(env.BACKUP_BUCKET, event);
      return json({ status: "acknowledged", eventId: event.eventId, bodySha256: event.bodySha256 });
    }
    return json({ status: "queued", eventId: event.eventId, bodySha256: event.bodySha256,
      holdReason: event.frames.length ? null : "missing-rust-frames" }, written ? 202 : 200);
  } catch (error) {
    return error instanceof PayloadTooLarge ? json({ error: "Sentry payload too large" }, 413)
      : json({ error: "Sentry evidence storage unavailable" }, 503);
  }
}

export async function sentryRecords(request: Request, bucket: Bucket): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/sentry/poll" && request.method === "POST") {
    try {
      z.strictObject({}).parse(JSON.parse(new TextDecoder("utf-8", { fatal: true })
        .decode(await readBytes(request, 128))));
    } catch (error) {
      return json({ error: "Invalid runtime poll" }, error instanceof PayloadTooLarge ? 413 : 400);
    }
    const key = "sentry/poll-cursor.json";
    const previous = await bucket.get(key);
    if (previous && !previous.etag) throw new Error("Runtime poll requires an R2 entity tag");
    const cursor = previous ? cursorSchema.parse(JSON.parse(await previous.text())).cursor : null;
    const page = await pendingPage(bucket, 1, cursor ?? undefined);
    const written = await bucket.put(key, JSON.stringify({ cursor: page.cursor }), {
      onlyIf: previous ? { etagMatches: previous.etag } : { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json" },
    });
    if (!written) return json({ error: "Runtime poll cursor conflict; retry" }, 409);
    return json(page);
  }
  const match = /^\/sentry\/events\/([1-9][0-9]{0,19})\/([a-f0-9]{32})(\/ack|\/reserve)?$/.exec(url.pathname);
  if (match) {
    const object = await bucket.get(eventKey(match[1], match[2]));
    if (!object) return json({ error: "Not found" }, 404);
    const event = runtimeEvidenceSchema.parse(JSON.parse(await object.text()));
    if (event.projectId !== match[1] || event.eventId !== match[2])
      throw new Error("Stored Sentry identity mismatch");
    if (request.method === "GET" && !match[3]) return json(event);
    if (request.method !== "POST" || !match[3]) return json({ error: "Not found" }, 404);
    if (match[3] === "/reserve") return reserveRuntimeReview(request, bucket, event);
    let ack;
    try {
      ack = ackSchema.parse(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBytes(request, 1024))));
    } catch (error) {
      return json({ error: "Invalid Sentry acknowledgement" }, error instanceof PayloadTooLarge ? 413 : 400);
    }
    if (ack.bodySha256 !== event.bodySha256) return json({ error: "Sentry digest mismatch" }, 409);
    const review = await bucket.get(`reviews/${ack.reviewRunId}-${ack.attempt}/review.json`);
    if (!review)
      return json({ error: "Durable review record is required before acknowledgement" }, 409);
    const record = reviewSchema.safeParse(JSON.parse(await review.text()));
    if (!record.success || record.data.runId !== ack.reviewRunId || record.data.attempt !== ack.attempt ||
        !record.data.report.runtimeEvents.some((reference) => reference.projectId === event.projectId &&
          reference.eventId === event.eventId && reference.bodySha256 === event.bodySha256))
      return json({ error: "Durable review record does not reference this Sentry evidence" }, 409);
    const encoded = JSON.stringify(ack);
    const key = ackKey(match[1], match[2]);
    const written = await bucket.put(key, encoded, {
      onlyIf: { etagDoesNotMatch: "*" }, httpMetadata: { contentType: "application/json" },
    });
    if (!written) {
      const previous = await bucket.get(key);
      if (!previous || JSON.stringify(ackSchema.parse(JSON.parse(await previous.text()))) !== encoded)
        return json({ error: "Sentry acknowledgement conflict" }, 409);
    }
    await removePending(bucket, event);
    return json({ acknowledged: true });
  }
  if (url.pathname !== "/sentry/events" || request.method !== "GET")
    return json({ error: "Not found" }, 404);
  const limit = z.coerce.number().int().min(1).max(50).safeParse(url.searchParams.get("limit") ?? "25");
  const cursor = url.searchParams.get("cursor") ?? undefined;
  if (!limit.success || (cursor && (cursor.length > 2048 || /[\x00-\x1f]/.test(cursor))))
    return json({ error: "Invalid Sentry page" }, 400);
  return json(await pendingPage(bucket, limit.data, cursor));
}

async function pendingPage(bucket: Bucket, limit: number, cursor?: string) {
  if (!bucket.list) throw new Error("Sentry listing unavailable");
  const page = await bucket.list({ prefix: "sentry/pending/", limit, ...(cursor ? { cursor } : {}) });
  const events: (RuntimeEvidence & { activeReview?: z.infer<typeof runtimeReviewRefSchema> })[] = [];
  for (const object of page.objects) {
    const key = /^sentry\/pending\/([1-9][0-9]{0,19})\/([a-f0-9]{32})\.json$/.exec(object.key);
    if (!key) throw new Error("Invalid stored Sentry path");
    const pending = await bucket.get(object.key);
    if (!pending) continue;
    const reference = referenceSchema.parse(JSON.parse(await pending.text()));
    if (reference.projectId !== key[1] || reference.eventId !== key[2])
      throw new Error("Stored Sentry pending identity mismatch");
    const stored = await bucket.get(eventKey(key[1], key[2]));
    if (!stored) throw new Error("Missing listed Sentry event");
    const event = runtimeEvidenceSchema.parse(JSON.parse(await stored.text()));
    if (event.projectId !== key[1] || event.eventId !== key[2] || event.bodySha256 !== reference.bodySha256)
      throw new Error("Stored Sentry identity mismatch");
    if (await acknowledged(bucket, event)) await removePending(bucket, event);
    else events.push({ ...event, ...(reference.activeReview ? { activeReview: reference.activeReview } : {}) });
  }
  if (page.truncated && !page.cursor) throw new Error("Missing Sentry page cursor");
  return { events, cursor: page.truncated ? page.cursor ?? null : null };
}

async function reserveRuntimeReview(request: Request, bucket: Bucket, event: RuntimeEvidence): Promise<Response> {
  let reservation;
  try {
    reservation = reservationSchema.parse(JSON.parse(new TextDecoder("utf-8", { fatal: true })
      .decode(await readBytes(request, 1024))));
  } catch (error) {
    return json({ error: "Invalid runtime review reservation" }, error instanceof PayloadTooLarge ? 413 : 400);
  }
  if (reservation.bodySha256 !== event.bodySha256)
    return json({ error: "Sentry digest mismatch" }, 409);
  if (await acknowledged(bucket, event))
    return json({ error: "Sentry event is already acknowledged" }, 409);
  const key = pendingKey(event.projectId, event.eventId);
  const pending = await bucket.get(key);
  if (!pending) return json({ error: "Sentry event is not pending" }, 409);
  if (!pending.etag) throw new Error("Runtime review reservation requires an R2 entity tag");
  const reference = referenceSchema.parse(JSON.parse(await pending.text()));
  if (reference.projectId !== event.projectId || reference.eventId !== event.eventId || reference.bodySha256 !== event.bodySha256)
    throw new Error("Stored Sentry pending identity mismatch");
  if (JSON.stringify(reference.activeReview) === JSON.stringify(reservation.activeReview))
    return json({ activeReview: reference.activeReview });
  if (JSON.stringify(reference.activeReview ?? null) !== JSON.stringify(reservation.expectedActiveReview))
    return json({ error: "Runtime review reservation conflict" }, 409);
  if (reference.activeReview) {
    const previous = await bucket.get(`reviews/${reference.activeReview.runId}-${reference.activeReview.attempt}/review.json`);
    if (previous) {
      const record = reviewSchema.extend({ report: runtimePreInferenceReportSchema }).safeParse(JSON.parse(await previous.text()));
      if (!record.success || record.data.runId !== reference.activeReview.runId || record.data.attempt !== reference.activeReview.attempt ||
          !canRecoverRuntimeBeforeInference(record.data.report, reference.activeReview, event))
        return json({ error: "Existing durable runtime review must be resumed" }, 409);
    }
  }
  const written = await bucket.put(key, JSON.stringify({ ...reference, activeReview: reservation.activeReview }), {
    onlyIf: { etagMatches: pending.etag }, httpMetadata: { contentType: "application/json" },
  });
  if (!written) {
    const winner = await bucket.get(key);
    if (!winner || JSON.stringify(referenceSchema.parse(JSON.parse(await winner.text())).activeReview) !== JSON.stringify(reservation.activeReview))
      return json({ error: "Runtime review reservation conflict" }, 409);
  }
  return json({ activeReview: reservation.activeReview });
}

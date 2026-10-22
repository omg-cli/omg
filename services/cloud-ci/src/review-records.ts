import { z } from "zod";
import type * as Workers from "@cloudflare/workers-types/index.ts";

type Request = globalThis.Request | Workers.Request;

type Response = Workers.Response;

declare const Response: typeof Workers.Response;

const reportSchema = z
  .object({
    repository: z.literal("omg-cli/omg"),
    sha: z.string().regex(/^[a-f0-9]{40}$/),
    branch: z.enum(["main"]),
  })
  .catchall(z.json());

const envelopeSchema = z.strictObject({
  repository: z.literal("omg-cli/omg"),
  runId: z.string().regex(/^[1-9][0-9]{0,19}$/),
  attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
  report: reportSchema,
});

type Json = z.infer<ReturnType<typeof z.json>>;

type Bucket = {
  get(key: string): Promise<{ text(): Promise<string> } | null>;
  put(key: string, value: string, options?: R2PutOptions): Promise<object | null>;
};

const json = (value: Json, status = 200) =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

function canonical(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;

  if (value instanceof Object)
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;

  return JSON.stringify(value);
}

const intentSchema = z.strictObject({
  repository: z.literal("omg-cli/omg"),
  kind: z.literal("admission-retry-intent"),
  runId: z.string().regex(/^[1-9][0-9]{0,19}$/),
  attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
  ownerRunId: z.string().regex(/^[1-9][0-9]{0,19}$/),
  ownerAttempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
  parent: z.string().regex(/^[1-9][0-9]{0,19}-[1-9][0-9]{0,5}$/),
  sha: z.string().regex(/^[a-f0-9]{40}$/),
  cursor: z.number().int().nonnegative(),
  controllerRevision: z.string().regex(/^[a-f0-9]{40}$/),
  manifestDigest: z.string().regex(/^[a-f0-9]{64}$/),
});

const MAX_RECORD_BYTES = 2 * 1024 * 1024;

async function readBody(request: Request): Promise<string | null> {
  const reader = request.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;

  if (reader) {
    try {
      while (true) {
        const chunk = await reader.read();

        if (chunk.done) break;
        size += chunk.value.byteLength;

        if (size > MAX_RECORD_BYTES) {
          await reader.cancel();
          return null;
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

  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
}

type Claim = "created" | "identical" | "conflict";

async function claim(
  bucket: Bucket,
  key: string,
  encoded: string,
  parse: (text: string) => unknown,
): Promise<Claim> {
  const written = await bucket.put(key, encoded, {
    onlyIf: { etagDoesNotMatch: "*" },
    httpMetadata: { contentType: "application/json" },
  });

  if (written) return "created";
  const previous = await bucket.get(key);

  if (!previous) return "conflict";

  return canonical(parse(await previous.text()) as Json) === encoded ? "identical" : "conflict";
}

export async function reviewRecords(request: Request, bucket: Bucket): Promise<Response> {
  const path = new URL(request.url).pathname;
  const intent = /^\/review-records\/([1-9][0-9]{0,19})-([1-9][0-9]{0,5})\/recovery-intent$/.exec(
    path,
  );

  if (intent) return recoveryIntent(request, bucket, intent[1], intent[2]);
  const match = /^\/review-records\/([1-9][0-9]{0,19})-([1-9][0-9]{0,5})$/.exec(path);

  if (!match || !["GET", "POST"].includes(request.method)) return json({ error: "Not found" }, 404);
  const key = `reviews/${match[1]}-${match[2]}/review.json`;

  try {
    if (request.method === "GET") {
      const stored = await bucket.get(key);

      if (!stored) return json({ error: "Not found" }, 404);
      const record = envelopeSchema.parse(JSON.parse(await stored.text()));

      if (record.runId !== match[1] || record.attempt !== match[2])
        throw new Error("Stored identity mismatch");

      return json(record.report);
    }

    let record;

    try {
      const text = await readBody(request);

      if (text === null) return json({ error: "Review record too large" }, 413);
      record = envelopeSchema.parse(JSON.parse(text));

      if (record.runId !== match[1] || record.attempt !== match[2])
        return json({ error: "Review identity mismatch" }, 400);
    } catch {
      return json({ error: "Invalid review record" }, 400);
    }

    const encoded = canonical(record);
    const claimed = await claim(bucket, key, encoded, (text) =>
      envelopeSchema.parse(JSON.parse(text)),
    );

    if (claimed === "conflict") return json({ error: "Review record conflict" }, 409);

    return json({ stored: true });
  } catch {
    return json({ error: "Review storage unavailable" }, 503);
  }
}

async function recoveryIntent(
  request: Request,
  bucket: Bucket,
  runId: string,
  attempt: string,
): Promise<Response> {
  if (!["GET", "POST"].includes(request.method)) return json({ error: "Not found" }, 404);
  const key = `reviews/${runId}-${attempt}/recovery-intent.json`;

  try {
    if (request.method === "GET") {
      const stored = await bucket.get(key);

      if (!stored) return json({ error: "Not found" }, 404);
      const intent = intentSchema.parse(JSON.parse(await stored.text()));

      if (intent.runId !== runId || intent.attempt !== attempt)
        throw new Error("Stored identity mismatch");

      return json(intent);
    }

    let intent;

    try {
      const text = await readBody(request);

      if (text === null) return json({ error: "Review record too large" }, 413);
      intent = intentSchema.parse(JSON.parse(text));

      if (intent.runId !== runId || intent.attempt !== attempt)
        return json({ error: "Review identity mismatch" }, 400);
    } catch {
      return json({ error: "Invalid review record" }, 400);
    }

    const claimed = await claim(bucket, key, canonical(intent), (text) =>
      intentSchema.parse(JSON.parse(text)),
    );

    if (claimed === "conflict") return json({ error: "Review record conflict" }, 409);

    return json({ stored: true, created: claimed === "created" });
  } catch {
    return json({ error: "Review storage unavailable" }, 503);
  }
}

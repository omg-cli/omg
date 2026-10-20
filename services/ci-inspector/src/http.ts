import { snapshotSchema, type Snapshot } from "./snapshot";
import type { ReadableStreamDefaultReader } from "@cloudflare/workers-types/index.ts";

export type InspectionRequest = Pick<Request, "url" | "method"> & {
  headers: Pick<Headers, "get">;
  body: { getReader(): Pick<ReadableStreamDefaultReader<Uint8Array>, "read" | "cancel"> } | null;
};

export type InspectorResult = { summary: string; model?: string; usage?: unknown };

const MAX_BODY = 128 * 1024;

export async function authorized(
  request: Pick<InspectionRequest, "headers">,
  secret: string,
): Promise<boolean> {
  if (!secret) return false;
  const encoder = new TextEncoder();

  const hashes = await Promise.all(
    [request.headers.get("authorization") ?? "", `Bearer ${secret}`].map((value) =>
      crypto.subtle.digest("SHA-256", encoder.encode(value)),
    ),
  );

  const first = new Uint8Array(hashes[0]);
  const second = new Uint8Array(hashes[1]);
  let difference = 0;

  for (let index = 0; index < first.length; index++)
    difference |= (first[index] ?? 0) ^ (second[index] ?? 0);

  return difference === 0;
}

export async function readBoundedJson(
  request: Pick<InspectionRequest, "body">,
  maximumBytes: number,
): Promise<{ kind: "value"; value: unknown } | { kind: "error"; status: number; error: string }> {
  const reader = request.body?.getReader();

  if (!reader) return { kind: "error", status: 400, error: "Missing snapshot" };

  const chunks: Uint8Array[] = [];
  let size = 0;

  try {
    for (;;) {
      const chunk = await reader.read();

      if (chunk.done) break;

      size += chunk.value.byteLength;

      if (size > maximumBytes) {
        await reader.cancel();

        return { kind: "error", status: 413, error: "Snapshot too large" };
      }

      chunks.push(chunk.value);
    }
  } catch {
    return { kind: "error", status: 400, error: "Invalid body" };
  }

  const bytes = new Uint8Array(size);
  let offset = 0;

  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes),
    );

    return { kind: "value", value };
  } catch {
    return { kind: "error", status: 400, error: "Invalid JSON" };
  }
}

export async function handleInspection(
  request: InspectionRequest,
  env: { CI_INSPECTOR_TOKEN: string },
  inspect: (snapshot: Snapshot) => Promise<InspectorResult>,
): Promise<Response> {
  const respond = (
    data:
      | (InspectorResult & Pick<Snapshot, "repository" | "runId" | "branch" | "sha">)
      | { error: string },
    status = 200,
  ) => Response.json(data, { status, headers: { "cache-control": "no-store" } });

  if (new URL(request.url).pathname !== "/inspect") return respond({ error: "Not found" }, 404);

  if (request.method !== "POST") return respond({ error: "Method not allowed" }, 405);

  if (!(await authorized(request, env.CI_INSPECTOR_TOKEN)))
    return respond({ error: "Unauthorized" }, 401);

  if (!request.headers.get("content-type")?.startsWith("application/json"))
    return respond({ error: "Expected application/json" }, 415);
  const body = await readBoundedJson(request, MAX_BODY);

  if (body.kind === "error") return respond({ error: body.error }, body.status);

  const parsed = snapshotSchema.safeParse(body.value);

  if (!parsed.success) return respond({ error: "Invalid CI snapshot" }, 400);
  const snapshot = parsed.data;

  try {
    const result = await inspect(snapshot);

    if (result.summary.length > 16000)
      return respond({ error: "Inspection output too large" }, 502);

    return respond({
      repository: snapshot.repository,
      runId: snapshot.runId,
      branch: snapshot.branch,
      sha: snapshot.sha,
      ...result,
    });
  } catch {
    return respond({ error: "Inspection failed" }, 502);
  }
}

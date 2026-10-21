import { z } from "zod";
import type * as Workers from "@cloudflare/workers-types/index.ts";

type Request = globalThis.Request | Workers.Request;

type Response = Workers.Response;

declare const Response: typeof Workers.Response;

type DiagnosticBucket = {
  get(key: string): Promise<{ text(): Promise<string>; size?: number } | null>;
  list?(options: {
    prefix: string;
    limit: number;
    cursor?: string;
  }): Promise<{ objects: { key: string }[]; truncated: boolean; cursor?: string }>;
};

const recordSchema = z.strictObject({
  version: z.literal(1),
  sandboxId: z.string().regex(/^[a-f0-9]{64}$/),
  fuseExitCode: z.number().int().min(0).max(255).optional(),
  runner: z
    .string()
    .regex(/^[a-z0-9-]{1,16}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/)
    .optional(),
  events: z
    .array(
      z.strictObject({
        sequence: z.number().int().positive().safe(),
        phase: z.enum([
          "configure",
          "preflight",
          "checkout",
          "restore",
          "process-start",
          "process-log-stream-open",
          "backup",
          "log-read",
          "log-list",
          "activity-expired",
          "stop",
          "destroy",
        ]),
        outcome: z.enum(["started", "succeeded", "failed"]),
        time: z.iso.datetime(),
        stop: z
          .strictObject({
            reason: z.enum(["exit", "runtime_signal"]),
            exitCode: z.number().int().min(-255).max(255),
          })
          .optional(),
        error: z
          .strictObject({
            name: z.enum([
              "Error",
              "RPCTransportError",
              "BackupRestoreError",
              "BackupCreateError",
              "ProcessReadyTimeoutError",
              "WorkflowInternalError",
              "TimeoutError",
            ]),
            code: z
              .enum([
                "RPC_TRANSPORT_ERROR",
                "BACKUP_RESTORE_FAILED",
                "BACKUP_CREATE_FAILED",
                "BACKUP_NOT_FOUND",
                "BACKUP_EXPIRED",
                "PROCESS_READY_TIMEOUT",
              ])
              .optional(),
            kind: z
              .enum([
                "session_disposed",
                "connection_failed",
                "upgrade_failed",
                "peer_closed",
                "invalid_frame",
                "protocol_error",
                "unknown",
              ])
              .optional(),
          })
          .optional(),
      }),
    )
    .max(64),
  truncated: z.boolean(),
});

const json = <T>(value: T, status = 200) =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

export async function diagnosticsHttp(
  request: Request,
  bucket: DiagnosticBucket,
): Promise<Response> {
  if (request.method !== "GET") return json({ error: "Not found" }, 404);
  const url = new URL(request.url);

  if (
    [...url.searchParams.keys()].some((key) => key !== "cursor") ||
    url.searchParams.getAll("cursor").length > 1 ||
    (url.searchParams.get("cursor")?.length ?? 0) > 1024
  )
    return json({ error: "Invalid diagnostic query" }, 400);

  try {
    if (url.pathname === "/diagnostics/sandboxes") {
      if (!bucket.list) return json({ error: "Diagnostics unavailable" }, 503);
      const cursor = url.searchParams.get("cursor") ?? undefined;
      const listed = await bucket.list({ prefix: "diagnostics/sandboxes/", limit: 50, cursor });

      if (listed.objects.length > 50 || (listed.truncated && !listed.cursor))
        throw new Error("Invalid diagnostic listing");

      const ids = listed.objects.map((object) => {
        const match = /^diagnostics\/sandboxes\/([a-f0-9]{64})\.json$/.exec(object.key);

        if (!match) throw new Error("Invalid diagnostic key");

        return match[1];
      });

      return json({
        ids,
        truncated: listed.truncated,
        cursor: listed.truncated ? listed.cursor : null,
      });
    }

    const match = /^\/diagnostics\/sandboxes\/([a-f0-9]{64})$/.exec(url.pathname);

    if (!match || url.searchParams.size) return json({ error: "Not found" }, 404);
    const stored = await bucket.get(`diagnostics/sandboxes/${match[1]}.json`);

    if (!stored) return json({ error: "Not found" }, 404);

    if ((stored.size ?? 0) > 32000) throw new Error("Diagnostic record exceeds byte budget");
    const text = await stored.text();

    if (new TextEncoder().encode(text).length > 32000)
      throw new Error("Diagnostic record exceeds byte budget");
    const record = recordSchema.parse(JSON.parse(text));

    if (record.sandboxId !== match[1]) throw new Error("Diagnostic identity mismatch");

    return json(record);
  } catch {
    return json({ error: "Diagnostics unavailable" }, 503);
  }
}

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

export const stableInterruptionReasons = [
  "runtime_replaced",
  "transport_disposed",
  "sandbox_lifetime_changed",
  "recovery_exhausted",
] as const;

export const stableInterruptionOperations = [
  "sandbox.exec",
  "sandbox.execWithSessionToken",
  "sandbox.startProcess",
  "sandbox.restoreBackup",
  "sandbox.createBackup",
  "sandbox.streamProcessLogs",
  "sandbox.readFileStream",
  "sandbox.listFiles",
  "sandbox.destroy",
  "sandbox.stop",
  "sandbox.configure",
  "commands.execute",
  "commands.executeStream",
  "processes.startProcess",
  "processes.streamProcessLogs",
  "files.readFileStream",
  "files.listFiles",
  "files.mkdir",
  "files.writeFile",
  "files.writeFileStream",
  "backup.restore",
  "backup.restoreArchive",
  "backup.createArchive",
  "backup.uploadParts",
  "rpc.connect",
] as const;

export const stableInterruptionCauses = [
  "code-update-reset",
  "network-connection-lost",
  "do-storage-startup-reset",
] as const;

export const diagnosticByteLimit = 32000;
export const stableInterruptionPhases = [
  "durable_object_call", "rpc_call", "connection", "validating",
  "runtime_ready", "archive_ready", "interrupted",
] as const;

export const diagnosticErrorSchema = z.strictObject({
  name: z.enum([
    "Error",
    "OperationInterruptedError",
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
      "OPERATION_INTERRUPTED",
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
  closeCode: z.number().int().min(1000).max(4999).optional(),
  reason: z.enum(stableInterruptionReasons).optional(),
  operation: z.enum(stableInterruptionOperations).optional(),
  phase: z.enum(stableInterruptionPhases).optional(),
  admitted: z.union([z.boolean(), z.literal("unknown")]).optional(),
  retryable: z.boolean().optional(),
  containerExitCode: z.number().int().min(-255).max(255).optional(),
  stopReason: z.enum(["exit", "runtime_signal"]).optional(),
  cause: z.enum(stableInterruptionCauses).optional(),
});

export const recordSchema = z.strictObject({
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
        error: diagnosticErrorSchema.optional(),
      }),
    )
    .max(64),
  truncated: z.boolean(),
}).refine((record) => record.events.every((event, index, events) =>
  event.sequence < Number.MAX_SAFE_INTEGER - 2 &&
  (event.sequence > (events[index - 1]?.sequence ?? 0))), "Invalid diagnostic sequence");

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

      const ids = listed.objects.flatMap((object) => {
        if (/^diagnostics\/sandboxes\/[a-f0-9]{64}-retention\.json$/.test(object.key)) return [];

        const match = /^diagnostics\/sandboxes\/([a-f0-9]{64})\.json$/.exec(object.key);

        if (!match) throw new Error("Invalid diagnostic key");

        return [match[1]];
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

    if ((stored.size ?? 0) > diagnosticByteLimit) throw new Error("Diagnostic record exceeds byte budget");
    const text = await stored.text();

    if (new TextEncoder().encode(text).length > diagnosticByteLimit)
      throw new Error("Diagnostic record exceeds byte budget");
    const record = recordSchema.parse(JSON.parse(text));

    if (record.sandboxId !== match[1]) throw new Error("Diagnostic identity mismatch");

    return json(record);
  } catch {
    return json({ error: "Diagnostics unavailable" }, 503);
  }
}

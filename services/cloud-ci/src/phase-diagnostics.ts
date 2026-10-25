import { z } from "zod";
import {
    diagnosticErrorSchema,
    diagnosticByteLimit,
    stableInterruptionPhases,
    recordSchema,
    stableInterruptionCauses,
    stableInterruptionOperations,
    stableInterruptionReasons,
} from "./diagnostics-http";

type Phase =
    | "configure"
    | "preflight"
    | "checkout"
    | "restore"
    | "process-start"
    | "process-log-stream-open"
    | "backup"
    | "log-read"
    | "log-list"
    | "activity-expired"
    | "stop"
    | "destroy";

type InterruptionCause = (typeof stableInterruptionCauses)[number];

const failureSchema = z.object({
    name: z
        .enum([
            "Error",
            "OperationInterruptedError",
            "RPCTransportError",
            "BackupRestoreError",
            "BackupCreateError",
            "ProcessReadyTimeoutError",
            "WorkflowInternalError",
            "TimeoutError",
        ])
        .catch("Error"),
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
        .optional()
        .catch(undefined),
    context: z
        .object({
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
                .catch("unknown"),
            closeCode: z.number().int().min(1000).max(4999).optional().catch(undefined),
            reason: z.enum(stableInterruptionReasons).optional().catch(undefined),
            operation: z.enum(stableInterruptionOperations).optional().catch(undefined),
            phase: z.enum(stableInterruptionPhases).optional().catch(undefined),
            admitted: z.union([z.boolean(), z.literal("unknown")]).optional().catch(undefined),
            retryable: z.boolean().optional().catch(undefined),
            containerExitCode: z.number().int().min(-255).max(255).optional().catch(undefined),
            stopReason: z.enum(["exit", "runtime_signal"]).optional().catch(undefined),
        })
        .optional()
        .catch(undefined),
});

type DiagnosticRecord = z.infer<typeof recordSchema>;

type PhaseEvent = DiagnosticRecord["events"][number];

const stopSchema = z.object({
    reason: z.enum(["exit", "runtime_signal"]),
    exitCode: z.number().int().min(-255).max(255),
});

export type StopDetails = z.infer<typeof stopSchema>;

const causeProbe = z.object({
    message: z.string().max(8192).optional(),
    cause: z.unknown().optional(),
});

function classifyCause(error: unknown): InterruptionCause | undefined {
    let current: unknown = error;
    for (let depth = 0; depth < 8; depth++) {
        const probe = causeProbe.safeParse(current);
        if (!probe.success) return undefined;
        const message = probe.data.message ?? "";
        if (/reset because its code was updated|this script has been upgraded/i.test(message))
            return "code-update-reset";
        if (/network connection lost/i.test(message)) return "network-connection-lost";
        if (/internal error while starting up durable object storage caused object to be reset/i.test(message))
            return "do-storage-startup-reset";
        current = probe.data.cause;
    }
    return undefined;
}

export class PhaseDiagnostics {
    private events: PhaseEvent[] = [];
    private sequence = 0;
    private truncated = false;
    private pending: Promise<void> = Promise.resolve();
    private ready: Promise<void>;
    private writable = true;
    private writeWarningEmitted = false;
    private readWarningEmitted = false;
    private runner?: string;
    private fuseExitCode?: number;
    constructor(
        readonly id: string,
        readonly write: (key: string, value: string) => Promise<object | null | void>,
        private readonly read?: (key: string) => Promise<string | null>,
    ) {
        if (!/^[a-f0-9]{64}$/.test(id)) throw new Error("Invalid sandbox diagnostic identity");
        this.ready = this.pending = this.pending.then(() => this.hydrate());
    }
    private get key() {
        return `diagnostics/sandboxes/${this.id}.json`;
    }
    private async hydrate() {
        if (!this.read) return;

        let stored: string | null;

        try {
            stored = await this.read(this.key);
        } catch {
            this.writable = false;
            this.warnReadFailure();

            return;
        }

        if (stored === null) return;
        if (new TextEncoder().encode(stored).byteLength > diagnosticByteLimit) {
            this.writable = false;
            this.warnReadFailure();
            return;
        }

        let value: unknown;

        try {
            value = JSON.parse(stored);
        } catch {
            this.writable = false;
            this.warnReadFailure();

            return;
        }

        const parsed = recordSchema.safeParse(value);

        if (!parsed.success || parsed.data.sandboxId !== this.id) {
            this.writable = false;
            this.warnReadFailure();

            return;
        }

        this.events = parsed.data.events;
        this.truncated = parsed.data.truncated;
        this.sequence = this.events.reduce((max, event) => Math.max(max, event.sequence), 0);
        this.runner ??= parsed.data.runner;
        this.fuseExitCode ??= parsed.data.fuseExitCode;
    }
    private warnReadFailure() {
        if (this.readWarningEmitted) return;

        this.readWarningEmitted = true;
        console.warn(
            JSON.stringify({
                event: "cloud-ci-diagnostic-read-failed",
                sandboxId: this.id,
            }),
        );
    }
    setRunner(name: string) {
        if (
            /^[a-z0-9-]{1,16}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(
                name,
            )
        )
            this.runner = name;
    }
    setFuseExitCode(exitCode: number) {
        if (Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255)
            this.fuseExitCode = exitCode;
    }
    private record(
        phase: Phase,
        outcome: PhaseEvent["outcome"],
        error?: PhaseEvent["error"],
        stop?: StopDetails,
    ) {
        const parsedStop = stopSchema.safeParse(stop);
        const time = new Date().toISOString();
        this.pending = this.pending.then(async () => {
            if (!this.writable) return;
            this.events.push({
                sequence: ++this.sequence, phase, outcome, time, error,
                stop: parsedStop.success ? parsedStop.data : undefined,
            });
            while (this.events.length > 64 ||
                new TextEncoder().encode(this.document()).byteLength > diagnosticByteLimit) {
                this.events.shift();
                this.truncated = true;
            }
            try {
                await this.write(this.key, this.document());
            } catch {
                if (!this.writeWarningEmitted) {
                    this.writeWarningEmitted = true;
                    console.warn(
                        JSON.stringify({
                            event: "cloud-ci-diagnostic-write-failed",
                            sandboxId: this.id,
                        }),
                    );
                }
            }
        });
    }
    async run<T>(phase: Phase, operation: () => Promise<T>, stop?: StopDetails): Promise<T> {
        this.record(phase, "started", undefined, stop);

        try {
            const result = await operation();
            this.record(phase, "succeeded", undefined, stop);

            return result;
        } catch (error) {
            this.record(phase, "failed", this.describeFailure(error), stop);
            throw error;
        }
    }
    private document() {
        return JSON.stringify({
            version: 1,
            sandboxId: this.id,
            runner: this.runner,
            fuseExitCode: this.fuseExitCode,
            events: this.events,
            truncated: this.truncated,
        });
    }
    private describeFailure(error: unknown): PhaseEvent["error"] {
        const parsed = failureSchema.safeParse(error);
        const context = parsed.success ? parsed.data.context : undefined;
        const validated = diagnosticErrorSchema.safeParse({
            name: parsed.success ? parsed.data.name : "Error",
            code: parsed.success ? parsed.data.code : undefined,
            kind: context?.kind,
            closeCode: context?.closeCode,
            reason: context?.reason,
            operation: context?.operation,
            phase: context?.phase,
            admitted: context?.admitted,
            retryable: context?.retryable,
            containerExitCode: context?.containerExitCode,
            stopReason: context?.stopReason,
            cause: classifyCause(error),
        });

        return validated.success ? validated.data : { name: "Error" };
    }
    async flush() {
        await this.ready;
        await this.pending;
    }
}

import { z } from "zod";

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

const failureSchema = z.object({
    name: z
        .enum([
            "Error",
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
        })
        .optional()
        .catch(undefined),
});

type PhaseEvent = {
    sequence: number;
    phase: Phase;
    outcome: "started" | "succeeded" | "failed";
    time: string;
    error?: { name: string; code?: string; kind?: string };
    stop?: StopDetails;
};

const stopSchema = z.object({
    reason: z.enum(["exit", "runtime_signal"]),
    exitCode: z.number().int().min(-255).max(255),
});

export type StopDetails = z.infer<typeof stopSchema>;

export class PhaseDiagnostics {
    private events: PhaseEvent[] = [];
    private sequence = 0;
    private truncated = false;
    private pending = Promise.resolve();
    private writeWarningEmitted = false;
    private runner?: string;
    private fuseExitCode?: number;
    constructor(
        readonly id: string,
        readonly write: (key: string, value: string) => Promise<object | null | void>,
    ) {
        if (!/^[a-f0-9]{64}$/.test(id)) throw new Error("Invalid sandbox diagnostic identity");
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
        this.events.push({
            sequence: ++this.sequence,
            phase,
            outcome,
            time: new Date().toISOString(),
            error,
            stop: parsedStop.success ? parsedStop.data : undefined,
        });

        if (this.events.length > 64) {
            this.events.shift();
            this.truncated = true;
        }

        const document = JSON.stringify({
            version: 1,
            sandboxId: this.id,
            runner: this.runner,
            fuseExitCode: this.fuseExitCode,
            events: this.events,
            truncated: this.truncated,
        });

        this.pending = this.pending.then(async () => {
            try {
                await this.write(`diagnostics/sandboxes/${this.id}.json`, document);
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
            const parsed = failureSchema.safeParse(error);
            this.record(
                phase,
                "failed",
                parsed.success
                    ? {
                          name: parsed.data.name,
                          code: parsed.data.code,
                          kind: parsed.data.context?.kind,
                      }
                    : { name: "Error" },
                stop,
            );
            throw error;
        }
    }
    async flush() {
        await this.pending;
    }
}

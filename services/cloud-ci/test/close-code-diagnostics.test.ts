import { expect, test } from "bun:test";
import { PhaseDiagnostics } from "../src/phase-diagnostics";
import { diagnosticsHttp, recordSchema } from "../src/diagnostics-http";
const id = "d".repeat(64);
test("owner schema rejects close codes outside the WebSocket range", async () => {
    const url = new Request(`https://fixture/diagnostics/sandboxes/${id}`);
    const bucket = (closeCode: unknown) => ({
        get: async () => ({
            text: async () =>
                JSON.stringify({
                    version: 1,
                    sandboxId: id,
                    truncated: false,
                    events: [
                        {
                            sequence: 1,
                            phase: "log-read",
                            outcome: "failed",
                            time: "2026-10-25T06:44:55.796Z",
                            error: {
                                name: "OperationInterruptedError",
                                kind: "peer_closed",
                                closeCode,
                            },
                        },
                    ],
                }),
        }),
    });

    expect((await diagnosticsHttp(url, bucket(1011))).status).toBe(200);
    expect((await diagnosticsHttp(url, bucket(6000))).status).toBe(503);
    expect((await diagnosticsHttp(url, bucket(1011.5))).status).toBe(503);
    expect((await diagnosticsHttp(url, bucket("1011"))).status).toBe(503);
});

test("structured socket metadata survives persistence and owner retrieval without raw details", async () => {
    for (const closeCode of [1011, 6000, 1011.5, "1011"]) {
        let stored = "";
        const trace = new PhaseDiagnostics(id, async (_key, value) => {
            stored = value;
        });
        const failure = Object.assign(new Error("private-fixture-secret"), {
            name: "OperationInterruptedError",
            code: "OPERATION_INTERRUPTED",
            context: {
                kind: "peer_closed",
                closeCode,
                reason: "transport_disposed",
                operation: "commands.execute",
                phase: "rpc_call",
                admitted: true,
                retryable: false,
                closeReason: "private-fixture-secret",
                originalMessage: "private-fixture-secret",
            },
        });
        await expect(
            trace.run("log-read", async () => {
                throw failure;
            }),
        ).rejects.toBe(failure);
        await trace.flush();
        const response = await diagnosticsHttp(
            new Request(`https://fixture/diagnostics/sandboxes/${id}`),
            {
                get: async () => ({ text: async () => stored }),
            },
        );
        expect(response.status).toBe(200);
        const document = recordSchema.parse(await response.json());
        expect(document.events.at(-1)?.error).toEqual({
            name: "OperationInterruptedError",
            code: "OPERATION_INTERRUPTED",
            kind: "peer_closed",
            ...(closeCode === 1011 ? { closeCode: 1011 } : {}),
            reason: "transport_disposed",
            operation: "commands.execute",
            phase: "rpc_call",
            admitted: true,
            retryable: false,
        });
        expect(stored).not.toContain("private-fixture-secret");
        expect(JSON.stringify(document)).not.toContain("closeReason");
    }
});

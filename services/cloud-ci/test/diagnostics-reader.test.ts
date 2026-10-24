
import { expect, test } from "bun:test";
import { PhaseDiagnostics } from "../src/phase-diagnostics";
import { diagnosticsHttp } from "../src/diagnostics-http";

test("public diagnostics reader accepts real recorder output for a structured interruption", async () => {
    const id = "d".repeat(64);
    const store = new Map<string, string>();
    const trace = new PhaseDiagnostics(
        id,
        async (target, value) => {
            store.set(target, value);
        },
        async (target) => store.get(target) ?? null,
    );
    const interruption = Object.assign(new Error("private-fixture-secret"), {
        name: "OperationInterruptedError",
        code: "OPERATION_INTERRUPTED",
        context: {
            reason: "runtime_replaced",
            operation: "sandbox.exec",
            phase: "durable_object_call",
            admitted: "unknown",
            retryable: false,
            containerExitCode: 137,
        },
        cause: Object.assign(new Error("Network connection lost. private-fixture-secret"), {}),
    });
    await expect(
        trace.run("process-start", async () => {
            throw interruption;
        }),
    ).rejects.toBe(interruption);
    await trace.flush();

    const bucket = {
        get: async (target: string) => {
            const text = store.get(target);
            return text === undefined ? null : { text: async () => text, size: text.length };
        },
    };
    const response = await diagnosticsHttp(
        new Request(`https://ci.test/diagnostics/sandboxes/${id}`),
        bucket,
    );
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain('"code":"OPERATION_INTERRUPTED"');
    expect(body).toContain('"reason":"runtime_replaced"');
    expect(body).toContain('"operation":"sandbox.exec"');
    expect(body).toContain('"phase":"durable_object_call"');
    expect(body).toContain('"admitted":"unknown"');
    expect(body).toContain('"retryable":false');
    expect(body).toContain('"containerExitCode":137');
    expect(body).toContain('"cause":"network-connection-lost"');
    expect(body).not.toContain("private-fixture-secret");
});

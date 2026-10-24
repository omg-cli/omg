
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

test("delayed hydration serializes concurrent events without delaying command results", async () => {
    const id = "9".repeat(64);
    const key = `diagnostics/sandboxes/${id}.json`;
    const store = new Map<string, string>();
    const first = new PhaseDiagnostics(id, async (target, text) => { store.set(target, text); });
    await first.run("checkout", async () => 1);
    await first.flush();
    const original = store.get(key);
    if (original === undefined) throw new Error("Missing initial history");
    let release: (text: string) => void = () => { throw new Error("Read not started"); };
    const hydration = new Promise<string>((resolve) => { release = resolve; });
    const recreated = new PhaseDiagnostics(id,
        async (target, text) => { store.set(target, text); }, async () => hydration);
    expect(await Promise.all([
        recreated.run("restore", async () => 2),
        recreated.run("log-read", async () => 3),
    ])).toEqual([2, 3]);
    expect(store.get(key)).toBe(original);
    release(original);
    await recreated.flush();
    const record = JSON.parse(store.get(key) ?? "{}");
    expect(record.events.map((event: { sequence: number }) => event.sequence)).toEqual([1, 2, 3, 4, 5, 6]);
    expect(record.events.slice(2).map((event: { phase: string }) => event.phase)).toEqual(["restore", "log-read", "restore", "log-read"]);
});

test("invalid sequence history is preserved and cannot replace a failed command", async () => {
    for (const sequences of [[2, 2], [2, 1], [Number.MAX_SAFE_INTEGER]]) {
        const id = "8".repeat(64);
        const key = `diagnostics/sandboxes/${id}.json`;
        const original = JSON.stringify({ version: 1, sandboxId: id, truncated: false,
            events: sequences.map((sequence) => ({sequence, phase: "checkout", outcome: "succeeded", time: "2026-10-23T00:00:00.000Z"})) });
        const store = new Map([[key, original]]);
        const trace = new PhaseDiagnostics(id, async (target, text) => { store.set(target, text); }, async () => original);
        const failure = new Error("Original command failure");
        await expect(trace.run("restore", async () => { throw failure; })).rejects.toBe(failure);
        await trace.flush();
        expect(store.get(key)).toBe(original);
    }
});

test("expanded concurrent interruption history fits the unchanged public reader byte budget", async () => {
    const id = "7".repeat(64);
    const key = `diagnostics/sandboxes/${id}.json`;
    const seed = JSON.stringify({ version: 1, sandboxId: id, truncated: false,
        events: [{sequence: 9007199254700000, phase: "checkout", outcome: "succeeded", time: "2026-10-23T00:00:00.000Z"}] });
    const store = new Map([[key, seed]]);
    const trace = new PhaseDiagnostics(id, async (target, text) => { store.set(target, text); }, async () => seed);
    trace.setRunner("abcdefghijklmnop-12345678-1234-1234-1234-123456789012");
    await Promise.all(Array.from({ length: 64 }, async () => {
        const failure = Object.assign(new Error("private-fixture-secret"), { name: "OperationInterruptedError", code: "OPERATION_INTERRUPTED",
            context: { kind: "connection_failed", reason: "sandbox_lifetime_changed", operation: "sandbox.execWithSessionToken",
                phase: "durable_object_call", admitted: "unknown", retryable: false, containerExitCode: 137, stopReason: "runtime_signal" },
            cause: new Error("Internal error while starting up Durable Object storage caused object to be reset. private-fixture-secret") });
        await expect(trace.run("process-log-stream-open", async () => { throw failure; }, {reason: "runtime_signal", exitCode: 137})).rejects.toBe(failure);
    }));
    await trace.flush();
    const text = store.get(key) ?? "";
    expect(new TextEncoder().encode(text).byteLength).toBeLessThanOrEqual(32000);
    const record = JSON.parse(text);
    expect(record.truncated).toBe(true);
    expect(record.events.length).toBeLessThanOrEqual(64);
    expect(record.events.at(-1).sequence).toBe(9007199254700128);
    expect(record.events.at(-1).error.cause).toBe("do-storage-startup-reset");
    expect(text).not.toContain("private-fixture-secret");
    const response = await diagnosticsHttp(new Request(`https://ci.test/diagnostics/sandboxes/${id}`), {
        get: async () => ({ text: async () => text, size: new TextEncoder().encode(text).byteLength }),
    });
    expect(response.status).toBe(200);
});

test("actual RPC and restore contexts retain their closed SDK fields", async () => {
    for (const [operation, phase] of [["commands.execute", "rpc_call"], ["backup.restore", "archive_ready"]]) {
        let text = "";
        const trace = new PhaseDiagnostics("6".repeat(64), async (_key, value) => { text = value; });
        const failure = Object.assign(new Error("private-fixture-secret"), { name: "OperationInterruptedError", code: "OPERATION_INTERRUPTED",
            context: { reason: "runtime_replaced", operation, phase, admitted: true, retryable: false },
            cause: new Error("Durable Object reset because its code was updated. private-fixture-secret") });
        await expect(trace.run("restore", async () => { throw failure; })).rejects.toBe(failure);
        await trace.flush();
        expect(JSON.parse(text).events.at(-1).error).toMatchObject({code: "OPERATION_INTERRUPTED", operation, phase, cause: "code-update-reset"});
        expect(text).not.toContain("private-fixture-secret");
    }
});

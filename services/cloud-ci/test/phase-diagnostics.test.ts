import { expect, test } from "bun:test";
import { PhaseDiagnostics } from "../src/phase-diagnostics";

test("phase evidence preserves failure identity and only closed error identifiers", async () => {
    const writes = new Map<string, string>();

    const trace = new PhaseDiagnostics("a".repeat(64), async (key, value) => {
        writes.set(key, value);
    });

    const failure = Object.assign(new Error("Authorization: Bearer private-fixture-secret"), {
        name: "RPCTransportError",
        code: "RPC_TRANSPORT_ERROR",
        context: { kind: "session_disposed", originalMessage: "private-fixture-secret" },
    });

    let observed;

    try {
        await trace.run("restore", async () => {
            throw failure;
        });
    } catch (error) {
        observed = error;
    }

    expect(observed).toBe(failure);
    await trace.flush();
    const evidence = writes.get(`diagnostics/sandboxes/${"a".repeat(64)}.json`) ?? "";
    expect(evidence).toContain('"phase":"restore"');
    expect(evidence).toContain('"kind":"session_disposed"');
    expect(evidence).not.toContain("private-fixture-secret");
    expect(evidence).not.toContain("Authorization");
});

test("diagnostic persistence failure cannot replace command result and event storage is capped", async () => {
    let last = "";

    const trace = new PhaseDiagnostics("b".repeat(64), async (_key, value) => {
        last = value;
        throw new Error("storage outage");
    });

    for (let index = 0; index < 40; index++)
        expect(await trace.run("log-read", async () => 7)).toBe(7);
    await trace.flush();
    expect(last).toContain('"truncated":true');
    expect(last.length).toBeLessThan(20000);
});

test("diagnostic write failures are bounded and sanitized without replacing command failure", async () => {
    const warnings: string[] = [];
    const warn = console.warn;
    console.warn = (value: string) => {
        warnings.push(value);
    };
    try {
        const trace = new PhaseDiagnostics("c".repeat(64), async () => {
            throw new Error("private-token");
        });
        const failure = new Error("original command failure");
        for (let index = 0; index < 3; index++) {
            await expect(
                trace.run("restore", async () => {
                    throw failure;
                }),
            ).rejects.toBe(failure);
        }
        await trace.flush();
        expect(warnings).toEqual([
            JSON.stringify({
                event: "cloud-ci-diagnostic-write-failed",
                sandboxId: "c".repeat(64),
            }),
        ]);
        expect(warnings.join()).not.toContain("private-token");
    } finally {
        console.warn = warn;
    }
});

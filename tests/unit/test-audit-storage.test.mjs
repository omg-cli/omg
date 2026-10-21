import { test } from "bun:test";
import assert from "node:assert/strict";
import { updateCodingResult } from "../../services/ci-coder/src/tools.ts";

test("audit storage budget rejects oversized exact serialized state before any durable put", async () => {
    let puts = 0;
    const state = {
        calls: 1,
        reads: [],
        verifiedDigests: [],
        testAudit: {
            proposal: { padding: "x".repeat(1.5 * 1024 * 1024) },
            proposalSha256: "a".repeat(64),
        },
    };
    const transaction = {
        get: async () => undefined,
        put: async () => {
            puts++;
        },
    };
    const storage = { transaction: async (change) => change(transaction) };
    await assert.rejects(
        updateCodingResult(storage, () => state),
        /1.5 MiB/,
    );
    assert.equal(puts, 0);
    await updateCodingResult(storage, () => ({
        calls: 0,
        reads: [],
        verifiedDigests: [],
    }));
    assert.equal(puts, 1);
});

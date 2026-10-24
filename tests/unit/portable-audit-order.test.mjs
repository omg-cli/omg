import { test } from "bun:test";
import assert from "node:assert/strict";
import { runTestAuditPage } from "../../scripts/test-audit-flow.mjs";

const sha = "a".repeat(40);
const row = { id: "lib:omg_lib#doctor::probe", status: "selected",
    request: { sha }, task: { path: "src/doctor.rs", target: "lib", testName: "doctor::probe" } };
const formatting = { status: "passed", sha, ref: "refs/heads/main", runId: "100", attempt: "2" };
const input = { collected: { rows: [row], sourceRange: { kind: "test-audit" } },
    sha, branch: "main", formatting, publishRequested: true };

test("unsupported portable test is held before any model call and remains unresolved", async () => {
    let modelCalls = 0;
    const report = await runTestAuditPage({ ...input, io: {
        portableTest: async () => { throw new Error("Portable test is not executed in this recipe"); },
        audit: async () => { modelCalls++; return null; },
    } });
    assert.equal(modelCalls, 0);
    assert.deepEqual(report.testAuditOutcomes, [{ id: row.id, status: "held", reason: "Portable test is not executed in this recipe" }]);
    assert.deepEqual(report.unreviewedPaths, [{ path: row.task.path, reason: "Portable test is not executed in this recipe" }]);
    assert.deepEqual(report.testAudits, []);
    assert.deepEqual(report.publications, []);
});

test("portable membership admits the original row before the unchanged audit path", async () => {
    const calls = [];
    const report = await runTestAuditPage({ ...input, io: {
        portableTest: async (actualRow, actualFormatting) => {
            assert.equal(actualRow, row); assert.equal(actualFormatting, formatting); calls.push("membership");
        },
        audit: async actualRow => { assert.equal(actualRow, row); calls.push("audit"); return null; },
    } });
    assert.deepEqual(calls, ["membership", "audit"]);
    assert.deepEqual(report.testAuditOutcomes, [{ id: row.id, status: "no-supported-strengthening" }]);
    assert.deepEqual(report.publications, []);
});

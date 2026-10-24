import { test } from "bun:test";
import assert from "node:assert/strict";
import {
    runTestAuditPage,
    testAuditContinuation,
} from "../../scripts/test-audit-flow.mjs";

test("bounded test-audit page hands exact selected task to coder and preserves held and no-findings statuses", async () => {
    const calls = [];
    const sha = "a".repeat(40),
        digest = "b".repeat(64);
    const collected = {
        sourceRange: {
            kind: "test-audit",
            sha,
            inventoryDigest: digest,
            cursor: 0,
            nextCursor: 2,
            totalPaths: 3,
            pagePaths: 2,
        },
        rows: [
            { id: "a::case", status: "held", reason: "native-only" },
            {
                id: "b::case",
                status: "selected",
                request: { sha },
                task: { testName: "b::case" },
            },
        ],
    };
    const result = await runTestAuditPage({
        collected,
        sha,
        branch: "main",
        formatting: { status: "passed" },
        publishRequested: true,
        io: {
            portableTest: async () => {},
            audit: async (row) => {
                calls.push(row);
                return null;
            },
        },
    });
    assert.equal(calls.length, 1);
    assert.deepEqual(calls[0], collected.rows[1]);
    assert.equal(
        result.testAuditOutcomes[1].status,
        "no-supported-strengthening",
    );
    assert.equal(result.publications.length, 0);
    const next = testAuditContinuation(result, sha, "42", "1");
    assert.equal(next.inputs.scope, "test-audit");
    assert.equal(next.inputs.audit_cursor, "2");
    assert.equal(
        testAuditContinuation(result, "c".repeat(40), "42", "1").status,
        "incomplete-stale",
    );
});
import {
    reviewTarget,
    runReviewFlow,
    sourceAuditContinuation,
} from "../../scripts/ai-review-flow.mjs";
test("existing review coordinator accepts bounded audit scope and bypasses defect Inspector for selected tests", async () => {
    const sha = "a".repeat(40),
        inventoryDigest = "b".repeat(64);
    const target = reviewTarget("workflow_dispatch", {
        repository: { full_name: "omg-cli/omg" },
        inputs: { branch: "main", scope: "test-audit", publish: "true" },
    });
    assert.equal(target.range.kind, "test-audit");
    const row = {
        id: "value::checks_value",
        status: "selected",
        task: {
            path: "src/value.rs",
            testName: "value::checks_value",
            originalBlobSha: "c".repeat(40),
            target: "lib",
        },
        request: { sha },
    };
    let calls = 0;
    const report = await runReviewFlow({
        target: { ...target, sha },
        io: {
            head: async () => sha,
            collect: async () => ({
                baseSha: sha,
                sourceRange: {
                    kind: "test-audit",
                    sha,
                    inventoryDigest,
                    cursor: 0,
                    totalPaths: 3,
                    pagePaths: 2,
                    nextCursor: 2,
                },
                entries: [{ path: "src/value.rs" }],
                rows: [row, { id: "held", status: "held", reason: "native" }],
                unreviewedPaths: [],
            }),
            format: async () => ({ status: "passed" }),
            portableTest: async () => {},
            audit: async () => {
                calls++;
                return null;
            },
            review: async () => {
                throw new Error("Inspector must not receive test audit tasks");
            },
        },
    });
    assert.equal(calls, 1);
    assert.equal(report.testAuditOutcomes.length, 2);
    assert.equal(
        sourceAuditContinuation(report, sha, "42", "1").inputs.scope,
        "test-audit",
    );
});

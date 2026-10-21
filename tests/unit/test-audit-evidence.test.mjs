import { test } from "bun:test";
import assert from "node:assert/strict";
import { testAuditProofFixture } from "./fixtures/test-audit-proof.mjs";
import { verifyCloudTestAudit } from "../../scripts/cloud-test-audit-evidence.mjs";
import { verifyCloudCiReceipt } from "../../scripts/cloud-ci-evidence.mjs";

test("existing-test receipt admits all actual raw state reports and portable leaves only through separate purpose", async () => {
    const f = testAuditProofFixture();
    let reads = 0;
    const evidence = await verifyCloudTestAudit(
        f.receipt,
        f.request,
        f.policy,
        async (key) => {
            reads++;
            return f.load(key);
        },
    );
    assert.equal(evidence.strongerFault.exitCode, 101);
    assert.equal(reads, 20);
    assert.throws(
        () => verifyCloudCiReceipt(f.receipt, f.request, f.policy),
        /separate/,
    );
    for (const mutate of [
        (f) => {
            f.objects.delete(f.receipt.testAuditReports[0].key);
        },
        (f) => {
            f.objects.set(f.receipt.testAuditReports[2].key, "forged");
        },
        (f) => {
            f.receipt.testAuditReceipt.strongerFault.assertionLine = 5;
        },
        (f) => {
            f.receipt.checks.pop();
        },
    ]) {
        const bad = testAuditProofFixture();
        mutate(bad);
        await assert.rejects(
            verifyCloudTestAudit(
                bad.receipt,
                bad.request,
                bad.policy,
                bad.load,
            ),
        );
    }
});

test("adequate existing test admits exactly two raw phases and exports no changed paths", async () => {
    const f = testAuditProofFixture({ sensitivity: true });
    let reads = 0;
    const result = await verifyCloudTestAudit(
        f.receipt,
        f.request,
        f.policy,
        async (key) => {
            reads++;
            return f.load(key);
        },
    );
    assert.equal(result.purpose, "existing-test-sensitivity");
    assert.deepEqual(result.changedPaths, []);
    assert.equal(reads, 18);
    assert.equal(f.receipt.testAuditReports.length, 2);
});

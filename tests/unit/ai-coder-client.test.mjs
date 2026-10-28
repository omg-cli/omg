import assert from "node:assert/strict";
import { test } from "bun:test";
import { admitCoderResult, coderNoRepairDiagnostic, readCoderNoRepairDiagnostic } from "../../scripts/ai-coder-client.mjs";
import { proposalDigest } from "../../scripts/ai-review-publication.mjs";
import { operationIdentity, parseCodingRequest } from "../../services/ci-coder/src/request.ts";
import { testAuditProofFixture } from "./fixtures/test-audit-proof.mjs";

test("no-repair diagnostics bind the actual operation and retain only a bounded complete unverified conclusion",()=>{
    const {request}=fixture(),id=operationIdentity(request);
    const response={id,status:"done",diagnosisHistory:[{id:"m1",text:["Read source"]},{id:"m2",text:[]},
        {id:"m3",text:["The designated regression path was unavailable."]}]};
    assert.deepEqual(coderNoRepairDiagnostic(response,request),{operationId:id,
        scope:"Unverified agent conclusion, not test or repair proof",agentConclusion:"The designated regression path was unavailable.",omissionReason:null});
    assert.throws(()=>coderNoRepairDiagnostic({...response,id:"other"},request));
    assert.throws(()=>coderNoRepairDiagnostic({...response,status:"running"},request));
    const large={...response,diagnosisHistory:[{id:"m4",text:["é".repeat(4001)]}]};
    const original=JSON.stringify(large);
    const result=coderNoRepairDiagnostic(large,request);
    assert.equal(result.agentConclusion,null);
    assert.match(result.omissionReason,/Complete message exceeds/);
    assert.equal(JSON.stringify(large),original);
});

test("unavailable or invalid optional history preserves a completed no-repair outcome without trusting diagnostic bytes",async()=>{
    const {request}=fixture(),id=operationIdentity(request);
    const expected={operationId:id,scope:"Unverified agent conclusion, not test or repair proof",agentConclusion:null,
        omissionReason:"Opt-in history unavailable or rejected; no repair produced"};
    assert.deepEqual(await readCoderNoRepairDiagnostic(async()=>{throw new Error("Bearer private-fixture-token");},request),expected);
    assert.deepEqual(await readCoderNoRepairDiagnostic(async()=>({id:"wrong",status:"done",diagnosisHistory:[]}),request),expected);
    const response={id,status:"done",diagnosisHistory:[{id:"m1",text:["No supported repair"]}]};
    assert.deepEqual(await readCoderNoRepairDiagnostic(async()=>response,request),coderNoRepairDiagnostic(response,request));
});

function auditFixture() {
    const proof = testAuditProofFixture();
    const base = fixture();
    const { proposal } = proof;
    const request = parseCodingRequest({
        ...base.request,
        source: {
            ...base.request.source,
            changedPaths: [],
            auditPaths: [proposal.test.path, proposal.fault.path],
            diff: "",
            ciFailures: [],
            sourceFiles: [
                { path: proposal.test.path, content: proposal.test.originalContent, blobSha: proposal.test.originalBlobSha },
                { path: proposal.fault.path, content: proof.production, blobSha: proposal.fault.originalBlobSha },
            ],
        },
        testAuditTask: {
            path: proposal.test.path,
            testName: proposal.test.testName,
            originalBlobSha: proposal.test.originalBlobSha,
        },
    });
    const digest = proof.receipt.testAuditReceipt.proposalSha256;
    const id = `cl-42-1-${request.sha}-ta-${digest.slice(0, 16)}`;
    const continuationId = `cv-42-1-${request.sha}-${digest.slice(0, 16)}`;
    const response = {
        ...base.response,
        ...request,
        id: operationIdentity(request),
        result: {
            ...base.response.result,
            reads: [{ path: proposal.test.path, start: 1, end: 1 }],
            testAudit: { proposal, proposalSha256: digest },
            verification: { proposalSha256: digest, id, receipt: {} },
            verificationJob: { ...base.response.result.verificationJob, id, proposalSha256: digest, continuationId, status: "verified" },
        },
        initialOperation: { operationId: operationIdentity(request), status: "done" },
        continuation: { ...base.response.continuation, operationId: continuationId, parentOperationId: operationIdentity(request), proposalSha256: digest, verificationId: id },
    };
    delete response.result.proposal;
    return { request, policy: base.policy, response, digest };
}

test("existing-test audit admission binds the exact audit proposal and only the exact failed continuation reason", () => {
    const { request, policy, response, digest } = auditFixture();
    assert.equal(admitCoderResult(response, request, policy).proposalSha256, digest);
    const failed = structuredClone(response);
    delete failed.result.verification;
    failed.result.verificationJob.status = "failed";
    failed.result.verificationJob.reason = "audit verifier rejected the fault marker";
    assert.throws(() => admitCoderResult(failed, request, policy), /audit verifier rejected the fault marker/);
    for (const mutate of [
        (value) => { value.result.verificationJob.id = "other"; },
        (value) => { value.result.verificationJob.proposalSha256 = "0".repeat(64); },
        (value) => { value.result.verificationJob.sessionId = "other"; },
        (value) => { value.result.verificationJob.continuationId = "other"; },
    ]) {
        const changed = structuredClone(failed);
        mutate(changed);
        assert.throws(
            () => admitCoderResult(changed, request, policy),
            (error) => !String(error.message).includes("audit verifier rejected the fault marker"),
        );
    }
});

function fixture() {
    const request = {
        repository: "omg-cli/omg",
        sha: "a".repeat(40),
        branch: "main",
        runId: "42",
        attempt: "1",
        source: {
            repository: "omg-cli/omg",
            sha: "a".repeat(40),
            branch: "main",
            changedPaths: ["src/value.rs"],
            diff: "value",
            ciFailures: [],
            sourceFiles: [
                {
                    path: "src/value.rs",
                    content: "pub const value: usize = 1;\n",
                    blobSha: "e".repeat(40),
                },
            ],
        },
    };

    const policy = {
        bundleSha256: "b".repeat(64),
        imageDigest: `sha256:${"c".repeat(64)}`,
        verifierRevision: "d".repeat(40),
    };

    const proposal = {
        repository: request.repository,
        baseSha: request.sha,
        branch: request.branch,
        changes: [],
    };

    const digest = proposalDigest(proposal);

    const response = {
        ...request,
        id: operationIdentity(request),
        status: "done",
        runtime: {
            ...policy,
            model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
            reasoningEffort: "low",
        },
        skillsDelivery: { bundleSha256: policy.bundleSha256, sessionId: "session-1" },
        result: {
            calls: 4,
            reads: [{ path: "src/value.rs", start: 1, end: 1 }],
            sessionId: "session-1",
            skillBundleSha256: policy.bundleSha256,
            proposal: {
                proposal,
                regression: { path: "tests/ci-review-a-1.rs", testName: "value" },
                proposalSha256: digest,
            },
            verification: {
                proposalSha256: digest,
                id: `cl-42-1-${request.sha}-v-${digest.slice(0, 16)}`,
                receipt: {},
            },
        },
    };

    const id = operationIdentity(request);
    const continuationId = `cv-${request.runId}-${request.attempt}-${request.sha}-${digest.slice(0, 16)}`;
    response.initialOperation = { operationId: id, status: "done" };
    response.continuation = {
        operationId: continuationId,
        parentOperationId: id,
        sessionId: "session-1",
        proposalSha256: digest,
        verificationId: response.result.verification.id,
        status: "done",
    };
    response.result.verificationJob = {
        id: response.result.verification.id,
        proposalSha256: digest,
        sessionId: "session-1",
        continuationId,
        status: "verified",
        deadline: 1,
    };

    return { request, policy, response };
}

test("coding admission binds exact server skill delivery, runtime, source and verified proposal", () => {
    const { request, policy, response } = fixture();
    assert.equal(
        admitCoderResult(response, request, policy).proposalSha256,
        response.result.proposal.proposalSha256,
    );

    for (const mutate of [
        (value) => {
            value.skillsDelivery = undefined;
        },
        (value) => {
            value.result.sessionId = "different-session";
        },
        (value) => {
            value.runtime.bundleSha256 = "e".repeat(64);
        },
        (value) => {
            value.runtime.model = "unapproved";
        },
        (value) => {
            value.runtime.reasoningEffort = "high";
        },
        (value) => {
            value.result.verification.proposalSha256 = "f".repeat(64);
        },
        (value) => {
            value.result.proposal.proposal.changes.push({ path: "changed" });
        },
        (value) => {
            value.sha = "f".repeat(40);
        },
        (value) => {
            value.result.reads = [];
        },
        (value) => {
            value.result.calls = 97;
        },
    ]) {
        const changed = structuredClone(response);
        mutate(changed);
        assert.throws(() => admitCoderResult(changed, request, policy));
    }
});

test("coding proposals require the actual completed continuation of the verified original session", () => {
    const { request, policy, response } = fixture();
    for (const change of [
        (value) => {
            delete value.continuation;
        },
        (value) => {
            value.continuation.status = "unanswered";
        },
        (value) => {
            value.continuation.operationId = value.id;
        },
        (value) => {
            value.continuation.parentOperationId = "other";
        },
        (value) => {
            value.continuation.sessionId = "other";
        },
        (value) => {
            value.continuation.proposalSha256 = "0".repeat(64);
        },
        (value) => {
            value.continuation.verificationId = "other";
        },
        (value) => {
            value.initialOperation.status = "running";
        },
        (value) => {
            value.initialOperation.operationId = "other";
        },
        (value) => {
            value.result.verificationJob.status = "pending";
        },
        (value) => {
            value.result.verificationJob.continuationId = "other";
        },
        (value) => {
            value.result.verificationJob.sessionId = "other";
        },
    ]) {
        const changed = structuredClone(response);
        change(changed);
        assert.throws(() => admitCoderResult(changed, request, policy));
    }
    const noFinding = structuredClone(response);
    delete noFinding.result.proposal;
    delete noFinding.result.verificationJob;
    delete noFinding.continuation;
    assert.equal(admitCoderResult(noFinding, request, policy), null);
});

test("coding admission surfaces the exact failed verification reason for the active proposal", () => {
    const { request, policy, response } = fixture();
    const failed = structuredClone(response);
    delete failed.result.verification;
    failed.result.verificationJob.status = "failed";
    failed.result.verificationJob.reason =
        "Automatic repairs cannot change existing Rust tests";
    assert.throws(
        () => admitCoderResult(failed, request, policy),
        /Automatic repairs cannot change existing Rust tests/,
    );
});

test("coding admission does not attribute a forged or stale failed job to the active proposal", () => {
    const { request, policy, response } = fixture();
    for (const mutate of [
        (value) => {
            value.result.verificationJob.id = "other";
        },
        (value) => {
            value.result.verificationJob.proposalSha256 = "0".repeat(64);
        },
        (value) => {
            value.result.verificationJob.sessionId = "other";
        },
        (value) => {
            value.result.verificationJob.continuationId = "other";
        },
        (value) => {
            value.continuation.operationId = "other";
        },
    ]) {
        const changed = structuredClone(response);
        delete changed.result.verification;
        changed.result.verificationJob.status = "failed";
        changed.result.verificationJob.reason = "stale failed reason";
        mutate(changed);
        assert.throws(
            () => admitCoderResult(changed, request, policy),
            (error) => !String(error.message).includes("stale failed reason"),
        );
    }
});

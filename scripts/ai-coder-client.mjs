import { createTestAuditProposal } from "../services/ci-coder/src/test-audit.ts";
import { proposalDigest } from "./ai-review-publication.mjs";
import { operationIdentity } from "../services/ci-coder/src/request.ts";
import { Schema } from "effect";

export async function readCoderNoRepairDiagnostic(readHistory,request) {
    try {return coderNoRepairDiagnostic(await readHistory(),request);}
    catch {return {operationId:operationIdentity(request),scope:"Unverified agent conclusion, not test or repair proof",
        agentConclusion:null,omissionReason:"Opt-in history unavailable or rejected; no repair produced"};}
}

export function coderNoRepairDiagnostic(response,request) {
    const history=Schema.decodeUnknownSync(Schema.Struct({
        id:Schema.Literal(operationIdentity(request)),status:Schema.Literal("done"),
        diagnosisHistory:Schema.Array(Schema.Struct({id:Schema.String,text:Schema.Array(Schema.String)})),
    }))({id:response.id,status:response.status,diagnosisHistory:response.diagnosisHistory});
    const conclusion=history.diagnosisHistory.map(message=>message.text.join("\n")).filter(text=>text.trim()).at(-1);
    const omitted=conclusion!==undefined&&Buffer.byteLength(conclusion,"utf8")>8000;
    return {operationId:history.id,scope:"Unverified agent conclusion, not test or repair proof",
        agentConclusion:omitted?null:conclusion??null,
        omissionReason:omitted?"Complete message exceeds the 8000-byte diagnostic summary budget; opt-in history retains it":null};
}

export function coderEndpoint(config) {
    if (
        config.endpoint !== "https://omg-ci-coder.latham.workers.dev/" ||
        !/^[a-f0-9]{64}$/.test(config.bundleSha256)
    )
        throw new Error("Trusted coding endpoint and mandatory skill bundle are required.");

    return config.endpoint;
}

export function admitCoderResult(response, request, policy) {
    if (
        response.id !== operationIdentity(request) ||
        response.status !== "done" ||
        ["repository", "sha", "branch", "runId", "attempt"].some(
            (key) => response[key] !== request[key],
        )
    )
        throw new Error("Coding operation identity mismatch or incomplete operation.");
    const runtime = response.runtime;
    const state = response.result;
    const delivery = response.skillsDelivery;

    if (
        !runtime ||
        !state ||
        !delivery ||
        !/^[a-f0-9]{64}$/.test(policy.bundleSha256) ||
        runtime.bundleSha256 !== policy.bundleSha256 ||
        runtime.imageDigest !== policy.imageDigest ||
        runtime.verifierRevision !== policy.verifierRevision ||
        runtime.model !== "@cf/deepseek-ai/deepseek-v4.1-flash-1017" ||
        runtime.reasoningEffort !== "low" ||
        delivery.bundleSha256 !== policy.bundleSha256 ||
        state.skillBundleSha256 !== policy.bundleSha256 ||
        !Schema.is(Schema.String)(delivery.sessionId) ||
        !delivery.sessionId ||
        state.sessionId !== delivery.sessionId ||
        !Number.isSafeInteger(state.calls) ||
        state.calls < 1 ||
        state.calls > 96 ||
        !Array.isArray(state.reads) ||
        state.reads.length === 0 ||
        state.reads.some(
            (read) =>
                !request.source.sourceFiles.some((file) => file.path === read.path) ||
                !Number.isSafeInteger(read.start) ||
                read.start < 1 ||
                !Number.isSafeInteger(read.end) ||
                read.end < read.start,
        )
    )
        throw new Error("Coding runtime or server-recorded mandatory skill delivery mismatch.");

    if (state.testAudit) {
        if (!request.testAuditTask || state.proposal) throw new Error("Mixed existing-test and repair proposal.");
        const audit = createTestAuditProposal(request, state.testAudit.proposal);
        const digest = audit.proposalSha256;
        const id = `cl-${request.runId}-${request.attempt}-${request.sha}-ta-${digest.slice(0,16)}`;
        const continuationId = `cv-${request.runId}-${request.attempt}-${request.sha}-${digest.slice(0,16)}`;
        if (state.testAudit.proposalSha256 !== digest ||
            response.initialOperation?.operationId !== response.id || !["done","unanswered"].includes(response.initialOperation?.status) ||
            response.continuation?.operationId !== continuationId || response.continuation.parentOperationId !== response.id ||
            response.continuation.sessionId !== state.sessionId || response.continuation.proposalSha256 !== digest ||
            response.continuation.verificationId !== id ||
            response.continuation.status !== "done" ||
            state.verificationJob?.id !== id || state.verificationJob.proposalSha256 !== digest ||
            state.verificationJob.sessionId !== state.sessionId || state.verificationJob.continuationId !== continuationId)
            throw new Error("Existing-test audit lacks its exact completed verification continuation.");
        if (state.verificationJob.status === "failed")
            throw new Error(`Existing-test audit verification failed for the exact proposal: ${state.verificationJob.reason}`);
        if (state.verificationJob.status !== "verified" || state.verification?.proposalSha256 !== digest || state.verification.id !== id)
            throw new Error("Existing-test audit lacks its exact completed verification continuation.");
        return {...audit,readPaths:[...new Set(state.reads.map(read=>read.path))]};
    }
    if (request.testAuditTask && state.proposal) throw new Error("Existing-test task cannot export a production repair.");
    if (!state.proposal) return null;
    const adapted = state.proposal;
    const digest = proposalDigest(adapted.proposal);

    if (
        adapted.proposalSha256 !== digest ||
        adapted.proposal.baseSha !== request.sha ||
        adapted.proposal.branch !== request.branch ||
        adapted.proposal.repository !== request.repository
    )
        throw new Error("Coding proposal differs from its verified source identity.");

    const continuationId = `cv-${request.runId}-${request.attempt}-${request.sha}-${digest.slice(0, 16)}`;
    const continuation = response.continuation;
    const job = state.verificationJob;
    const verificationId = `cl-${request.runId}-${request.attempt}-${request.sha}-v-${digest.slice(0, 16)}`;
    if (
        response.initialOperation?.operationId !== response.id ||
        !["done", "unanswered"].includes(response.initialOperation?.status) ||
        continuation?.operationId !== continuationId ||
        continuation.parentOperationId !== response.id ||
        continuation.sessionId !== state.sessionId ||
        continuation.proposalSha256 !== digest ||
        continuation.verificationId !== verificationId ||
        continuation.status !== "done" ||
        job?.id !== verificationId ||
        job.proposalSha256 !== digest ||
        job.sessionId !== state.sessionId ||
        job.continuationId !== continuationId
    )
        throw new Error(
            "Coding verification continuation was not completed for the original session.",
        );
    if (job.status === "failed")
        throw new Error(`Coding verification failed for the exact proposal: ${job.reason}`);
    if (
        job.status !== "verified" ||
        state.verification?.proposalSha256 !== digest ||
        state.verification.id !== verificationId
    )
        throw new Error(
            "Coding verification continuation was not completed for the original session.",
        );

    return adapted;
}

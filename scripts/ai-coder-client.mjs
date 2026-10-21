import { createTestAuditProposal } from "../services/ci-coder/src/test-audit.ts";
import { proposalDigest } from "./ai-review-publication.mjs";
import { operationIdentity } from "../services/ci-coder/src/request.ts";
import { Schema } from "effect";

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
        runtime.reasoningEffort !== "high" ||
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
        if (state.testAudit.proposalSha256 !== digest || state.verification?.proposalSha256 !== digest || state.verification.id !== id ||
            response.initialOperation?.operationId !== response.id || !["done","unanswered"].includes(response.initialOperation?.status) ||
            response.continuation?.operationId !== continuationId || response.continuation.parentOperationId !== response.id ||
            response.continuation.sessionId !== state.sessionId || response.continuation.proposalSha256 !== digest ||
            response.continuation.verificationId !== id || response.continuation.status !== "done" ||
            state.verificationJob?.status !== "verified" || state.verificationJob.id !== id || state.verificationJob.proposalSha256 !== digest ||
            state.verificationJob.sessionId !== state.sessionId || state.verificationJob.continuationId !== continuationId)
            throw new Error("Existing-test audit lacks its exact completed verification continuation.");
        return {...audit,readPaths:[...new Set(state.reads.map(read=>read.path))]};
    }
    if (request.testAuditTask && state.proposal) throw new Error("Existing-test task cannot export a production repair.");
    if (!state.proposal) return null;
    const adapted = state.proposal;
    const digest = proposalDigest(adapted.proposal);

    if (
        adapted.proposalSha256 !== digest ||
        state.verification?.proposalSha256 !== digest ||
        state.verification.id !==
            `cl-${request.runId}-${request.attempt}-${request.sha}-v-${digest.slice(0, 16)}` ||
        adapted.proposal.baseSha !== request.sha ||
        adapted.proposal.branch !== request.branch ||
        adapted.proposal.repository !== request.repository
    )
        throw new Error("Coding proposal differs from its verified source identity.");

    const continuationId = `cv-${request.runId}-${request.attempt}-${request.sha}-${digest.slice(0, 16)}`;
    const continuation = response.continuation;
    const job = state.verificationJob;
    if (
        response.initialOperation?.operationId !== response.id ||
        !["done", "unanswered"].includes(response.initialOperation?.status) ||
        continuation?.operationId !== continuationId ||
        continuation.parentOperationId !== response.id ||
        continuation.sessionId !== state.sessionId ||
        continuation.proposalSha256 !== digest ||
        continuation.verificationId !== state.verification.id ||
        continuation.status !== "done" ||
        job?.status !== "verified" ||
        job.id !== state.verification.id ||
        job.proposalSha256 !== digest ||
        job.sessionId !== state.sessionId ||
        job.continuationId !== continuationId
    )
        throw new Error(
            "Coding verification continuation was not completed for the original session.",
        );

    return adapted;
}

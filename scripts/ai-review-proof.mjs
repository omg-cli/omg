import { Schema } from "effect";
import { admitPublication, proposalDigest, sha256 } from "./ai-review-publication.mjs";
import { verifyCloudCiReceipt } from "./cloud-ci-evidence.mjs";
import { expectedCloudChecks } from "../services/cloud-ci/runner/plan.mjs";

export function ciPolicy(config) {
    if (
        config.endpoint !== "https://omg-cloud-ci.latham.workers.dev/" ||
        !/^sha256:[a-f0-9]{64}$/.test(config.imageDigest)
    )
        throw new Error("Trusted CI endpoint and image digest are required.");

    if (
        !Schema.is(Schema.String)(config.verifierRevision) ||
        !/^[a-f0-9]{40}$/.test(config.verifierRevision)
    )
        throw new Error("Expected an exact commit SHA.");

    return { imageDigest: config.imageDigest, verifierRevision: config.verifierRevision };
}

export function verifyPublicationProof(receipt, request, config, adapted, sources) {
    const policy = ciPolicy(config);

    const proof = verifyCloudCiReceipt(receipt, request, {
        imageDigest: policy.imageDigest,
        proposalSha256: proposalDigest(adapted.proposal),
    });

    if (proof.imageDigest !== policy.imageDigest || !proof.verificationReceipt)
        throw new Error("Cloudflare verifier image or verification proof mismatch.");
    const requiredChecks = expectedCloudChecks(request.ref);
    const nested = proof.verificationReceipt;

    if (
        proposalDigest(proof.verification?.proposal) !== proposalDigest(adapted.proposal) ||
        proof.verification?.regression?.path !== adapted.regression.path ||
        proof.verification?.regression?.testName !== adapted.regression.testName ||
        proof.verification?.verifierRevision !== policy.verifierRevision
    )
        throw new Error("Verification request differs from the trusted proposal.");

    for (const check of proof.checks) {
        const verified = nested.portableChecks?.find((entry) => entry.name === check.name);

        if (verified?.reportSha256 !== sha256(JSON.stringify(check)))
            throw new Error("Portable check record digest mismatch.");
    }

    if (
        nested.runId !== Number(request.runId) ||
        nested.runAttempt !== Number(request.attempt) ||
        nested.baseline?.testName !== adapted.regression.testName
    )
        throw new Error("Regression or verification run identity mismatch.");
    admitPublication({
        proposal: adapted.proposal,
        receipt: nested,
        sources,
        verifierRevision: policy.verifierRevision,
        requiredChecks,
    });

    return {
        receipt: nested,
        policy: { verifierRevision: policy.verifierRevision, requiredChecks },
    };
}

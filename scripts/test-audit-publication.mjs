import { createHash } from "node:crypto";
import { testAuditSchema, testAuditDigest } from "../services/cloud-ci/src/test-audit-contract.ts";
import { verifyCloudTestAudit } from "./cloud-test-audit-evidence.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const blob = (value) => createHash("sha1").update(`blob ${Buffer.byteLength(value)}\0`).update(value).digest("hex");
const canonical = (value) => JSON.stringify(value, (_, item) => item && typeof item === "object" && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);

export function testAuditPublicationProposal(rawAudit) {
    const { proposal } = testAuditSchema.parse(rawAudit);
    if (proposal.purpose !== "existing-test-strengthening")
        throw new Error("Only a verified existing-test strengthening may create a publication.");
    const test = proposal.test;
    const key = hash(canonical({ purpose: proposal.purpose, path: test.path, testName: test.testName,
        originalBlobSha: test.originalBlobSha }));
    return { repository: proposal.repository, branch: proposal.branch, baseSha: proposal.baseSha,
        finding: { key, title: `Strengthen existing test ${test.testName}`.slice(0, 160),
            summary: "A controlled four-state comparison demonstrates an additional assertion detects a fault missed by the original test. Independent review must establish that the assertion and fault represent the intended behavior.",
            path: test.path, line: 1, sourceQuote: test.originalContent.split(/\r?\n/)[0].slice(0, 4000),
            reproduction: `Run the existing ${test.testName} test against intact and controlled-fault source, then repeat with the additional assertion.` },
        changes: [{ path: test.path, originalBlobSha: test.originalBlobSha,
            oldContentQuote: test.originalContent.slice(0, 4000), newContent: test.newContent, sha256: test.sha256 }] };
}

export async function readmitTestAuditProof({ request, receipt, policy, load }) {
    if (policy?.endpoint !== "https://omg-cloud-ci.latham.workers.dev/" ||
        !/^sha256:[a-f0-9]{64}$/.test(policy.imageDigest ?? "") || !/^[a-f0-9]{40}$/.test(policy.verifierRevision ?? ""))
        throw new Error("Trusted existing-test audit verifier policy required.");
    if (!request?.testAudit || typeof load !== "function") throw new Error("Existing-test audit request and raw proof loader required.");
    const audit = testAuditSchema.parse(request.testAudit);
    if (audit.proposal.purpose !== "existing-test-strengthening")
        throw new Error("Existing-test sensitivity evidence cannot authorize publication.");
    const evidence = await verifyCloudTestAudit(receipt, request, policy, load);
    return { audit, evidence, proposal: testAuditPublicationProposal(audit), evidenceDigest: hash(canonical(evidence)) };
}

export function admitTestAuditSources(admitted, sources) {
    const { proposal } = admitted.audit;
    for (const file of [proposal.test, proposal.fault]) {
        const original = sources.get(file.path);
        if (!original || original.mode !== "100644" || typeof original.content !== "string" || original.content.includes("\0") ||
            original.sha !== file.originalBlobSha || blob(original.content) !== file.originalBlobSha ||
            (file === proposal.test ? original.content !== file.originalContent : !original.content.includes(file.oldContentQuote)))
            throw new Error("Existing-test audit original Git source differs from private proof.");
    }
    if (sources.get(proposal.fault.path).content === proposal.fault.newContent)
        throw new Error("Existing-test audit fault does not change production source.");
    return { ...admitted, receipt: admitted.evidence,
        headBranch: `ai-fix/${admitted.proposal.finding.key.slice(0, 16)}-${proposal.baseSha.slice(0, 12)}` };
}

export function testAuditPublicationBodies(admitted) {
    const { proposal, evidence, evidenceDigest } = admitted;
    const original = admitted.audit.proposal;
    const phases = ["oldIntact", "oldFault", "strongerFault", "strongerIntact"];
    const details = [
        `Proof purpose: ${original.purpose}`,
        "Proposed strengthening of an existing test. This comparison is not evidence of a production bug or a production fix.",
        `Existing test: ${original.test.path} :: ${original.test.testName}`,
        `Base SHA: ${original.baseSha}`,
        ...phases.map((phase) => `${phase}: exit ${evidence[phase].exitCode}; ${evidence[phase].tests} executed, ${evidence[phase].failures} failures, ${evidence[phase].errors} errors, ${evidence[phase].skipped} skipped. Report SHA-256: ${evidence[phase].reportSha256}`),
        `Audit proposal SHA-256: ${testAuditDigest(original)}`,
        `Proposal SHA-256: ${hash(canonical(proposal))}`,
        `Receipt SHA-256: ${evidenceDigest}`,
        `Verifier run: https://github.com/omg-cli/omg/actions/runs/${evidence.runId}/attempts/${evidence.runAttempt}`,
        `Verifier revision: ${evidence.verifierRevision}`,
        "Only the additional test assertion is published. The controlled fault was restored and remains private verification evidence. Independent semantic approval is required; no automatic merge.",
    ].join("\n\n");
    return { issue: `<!-- ai-review:${proposal.finding.key} -->\n\n${details}`,
        pullRequest: `<!-- ai-review-patch:${proposal.finding.key}:main:${proposal.baseSha} -->\n\n${details}` };
}

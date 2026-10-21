import { admitPublishedTree, decideAiFixReview } from "./ai-fix-review.mjs";
import { proposalDigest, sha256, canonicalJson, loadTestAuditPublicationSources } from "./ai-review-publication.mjs";
import { readmitTestAuditProof, admitTestAuditSources, testAuditPublicationProposal } from "./test-audit-publication.mjs";
import { testAuditDigest } from "../services/cloud-ci/src/test-audit-contract.ts";
import { patchReviewInputSchema, patchReviewDigest, admitPatchReview } from "../services/ci-inspector/src/patch-review-contract.ts";

const prefix = "/repos/omg-cli/omg";
async function list(github, route, field) {
    const all = [];
    for (let page = 1; page <= 10; page++) {
        const response = await github.request("GET", `${route}${route.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
        const rows = field ? response[field] : response;
        if (!Array.isArray(rows)) throw new Error("Invalid independent audit inventory.");
        all.push(...rows);
        if (rows.length < 100) return all;
    }
    throw new Error("Independent audit inventory exceeds its bound.");
}

export async function reviewTestAuditFix({ github, services, number, expectedHead, publisher, policy, approve, pull }) {
    const getPull = () => github.request("GET", `${prefix}/pulls/${number}`);
    const getChecks = () => list(github, `${prefix}/commits/${expectedHead}/check-runs?filter=latest`, "check_runs");
    const check = (candidate, checks) => {
        const result = decideAiFixReview({ pull: candidate, expectedHead, publisher, checks });
        if (result.action === "reject") throw new Error(result.reason);
    };
    const currentMain = async () => (await github.request("GET", `${prefix}/git/ref/heads/main`)).object.sha;
    check(pull, await getChecks());
    if (await currentMain() !== pull.base.sha) throw new Error("Test-strengthening base is no longer current main.");
    const links = [...pull.body.matchAll(/^Verifier run: https:\/\/github\.com\/omg-cli\/omg\/actions\/runs\/([1-9][0-9]{0,19})\/attempts\/([1-9][0-9]{0,5})$/gm)];
    if (links.length !== 1) throw new Error("Exact original audit run is required.");
    const [, runId, attempt] = links[0];
    const report = await services.ciJson(`/review-records/${runId}-${attempt}`);
    if (report.repository !== "omg-cli/omg" || report.branch !== "main" || report.sha !== pull.base.sha ||
        report.controllerRevision !== policy.controllerRevision || report.publishRequested !== true ||
        !Array.isArray(report.testAudits) || report.testAudits.length > 3)
        throw new Error("Untrusted original test audit publication record.");
    const run = await github.request("GET", `${prefix}/actions/runs/${runId}/attempts/${attempt}`);
    if (String(run.id) !== runId || run.run_attempt !== Number(attempt) || run.repository?.full_name !== "omg-cli/omg" ||
        run.head_branch !== "main" || run.path !== ".github/workflows/ai-review.yml" || run.head_sha !== report.sha ||
        run.status !== "completed" || !["success", "failure"].includes(run.conclusion) ||
        !["workflow_dispatch", "schedule", "repository_dispatch"].includes(run.event))
        throw new Error("Original test audit workflow identity mismatch.");
    const jobs = (await list(github, `${prefix}/actions/runs/${runId}/attempts/${attempt}/jobs`, "jobs")).filter(job => job.name === "review");
    if (jobs.length !== 1 || !Number.isSafeInteger(jobs[0].id) || jobs[0].id < 1 || jobs[0].run_id !== run.id ||
        jobs[0].run_attempt !== Number(attempt) || jobs[0].run_url !== `https://api.github.com${prefix}/actions/runs/${runId}` ||
        jobs[0].workflow_name !== "AI source review" || jobs[0].head_branch !== "main" || jobs[0].head_sha !== report.sha ||
        jobs[0].status !== "completed" || jobs[0].conclusion !== "success")
        throw new Error("Original exact audit review job did not complete.");
    const digest = /^Audit proposal SHA-256: ([a-f0-9]{64})$/m.exec(pull.body)?.[1];
    const selected = report.testAudits.filter(item => testAuditDigest(item.request?.testAudit?.proposal) === digest);
    if (selected.length !== 1) throw new Error("Original audit does not uniquely bind this PR.");
    const { request, id } = selected[0];
    if (request.repository !== "omg-cli/omg" || request.sha !== pull.base.sha || request.ref !== "refs/heads/main" ||
        request.runId !== runId || request.attempt !== attempt || id !== `cl-${runId}-${attempt}-${request.sha}-ta-${digest.slice(0,16)}`)
        throw new Error("Test audit verification identity differs.");
    const receipt = await services.ciJson(`/runs/${id}/receipt`);
    const proof = await readmitTestAuditProof({ request, receipt, policy, load: key => {
        const parts = key.split("/");
        if (parts.length !== 3 || !["logs", "reports"].includes(parts[0]) || parts[1] !== id || !/^[A-Za-z0-9_.-]+$/.test(parts[2]))
            throw new Error("Unexpected raw audit object path.");
        return services.ciRaw(`/runs/${id}/${parts[0]}/${parts[2]}`);
    } });
    const normalized = testAuditPublicationProposal(request.testAudit);
    const { sources } = await loadTestAuditPublicationSources(github, request.testAudit);
    admitTestAuditSources(proof, sources);
    if (/^Proposal SHA-256: ([a-f0-9]{64})$/m.exec(pull.body)?.[1] !== proposalDigest(normalized) ||
        /^Receipt SHA-256: ([a-f0-9]{64})$/m.exec(pull.body)?.[1] !== proof.evidenceDigest ||
        pull.body.split(/\r?\n/)[0] !== `<!-- ai-review-patch:${normalized.finding.key}:main:${request.sha} -->`)
        throw new Error("Published test patch or four-state receipt digest differs.");
    const [base, head] = await Promise.all([github.request("GET", `${prefix}/git/commits/${request.sha}`), github.request("GET", `${prefix}/git/commits/${expectedHead}`)]);
    if (base.sha !== request.sha || head.sha !== expectedHead || !/^[a-f0-9]{40}$/.test(base.tree?.sha ?? "") ||
        !/^[a-f0-9]{40}$/.test(head.tree?.sha ?? "") || head.parents?.length !== 1 || head.parents[0].sha !== request.sha)
        throw new Error("Strengthened test must have only its verified base parent.");
    const [baseTree, headTree] = await Promise.all([github.request("GET", `${prefix}/git/trees/${base.tree.sha}?recursive=1`), github.request("GET", `${prefix}/git/trees/${head.tree.sha}?recursive=1`)]);
    admitPublishedTree({ proposal: normalized, baseTree, headTree });
    await services.admitQemu({ github, checks: await getChecks(), headSha: expectedHead, baseSha: request.sha, headTreeSha: head.tree.sha });
    const { originalContent, newContent, ...test } = request.testAudit.proposal.test;
    const input = patchReviewInputSchema.parse({ purpose: "test-strengthening-approval", repository: "omg-cli/omg", branch: "main",
        baseSha: request.sha, headSha: expectedHead, headTreeSha: head.tree.sha, proposalSha256: digest,
        patch: [{ path: test.path, before: originalContent, after: newContent }],
        audit: { test, fault: request.testAudit.proposal.fault, receipt: proof.evidence } });
    const verdictReceipt = await services.inspectPatch(input);
    const verdict = admitPatchReview(input, verdictReceipt);
    const record = { purpose: input.purpose, repository: "omg-cli/omg", number, headSha: expectedHead,
        inputSha256: patchReviewDigest(input), proposalSha256: digest, receipt: verdictReceipt, controllerRevision: policy.reviewControllerRevision };
    await services.saveReview(record);
    if (verdict.verdict !== "approved") return { action: "held", verdict: verdict.verdict, reason: verdict.reason };
    const fresh = await getPull();
    check(fresh, await getChecks());
    if (fresh.base.sha !== request.sha || fresh.body !== pull.body || await currentMain() !== request.sha)
        throw new Error("Test-strengthening publication changed during independent review.");
    const marker = `<!-- ai-test-approval:${expectedHead}:${record.inputSha256} -->`;
    const reviews = await list(github, `${prefix}/pulls/${number}/reviews`);
    if (reviews.some(review => review.user?.login === "github-actions[bot]" && review.user?.id === 41898282 &&
        review.commit_id === expectedHead && review.state === "APPROVED" && review.body?.split(/\r?\n/)[0] === marker))
        return { action: "existing", headSha: expectedHead };
    if (!approve) return { action: "dry-run", headSha: expectedHead, inputSha256: record.inputSha256 };
    const result = await github.request("POST", `${prefix}/pulls/${number}/reviews`, { commit_id: expectedHead, event: "APPROVE",
        body: `${marker}\n\nIndependent approval of the complete existing-test strengthening. The original and stronger tests were compared against intact and controlled-fault source; all four raw reports, exact test-only published tree, CI, coverage and QEMU evidence were independently admitted. No production-fix claim or automatic merge.\n\nAudit proposal SHA-256: ${digest}\nPatch-review input SHA-256: ${record.inputSha256}\nInspector receipt SHA-256: ${sha256(canonicalJson(verdictReceipt))}` });
    if (result.commit_id !== expectedHead || result.state !== "APPROVED" || result.user?.id !== 41898282 || result.user?.login !== "github-actions[bot]")
        throw new Error("Independent audit approval identity mismatch.");
    return { action: "approved", headSha: expectedHead, reviewId: result.id };
}

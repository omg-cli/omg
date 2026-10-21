import { createHash } from "node:crypto";
import { collectCandidateSources } from "./ai-review-candidate.mjs";
import { proposalDigest, sha256, canonicalJson } from "./ai-review-publication.mjs";
import { verifyPublicationProof } from "./ai-review-proof.mjs";
import { verifyCloudCiObjects } from "./cloud-ci-evidence.mjs";
import { patchReviewInputSchema, patchReviewDigest, admitPatchReview } from "../services/ci-inspector/src/patch-review-contract.ts";

const repository = "omg-cli/omg";
const requiredChecks = [
    "CI Success",
    "Instrumented coverage tests",
    "Generate Coverage Report",
    "Orchestration tests, types and dry builds",
    "QEMU behavioral verification / QEMU matrix result",
];
const sha40 = /^[a-f0-9]{40}$/;

export function gitBlobSha(content) {
    const bytes = Buffer.from(content);
    return createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
}

export function admitPublishedTree({ proposal, baseTree, headTree }) {
    function entries(tree) {
        if (tree?.truncated !== false || !Array.isArray(tree.tree))
            throw new Error("Complete exact Git tree inventory is required.");
        const leaves = tree.tree.filter((entry) => entry.type !== "tree");
        if (new Set(leaves.map((entry) => entry.path)).size !== leaves.length)
            throw new Error("Duplicate Git tree paths.");
        return new Map(leaves.map((entry) => [entry.path, entry]));
    }
    const expected = entries(baseTree);
    const actual = entries(headTree);
    for (const change of proposal.changes) {
        if ((expected.get(change.path)?.sha ?? null) !== change.originalBlobSha)
            throw new Error("Published patch original blob mismatch.");
        expected.set(change.path, {
            path: change.path, mode: "100644", type: "blob", sha: gitBlobSha(change.newContent),
        });
    }
    if (actual.size !== expected.size || [...expected].some(([path, entry]) =>
        ["mode", "type", "sha"].some((field) => actual.get(path)?.[field] !== entry[field])))
        throw new Error("Published head differs from the verified proposal or changes protected paths.");
    return true;
}

export function decideAiFixReview({ pull, expectedHead, publisher, checks }) {
    const reject = (reason) => ({ action: "reject", reason });
    if (
        publisher?.id !== 345568822 || !publisher.login ||
        pull?.user?.id !== publisher.id || pull.user.login !== publisher.login ||
        pull.state !== "open" || pull.draft !== false ||
        !Number.isSafeInteger(pull.number) || pull.number < 1 ||
        pull.base?.repo?.full_name !== repository || pull.head?.repo?.full_name !== repository ||
        pull.base.ref !== "main" || !sha40.test(pull.base.sha) ||
        !sha40.test(expectedHead) || pull.head.sha !== expectedHead
    ) return reject("Publisher, repository or current PR head identity mismatch.");

    const marker = /^<!-- ai-review-patch:([a-f0-9]{64}):main:([a-f0-9]{40}) -->\r?\n/.exec(pull.body ?? "");
    if (!marker || marker[2] !== pull.base.sha ||
        pull.head.ref !== `ai-fix/${marker[1].slice(0, 16)}-${marker[2].slice(0, 12)}` ||
        !/^Proposal SHA-256: [a-f0-9]{64}$/m.test(pull.body) ||
        !/^Receipt SHA-256: [a-f0-9]{64}$/m.test(pull.body)
    ) return reject("Missing or mismatched publication marker, branch or evidence digest.");

    if (!Array.isArray(checks) || requiredChecks.some((name) => {
        const matches = checks.filter((check) => check.name === name);
        return matches.length !== 1 || matches[0].head_sha !== expectedHead ||
            matches[0].app?.id !== 15368 || matches[0].app?.slug !== "github-actions" ||
            matches[0].status !== "completed" || matches[0].conclusion !== "success";
    })) return reject("Required exact-head GitHub Actions checks are missing, ambiguous or unsuccessful.");

    return {
        action: "blocked",
        reason: "Independent raw proof and explicit patch-review verdict are required before approval.",
    };
}

const prefix = `/repos/${repository}`;

async function list(github, route, field) {
    const all = [];
    for (let page = 1; page <= 10; page++) {
        const response = await github.request("GET", `${route}${route.includes("?") ? "&" : "?"}per_page=100&page=${page}`);
        const rows = field ? response[field] : response;
        if (!Array.isArray(rows)) throw new Error("Invalid GitHub list response.");
        all.push(...rows);
        if (rows.length < 100) return all;
    }
    throw new Error("GitHub review inventory exceeds the bounded listing limit.");
}

export async function reviewAiFix({ github, services, number, expectedHead, publisher, policy, approve = false }) {
    if (!Number.isSafeInteger(number) || number < 1 || !sha40.test(expectedHead))
        throw new Error("Exact PR number and head are required.");
    const getPull = () => github.request("GET", `${prefix}/pulls/${number}`);
    const getChecks = () => list(github, `${prefix}/commits/${expectedHead}/check-runs?filter=latest`, "check_runs");
    const currentMain = async () => (await github.request("GET", `${prefix}/git/ref/heads/main`)).object.sha;
    const pull = await getPull();
    const checkCandidate = (pull, checks) => {
        const decision = decideAiFixReview({ pull, expectedHead, publisher, checks });
        if (decision.action === "reject") throw new Error(decision.reason);
    };
    checkCandidate(pull, await getChecks());
    if (await currentMain() !== pull.base.sha) throw new Error("Publication base is no longer current main.");
    const verifierLinks = [...pull.body.matchAll(/^Verifier run: https:\/\/github\.com\/omg-cli\/omg\/actions\/runs\/([1-9][0-9]{0,19})\/attempts\/([1-9][0-9]{0,5})$/gm)];
    if (verifierLinks.length !== 1) throw new Error("Exact original verifier run is required.");
    const [, runId, attempt] = verifierLinks[0];
    const report = await services.ciJson(`/review-records/${runId}-${attempt}`);
    if (report.repository !== repository || report.branch !== "main" || report.sha !== pull.base.sha ||
        report.controllerRevision !== policy.controllerRevision || report.publishRequested !== true ||
        !Array.isArray(report.publications) || report.publications.length > 3)
        throw new Error("Untrusted original publication record.");
    const originalRun = await github.request("GET", `${prefix}/actions/runs/${runId}/attempts/${attempt}`);
    if (originalRun.repository?.full_name !== repository || originalRun.head_branch !== "main" ||
        originalRun.path !== ".github/workflows/ai-review.yml" || originalRun.head_sha !== report.sha ||
        !Number.isSafeInteger(originalRun.id) || String(originalRun.id) !== runId ||
        originalRun.run_attempt !== Number(attempt) || originalRun.status !== "completed" ||
        !["success", "failure"].includes(originalRun.conclusion) ||
        !["workflow_dispatch", "schedule", "repository_dispatch"].includes(originalRun.event))
        throw new Error("Original publication workflow identity mismatch.");
    const reviewJobs = (await list(github, `${prefix}/actions/runs/${runId}/attempts/${attempt}/jobs`, "jobs"))
        .filter((job) => job.name === "review");
    if (reviewJobs.length !== 1 || !Number.isSafeInteger(reviewJobs[0].id) || reviewJobs[0].id < 1 ||
        reviewJobs[0].run_id !== originalRun.id || reviewJobs[0].run_attempt !== Number(attempt) ||
        reviewJobs[0].run_url !== `https://api.github.com${prefix}/actions/runs/${runId}` ||
        reviewJobs[0].workflow_name !== "AI source review" || reviewJobs[0].head_branch !== "main" ||
        reviewJobs[0].head_sha !== report.sha || reviewJobs[0].status !== "completed" ||
        reviewJobs[0].conclusion !== "success")
        throw new Error("Original exact-attempt review job did not complete successfully.");
    const digest = /^Proposal SHA-256: ([a-f0-9]{64})$/m.exec(pull.body)?.[1];
    const publications = report.publications.filter((item) => proposalDigest(item.proposal) === digest);
    if (publications.length !== 1) throw new Error("Original proposal does not uniquely bind this PR.");
    const { proposal, request, regression, id } = publications[0];
    if (proposal.baseSha !== pull.base.sha || proposal.repository !== repository || proposal.branch !== "main" ||
        pull.body.split(/\r?\n/)[0] !== `<!-- ai-review-patch:${proposal.finding.key}:main:${proposal.baseSha} -->` ||
        id !== `cl-${runId}-${attempt}-${proposal.baseSha}-v-${digest.slice(0, 16)}` ||
        request.runId !== runId || request.attempt !== attempt || request.sha !== proposal.baseSha)
        throw new Error("Original proposal and verification run identity mismatch.");
    const sources = await collectCandidateSources({ github, sha: proposal.baseSha,
        paths: [...new Set([proposal.finding.path, ...proposal.changes.map((file) => file.path)])] });
    const nativeReceipt = await services.ciJson(`/runs/${id}/receipt`);
    const verified = verifyPublicationProof(nativeReceipt, request, policy, { proposal, regression }, sources);
    if (/^Receipt SHA-256: ([a-f0-9]{64})$/m.exec(pull.body)?.[1] !== sha256(canonicalJson(verified.receipt)))
        throw new Error("Published receipt digest differs from the original raw proof.");
    await verifyCloudCiObjects(nativeReceipt, (key) => {
        const parts = key.split("/");
        if (parts.length !== 3 || !["logs", "reports"].includes(parts[0]) || parts[1] !== id ||
            !/^[A-Za-z0-9_.-]+$/.test(parts[2])) throw new Error("Unexpected raw proof object path.");
        return services.ciRaw(`/runs/${id}/${parts[0]}/${parts[2]}`);
    });
    const [baseCommit, headCommit] = await Promise.all([
        github.request("GET", `${prefix}/git/commits/${proposal.baseSha}`),
        github.request("GET", `${prefix}/git/commits/${expectedHead}`),
    ]);
    if (baseCommit.sha !== proposal.baseSha || headCommit.sha !== expectedHead ||
        !sha40.test(baseCommit.tree?.sha) || !sha40.test(headCommit.tree?.sha) ||
        headCommit.parents?.length !== 1 || headCommit.parents[0].sha !== proposal.baseSha)
        throw new Error("Published repair must have exactly the verified base parent.");
    const [baseTree, headTree] = await Promise.all([
        github.request("GET", `${prefix}/git/trees/${baseCommit.tree.sha}?recursive=1`),
        github.request("GET", `${prefix}/git/trees/${headCommit.tree.sha}?recursive=1`),
    ]);
    admitPublishedTree({ proposal, baseTree, headTree });
    await services.admitQemu({ github, checks: await getChecks(), headSha: expectedHead,
        baseSha: proposal.baseSha, headTreeSha: headCommit.tree.sha });
    const input = patchReviewInputSchema.parse({ purpose: "fix-approval", repository, branch: "main",
        baseSha: proposal.baseSha, headSha: expectedHead, headTreeSha: headCommit.tree.sha,
        proposalSha256: digest,
        finding: { summary: proposal.finding.summary, reproduction: proposal.finding.reproduction,
            path: proposal.finding.path, line: proposal.finding.line, sourceQuote: proposal.finding.sourceQuote },
        regression: { testName: verified.receipt.baseline.testName, assertionFailure: verified.receipt.baseline.assertionFailure,
            assertionFile: verified.receipt.baseline.assertionFile, assertionLine: verified.receipt.baseline.assertionLine,
            assertionSourceSha256: verified.receipt.baseline.assertionSourceSha256,
            baselineExitCode: verified.receipt.baseline.exitCode, patchedExitCode: verified.receipt.patched.exitCode },
        patch: proposal.changes.map((file) => ({ path: file.path,
            before: sources.get(file.path)?.content ?? null, after: file.newContent })) });
    const receipt = await services.inspectPatch(input);
    const result = admitPatchReview(input, receipt);
    const record = { repository, number, headSha: expectedHead, inputSha256: patchReviewDigest(input),
        proposalSha256: digest, receipt, controllerRevision: policy.reviewControllerRevision };
    await services.saveReview(record);
    if (result.verdict !== "approved") return { action: "held", verdict: result.verdict, reason: result.reason };
    const fresh = await getPull();
    checkCandidate(fresh, await getChecks());
    if (fresh.base.sha !== proposal.baseSha || await currentMain() !== proposal.baseSha || fresh.body !== pull.body)
        throw new Error("PR publication changed during independent review.");
    const marker = `<!-- ai-fix-approval:${expectedHead}:${record.inputSha256} -->`;
    const reviews = await list(github, `${prefix}/pulls/${number}/reviews`);
    const existing = reviews.filter((review) => review.user?.login === "github-actions[bot]" &&
        review.user?.id === 41898282 && review.commit_id === expectedHead && review.state === "APPROVED" &&
        review.body?.split(/\r?\n/)[0] === marker);
    if (existing.length) return { action: "existing", headSha: expectedHead };
    if (!approve) return { action: "dry-run", headSha: expectedHead, inputSha256: record.inputSha256 };
    const review = await github.request("POST", `${prefix}/pulls/${number}/reviews`, {
        commit_id: expectedHead, event: "APPROVE", body: `${marker}\n\nIndependent patch review approved the complete exact patch and regression assertion. Original raw RED/GREEN proof, immutable proposal, published tree, exact-head CI/coverage/orchestration and QEMU source evidence were independently admitted.\n\nProposal SHA-256: ${digest}\nPatch-review input SHA-256: ${record.inputSha256}\nInspector receipt SHA-256: ${sha256(canonicalJson(receipt))}\n\n${result.reason}`,
    });
    if (review.commit_id !== expectedHead || review.state !== "APPROVED" ||
        review.user?.id !== 41898282 || review.user?.login !== "github-actions[bot]")
        throw new Error("Independent GitHub approval identity mismatch.");
    return { action: "approved", headSha: expectedHead, reviewId: review.id };
}

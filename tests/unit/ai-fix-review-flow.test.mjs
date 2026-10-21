import test from "node:test";
import assert from "node:assert/strict";
import { reviewAiFix, gitBlobSha } from "../../scripts/ai-fix-review.mjs";
import { admitQemuRun, admitQemuSource } from "../../scripts/ai-fix-review-qemu.mjs";
import { proposalDigest, findingKey, sha256, canonicalJson, publicationBodies } from "../../scripts/ai-review-publication.mjs";
import { cloudCiPlanSha256 } from "../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudChecks, expectedCloudReports } from "../../services/cloud-ci/runner/plan.mjs";
import { patchReviewDigest } from "../../services/ci-inspector/src/patch-review-contract.ts";

function fixture() {
    const base = "a".repeat(40), head = "b".repeat(40), tree = "c".repeat(40);
    const source = "pub const VALUE: u8 = 1;\n";
    const changed = "pub const VALUE: u8 = 2;\n";
    const regression = "#[test]\nfn value_returns_two() { assert_eq!(omg::VALUE, 2); }\n";
    const finding = { path: "src/value.rs", line: 1, sourceQuote: source.trim(), title: "Wrong exported value",
        summary: "The public constant returns 1 rather than 2.", reproduction: "Read the public constant." };
    finding.key = findingKey(finding);
    const proposal = { repository: "omg-cli/omg", branch: "main", baseSha: base, finding, changes: [
        { path: finding.path, originalBlobSha: gitBlobSha(source), oldContentQuote: source.trim(), newContent: changed, sha256: sha256(changed) },
        { path: "tests/ai-review-value.rs", originalBlobSha: null, oldContentQuote: "", newContent: regression, sha256: sha256(regression) },
    ] };
    const policy = { endpoint: "https://omg-cloud-ci.latham.workers.dev/", imageDigest: `sha256:${"d".repeat(64)}`,
        verifierRevision: "e".repeat(40), controllerRevision: "f".repeat(40), reviewControllerRevision: base };
    const digest = proposalDigest(proposal);
    const id = `cl-42-1-${base}-v-${digest.slice(0, 16)}`;
    const adapted = { proposal, regression: { path: "tests/ai-review-value.rs", testName: "value_returns_two" } };
    const request = { repository: proposal.repository, sha: base, ref: "refs/heads/main", runId: "42", attempt: "1",
        verification: { ...adapted, verifierRevision: policy.verifierRevision } };
    const raw = new Map();
    const object = (key, text) => { raw.set(key, text); return sha256(text); };
    const checks = expectedCloudChecks(request.ref).map((name) => ({ name, exitCode: 0,
        stdoutKey: `logs/${id}/${name}.stdout`, stderrKey: `logs/${id}/${name}.stderr`,
        stdoutSha256: object(`logs/${id}/${name}.stdout`, `${name} passed`),
        stderrSha256: object(`logs/${id}/${name}.stderr`, ""),
        reports: expectedCloudReports(name).map((name) => ({ name, key: `reports/${id}/${name}`,
            sha256: object(`reports/${id}/${name}`, `report ${name}`) })),
    }));
    const observation = { testName: "value_returns_two", tests: 1, failures: 0, exitCode: 0, errors: 0, skipped: 0,
        reportSha256: "1".repeat(64), stdoutSha256: sha256("stdout"), stderrSha256: sha256("stderr"),
        catalogSha256: sha256("catalog"), executableSha256: sha256("exe"), compilerMessagesSha256: sha256("compiler"),
        sourceSha256: sha256(regression), recipeSha256: sha256("literal recipe") };
    const receipt = { repository: proposal.repository, branch: "main", baseSha: base, proposalSha256: digest,
        verifierRevision: policy.verifierRevision, runId: 42, runAttempt: 1,
        baseline: { ...observation, exitCode: 101, failures: 1, assertionFailure: "assertion left == right failed: left 1 right 2",
            assertionFile: "tests/ai-review-value.rs", assertionLine: 2, assertionSourceSha256: sha256(regression.split("\n")[1]) },
        patched: { ...observation }, portableChecks: checks.map((check) => ({ name: check.name, exitCode: 0, reportSha256: sha256(JSON.stringify(check)) })),
        protectedPathsUnchanged: true };
    const verificationReports = ["baseline", "patched"].map((phase) => {
        const name = `regression-${phase}.json`, key = `reports/${id}/${name}`;
        receipt[phase].reportSha256 = object(key, JSON.stringify({ phase, observedExit: receipt[phase].exitCode }));
        return { name, key, sha256: receipt[phase].reportSha256 };
    });
    const native = { ...request, conclusion: "success", imageDigest: policy.imageDigest, planSha256: cloudCiPlanSha256,
        requiredChecks: checks.map((check) => check.name), checks, verificationReports, verificationReceipt: receipt };
    const report = { repository: proposal.repository, branch: "main", sha: base, controllerRevision: policy.controllerRevision,
        publishRequested: true, publications: [{ ...adapted, request, id }] };
    const body = publicationBodies({ proposal, receipt, evidenceDigest: sha256(canonicalJson(receipt)) }).pullRequest;
    const pull = { number: 7, state: "open", draft: false, user: { login: "omg-ci-publisher[bot]", id: 345568822 }, body,
        base: { ref: "main", sha: base, repo: { full_name: proposal.repository } },
        head: { ref: `ai-fix/${finding.key.slice(0, 16)}-${base.slice(0, 12)}`, sha: head, repo: { full_name: proposal.repository } } };
    const baseTree = { truncated: false, tree: [{ path: finding.path, type: "blob", mode: "100644", sha: gitBlobSha(source) }] };
    const headTree = { truncated: false, tree: proposal.changes.map((file) => ({ path: file.path, type: "blob", mode: "100644", sha: gitBlobSha(file.newContent) })) };
    const ciChecks = ["CI Success", "Instrumented coverage tests", "Generate Coverage Report", "Orchestration tests, types and dry builds", "QEMU behavioral verification / QEMU matrix result"].map((name) => ({ name,
        head_sha: head, status: "completed", conclusion: "success", app: { id: 15368, slug: "github-actions" } }));
    const originalRun = { id: 42, repository: { full_name: proposal.repository }, head_branch: "main",
        path: ".github/workflows/ai-review.yml", head_sha: base, run_attempt: 1,
        status: "completed", conclusion: "success", event: "workflow_dispatch" };
    const originalJobs = [{ id: 4201, name: "review", workflow_name: "AI source review", run_id: 42, run_attempt: 1,
        run_url: "https://api.github.com/repos/omg-cli/omg/actions/runs/42", head_branch: "main", head_sha: base,
        status: "completed", conclusion: "success" }];
    const state = { posts: [], saved: [], pullReads: 0, mutateFresh: false, verdict: "approved", corruptRaw: false,
        originalRun, originalJobs };
    const github = { async request(method, route, data) {
        if (method === "POST") { state.posts.push({ route, data }); return { id: 1, commit_id: data.commit_id, state: "APPROVED", user: { id: 41898282, login: "github-actions[bot]" } }; }
        if (route.includes("/check-runs?")) return { check_runs: ciChecks };
        if (route.endsWith("/git/ref/heads/main")) return { object: { sha: base } };
        if (route.endsWith("/pulls/7")) { state.pullReads++; return structuredClone(state.mutateFresh && state.pullReads > 1 ? { ...pull, head: { ...pull.head, sha: "9".repeat(40) } } : pull); }
        if (route.includes("/reviews?")) return [];
        if (route.endsWith("/actions/runs/42/attempts/1")) return originalRun;
        if (route.includes("/actions/runs/42/attempts/1/jobs?")) return { jobs: originalJobs };
        if (route.endsWith(`/git/commits/${base}`)) return { sha: base, tree: { sha: "0".repeat(40) } };
        if (route.endsWith(`/git/commits/${head}`)) return { sha: head, tree: { sha: tree }, parents: [{ sha: base }] };
        if (route.includes(`/git/trees/${"0".repeat(40)}`)) return baseTree;
        if (route.includes(`/git/trees/${tree}`)) return headTree;
        if (route.endsWith(`/git/blobs/${gitBlobSha(source)}`)) return { encoding: "base64", content: Buffer.from(source).toString("base64") };
        throw new Error(`Unexpected GitHub route ${route}`);
    } };
    const services = { ciJson: async (route) => route.startsWith("/review-records/") ? report : native,
        ciRaw: async (route) => { const parts = route.split("/"); const key = `${parts[3]}/${id}/${parts[4]}`; return new Response(state.corruptRaw ? "substituted bytes" : raw.get(key)); },
        admitQemu: async () => {}, saveReview: async (record) => { state.saved.push(record); },
        inspectPatch: async (input) => ({ purpose: input.purpose, inputSha256: patchReviewDigest(input),
            baseSha: input.baseSha, headSha: input.headSha, headTreeSha: input.headTreeSha, proposalSha256: input.proposalSha256,
            model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017", readCompletePatch: true, codeExecutions: 1,
            result: { verdict: state.verdict, reason: "The literal assertion exercises the public constant and the edit repairs it.", findings: [] } }),
    };
    return { github, services, number: 7, expectedHead: head, publisher: pull.user, policy, approve: true,
        state, report, native, pull, headTree, receipt };
}

test("only independently admitted raw proof, exact tree, current checks and explicit verdict submit an exact-head approval", async () => {
    const input = fixture();
    const result = await reviewAiFix(input);
    assert.equal(result.action, "approved");
    assert.equal(input.state.saved.length, 1);
    assert.equal(input.state.posts.length, 1);
    assert.equal(input.state.posts[0].data.commit_id, input.expectedHead);
    assert.equal(input.state.posts[0].data.event, "APPROVE");
});

for (const [name, mutate] of [
    ["substituted raw object", (x) => { x.state.corruptRaw = true; }],
    ["different original controller", (x) => { x.report.controllerRevision = "0".repeat(40); }],
    ["changed original assertion", (x) => { x.native.verificationReceipt.baseline.assertionSourceSha256 = "0".repeat(64); }],
    ["changed original proposal", (x) => { x.report.publications[0].proposal.changes[0].newContent = "bad"; }],
    ["weak test substituted after publication", (x) => { x.headTree.tree[1].sha = "9".repeat(40); }],
    ["new head during independent review", (x) => { x.state.mutateFresh = true; }],
]) test(`never approves ${name}`, async () => {
    const input = fixture(); mutate(input);
    await assert.rejects(reviewAiFix(input));
    assert.equal(input.state.posts.length, 0);
});

test("insufficient independent evidence records a hold without an approval", async () => {
    const input = fixture(); input.state.verdict = "insufficient-evidence";
    assert.equal((await reviewAiFix(input)).action, "held");
    assert.equal(input.state.posts.length, 0);
});

test("recovered publication can approve original successful review proof when only its publisher failed", async () => {
    const input = fixture();
    input.state.originalRun.conclusion = "failure";
    assert.equal((await reviewAiFix(input)).action, "approved");
    assert.equal(input.state.posts[0].data.commit_id, input.expectedHead);
    assert.equal(input.native.verificationReceipt.runId, 42);
    assert.equal(input.native.verificationReceipt.runAttempt, 1);
});

for (const [name, mutate] of [
    ["failed original review", (x) => { x.state.originalJobs[0].conclusion = "failure"; }],
    ["cancelled original review", (x) => { x.state.originalJobs[0].conclusion = "cancelled"; }],
    ["pending original review", (x) => { x.state.originalJobs[0].status = "in_progress"; }],
    ["nonterminal original workflow", (x) => { x.state.originalRun.status = "in_progress"; }],
    ["cancelled original workflow", (x) => { x.state.originalRun.conclusion = "cancelled"; }],
    ["review from another attempt", (x) => { x.state.originalJobs[0].run_attempt = 2; }],
    ["review from another source", (x) => { x.state.originalJobs[0].head_sha = "9".repeat(40); }],
    ["review from another workflow run", (x) => { x.state.originalJobs[0].run_id = 43; }],
    ["missing original review", (x) => { x.state.originalJobs.length = 0; }],
    ["ambiguous original review", (x) => { x.state.originalJobs.push({ ...x.state.originalJobs[0], id: 4202 }); }],
]) test(`recovered publication never admits ${name}`, async () => {
    const input = fixture(); mutate(input);
    await assert.rejects(reviewAiFix(input));
    assert.equal(input.state.posts.length, 0);
});

test("QEMU run admission rejects a different source and non-CI producer", () => {
    const run = { id: 42, run_attempt: 1, repository: { full_name: "omg-cli/omg" }, path: ".github/workflows/ci.yml",
        event: "pull_request", head_sha: "a".repeat(40), status: "completed", conclusion: "success" };
    admitQemuRun(run, run.head_sha);
    assert.throws(() => admitQemuRun(run, "b".repeat(40)));
    assert.throws(() => admitQemuRun({ ...run, path: ".github/workflows/evil.yml" }, run.head_sha));
});

test("QEMU merge-ref execution admits only the exact repair tree and verified base/head parents", () => {
    const identity = { headSha: "a".repeat(40), baseSha: "b".repeat(40), headTreeSha: "c".repeat(40) };
    const merge = { sha: "d".repeat(40), tree: { sha: identity.headTreeSha }, parents: [{ sha: identity.baseSha }, { sha: identity.headSha }] };
    admitQemuSource(merge, identity);
    assert.throws(() => admitQemuSource({ ...merge, tree: { sha: "f".repeat(40) } }, identity));
    assert.throws(() => admitQemuSource({ ...merge, parents: [{ sha: "f".repeat(40) }, { sha: identity.headSha }] }, identity));
});

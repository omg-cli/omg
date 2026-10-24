import { test } from "bun:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, existsSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { admitTestAuditParent, recoverTestAuditCampaign, testAuditTarget } from "../../scripts/test-audit-campaign.mjs";
import * as reviewFlow from "../../scripts/ai-review-flow.mjs";
const loadTestAuditRenewal = (...args) => reviewFlow.loadTestAuditRenewal(...args);

const OLD = "1".repeat(40);
const CURRENT = "2".repeat(40);
const OLD_CONTROLLER = "3".repeat(40);
const CONTROLLER = "4".repeat(40);
const MANIFEST = "5".repeat(64);
const INVENTORY = "6".repeat(64);
const PRIOR_IMAGE = `sha256:${"7".repeat(64)}`;
const IMAGE = `sha256:${"8".repeat(64)}`;
const VERIFIER = "9".repeat(40);
const RECORD = "a".repeat(64);

const parent = (overrides = {}) => ({
    campaignRun: { runId: "100", attempt: "1" },
    repository: "omg-cli/omg",
    branch: "main",
    sha: OLD,
    controllerRevision: OLD_CONTROLLER,
    status: "reviewed",
    publishRequested: true,
    formatting: { status: "passed", sha: OLD, ref: "refs/heads/main", runId: "90", attempt: "1" },
    sourceRange: { kind: "test-audit", sha: OLD, manifestDigest: MANIFEST, inventoryDigest: INVENTORY, cursor: 109, nextCursor: 110, pageSize: 1, pagePaths: 1, totalPaths: 1233 },
    testAudits: [],
    testAuditOutcomes: [],
    ...overrides,
});
const renewal = (overrides = {}) => ({
    kind: "test-audit-controller-renewal",
    repository: "omg-cli/omg",
    enabled: true,
    source: OLD,
    branch: "main",
    publish: true,
    parent: "100-1",
    parentController: OLD_CONTROLLER,
    targetController: CONTROLLER,
    manifestDigest: MANIFEST,
    inventoryDigest: INVENTORY,
    priorImageDigest: PRIOR_IMAGE,
    publication: "skipped",
    imageDigest: IMAGE,
    verifierRevision: VERIFIER,
    ...overrides,
});
const loadedRenewal = (overrides = {}) => ({
    ...renewal(overrides),
    controllerRevision: CONTROLLER,
    recordSha256: RECORD,
});
const target = (overrides = {}) => ({
    branch: "main",
    sha: CURRENT,
    publish: true,
    auditParent: "100-1",
    range: { kind: "test-audit", sha: CURRENT, cursor: 110, manifestDigest: MANIFEST, resnapshot: true },
    ...overrides,
});
const campaign = (overrides = {}) => ({
    renewal: loadedRenewal(),
    mainSha: CURRENT,
    imageDigest: IMAGE,
    verifierRevision: VERIFIER,
    ...overrides,
});
const admit = (targetOverrides = {}, publicationResult = "skipped", campaignOverrides = {}) =>
    admitTestAuditParent(target(targetOverrides), parent(), CONTROLLER, MANIFEST, publicationResult, campaign(campaignOverrides));

const recoveryApi = ({ report, item, publication = "skipped", children = [] }) => {
    const workflow = { id: 391232924, name: "AI source review", path: ".github/workflows/ai-review.yml" };
    const direct = {
        id: item.id, run_attempt: item.run_attempt, status: "completed",
        display_title: item.display_title, head_sha: item.head_sha, head_branch: "main",
        path: workflow.path, name: "AI source review", workflow_id: workflow.id,
        repository: { full_name: "omg-cli/omg" }, event: "workflow_dispatch",
    };
    const jobs = { jobs: [
        { name: "review", status: "completed", conclusion: "success" },
        { name: "publish", status: "completed", conclusion: publication },
    ] };
    const github = {
        async request(method, route) {
            assert.equal(method, "GET");
            if (route === `/repos/omg-cli/omg/actions/runs/${item.id}`) return direct;
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml") return workflow;
            if (route === `/repos/omg-cli/omg/actions/runs/${item.id}/attempts/${item.run_attempt}`) return direct;
            if (route === `/repos/omg-cli/omg/actions/runs/${item.id}/attempts/${item.run_attempt}/jobs?per_page=100`) return jobs;
            if (route.includes("/runs?event=workflow_dispatch&head_sha=")) return { workflow_runs: children };
            if (route.includes("/runs?event=workflow_dispatch&branch=main")) return { workflow_runs: [item] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
    return { github };
};
const runRecovery = async ({ report, item, renewalRecord, publication = "skipped", children = [], imageDigest = IMAGE, verifierRevision = VERIFIER, manifestDigest = MANIFEST }) => {
    const dispatched = [], reruns = [];
    const result = await recoverTestAuditCampaign({
        ...recoveryApi({ report, item, publication, children }),
        currentSha: CURRENT, revision: CONTROLLER, renewal: renewalRecord,
        imageDigest, verifierRevision, manifestDigest,
        currentRunId: "200", currentRunAttempt: "1",
        loadRecord: async (ref) => { assert.equal(ref, `${item.id}-${item.run_attempt}`); return report; },
        dispatch: async (inputs) => dispatched.push(inputs),
        rerun: async (id) => reruns.push(id),
        loadIntent: async () => { throw Object.assign(new Error("missing"), { status: 404 }); },
        storeIntent: async () => ({ stored: true, created: true }),
    });
    return { result, dispatched, reruns };
};

const oldItem = { id: 100, run_attempt: 1, display_title: `Test audit initial ${OLD} 109`, head_sha: OLD, head_branch: "main", path: ".github/workflows/ai-review.yml", repository: { full_name: "omg-cli/omg" } };
const ordinaryItem = { id: 200, run_attempt: 1, display_title: `Test audit initial ${CURRENT} 109`, head_sha: CURRENT, head_branch: "main", path: ".github/workflows/ai-review.yml", repository: { full_name: "omg-cli/omg" } };
const ordinaryReport = () => parent({ campaignRun: { runId: "200", attempt: "1" }, sha: CURRENT, sourceRange: { ...parent().sourceRange, sha: CURRENT }, controllerRevision: CONTROLLER, formatting: { status: "passed", sha: CURRENT, ref: "refs/heads/main", runId: "200", attempt: "1" } });

test("renewal admits an exact old parent onto fresh main without transferring source proof", () => {
    const admitted = admit();
    assert.equal(admitted.upstream, undefined);
    assert.equal(admitted.range.inventoryDigest, undefined);
    assert.equal(admitted.range.resnapshot, true);
    assert.deepEqual(admitted.range.resnapshotOf, { runId: "100", attempt: "1", sha: OLD, cursor: 109, priorUnpublished: false });
    assert.equal(admitted.controllerTransition.from, OLD_CONTROLLER);
    assert.equal(admitted.controllerTransition.to, CONTROLLER);
    assert.equal(admitted.controllerTransition.parent, "100-1");
    assert.equal(admitted.controllerTransition.run, undefined);
});

test("ordinary current-controller intake ignores an enabled renewal record", () => {
    const admitted = admitTestAuditParent(
        target({ auditParent: "200-1", range: { kind: "test-audit", sha: CURRENT, cursor: 110, manifestDigest: MANIFEST, inventoryDigest: INVENTORY, resnapshot: false } }),
        ordinaryReport(), CONTROLLER, MANIFEST, "skipped", campaign(),
    );
    assert.equal(admitted.controllerTransition, undefined);
    assert.equal(admitted.range.resnapshot, false);
});

test("ordinary current-controller recovery ignores an enabled renewal record", async () => {
    const { result, dispatched, reruns } = await runRecovery({ report: ordinaryReport(), item: ordinaryItem, renewalRecord: loadedRenewal() });
    assert.equal(result.status, "dispatched");
    assert.equal(dispatched.length, 1);
    assert.equal(dispatched[0].audit_sha, CURRENT);
    assert.equal(dispatched[0].audit_cursor, "110");
    assert.equal(dispatched[0].audit_resnapshot, undefined);
    assert.equal(reruns.length, 0);
});

test("valid renewal recovery dispatches and the dispatched plan independently admits on intake", async () => {
    const { result, dispatched, reruns } = await runRecovery({ report: parent(), item: oldItem, renewalRecord: loadedRenewal() });
    assert.equal(result.status, "dispatched");
    assert.equal(dispatched.length, 1);
    assert.deepEqual(dispatched[0], { branch: "main", scope: "test-audit", publish: "true", audit_sha: CURRENT, audit_cursor: "110", audit_parent: "100-1", audit_manifest: MANIFEST, audit_resnapshot: "true" });
    assert.equal(reruns.length, 0);
    const parsed = testAuditTarget(dispatched[0]);
    const admitted = admitTestAuditParent({ ...parsed, range: { ...parsed.range, sha: CURRENT } }, parent(), CONTROLLER, MANIFEST, "skipped", campaign());
    assert.equal(admitted.range.resnapshot, true);
    assert.equal(admitted.controllerTransition.to, CONTROLLER);
});

test("missing and disabled renewal records leave the old parent held with zero dispatch", async () => {
    for (const renewalRecord of [undefined]) {
        const { result, dispatched } = await runRecovery({ report: parent(), item: oldItem, renewalRecord });
        assert.equal(result.status, "campaign-controller-or-manifest-held");
        assert.equal(dispatched.length, 0);
    }
    const context = { runId: "200", attempt: "1", controllerRevision: CONTROLLER, imageDigest: IMAGE, verifierRevision: VERIFIER };
    assert.equal(await loadTestAuditRenewal(context, async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); }), undefined);
    assert.equal(await loadTestAuditRenewal(context, async () => renewal({ enabled: false })), undefined);
});

test("malformed renewal records are rejected by the loader and held by recovery", async () => {
    const context = { runId: "200", attempt: "1", controllerRevision: CONTROLLER, imageDigest: IMAGE, verifierRevision: VERIFIER };
    await assert.rejects(loadTestAuditRenewal(context, async () => ({ ...renewal(), inventoryDigest: undefined })), /malformed/);
    const malformed = { ...loadedRenewal(), recordSha256: undefined };
    const { result, dispatched } = await runRecovery({ report: parent(), item: oldItem, renewalRecord: malformed });
    assert.equal(result.status, "campaign-controller-or-manifest-held");
    assert.equal(dispatched.length, 0);
});

test("renewal loader rejects runtime and controller context drift", async () => {
    const context = { runId: "200", attempt: "1", controllerRevision: CONTROLLER, imageDigest: IMAGE, verifierRevision: VERIFIER };
    const loaded = await loadTestAuditRenewal(context, async () => renewal());
    assert.equal(loaded.kind, "test-audit-controller-renewal");
    assert.equal(loaded.controllerRevision, CONTROLLER);
    assert.match(loaded.recordSha256, /^[a-f0-9]{64}$/);
    await assert.rejects(loadTestAuditRenewal({ ...context, imageDigest: PRIOR_IMAGE }, async () => renewal()), /runtime or controller context drifted/);
    await assert.rejects(loadTestAuditRenewal({ ...context, verifierRevision: OLD_CONTROLLER }, async () => renewal()), /runtime or controller context drifted/);
    await assert.rejects(loadTestAuditRenewal({ ...context, controllerRevision: OLD_CONTROLLER }, async () => renewal()), /runtime or controller context drifted/);
});

test("renewal admission rejects source, inventory, manifest, runtime and fresh-main drift", () => {
    assert.throws(() => admit({}, "skipped", { renewal: loadedRenewal({ source: "b".repeat(40) }) }), /lineage/);
    assert.throws(() => admit({}, "skipped", { renewal: loadedRenewal({ inventoryDigest: "b".repeat(64) }) }), /lineage/);
    assert.throws(() => admit({}, "skipped", { renewal: loadedRenewal({ manifestDigest: "b".repeat(64) }) }), /controller, runtime or manifest/);
    assert.throws(() => admit({}, "skipped", { imageDigest: PRIOR_IMAGE }), /runtime drifted/);
    assert.throws(() => admit({}, "skipped", { verifierRevision: OLD_CONTROLLER }), /runtime drifted/);
    assert.throws(() => admit({ sha: OLD, range: { ...target().range, sha: OLD } }, "skipped", { mainSha: OLD }), /lineage/);
    assert.throws(() => admit({}, "skipped", { mainSha: OLD }), /lineage/);
    assert.throws(() => admit({ range: { ...target().range, cursor: 109 } }), /authorize|cursor/);
    assert.throws(() => admitTestAuditParent(target(), parent({ status: "incomplete-stale" }), CONTROLLER, MANIFEST, "skipped", campaign()), /lineage/);
    assert.throws(() => admitTestAuditParent(target(), parent({ controllerRevision: "b".repeat(40) }), CONTROLLER, MANIFEST, "skipped", campaign()), /parent\/controller\/manifest/);
});

test("renewal publication must be an explicit terminal conclusion, not a defaulted or pending value", () => {
    assert.throws(() => admit({}, null), /publication/);
    assert.throws(() => admit({}, "pending"), /publication/);
    assert.throws(() => admit({}, "in_progress"), /publication/);
    assert.throws(() => admit({}, "failure"), /publication/);
    assert.throws(() => admit({}, "success"), /publication/);
    assert.equal(admit({}, "skipped").range.resnapshot, true);
});

test("renewal recovery holds publication drift and runtime drift with zero dispatch", async () => {
    const cases = [
        { renewalRecord: loadedRenewal({ publication: "success" }), publication: "skipped" },
        { renewalRecord: loadedRenewal(), publication: "failure" },
        { renewalRecord: loadedRenewal(), imageDigest: PRIOR_IMAGE },
        { renewalRecord: loadedRenewal(), verifierRevision: OLD_CONTROLLER },
        { renewalRecord: loadedRenewal({ source: "b".repeat(40) }) },
        { renewalRecord: loadedRenewal({ inventoryDigest: "b".repeat(64) }) },
        { renewalRecord: loadedRenewal({ manifestDigest: "b".repeat(64) }) },
    ];
    for (const entry of cases) {
        const { result, dispatched } = await runRecovery({ report: parent(), item: oldItem, ...entry });
        assert.equal(result.status, "campaign-controller-or-manifest-held");
        assert.equal(dispatched.length, 0);
    }
});

test("renewal recovery preserves duplicate child ownership and performs no second dispatch", async () => {
    const child = {
        id: 300, display_title: `Test audit 100-1 ${CURRENT} 110`,
        head_sha: CURRENT, head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const { result, dispatched } = await runRecovery({ report: parent(), item: oldItem, renewalRecord: loadedRenewal(), children: [child] });
    assert.equal(result.status, "existing-child");
    assert.deepEqual(result.runIds, ["300"]);
    assert.equal(dispatched.length, 0);
});

const missingChild = (overrides = {}) => ({
    id: 400, run_attempt: 1, status: "completed", conclusion: "failure",
    display_title: `Test audit 100-1 ${OLD} 109`, head_sha: OLD, head_branch: "main",
    path: ".github/workflows/ai-review.yml", repository: { full_name: "omg-cli/omg" },
    event: "workflow_dispatch", workflow_id: 391232924,
    ...overrides,
});
test("missing-record recovery is not authorized by a renewal record for a different parent", async () => {
    const child = missingChild();
    const dispatched = [], reruns = [], intents = [];
    const workflow = { id: 391232924, name: "AI source review", path: ".github/workflows/ai-review.yml" };
    const github = {
        async request(method, route) {
            assert.equal(method, "GET");
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml") return workflow;
            if (route === `/repos/omg-cli/omg/actions/runs/${child.id}`) return child;
            if (route.includes("/runs?event=workflow_dispatch&branch=main")) return { workflow_runs: [child] };
            if (route.includes("head_sha=")) return { workflow_runs: [] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
    const result = await recoverTestAuditCampaign({
        github, currentSha: CURRENT, revision: CONTROLLER, renewal: loadedRenewal(),
        imageDigest: IMAGE, verifierRevision: VERIFIER, manifestDigest: MANIFEST,
        currentRunId: "200", currentRunAttempt: "1",
        loadRecord: async (ref) => { if (ref === "100-1") return parent(); assert.equal(ref, "400-1"); throw Object.assign(new Error("missing"), { status: 404 }); },
        loadIntent: async (ref) => { intents.push(ref); throw Object.assign(new Error("missing"), { status: 404 }); },
        storeIntent: async () => { throw new Error("no intent should be stored"); },
        rerun: async (id) => reruns.push(id),
        dispatch: async (inputs) => dispatched.push(inputs),
    });
    assert.equal(result.status, "campaign-recovery-held");
    assert.equal(result.reason, "title-named-parent-lineage-mismatch");
    assert.equal(dispatched.length, 0);
    assert.equal(reruns.length, 0);
    assert.deepEqual(intents, ["400-1"]);
});
for (const job of ["review", "continue"]) {
    test(`${job} workflow materializes only bounded owner policy in protected configuration`, () => {
        const workflow = Bun.YAML.parse(readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"));
        const step = workflow.jobs[job].steps.find((item) => item.name?.startsWith("Create private"));
        assert.equal(step.env.OMG_CI_AUDIT_RENEWAL, "${{ vars.OMG_CI_AUDIT_RENEWAL }}");
        const match = step.run.match(/^bun run - <<'JS'\n([\s\S]*)\nJS\s*$/);
        assert.ok(match);
        for (const raw of ["", JSON.stringify(renewal()), "🦀".repeat(2050)]) {
            const home = mkdtempSync(path.join(tmpdir(), "omg-renewal-writer-"));
            try {
                const code = `import { homedir as checkedHome } from "node:os"; if (checkedHome() !== process.env.RENEWAL_TEST_HOME) throw new Error("Test home isolation failed");\n${match[1]}`;
                const env = { ...process.env, HOME: home, USERPROFILE: home, RENEWAL_TEST_HOME: home,
                    OMG_CI_API_TOKEN: "t".repeat(40), OMG_CI_INSPECTOR_TOKEN: "i".repeat(40), OMG_CI_CODER_TOKEN: "c".repeat(40),
                    OMG_CI_IMAGE_DIGEST: IMAGE, OMG_CI_VERIFIER_REVISION: VERIFIER,
                    OMG_CI_CODER_SKILL_BUNDLE_SHA256: MANIFEST, OMG_CI_AUDIT_RENEWAL: raw };
                const result = Bun.spawnSync([process.execPath, "-e", code], { env });
                const file = path.join(home, "ci", "test-audit-renewal.json");
                if (Buffer.byteLength(raw, "utf8") > 8192) {
                    assert.notEqual(result.exitCode, 0);
                    assert.match(result.stderr.toString(), /policy budget/);
                    assert.equal(existsSync(file), false);
                } else {
                    assert.equal(result.exitCode, 0, result.stderr.toString());
                    assert.equal(existsSync(file), raw !== "");
                    if (raw) {
                        assert.equal(readFileSync(file, "utf8"), raw);
                        if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600);
                        const repeated = Bun.spawnSync([process.execPath, "-e", code], { env });
                        assert.notEqual(repeated.exitCode, 0);
                        assert.equal(readFileSync(file, "utf8"), raw);
                    }
                }
                assert.equal(workflow.env?.OMG_CI_AUDIT_RENEWAL, undefined);
                assert.ok(workflow.jobs[job].steps.some((item) => item.if === "always()" && item.run?.includes('$HOME/ci/test-audit-renewal.json')));
            } finally {
                assert.equal(path.dirname(home), path.resolve(tmpdir()));
                assert.ok(path.basename(home).startsWith("omg-renewal-writer-"));
                rmSync(home, { recursive: true, force: true });
            }
        }
    });
}

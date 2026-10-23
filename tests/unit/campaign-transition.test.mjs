import { test } from "bun:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { admitTestAuditParent } from "../../scripts/test-audit-campaign.mjs";
const source = "1ab1494c81890facb179586b62acbe0128016a99",
    actual = "c".repeat(40),
    verifier = "f1d5a4b505551161b4bd1569bbaf919d04ab7f51",
    manifest = "3871d9de952fc615ac914f45265ac94497d4a6b1f4b48ed325fd20618a53ba54",
    inventory = "7772884734180b4fff99af3a93310fcb43067e7bd01212ae519fc010c73c038e",
    priorImage = "sha256:ce6487ba808ed16b4e7ae29c9db5df1b99308a29ab11257bfef970ef80453372",
    image = "sha256:22c2f3c4cc5dc6d895bcb7a60e095c11de9fd2fde50289432ae0967d465f0740";
const parentRecord = () => ({
    repository: "omg-cli/omg", sha: source, branch: "main", baseSha: source, batches: [],
    campaignParent: "39866608722-1", campaignRun: { attempt: "1", runId: "39866923977" },
    candidateOutcomes: [], controllerRevision: source,
    coverageMeaning: "Historical backlog names were reconciled to exact current file candidates. Only independently admitted exact test/fault execution earns bounded sensitivity credit. Held rows remain unresolved.",
    formatting: {
        attempt: "3", conclusion: "failure", ref: "refs/heads/main", runId: "39808913262", sha: source,
        sourceFormat: { audit: null, exitCode: 0, name: "source-format", reports: [], stderrKey: `logs/cl-39808913262-3-${source}/source-format.stderr`, stderrSha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", stdoutKey: `logs/cl-39808913262-3-${source}/source-format.stdout`, stdoutSha256: "2732d4411bb14cec5d0e90464ebeddde71d9ad1629dbad95b8e6ddcb9ce03220", verification: null },
        status: "passed",
    },
    publications: [], publishRequested: true, readPaths: [],
    sourceRange: { cursor: 61, inventoryDigest: inventory, kind: "test-audit", manifestDigest: manifest, nextCursor: 62, pagePaths: 1, pageSize: 1, sha: source, totalPaths: 1233 },
    status: "reviewed", suppliedPaths: ["tests/debian_tests.rs"],
    testAuditOutcomes: [{ id: "test:debian_tests#apt_integration::test_update_check_no_updates_when_current", status: "no-supported-strengthening" }],
    testAudits: [], triggerSha: source, unreviewedPaths: [],
});
const priorChildRecord = () => ({
    repository: "omg-cli/omg", sha: source, branch: "main", baseSha: source, batches: [],
    campaignParent: "39866923977-1", campaignRun: { attempt: "1", runId: "39871147004" },
    candidateOutcomes: [], controllerRevision: source,
    coverageMeaning: "Source inventory was collected, but model review was blocked because formatting evidence was not admitted.",
    formatting: { attempt: "3", reason: "source-format-evidence-unavailable-or-rejected", ref: "refs/heads/main", runId: "39808913262", sha: source, status: "blocked" },
    publications: [], publishRequested: true, readPaths: [],
    sourceRange: { cursor: 62, inventoryDigest: inventory, kind: "test-audit", manifestDigest: manifest, nextCursor: 63, pagePaths: 1, pageSize: 1, sha: source, totalPaths: 1233 },
    status: "format-blocked", suppliedPaths: [], triggerSha: source,
    unreviewedPaths: [{ path: "tests/debian_tests.rs", reason: "source-format-blocked" }],
});
const rawTransition = () => ({
    kind: "test-audit-controller-transition", repository: "omg-cli/omg", enabled: true,
    source, branch: "main", publish: true, parent: "39866923977-1", parentController: source,
    priorChild: "39871147004-1", run: "39871147004-2", cursor: 62, pageSize: 1, pagePaths: 1,
    totalPaths: 1233, manifestDigest: manifest, inventoryDigest: inventory,
    priorFormatting: { runId: "39808913262", attempt: "3", sha: source, ref: "refs/heads/main" },
    priorImageDigest: priorImage, imageDigest: image, verifierRevision: verifier,
});
const transitionRecord = () => {
    const raw = rawTransition();
    return { ...raw, controllerRevision: actual, recordSha256: createHash("sha256").update(JSON.stringify(raw)).digest("hex") };
};
const transition = transitionRecord();
const target = () => ({ branch: "main", sha: source, publish: true, auditParent: "39866923977-1", range: { kind: "test-audit", cursor: 62, manifestDigest: manifest, inventoryDigest: inventory } });
const campaign = () => ({ transition: { ...transition, priorFormatting: { ...transition.priorFormatting } }, priorChild: priorChildRecord(), runId: "39871147004", attempt: "2", imageDigest: image, verifierRevision: verifier });
const admit = (overrides = {}) => admitTestAuditParent(
    overrides.target ?? target(),
    overrides.parent ?? parentRecord(),
    overrides.revision ?? actual,
    overrides.manifest ?? manifest,
    overrides.publicationResult ?? "skipped",
    overrides.campaign === undefined ? campaign() : overrides.campaign,
);
test("exact blocked-child intake transition admits unchanged upstream with controller metadata", () => {
    const admitted = admit();
    assert.deepEqual(admitted.upstream, { runId: "39808913262", attempt: "3" });
    assert.deepEqual(admitted.controllerTransition, { from: source, to: actual, recordSha256: transition.recordSha256, parent: "39866923977-1", priorChild: "39871147004-1", run: "39871147004-2" });
    assert.equal(admitted.range.cursor, 62);
    assert.equal(admitted.range.resnapshot, undefined);
    assert.equal(admitted.range.inventoryDigest, inventory);
    assert.equal(admitted.sha, source);
});
test("ordinary controller equality admission is unchanged and adds no transition metadata", () => {
    const admitted = admitTestAuditParent({ ...target(), auditParent: "39866923977-1" }, { ...parentRecord(), controllerRevision: actual }, actual, manifest, "skipped");
    assert.deepEqual(admitted.upstream, { runId: "39808913262", attempt: "3" });
    assert.equal(admitted.controllerTransition, undefined);
});
test("derived controller revision, not verifier revision, authorizes the transition", () => {
    const changed = campaign();
    changed.verifierRevision = "9".repeat(40);
    changed.transition.verifierRevision = "9".repeat(40);
    assert.doesNotThrow(() => admit({ campaign: changed }));
    const wrong = campaign();
    wrong.transition.controllerRevision = "9".repeat(40);
    wrong.verifierRevision = actual;
    wrong.transition.verifierRevision = actual;
    assert.throws(() => admit({ campaign: wrong }), /controller or manifest/);
});
test("campaign intake rejects alternate identities, flags, pages and unproved prior records", () => {
    const cases = [
        ["alternate run", () => { const c = campaign(); c.runId = "39871147005"; c.transition.run = "39871147005-2"; return { campaign: c }; }],
        ["attempt 3", () => { const c = campaign(); c.attempt = "3"; c.transition.run = "39871147004-3"; return { campaign: c }; }],
        ["alternate parent", () => { const c = campaign(); c.transition.parent = "39866923978-1"; return { campaign: c }; }],
        ["alternate parent controller", () => { const c = campaign(); c.transition.parentController = "f".repeat(40); return { campaign: c }; }],
        ["alternate controller", () => { const c = campaign(); c.transition.controllerRevision = "f".repeat(40); return { campaign: c }; }],
        ["alternate source", () => { const c = campaign(); c.transition.source = "f".repeat(40); return { campaign: c }; }],
        ["alternate ref", () => { const c = campaign(); c.transition.priorFormatting.ref = "refs/heads/other"; return { campaign: c }; }],
        ["alternate manifest", () => { const c = campaign(); c.transition.manifestDigest = "f".repeat(64); return { campaign: c }; }],
        ["alternate inventory", () => { const c = campaign(); c.transition.inventoryDigest = "f".repeat(64); return { campaign: c }; }],
        ["alternate cursor", () => { const c = campaign(); c.transition.cursor = 63; return { campaign: c }; }],
        ["alternate page size", () => { const c = campaign(); c.transition.pageSize = 2; return { campaign: c }; }],
        ["alternate page paths", () => { const c = campaign(); c.transition.pagePaths = 2; return { campaign: c }; }],
        ["alternate total paths", () => { const c = campaign(); c.transition.totalPaths = 1234; return { campaign: c }; }],
        ["alternate next cursor", () => { const c = campaign(); c.priorChild.sourceRange.nextCursor = 64; return { campaign: c }; }],
        ["disabled record", () => { const c = campaign(); c.transition.enabled = false; return { campaign: c }; }],
        ["publish flag", () => { const c = campaign(); c.transition.publish = false; return { campaign: c }; }],
        ["active prior child", () => { const c = campaign(); c.priorChild.status = "in-progress"; return { campaign: c }; }],
        ["duplicate current attempt", () => { const c = campaign(); c.attempt = "1"; c.transition.run = "39871147004-1"; return { campaign: c, target: { ...target(), auditParent: "39871147004-1" } }; }],
        ["exhausted inventory", () => { const c = campaign(); c.transition.totalPaths = 63; c.priorChild.sourceRange.totalPaths = 63; c.priorChild.sourceRange.nextCursor = null; c.parent = undefined; return { campaign: c, parent: { ...parentRecord(), sourceRange: { ...parentRecord().sourceRange, totalPaths: 63 } } }; }],
        ["inferred field", () => { const c = campaign(); delete c.transition.priorImageDigest; return { campaign: c }; }],
        ["proved outcome", () => { const c = campaign(); c.priorChild.testAuditOutcomes = [{ id: "x", status: "verified-sensitivity" }]; return { campaign: c }; }],
        ["malformed outcomes", () => { const c = campaign(); c.priorChild.testAuditOutcomes = "none"; return { campaign: c }; }],
        ["nonempty publications", () => { const c = campaign(); c.priorChild.publications = [{}]; return { campaign: c }; }],
        ["alternate blocked path", () => { const c = campaign(); c.priorChild.unreviewedPaths[0].path = "tests/other.rs"; return { campaign: c }; }],
        ["alternate blocked reason", () => { const c = campaign(); c.priorChild.unreviewedPaths[0].reason = "other"; return { campaign: c }; }],
        ["invented prior field", () => { const c = campaign(); c.priorChild.extra = true; return { campaign: c }; }],
        ["missing prior field", () => { const c = campaign(); delete c.priorChild.triggerSha; return { campaign: c }; }],
        ["prior child controller", () => { const c = campaign(); c.priorChild.controllerRevision = "f".repeat(40); return { campaign: c }; }],
        ["prior child parent", () => { const c = campaign(); c.priorChild.campaignParent = "39866923978-1"; return { campaign: c }; }],
        ["parent status", () => { const p = parentRecord(); p.status = "format-blocked"; return { parent: p }; }],
        ["alternate revision", () => ({ revision: "9".repeat(40) })],
        ["alternate manifest arg", () => ({ manifest: "f".repeat(64) })],
        ["target publish", () => ({ target: { ...target(), publish: false } })],
        ["target branch", () => ({ target: { ...target(), branch: "other" } })],
        ["target cursor", () => ({ target: { ...target(), range: { ...target().range, cursor: 63 } } })] ,
        ["resnapshot flag", () => ({ target: { ...target(), range: { ...target().range, resnapshot: true } } })],
        ["target parent", () => ({ target: { ...target(), auditParent: "39871147004-3" } })],
        ["bad record hash", () => { const c = campaign(); c.transition.recordSha256 = "x"; return { campaign: c }; }],
        ["bad verifier revision", () => { const c = campaign(); c.transition.verifierRevision = "x"; return { campaign: c }; }],
        ["image mismatch", () => { const c = campaign(); c.imageDigest = priorImage; return { campaign: c }; }],
        ["prior image equals current", () => { const c = campaign(); c.transition.priorImageDigest = image; return { campaign: c }; }],
    ];
    for (const [name, build] of cases)
        assert.throws(() => admit(build()), /Campaign transition|Campaign prior child/, name);
});
test("campaign intake rejects a missing transition or prior child record", () => {
    const missing = campaign();
    delete missing.transition;
    assert.throws(() => admit({ campaign: missing }), /Campaign parent\/controller\/manifest mismatch/);
    const noChild = campaign();
    delete noChild.priorChild;
    assert.throws(() => admit({ campaign: noChild }), /Campaign transition/);
});
test("ordinary caller context with no admitted transition preserves strict controller equality", () => {
    const admitted = admitTestAuditParent(target(), { ...parentRecord(), controllerRevision: actual }, actual,
        manifest, "skipped", { transition: undefined, priorChild: undefined,
            runId: "39871147004", attempt: "2", imageDigest: image, verifierRevision: verifier });
    assert.deepEqual(admitted.upstream, { runId: "39808913262", attempt: "3" });
    assert.equal(admitted.controllerTransition, undefined);
});

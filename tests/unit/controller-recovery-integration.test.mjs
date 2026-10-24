import { test } from "bun:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { admitAuditResume, loadTestAuditTransition, transitionMatchesFormatting, admitFormattingRun } from "../../scripts/ai-review-flow.mjs";
import { cloudCiPlanSha256, verifyCloudCiObjects } from "../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudChecks } from "../../services/cloud-ci/runner/plan.mjs";
import { sha256 } from "../../scripts/ai-review-publication.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixed = path.join(root, "config/ci/test-audit-transition.json");
const raw = JSON.parse(await readFile(fixed, "utf8"));
const records = JSON.parse(await readFile(new URL("../fixtures/controller-recovery-records.json", import.meta.url), "utf8"));
const context = { runId: "39871147004", attempt: "2", controllerRevision: "c".repeat(40), imageDigest: raw.imageDigest, verifierRevision: raw.verifierRevision };

const receipt = (runId, attempt, imageDigest) => {
    const id = `cl-${runId}-${attempt}-${raw.source}`;
    return { id, repository: "omg-cli/omg", sha: raw.source, ref: "refs/heads/main", runId, attempt,
        imageDigest, conclusion: "success", planSha256: cloudCiPlanSha256, requiredChecks: expectedCloudChecks("refs/heads/main"),
        checks: [{ name: "source-format", exitCode: 0, reports: [], verification: null, audit: null,
            stdoutKey: `logs/${id}/source-format.stdout`, stderrKey: `logs/${id}/source-format.stderr`,
            stdoutSha256: sha256("clean\n"), stderrSha256: sha256("") }] };
};

for (const corruptFresh of [false, true]) test(`composed exact intake admits old raw evidence before fresh format, corruptFresh=${corruptFresh}`, async () => {
    const transition = await loadTestAuditTransition(context, async (file) => {
        assert.equal(file, fixed);
        return { ...raw, enabled: true };
    });
    const target = { branch: "main", publish: true, sha: raw.source, auditParent: "39866923977-1",
        range: structuredClone(records.priorChild.sourceRange) };
    const admitted = admitAuditResume(target, structuredClone(records.parent), context.controllerRevision, {
        ...context, transition, priorChild: structuredClone(records.priorChild), manifestDigest: raw.manifestDigest, publicationResult: "skipped",
    });
    assert.equal(admitted.auditParent, "39866923977-1");
    assert.deepEqual(admitted.upstream, { runId: "39808913262", attempt: "3" });
    assert.equal(admitted.controllerTransition.to, "c".repeat(40));
    assert.equal(transitionMatchesFormatting(transition, { sha: target.sha, branch: "main", upstream: admitted.upstream }), true);
    const prior = receipt("39808913262", "3", raw.priorImageDigest);
    const fresh = receipt("39871147004", "2", raw.imageDigest);
    const events = [];
    const run = () => admitFormattingRun({ sha: raw.source, branch: "main", upstream: admitted.upstream,
        runId: context.runId, attempt: context.attempt, imageDigest: raw.imageDigest, priorImageDigest: transition.priorImageDigest,
        fetchReceipt: async (id) => { assert.ok(id === prior.id || id === fresh.id); return id === prior.id ? prior : fresh; },
        startRun: async (request) => {
            assert.equal(request.runId, "39871147004"); assert.equal(request.attempt, "2");
            events.push("start-current");
        },
        verifyLogs: async (id, format) => {
            await verifyCloudCiObjects({ checks: [format] }, async (key) => {
                assert.ok(key === `logs/${id}/source-format.stdout` || key === `logs/${id}/source-format.stderr`);
                return new Response(key.endsWith("stderr") ? "" : corruptFresh && id === fresh.id ? "corrupt" : "clean\n");
            });
            events.push(id === prior.id ? "prior-raw-admitted" : "fresh-raw-admitted");
        } });
    if (corruptFresh) {
        await assert.rejects(run, /digest|hash/i);
        assert.deepEqual(events, ["prior-raw-admitted", "start-current"]);
    } else {
        const formatting = await run();
        assert.equal(formatting.status, "passed");
        assert.equal(formatting.runId, "39871147004");
        assert.equal(formatting.attempt, "2");
        assert.deepEqual(events, ["prior-raw-admitted", "start-current", "fresh-raw-admitted"]);
    }
});

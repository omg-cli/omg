import { test } from "bun:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { admitFormattingRun } from "../../scripts/ai-review-flow.mjs";
import { cloudCiPlanSha256, verifyCloudCiObjects } from "../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudChecks } from "../../services/cloud-ci/runner/plan.mjs";

const sha = "a".repeat(40);
const branch = "main";
const ref = "refs/heads/main";
const imageDigest = `sha256:${"c".repeat(64)}`;
const priorImageDigest = `sha256:${"b".repeat(64)}`;
const runId = "500";
const attempt = "2";
const upstream = { runId: "400", attempt: "3" };
const requiredChecks = expectedCloudChecks(ref);
const digest = (text) => createHash("sha256").update(text).digest("hex");
const clean = "source format clean\n";

const receiptFor = ({ run = runId, att = attempt, image = imageDigest, stdoutText = clean, stderrText = "" } = {}) => {
    const id = `cl-${run}-${att}-${sha}`;
    return {
        id,
        repository: "omg-cli/omg",
        sha,
        ref,
        runId: run,
        attempt: att,
        conclusion: "success",
        requiredChecks,
        checks: [{
            name: "source-format",
            exitCode: 0,
            stdoutKey: `logs/${id}/source-format.stdout`,
            stderrKey: `logs/${id}/source-format.stderr`,
            stdoutSha256: digest(stdoutText),
            stderrSha256: digest(stderrText),
            reports: [],
            verification: null,
            audit: null,
        }],
        imageDigest: image,
        planSha256: cloudCiPlanSha256,
    };
};

const logsFor = (receipt, { stdoutText = clean, stderrText = "" } = {}) => {
    const check = receipt.checks[0];
    return new Map([[check.stdoutKey, stdoutText], [check.stderrKey, stderrText]]);
};

const rawVerifier = (logs) => async (_id, format) => {
    assert.equal(format.name, "source-format");
    await verifyCloudCiObjects({ checks: [format] }, async (key) => {
        if (!logs.has(key)) return new Response("missing", { status: 404 });
        return new Response(logs.get(key));
    });
};

const call = (overrides) => admitFormattingRun({
    sha,
    branch,
    upstream: undefined,
    runId,
    attempt,
    imageDigest,
    priorImageDigest: undefined,
    ...overrides,
});

test("reuse0: current-image upstream receipt starts zero runs and verifies raw logs", async () => {
    const prior = receiptFor({ run: upstream.runId, att: upstream.attempt, image: imageDigest });
    const fetched = [];
    let starts = 0;
    const result = await call({
        upstream,
        priorImageDigest,
        fetchReceipt: async (id) => { fetched.push(id); return prior; },
        startRun: async () => { starts += 1; },
        verifyLogs: rawVerifier(logsFor(prior)),
    });
    assert.equal(starts, 0);
    assert.deepEqual(fetched, [prior.id]);
    assert.equal(result.status, "passed");
    assert.equal(result.runId, upstream.runId);
    assert.equal(result.attempt, upstream.attempt);
    assert.equal(result.sourceFormat.name, "source-format");
});

test("fetch-null-auth-wrong-corrupt0: unusable upstream evidence throws before any start", async () => {
    const current = receiptFor({ run: upstream.runId, att: upstream.attempt, image: imageDigest });
    const prior = receiptFor({ run: upstream.runId, att: upstream.attempt, image: priorImageDigest });
    const cases = [
        { name: "null", fetchReceipt: async () => null, verifyLogs: rawVerifier(logsFor(current)) },
        { name: "auth", fetchReceipt: async () => { throw Object.assign(new Error("HTTP 401"), { status: 401 }); }, verifyLogs: rawVerifier(logsFor(current)) },
        { name: "wrong", fetchReceipt: async () => ({ ...current, sha: "d".repeat(40) }), verifyLogs: rawVerifier(logsFor(current)) },
        { name: "corrupt", fetchReceipt: async () => prior, verifyLogs: rawVerifier(logsFor(prior, { stdoutText: "corrupt" })) },
    ];
    for (const item of cases) {
        let starts = 0;
        await assert.rejects(() => call({
            upstream,
            priorImageDigest,
            fetchReceipt: item.fetchReceipt,
            startRun: async () => { starts += 1; },
            verifyLogs: item.verifyLogs,
        }), undefined, item.name);
        assert.equal(starts, 0, item.name);
    }
});

test("stale1current: admitted prior image starts exactly one current run", async () => {
    const prior = receiptFor({ run: upstream.runId, att: upstream.attempt, image: priorImageDigest });
    const current = receiptFor({ run: runId, att: attempt, image: imageDigest });
    const starts = [];
    const result = await call({
        upstream,
        priorImageDigest,
        fetchReceipt: async (id) => (id === prior.id ? prior : current),
        startRun: async (request) => { starts.push(request); },
        verifyLogs: rawVerifier(new Map([...logsFor(prior), ...logsFor(current)])),
    });
    assert.equal(starts.length, 1);
    assert.equal(starts[0].runId, runId);
    assert.equal(starts[0].attempt, attempt);
    assert.equal(starts[0].sha, sha);
    assert.equal(result.runId, runId);
    assert.equal(result.attempt, attempt);
    assert.equal(result.sourceFormat.name, "source-format");
});

test("stale-unadmitted: an upstream image without an admitted prior digest never refreshes", async () => {
    const prior = receiptFor({ run: upstream.runId, att: upstream.attempt, image: priorImageDigest });
    let starts = 0;
    await assert.rejects(() => call({
        upstream,
        priorImageDigest: undefined,
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
        verifyLogs: rawVerifier(logsFor(prior)),
    }), /prior evidence is not admitted/);
    assert.equal(starts, 0);
});

test("freshfailure-noinference: corrupt fresh receipt blocks with one start and no inference", async () => {
    const fresh = receiptFor({ run: runId, att: attempt, image: imageDigest, stdoutText: "declared" });
    const starts = [];
    let fetches = 0;
    await assert.rejects(() => call({
        fetchReceipt: async () => { fetches += 1; return fresh; },
        startRun: async (request) => { starts.push(request); },
        verifyLogs: rawVerifier(logsFor(fresh, { stdoutText: "different" })),
    }), /hash mismatch/);
    assert.equal(starts.length, 1);
    assert.equal(starts[0].runId, runId);
    assert.equal(fetches, 1);
});
test("stale formatting cannot refresh its own prior canonical run", async () => {
    const prior = receiptFor({ image: priorImageDigest });
    let starts = 0;
    await assert.rejects(() => call({
        upstream: { runId, attempt }, priorImageDigest,
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
        verifyLogs: rawVerifier(logsFor(prior)),
    }));
    assert.equal(starts, 0);
});

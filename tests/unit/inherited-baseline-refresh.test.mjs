import { test } from "bun:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { admitFormattingRun } from "../../scripts/ai-review-flow.mjs";
import {
    cloudCiPlanSha256,
    verifyCloudCiObjects,
    CloudCiEngineFailure,
} from "../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudChecks, expectedCloudReports } from "../../services/cloud-ci/runner/plan.mjs";

const sha = "a".repeat(40);
const branch = "main";
const ref = "refs/heads/main";
const imageDigest = `sha256:${"c".repeat(64)}`;
const runId = "900";
const attempt = "4";
const upstream = { runId: "800", attempt: "2" };
const clean = "source format clean\n";
const digest = (text) => createHash("sha256").update(text).digest("hex");
const portableNames = expectedCloudReports("rust-portable-tests");

const receiptFor = ({ run = upstream.runId, att = upstream.attempt, portable = true, exitCode = 0, receiptSha = sha, engine = false } = {}) => {
    const id = `cl-${run}-${att}-${sha}`;
    const checks = [{
        name: "source-format",
        exitCode: 0,
        stdoutKey: `logs/${id}/source-format.stdout`,
        stderrKey: `logs/${id}/source-format.stderr`,
        stdoutSha256: digest(clean),
        stderrSha256: digest(""),
        reports: [],
    }];
    if (portable)
        checks.push({
            name: "rust-portable-tests",
            exitCode,
            stdoutKey: `logs/${id}/rust-portable-tests.stdout`,
            stderrKey: `logs/${id}/rust-portable-tests.stderr`,
            stdoutSha256: digest(""),
            stderrSha256: digest(""),
            reports: portableNames.map((name) => ({ name, key: `reports/${id}/${name}`, sha256: digest(name) })),
        });
    return {
        id,
        repository: "omg-cli/omg",
        sha: receiptSha,
        ref,
        runId: run,
        attempt: att,
        conclusion: "failure",
        ...(engine ? { failureCategory: "workflow-internal-error" } : {}),
        requiredChecks: expectedCloudChecks(ref),
        checks,
        imageDigest,
        planSha256: cloudCiPlanSha256,
    };
};

const verifyLogs = async (_id, format) => {
    assert.equal(format.name, "source-format");
    await verifyCloudCiObjects({ checks: [format] }, async (key) =>
        new Response(key.endsWith(".stderr") ? "" : clean));
};

const call = (overrides) => admitFormattingRun({
    sha,
    branch,
    upstream,
    runId,
    attempt,
    imageDigest,
    priorImageDigest: undefined,
    requirePortableEvidence: true,
    fetchReceipt: async () => { throw new Error("unexpected receipt read"); },
    startRun: async () => {},
    verifyLogs,
    ...overrides,
});

test("inherited engine baseline missing portable evidence refreshes on the current attempt", async () => {
    const prior = receiptFor({ portable: false, engine: true });
    const fresh = receiptFor({ run: runId, att: attempt, portable: true });
    const starts = [];
    const fetched = [];
    const result = await call({
        fetchReceipt: async (id) => { fetched.push(id); return id === prior.id ? prior : fresh; },
        startRun: async (request) => { starts.push(request); },
    });
    assert.equal(starts.length, 1);
    assert.equal(starts[0].runId, runId);
    assert.equal(starts[0].attempt, attempt);
    assert.equal(starts[0].sha, sha);
    assert.deepEqual(fetched, [prior.id, fresh.id]);
    assert.equal(result.runId, runId);
    assert.equal(result.attempt, attempt);
});

test("refresh starts a distinct current identity and leaves the inherited receipt byte identical", async () => {
    const prior = receiptFor({ portable: false, engine: true });
    const snapshot = JSON.stringify(prior);
    const fresh = receiptFor({ run: runId, att: attempt, portable: true });
    const starts = [];
    await call({
        fetchReceipt: async (id) => (id === prior.id ? prior : fresh),
        startRun: async (request) => { starts.push(request); },
    });
    assert.equal(starts.length, 1);
    assert.equal(`cl-${starts[0].runId}-${starts[0].attempt}-${sha}`, `cl-${runId}-${attempt}-${sha}`);
    assert.notEqual(`cl-${starts[0].runId}-${starts[0].attempt}-${sha}`, prior.id);
    assert.equal(JSON.stringify(prior), snapshot);
});

test("admitted portable evidence on the inherited baseline is reused with zero starts", async () => {
    const prior = receiptFor({ portable: true });
    let starts = 0;
    const result = await call({
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
    });
    assert.equal(starts, 0);
    assert.equal(result.runId, upstream.runId);
    assert.equal(result.attempt, upstream.attempt);
});

test("spoofed engine text and mismatched identity never refresh", async () => {
    const wrongKey = receiptFor({ portable: true });
    wrongKey.checks[1].reports[0].key += ".other";
    const cases = [
        receiptFor({ portable: true, exitCode: 1 }),
        receiptFor({ portable: false, receiptSha: "d".repeat(40) }),
        wrongKey,
    ];
    for (const prior of cases) {
        let starts = 0;
        await assert.rejects(() => call({
            fetchReceipt: async () => prior,
            startRun: async () => { starts += 1; },
        }));
        assert.equal(starts, 0);
    }
});

test("an ordinary source-format failure is not refreshed", async () => {
    const prior = receiptFor({ portable: false });
    prior.checks[0].exitCode = 1;
    let starts = 0;
    await assert.rejects(() => call({
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
    }));
    assert.equal(starts, 0);
});

test("a refresh cannot reuse the current immutable run identity", async () => {
    const prior = receiptFor({ run: runId, att: attempt, portable: false, engine: true });
    let starts = 0;
    await assert.rejects(() => call({
        upstream: { runId, attempt },
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
    }), /cannot reuse its prior run identity/);
    assert.equal(starts, 0);
});

test("format-only review still reuses a same-image baseline without portable evidence", async () => {
    const prior = receiptFor({ portable: false });
    let starts = 0;
    const result = await call({
        requirePortableEvidence: false,
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
    });
    assert.equal(starts, 0);
    assert.equal(result.runId, upstream.runId);
    assert.equal(result.attempt, upstream.attempt);
});

test("uncategorized missing portable evidence never starts a refresh", async () => {
    const prior = receiptFor({ portable: false });
    let starts = 0;
    await assert.rejects(() => call({
        fetchReceipt: async () => prior,
        startRun: async () => { starts += 1; },
    }), (error) => error instanceof Error && !(error instanceof CloudCiEngineFailure));
    assert.equal(starts, 0);
});

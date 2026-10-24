import { test } from "bun:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { admitPortableAuditRow, verifiedPortableReport } from "../../scripts/ai-review-flow.mjs";
import { cloudCiPlanSha256 } from "../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudChecks } from "../../services/cloud-ci/runner/plan.mjs";

const sha = "a".repeat(40), image = "sha256:" + "b".repeat(64);
const baseline = { status: "passed", sha, ref: "refs/heads/main", runId: "100", attempt: "2" };
const id = `cl-100-2-${sha}`;
const row = { request: { sha }, task: { path: "src/doctor.rs", target: "lib", testName: "cli::doctor::tests::probe" } };
const hash = value => createHash("sha256").update(value).digest("hex");
function xml({ suite = "omg", name = row.task.testName, classname = suite, skipped = false, duplicate = false } = {}) {
    const sample = `<testcase classname="${classname}" name="${name}">${skipped ? "<skipped/>" : ""}</testcase>`;
    return `<testsuites tests="${duplicate ? 3 : 2}" skipped="${skipped ? 1 : 0}" failures="0" errors="0"><testsuite name="${suite}">${sample}${duplicate ? sample : ""}<testcase classname="${suite}" name="other::executed"/></testsuite></testsuites>`;
}
function setup(content = xml()) {
    const reports = ["rust-pgp-license-junit.xml", "rust-debian-pure-junit.xml"].map(name => ({ name, key: `reports/${id}/${name}`, sha256: hash(content) }));
    const receipt = { id, repository: "omg-cli/omg", sha, ref: "refs/heads/main", runId: "100", attempt: "2", conclusion: "success", imageDigest: image, planSha256: cloudCiPlanSha256,
        requiredChecks: expectedCloudChecks("refs/heads/main"), checks: [
            { name: "source-format", exitCode: 0, stdoutKey: `logs/${id}/source-format.stdout`, stderrKey: `logs/${id}/source-format.stderr`, stdoutSha256: "c".repeat(64), stderrSha256: "d".repeat(64), reports: [] },
            { name: "rust-portable-tests", exitCode: 0, reports },
        ] };
    const calls = [];
    const io = {
        receipt: async actualId => { calls.push(["receipt", actualId]); return receipt; },
        report: async (actualId, key) => { calls.push(["report", actualId, key]); return new Response(content); },
    };
    return { content, receipt, reports, calls, io };
}

test("real Nextest library identity is admitted from the inherited baseline using one verified report read", async () => {
    const state = setup();
    assert.deepEqual(await admitPortableAuditRow(row, baseline, state.io, image), { classname: "omg", name: row.task.testName });
    assert.deepEqual(state.calls, [["receipt", id], ["report", id, `reports/${id}/rust-pgp-license-junit.xml`]]);
});

test("integration membership uses the Cargo target classname, not the Rust module prefix", async () => {
    const state = setup(xml({ suite: "omg::cli_surface", name: "nested::probe" }));
    const integration = { request: { sha }, task: { path: "tests/cli_surface.rs", testName: "nested::probe" } };
    assert.deepEqual(await admitPortableAuditRow(integration, baseline, state.io, image), { classname: "omg::cli_surface", name: "nested::probe" });
});

test("unrelated baseline failure does not reject a successful exact portable execution", async () => {
    const state = setup(); state.receipt.conclusion = "failure";
    assert.equal((await admitPortableAuditRow(row, baseline, state.io, image)).name, row.task.testName);
});

for (const [name, mutate] of [
    ["source", state => { state.receipt.sha = "e".repeat(40); }],
    ["run", state => { state.receipt.runId = "101"; }],
    ["attempt", state => { state.receipt.attempt = "1"; }],
    ["image", state => { state.receipt.imageDigest = "sha256:" + "e".repeat(64); }],
    ["plan", state => { state.receipt.planSha256 = "e".repeat(64); }],
    ["portable exit", state => { state.receipt.checks[1].exitCode = 1; }],
    ["missing report", state => { state.receipt.checks[1].reports.pop(); }],
    ["wrong report key", state => { state.reports[0].key += ".other"; }],
    ["duplicate portable check", state => { state.receipt.checks.push(state.receipt.checks[1]); }],
]) test(`portable admission rejects ${name} before loading report bytes`, async () => {
    const state = setup(); mutate(state);
    await assert.rejects(() => admitPortableAuditRow(row, baseline, state.io, image));
    assert.equal(state.calls.some(call => call[0] === "report"), false);
});

test("stale formatting baseline is rejected before any receipt read", async () => {
    const state = setup();
    await assert.rejects(() => admitPortableAuditRow(row, { ...baseline, sha: "e".repeat(40) }, state.io, image), /baseline identity/);
    assert.deepEqual(state.calls, []);
});

for (const [label, content] of [
    ["wrong suite", xml({ suite: "omg_lib" })],
    ["wrong classname", xml({ classname: "omg_lib" })],
    ["synthetic full name", xml({ name: "probe", classname: "cli::doctor::tests" })],
    ["missing test", xml({ name: "other::test" })],
    ["skipped target with another executed case", xml({ skipped: true })],
    ["duplicate target", xml({ duplicate: true })],
]) test(`portable admission holds ${label}`, async () => {
    const state = setup(content);
    await assert.rejects(() => admitPortableAuditRow(row, baseline, state.io, image), /not executed exactly once/);
});

test("the report bytes actually parsed must match the receipt hash", async () => {
    const state = setup();
    state.io.report = async () => new Response(xml({ name: "substituted::case" }));
    await assert.rejects(() => admitPortableAuditRow(row, baseline, state.io, image), /hash mismatch/);
});

test("report hash validation uses a single remote read and retains that exact body", async () => {
    const body = xml(); let reads = 0;
    const text = await verifiedPortableReport({ key: "reports/example/report.xml", sha256: hash(body) }, async () => {
        reads++; return new Response(reads === 1 ? body : "substituted");
    });
    assert.equal(reads, 1); assert.equal(text, body);
});

test("report stream is bounded by the existing 20MB evidence retention budget", async () => {
    let cancelled = false;
    const stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(20_000_001)); }, cancel() { cancelled = true; } });
    await assert.rejects(() => verifiedPortableReport({ key: "oversize", sha256: "a".repeat(64) }, async () => new Response(stream)), /byte budget/);
    assert.equal(cancelled, true);
});

test("unavailable or invalid UTF-8 evidence cannot become portable membership", async () => {
    await assert.rejects(() => verifiedPortableReport({ key: "missing" }, async () => new Response(null, { status: 404 })), /unavailable/);
    const bytes = new Uint8Array([255]);
    await assert.rejects(() => verifiedPortableReport({ key: "bad-utf8", sha256: hash(bytes) }, async () => new Response(bytes)), /UTF-8|encoded|invalid/i);
});


test("actual terminal-error evidence route preserves a passed portable check without admitting a final receipt", async () => {
    const { runtimeServer } = await import("./fixtures/runtime-server.mjs");
    const { fetchCi } = await import("../../services/cloud-ci/src/http.ts");
    const server = runtimeServer();
    const state = setup(); state.receipt.conclusion = "failure";
    const request = { repository: "omg-cli/omg", sha, ref: "refs/heads/main", runId: "100", attempt: "2" };
    assert.equal(server.stageNativeProof(request, state.receipt), id);
    server.objects.set(state.reports[0].key, state.content);
    server.env.CI_WORKFLOW.get = async actualId => {
        assert.equal(actualId, id);
        return { status: async () => ({ status: "errored" }) };
    };
    const read = route => fetchCi(new Request(new URL(route, server.endpoint), {
        headers: { Authorization: `Bearer ${server.token}` },
    }), server.env);
    assert.equal((await read(`/runs/${id}/receipt`)).status, 422);
    const io = {
        receipt: async actualId => {
            const response = await read(`/runs/${actualId}/evidence`);
            assert.equal(response.status, 200);
            return response.json();
        },
        report: (actualId, key) => read(`/runs/${actualId}/reports/${key.split("/")[2]}`),
    };
    assert.deepEqual(await admitPortableAuditRow(row, baseline, io, image), { classname: "omg", name: row.task.testName });
    assert.equal((await read(`/runs/${id}/receipt`)).status, 422);
});

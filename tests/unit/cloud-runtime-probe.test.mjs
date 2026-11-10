import assert from "node:assert/strict";
import { test } from "bun:test";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { admitHold, admitCoder, helperOutput, probeIdentity } from "../../scripts/cloud-runtime-probe.mjs";
import { planIdentity } from "../../services/cloud-ci/runner/plan.mjs";

const sha = "a".repeat(40);
const bundle = "b".repeat(64);
const image = `sha256:${"c".repeat(64)}`;
const verifier = "d".repeat(40);
const model = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";
const env = { GITHUB_REPOSITORY: "omg-cli/omg", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main",
  PROBE_TASK: "runtime-probe", CONTROLLER_SHA: sha, EXPECTED_CONTROLLER: sha, GITHUB_SHA: sha,
  GITHUB_WORKFLOW_SHA: sha, GITHUB_RUN_ID: "42", GITHUB_RUN_ATTEMPT: "1", ROLLOUT_LOCK_RUN_ID: "41" };
const identity = probeIdentity(env, sha);

test("operator identity rejects untrusted dispatch and every controller join mismatch", () => {
  for (const change of [{ GITHUB_REPOSITORY: "fork/omg" }, { GITHUB_EVENT_NAME: "workflow_run" },
    { GITHUB_REF: "refs/tags/main" }, { PROBE_TASK: "portable" }, { EXPECTED_CONTROLLER: "e".repeat(40) },
    { GITHUB_SHA: "e".repeat(40) }, { GITHUB_WORKFLOW_SHA: "e".repeat(40) }, { ROLLOUT_LOCK_RUN_ID: "42" }]) {
    assert.throws(() => probeIdentity({ ...env, ...change }, sha));
  }
  assert.throws(() => probeIdentity(env, "e".repeat(40)));
  assert.equal(identity.controller, sha);
});

test("operator workflow reuses one private writer and cannot enter portable or publisher steps", async () => {
  const workflow = Bun.YAML.parse(await readFile(new URL("../../.github/workflows/cloud-ci.yml", import.meta.url), "utf8"));
  const job = workflow.jobs.portable;
  const allowed = new Function("github", "inputs", `return (${job.if.replaceAll("==", "===")});`);
  const github = { repository: "omg-cli/omg", event_name: "workflow_dispatch", ref: "refs/heads/main", ref_name: "main" };
  assert.equal(allowed(github, { task: "runtime-probe" }), true);
  for (const change of [{ repository: "fork/omg" }, { event_name: "workflow_run" }, { ref: "refs/tags/main" }, { ref: "refs/heads/feature" }])
    assert.equal(allowed({ ...github, ...change }, { task: "runtime-probe" }), false);
  const group = new Function("github", "inputs", `return (${workflow.concurrency.group.slice(3, -2)});`);
  for (const [task, expected] of [["runtime-probe", "omg-ci-operator-probe"], ["portable", "omg-ai-review-global"],
    ["rollout-lock", "omg-ai-review-global"], ["dependencies", "omg-cloud-dependencies"]])
    assert.equal(group(github, { task }), expected);
  assert.equal(group({ ...github, event_name: "workflow_run" }, {}), "omg-cloud-dependencies");
  assert.deepEqual(job.permissions, { contents: "read", actions: "read" });
  const writers = job.steps.filter(step => step.name === "Create private OMG service configuration");
  assert.equal(writers.length, 1);
  assert.deepEqual(Object.keys(writers[0].env).filter(key => key.endsWith("TOKEN")),
    ["OMG_CI_API_TOKEN", "OMG_CI_INSPECTOR_TOKEN", "OMG_CI_CODER_TOKEN"]);
  const names = job.steps.map(step => step.name);
  assert.ok(names.indexOf("Install immutable controller dependencies") < names.indexOf(writers[0].name));
  assert.ok(names.indexOf("Recheck operator hold before private credentials") < names.indexOf(writers[0].name));
  for (const name of ["Fetch candidate Git objects without checking out candidate files", "Mirror exact candidate Git objects",
    "Run isolated Cloudflare checks and admit exact-run receipt"])
    assert.equal(job.steps.find(step => step.name === name).if, "inputs.task == 'portable'");
  assert.equal(job.steps.find(step => step.name === "Report admitted Cloudflare result").if, "always() && inputs.task == 'portable'");
  assert.equal(job.steps.find(step => step.name === "Remove private OMG service configuration").if, "always()");
  assert.equal(JSON.stringify(job).includes("CLOUDFLARE_API_TOKEN"), false);
  assert.equal(JSON.stringify(job).includes("APP_PRIVATE_KEY"), false);
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
});

function activeHold() {
  const now = Date.parse("2026-11-09T23:30:00Z");
  return { now, run: { id: 41, repository: { full_name: "omg-cli/omg" }, path: ".github/workflows/cloud-ci.yml",
    head_sha: sha, head_branch: "main", event: "workflow_dispatch", status: "in_progress", conclusion: null },
    jobs: { jobs: [{ id: 12, name: "Hold cloud admission groups for operator rollout", status: "in_progress", conclusion: null,
      steps: [{ name: "Hold both admission groups for at most 30 minutes", status: "in_progress", conclusion: null,
        started_at: "2026-11-09T23:29:00Z" }] }] },
    groups: {
      global: { group_name: "omg-ai-review-global", group_members: [{ run_id: 41, status: "in_progress" }] },
      dependencies: { group_name: "omg-cloud-dependencies", group_members: [{ run_id: 41, job_id: 12, status: "in_progress" }] },
    } };
}

test("configured concurrency groups and a queued or expired step cannot impersonate a live hold", () => {
  const original = activeHold();
  assert.equal(admitHold(original.run, original.jobs, original.groups, identity, original.now, 1_080_000).jobId, 12);
  for (const corrupt of [
    value => { value.run.head_sha = "e".repeat(40); },
    value => { value.jobs.jobs[0].steps[0].status = "queued"; },
    value => { value.groups.global.group_members = []; },
    value => { value.groups.dependencies.group_members[0].job_id = 13; },
    value => { value.groups.global.group_members[0].status = "pending"; },
    value => { value.jobs.jobs[0].steps[0].started_at = "2026-11-09T22:59:00Z"; },
  ]) {
    const value = structuredClone(original);
    corrupt(value);
    assert.throws(() => admitHold(value.run, value.jobs, value.groups, identity, value.now, 1_080_000));
  }
});

test("coder policy admission binds explicit safe scalars to protected runtime pins", () => {
  const receipt = { id: `cl-42-1-${sha}-s-${"e".repeat(64)}`, sha, freshAccepted: true, readOnly: true,
    runtime: { model, reasoningEffort: "low", imageDigest: image, verifierRevision: verifier, bundleSha256: bundle },
    delivery: { sessionId: "ses_fixture", bundleSha256: bundle }, calls: 1, reads: [{ path: "src/lib.rs", start: 1, end: 1 }],
    inference: "real-worker", productAcceptance: false };
  assert.equal(admitCoder(receipt, identity, { imageDigest: image, verifierRevision: verifier }, { bundleSha256: bundle }).freshAccepted, true);
  for (const corrupt of [value => { value.freshAccepted = false; }, value => { value.runtime.bundleSha256 = "f".repeat(64); },
    value => { value.runtime.imageDigest = `sha256:${"f".repeat(64)}`; }, value => { value.reads[0].path = "../private.token"; }]) {
    const value = structuredClone(receipt);
    corrupt(value);
    assert.throws(() => admitCoder(value, identity, { imageDigest: image, verifierRevision: verifier }, { bundleSha256: bundle }));
  }
});

test("helper stdout requires strict JSON and explicit known progress records", () => {
  const progress = { id: `cl-42-1-${sha}-s-${"e".repeat(64)}`, sha, status: "starting", productAcceptance: false };
  assert.equal(helperOutput(JSON.stringify(progress), identity).length, 1);
  for (const output of ["not JSON", JSON.stringify({ ...progress, privateField: "do-not-print" }),
    JSON.stringify({ ...progress, status: "unknown" }), JSON.stringify(progress) + "\nstartup noise"])
    assert.throws(() => helperOutput(output, identity));
  const otherOperation = { id: `cl-42-1-${sha}-s-${"f".repeat(64)}`, sha, productAcceptance: false,
    inference: "real-worker", freshAccepted: true, readOnly: true, runtime: {}, delivery: {}, calls: 1, reads: [] };
  assert.throws(() => helperOutput(JSON.stringify(progress) + "\n" + JSON.stringify(otherOperation), identity));
});

const repo = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8", windowsHide: true }).trim();
const sourceSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", windowsHide: true }).trim();
const helper = fileURLToPath(new URL("../../services/ci-coder/test/harness-runtime.mjs", import.meta.url));
const { operationIdentity } = await import(pathToFileURL(path.join(repo, "services/ci-coder/src/request.ts")).href);

async function helperCase(scenario = "valid", mutationField) {
  const root = await mkdtemp(path.join(tmpdir(), "omg-operator-probe-"));
  const secret = "operator-fixture-secret-never-log".repeat(2);
  const requests = [];
  let getCalls = 0;
  let submitted;
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    assert.equal(request.headers.get("authorization"), `Bearer ${secret}`);
    const url = new URL(request.url);
    if (url.pathname === "/operations" && request.method === "POST") {
      submitted = await request.json();
      requests.push(submitted);
      return Response.json({ id: operationIdentity(submitted), accepted: scenario !== "cached" }, { status: scenario === "wrong-http" ? 200 : 202 });
    }
    if (submitted && url.pathname === `/operations/${operationIdentity(submitted)}` && request.method === "GET") {
      getCalls++;
      const actualBundle = scenario === "wrong-bundle" ? "f".repeat(64) : bundle;
      const result = { calls: 1, reads: [{ path: "src/lib.rs", start: 1, end: 1, privateField: secret }], verifiedDigests: [],
        sessionId: "ses_fixture", skillBundleSha256: actualBundle };
      if (mutationField === "verifiedDigests") result.verifiedDigests.push("e".repeat(64));
      else if (mutationField) result[mutationField] = scenario === "null-mutation" ? null : { privateField: secret };
      return Response.json({ id: operationIdentity(submitted), sha: sourceSha, status: "done", result,
        runtime: { model, reasoningEffort: "low", bundleSha256: actualBundle, imageDigest: image, verifierRevision: verifier, privateField: secret },
        skillsDelivery: { bundleSha256: actualBundle, sessionId: "ses_fixture", privateField: secret } });
    }
    return new Response("fixture route rejected", { status: 404 });
  } });
  try {
    const configRoot = path.join(root, "ci");
    await mkdir(configRoot, { mode: 0o700 });
    const tokenFile = path.join(configRoot, "omg-ci-coder.token");
    await writeFile(tokenFile, secret, { mode: 0o600 });
    await writeFile(path.join(configRoot, "omg-ci-coder.json"), JSON.stringify({
      endpoint: "https://omg-ci-coder.latham.workers.dev/", tokenFile, bundleSha256: bundle,
    }), { mode: 0o600 });
    const preload = path.join(root, "preload.mjs");
    const requestPath = pathToFileURL(path.join(repo, "services/ci-coder/src/request.ts")).href;
    const runtimePath = pathToFileURL(path.join(repo, "services/ci-coder/src/runtime.ts")).href;
    await writeFile(preload, `import {plugin} from "bun";
import {fileURLToPath} from "node:url";
plugin({name:"isolated helper IO",setup(build){
build.onResolve({filter:/^os$/,namespace:"node"},()=>({path:"os",namespace:"fixture-os"}));
build.onLoad({filter:/.*/,namespace:"fixture-os"},()=>({contents:${JSON.stringify(`export const homedir=()=>${JSON.stringify(root)};export default {homedir};`)},loader:"js"}));
build.onResolve({filter:/^\.\.\\/src\\/(request|runtime)\\.ts$/},args=>{if(args.importer!==${JSON.stringify(helper)})return;return{path:fileURLToPath(args.path.endsWith("/request.ts")?${JSON.stringify(requestPath)}:${JSON.stringify(runtimePath)})};});}});
const original=globalThis.fetch;
globalThis.fetch=(input,options)=>{const url=new URL(input);if(url.origin!=="https://omg-ci-coder.latham.workers.dev")throw new Error("Unexpected probe origin");return original(${JSON.stringify(server.url.origin)}+url.pathname,options);};
`);
    const child = Bun.spawn([process.execPath, "--preload", preload, helper, sourceSha, "main", "42", "1"], {
      cwd: repo, stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 20000, killSignal: "SIGKILL", windowsHide: true,
    });
    const [exit, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
    assert.equal(stdout.includes(secret), false, "Probe stdout leaked a fixture credential");
    assert.equal(stderr.includes(secret), false, "Probe stderr leaked a fixture credential");
    return { exit, stdout, stderr, requests, getCalls };
  } finally {
    server.stop(true);
    assert.equal(path.dirname(path.resolve(root)), path.resolve(tmpdir()));
    assert.ok(path.basename(root).startsWith("omg-operator-probe-"));
    await rm(root, { recursive: true, force: true });
  }
}

test("actual helper child sends enforced read-only request and outputs only safe metadata", async () => {
  const result = await helperCase();
  assert.equal(result.exit, 0, "Helper did not complete the HTTP fixture");
  assert.equal(result.requests.length, 1);
  assert.ok(result.requests[0].diagnosisTask);
  assert.deepEqual(result.requests[0].source.changedPaths, []);
  assert.deepEqual(result.requests[0].source.auditPaths, ["src/lib.rs"]);
  assert.equal(result.requests[0].testAuditTask, undefined);
  const output = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  assert.equal(output.freshAccepted, true);
  assert.equal(output.readOnly, true);
  assert.deepEqual(output.delivery, { sessionId: "ses_fixture", bundleSha256: bundle });
  assert.deepEqual(output.reads, [{ path: "src/lib.rs", start: 1, end: 1 }]);
  assert.equal(JSON.stringify(output).includes("privateField"), false);
}, 30000);

for (const scenario of ["cached", "wrong-http", "wrong-bundle"])
  test(`actual helper rejects ${scenario}`, async () => {
    const result = await helperCase(scenario);
    assert.equal(result.requests.length, 1, "Rejection must reach the actual HTTP admission boundary");
    assert.equal(result.exit, 1, `Helper admitted ${scenario}`);
    if (scenario !== "wrong-bundle") assert.equal(result.getCalls, 0);
    else assert.equal(result.getCalls, 1);
  }, 30000);

for (const field of ["proposal", "dependencyPlan", "testAudit", "verificationJob", "verificationHandoff", "verification", "verifiedDigests"])
  test(`actual helper rejects ${field}${field === "proposal" ? ":null" : ""}`, async () => {
    const result = await helperCase(field === "proposal" ? "null-mutation" : "valid", field);
    assert.equal(result.requests.length, 1);
    assert.equal(result.getCalls, 1, "Mutation rejection must inspect an actual terminal response");
    assert.equal(result.exit, 1, `Helper admitted ${field}`);
  }, 30000);

async function operatorCase(scenario = "valid", mode = "run") {
  const root = await mkdtemp(path.join(tmpdir(), "omg-operator-probe-"));
  const ghSecret = "github-fixture-secret-never-log".repeat(2);
  const secrets = Object.fromEntries(["omg-cloud-ci", "omg-ci-coder", "omg-ci-inspector"].map(name =>
    [name, `${name}-fixture-secret-never-log`.repeat(2)]));
  const trace = [];
  let submitted;
  let holdReads = 0;
  const health = { ok: true, engine: "@cloudflare/ci@0.2.0", planSha256: createHash("sha256").update(planIdentity).digest("hex") };
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    const url = new URL(request.url);
    const [, host, ...parts] = url.pathname.split("/");
    const route = `/${parts.join("/")}`;
    trace.push({ host, route, method: request.method });
    if (host === "api.github.com") {
      assert.equal(request.headers.get("authorization"), `Bearer ${ghSecret}`);
      const held = activeHold();
      held.run.head_sha = sourceSha;
      const age = scenario === "short-lease" ? 660_000 : scenario === "short-preflight" ? 480_000 : 60_000;
      held.jobs.jobs[0].steps[0].started_at = new Date(Date.now() - age).toISOString();
      if (route.endsWith("/runs/41")) {
        holdReads++;
        if (scenario === "released-hold" && holdReads >= 3) { held.run.status = "completed"; held.run.conclusion = "cancelled"; }
        return Response.json(held.run);
      }
      if (route.endsWith("/runs/41/jobs")) return Response.json(held.jobs);
      if (route.endsWith("/concurrency_groups/omg-ai-review-global")) {
        if (scenario === "inactive-hold") held.groups.global.group_members = [];
        return Response.json(held.groups.global);
      }
      if (route.endsWith("/concurrency_groups/omg-cloud-dependencies")) return Response.json(held.groups.dependencies);
    }
    const service = host.replace(".latham.workers.dev", "");
    assert.equal(request.headers.get("authorization"), `Bearer ${secrets[service]}`);
    if (service === "omg-cloud-ci" && route === "/health") {
      if (scenario === "redirect") return new Response(null, { status: 302, headers: { location: "/omg-cloud-ci.latham.workers.dev/redirected-health" } });
      if (scenario === "bad-health") return Response.json({ ...health, planSha256: "f".repeat(64) });
      if (scenario === "malformed") return new Response(secrets[service]);
      if (scenario === "oversized") return Response.json({ ...health, padding: "x".repeat(8192) });
      return Response.json(health);
    }
    if (service === "omg-cloud-ci" && route === "/redirected-health") return Response.json(health);
    if (service === "omg-ci-coder" && route === "/operations" && request.method === "POST") {
      submitted = await request.json();
      assert.ok(submitted.diagnosisTask);
      assert.deepEqual(submitted.source.changedPaths, []);
      return Response.json({ id: operationIdentity(submitted), accepted: true }, { status: 202 });
    }
    if (service === "omg-ci-coder" && submitted && route === `/operations/${operationIdentity(submitted)}`) {
      return Response.json({ id: operationIdentity(submitted), sha: sourceSha, status: "done",
        result: { calls: 1, reads: [{ path: "src/lib.rs", start: 1, end: 1 }], verifiedDigests: [],
          sessionId: "ses_fixture", skillBundleSha256: bundle },
        runtime: { model, reasoningEffort: "low", imageDigest: image, verifierRevision: verifier, bundleSha256: bundle },
        skillsDelivery: { bundleSha256: bundle, sessionId: "ses_fixture" } });
    }
    if (service === "omg-ci-inspector" && route === "/inspect" && request.method === "POST") {
      const snapshot = await request.json();
      assert.equal(snapshot.sha, sourceSha);
      assert.deepEqual(snapshot.jobs, []);
      return Response.json({ repository: "omg-cli/omg", runId: 42, branch: "main", sha: sourceSha,
        model: scenario === "wrong-inspector" ? "wrong-model" : model, summary: secrets[service],
        codeExecutions: 1, snapshotToolCalls: 1 });
    }
    return new Response("fixture route rejected", { status: 404 });
  } });
  try {
    const configRoot = path.join(root, "ci");
    await mkdir(configRoot, { mode: 0o700 });
    if (mode !== "preflight") for (const name of Object.keys(secrets)) {
      const tokenFile = path.join(configRoot, `${name}.token`);
      await writeFile(tokenFile, secrets[name], { mode: 0o600 });
      await writeFile(path.join(configRoot, `${name}.json`), JSON.stringify({ endpoint: `https://${name}.latham.workers.dev/`, tokenFile,
        ...(name === "omg-cloud-ci" ? { imageDigest: image, verifierRevision: verifier } : {}),
        ...(name === "omg-ci-coder" ? { bundleSha256: bundle } : {}) }), { mode: 0o600 });
    }
    const preload = path.join(root, "preload.mjs");
    await writeFile(preload, `import {plugin} from "bun";
import {fileURLToPath} from "node:url";
plugin({name:"isolated operator IO",setup(build){
build.onResolve({filter:/^os$/,namespace:"node"},()=>({path:"os",namespace:"fixture-os"}));
build.onLoad({filter:/.*/,namespace:"fixture-os"},()=>({contents:${JSON.stringify(`export const homedir=()=>${JSON.stringify(root)};export default {homedir};`)},loader:"js"}));
}});
const originalFetch=globalThis.fetch;
globalThis.fetch=(input,options)=>{const url=new URL(input);if(!${JSON.stringify(["api.github.com", ...Object.keys(secrets).map(name => `${name}.latham.workers.dev`)])}.includes(url.hostname)||url.protocol!=="https:")throw new Error("Unexpected operator origin");return originalFetch(${JSON.stringify(server.url.origin)}+"/"+url.hostname+url.pathname+url.search,options);};
const originalSpawn=Bun.spawn;
Bun.spawn=(command,options)=>{if(command[1]!==${JSON.stringify(helper)}||options.env.GH_TOKEN||options.env.GITHUB_TOKEN)throw new Error("Unexpected child or GitHub credential inheritance");return originalSpawn([command[0],"--preload",fileURLToPath(import.meta.url),...command.slice(1)],options);};
`);
    const script = fileURLToPath(new URL("../../scripts/cloud-runtime-probe.mjs", import.meta.url));
    const summary = path.join(root, "summary.txt");
    const child = Bun.spawn([process.execPath, "--preload", preload, script, mode], {
      cwd: repo, env: { ...process.env, ...env, CONTROLLER_SHA: sourceSha, EXPECTED_CONTROLLER: sourceSha,
        GITHUB_SHA: sourceSha, GITHUB_WORKFLOW_SHA: sourceSha, GH_TOKEN: ghSecret, GITHUB_TOKEN: ghSecret,
        GITHUB_STEP_SUMMARY: summary }, stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 25000, killSignal: "SIGKILL", windowsHide: true,
    });
    const [exit, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
    const summaryText = await Bun.file(summary).exists() ? await readFile(summary, "utf8") : "";
    for (const secret of [ghSecret, ...Object.values(secrets)])
      assert.equal((stdout + stderr + summaryText).includes(secret), false, "Operator output leaked a fixture credential");
    return { exit, stdout, stderr, trace, holdReads, summaryText };
  } finally {
    server.stop(true);
    assert.equal(path.dirname(path.resolve(root)), path.resolve(tmpdir()));
    assert.ok(path.basename(root).startsWith("omg-operator-probe-"));
    await rm(root, { recursive: true, force: true });
  }
}

test("operator command completes the real child and HTTP fixture without portable execution or secret output", async () => {
  const result = await operatorCase();
  assert.equal(result.exit, 0, `Operator did not complete the HTTP fixture: ${result.stderr}`);
  assert.equal(result.holdReads, 4);
  assert.equal(result.trace.filter(call => call.route === "/operations" && call.method === "POST").length, 1);
  assert.equal(result.trace.filter(call => call.route === "/inspect").length, 1);
  assert.equal(result.trace.filter(call => call.route === "/health").length, 2);
  assert.equal(result.trace.some(call => /\/runs$|source-token|publish/.test(call.route)), false);
  const receipt = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  assert.equal(receipt.health, "admitted");
  assert.equal(receipt.coder.freshAccepted, true);
  assert.equal(receipt.inspector.snapshotToolCalls, 1);
  assert.equal(receipt.productAcceptance, false);
  assert.equal(receipt.publication, false);
  assert.equal(receipt.providerVersionAttestation, "external-before-after-receipts-required");
}, 30000);

test("operator preflight verifies the hold without reading service credentials", async () => {
  const result = await operatorCase("valid", "preflight");
  assert.equal(result.exit, 0);
  assert.equal(result.trace.length, 4);
  assert.ok(result.trace.every(call => call.host === "api.github.com"));
  const late = await operatorCase("short-preflight", "preflight");
  assert.equal(late.exit, 1);
  assert.equal(late.trace.length, 4);
  assert.ok(late.trace.every(call => call.host === "api.github.com"));
}, 30000);

for (const scenario of ["inactive-hold", "short-lease", "bad-health", "redirect", "malformed", "oversized", "released-hold", "wrong-inspector"])
  test(`operator command rejects ${scenario} at its observed HTTP boundary`, async () => {
    const result = await operatorCase(scenario);
    assert.equal(result.exit, 1);
    assert.ok(result.holdReads >= 1, "Rejection must reach the actual hold API");
    const posts = result.trace.filter(call => call.route === "/operations" && call.method === "POST");
    if (["released-hold", "wrong-inspector"].includes(scenario)) assert.equal(posts.length, 1);
    else assert.equal(posts.length, 0);
    if (!["inactive-hold", "short-lease"].includes(scenario)) assert.ok(result.trace.some(call => call.route === "/health"));
    if (scenario === "released-hold") { assert.equal(result.holdReads, 3); assert.equal(result.trace.some(call => call.route === "/inspect"), false); }
    if (scenario === "wrong-inspector") assert.equal(result.trace.filter(call => call.route === "/inspect").length, 1);
    if (scenario === "redirect") assert.equal(result.trace.some(call => call.route === "/redirected-health"), false);
    assert.equal(result.summaryText, "");
  }, 30000);

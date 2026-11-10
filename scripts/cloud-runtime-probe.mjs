import { readFile, appendFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const repository = "omg-cli/omg";
const model = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";
const hex40 = value => typeof value === "string" && /^[a-f0-9]{40}$/.test(value);
const hex64 = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const number = value => typeof value === "string" && /^[1-9][0-9]{0,19}$/.test(value) && Number.isSafeInteger(Number(value));
const check = (condition, message) => { if (!condition) throw new Error(message); };

export function probeIdentity(env, head) {
  const controller = env.CONTROLLER_SHA;
  check(env.GITHUB_REPOSITORY === repository && env.GITHUB_EVENT_NAME === "workflow_dispatch" &&
    env.GITHUB_REF === "refs/heads/main" && env.PROBE_TASK === "runtime-probe", "Probe requires the dedicated main dispatch");
  check(hex40(controller) && [env.EXPECTED_CONTROLLER, env.GITHUB_SHA, env.GITHUB_WORKFLOW_SHA, head]
    .every(value => value === controller), "Probe controller identity differs");
  check(number(env.ROLLOUT_LOCK_RUN_ID) && number(env.GITHUB_RUN_ID) &&
    /^[1-9][0-9]{0,5}$/.test(env.GITHUB_RUN_ATTEMPT ?? "") &&
    env.ROLLOUT_LOCK_RUN_ID !== env.GITHUB_RUN_ID, "Invalid probe or hold identity");
  return { controller, runId: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT, lockRun: env.ROLLOUT_LOCK_RUN_ID };
}

export function admitHold(run, jobs, groups, identity, now, minimumRemainingMs) {
  check(String(run?.id) === identity.lockRun && run.repository?.full_name === repository &&
    run.path === ".github/workflows/cloud-ci.yml" && run.head_sha === identity.controller &&
    run.head_branch === "main" && run.event === "workflow_dispatch" &&
    run.status === "in_progress" && run.conclusion === null, "Rollout hold run is not active for this controller");
  const selected = jobs?.jobs?.filter(job => job.name === "Hold cloud admission groups for operator rollout");
  check(selected?.length === 1, "Rollout hold job is missing or ambiguous");
  const job = selected[0];
  check(Number.isSafeInteger(job.id) && job.id > 0 && job.status === "in_progress" && job.conclusion === null,
    "Rollout hold job is not active");
  const steps = job.steps?.filter(step => step.name === "Hold both admission groups for at most 30 minutes");
  check(steps?.length === 1 && steps[0].status === "in_progress" && steps[0].conclusion === null,
    "Rollout hold step is not running");
  const started = Date.parse(steps[0].started_at);
  const expires = started + 1_800_000;
  check(Number.isFinite(started) && started <= now && expires - now >= minimumRemainingMs,
    "Rollout hold lease is insufficient");
  for (const [key, name] of [["global", "omg-ai-review-global"], ["dependencies", "omg-cloud-dependencies"]]) {
    const group = groups?.[key];
    check(group?.group_name === name && Array.isArray(group.group_members), "Live rollout concurrency group is missing");
    const holders = group.group_members.filter(member => member.status === "in_progress");
    check(holders.length === 1 && String(holders[0].run_id) === identity.lockRun &&
      (name === "omg-cloud-dependencies" ? holders[0].job_id === job.id : holders[0].job_id === undefined),
      "Rollout concurrency group is not held by the expected run and job");
  }
  return { runId: identity.lockRun, jobId: job.id, startedAt: new Date(started).toISOString(), expiresAt: new Date(expires).toISOString() };
}

async function json(url, options, maximumBytes, timeoutMs) {
  const response = await fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
  check(response.status === 200 && response.body, "Probe HTTP request failed");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maximumBytes) { await reader.cancel(); throw new Error("Probe response exceeds its byte budget"); }
      chunks.push(chunk.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

async function hold(identity, minimumRemainingMs) {
  const token = process.env.GH_TOKEN;
  check(typeof token === "string" && /^[^\s]{20,512}$/.test(token), "Read-only GitHub authentication is required");
  const base = `https://api.github.com/repos/${repository}/actions/runs/${identity.lockRun}`;
  const options = { headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10" } };
  const [run, jobs, global, dependencies] = await Promise.all([
    json(base, options, 1_048_576, 30000),
    json(`${base}/jobs?per_page=100`, options, 1_048_576, 30000),
    json(`https://api.github.com/repos/${repository}/actions/concurrency_groups/omg-ai-review-global`, options, 1_048_576, 30000),
    json(`https://api.github.com/repos/${repository}/actions/concurrency_groups/omg-cloud-dependencies`, options, 1_048_576, 30000),
  ]);
  return admitHold(run, jobs, { global, dependencies }, identity, Date.now(), minimumRemainingMs);
}

async function service(name) {
  const root = path.join(os.homedir(), "ci");
  const config = JSON.parse(await readFile(path.join(root, `${name}.json`), "utf8"));
  check(config.endpoint === `https://${name}.latham.workers.dev/` &&
    config.tokenFile === path.join(root, `${name}.token`), "Probe service configuration differs");
  const token = (await readFile(config.tokenFile, "utf8")).trim();
  check(/^[^\s]{32,512}$/.test(token), "Invalid dedicated probe credential");
  return { config, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" } };
}

export function admitCoder(receipt, identity, ci, coder) {
  const expected = `cl-${identity.runId}-${identity.attempt}-${identity.controller}-s-`;
  check(typeof receipt?.id === "string" && receipt.id.startsWith(expected) && hex64(receipt.id.slice(expected.length)) &&
    receipt.sha === identity.controller && receipt.freshAccepted === true && receipt.readOnly === true &&
    receipt.inference === "real-worker" && receipt.productAcceptance === false, "Coder probe identity or fresh admission differs");
  const runtime = receipt.runtime;
  check(runtime?.model === model && runtime.reasoningEffort === "low" &&
    runtime.imageDigest === ci.imageDigest && runtime.verifierRevision === ci.verifierRevision &&
    runtime.bundleSha256 === coder.bundleSha256 && hex64(runtime.bundleSha256), "Coder probe runtime policy differs");
  check(receipt.delivery?.bundleSha256 === coder.bundleSha256 &&
    typeof receipt.delivery.sessionId === "string" && /^ses_[A-Za-z0-9_-]{1,200}$/.test(receipt.delivery.sessionId),
    "Coder probe skill delivery differs");
  check(Number.isInteger(receipt.calls) && receipt.calls > 0 && receipt.calls <= 96 &&
    Array.isArray(receipt.reads) && receipt.reads.length > 0 && receipt.reads.length <= 96, "Coder probe has no bounded source reads");
  const reads = receipt.reads.map(read => {
    check(read.path === "src/lib.rs" && Number.isSafeInteger(read.start) && read.start > 0 &&
      Number.isSafeInteger(read.end) && read.end >= read.start && read.end - read.start < 80, "Coder probe read metadata is invalid");
    return { path: "src/lib.rs", start: read.start, end: read.end };
  });
  return { id: receipt.id, sha: identity.controller, freshAccepted: true, readOnly: true,
    runtime: { model, reasoningEffort: "low", imageDigest: ci.imageDigest, verifierRevision: ci.verifierRevision, bundleSha256: coder.bundleSha256 },
    delivery: { sessionId: receipt.delivery.sessionId, bundleSha256: coder.bundleSha256 }, calls: receipt.calls, reads };
}

export function helperOutput(stdout, identity) {
  check(Buffer.byteLength(stdout, "utf8") <= 65536, "Coder probe output exceeds its budget");
  const lines = stdout.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  const prefix = `cl-${identity.runId}-${identity.attempt}-${identity.controller}-s-`;
  for (const [index, line] of lines.entries()) {
    check(line && typeof line === "object" && !Array.isArray(line) && typeof line.id === "string" &&
      line.id.startsWith(prefix) && hex64(line.id.slice(prefix.length)) && line.id === lines[0].id && line.sha === identity.controller &&
      line.productAcceptance === false, "Coder probe output identity differs");
    if (line.inference === undefined) {
      check(Object.keys(line).sort().join(" ") === "id productAcceptance sha status" &&
        ["starting", "queued", "running", "done", "unanswered"].includes(line.status) &&
        (index !== 0 || line.status === "starting"), "Unknown coder probe progress output");
    } else {
      check(Object.keys(line).sort().join(" ") === "calls delivery freshAccepted id inference productAcceptance readOnly reads runtime sha" &&
        index === lines.length - 1 && index > 0, "Unknown coder probe completion output");
    }
  }
  return lines;
}

async function main() {
  check(process.argv.length === 3 && ["preflight", "run"].includes(process.argv[2]), "Use cloud-runtime-probe.mjs preflight|run");
  const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", windowsHide: true }).trim();
  const identity = probeIdentity(process.env, head);
  if (process.argv[2] === "preflight") {
    console.log(JSON.stringify({ controller: identity.controller, hold: await hold(identity, 1_380_000), phase: "preflight" }));
    return;
  }
  const startedAt = new Date().toISOString();
  const initialHold = await hold(identity, 1_200_000);
  const [ci, coder, inspector] = await Promise.all([service("omg-cloud-ci"), service("omg-ci-coder"), service("omg-ci-inspector")]);
  check(/^sha256:[a-f0-9]{64}$/.test(ci.config.imageDigest ?? "") && hex40(ci.config.verifierRevision) &&
    hex64(coder.config.bundleSha256), "Probe expected runtime policy is malformed");
  const { admitCloudCiRuntime } = await import("./cloud-ci-evidence.mjs");
  admitCloudCiRuntime(await json(`${ci.config.endpoint}health`, { headers: ci.headers }, 8192, 30000));
  await hold(identity, 1_200_000);
  const childEnv = { ...process.env };
  for (const key of Object.keys(childEnv))
    if (["GH_TOKEN", "GITHUB_TOKEN"].includes(key) || /^OMG_CI_.*TOKEN$/.test(key)) delete childEnv[key];
  const helper = fileURLToPath(new URL("../services/ci-coder/test/harness-runtime.mjs", import.meta.url));
  const child = Bun.spawn([process.execPath, helper, identity.controller, "main", identity.runId, identity.attempt], {
    env: childEnv, stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 600000, killSignal: "SIGKILL", windowsHide: true,
  });
  const [exit, stdout] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
  const lines = helperOutput(stdout, identity);
  const recorded = lines[0];
  if (exit !== 0) {
    if (recorded) console.log(JSON.stringify({ coderOperationId: recorded.id, observation: "incomplete", keepAdmissionHeld: true }));
    throw new Error("Coder observation failed; remote termination is not established");
  }
  const completed = lines.filter(line => line.inference === "real-worker");
  check(completed.length === 1, "Coder probe completion is missing or ambiguous");
  const coding = admitCoder(completed[0], identity, ci.config, coder.config);
  await hold(identity, 420000);
  const snapshot = { repository, runId: Number(identity.runId), branch: "main", sha: identity.controller,
    prompt: "Isolated operator runtime smoke: no CI job evidence was supplied. Use listJobs and report that limitation. Do not infer passing tests or propose execution.", jobs: [] };
  const inspected = await json(`${inspector.config.endpoint}inspect`, {
    method: "POST", headers: inspector.headers, body: JSON.stringify(snapshot),
  }, 65536, 60000);
  check(inspected?.repository === repository && inspected.runId === snapshot.runId && inspected.branch === "main" &&
    inspected.sha === identity.controller && inspected.model === model && typeof inspected.summary === "string" &&
    inspected.summary.trim().length > 0 && inspected.summary.length <= 16000 &&
    Number.isInteger(inspected.codeExecutions) && inspected.codeExecutions > 0 && inspected.codeExecutions <= 4 &&
    Number.isInteger(inspected.snapshotToolCalls) && inspected.snapshotToolCalls > 0 && inspected.snapshotToolCalls <= 12,
    "Inspector probe did not execute the bounded real model and tools");
  admitCloudCiRuntime(await json(`${ci.config.endpoint}health`, { headers: ci.headers }, 8192, 30000));
  const finalHold = await hold(identity, 300000);
  const receipt = { kind: "operator-runtime-probe", controller: identity.controller, runId: identity.runId, attempt: identity.attempt,
    startedAt, completedAt: new Date().toISOString(), hold: initialHold, finalHold, health: "admitted", coder: coding,
    inspector: { model, codeExecutions: inspected.codeExecutions, snapshotToolCalls: inspected.snapshotToolCalls },
    productAcceptance: false, publication: false, providerVersionAttestation: "external-before-after-receipts-required" };
  console.log(JSON.stringify(receipt));
  if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,
    `Operator runtime probe completed for ${identity.controller}, run ${identity.runId}/${identity.attempt}. Real coder/inspector tools executed; no publication or portable-test proof. Provider version/time join remains required.\n`);
}

if (import.meta.main) main().catch(() => {
  console.error("Cloudflare runtime probe failed. Keep rollout admission held; observe any recorded remote operation before retrying or releasing admission.");
  process.exitCode = 1;
});

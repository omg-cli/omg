import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout } from "node:timers/promises";
import { createHash } from "node:crypto";
import { parseCodingRequest, operationIdentity } from "../src/request.ts";
import { CODING_MODEL } from "../src/runtime.ts";

const [sha, branch, runId, attempt] = process.argv.slice(2);

if (process.argv.length !== 6 || !/^[a-f0-9]{40}$/.test(sha ?? ""))
  throw new Error(
    "Usage: bun services/ci-coder/test/harness-runtime.mjs <sha> <main> <probe-run-id> <attempt>",
  );

const config = JSON.parse(
  await readFile(path.join(homedir(), "ci/omg-ci-coder.json"), "utf8"),
);

const endpoint = new URL(config.endpoint);

if (
  !["https://omg-ci-coder.latham.workers.dev/"].includes(
    endpoint.href,
  )
)
  throw new Error("Runtime probe requires the dedicated coding Worker");

if (!path.isAbsolute(config.tokenFile))
  throw new Error("Coder credential must use an absolute protected path");

const token = (await readFile(config.tokenFile, "utf8")).trim();

if (token.length < 32 || /\s/.test(token)) throw new Error("Invalid coder credential");

const sourcePath = "src/lib.rs";

const source = spawnSync("git", ["-c", "maintenance.auto=false", "-c", "gc.auto=0", "show", `${sha}:${sourcePath}`], {
  encoding: "buffer",
  windowsHide: true,
});

if (source.status !== 0) throw new Error("Exact source fixture is unavailable");

const content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(source.stdout);

const blobSha = createHash("sha1")
  .update(`blob ${source.stdout.length}\0`)
  .update(source.stdout)
  .digest("hex");

const request = parseCodingRequest({
  repository: "omg-cli/omg",
  sha,
  branch,
  runId,
  attempt,
  source: {
    repository: "omg-cli/omg",
    sha,
    branch,
    changedPaths: [sourcePath],
    diff: "",
    sourceFiles: [{ path: sourcePath, blobSha, content }],
    ciFailures: [
      {
        job: "Isolated runtime probe",
        step: "Read-only source fixture",
        log: "This fixture does not claim a product defect or observed product-test failure.",
      },
    ],
  },
});

const id = operationIdentity(request);

assert.match(id, /^cl-[1-9][0-9]*-[1-9][0-9]*-[a-f0-9]{40}-s-[a-f0-9]{64}$/);

async function json(route, body) {
  const response = await fetch(new URL(route, endpoint), {
    method: body ? "POST" : "GET",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(120000),
  });

  if (!response.ok) throw new Error(`Coder probe failed HTTP ${response.status}`);

  return response.json();
}

const started = await json("/operations", JSON.stringify(request));

assert.equal(started.id, id);

const deadline = Date.now() + 10 * 60 * 1000;
let previous;

for (;;) {
  if (Date.now() > deadline)
    throw new Error("Coder runtime probe exceeded its ten-minute observation budget");
  const state = await json(`/operations/${id}`);
  assert.equal(state.id, id);
  assert.equal(state.sha, sha);

  if (state.status !== previous) console.log(JSON.stringify({ id, status: state.status }));
  previous = state.status;

  if (state.status === "unanswered")
    throw new Error("Real OpenCode operation did not complete successfully");

  if (state.status === "done") {
    assert.equal(state.runtime.model, CODING_MODEL);
    assert.equal(state.runtime.reasoningEffort, "low");
    assert.equal(state.skillsDelivery.bundleSha256, state.runtime.bundleSha256);
    assert.match(state.skillsDelivery.sessionId, /^ses_/);
    assert.ok(
      state.result.calls > 0 && state.result.reads.length > 0,
      "Actual source-tool reads are required",
    );
    console.log(
      JSON.stringify({
        id,
        sha,
        model: state.runtime.model,
        reasoningEffort: state.runtime.reasoningEffort,
        skillDelivery: state.skillsDelivery,
        calls: state.result.calls,
        reads: state.result.reads,
        inference: "real-worker",
        productAcceptance: false,
      }),
    );
    break;
  }

  await setTimeout(3000);
}

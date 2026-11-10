import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { setTimeout } from "node:timers/promises";
import { createHash } from "node:crypto";
import { parseCodingRequest, operationIdentity } from "../src/request.ts";
import { CODING_MODEL } from "../src/runtime.ts";

const check = (condition, message) => { if (!condition) throw new Error(message); };

async function main() {
  const [sha, branch, runId, attempt] = process.argv.slice(2);

  if (process.argv.length !== 6 || !/^[a-f0-9]{40}$/.test(sha ?? ""))
    throw new Error("Exact runtime probe identity is required");

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

  if (!/^[^\s]{32,512}$/.test(token) || !/^[a-f0-9]{64}$/.test(config.bundleSha256 ?? ""))
    throw new Error("Invalid protected coder policy");

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
    diagnosisTask: { question: "Isolated read-only runtime smoke: use read_source to read src/lib.rs and report only what was observed. No product defect or passing test is claimed. Never propose, verify or export a repair." },
    source: {
      repository: "omg-cli/omg",
      sha,
      branch,
      changedPaths: [],
      auditPaths: [sourcePath],
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

  check(/^cl-[1-9][0-9]*-[1-9][0-9]*-[a-f0-9]{40}-s-[a-f0-9]{64}$/.test(id), "Invalid probe operation identity");

  const deadline = Date.now() + 10 * 60 * 1000;

  async function json(route, body) {
    const response = await fetch(new URL(route, endpoint), {
      method: body ? "POST" : "GET",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(Math.max(1, Math.min(120000, deadline - Date.now()))),
    });

    check(response.status === (body ? 202 : 200) && response.body, "Coder probe HTTP request failed");
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > 2 * 1024 * 1024) { await reader.cancel(); throw new Error("Coder probe response exceeds its budget"); }
        chunks.push(chunk.value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  }

  console.log(JSON.stringify({ id, sha, status: "starting", productAcceptance: false }));
  const started = await json("/operations", JSON.stringify(request));

  check(started.id === id && started.accepted === true && started.conflict === undefined, "Coder probe was not freshly admitted");
  let previous;

  for (;;) {
    if (Date.now() > deadline)
      throw new Error("Coder runtime probe exceeded its ten-minute observation budget");
    const state = await json(`/operations/${id}`);
    check(state.id === id && state.sha === sha && ["queued", "running", "done", "unanswered"].includes(state.status),
      "Coder probe state identity differs");

    if (state.status !== previous) console.log(JSON.stringify({ id, sha, status: state.status, productAcceptance: false }));
    previous = state.status;

    if (state.status === "unanswered")
      throw new Error("Real OpenCode operation did not complete successfully");

    if (state.status === "done") {
      const runtime = state.runtime;
      const delivery = state.skillsDelivery;
      const result = state.result;
      check(runtime?.model === CODING_MODEL && runtime.reasoningEffort === "low" &&
        runtime.bundleSha256 === config.bundleSha256 && /^sha256:[a-f0-9]{64}$/.test(runtime.imageDigest ?? "") &&
        /^[a-f0-9]{40}$/.test(runtime.verifierRevision ?? ""), "Coder probe runtime policy differs");
      check(delivery?.bundleSha256 === config.bundleSha256 && typeof delivery.sessionId === "string" &&
        /^ses_[A-Za-z0-9_-]{1,200}$/.test(delivery.sessionId) && result?.sessionId === delivery.sessionId &&
        result.skillBundleSha256 === config.bundleSha256, "Coder probe skill delivery differs");
      check(["proposal", "dependencyPlan", "testAudit", "verificationJob", "verificationHandoff", "verification"]
        .every(field => result[field] === undefined) && Array.isArray(result.verifiedDigests) && result.verifiedDigests.length === 0,
        "Read-only coder probe contains mutation or verification state");
      check(Number.isInteger(result.calls) && result.calls > 0 && result.calls <= 96 && Array.isArray(result.reads) &&
        result.reads.length > 0 && result.reads.length <= result.calls, "Actual bounded source-tool reads are required");
      const lineCount = content.split("\n").length;
      const reads = result.reads.map(read => {
        check(read.path === sourcePath && Number.isSafeInteger(read.start) && read.start > 0 &&
          Number.isSafeInteger(read.end) && read.end >= read.start && read.end <= lineCount && read.end - read.start < 80,
          "Coder probe source read metadata differs");
        return { path: sourcePath, start: read.start, end: read.end };
      });
      console.log(
        JSON.stringify({
          id,
          sha,
          freshAccepted: true,
          readOnly: true,
          runtime: { model: CODING_MODEL, reasoningEffort: "low", bundleSha256: config.bundleSha256,
            imageDigest: runtime.imageDigest, verifierRevision: runtime.verifierRevision },
          delivery: { bundleSha256: config.bundleSha256, sessionId: delivery.sessionId },
          calls: result.calls,
          reads,
          inference: "real-worker",
          productAcceptance: false,
        }),
      );
      break;
    }

    await setTimeout(3000);
  }
}

main().catch(() => {
  console.error("Coder runtime probe failed; keep admission held and observe the recorded operation before retrying.");
  process.exitCode = 1;
});

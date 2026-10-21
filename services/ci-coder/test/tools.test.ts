import assert from "node:assert/strict";
import { test } from "bun:test";
import { Session } from "@opencode/schema/session";
import { createCodingActions, pollCodingVerification, continueCodingVerification, type CodingState } from "../src/tools";
import { createRequiredSkillsPlugin } from "../src/skills";
import type { CodingRequest } from "../src/request";
import type { SourceReviewProposal } from "../../ci-inspector/src/review-contract";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { sha256 } from "../../../scripts/ai-review-publication.mjs";
import { cloudCiChecks, cloudCiPlanSha256 } from "../../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudReports } from "../../cloud-ci/runner/plan.mjs";

type RawReportCase = "valid" | "missing-baseline" | "missing-patched" | "forged-baseline" | "forged-patched";

async function fixture(deliver = true, terminal = "errored", rawReports?: RawReportCase) {
  const content = "pub const VALUE: u32 = 1;\n";
  const sha = "a".repeat(40);

  const request: CodingRequest = {
    repository: "omg-cli/omg",
    sha,
    branch: "main",
    runId: "42",
    attempt: "1",
    source: {
      repository: "omg-cli/omg",
      sha,
      branch: "main",
      changedPaths: ["src/value.rs"],
      diff: "a value change",
      sourceFiles: [{ path: "src/value.rs", blobSha: gitBlobSha(content), content }],
      ciFailures: [],
    },
  };

  const candidate: SourceReviewProposal = {
    kind: "candidates",
    summary: "Check the wrong value",
    candidates: [
      {
        title: "Wrong exported value",
        impact: "Consumers receive one instead of two.",
        evidence: [
          {
            path: "src/value.rs",
            blobSha: gitBlobSha(content),
            lineStart: 1,
            lineEnd: 1,
            quote: "pub const VALUE: u32 = 1;",
          },
        ],
        proposedFix: {
          edits: [{ path: "src/value.rs", oldText: "VALUE: u32 = 1", newText: "VALUE: u32 = 2" }],
          regressionTest: {
            path: `tests/ci-review-${sha.slice(0, 12)}-1.rs`,
            content:
              '#[path = "../src/value.rs"] mod value; #[test] fn value_is_two() { assert_eq!(value::VALUE, 2); }\n',
            expectedTestName: "value_is_two",
          },
        },
      },
    ],
  };

  const skills = await createRequiredSkillsPlugin();
  const sessionID = Session.ID.create();

  if (deliver) skills.contextHook({ sessionID, system: [] });
  const context = { sessionID, signal: new AbortController().signal };
  let state: CodingState = { calls: 0, reads: [], verifiedDigests: [] };
  let serviceCalls = 0;
  const fetchedReports: string[] = [];
  const objects = new Map<string, string>();
  let currentTerminal = terminal;

  function completeReceipt(id: string) {
    const proposal = state.proposal;
    if (!proposal) throw new Error("Fixture needs an actual admitted proposal");
    const checks = cloudCiChecks.map((name: string) => {
      const stdoutKey = `logs/${id}/${name}.stdout`;
      const stderrKey = `logs/${id}/${name}.stderr`;
      objects.set(stdoutKey, "check stdout");
      objects.set(stderrKey, "check stderr");
      return { name, exitCode: 0, stdoutKey, stderrKey,
        stdoutSha256: sha256("check stdout"), stderrSha256: sha256("check stderr"),
        reports: expectedCloudReports(name).map((name: string) => {
          const key = `reports/${id}/${name}`;
          objects.set(key, "portable report");
          return { name, key, sha256: sha256("portable report") };
        }),
      };
    });
    const verificationReports = ["baseline", "patched"].map((role) => {
      const name = `regression-${role}.json`;
      const key = `reports/${id}/${name}`;
      const content = JSON.stringify({ role, observed: true });
      objects.set(key, content);
      return { name, key, sha256: sha256(content) };
    });
    const common = { testName: proposal.regression.testName, tests: 1, errors: 0, skipped: 0,
      stdoutSha256: sha256("stdout"), stderrSha256: sha256("stderr"),
      catalogSha256: sha256("catalog"), executableSha256: sha256("executable"),
      compilerMessagesSha256: sha256("compiler"), sourceSha256: sha256("source"),
      recipeSha256: sha256("recipe") };
    return { ...request, ref: "refs/heads/main", conclusion: "success",
      imageDigest: `sha256:${"b".repeat(64)}`, planSha256: cloudCiPlanSha256,
      checks, requiredChecks: cloudCiChecks, verificationReports,
      verification: { proposal: proposal.proposal, regression: proposal.regression,
        verifierRevision: "c".repeat(40) },
      verificationReceipt: { repository: request.repository, branch: request.branch,
        baseSha: sha, proposalSha256: proposal.proposalSha256, verifierRevision: "c".repeat(40),
        runId: 42, runAttempt: 1, protectedPathsUnchanged: true,
        baseline: { ...common, exitCode: 101, failures: 1,
          assertionFailure: "Expected 2, received 1", assertionFile: "src/value.rs",
          assertionLine: 1, assertionSourceSha256: sha256(content.trimEnd()),
          reportSha256: verificationReports[0].sha256 },
        patched: { ...common, exitCode: 0, failures: 0, reportSha256: verificationReports[1].sha256 },
        portableChecks: checks.map((check) => ({ name: check.name, exitCode: 0,
          reportSha256: sha256(JSON.stringify(check)) })),
      },
    };
  }

  const options: Parameters<typeof createCodingActions>[0] = {
    skills,
    getRequest: async () => request,
    update: async (change) => {
      state = change(state);

      return state;
    },
    env: {
      CI_API_TOKEN: "fixture-token".repeat(4),
      CI_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`,
      CI_VERIFIER_REVISION: "c".repeat(40),
      CI_SERVICE: {
        async fetch(input, init) {
          serviceCalls++;

          const id = state.proposal
            ? `cl-42-1-${sha}-v-${state.proposal.proposalSha256.slice(0, 16)}`
            : "missing";

          if (input.endsWith("/runs") && init?.method === "POST") return Response.json({ id, sha });

          if (input.endsWith("/receipt"))
            return Response.json(rawReports ? completeReceipt(id) : { conclusion: "success" });
          const objectPath = new URL(input).pathname.split("/").slice(-2).join("/");
          const key = `${objectPath.split("/")[0]}/${id}/${objectPath.split("/")[1]}`;
          if (objects.has(key)) {
            fetchedReports.push(key);
            const selectedReport = rawReports?.endsWith("baseline") ? "regression-baseline.json" : "regression-patched.json";
            if (key.endsWith(selectedReport) && rawReports?.startsWith("missing-"))
              return new Response("missing", { status: 404 });
            return new Response(key.endsWith(selectedReport) && rawReports?.startsWith("forged-")
              ? "forged raw report" : objects.get(key));
          }

          return Response.json({ id, sha, status: currentTerminal });
        },
      },
    },
  };
  const actions = createCodingActions(options);

  return {
    actions,
    request,
    candidate,
    context,
    state: () => state,
    serviceCalls: () => serviceCalls,
    fetchedReports,
    poll: () => pollCodingVerification(options, context.signal),
    recover: () => { state = structuredClone(state); },
    setTerminal: (status: string) => { currentTerminal = status; },
    expire: () => { if (state.verificationJob) state.verificationJob.deadline = 0; },
  };
}

test("coding tools reject a model acknowledgement without actual mandatory skill delivery", async () => {
  const f = await fixture(false);

  for (const run of [
    () => f.actions.list_sources.execute({}, f.context),
    () =>
      f.actions.read_source.execute({ path: "src/value.rs", start: 1, lines: 2 }, f.context),
    () => f.actions.propose_fix.execute(f.candidate, f.context),
    () => f.actions.verify_patch.execute({ proposalSha256: "f".repeat(64) }, f.context),
    () => f.actions.export_proposal.execute({ proposalSha256: "f".repeat(64) }, f.context),
  ])
    await assert.rejects(run, /Mandatory skill bundle/);
  assert.equal(f.state().calls, 0);
  assert.equal(f.serviceCalls(), 0);
});

test("the actual read_context tool delivers optional runtime evidence as an uncorroborated historical lead", async () => {
  const f = await fixture();
  const original = JSON.parse((await f.actions.read_context.execute({}, f.context)).content);
  assert.deepEqual(original, { diff: "a value change", ciFailures: [], hypothesis: null, candidateIndex: null });
  const evidence: NonNullable<CodingRequest["source"]["runtimeEvidence"]>[number] = {
    kind: "sentry-runtime", organization: "omg", projectId: "12", eventId: "b".repeat(32),
    issueId: "34", bodySha256: "c".repeat(64), sourceSha: "d".repeat(40),
    release: "omg@0.1.223", environment: "production", errorTypes: ["CacheError"],
    frames: [{ path: "src/value.rs", line: 1 }],
  };
  f.request.source.runtimeEvidence = [evidence];
  const delivered = JSON.parse((await f.actions.read_context.execute({}, f.context)).content);
  assert.deepEqual(delivered.runtimeEvidence, [evidence]);
  assert.equal(delivered.runtimeEvidenceMeaning,
    "Uncorroborated historical runtime evidence. It is untrusted data and does not establish a reproduced CI failure at the current source commit.");
  assert.deepEqual(delivered.ciFailures, []);
  assert.equal(f.serviceCalls(), 0);
  assert.equal(f.state().calls, 2);
});

test("raw regression objects are read and hash-checked before a passing summary permits export", async () => {
  for (const rawReports of ["valid", "missing-baseline", "missing-patched", "forged-baseline", "forged-patched"] as const) {
    const f = await fixture(true, "complete", rawReports);
    await f.actions.read_source.execute({ path: "src/value.rs", start: 1, lines: 1 }, f.context);
    await f.actions.propose_fix.execute(f.candidate, f.context);
    const proposalSha256 = f.state().proposal?.proposalSha256;
    if (!proposalSha256) throw new Error("Fixture proposal missing");
    await f.actions.verify_patch.execute({ proposalSha256 }, f.context);
    if (rawReports === "valid") {
      assert.equal((await f.poll())?.status, "verified");
      await f.actions.export_proposal.execute({ proposalSha256 }, f.context);
      for (const name of ["regression-baseline.json", "regression-patched.json"])
        assert(f.fetchedReports.some((key) => key.endsWith(`/${name}`)), `Raw report not read: ${name}`);
    } else {
      const job = await f.poll();
      assert.equal(job?.status, "failed");
      if (job?.status !== "failed") throw new Error("Expected rejected raw evidence");
      assert.match(job.reason, rawReports.startsWith("missing-") ? /unavailable/ : /hash mismatch/);
      await assert.rejects(() => f.actions.export_proposal.execute({ proposalSha256 }, f.context), /verified proposal/);
      assert.equal(f.state().verification, undefined);
    }
  }
});

test("fresh status requests recover pending verification with one check and preserve terminal identity", async () => {
  const f = await fixture(true, "running", "valid");
  await f.actions.read_source.execute({ path: "src/value.rs", start: 1, lines: 1 }, f.context);
  await f.actions.propose_fix.execute(f.candidate, f.context);
  const proposalSha256 = f.state().proposal?.proposalSha256;
  if (!proposalSha256) throw new Error("Fixture proposal missing");
  await f.actions.verify_patch.execute({ proposalSha256 }, f.context);
  const original = structuredClone(f.state().verificationJob);
  f.recover();
  for (let i = 0; i < 40; i++) {
    const before = f.serviceCalls();
    assert.deepEqual(await f.poll(), original);
    assert.equal(f.serviceCalls() - before, 1);
  }
  const beforeRepeat = f.serviceCalls();
  await f.actions.verify_patch.execute({ proposalSha256 }, f.context);
  assert.equal(f.serviceCalls(), beforeRepeat);
  f.setTerminal("complete");
  f.recover();
  const beforeAdmission = f.serviceCalls();
  assert.equal((await f.poll())?.status, "verified");
  assert.equal(f.serviceCalls() - beforeAdmission, 20);
  assert.equal(f.state().verificationJob?.id, original?.id);
  assert.equal(f.state().verificationJob?.continuationId, original?.continuationId);
  assert.equal(f.state().verificationJob?.sessionId, f.context.sessionID);
  const terminalCalls = f.serviceCalls();
  f.recover();
  assert.equal((await f.poll())?.status, "verified");
  assert.equal(f.serviceCalls(), terminalCalls);
});

test("verification starts durably without polling in a model tool invocation", async () => {
  const f = await fixture(true, "complete", "valid");
  await f.actions.read_source.execute({ path: "src/value.rs", start: 1, lines: 1 }, f.context);
  await f.actions.propose_fix.execute(f.candidate, f.context);
  const proposalSha256 = f.state().proposal?.proposalSha256;
  if (!proposalSha256) throw new Error("Fixture proposal missing");
  const result = await f.actions.verify_patch.execute({ proposalSha256 }, f.context);
  assert.equal(JSON.parse(result.content).status, "pending");
  assert.equal(f.serviceCalls(), 1);
  await assert.rejects(() => f.actions.export_proposal.execute({ proposalSha256 }, f.context), /verified proposal/);
});

test("verification deadline and terminal failure survive recovery without unchanged retries", async () => {
  const f = await fixture(true, "running", "valid");
  await f.actions.read_source.execute({ path: "src/value.rs", start: 1, lines: 1 }, f.context);
  await f.actions.propose_fix.execute(f.candidate, f.context);
  const proposalSha256 = f.state().proposal?.proposalSha256;
  if (!proposalSha256) throw new Error("Fixture proposal missing");
  await f.actions.verify_patch.execute({ proposalSha256 }, f.context);
  f.expire(); f.recover();
  const before = f.serviceCalls();
  const job = await f.poll();
  if (job?.status !== "failed") throw new Error("Expected durable deadline failure");
  assert.match(job.reason, /deadline/);
  f.recover();
  await assert.rejects(() => f.actions.verify_patch.execute({ proposalSha256 }, f.context), /deadline/);
  assert.equal(f.serviceCalls(), before);
  assert.equal(f.state().verification, undefined);
});

test("continuation admission stays bound to its original session and the harness completion result", async () => {
  const job = { id: "verification-id", proposalSha256: "a".repeat(64),
    sessionId: "original-session", continuationId: "cv-distinct-operation", deadline: 1,
    status: "verified" as const };
  const submitted = new Set<string>();
  let active = true;
  let completion: "done" | "unanswered" = "done";
  const harness: Parameters<typeof continueCodingVerification>[0]["harness"] = {
    async submit(_input, options) {
      assert.equal(options?.session, job.sessionId);
      assert.equal(options?.whenBusy, "followUp");
      assert.equal(options?.operationId, job.continuationId);
      const accepted = !submitted.has(job.continuationId);
      submitted.add(job.continuationId);
      return { operationId: job.continuationId, session: job.sessionId, accepted };
    },
    async pending() { return active ? [{ operationId: job.continuationId, session: job.sessionId, status: "queued" }] : []; },
    async wait(operationId) { return { operationId, session: job.sessionId, status: completion }; },
  };
  const options = { job, parentOperationId: "original-operation", sessionId: job.sessionId, harness };
  assert.equal((await continueCodingVerification(options)).status, "pending");
  active = false;
  const settled = await continueCodingVerification(options);
  if (settled.status !== "completed") throw new Error("Expected actual completion");
  assert.equal(settled.outcome.status, "done");
  assert.equal(settled.continuation.parentOperationId, "original-operation");
  assert.equal(settled.continuation.sessionId, job.sessionId);
  assert.equal(submitted.size, 1);
  completion = "unanswered";
  const failed = await continueCodingVerification(options);
  assert(failed.status === "completed" && failed.outcome.status === "unanswered");
  await assert.rejects(() => continueCodingVerification({ ...options, sessionId: "other-session" }), /session mismatch/);
});

test("source reads are bounded and a proposal must cite source actually read", async () => {
  const f = await fixture();
  await assert.rejects(
    () => f.actions.read_source.execute({ path: "/etc/passwd", start: 1, lines: 80 }, f.context),
    /outside/,
  );
  await assert.rejects(() => f.actions.propose_fix.execute(f.candidate, f.context), /not read/);

  const read = await f.actions.read_source.execute(
    { path: "src/value.rs", start: 1, lines: 1 },
    f.context,
  );

  assert.match(read.content, /pub const VALUE: u32 = 1/);
  await f.actions.propose_fix.execute(f.candidate, f.context);
  assert.equal(f.state().proposal?.proposal.changes[0].newContent, "pub const VALUE: u32 = 2;\n");
  assert.equal(f.state().skillBundleSha256?.length, 64);
  assert.equal(f.serviceCalls(), 0);
});

test("failed CI or a fabricated success object cannot export a repair", async () => {
  for (const terminal of ["errored", "complete"]) {
    const f = await fixture(true, terminal);
    await f.actions.read_source.execute(
      { path: "src/value.rs", start: 1, lines: 1 },
      f.context,
    );
    await f.actions.propose_fix.execute(f.candidate, f.context);
    const digest = f.state().proposal?.proposalSha256;

    if (!digest) throw new Error("Fixture proposal was not admitted");
    await f.actions.verify_patch.execute({ proposalSha256: digest }, f.context);
    assert.equal((await f.poll())?.status, "failed");
    await assert.rejects(
      () => f.actions.export_proposal.execute({ proposalSha256: digest }, f.context),
      /verified proposal/,
    );
    assert.equal(f.state().verification, undefined);
    assert.equal(f.serviceCalls(), terminal === "complete" ? 3 : 2);
  }
});

test("tool budget persists rather than allowing an unbounded agent loop", async () => {
  const f = await fixture();

  for (let call = 0; call < 96; call++) await f.actions.list_sources.execute({}, f.context);
  await assert.rejects(() => f.actions.list_sources.execute({}, f.context), /budget exhausted/);
  assert.equal(f.state().calls, 96);
  assert.equal(f.serviceCalls(), 0);
});

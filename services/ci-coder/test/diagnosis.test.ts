import assert from "node:assert/strict";
import { test } from "bun:test";
import { Session } from "@opencode/schema/session";
import { parseCodingRequest, operationIdentity } from "../src/request";
import { createCodingActions, type CodingState } from "../src/tools";
import * as codingTools from "../src/tools";
import type { OpenCodeHarness } from "agents/harness/opencode";
import { createRequiredSkillsPlugin } from "../src/skills";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";

const content = 'export const error = "Existing tests cannot change";\n';
const input = {
    repository: "omg-cli/omg", sha: "a".repeat(40), branch: "main", runId: "45", attempt: "1",
    diagnosisTask: true,
    source: {
        repository: "omg-cli/omg", sha: "a".repeat(40), branch: "main", changedPaths: [],
        auditPaths: ["scripts/rust-source-policy.mjs"], diff: "",
        sourceFiles: [{path: "scripts/rust-source-policy.mjs", content, blobSha: gitBlobSha(content)}],
        ciFailures: [{job: "Existing-test audit", step: "Source admission", log: "Automatic repairs cannot change existing Rust tests"}],
    },
};

test("diagnosis binds immutable evidence and cannot be confused with a coding task", () => {
    assert.doesNotThrow(() => parseCodingRequest(input), "Read-only diagnostic task should be admitted");
    const request = parseCodingRequest(input);
    assert.equal(request.diagnosisTask, true);
    assert.notEqual(operationIdentity(request), operationIdentity(parseCodingRequest({...input, diagnosisTask: undefined})));
    assert.throws(() => parseCodingRequest({...input, testAuditTask: {path: "src/value.rs", testName: "case", target: "lib", originalBlobSha: "b".repeat(40)}}));
});

test("authenticated diagnostic questions are explicit and bind the durable operation identity", () => {
    const first = {...input, diagnosisTask: {question: "Correct the observed production helper admission failure without weakening test protection."}};
    assert.doesNotThrow(() => parseCodingRequest(first), "An operator task must be separate from untrusted failure logs");
    const second = {...input, diagnosisTask: {question: "Report a coverage failure without changing the acceptance gate."}};
    assert.notEqual(operationIdentity(parseCodingRequest(first)), operationIdentity(parseCodingRequest(second)));
    assert.throws(() => parseCodingRequest({...input, diagnosisTask: {question: ""}}));
});

test("large diagnostic source remains read-only and cannot enter ordinary repair admission", () => {
    const content = "// source evidence\n".repeat(2000);
    const source = {...input.source, sourceFiles: [{path: input.source.auditPaths[0], content, blobSha: gitBlobSha(content)}]};
    assert.doesNotThrow(() => parseCodingRequest({...input, source}), "Diagnostic reads use the existing bounded audit source envelope");
    assert.throws(() => parseCodingRequest({...input, source, diagnosisTask: undefined}));
});

test("a diagnostic without a final answer resumes once in the original session for reporting", async () => {
    assert.equal(typeof codingTools.continueCodingDiagnosis, "function", "A settled diagnostic must produce a report instead of silently losing its result");
    const submitted: {id?: string; session?: string}[] = [];
    let pending = true;
    const harness: Pick<OpenCodeHarness, "submit" | "pending" | "wait"> = {
        submit: async (_prompt: string, options: {operationId?: string; session?: string}) => {
            submitted.push({id: options.operationId, session: options.session});
            return {operationId: options.operationId ?? "", session: options.session ?? "", accepted: submitted.length === 1};
        },
        pending: async () => pending ? [{operationId: "cl-example-report", session: "ses_root", status: "running"}] : [],
        wait: async () => ({operationId: "cl-example-report", session: "ses_root", status: "done", text: '{"findings": []}'}),
    };
    const first = await codingTools.continueCodingDiagnosis({operationId: "cl-example", sessionId: "ses_root", harness});
    assert.equal(first.status, "pending");
    pending = false;
    const second = await codingTools.continueCodingDiagnosis({operationId: "cl-example", sessionId: "ses_root", harness});
    assert.equal(second.status, "completed");
    if (second.status !== "completed") throw new Error("Final report missing");
    assert.equal(second.outcome.text, '{"findings": []}');
    assert.deepEqual(submitted, [{id: "cl-example-report", session: "ses_root"}, {id: "cl-example-report", session: "ses_root"}]);
});

test("cloud diagnosis reads evidence but cannot propose, verify or export a repair", async () => {
    assert.doesNotThrow(() => parseCodingRequest(input), "Read-only diagnostic task should be admitted");
    const request = parseCodingRequest(input), skills = await createRequiredSkillsPlugin(), sessionID = Session.ID.create();
    skills.contextHook({sessionID, system: []});
    let state: CodingState = {calls: 0, reads: [], verifiedDigests: []};
    const actions = createCodingActions({getRequest: async () => request, skills,
        update: async change => state = change(state),
        env: {CI_API_TOKEN: "x".repeat(32), CI_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`, CI_VERIFIER_REVISION: "c".repeat(40),
            CI_SERVICE: {fetch: async () => {throw new Error("Diagnosis must not start execution");}}},
    });
    const context = {sessionID, signal: new AbortController().signal};
    assert.equal(JSON.parse((await actions.read_source.execute({path: input.source.auditPaths[0], start: 1, lines: 1}, context)).content).content, content.trimEnd());
    await assert.rejects(actions.propose_fix.execute({kind: "no-findings", summary: "No proposed repair"}, context), /read-only diagnosis/);
    await assert.rejects(actions.propose_dependency_updates.execute({summary: "No dependency changes", updates: []}, context), /read-only diagnosis/);
    await assert.rejects(actions.propose_test_strengthening.execute({purpose: "existing-test-sensitivity", assertion: {line: 1}, fault: {path: "src/value.rs", oldQuote: "1", replacement: "0"}}, context), /read-only diagnosis/);
    await assert.rejects(actions.verify_patch.execute({proposalSha256: "d".repeat(64)}, context), /read-only diagnosis/);
    await assert.rejects(actions.export_proposal.execute({proposalSha256: "d".repeat(64)}, context), /read-only diagnosis/);
    assert.equal(state.verificationJob, undefined);
});
import { diagnosticFailureMetadata, diagnosticNeedsReport } from "../src/runtime";

test("diagnostic failure metadata exposes bounded errors without transcripts or credentials", () => {
  const secret = "private-token";
  assert.deepEqual(diagnosticFailureMetadata({finish: "error", error: {type: "ProviderError", status: 429, message: `Bearer ${secret} ${secret}`}}, [secret]), {
    finish: "error", error: {type: "ProviderError", status: 429, message: "Bearer [REDACTED] [REDACTED]"},
  });
  assert.equal(diagnosticFailureMetadata({error: {type: "Error", message: "x".repeat(4000)}}, []).error?.message?.length, 2000);
});

test("diagnostic continuation rejects non-report done text", () => {
  const valid = '{"findings":[],"edits":[],"tests":[]}';
  const sp = String.fromCharCode(32), nl = String.fromCharCode(10), tab = String.fromCharCode(9);
  const needs = diagnosticNeedsReport;
  assert.equal(needs(valid), false);
  assert.equal(needs(sp + nl + valid + nl + sp), false);
  assert.equal(needs(undefined), true);
  assert.equal(needs(null), true);
  const invalid = ["", sp + nl + tab, nl, "I hit the step limit before I could produce the final answer; draft Python script was not emitted.", "not json", "null", "[]", String.fromCharCode(34) + "text" + String.fromCharCode(34), "42", "{}", '{"findings":[],"edits":[]}', '{"findings":{},"edits":[],"tests":[]}'];
  for (const text of invalid) assert.equal(needs(text), true, text);
});

import { diagnosticHistory, DIAGNOSIS_HISTORY_MAX_BYTES } from "../src/runtime";

test("diagnostic history keeps ordered assistant text and excludes everything else", () => {
    const production = `diff --git a/src/lib.rs b/src/lib.rs
+pub fn fixed() {}
`;
    const testPatch = `diff --git a/tests/fixed.rs b/tests/fixed.rs
+#[test] fn fixed() {}
`;
    const secret = "fixture-secret";
    const history = diagnosticHistory([
        { type: "user", id: "u1", content: [{ type: "text", text: "ignore user" }] },
        { type: "system", id: "s1", content: [{ type: "text", text: "ignore system" }] },
        { type: "assistant", id: "a1", content: [
            { type: "text", text: production + `Bearer ${secret}` },
            { type: "reasoning", text: "ignore reasoning" },
            { type: "tool" },
        ] },
        { type: "assistant", id: "a2", content: [{ type: "text", text: testPatch + ` ${secret}` }] },
    ], [secret]);
    assert.deepEqual(history, [
        { id: "a1", text: [production + "Bearer [REDACTED]"] },
        { id: "a2", text: [testPatch + " [REDACTED]"] },
    ]);
    assert.equal(/ignore (user|system|reasoning)/.test(JSON.stringify(history)), false);
    assert.equal(JSON.stringify(history).includes(secret), false);
});

test("diagnostic history rejects overflow instead of truncating patch text", () => {
    const text = "x".repeat(DIAGNOSIS_HISTORY_MAX_BYTES + 1);
    assert.throws(
        () => diagnosticHistory([{ type: "assistant", id: "a1", content: [{ type: "text", text }] }], []),
        /exceeds/,
    );
});

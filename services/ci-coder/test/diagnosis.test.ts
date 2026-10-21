import assert from "node:assert/strict";
import { test } from "bun:test";
import { Session } from "@opencode/schema/session";
import { parseCodingRequest, operationIdentity } from "../src/request";
import { createCodingActions, type CodingState } from "../src/tools";
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

test("large diagnostic source remains read-only and cannot enter ordinary repair admission", () => {
    const content = "// source evidence\n".repeat(2000);
    const source = {...input.source, sourceFiles: [{path: input.source.auditPaths[0], content, blobSha: gitBlobSha(content)}]};
    assert.doesNotThrow(() => parseCodingRequest({...input, source}), "Diagnostic reads use the existing bounded audit source envelope");
    assert.throws(() => parseCodingRequest({...input, source, diagnosisTask: undefined}));
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

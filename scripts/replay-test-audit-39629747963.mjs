import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { ciPolicy } from "./ai-review-proof.mjs";
import { admitCoderResult, coderEndpoint } from "./ai-coder-client.mjs";
import { parseCodingRequest, operationIdentity } from "../services/ci-coder/src/request.ts";
import { publishTestAuditReview, canonicalJson, sha256 } from "./ai-review-publication.mjs";
import { testAuditDigest } from "../services/cloud-ci/src/test-audit-contract.ts";
import { createGhClient } from "./publish-ai-review.mjs";

export function admitOriginalRecord(record) {
    assert.equal(sha256(canonicalJson(record)), "79632ad1754ee169af0dd5c920a9173c7a134bacc029cc31abc3d3a0a3334ef6");
    assert.equal(record.controllerRevision, "c2b7f1bcb09e2fa83039be4626132bacba3d6d6a");
    assert.equal(record.sha, "31bbddd87936e27f908789c29f3b203a9754612a");
    assert.deepEqual(record.campaignRun, { attempt: "2", runId: "39629747963" });
    assert.equal(record.status, "reviewed");
    assert.equal(record.publishRequested, true);
    assert.equal(record.publications.length, 0);
    assert.equal(record.testAudits.length, 1);
    return record.testAudits[0];
}

async function json(url, token) {
    const response = await fetch(url, { headers: { authorization: `Bearer ${token}` }, redirect: "error", signal: AbortSignal.timeout(30000) });
    assert.equal(response.ok, true);
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            assert(size <= 2 * 1024 * 1024, "Replay JSON exceeds its byte budget");
            chunks.push(value);
        }
    } finally {
        await reader.cancel();
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
}

export async function main() {
    assert.deepEqual(process.argv.slice(2), ["--publish"]);
    assert.equal(process.env.GITHUB_REPOSITORY, "omg-cli/omg");
    assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
    assert.equal(process.env.GITHUB_REF, "refs/heads/codex/cloud-publication-proof-replay");
    const configRoot = path.join(homedir(), "ci");
    const config = JSON.parse(await readFile(path.join(configRoot, "omg-cloud-ci.json"), "utf8"));
    const coder = JSON.parse(await readFile(path.join(configRoot, "omg-ci-coder.json"), "utf8"));
    const policy = ciPolicy(config);
    coderEndpoint(coder);
    const token = (await readFile(config.tokenFile, "utf8")).trim();
    const codingToken = (await readFile(coder.tokenFile, "utf8")).trim();
    const record = await json(new URL("/review-records/39629747963-2", policy.endpoint), token);
    const audit = admitOriginalRecord(record);
    const { request, coding, id } = audit;
    assert.equal(id, `cl-39629747963-2-${record.sha}-ta-${testAuditDigest(request.testAudit.proposal).slice(0, 16)}`);
    assert.equal(request.runId, "39629747963");
    assert.equal(request.attempt, "2");
    assert.equal(request.sha, record.sha);
    assert.equal(request.ref, "refs/heads/main");
    const codingRequest = parseCodingRequest(coding.request);
    assert(codingRequest.testAuditTask);
    assert.equal(coding.id, audit.coderOperationId);
    assert.equal(coding.id, operationIdentity(codingRequest));
    assert.equal(codingRequest.sha, record.sha);
    assert.equal(codingRequest.runId, request.runId);
    assert.equal(codingRequest.attempt, request.attempt);
    const state = await json(new URL(`/operations/${coding.id}`, coder.endpoint), codingToken);
    const coded = admitCoderResult(state, codingRequest, { ...policy, bundleSha256: coder.bundleSha256 });
    assert.equal(coded?.proposalSha256, testAuditDigest(request.testAudit.proposal));
    const receipt = await json(new URL(`/runs/${id}/receipt`, policy.endpoint), token);
    const result = await publishTestAuditReview({ github: createGhClient(), request, receipt, policy, publish: true,
        load: key => {
            const [kind, run, name] = key.split("/");
            return fetch(new URL(`/runs/${run}/${kind}/${name}`, policy.endpoint), {
                headers: { authorization: `Bearer ${token}` }, redirect: "error", signal: AbortSignal.timeout(30000),
            });
        } });
    console.log(JSON.stringify({ replayExecutor: process.env.GITHUB_SHA, replayRun: process.env.GITHUB_RUN_ID,
        originalRun: request.runId, originalAttempt: request.attempt, originalController: record.controllerRevision, result }));
}

if (import.meta.main) await main();

import assert from "node:assert/strict";
import { test } from "bun:test";
import { Session } from "@opencode/schema/session";
import { parseCodingRequest, operationIdentity } from "../src/request";
import { createCodingActions, type CodingState } from "../src/tools";
import { createRequiredSkillsPlugin } from "../src/skills";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { admitDependencyResult } from "../src/dependency";

const lock =
    'version = 4\n\n[[package]]\nname = "example"\nversion = "0.3.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n';
const manifest = '[package]\nname = "fixture"\nversion = "1.0.0"\n';
const input = {
    repository: "omg-cli/omg",
    sha: "a".repeat(40),
    branch: "main",
    runId: "43",
    attempt: "1",
    source: {
        repository: "omg-cli/omg",
        sha: "a".repeat(40),
        branch: "main",
        changedPaths: [],
        auditPaths: ["Cargo.toml", "Cargo.lock"],
        diff: "",
        sourceFiles: [
            {
                path: "Cargo.toml",
                blobSha: gitBlobSha(manifest),
                content: manifest,
            },
            { path: "Cargo.lock", blobSha: gitBlobSha(lock), content: lock },
        ],
        ciFailures: [
            {
                job: "Dependency audit",
                step: "cargo audit",
                log: "example 0.3.1: RUSTSEC-2026-0001; patched >=0.3.2",
            },
        ],
    },
    dependencyTask: {
        targets: [
            {
                name: "example",
                version: "0.3.1",
                availableVersions: ["0.3.2"],
                advisories: ["RUSTSEC-2026-0001"],
            },
        ],
    },
};
const plan = {
    summary:
        "Update the reported dependency without changing manifest requirements.",
    updates: [{ name: "example", from: "0.3.1", to: "0.3.2" }],
};

test("publisher independently admits cloud plan identity, runtime, skills and actual reads", () => {
    const request = parseCodingRequest(input),
        id = operationIdentity(request);
    const policy = {
        bundleSha256: "b".repeat(64),
        imageDigest: `sha256:${"c".repeat(64)}`,
        verifierRevision: "d".repeat(40),
    };
    const state = {
        id,
        repository: request.repository,
        sha: request.sha,
        branch: request.branch,
        runId: request.runId,
        attempt: request.attempt,
        status: "done",
        initialOperation: { operationId: id, status: "done" },
        runtime: {
            ...policy,
            model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
            reasoningEffort: "high",
        },
        skillsDelivery: {
            bundleSha256: policy.bundleSha256,
            sessionId: "ses_fixture",
        },
        result: {
            calls: 4,
            sessionId: "ses_fixture",
            skillBundleSha256: policy.bundleSha256,
            reads: [
                { path: "Cargo.toml", start: 1, end: 3 },
                { path: "Cargo.lock", start: 3, end: 6 },
            ],
            dependencyPlan: plan,
        },
    };
    assert.deepEqual(admitDependencyResult(state, request, id, policy), plan);
    for (const bad of [
        { ...state, sha: "e".repeat(40) },
        { ...state, status: "running" },
        { ...state, runtime: { ...state.runtime, model: "other" } },
        {
            ...state,
            skillsDelivery: { ...state.skillsDelivery, sessionId: "ses_other" },
        },
        {
            ...state,
            result: {
                ...state.result,
                reads: [{ path: "Cargo.toml", start: 1, end: 3 }],
            },
        },
        {
            ...state,
            result: {
                ...state.result,
                dependencyPlan: {
                    ...plan,
                    updates: [{ ...plan.updates[0], to: "0.3.9" }],
                },
            },
        },
    ])
        assert.throws(() => admitDependencyResult(bad, request, id, policy));
});

test("dependency repair is a separate exact-source task and changes operation identity", () => {
    const request = parseCodingRequest(input);
    assert.deepEqual(request.dependencyTask, input.dependencyTask);
    const other = parseCodingRequest({
        ...input,
        dependencyTask: {
            targets: [
                {
                    ...input.dependencyTask.targets[0],
                    availableVersions: ["0.3.3"],
                },
            ],
        },
    });
    assert.notEqual(operationIdentity(request), operationIdentity(other));
    for (const value of [
        {
            ...input,
            testAuditTask: {
                path: "tests/a.rs",
                testName: "a",
                originalBlobSha: "b".repeat(40),
            },
        },
        {
            ...input,
            dependencyTask: {
                targets: [
                    { ...input.dependencyTask.targets[0], name: "--config" },
                ],
            },
        },
        {
            ...input,
            dependencyTask: {
                targets: [
                    { ...input.dependencyTask.targets[0], version: "0.3.0" },
                ],
            },
        },
        {
            ...input,
            dependencyTask: {
                targets: [
                    input.dependencyTask.targets[0],
                    input.dependencyTask.targets[0],
                ],
            },
        },
        { ...input, source: { ...input.source, ciFailures: [] } },
    ])
        assert.throws(() => parseCodingRequest(value));
});

test("cloud dependency proposal requires skills and actual lockfile reads and exports no source edits", async () => {
    const request = parseCodingRequest(input);
    const skills = await createRequiredSkillsPlugin();
    const sessionID = Session.ID.create();
    const context = { sessionID, signal: new AbortController().signal };
    let state: CodingState = { calls: 0, reads: [], verifiedDigests: [] };
    const actions = createCodingActions({
        getRequest: async () => request,
        skills,
        update: async (change) => (state = change(state)),
        env: {
            CI_API_TOKEN: "x".repeat(32),
            CI_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`,
            CI_VERIFIER_REVISION: "c".repeat(40),
            CI_SERVICE: {
                fetch: async () => {
                    throw new Error(
                        "Dependency planning must not start ordinary source verification",
                    );
                },
            },
        },
    });
    await assert.rejects(
        actions.propose_dependency_updates.execute(plan, context),
    );
    skills.contextHook({ sessionID, system: [] });
    await assert.rejects(
        actions.propose_dependency_updates.execute(plan, context),
        /read/i,
    );
    await actions.read_source.execute(
        { path: "Cargo.lock", start: 3, lines: 4 },
        context,
    );
    await actions.read_source.execute(
        { path: "Cargo.toml", start: 1, lines: 3 },
        context,
    );
    for (const updates of [
        [],
        [...plan.updates, ...plan.updates],
        [{ name: "other", from: "0.3.1", to: "0.3.2" }],
        [{ ...plan.updates[0], to: "0.3.0" }],
        [{ ...plan.updates[0], to: "0.3.9" }],
        [{ ...plan.updates[0], to: "0.3.2;echo secret" }],
    ])
        await assert.rejects(
            actions.propose_dependency_updates.execute(
                { ...plan, updates },
                context,
            ),
        );
    const result = JSON.parse(
        (await actions.propose_dependency_updates.execute(plan, context))
            .content,
    );
    assert.deepEqual(result.plan, plan);
    assert.equal(result.verified, false);
    assert.deepEqual(state.dependencyPlan, plan);
    assert.equal(state.proposal, undefined);
    await assert.rejects(
        actions.propose_fix.execute(
            { kind: "no-findings", summary: "No source repair" },
            context,
        ),
        /dependency/i,
    );
});

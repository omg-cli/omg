import { test } from "bun:test";
import assert from "node:assert/strict";
import {
    planTestAuditContinuation,
    parentPublicationResult,
    admitTestAuditParent,
    testAuditRunTitle,
} from "../../scripts/test-audit-campaign.mjs";
const a = "a".repeat(40),
    b = "b".repeat(40),
    manifest = "c".repeat(64),
    controller = "d".repeat(40);
const fixture = () => ({
    campaignRun: { runId: "42", attempt: "1" },
    repository: "omg-cli/omg",
    branch: "main",
    sha: a,
    controllerRevision: controller,
    status: "reviewed",
    formatting: {
        status: "passed",
        sha: a,
        ref: "refs/heads/main",
        runId: "42",
        attempt: "1",
    },
    publishRequested: true,
    sourceRange: {
        kind: "test-audit",
        sha: a,
        manifestDigest: manifest,
        inventoryDigest: "e".repeat(64),
        cursor: 3,
        nextCursor: 4,
        pageSize: 1,
        pagePaths: 1,
        totalPaths: 10,
    },
    testAuditOutcomes: [{ id: "case", status: "verified-sensitivity" }],
    testAudits: [],
});
test("campaign main advance resumes completed rows at next cursor without carrying prior formatting or credit", () => {
    const parent = fixture();
    const plan = planTestAuditContinuation(parent, b, "42", "1", "skipped");
    assert.equal(plan.status, "continue");
    assert.equal(plan.inputs.audit_cursor, "4");
    assert.equal(plan.inputs.audit_sha, b);
    assert.equal(plan.inputs.audit_resnapshot, "true");
    const target = {
        branch: "main",
        sha: b,
        publish: true,
        auditParent: "42-1",
        range: {
            kind: "test-audit",
            cursor: 4,
            manifestDigest: manifest,
            resnapshot: true,
        },
    };
    const resumed = admitTestAuditParent(
        target,
        parent,
        controller,
        manifest,
        "skipped",
    );
    assert.equal(resumed.upstream, undefined);
    assert.equal(resumed.range.resnapshotOf.sha, a);
    assert.throws(
        () =>
            admitTestAuditParent(
                target,
                parent,
                controller,
                "f".repeat(64),
                "skipped",
            ),
        /manifest|parent/i,
    );
});
test("stale inference and unpublished proof reanalyse same row but successful publication advances", () => {
    const stale = {
        ...fixture(),
        status: "incomplete-stale",
        formatting: { status: "not-started" },
    };
    assert.equal(
        planTestAuditContinuation(stale, b, "42", "1", "skipped").inputs
            .audit_cursor,
        "3",
    );
    const parent = {
        ...fixture(),
        testAudits: [
            {
                request: {
                    testAudit: {
                        proposal: { purpose: "existing-test-strengthening" },
                    },
                },
            },
        ],
        testAuditOutcomes: [{ status: "verified-strengthening" }],
    };
    assert.equal(
        planTestAuditContinuation(parent, b, "42", "1", "failure").inputs
            .audit_cursor,
        "3",
    );
    assert.equal(
        planTestAuditContinuation(parent, b, "42", "1", "success").inputs
            .audit_cursor,
        "4",
    );
    assert.equal(
        planTestAuditContinuation(parent, a, "42", "1", "failure").status,
        "publication-unresolved",
    );
    assert.equal(testAuditRunTitle("42-1", b, 3), `Test audit 42-1 ${b} 3`);
});
import {
    recoverTestAuditCampaign,
    dispatchTestAuditPlan,
    admitDuplicateTestAudit,
} from "../../scripts/test-audit-campaign.mjs";
test("bounded recovery never starts over on missing campaign and dispatch dedupe performs no second dispatch", async () => {
    let pages = 0,
        dispatches = 0;
    const other = { display_title: "AI source review" };
    const held = await recoverTestAuditCampaign({
        github: {
            request: async () => {
                pages++;
                return { workflow_runs: Array(100).fill(other) };
            },
        },
        currentSha: b,
        revision: controller,
        manifestDigest: manifest,
        loadRecord: async () => {
            throw new Error("No candidate record should be read");
        },
        dispatch: async () => {
            dispatches++;
        },
    });
    assert.equal(held.status, "campaign-lookback-exhausted");
    assert.equal(pages, 5);
    assert.equal(dispatches, 0);
    const plan = planTestAuditContinuation(fixture(), b, "42", "1", "skipped");
    const child = {
        id: 99,
        display_title: testAuditRunTitle("42-1", b, 4),
        head_sha: b,
        head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const duplicate = await dispatchTestAuditPlan({
        github: { request: async () => ({ workflow_runs: [child] }) },
        plan,
        dispatch: async () => {
            dispatches++;
        },
        currentRunId: "50",
    });
    assert.equal(duplicate.status, "existing-child");
    assert.equal(dispatches, 0);
    assert.equal(
        admitDuplicateTestAudit(
            {
                ...fixture(),
                sha: b,
                campaignParent: "42-1",
                sourceRange: { ...fixture().sourceRange, cursor: 4 },
            },
            { sha: b, auditParent: "42-1", range: { cursor: 4 } },
            controller,
            manifest,
        ),
        true,
    );
});
import {
    findDuplicateTestAuditRecord,
    testAuditTarget,
} from "../../scripts/test-audit-campaign.mjs";
test("intake duplicate record guard returns before any new verification and rejects forged parent references", async () => {
    const parent = fixture(),
        target = {
            branch: "main",
            sha: b,
            publish: true,
            auditParent: "42-1",
            range: {
                kind: "test-audit",
                cursor: 4,
                manifestDigest: manifest,
                resnapshot: true,
            },
        };
    assert.throws(
        () =>
            admitTestAuditParent(
                { ...target, auditParent: "99-1" },
                parent,
                controller,
                manifest,
                "skipped",
            ),
        /parent/,
    );
    const stored = {
        ...parent,
        sha: b,
        campaignParent: "42-1",
        sourceRange: { ...parent.sourceRange, sha: b, cursor: 4 },
    };
    let loads = 0;
    const prior = {
        id: 99,
        run_attempt: 1,
        display_title: testAuditRunTitle("42-1", b, 4),
        head_sha: b,
        head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const duplicate = await findDuplicateTestAuditRecord({
        github: { request: async () => ({ workflow_runs: [prior] }) },
        target,
        revision: controller,
        manifestDigest: manifest,
        currentRunId: "100",
        loadRecord: async (ref) => {
            loads++;
            assert.equal(ref, "99-1");
            return stored;
        },
    });
    assert.deepEqual(duplicate, { runId: "99", attempt: "1" });
    assert.equal(loads, 1);
    const parsed = testAuditTarget({
        branch: "main",
        scope: "test-audit",
        publish: "true",
        audit_sha: b,
        audit_parent: "42-1",
        audit_cursor: "4",
        audit_manifest: manifest,
        audit_resnapshot: "true",
    });
    assert.equal(parsed.range.inventoryDigest, undefined);
    assert.equal(parsed.range.resnapshot, true);
});
test("recovery rereads exact terminal workflow attempt, advances confirmed work and holds same-source unpublished proof", async () => {
    for (const publicationResult of ["success", "failure"]) {
        const report = {
            ...fixture(),
            testAudits: [
                {
                    request: {
                        testAudit: {
                            proposal: {
                                purpose: "existing-test-strengthening",
                            },
                        },
                    },
                },
            ],
        };
        const metadata = {
            id: 42,
            run_attempt: 1,
            head_sha: a,
            head_branch: "main",
            path: ".github/workflows/ai-review.yml",
            name: "AI source review",
            workflow_id: 391232924,
            repository: { full_name: "omg-cli/omg" },
            event: "workflow_dispatch",
        };
        const prior = {
            ...metadata,
            status: "completed",
            display_title: testAuditRunTitle("initial", a, 3),
        };
        const github = {
            request: async (_method, route) => {
                if (route.includes("head_sha=")) return { workflow_runs: [] };
                if (route.includes("/attempts/1/jobs"))
                    return {
                        jobs: [
                            {
                                name: "review",
                                status: "completed",
                                conclusion: "success",
                            },
                            {
                                name: "publish",
                                status: "completed",
                                conclusion: publicationResult,
                            },
                        ],
                    };
                if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                    return {id:391232924,name:"AI source review",path:".github/workflows/ai-review.yml"};
                if (route.includes("/attempts/1")) return metadata;
                return { workflow_runs: [prior] };
            },
        };
        const dispatched = [];
        const result = await recoverTestAuditCampaign({
            github,
            currentSha: publicationResult === "success" ? b : a,
            revision: controller,
            manifestDigest: manifest,
            currentRunId: "50",
            loadRecord: async () => report,
            dispatch: async (inputs) => dispatched.push(inputs),
        });
        if (publicationResult === "success") {
            assert.equal(result.status, "dispatched");
            assert.equal(dispatched[0].audit_cursor, "4");
            assert.equal(dispatched[0].audit_resnapshot, "true");
            assert.equal(dispatched[0].audit_digest, undefined);
        } else {
            assert.equal(result.status, "publication-unresolved");
            assert.equal(dispatched.length, 0);
        }
    }
});


test("campaign continuation admits a titled run only from the bound workflow identity", async () => {
    const report=fixture();
    const workflow={id:391232924,name:"AI source review",path:".github/workflows/ai-review.yml"};
    const metadata={id:42,run_attempt:1,head_sha:a,head_branch:"main",path:workflow.path,name:testAuditRunTitle("initial",a,3),workflow_id:workflow.id,repository:{full_name:"omg-cli/omg"},event:"workflow_dispatch"};
    const jobs={jobs:[{name:"review",conclusion:"success",status:"completed"},{name:"publish",conclusion:"skipped",status:"completed"}]};
    const api=(runData,workflowData)=>({async request(method,path){
        assert.equal(method,"GET");
        if(path === "/repos/omg-cli/omg/actions/runs/42/attempts/1")return runData;
        if(path === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")return workflowData;
        if(path === "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100")return jobs;
        assert.fail(`Unexpected route ${path}`);
    }});
    assert.equal(await parentPublicationResult(api(metadata,workflow),"42-1",report),"skipped");
    for(const changed of [{workflow_id:391232925},{head_sha:b},{head_branch:"other"},{path:".github/workflows/other.yml"},{repository:{full_name:"other/repo"}},{run_attempt:2},{event:"pull_request"}])
        await assert.rejects(parentPublicationResult(api({...metadata,...changed},workflow),"42-1",report),/workflow identity mismatch/);
    for(const changed of [{id:0},{name:"Other workflow"},{path:".github/workflows/other.yml"}])
        await assert.rejects(parentPublicationResult(api(metadata,{...workflow,...changed}),"42-1",report),/workflow identity mismatch/);
});

const parentJobsApi = (metadata, workflow, responses) => {
    const calls = { jobs: 0 };
    return {
        calls,
        async request(method, path) {
            assert.equal(method, "GET");
            if (path === "/repos/omg-cli/omg/actions/runs/42/attempts/1")
                return metadata;
            if (path === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                return workflow;
            if (
                path ===
                "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100"
            ) {
                const response =
                    responses[Math.min(calls.jobs, responses.length - 1)];
                calls.jobs++;
                return response;
            }
            assert.fail(`Unexpected route ${path}`);
        },
    };
};
const parentWorkflow = {
    id: 391232924,
    name: "AI source review",
    path: ".github/workflows/ai-review.yml",
};
const parentMetadata = {
    id: 42,
    run_attempt: 1,
    head_sha: a,
    head_branch: "main",
    path: parentWorkflow.path,
    name: testAuditRunTitle("initial", a, 3),
    workflow_id: parentWorkflow.id,
    repository: { full_name: "omg-cli/omg" },
    event: "workflow_dispatch",
};
const parentJob = (name, status, conclusion) => ({
    name,
    status,
    conclusion,
});

test("parent admission waits through a pending review and missing publish before admitting terminal jobs", async () => {
    const waits = [];
    const api = parentJobsApi(parentMetadata, parentWorkflow, [
        {
            jobs: [
                parentJob("review", "in_progress", null),
                parentJob("continue", "completed", "success"),
            ],
        },
        {
            jobs: [
                parentJob("review", "completed", "success"),
                parentJob("publish", "completed", "skipped"),
                parentJob("continue", "completed", "success"),
            ],
        },
    ]);
    assert.equal(
        await parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        "skipped",
    );
    assert.equal(api.calls.jobs, 2);
    assert.deepEqual(waits, [1000]);
});

test("parent admission waits for a missing publish job then admits its terminal conclusion", async () => {
    const waits = [];
    const api = parentJobsApi(parentMetadata, parentWorkflow, [
        {
            jobs: [parentJob("review", "completed", "success")],
        },
        {
            jobs: [
                parentJob("review", "completed", "success"),
                parentJob("publish", "completed", "success"),
            ],
        },
    ]);
    assert.equal(
        await parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        "success",
    );
    assert.equal(api.calls.jobs, 2);
    assert.deepEqual(waits, [1000]);
});

test("parent admission fails after a bounded wait and reports observed nonterminal statuses", async () => {
    const waits = [];
    const api = parentJobsApi(parentMetadata, parentWorkflow, [
        { jobs: [parentJob("review", "in_progress", null)] },
    ]);
    await assert.rejects(
        parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        /not terminal after bounded wait: review=in_progress\/none publish=missing/,
    );
    assert.equal(api.calls.jobs, 6);
    assert.equal(waits.length, 5);
    assert.ok(waits.reduce((total, ms) => total + ms, 0) <= 30000);
});

test("parent admission rejects a terminal failed review without retrying", async () => {
    const waits = [];
    const api = parentJobsApi(parentMetadata, parentWorkflow, [
        {
            jobs: [
                parentJob("review", "completed", "failure"),
                parentJob("publish", "completed", "skipped"),
            ],
        },
    ]);
    await assert.rejects(
        parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        /review did not succeed/,
    );
    assert.equal(api.calls.jobs, 1);
    assert.equal(waits.length, 0);
});

test("parent admission rejects ambiguous duplicate job identities without retrying", async () => {
    const waits = [];
    const api = parentJobsApi(parentMetadata, parentWorkflow, [
        {
            jobs: [
                parentJob("review", "completed", "success"),
                parentJob("review", "completed", "success"),
                parentJob("publish", "completed", "skipped"),
            ],
        },
    ]);
    await assert.rejects(
        parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        /ambiguous/,
    );
    assert.equal(api.calls.jobs, 1);
    assert.equal(waits.length, 0);
});

test("parent admission fails invalid parent workflow metadata before any jobs retry", async () => {
    const waits = [];
    const api = parentJobsApi(
        { ...parentMetadata, workflow_id: parentWorkflow.id + 1 },
        parentWorkflow,
        [
            {
                jobs: [
                    parentJob("review", "completed", "success"),
                    parentJob("publish", "completed", "skipped"),
                ],
            },
        ],
    );
    await assert.rejects(
        parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        /workflow identity mismatch/,
    );
    assert.equal(api.calls.jobs, 0);
    assert.equal(waits.length, 0);
});

test("parent admission admits an already terminal parent without any wait", async () => {
    const waits = [];
    const api = parentJobsApi(parentMetadata, parentWorkflow, [
        {
            jobs: [
                parentJob("review", "completed", "success"),
                parentJob("publish", "completed", "skipped"),
                parentJob("continue", "completed", "success"),
            ],
        },
    ]);
    assert.equal(
        await parentPublicationResult(api, "42-1", fixture(), {
            wait: async (ms) => waits.push(ms),
        }),
        "skipped",
    );
    assert.equal(api.calls.jobs, 1);
    assert.equal(waits.length, 0);
});

test("parent admission propagates jobs API errors without waiting", async () => {
    let jobs = 0,
        waits = 0;
    const api = {
        async request(method, path) {
            assert.equal(method, "GET");
            if (path.endsWith("/jobs?per_page=100")) {
                jobs++;
                throw Object.assign(new Error("jobs unavailable"), {
                    status: 503,
                });
            }
            if (path === "/repos/omg-cli/omg/actions/runs/42/attempts/1")
                return parentMetadata;
            if (path === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                return parentWorkflow;
            assert.fail(`Unexpected route ${path}`);
        },
    };
    await assert.rejects(
        parentPublicationResult(api, "42-1", fixture(), {
            wait: async () => waits++,
        }),
        /jobs unavailable/,
    );
    assert.equal(jobs, 1);
    assert.equal(waits, 0);
});

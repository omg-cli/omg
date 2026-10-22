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
                if (route === "/repos/omg-cli/omg/actions/runs/42") return prior;
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

test("recovery uses the direct current run attempt instead of stale list attempt metadata", async () => {
    const title = testAuditRunTitle("initial", a, 3);
    const listRun = {
        id: 42,
        run_attempt: 1,
        status: "completed",
        display_title: title,
        head_sha: a,
        head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const current = {
        ...listRun,
        run_attempt: 2,
        event: "workflow_dispatch",
        workflow_id: 391232924,
    };
    const workflow = {
        id: 391232924,
        name: "AI source review",
        path: ".github/workflows/ai-review.yml",
    };
    const reports = {
        "42-1": {
            ...fixture(),
            campaignRun: { runId: "42", attempt: "1" },
        },
        "42-2": {
            ...fixture(),
            campaignRun: { runId: "42", attempt: "2" },
        },
    };
    const jobs = {
        jobs: [
            { name: "review", status: "completed", conclusion: "success" },
            { name: "publish", status: "completed", conclusion: "skipped" },
        ],
    };
    const loads = [];
    const dispatched = [];
    const github = {
        async request(method, route) {
            assert.equal(method, "GET");
            if (route.includes("head_sha=")) return { workflow_runs: [] };
            if (route === "/repos/omg-cli/omg/actions/runs/42") return current;
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                return workflow;
            if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/1")
                return { ...current, run_attempt: 1 };
            if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/2")
                return current;
            if (
                route ===
                "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100"
            )
                return jobs;
            if (
                route ===
                "/repos/omg-cli/omg/actions/runs/42/attempts/2/jobs?per_page=100"
            )
                return jobs;
            if (route.includes("/runs?event=workflow_dispatch"))
                return { workflow_runs: [listRun] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
    const result = await recoverTestAuditCampaign({
        github,
        currentSha: b,
        revision: controller,
        manifestDigest: manifest,
        currentRunId: "50",
        loadRecord: async (ref) => {
            loads.push(ref);
            return reports[ref];
        },
        dispatch: async (inputs) => dispatched.push(inputs),
    });
    assert.equal(result.status, "dispatched");
    assert.deepEqual(loads, ["42-2"]);
    assert.equal(dispatched.length, 1);
    assert.equal(dispatched[0].audit_parent, "42-2");
    assert.equal(dispatched[0].audit_resnapshot, "true");
});

test("recovery holds a live direct run despite a stale terminal list row", async () => {
    const title = testAuditRunTitle("initial", a, 3);
    const listRun = {
        id: 42,
        run_attempt: 1,
        status: "completed",
        display_title: title,
        head_sha: a,
        head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const current = {
        ...listRun,
        status: "in_progress",
        event: "workflow_dispatch",
        workflow_id: 391232924,
    };
    const workflow = {
        id: 391232924,
        name: "AI source review",
        path: ".github/workflows/ai-review.yml",
    };
    const metadata = { ...current, run_attempt: 1 };
    const jobs = {
        jobs: [
            { name: "review", status: "completed", conclusion: "success" },
            { name: "publish", status: "completed", conclusion: "skipped" },
        ],
    };
    let loads = 0;
    let dispatches = 0;
    const github = {
        async request(method, route) {
            assert.equal(method, "GET");
            if (route === "/repos/omg-cli/omg/actions/runs/42") return current;
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                return workflow;
            if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/1")
                return metadata;
            if (
                route ===
                "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100"
            )
                return jobs;
            if (route.includes("/runs?event=workflow_dispatch"))
                return { workflow_runs: [listRun] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
    const result = await recoverTestAuditCampaign({
        github,
        currentSha: a,
        revision: controller,
        manifestDigest: manifest,
        currentRunId: "50",
        loadRecord: async () => {
            loads++;
            return fixture();
        },
        dispatch: async () => {
            dispatches++;
        },
    });
    assert.deepEqual(result, {
        status: "campaign-already-active",
        runId: "42",
    });
    assert.equal(loads, 0);
    assert.equal(dispatches, 0);
});

test("recovery rejects foreign or malformed direct run provenance without dispatch", async () => {
    const title = testAuditRunTitle("initial", a, 3);
    const listRun = {
        id: 42,
        run_attempt: 1,
        status: "completed",
        display_title: title,
        head_sha: a,
        head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const current = {
        ...listRun,
        event: "workflow_dispatch",
        workflow_id: 391232924,
    };
    const workflow = {
        id: 391232924,
        name: "AI source review",
        path: ".github/workflows/ai-review.yml",
    };
    const metadata = { ...current, run_attempt: 1 };
    const jobs = {
        jobs: [
            { name: "review", status: "completed", conclusion: "success" },
            { name: "publish", status: "completed", conclusion: "skipped" },
        ],
    };
    const attempt = async (direct, item = listRun, workflowOverride = workflow) => {
        let loads = 0;
        let dispatches = 0;
        const github = {
            async request(method, route) {
                assert.equal(method, "GET");
                if (route === "/repos/omg-cli/omg/actions/runs/42")
                    return direct;
                if (route === "/repos/omg-cli/omg/actions/runs/0")
                    return { ...direct, id: 0, run_attempt: 0 };
                if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                    return workflowOverride;
                if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/1")
                    return metadata;
                if (
                    route ===
                    "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100"
                )
                    return jobs;
                if (route.includes("/runs?event=workflow_dispatch"))
                    return { workflow_runs: [item] };
                assert.fail(`Unexpected route ${route}`);
            },
        };
        await assert.rejects(
            recoverTestAuditCampaign({
                github,
                currentSha: a,
                revision: controller,
                manifestDigest: manifest,
                currentRunId: "50",
                loadRecord: async () => {
                    loads++;
                    throw Object.assign(new Error("missing"), {
                        status: 404,
                    });
                },
                dispatch: async () => {
                    dispatches++;
                },
            }),
            /Campaign run (?:workflow )?identity/,
        );
        assert.equal(loads, 0);
        assert.equal(dispatches, 0);
    };
    await attempt({ ...current, repository: { full_name: "other/repo" } });
    await attempt({ ...current, workflow_id: 391232925 });
    await attempt({ ...current, head_sha: b });
    await attempt({ ...current, head_branch: "other" });
    await attempt({ ...current, run_attempt: 0 });
    await attempt(current, listRun, { ...workflow, name: "Other workflow" });
    await attempt(current, listRun, {
        ...workflow,
        path: ".github/workflows/other.yml",
    });
    await attempt(current, { ...listRun, id: 0 });
});

test("recovery dispatches a valid same-source terminal continuation from direct metadata", async () => {
    const title = testAuditRunTitle("initial", a, 3);
    const listRun = {
        id: 42,
        run_attempt: 1,
        status: "completed",
        display_title: title,
        head_sha: a,
        head_branch: "main",
        path: ".github/workflows/ai-review.yml",
        repository: { full_name: "omg-cli/omg" },
    };
    const current = {
        ...listRun,
        event: "workflow_dispatch",
        workflow_id: 391232924,
    };
    const workflow = {
        id: 391232924,
        name: "AI source review",
        path: ".github/workflows/ai-review.yml",
    };
    const report = fixture();
    const loads = [];
    const dispatched = [];
    const github = {
        async request(method, route) {
            assert.equal(method, "GET");
            if (route.includes("head_sha=")) return { workflow_runs: [] };
            if (route === "/repos/omg-cli/omg/actions/runs/42") return current;
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                return workflow;
            if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/1")
                return current;
            if (
                route ===
                "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100"
            )
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
                            conclusion: "skipped",
                        },
                    ],
                };
            if (route.includes("/runs?event=workflow_dispatch"))
                return { workflow_runs: [listRun] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
    const result = await recoverTestAuditCampaign({
        github,
        currentSha: a,
        revision: controller,
        manifestDigest: manifest,
        currentRunId: "50",
        loadRecord: async (ref) => {
            loads.push(ref);
            return report;
        },
        dispatch: async (inputs) => dispatched.push(inputs),
    });
    assert.equal(result.status, "dispatched");
    assert.deepEqual(loads, ["42-1"]);
    assert.equal(dispatched.length, 1);
    assert.equal(dispatched[0].audit_cursor, "4");
    assert.equal(dispatched[0].audit_sha, a);
    assert.equal(dispatched[0].audit_resnapshot, undefined);
    assert.equal(dispatched[0].audit_digest, report.sourceRange.inventoryDigest);
});

const missingTitle = testAuditRunTitle("99-1", a, 18);
const missingChild = (overrides = {}) => ({
    id: 42,
    run_attempt: 1,
    status: "completed",
    conclusion: "failure",
    display_title: missingTitle,
    head_sha: a,
    head_branch: "main",
    path: ".github/workflows/ai-review.yml",
    repository: { full_name: "omg-cli/omg" },
    event: "workflow_dispatch",
    workflow_id: 391232924,
    ...overrides,
});
const missingWorkflow = {
    id: 391232924,
    name: "AI source review",
    path: ".github/workflows/ai-review.yml",
};
const missingParentRun = () => ({
    id: 99,
    run_attempt: 1,
    status: "completed",
    conclusion: "success",
    head_sha: a,
    head_branch: "main",
    path: ".github/workflows/ai-review.yml",
    repository: { full_name: "omg-cli/omg" },
    event: "workflow_dispatch",
    workflow_id: 391232924,
});
const missingParent = () => ({
    campaignRun: { runId: "99", attempt: "1" },
    repository: "omg-cli/omg",
    branch: "main",
    sha: a,
    controllerRevision: controller,
    status: "reviewed",
    publishRequested: true,
    formatting: { status: "passed", sha: a, ref: "refs/heads/main", runId: "99", attempt: "1" },
    sourceRange: {
        kind: "test-audit",
        sha: a,
        manifestDigest: manifest,
        inventoryDigest: "e".repeat(64),
        cursor: 17,
        nextCursor: 18,
        pageSize: 1,
        pagePaths: 1,
        totalPaths: 40,
    },
    testAudits: [],
});
const missingIntent = () => ({
    repository: "omg-cli/omg",
    kind: "admission-retry-intent",
    runId: "42",
    attempt: "1",
    ownerRunId: "500",
    ownerAttempt: "1",
    parent: "99-1",
    sha: a,
    cursor: 18,
    controllerRevision: controller,
    manifestDigest: manifest,
});
function missingApi({ child }) {
    const calls = [];
    const jobs = {
        jobs: [
            { name: "review", status: "completed", conclusion: "success" },
            { name: "publish", status: "completed", conclusion: "skipped" },
        ],
    };
    return {
        calls,
        async request(method, route) {
            calls.push(`${method} ${route}`);
            assert.equal(method, "GET");
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml") return missingWorkflow;
            if (route === "/repos/omg-cli/omg/actions/runs/42") return child;
            if (route === "/repos/omg-cli/omg/actions/runs/99/attempts/1") return missingParentRun();
            if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/1") return { ...child, run_attempt: 1 };
            if (route === "/repos/omg-cli/omg/actions/runs/42/attempts/1/jobs?per_page=100") return jobs;
            if (route === "/repos/omg-cli/omg/actions/runs/99/attempts/1/jobs?per_page=100") return jobs;
            if (route.includes("head_sha=")) return { workflow_runs: [] };
            if (route.includes("/runs?event=workflow_dispatch")) return { workflow_runs: [child] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
}
const missingDeps = (child) => ({
    github: missingApi({ child }),
    loadRecord: async (ref) => {
        if (ref === "99-1") return missingParent();
        throw Object.assign(new Error("missing"), { status: 404 });
    },
    loadIntent: async () => {
        throw Object.assign(new Error("missing"), { status: 404 });
    },
    storeIntent: async () => ({ stored: true, created: true }),
    rerun: async () => {},
});
const recoverMissing = (overrides) =>
    recoverTestAuditCampaign({
        currentSha: a,
        revision: controller,
        manifestDigest: manifest,
        currentRunId: "500",
        currentRunAttempt: "1",
        dispatch: async () => {
            throw new Error("Recovery must not dispatch a new campaign");
        },
        ...overrides,
    });

test("missing child record reruns the same terminal run through its title-named parent", async () => {
    const child = missingChild();
    const api = missingApi({ child });
    const stored = [],
        reruns = [];
    const result = await recoverMissing({
        ...missingDeps(child),
        github: api,
        storeIntent: async (ref, body) => {
            stored.push([ref, body]);
            return { stored: true, created: true };
        },
        rerun: async (id) => reruns.push(id),
    });
    assert.equal(result.status, "campaign-recovery-rerun-requested");
    assert.deepEqual(reruns, ["42"]);
    assert.equal(stored.length, 1);
    assert.equal(stored[0][0], "42-1");
    assert.equal(stored[0][1].parent, "99-1");
    assert.equal(stored[0][1].cursor, 18);
    assert.equal(stored[0][1].ownerRunId, "500");
    assert.equal(stored[0][1].sha, a);
    assert.ok(api.calls.includes("GET /repos/omg-cli/omg/actions/runs/99/attempts/1"));
});

test("an identical durable intent does not authorize a second rerun", async () => {
    const child = missingChild();
    let reads = 0,
        reruns = 0;
    const result = await recoverMissing({
        ...missingDeps(child),
        loadIntent: async () => {
            reads++;
            if (reads === 1) throw Object.assign(new Error("missing"), { status: 404 });
            return missingIntent();
        },
        storeIntent: async () => ({ stored: true, created: false }),
        rerun: async () => reruns++,
    });
    assert.equal(result.status, "campaign-recovery-unknown");
    assert.equal(result.owner, "500-1");
    assert.equal(reruns, 0);
    assert.equal(reads, 2);
});

test("a competing claim that wins the conditional write blocks this run's rerun", async () => {
    const child = missingChild();
    let reads = 0,
        reruns = 0;
    const result = await recoverMissing({
        ...missingDeps(child),
        loadIntent: async () => {
            reads++;
            if (reads === 1) throw Object.assign(new Error("missing"), { status: 404 });
            return { ...missingIntent(), ownerRunId: "501" };
        },
        storeIntent: async () => ({ stored: true, created: false }),
        rerun: async () => reruns++,
    });
    assert.equal(result.status, "campaign-recovery-intent-conflict");
    assert.equal(result.owner, "501-1");
    assert.equal(reruns, 0);
});

test("a pre-existing competing intent blocks the rerun before parent work", async () => {
    const child = missingChild();
    let reruns = 0;
    const result = await recoverMissing({
        ...missingDeps(child),
        loadRecord: async (ref) => {
            if (ref === "42-1")
                throw Object.assign(new Error("missing"), { status: 404 });
            throw new Error("A competing intent is reconciled before parent reads");
        },
        loadIntent: async () => ({ ...missingIntent(), ownerRunId: "501" }),
        storeIntent: async () => {
            throw new Error("A competing intent must not be overwritten");
        },
        rerun: async () => reruns++,
    });
    assert.equal(result.status, "campaign-recovery-intent-conflict");
    assert.equal(result.owner, "501-1");
    assert.equal(reruns, 0);
});

test("concurrent same-owner recoveries issue at most one rerun", async () => {
    const child = missingChild();
    let intentRecord = null,
        reruns = 0;
    const loadIntent = async () => {
        if (!intentRecord) throw Object.assign(new Error("missing"), { status: 404 });
        return intentRecord;
    };
    const storeIntent = async (ref, body) => {
        assert.equal(ref, "42-1");
        if (intentRecord) return { stored: true, created: false };
        intentRecord = body;
        return { stored: true, created: true };
    };
    const run = () =>
        recoverMissing({
            ...missingDeps(child),
            loadIntent,
            storeIntent,
            rerun: async () => {
                reruns++;
            },
        });
    const results = await Promise.all([run(), run()]);
    assert.equal(reruns, 1);
    assert.deepEqual(results.map((result) => result.status).sort(), [
        "campaign-recovery-rerun-requested",
        "campaign-recovery-unknown",
    ]);
});

test("recovery holds every state it cannot prove", async () => {
    const cases = [
        [missingChild({ status: "in_progress", conclusion: null }), {}, "campaign-already-active", undefined],
        [missingChild({ run_attempt: 3 }), {}, "campaign-recovery-attempts-exhausted", undefined],
        [missingChild({ head_sha: b }), {}, "campaign-recovery-held", "recovery-lineage-mismatch"],
        [missingChild({ display_title: testAuditRunTitle("42-1", a, 18) }), {}, "campaign-recovery-held", "recovery-lineage-mismatch"],
        [missingChild(), { loadRecord: async (ref) => {
            if (ref === "42-1")
                throw Object.assign(new Error("missing"), { status: 404 });
            assert.equal(ref, "99-1");
            return { ...missingParent(), controllerRevision: "f".repeat(40) };
        } }, "campaign-recovery-held", "title-named-parent-lineage-mismatch"],
        [missingChild(), { loadRecord: async () => { throw Object.assign(new Error("missing"), { status: 404 }); } }, "campaign-recovery-held", "title-named-parent-record-missing"],
    ];
    for (const [child, overrides, status, reason] of cases) {
        let reruns = 0;
        const result = await recoverMissing({
            ...missingDeps(child),
            ...overrides,
            rerun: async () => {
                reruns++;
            },
        });
        assert.equal(result.status, status);
        assert.equal(result.reason, reason);
        assert.equal(reruns, 0);
    }
});

test("an unknown rerun outcome is recorded and never repeated blindly", async () => {
    const child = missingChild();
    let reruns = 0;
    const first = await recoverMissing({
        ...missingDeps(child),
        rerun: async () => {
            reruns++;
            throw new Error("network outcome unknown");
        },
    });
    assert.equal(first.status, "campaign-recovery-unknown");
    assert.equal(reruns, 1);
    const observed = await recoverMissing({
        ...missingDeps(child),
        loadIntent: async () => missingIntent(),
        storeIntent: async () => {
            throw new Error("An existing intent must not be rewritten");
        },
        rerun: async () => {
            reruns++;
        },
    });
    assert.equal(observed.status, "campaign-recovery-unknown");
    assert.equal(reruns, 1);
});

test("an existing durable proof record continues without any recovery intent", async () => {
    const child = missingChild();
    let intents = 0,
        dispatched = 0;
    const result = await recoverMissing({
        ...missingDeps(child),
        loadRecord: async () => fixture(),
        loadIntent: async () => {
            intents++;
            throw new Error("A durable record needs no intent");
        },
        storeIntent: async () => {
            throw new Error("A durable record needs no intent");
        },
        rerun: async () => {
            throw new Error("A durable record needs no rerun");
        },
        dispatch: async () => {
            dispatched++;
        },
    });
    assert.equal(result.status, "dispatched");
    assert.equal(dispatched, 1);
    assert.equal(intents, 0);
});

const rereadSequence = (child, observed) => {
    let reads = 0;
    return {
        reads: () => reads,
        async request(method, route) {
            assert.equal(method, "GET");
            if (route === "/repos/omg-cli/omg/actions/workflows/ai-review.yml")
                return missingWorkflow;
            if (route === "/repos/omg-cli/omg/actions/runs/42")
                return reads++ === 0 ? child : observed;
            if (route === "/repos/omg-cli/omg/actions/runs/99/attempts/1")
                return missingParentRun();
            if (
                route ===
                "/repos/omg-cli/omg/actions/runs/99/attempts/1/jobs?per_page=100"
            )
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
                            conclusion: "skipped",
                        },
                    ],
                };
            if (route.includes("/runs?event=workflow_dispatch"))
                return { workflow_runs: [child] };
            assert.fail(`Unexpected route ${route}`);
        },
    };
};

test("a stored intent from another controller or manifest is rejected before parent work", async () => {
    const child = missingChild();
    for (const drift of [
        { controllerRevision: "f".repeat(40) },
        { manifestDigest: "f".repeat(64) },
    ]) {
        let parentReads = 0,
            stores = 0,
            reruns = 0;
        await assert.rejects(
            recoverMissing({
                ...missingDeps(child),
                loadRecord: async (ref) => {
                    if (ref === "42-1")
                        throw Object.assign(new Error("missing"), {
                            status: 404,
                        });
                    parentReads++;
                    return missingParent();
                },
                loadIntent: async () => ({ ...missingIntent(), ...drift }),
                storeIntent: async () => {
                    stores++;
                    return { stored: true, created: true };
                },
                rerun: async () => {
                    reruns++;
                },
            }),
            /Recovery intent identity mismatch/,
        );
        assert.equal(parentReads, 0);
        assert.equal(stores, 0);
        assert.equal(reruns, 0);
    }
});

test("recovery reread rejects title, attempt, status and conclusion drift before any claim", async () => {
    const child = missingChild();
    const drifts = [
        { ...child, display_title: testAuditRunTitle("initial", a, 18) },
        { ...child, run_attempt: undefined },
        { ...child, run_attempt: 1000000 },
        { ...child, status: "mystery" },
        { ...child, status: "in_progress", conclusion: "failure" },
        { ...child, status: "completed", conclusion: null },
    ];
    for (const observed of drifts) {
        let stores = 0,
            reruns = 0;
        const api = rereadSequence(child, observed);
        await assert.rejects(
            recoverMissing({
                ...missingDeps(child),
                github: api,
                storeIntent: async () => {
                    stores++;
                    return { stored: true, created: true };
                },
                rerun: async () => {
                    reruns++;
                },
            }),
            /Campaign run workflow identity mismatch/,
        );
        assert.equal(api.reads(), 2);
        assert.equal(stores, 0);
        assert.equal(reruns, 0);
    }
});

test("a reconciled advanced attempt stays valid and never reruns", async () => {
    const child = missingChild();
    let stores = 0,
        reruns = 0;
    const api = rereadSequence(child, { ...child, run_attempt: 2 });
    const result = await recoverMissing({
        ...missingDeps(child),
        github: api,
        loadIntent: async () => missingIntent(),
        storeIntent: async () => {
            stores++;
            return { stored: true, created: true };
        },
        rerun: async () => {
            reruns++;
        },
    });
    assert.equal(result.status, "campaign-recovery-reconciled");
    assert.equal(result.current, "42-2");
    assert.equal(result.owner, "500-1");
    assert.equal(api.reads(), 2);
    assert.equal(stores, 0);
    assert.equal(reruns, 0);
});

const sha = /^[a-f0-9]{40}$/,
    digest = /^[a-f0-9]{64}$/,
    run = /^[1-9][0-9]{0,19}-[1-9][0-9]{0,5}$/;
export function testAuditRunTitle(parent, source, cursor) {
    return `Test audit ${parent || "initial"} ${source} ${cursor}`;
}
function checkRange(report) {
    const r = report.sourceRange;
    if (
        report.repository !== "omg-cli/omg" ||
        report.branch !== "main" ||
        !sha.test(report.sha) ||
        r?.kind !== "test-audit" ||
        !digest.test(r.manifestDigest ?? "") ||
        r.sha !== report.sha ||
        !Number.isSafeInteger(r.cursor) ||
        r.cursor < 0 ||
        !Number.isSafeInteger(r.totalPaths) ||
        r.totalPaths < 1 ||
        r.totalPaths > 10000 ||
        r.cursor >= r.totalPaths ||
        r.pageSize !== 1 ||
        r.pagePaths !== 1 ||
        r.nextCursor !== (r.cursor + 1 < r.totalPaths ? r.cursor + 1 : null)
    )
        throw new Error("Invalid campaign manifest or cursor identity");
    return r;
}
export function planTestAuditContinuation(
    report,
    currentSha,
    runId,
    attempt,
    publicationResult,
) {
    const r = checkRange(report),
        parent = `${runId}-${attempt}`;
    if (!sha.test(currentSha) || !run.test(parent))
        throw new Error("Invalid campaign source or parent");
    const strengthening = (report.testAudits ?? []).some(
        (audit) =>
            audit.request?.testAudit?.proposal?.purpose ===
            "existing-test-strengthening",
    );
    const confirmedPublication =
        publicationResult === "success" && report.publishRequested === true;
    const unpublished = strengthening && !confirmedPublication;
    const beforeInference = ["incomplete-stale", "format-blocked"].includes(
        report.status,
    );
    if (
        !["reviewed", "incomplete-stale", "format-blocked"].includes(
            report.status,
        )
    )
        return { status: "incomplete-review-blocked" };
    if (currentSha === report.sha) {
        if (beforeInference) return { status: "incomplete-review-blocked" };
        if (unpublished) return { status: "publication-unresolved" };
    }
    const resnapshot = currentSha !== report.sha;
    const cursor =
        resnapshot && (beforeInference || unpublished)
            ? r.cursor
            : r.nextCursor;
    if (cursor === null)
        return {
            status: "inventory-exhausted",
            qualification:
                "Completion refers to per-source historical attempts, not current whole-tree sensitivity coverage.",
        };
    const inputs = {
        branch: "main",
        scope: "test-audit",
        publish: String(report.publishRequested === true),
        audit_sha: currentSha,
        audit_cursor: String(cursor),
        audit_parent: parent,
        audit_manifest: r.manifestDigest,
        ...(resnapshot
            ? { audit_resnapshot: "true" }
            : { audit_digest: r.inventoryDigest }),
    };
    if (!resnapshot && !digest.test(r.inventoryDigest ?? ""))
        throw new Error("Campaign inventory digest missing");
    return {
        status: "continue",
        inputs,
        resnapshot,
        priorUnpublished: unpublished,
        qualification: resnapshot
            ? "Prior results remain bound to their original source. This dispatch re-inventories current main."
            : "Exact immutable inventory continuation.",
    };
}
export function admitTestAuditParent(
    target,
    parent,
    revision,
    manifestDigest,
    publicationResult,
) {
    const r = checkRange(parent);
    if (
        `${parent.campaignRun?.runId}-${parent.campaignRun?.attempt}` !==
            target.auditParent ||
        !run.test(target.auditParent ?? "") ||
        parent.controllerRevision !== revision ||
        r.manifestDigest !== manifestDigest ||
        target.range?.manifestDigest !== manifestDigest ||
        target.branch !== "main" ||
        target.publish !== parent.publishRequested
    )
        throw new Error("Campaign parent/controller/manifest mismatch");
    const [runId, attempt] = target.auditParent.split("-");
    const plan = planTestAuditContinuation(
        parent,
        target.sha,
        runId,
        attempt,
        publicationResult,
    );
    if (
        plan.status !== "continue" ||
        Number(plan.inputs.audit_cursor) !== target.range.cursor ||
        Boolean(plan.resnapshot) !== Boolean(target.range.resnapshot)
    )
        throw new Error(
            "Campaign parent did not authorize this cursor or source",
        );
    if (plan.resnapshot)
        return {
            ...target,
            upstream: undefined,
            range: {
                ...target.range,
                inventoryDigest: undefined,
                resnapshotOf: {
                    runId,
                    attempt,
                    sha: parent.sha,
                    cursor: r.cursor,
                    priorUnpublished: plan.priorUnpublished,
                },
                qualification: plan.qualification,
            },
        };
    if (
        parent.sha !== target.sha ||
        r.inventoryDigest !== target.range.inventoryDigest
    )
        throw new Error("Campaign immutable inventory mismatch");
    if (parent.formatting?.status !== "passed") return target;
    if (
        parent.formatting.sha !== target.sha ||
        parent.formatting.ref !== "refs/heads/main" ||
        !/^[1-9][0-9]{0,19}$/.test(parent.formatting.runId ?? "") ||
        !/^[1-9][0-9]{0,5}$/.test(parent.formatting.attempt ?? "")
    )
        throw new Error("Campaign formatting source mismatch");
    return {
        ...target,
        upstream: {
            runId: parent.formatting.runId,
            attempt: parent.formatting.attempt,
        },
    };
}
export async function listTestAuditChildren(
    github,
    { sha: source, parent, cursor, currentRunId },
) {
    const title = testAuditRunTitle(parent, source, cursor);
    const response = await github.request(
        "GET",
        `/repos/omg-cli/omg/actions/workflows/ai-review.yml/runs?event=workflow_dispatch&head_sha=${source}&per_page=100`,
    );
    if (!Array.isArray(response.workflow_runs))
        throw new Error("Workflow inventory unavailable for campaign dedupe");
    return response.workflow_runs.filter(
        (item) =>
            String(item.id) !== String(currentRunId) &&
            item.display_title === title &&
            item.head_sha === source &&
            item.head_branch === "main" &&
            item.path === ".github/workflows/ai-review.yml" &&
            item.repository?.full_name === "omg-cli/omg",
    );
}
export function admitDuplicateTestAudit(
    record,
    target,
    revision,
    manifestDigest,
) {
    return (
        record?.controllerRevision === revision &&
        record.repository === "omg-cli/omg" &&
        record.branch === "main" &&
        record.sha === target.sha &&
        record.sourceRange?.kind === "test-audit" &&
        record.sourceRange.manifestDigest === manifestDigest &&
        record.sourceRange.cursor === target.range.cursor &&
        record.campaignParent === (target.auditParent ?? null) &&
        record.status !== "duplicate-noop"
    );
}
export function testAuditTarget(input) {
    const cursor = Number(input.audit_cursor || "0"),
        resnapshot =
            input.audit_resnapshot === true ||
            input.audit_resnapshot === "true";
    if (
        input.branch !== "main" ||
        ![undefined, false, true, "false", "true", ""].includes(
            input.audit_resnapshot,
        ) ||
        !Number.isSafeInteger(cursor) ||
        cursor < 0 ||
        cursor >= 10000
    )
        throw new Error("Invalid campaign input");
    const hasParent = Boolean(input.audit_parent);
    if (resnapshot) {
        if (
            !run.test(input.audit_parent ?? "") ||
            !sha.test(input.audit_sha ?? "") ||
            !digest.test(input.audit_manifest ?? "") ||
            input.audit_digest
        )
            throw new Error("Resnapshot requires exact parent/source/manifest");
    } else if (cursor === 0) {
        if (
            hasParent ||
            input.audit_sha ||
            input.audit_digest ||
            input.audit_manifest
        )
            throw new Error(
                "Initial campaign cannot inject an immutable cursor identity",
            );
    } else if (
        !run.test(input.audit_parent ?? "") ||
        !sha.test(input.audit_sha ?? "") ||
        !digest.test(input.audit_manifest ?? "") ||
        !digest.test(input.audit_digest ?? "")
    )
        throw new Error(
            "Campaign continuation requires exact immutable parent identity",
        );
    return {
        branch: "main",
        sha: hasParent ? input.audit_sha : null,
        publish: input.publish === true || input.publish === "true",
        range: {
            kind: "test-audit",
            cursor,
            ...(input.audit_digest
                ? { inventoryDigest: input.audit_digest }
                : {}),
            ...(input.audit_manifest
                ? { manifestDigest: input.audit_manifest }
                : {}),
            ...(resnapshot ? { resnapshot: true } : {}),
        },
        ...(hasParent ? { auditParent: input.audit_parent } : {}),
    };
}
export async function parentPublicationResult(
    github,
    parentRef,
    report,
    { wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) } = {},
) {
    if (
        !run.test(parentRef) ||
        `${report.campaignRun?.runId}-${report.campaignRun?.attempt}` !==
            parentRef
    )
        throw new Error("Invalid parent attempt");
    const [id, attempt] = parentRef.split("-");
    const [metadata, workflow] = await Promise.all([
        github.request("GET", `/repos/omg-cli/omg/actions/runs/${id}/attempts/${attempt}`),
        github.request("GET", "/repos/omg-cli/omg/actions/workflows/ai-review.yml"),
    ]);
    if (
        String(metadata.id) !== id ||
        metadata.run_attempt !== Number(attempt) ||
        metadata.head_sha !== (report.triggerSha ?? report.sha) ||
        metadata.head_branch !== "main" ||
        metadata.path !== ".github/workflows/ai-review.yml" ||
        !Number.isSafeInteger(workflow.id) || workflow.id < 1 ||
        metadata.workflow_id !== workflow.id ||
        workflow.path !== ".github/workflows/ai-review.yml" ||
        workflow.name !== "AI source review" ||
        metadata.repository?.full_name !== "omg-cli/omg" ||
        !["workflow_dispatch", "schedule"].includes(metadata.event)
    )
        throw new Error("Campaign parent workflow identity mismatch");
    const retryDelaysMs = [1000, 2000, 4000, 8000, 14000];
    const describe = (jobs) =>
        jobs.length
            ? jobs
                  .map(
                      (job) =>
                          `${job?.status ?? "unknown"}/${job?.conclusion ?? "none"}`,
                  )
                  .join(",")
            : "missing";
    for (let retry = 0; ; retry++) {
        const result = await github.request(
            "GET",
            `/repos/omg-cli/omg/actions/runs/${id}/attempts/${attempt}/jobs?per_page=100`,
        );
        if (!Array.isArray(result.jobs))
            throw new Error("Campaign parent jobs inventory unavailable");
        const reviews = result.jobs.filter((job) => job?.name === "review"),
            publish = result.jobs.filter((job) => job?.name === "publish");
        if (reviews.length > 1 || publish.length > 1)
            throw new Error("Campaign parent job identity is ambiguous");
        if (reviews.length === 1 && reviews[0].status === "completed") {
            if (reviews[0].conclusion !== "success")
                throw new Error(
                    `Campaign parent review did not succeed: ${describe(reviews)}`,
                );
            if (publish.length === 1 && publish[0].status === "completed") {
                if (
                    ![
                        "success",
                        "skipped",
                        "failure",
                        "cancelled",
                        "timed_out",
                    ].includes(publish[0].conclusion)
                )
                    throw new Error(
                        `Campaign parent publish conclusion is not accepted: ${describe(publish)}`,
                    );
                return publish[0].conclusion;
            }
        }
        const observed = `review=${describe(reviews)} publish=${describe(publish)}`;
        if (retry >= retryDelaysMs.length)
            throw new Error(
                `Campaign parent jobs are not terminal after bounded wait: ${observed}`,
            );
        await wait(retryDelaysMs[retry]);
    }
}
export async function dispatchTestAuditPlan({
    github,
    plan,
    dispatch,
    currentRunId,
}) {
    if (plan.status !== "continue") return plan;
    const inputs = plan.inputs;
    const children = await listTestAuditChildren(github, {
        sha: inputs.audit_sha,
        parent: inputs.audit_parent,
        cursor: Number(inputs.audit_cursor),
        currentRunId,
    });
    if (children.length)
        return {
            status: "existing-child",
            runIds: children.map((item) => String(item.id)),
            qualification: plan.qualification,
        };
    await dispatch(inputs);
    return { ...plan, status: "dispatched" };
}
export async function recoverTestAuditCampaign({
    github,
    currentSha,
    revision,
    manifestDigest,
    loadRecord,
    dispatch,
    currentRunId,
}) {
    for (let page = 1; page <= 5; page++) {
        const response = await github.request(
            "GET",
            `/repos/omg-cli/omg/actions/workflows/ai-review.yml/runs?event=workflow_dispatch&branch=main&per_page=100&page=${page}`,
        );
        if (!Array.isArray(response.workflow_runs))
            throw new Error("Campaign recovery workflow inventory unavailable");
        for (const item of response.workflow_runs) {
            if (
                !/^Test audit (?:initial|[1-9][0-9]{0,19}-[1-9][0-9]{0,5}) [a-f0-9]{40} [0-9]+$/.test(
                    item.display_title ?? "",
                )
            )
                continue;
            if (
                item.head_branch !== "main" ||
                item.path !== ".github/workflows/ai-review.yml" ||
                item.repository?.full_name !== "omg-cli/omg"
            )
                continue;
            if (item.status !== "completed")
                return {
                    status: "campaign-already-active",
                    runId: String(item.id),
                };
            const parentRef = `${item.id}-${item.run_attempt}`;
            let report;
            try {
                report = await loadRecord(parentRef);
            } catch (error) {
                if (error.status === 404)
                    return {
                        status: "campaign-record-missing",
                        parent: parentRef,
                    };
                throw error;
            }
            if (report.status === "duplicate-noop") continue;
            if (
                report.controllerRevision !== revision ||
                report.sourceRange?.manifestDigest !== manifestDigest
            )
                return {
                    status: "campaign-controller-or-manifest-held",
                    parent: parentRef,
                };
            const publicationResult = await parentPublicationResult(
                github,
                parentRef,
                report,
            );
            const plan = planTestAuditContinuation(
                report,
                currentSha,
                String(item.id),
                String(item.run_attempt),
                publicationResult,
            );
            return dispatchTestAuditPlan({
                github,
                plan,
                dispatch,
                currentRunId,
            });
        }
        if (response.workflow_runs.length < 100)
            return {
                status: "campaign-history-not-found",
                qualification:
                    "No initial campaign was found. Recovery does not start over or infer completion.",
            };
    }
    return {
        status: "campaign-lookback-exhausted",
        qualification:
            "Five pages of 100 manual workflow dispatches were searched. Recovery is held without model calls or invented progress.",
    };
}
export async function findDuplicateTestAuditRecord({
    github,
    target,
    revision,
    manifestDigest,
    currentRunId,
    loadRecord,
}) {
    const candidates = await listTestAuditChildren(github, {
        sha: target.sha,
        parent: target.auditParent,
        cursor: target.range.cursor,
        currentRunId,
    });
    for (const prior of candidates) {
        let record;
        try {
            record = await loadRecord(`${prior.id}-${prior.run_attempt}`);
        } catch (error) {
            if (error.status === 404) continue;
            throw error;
        }
        if (admitDuplicateTestAudit(record, target, revision, manifestDigest))
            return {
                runId: String(prior.id),
                attempt: String(prior.run_attempt),
            };
    }
    return null;
}

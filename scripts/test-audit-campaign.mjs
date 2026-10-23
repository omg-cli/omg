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
function shape(value, required, optional = []) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const keys = Object.keys(value);
    return required.every((key) => Object.hasOwn(value, key)) &&
        keys.every((key) => required.includes(key) || optional.includes(key)) &&
        keys.length <= required.length + optional.length;
}
const absentOrEmpty = (value) =>
    value === undefined || (Array.isArray(value) && value.length === 0);
const sameFormat = (formatting, expected) =>
    formatting?.runId === expected.runId &&
    formatting?.attempt === expected.attempt &&
    formatting?.sha === expected.sha &&
    formatting?.ref === expected.ref;
function transitionIntake(target, parent, revision, manifestDigest, campaign) {
    const t = campaign?.transition,
        child = campaign?.priorChild,
        parentRef = `${parent.campaignRun?.runId}-${parent.campaignRun?.attempt}`,
        childRef = `${child?.campaignRun?.runId}-${child?.campaignRun?.attempt}`;
    if (!shape(t, ["kind","repository","enabled","source","branch","publish","parent","parentController","priorChild","run","cursor","pageSize","pagePaths","totalPaths","manifestDigest","inventoryDigest","priorFormatting","priorImageDigest","imageDigest","verifierRevision","controllerRevision","recordSha256"]))
        throw new Error("Campaign transition record missing or inferred");
    if (t.kind !== "test-audit-controller-transition" || t.repository !== "omg-cli/omg" || t.enabled !== true)
        throw new Error("Campaign transition record is not enabled");
    if (!sha.test(revision ?? "") || t.branch !== "main" || t.publish !== true ||
        !sha.test(t.source ?? "") || t.controllerRevision !== revision ||
        !digest.test(t.recordSha256 ?? "") || !sha.test(t.verifierRevision ?? "") ||
        !digest.test(t.manifestDigest ?? "") || !digest.test(t.inventoryDigest ?? "") ||
        t.manifestDigest !== manifestDigest || target.range?.manifestDigest !== manifestDigest ||
        target.branch !== "main" || target.publish !== true)
        throw new Error("Campaign transition controller or manifest mismatch");
    if (!run.test(parentRef) || !run.test(childRef) || parentRef !== t.parent ||
        parent.controllerRevision !== t.parentController || parent.status !== "reviewed" ||
        parent.sha !== t.source || target.sha !== t.source || target.auditParent !== t.parent ||
        childRef !== t.priorChild)
        throw new Error("Campaign transition parent or prior child lineage mismatch");
    if (!shape(child, ["repository","sha","branch","baseSha","batches","campaignParent","campaignRun","candidateOutcomes","controllerRevision","coverageMeaning","formatting","publications","publishRequested","readPaths","sourceRange","status","suppliedPaths","triggerSha","unreviewedPaths"], ["testAudits","testAuditOutcomes"]) ||
        child.repository !== "omg-cli/omg" || child.branch !== "main" ||
        child.status !== "format-blocked" || child.sha !== t.source ||
        child.baseSha !== t.source || child.triggerSha !== t.source ||
        child.controllerRevision !== t.parentController || child.campaignParent !== parentRef ||
        child.publishRequested !== true || !absentOrEmpty(child.testAudits) ||
        !absentOrEmpty(child.testAuditOutcomes) ||
        ![child.batches, child.candidateOutcomes, child.publications, child.readPaths, child.suppliedPaths].every((value) => Array.isArray(value) && value.length === 0))
        throw new Error("Campaign prior child record shape or proof mismatch");
    if (campaign?.runId !== child.campaignRun?.runId || campaign?.attempt === child.campaignRun?.attempt ||
        campaign?.attempt === t.priorFormatting?.attempt || t.run !== `${campaign?.runId}-${campaign?.attempt}` ||
        campaign?.imageDigest !== t.imageDigest || campaign?.verifierRevision !== t.verifierRevision)
        throw new Error("Campaign transition current run identity mismatch");
    if (!Number.isSafeInteger(t.cursor) || t.cursor < 1 || t.cursor >= t.totalPaths - 1 ||
        t.pageSize !== 1 || t.pagePaths !== 1 || !Number.isSafeInteger(t.totalPaths) ||
        t.totalPaths < 3 || t.totalPaths > 10000 ||
        parent.sourceRange?.kind !== "test-audit" || parent.sourceRange?.sha !== t.source ||
        parent.sourceRange?.manifestDigest !== t.manifestDigest ||
        parent.sourceRange?.inventoryDigest !== t.inventoryDigest ||
        parent.sourceRange?.cursor + 1 !== t.cursor || parent.sourceRange?.nextCursor !== t.cursor ||
        parent.sourceRange?.pageSize !== 1 || parent.sourceRange?.pagePaths !== 1 ||
        parent.sourceRange?.totalPaths !== t.totalPaths ||
        child.sourceRange?.kind !== "test-audit" || child.sourceRange?.sha !== t.source ||
        child.sourceRange?.manifestDigest !== t.manifestDigest ||
        child.sourceRange?.inventoryDigest !== t.inventoryDigest ||
        child.sourceRange?.cursor !== t.cursor || child.sourceRange?.nextCursor !== t.cursor + 1 ||
        child.sourceRange?.pageSize !== 1 || child.sourceRange?.pagePaths !== 1 ||
        child.sourceRange?.totalPaths !== t.totalPaths ||
        target.range?.cursor !== t.cursor || target.range?.inventoryDigest !== t.inventoryDigest ||
        target.range?.resnapshot === true)
        throw new Error("Campaign transition page or inventory mismatch");
    if (!shape(t.priorFormatting, ["runId","attempt","sha","ref"]) ||
        !/^[1-9][0-9]{0,19}$/.test(t.priorFormatting.runId ?? "") ||
        !/^[1-9][0-9]{0,5}$/.test(t.priorFormatting.attempt ?? "") ||
        t.priorFormatting.sha !== t.source || t.priorFormatting.ref !== "refs/heads/main" ||
        parent.formatting?.status !== "passed" || !sameFormat(parent.formatting, t.priorFormatting) ||
        child.formatting?.status !== "blocked" ||
        child.formatting?.reason !== "source-format-evidence-unavailable-or-rejected" ||
        !sameFormat(child.formatting, t.priorFormatting))
        throw new Error("Campaign transition formatting lineage mismatch");
    if (!/^sha256:[a-f0-9]{64}$/.test(t.imageDigest ?? "") ||
        !/^sha256:[a-f0-9]{64}$/.test(t.priorImageDigest ?? "") ||
        t.imageDigest === t.priorImageDigest)
        throw new Error("Campaign transition runtime identity mismatch");
    if (!Array.isArray(child.unreviewedPaths) || child.unreviewedPaths.length !== 1 ||
        !shape(child.unreviewedPaths[0], ["path","reason"]) ||
        child.unreviewedPaths[0].path !== "tests/debian_tests.rs" ||
        child.unreviewedPaths[0].reason !== "source-format-blocked")
        throw new Error("Campaign prior child blocked path mismatch");
    return { from: parent.controllerRevision, to: revision, recordSha256: t.recordSha256, parent: parentRef, priorChild: childRef, run: t.run };
}
export function admitTestAuditParent(target, parent, revision, manifestDigest, publicationResult, campaign) {
    const r = checkRange(parent);
    const transition = campaign?.transition === undefined ? null : transitionIntake(target, parent, revision, manifestDigest, campaign);
    if (transition === null) {
        if (`${parent.campaignRun?.runId}-${parent.campaignRun?.attempt}` !== target.auditParent ||
            !run.test(target.auditParent ?? "") || parent.controllerRevision !== revision ||
            r.manifestDigest !== manifestDigest || target.range?.manifestDigest !== manifestDigest ||
            target.branch !== "main" || target.publish !== parent.publishRequested)
            throw new Error("Campaign parent/controller/manifest mismatch");
    } else if (r.manifestDigest !== manifestDigest || target.range?.manifestDigest !== manifestDigest ||
        target.branch !== "main" || target.publish !== parent.publishRequested)
        throw new Error("Campaign parent/controller/manifest mismatch");
    const [runId, attempt] = target.auditParent.split("-");
    const plan = planTestAuditContinuation(parent, target.sha, runId, attempt, publicationResult);
    if (plan.status !== "continue" || Number(plan.inputs.audit_cursor) !== target.range.cursor ||
        Boolean(plan.resnapshot) !== Boolean(target.range.resnapshot))
        throw new Error("Campaign parent did not authorize this cursor or source");
    if (plan.resnapshot)
        return {
            ...target,
            upstream: undefined,
            range: {
                ...target.range,
                inventoryDigest: undefined,
                resnapshotOf: { runId, attempt, sha: parent.sha, cursor: r.cursor, priorUnpublished: plan.priorUnpublished },
                qualification: plan.qualification,
            },
        };
    if (parent.sha !== target.sha || r.inventoryDigest !== target.range.inventoryDigest)
        throw new Error("Campaign immutable inventory mismatch");
    if (parent.formatting?.status !== "passed") return target;
    if (parent.formatting.sha !== target.sha || parent.formatting.ref !== "refs/heads/main" ||
        !/^[1-9][0-9]{0,19}$/.test(parent.formatting.runId ?? "") ||
        !/^[1-9][0-9]{0,5}$/.test(parent.formatting.attempt ?? ""))
        throw new Error("Campaign formatting source mismatch");
    const admitted = { ...target, upstream: { runId: parent.formatting.runId, attempt: parent.formatting.attempt } };
    return transition === null ? admitted : { ...admitted, controllerTransition: transition };
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
export const MAX_RECOVERY_ATTEMPTS = 3;
export function missingRecordIntent({
    title,
    child,
    revision,
    manifestDigest,
    ownerRunId,
    ownerAttempt,
}) {
    const match =
        /^Test audit ([1-9][0-9]{0,19}-[1-9][0-9]{0,5}) ([a-f0-9]{40}) ([0-9]+)$/.exec(
            title ?? "",
        );
    if (!match) return { held: "recovery-requires-title-named-parent" };
    const [, parent, source, cursorText] = match;
    const cursor = Number(cursorText);
    const childRef = `${child.id}-${child.run_attempt}`;
    if (
        !run.test(parent) ||
        parent === childRef ||
        parent.split("-")[0] === String(child.id) ||
        source !== child.head_sha
    )
        return { held: "recovery-lineage-mismatch" };
    if (!Number.isSafeInteger(cursor) || cursor < 1)
        return { held: "recovery-cursor-mismatch" };
    if (
        !run.test(`${ownerRunId}-${ownerAttempt}`) ||
        !sha.test(source) ||
        !sha.test(revision) ||
        !digest.test(manifestDigest)
    )
        throw new Error("Invalid recovery intent identity");
    return {
        intent: {
            repository: "omg-cli/omg",
            kind: "admission-retry-intent",
            runId: String(child.id),
            attempt: String(child.run_attempt),
            ownerRunId,
            ownerAttempt,
            parent,
            sha: source,
            cursor,
            controllerRevision: revision,
            manifestDigest,
        },
    };
}
export async function recoverMissingTestAuditRecord({
    github,
    child,
    title,
    revision,
    manifestDigest,
    ownerRunId,
    ownerAttempt,
    loadRecord,
    loadIntent,
    storeIntent,
    rerun,
}) {
    if (
        ![loadRecord, loadIntent, storeIntent, rerun].every(
            (fn) => typeof fn === "function",
        )
    )
        throw new Error(
            "Missing-record recovery requires parent, intent storage and rerun callers",
        );
    const parentRef = `${child.id}-${child.run_attempt}`;
    if (child.status !== "completed")
        return { status: "campaign-already-active", runId: String(child.id) };
    if (!["failure", "cancelled", "timed_out"].includes(child.conclusion))
        return {
            status: "campaign-recovery-held",
            parent: parentRef,
            reason: "missing-record-attempt-is-not-a-failed-attempt",
        };
    if (Number(child.run_attempt) >= MAX_RECOVERY_ATTEMPTS)
        return {
            status: "campaign-recovery-attempts-exhausted",
            parent: parentRef,
        };
    const planned = missingRecordIntent({
        title,
        child,
        revision,
        manifestDigest,
        ownerRunId,
        ownerAttempt,
    });
    if (planned.held)
        return {
            status: "campaign-recovery-held",
            parent: parentRef,
            reason: planned.held,
        };
    const intent = planned.intent;
    const owner = `${ownerRunId}-${ownerAttempt}`;
    const reread = async () => {
        const [metadata, workflow] = await Promise.all([
            github.request("GET", `/repos/omg-cli/omg/actions/runs/${child.id}`),
            github.request(
                "GET",
                "/repos/omg-cli/omg/actions/workflows/ai-review.yml",
            ),
        ]);
        if (
            String(metadata.id) !== String(child.id) ||
            metadata.head_sha !== intent.sha ||
            metadata.head_branch !== "main" ||
            metadata.path !== ".github/workflows/ai-review.yml" ||
            metadata.repository?.full_name !== "omg-cli/omg" ||
            metadata.display_title !== title ||
            metadata.event !== "workflow_dispatch" ||
            !Number.isSafeInteger(metadata.run_attempt) ||
            metadata.run_attempt < 1 ||
            metadata.run_attempt > 999999 ||
            ![
                "queued",
                "in_progress",
                "completed",
                "requested",
                "waiting",
                "pending",
            ].includes(metadata.status) ||
            (metadata.status === "completed"
                ? ![
                      "success",
                      "failure",
                      "cancelled",
                      "timed_out",
                      "action_required",
                      "neutral",
                      "skipped",
                      "stale",
                  ].includes(metadata.conclusion)
                : metadata.conclusion != null) ||
            !Number.isSafeInteger(workflow.id) ||
            workflow.id < 1 ||
            metadata.workflow_id !== workflow.id ||
            workflow.path !== ".github/workflows/ai-review.yml" ||
            workflow.name !== "AI source review"
        )
            throw new Error("Campaign run workflow identity mismatch");
        return metadata;
    };
    const reconcile = async (existing) => {
        if (
            existing.kind !== "admission-retry-intent" ||
            existing.repository !== "omg-cli/omg" ||
            existing.runId !== String(child.id) ||
            existing.attempt !== String(child.run_attempt) ||
            existing.parent !== intent.parent ||
            existing.sha !== intent.sha ||
            existing.cursor !== intent.cursor ||
            existing.controllerRevision !== revision ||
            existing.manifestDigest !== manifestDigest
        )
            throw new Error("Recovery intent identity mismatch");
        const observed = await reread();
        const priorOwner = `${existing.ownerRunId}-${existing.ownerAttempt}`;
        if (
            Number(observed.run_attempt) > Number(child.run_attempt) ||
            observed.status !== "completed"
        )
            return {
                status: "campaign-recovery-reconciled",
                parent: parentRef,
                current: `${observed.id}-${observed.run_attempt}`,
                owner: priorOwner,
            };
        if (priorOwner !== owner)
            return {
                status: "campaign-recovery-intent-conflict",
                parent: parentRef,
                owner: priorOwner,
                qualification:
                    "Another recovery attempt owns the durable rerun intent. This run does not issue a second rerun.",
            };
        return {
            status: "campaign-recovery-unknown",
            parent: parentRef,
            owner: priorOwner,
            qualification:
                "This run already won the durable intent but the child attempt did not advance. The earlier POST outcome is unknown and is not repeated.",
        };
    };
    let existing = null;
    try {
        existing = await loadIntent(parentRef);
    } catch (error) {
        if (error.status !== 404) throw error;
    }
    if (existing) return reconcile(existing);
    let parentRecord;
    try {
        parentRecord = await loadRecord(intent.parent);
    } catch (error) {
        if (error.status === 404)
            return {
                status: "campaign-recovery-held",
                parent: parentRef,
                reason: "title-named-parent-record-missing",
            };
        throw error;
    }
    if (
        parentRecord.repository !== "omg-cli/omg" ||
        parentRecord.branch !== "main" ||
        parentRecord.controllerRevision !== revision ||
        parentRecord.sourceRange?.manifestDigest !== manifestDigest
    )
        return {
            status: "campaign-recovery-held",
            parent: parentRef,
            reason: "title-named-parent-lineage-mismatch",
        };
    let publicationResult;
    try {
        publicationResult = await parentPublicationResult(
            github,
            intent.parent,
            parentRecord,
        );
    } catch (error) {
        return {
            status: "campaign-recovery-held",
            parent: parentRef,
            reason: "title-named-parent-not-terminal-successful",
            qualification:
                error instanceof Error
                    ? error.message
                    : "Parent review or publication is not terminal.",
        };
    }
    const plan = planTestAuditContinuation(
        parentRecord,
        intent.sha,
        ...intent.parent.split("-"),
        publicationResult,
    );
    if (
        plan.status !== "continue" ||
        Number(plan.inputs.audit_cursor) !== intent.cursor ||
        plan.inputs.audit_parent !== intent.parent
    )
        return {
            status: "campaign-recovery-held",
            parent: parentRef,
            reason: "title-named-parent-did-not-authorize-this-cursor",
        };
    const current = await reread();
    if (
        current.status !== "completed" ||
        Number(current.run_attempt) !== Number(child.run_attempt) ||
        !["failure", "cancelled", "timed_out"].includes(current.conclusion)
    )
        return {
            status: "campaign-recovery-held",
            parent: parentRef,
            reason: "child-state-changed-before-mutation",
        };
    let won;
    try {
        won = await storeIntent(parentRef, intent);
    } catch (error) {
        if (error.status === 409)
            return {
                status: "campaign-recovery-intent-conflict",
                parent: parentRef,
                owner,
            };
        throw error;
    }
    if (won?.stored !== true)
        throw new Error("Recovery intent was not acknowledged");
    if (won.created !== true) {
        let claimed = null;
        try {
            claimed = await loadIntent(parentRef);
        } catch (error) {
            if (error.status !== 404) throw error;
        }
        if (claimed) return reconcile(claimed);
        return {
            status: "campaign-recovery-intent-held",
            parent: parentRef,
            owner,
            qualification:
                "The durable intent already existed but could not be read back, so this run does not issue a second rerun.",
        };
    }
    try {
        await rerun(String(child.id));
    } catch {
        return {
            status: "campaign-recovery-unknown",
            parent: parentRef,
            owner,
            qualification:
                "The rerun request outcome is unknown. The durable intent prevents a blind repeat; the next recovery reconciles the child attempt.",
        };
    }
    return {
        status: "campaign-recovery-rerun-requested",
        parent: parentRef,
        owner,
        qualification:
            "GitHub's rerun endpoint has no compare-and-swap. A concurrent rerun between the recheck and this request can advance the attempt first; the next recovery reconciles by attempt identity.",
    };
}
export async function recoverTestAuditCampaign({
    github,
    currentSha,
    revision,
    manifestDigest,
    loadRecord,
    dispatch,
    currentRunId,
    currentRunAttempt,
    loadIntent,
    storeIntent,
    rerun,
}) {
    const currentCampaignRun = async (item) => {
        const id = String(item.id ?? "");
        if (!/^[1-9][0-9]{0,19}$/.test(id))
            throw new Error("Campaign run identity is malformed");
        const [metadata, workflow] = await Promise.all([
            github.request("GET", `/repos/omg-cli/omg/actions/runs/${id}`),
            github.request(
                "GET",
                "/repos/omg-cli/omg/actions/workflows/ai-review.yml",
            ),
        ]);
        if (
            String(metadata.id) !== id ||
            metadata.display_title !== item.display_title ||
            metadata.head_sha !== item.head_sha ||
            metadata.head_branch !== "main" ||
            metadata.path !== ".github/workflows/ai-review.yml" ||
            metadata.repository?.full_name !== "omg-cli/omg" ||
            metadata.event !== "workflow_dispatch" ||
            ![
                "queued",
                "in_progress",
                "completed",
                "requested",
                "waiting",
                "pending",
            ].includes(metadata.status) ||
            !Number.isSafeInteger(metadata.run_attempt) ||
            metadata.run_attempt < 1 ||
            metadata.run_attempt > 999999 ||
            !Number.isSafeInteger(workflow.id) ||
            workflow.id < 1 ||
            metadata.workflow_id !== workflow.id ||
            workflow.path !== ".github/workflows/ai-review.yml" ||
            workflow.name !== "AI source review"
        )
            throw new Error("Campaign run workflow identity mismatch");
        return metadata;
    };
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
            const metadata = await currentCampaignRun(item);
            const parentRef = `${item.id}-${metadata.run_attempt}`;
            if (metadata.status !== "completed")
                return {
                    status: "campaign-already-active",
                    runId: String(metadata.id),
                };
            let report;
            try {
                report = await loadRecord(parentRef);
            } catch (error) {
                if (error.status === 404)
                    return recoverMissingTestAuditRecord({
                        github,
                        child: metadata,
                        title: item.display_title,
                        revision,
                        manifestDigest,
                        ownerRunId: String(currentRunId),
                        ownerAttempt: currentRunAttempt,
                        loadRecord,
                        loadIntent,
                        storeIntent,
                        rerun,
                    });
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
                String(metadata.run_attempt),
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

import { planTestAuditContinuation,admitTestAuditParent,testAuditTarget,parentPublicationResult,listTestAuditChildren,admitDuplicateTestAudit,dispatchTestAuditPlan,recoverTestAuditCampaign,findDuplicateTestAuditRecord } from "./test-audit-campaign.mjs";
import { collectTestAuditPage,testAuditManifestDigest } from "./test-audit-inventory.mjs";
import { runTestAuditPage, testAuditContinuation } from "./test-audit-flow.mjs";
import { verifyCloudTestAudit } from "./cloud-test-audit-evidence.mjs";
import { testAuditDigest } from "../services/cloud-ci/src/test-audit-contract.ts";
import { publishTestAuditReview } from "./ai-review-publication.mjs";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Schema } from "effect";
import { collectCandidateSources } from "./ai-review-candidate.mjs";
import { collectRuntimeSources, acknowledgeRuntimeSources } from "./sentry-review-input.mjs";
import { admitCoderResult, coderEndpoint } from "./ai-coder-client.mjs";
import { parseCodingRequest, operationIdentity } from "../services/ci-coder/src/request.ts";
import { proposalDigest, publishAiReview, sha256, canonicalJson } from "./ai-review-publication.mjs";
import { ciPolicy, verifyPublicationProof } from "./ai-review-proof.mjs";
import { createGhClient } from "./publish-ai-review.mjs";
import {
    CloudCiEngineFailure,
    verifyCloudCiObjects,
    parseCloudCiRequest,
    cloudCiPlanSha256,
    admitCloudCiRuntime,
} from "./cloud-ci-evidence.mjs";
import { expectedCloudChecks, expectedCloudReports } from "../services/cloud-ci/runner/plan.mjs";
import { assertPortableTestMember } from "../services/cloud-ci/portable-report.mjs";
import {
    SOURCE_REPOSITORY,
    sourceChanges,
    isReviewSourcePath,
    createSourceReviewEvidence,
    createSourceAuditEvidence,
    sourceReviewEndpoint,
} from "./review-source-evidence.mjs";
import { validateReviewProposal } from "../services/ci-inspector/src/review-contract.ts";

const root = fileURLToPath(new URL("../", import.meta.url));
const command = promisify(execFile);
const prefix = `/repos/${SOURCE_REPOSITORY}`;

export function admitSourceFormatting(receipt, expected, imageDigest) {
    const request = parseCloudCiRequest(expected);
    const id = `cl-${request.runId}-${request.attempt}-${request.sha}`;

    if (
        receipt.id !== id ||
        receipt.verification ||
        !["success", "failure"].includes(receipt.conclusion) ||
        Object.entries(request).some(([key, value]) => receipt[key] !== value)
    )
        throw new Error("Formatting evidence identity mismatch.");

    if (!/^sha256:[a-f0-9]{64}$/.test(imageDigest) || receipt.imageDigest !== imageDigest)
        throw new Error("Formatting evidence image mismatch.");

    if (receipt.planSha256 !== cloudCiPlanSha256)
        throw new Error("Formatting evidence plan mismatch.");
    const required = expectedCloudChecks(request.ref);

    if (
        !Array.isArray(receipt.requiredChecks) ||
        receipt.requiredChecks.length !== required.length ||
        new Set(receipt.requiredChecks).size !== required.length ||
        required.some((name) => !receipt.requiredChecks.includes(name)) ||
        !Array.isArray(receipt.checks) ||
        new Set(receipt.checks.map((check) => check.name)).size !== receipt.checks.length ||
        receipt.checks.some((check) => !required.includes(check.name))
    )
        throw new Error("Source format evidence inventory is invalid.");
    const format = receipt.checks.find((check) => check.name === "source-format");

    if (
        !format &&
        receipt.conclusion === "failure" &&
        receipt.failureCategory === "workflow-internal-error"
    )
        throw new CloudCiEngineFailure("workflow-internal-error");
    const hash = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/));

    if (
        !Schema.is(
            Schema.Struct({
                name: Schema.Literal("source-format"),
                exitCode: Schema.Literal(0),
                stdoutKey: Schema.String,
                stderrKey: Schema.String,
                stdoutSha256: hash,
                stderrSha256: hash,
                reports: Schema.Array(Schema.Unknown),
            }),
        )(format) ||
        format.reports.length !== 0
    )
        throw new Error("Source format did not pass with complete evidence.");

    if (
        format.stdoutKey !== `logs/${id}/source-format.stdout` ||
        format.stderrKey !== `logs/${id}/source-format.stderr`
    )
        throw new Error("Source format object identity mismatch.");

    return format;
}

export function admitPortableTestReceipt(receipt, expected, imageDigest) {
    admitSourceFormatting(receipt, expected, imageDigest);
    const request = parseCloudCiRequest(expected);
    const id = `cl-${request.runId}-${request.attempt}-${request.sha}`;

    if (
        receipt.id !== id ||
        !["success", "failure"].includes(receipt.conclusion) ||
        Object.entries(request).some(([key, value]) => receipt[key] !== value)
    )
        throw new Error("Portable test evidence identity mismatch.");

    if (!/^sha256:[a-f0-9]{64}$/.test(imageDigest ?? "") || receipt.imageDigest !== imageDigest)
        throw new Error("Portable test evidence image mismatch.");

    if (receipt.planSha256 !== cloudCiPlanSha256)
        throw new Error("Portable test evidence plan mismatch.");

    const portable = (Array.isArray(receipt.checks) ? receipt.checks : []).filter(
        (check) => check?.name === "rust-portable-tests",
    );

    if (portable.length !== 1) {
        if (
            portable.length === 0 &&
            receipt.conclusion === "failure" &&
            receipt.failureCategory === "workflow-internal-error"
        )
            throw new CloudCiEngineFailure("workflow-internal-error");
        throw new Error("Portable test check is missing or duplicated.");
    }

    const names = expectedCloudReports("rust-portable-tests");
    const reports = Array.isArray(portable[0].reports) ? portable[0].reports : [];

    if (
        portable[0].exitCode !== 0 ||
        reports.length !== names.length ||
        new Set(reports.map((report) => report.name)).size !== names.length ||
        names.some((name) => !reports.some((report) => report.name === name)) ||
        reports.some((report) => report.key !== `reports/${id}/${report.name}`)
    )
        throw new Error("Portable test reports are missing or unexpected.");

    return reports.find((report) => report.name === "rust-pgp-license-junit.xml");
}

export async function verifiedPortableReport(report, load) {
    const response = await load(report.key);
    if (!response.ok || !response.body)
        throw new Error(`Portable test report is unavailable: ${report.key}.`);
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body) {
        size += chunk.byteLength;
        if (size > 20_000_000) throw new Error("Portable test report exceeds its byte budget.");
        chunks.push(chunk);
    }
    const bytes = Buffer.concat(chunks);
    await verifyCloudCiObjects({ checks: [], verificationReports: [report] }, async () => new Response(bytes));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export async function admitPortableAuditRow(row, formatting, io, imageDigest) {
    if (formatting?.status !== "passed" || formatting.sha !== row.request.sha || formatting.ref !== "refs/heads/main")
        throw new Error("Portable test baseline identity mismatch.");
    const request = parseCloudCiRequest({repository: SOURCE_REPOSITORY, sha: row.request.sha,
        ref: formatting.ref, runId: formatting.runId, attempt: formatting.attempt});
    const id = `cl-${request.runId}-${request.attempt}-${request.sha}`;
    const receipt = await io.receipt(id);
    const report = admitPortableTestReceipt(receipt, request, imageDigest);
    const xml = await verifiedPortableReport(report, key => io.report(id, key));
    const suite = row.task.target === "lib" ? "omg" : `omg::${path.basename(row.task.path, ".rs")}`;
    return assertPortableTestMember(xml, suite, row.task.testName);
}

export async function admitFormattingRun({
    sha,
    branch,
    upstream,
    runId,
    attempt,
    imageDigest,
    priorImageDigest,
    requirePortableEvidence = false,
    fetchReceipt,
    startRun,
    verifyLogs,
}) {
    exactSha(sha);
    branchName(branch);

    if (!/^sha256:[a-f0-9]{64}$/.test(imageDigest ?? ""))
        throw new Error("Formatting evidence image mismatch.");

    if (priorImageDigest !== undefined && !/^sha256:[a-f0-9]{64}$/.test(priorImageDigest))
        throw new Error("Formatting prior image identity is invalid.");

    const currentRequest = parseCloudCiRequest({
        repository: SOURCE_REPOSITORY,
        sha,
        ref: `refs/heads/${branch}`,
        runId,
        attempt,
    });
    const currentId = `cl-${currentRequest.runId}-${currentRequest.attempt}-${sha}`;

    const admit = async (receipt, expected, image) => {
        if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt))
            throw new Error("Formatting evidence is unavailable.");
        const format = admitSourceFormatting(receipt, expected, image);
        await verifyLogs(`cl-${expected.runId}-${expected.attempt}-${expected.sha}`, format);
        return format;
    };

    const passed = (receipt, format) => ({
        status: "passed",
        runId: receipt.runId,
        attempt: receipt.attempt,
        sha,
        ref: receipt.ref,
        conclusion: receipt.conclusion,
        sourceFormat: format,
        ...(receipt.sourceBaseSha ? { sourceBaseSha: exactSha(receipt.sourceBaseSha) } : {}),
    });

    if (upstream !== undefined && upstream !== null) {
        const upstreamRequest = parseCloudCiRequest({
            repository: SOURCE_REPOSITORY,
            sha,
            ref: `refs/heads/${branch}`,
            runId: upstream.runId,
            attempt: upstream.attempt,
        });
        const prior = await fetchReceipt(
            `cl-${upstreamRequest.runId}-${upstreamRequest.attempt}-${sha}`,
        );

        if (prior === null || typeof prior !== "object" || Array.isArray(prior))
            throw new Error("Formatting evidence is unavailable.");

        if (prior.imageDigest === imageDigest) {
            const format = await admit(prior, upstreamRequest, imageDigest);

            if (!requirePortableEvidence) return passed(prior, format);

            try {
                admitPortableTestReceipt(prior, upstreamRequest, imageDigest);

                return passed(prior, format);
            } catch (error) {
                if (!(error instanceof CloudCiEngineFailure)) throw error;

                if (upstreamRequest.runId === currentRequest.runId && upstreamRequest.attempt === currentRequest.attempt)
                    throw new Error("Formatting refresh cannot reuse its prior run identity.");
            }
        } else {
            if (priorImageDigest === undefined || prior.imageDigest !== priorImageDigest)
                throw new Error("Formatting prior evidence is not admitted.");

            if (upstreamRequest.runId === currentRequest.runId && upstreamRequest.attempt === currentRequest.attempt)
                throw new Error("Formatting refresh cannot reuse its prior run identity.");

            await admit(prior, upstreamRequest, priorImageDigest);
        }
    }

    await startRun(currentRequest);
    const receipt = await fetchReceipt(currentId);
    const format = await admit(receipt, currentRequest, imageDigest);

    return passed(receipt, format);
}

export function reviewRecord(report, runId, attempt) {
    if (!/^[1-9][0-9]{0,19}$/.test(runId ?? "") || !/^[1-9][0-9]{0,5}$/.test(attempt ?? ""))
        throw new Error("Invalid review run identity.");

    if (report.repository !== SOURCE_REPOSITORY) throw new Error("Unexpected review repository.");
    exactSha(report.sha);
    exactSha(report.controllerRevision);
    branchName(report.branch);
    const record = { repository: SOURCE_REPOSITORY, runId, attempt, report };

    if (Buffer.byteLength(JSON.stringify(record)) > 2 * 1024 * 1024)
        throw new Error("Review record exceeds 2 MiB; no coverage was truncated.");

    return record;
}

function branchName(value) {
    if (!["main"].includes(value)) throw new Error("Unsupported review branch.");

    return value;
}

function exactSha(value) {
    if (!Schema.is(Schema.String)(value) || !/^[a-f0-9]{40}$/.test(value))
        throw new Error("Expected an exact commit SHA.");

    return value;
}

export function reviewTarget(eventName, event) {
    if (event.repository?.full_name !== SOURCE_REPOSITORY)
        throw new Error("Unexpected review repository.");

    if (eventName === "schedule") {
        if (event.schedule === "*/15 * * * *")
            return { branch: "main", sha: null, publish: true, range: { kind: "runtime" } };
        if (event.schedule !== undefined && event.schedule !== "23 6 * * 1") throw new Error("Unknown review schedule.");
        return { branch: "main", sha: null, publish: true, range: { kind: "audit", cursor: 0 } };
    }

    if (eventName === "push") {
        if (event.deleted || !event.ref?.startsWith("refs/heads/"))
            throw new Error("Unsupported review branch.");

        return {
            branch: branchName(event.ref.slice(11)),
            sha: exactSha(event.after),
            publish: true,
            range: { kind: "push", baseSha: exactSha(event.before) },
        };
    }

    if (eventName === "workflow_run") {
        const run = event.workflow_run;

        if (run?.head_repository?.full_name !== SOURCE_REPOSITORY)
            throw new Error("Unexpected CI repository.");

        if (
            !["success", "failure", "timed_out"].includes(run.conclusion) ||
            run.event !== "push" ||
            run.name !== "Cloudflare verification"
        )
            throw new Error("Only completed trusted Cloudflare push CI events are reviewable.");

        const upstream = { runId: String(run.id), attempt: String(run.run_attempt) };

        if (
            !/^[1-9][0-9]{0,19}$/.test(upstream.runId) ||
            !/^[1-9][0-9]{0,5}$/.test(upstream.attempt)
        )
            throw new Error("Invalid upstream CI run identity.");

        return {
            branch: branchName(run.head_branch),
            sha: exactSha(run.head_sha),
            publish: true,
            upstream,
        };
    }

    if (eventName === "workflow_dispatch") {
        const input = event.inputs ?? {};

        if (Object.keys(input).some((key) => !["branch", "publish", "scope", "audit_sha", "audit_digest", "audit_cursor", "audit_parent", "audit_manifest", "audit_resnapshot"].includes(key)))
            throw new Error("Unknown manual review input.");

        if (![undefined, false, true, "false", "true"].includes(input.publish))
            throw new Error("Invalid publication input.");

        if (![undefined, "changes", "source-audit", "runtime-events", "test-audit"].includes(input.scope)) throw new Error("Unknown review scope.");
        if(input.scope === "test-audit")return testAuditTarget(input);
        if(input.audit_manifest||![undefined,false,"false", ""].includes(input.audit_resnapshot))throw new Error("Campaign inputs require test-audit scope");
        const auditInputs = [input.audit_sha, input.audit_digest, input.audit_cursor, input.audit_parent];
        if (input.scope === "source-audit") {
            const cursor = Number(input.audit_cursor || "0");
            if (!Number.isSafeInteger(cursor) || cursor < 0 || cursor % 48 ||
                (cursor === 0 ? auditInputs.some((value) => value && value !== "0") :
                    !/^[a-f0-9]{64}$/.test(input.audit_digest ?? "") ||
                    !/^[1-9][0-9]{0,19}-[1-9][0-9]{0,5}$/.test(input.audit_parent ?? "")))
                throw new Error("Invalid source audit cursor or parent identity.");
            return {
                branch: branchName(input.branch), sha: cursor ? exactSha(input.audit_sha) : null,
                publish: input.publish === true || input.publish === "true",
                range: { kind: "audit", cursor, ...(cursor ? { inventoryDigest: input.audit_digest } : {}) },
                ...(cursor ? { auditParent: input.audit_parent } : {}),
            };
        }
        if (auditInputs.some(Boolean)) throw new Error("Audit inputs require source-audit scope.");
        if (input.scope === "runtime-events") return {
            branch: branchName(input.branch), sha: null, publish: input.publish === true || input.publish === "true",
            range: { kind: "runtime" },
        };

        return {
            branch: branchName(input.branch),
            sha: null,
            publish: input.publish === true || input.publish === "true",
        };
    }

    throw new Error("Unsupported review event.");
}

export function pinReviewTarget(target, triggerSha) {
    exactSha(triggerSha);
    return target.sha === null ? { ...target, sha: triggerSha, queuedTrigger: true } : target;
}

export function partitionReviewSources(entries) {
    if (!Array.isArray(entries) || entries.length > 500)
        throw new Error("Changed-path inventory exceeds 500; no coverage was truncated.");
    const seen = new Set();
    const batches = [];
    const unreviewedPaths = [];
    let batch = [];
    let bytes = 0;

    for (const entry of entries) {
        if (seen.has(entry.path)) throw new Error("Duplicate source path.");
        seen.add(entry.path);
        let reason;

        if (!isReviewSourcePath(entry.path)) reason = "unsupported-source-type";
        else if (Buffer.byteLength(entry.content) > 24000) reason = "source-byte-budget-exceeded";
        else if (Buffer.byteLength(entry.diff ?? "") > 64000) reason = "diff-byte-budget-exceeded";

        if (reason) {
            unreviewedPaths.push({ path: entry.path, reason });
            continue;
        }

        if (batch.length === 12 || bytes + Buffer.byteLength(entry.diff ?? "") > 64000) {
            batches.push(batch);
            batch = [];
            bytes = 0;
        }

        if (batches.length >= 4) {
            unreviewedPaths.push({ path: entry.path, reason: "batch-budget-exceeded" });
            continue;
        }

        batch.push(entry);
        bytes += Buffer.byteLength(entry.diff ?? "");
    }

    if (batch.length) batches.push(batch);

    return { batches, unreviewedPaths };
}

export function validateReviewReceipt(input, response) {
    for (const key of ["repository", "sha", "branch"])
        if (response[key] !== input[key]) throw new Error("Model receipt identity mismatch.");
    const supplied = input.sourceFiles.map((file) => file.path);

    if (
        response.model !== "@cf/deepseek-ai/deepseek-v4.1-flash-1017" ||
        response.publication !== "requires-verifier" ||
        !Number.isSafeInteger(response.codeExecutions) ||
        response.codeExecutions < 1 ||
        !Number.isSafeInteger(response.sourceToolCalls) ||
        response.sourceToolCalls < 1 ||
        response.sourceToolCalls > 18 ||
        !Schema.is(Schema.Boolean)(response.readDiff) ||
        !Array.isArray(response.suppliedPaths) ||
        !Array.isArray(response.readPaths) ||
        response.suppliedPaths.length !== supplied.length ||
        new Set(response.suppliedPaths).size !== supplied.length ||
        response.suppliedPaths.some((file) => !supplied.includes(file)) ||
        !response.readPaths.length ||
        new Set(response.readPaths).size !== response.readPaths.length ||
        response.readPaths.some((file) => !supplied.includes(file))
    )
        throw new Error("Invalid source read receipt.");

    return response;
}

function reviewProposal(input, response) {
    const proposal =
        response.kind === "no-findings"
            ? { kind: response.kind, summary: response.summary }
            : {
                  kind: response.kind,
                  summary: response.summary,
                  candidates: response.candidates.map(({ verification, ...candidate }) => {
                      if (verification !== "uncorroborated")
                          throw new Error("Invalid candidate verification state.");

                      if (
                          candidate.evidence.some((item) => !response.readPaths.includes(item.path))
                      )
                          throw new Error("Candidate cites unread source.");

                      return candidate;
                  }),
              };

    return validateReviewProposal(input, proposal);
}

export async function runReviewFlow({ target, io }) {
    const branch = branchName(target.branch);
    const head = exactSha(await io.head(branch));

    if (target.sha !== null && target.sha !== head) {
        if (!["audit", "test-audit"].includes(target.range?.kind) && !target.queuedTrigger) throw new Error("Review target is stale.");
        return {
            repository: SOURCE_REPOSITORY, branch, sha: exactSha(target.sha), currentSha: head, baseSha: target.sha,
            ...(target.range ? { sourceRange: { ...target.range, sha: target.sha } } : {}), status: "incomplete-stale",
            formatting: { status: "not-started", reason: "audit-snapshot-no-longer-current" },
            suppliedPaths: [], readPaths: [], unreviewedPaths: [], batches: [], publications: [], candidateOutcomes: [],
            publishRequested: target.publish,
            coverageMeaning: target.queuedTrigger
                ? "The queued trigger snapshot is incomplete because current main changed before this run began."
                : "The immutable audit snapshot is incomplete because current main changed before this page began.",
        };
    }
    const sha = head;
    const precollected = ["audit", "runtime", "test-audit"].includes(target.range?.kind)
        ? await io.collect(sha, branch, target.range, { reserve: target.publish === true }) : undefined;
    if (precollected?.replayRef) {
        try {
            return { ...admitRuntimeReplay({ original: precollected.replayReport, replayRef: precollected.replayRef,
                runtimeEvents: precollected.runtimeEvents, sha, controllerRevision: io.controllerRevision }), publishRequested: target.publish };
        } catch (error) {
            return {
                repository: SOURCE_REPOSITORY, branch, sha, baseSha: sha, status: "runtime-replay-held", runtimeUnresolved: true,
                runtimeEvents: precollected.runtimeEvents, replayOf: precollected.replayRef,
                formatting: { status: "not-started", reason: "canonical-runtime-publication-unresolved" },
                suppliedPaths: [], readPaths: [], unreviewedPaths: precollected.unreviewedPaths ?? [],
                batches: [], publications: [], candidateOutcomes: [], publishRequested: target.publish,
                coverageMeaning: error instanceof Error ? error.message : "Canonical runtime publication remains unresolved.",
            };
        }
    }
    if (precollected?.sourceRange?.kind === "test-audit" && precollected.entries.length === 0)
        return runTestAuditPage({collected:precollected,sha,branch,formatting:{status:"not-required",reason:"no-admitted-test-task"},publishRequested:target.publish,io});
    if (precollected && precollected.entries.length === 0) {
        const formatting = target.upstream
            ? await io.format(sha, branch, target.upstream)
            : { status: "not-required", reason: "no-admitted-source" };
        return {
            repository: SOURCE_REPOSITORY, branch, sha, baseSha: precollected.baseSha,
            sourceRange: precollected.sourceRange,
            status: target.upstream && formatting.status !== "passed" ? "format-blocked" : "no-reviewable-source",
            formatting,
            suppliedPaths: [], readPaths: [], unreviewedPaths: precollected.unreviewedPaths,
            batches: [], publications: [], candidateOutcomes: [], publishRequested: target.publish,
            ...(precollected.runtimeEvents ? { runtimeEvents: precollected.runtimeEvents } : {}),
            coverageMeaning: "No model inference or native verification was started because no source was admitted.",
        };
    }
    const formatting = await io.format(sha, branch, target.upstream, target.range?.kind === "test-audit");

    if (formatting.status !== "passed")
        return {
            repository: SOURCE_REPOSITORY,
            branch,
            sha,
            baseSha: precollected?.baseSha ?? null,
            ...(precollected ? { sourceRange: precollected.sourceRange } : {}),
            status: "format-blocked",
            ...(precollected?.runtimeEvents ? { runtimeEvents: precollected.runtimeEvents,
                modelInferencePerformed: false, nativeVerificationPerformed: false } : {}),
            formatting,
            suppliedPaths: [],
            readPaths: [],
            unreviewedPaths: precollected ? [...precollected.unreviewedPaths,
                ...precollected.entries.map(({ path }) => ({ path, reason: "source-format-blocked" }))] : [],
            batches: [],
            publications: [],
            candidateOutcomes: [],
            coverageMeaning:
                precollected
                    ? "Source inventory was collected, but model review was blocked because formatting evidence was not admitted."
                    : "Source inventory and model review were not started because formatting evidence was not admitted.",
            publishRequested: target.publish,
        };

    const range =
        target.range ??
        (formatting.sourceBaseSha
            ? { kind: "push", baseSha: formatting.sourceBaseSha }
            : undefined);

    let collected;

    try {
        collected = precollected ?? await io.collect(sha, branch, range);
    } catch (error) {
        if (!(error instanceof Error) || !error.message.startsWith("Source coverage is blocked:"))
            throw error;

        return {
            repository: SOURCE_REPOSITORY,
            branch,
            sha,
            baseSha: null,
            status: "coverage-blocked",
            formatting,
            suppliedPaths: [],
            readPaths: [],
            unreviewedPaths: [],
            batches: [],
            publications: [],
            candidateOutcomes: [],
            coverageMeaning: error.message,
            publishRequested: target.publish,
        };
    }

    if (collected.sourceRange?.kind === "test-audit")
        return runTestAuditPage({collected,sha,branch,formatting,publishRequested:target.publish,io});
    const partition = partitionReviewSources(collected.entries);

    const result = {
        repository: SOURCE_REPOSITORY,
        branch,
        sha,
        baseSha: collected.baseSha,
        sourceRange: collected.sourceRange,
        status: "reviewed",
        formatting,
        suppliedPaths: [],
        readPaths: [],
        unreviewedPaths: [...collected.unreviewedPaths, ...partition.unreviewedPaths],
        coverageMeaning:
            "Actual reads attest excerpts and diff chunks, not whole-file or repository coverage.",
        batches: [],
        publications: [],
        candidateOutcomes: [],
        publishRequested: target.publish,
        ...(collected.runtimeEvents ? { runtimeEvents: collected.runtimeEvents } : {}),
    };

    let candidateCount = 0;
    let mirrored = false;

    for (const entries of partition.batches) {
        const evidence = collected.sourceRange?.kind === "audit" ? createSourceAuditEvidence({
            sha, branch,
            sourceFiles: entries.map(({ path, blobSha, content }) => ({ path, blobSha, content })),
            runtimeEvidence: collected.runtimeEvidence,
        }) : createSourceReviewEvidence({
            sha,
            baseSha: collected.baseSha,
            branch,
            rawDiff: entries.map((entry) => entry.raw).join(""),
            numstat: entries.map((entry) => entry.numstat).join(""),
            diff: entries.map((entry) => entry.diff).join(""),
            blobs: new Map(entries.map((entry) => [entry.blobSha, Buffer.from(entry.content)])),
        });

        const response = validateReviewReceipt(
            evidence.sourceInput,
            await io.review(evidence.sourceInput),
        );

        const proposal = reviewProposal(evidence.sourceInput, response);
        result.suppliedPaths.push(...evidence.suppliedPaths);
        result.readPaths.push(...response.readPaths);
        result.unreviewedPaths.push(
            ...evidence.suppliedPaths
                .filter((file) => !response.readPaths.includes(file))
                .map((file) => ({ path: file, reason: "not-read-by-model" })),
        );
        result.batches.push({ sourceInput: evidence.sourceInput, modelResponse: response });

        if (proposal.kind !== "candidates") continue;

        for (let index = 0; index < proposal.candidates.length; index++) {
            const candidate = proposal.candidates[index];

            if (candidateCount >= 3) {
                result.candidateOutcomes.push({
                    title: candidate.title,
                    outcome: "verification-budget-exceeded",
                });
                continue;
            }

            if (!mirrored) {
                await io.mirror(sha);
                mirrored = true;
            }

            candidateCount++;
            const adapted = await io.adapt(evidence.sourceInput, proposal, index);

            if (!adapted) {
                result.candidateOutcomes.push({
                    title: candidate.title,
                    outcome: "coding-agent-produced-no-repair",
                });
                continue;
            }

            if ((await io.head(branch)) !== sha) throw new Error("Review target became stale.");

            const verified = await io.verify(adapted, sha, branch);
            result.publications.push({ proposal: adapted.proposal, ...verified });
            result.candidateOutcomes.push({
                title: candidate.title,
                outcome: "verified-for-publication",
            });
        }
    }

    return result;
}

const execute = (binary, args, encoding = "utf8") =>
    command(binary, args, {
        cwd: root,
        encoding,
        timeout: 180000,
        maxBuffer: 8 * 1024 * 1024,
        windowsHide: true,
    });

const git = async (args) =>
    (await execute("git", ["--no-pager", "--literal-pathspecs", ...args])).stdout;

export async function collectSources(github, sha, range, directory = root) {
    exactSha(sha);
    if (range?.kind === "audit") return collectAuditSources(sha, range, directory);

    const sourceExecute = (binary, args, encoding = "utf8") =>
        command(binary, args, {
            cwd: directory,
            encoding,
            timeout: 180000,
            maxBuffer: 8 * 1024 * 1024,
            windowsHide: true,
        });

    const sourceGit = async (args) =>
        (await sourceExecute("git", ["--no-pager", "--literal-pathspecs", ...args])).stdout;

    let selected = range;

    if (!selected) {
        const pulls = await github.request("GET", `${prefix}/commits/${sha}/pulls?per_page=100`);

        if (!Array.isArray(pulls) || pulls.length !== 1)
            throw new Error(
                "Source coverage is blocked: original push range is unavailable or ambiguous.",
            );
        const [pull] = pulls;

        if (
            pull.merge_commit_sha !== sha ||
            pull.state !== "closed" ||
            !Schema.is(Schema.String)(pull.merged_at) ||
            pull.head?.repo?.full_name !== SOURCE_REPOSITORY ||
            pull.base?.repo?.full_name !== SOURCE_REPOSITORY ||
            !["main"].includes(pull.base.ref)
        )
            throw new Error(
                "Source coverage is blocked: associated PR does not establish this exact merge.",
            );
        selected = { kind: "pull-request", baseSha: pull.base.sha, headSha: sha };
    }

    if (!["push", "pull-request"].includes(selected.kind))
        throw new Error("Invalid source review range.");
    let baseSha = exactSha(selected.baseSha);

    if (baseSha === "0".repeat(40) || baseSha === sha)
        throw new Error("Source coverage is blocked: an existing nonempty base is required.");

    if (selected.kind === "pull-request" && exactSha(selected.headSha) !== sha)
        throw new Error("Source range head identity mismatch.");

    for (const commitSha of [sha, baseSha])
        if ((await sourceGit(["rev-parse", `${commitSha}^{commit}`])).trim() !== commitSha)
            throw new Error("Source Git objects are unavailable.");
    const mergeBase = exactSha((await sourceGit(["merge-base", baseSha, sha])).trim());

    if (selected.kind === "push" && mergeBase !== baseSha)
        throw new Error("Source coverage is blocked: push base is not an ancestor of its head.");

    if (selected.kind === "pull-request") baseSha = mergeBase;

    if (baseSha === sha)
        throw new Error(
            "Source coverage is blocked: associated PR has no recoverable source range.",
        );
    const common = ["diff", "--no-ext-diff", "--no-textconv", "--no-renames"];
    const raw = await sourceGit([...common, "--raw", "--no-abbrev", "-z", baseSha, sha, "--"]);
    const fields = raw.split("\0");

    if (fields.pop() !== "" || fields.length % 2 || fields.length > 1000)
        throw new Error("Changed-path inventory is invalid or exceeds 500.");
    const entries = [];
    const unreviewedPaths = [];

    for (let index = 0; index < fields.length; index += 2) {
        const oneRaw = `${fields[index]}\0${fields[index + 1]}\0`;
        const [change] = sourceChanges(oneRaw);

        if (change.status === "D" || !isReviewSourcePath(change.path)) {
            unreviewedPaths.push({
                path: change.path,
                reason:
                    change.status === "D"
                        ? "deleted-at-reviewed-commit"
                        : "unsupported-source-type",
            });
            continue;
        }

        const size = Number((await sourceGit(["cat-file", "-s", change.newBlob])).trim());

        if (!Number.isSafeInteger(size) || size < 0) throw new Error("Invalid Git blob size.");

        if (size > 24000) {
            unreviewedPaths.push({ path: change.path, reason: "source-byte-budget-exceeded" });
            continue;
        }

        const numstat = await sourceGit([
            ...common,
            "--numstat",
            "-z",
            baseSha,
            sha,
            "--",
            change.path,
        ]);

        if (numstat.startsWith("-\t")) throw new Error("Binary source change is refused.");
        const bytes = (await sourceExecute("git", ["cat-file", "blob", change.newBlob], null))
            .stdout;
        const content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);

        if (content.includes("\0")) throw new Error("Binary source is refused.");

        const diff = await sourceGit([
            ...common,
            "--full-index",
            "--no-color",
            "--unified=3",
            baseSha,
            sha,
            "--",
            change.path,
        ]);

        entries.push({
            path: change.path,
            blobSha: change.newBlob,
            content,
            raw: oneRaw,
            numstat,
            diff,
        });
    }

    return {
        baseSha,
        sourceRange: { kind: selected.kind, baseSha, headSha: sha },
        entries,
        unreviewedPaths,
    };
}

export async function collectAuditSources(sha, range, directory = root) {
    exactSha(sha);
    if (!Number.isSafeInteger(range.cursor) || range.cursor < 0 || range.cursor % 48)
        throw new Error("Invalid audit cursor.");
    const sourceGit = async (args, encoding = "utf8") => (await command("git", ["--no-pager", "--literal-pathspecs", ...args], {
        cwd: directory, encoding, timeout: 180000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    })).stdout;
    if ((await sourceGit(["rev-parse", `${sha}^{commit}`])).trim() !== sha) throw new Error("Audit source commit unavailable.");
    const inventory = await sourceGit(["ls-tree", "-r", "-z", "-l", sha]);
    const inventoryDigest = sha256(inventory);
    if (range.inventoryDigest && range.inventoryDigest !== inventoryDigest) throw new Error("Audit inventory digest mismatch.");
    const files = inventory.split("\0");
    if (files.pop() !== "" || !files.length || files.length > 10000 || range.cursor >= files.length)
        throw new Error("Audit inventory or cursor is outside its bounded tree.");
    const entries = [];
    const unreviewedPaths = [];
    const page = files.slice(range.cursor, range.cursor + 48);
    for (const record of page) {
        const match = /^([0-7]{6}) (blob|commit) ([a-f0-9]{40}) +([0-9]+|-)\t([\s\S]+)$/.exec(record);
        if (!match) throw new Error("Malformed audit tree entry.");
        const [, mode, type, blobSha, sizeText, file] = match;
        let reason;
        if (!["100644", "100755"].includes(mode) || type !== "blob") reason = "nonregular-source";
        else if (file.includes("\\") || /[\x00-\x1f\x7f]/.test(file) || file.startsWith("/") ||
            file.split("/").some((segment) => !segment || segment === "." || segment === "..")) reason = "invalid-source-path";
        else if (!isReviewSourcePath(file)) reason = "unsupported-source-type";
        else if (Number(sizeText) > 24000) reason = "source-byte-budget-exceeded";
        if (reason) { unreviewedPaths.push({ path: file, reason }); continue; }
        const bytes = await sourceGit(["cat-file", "blob", blobSha], null);
        if (bytes.includes(0)) { unreviewedPaths.push({ path: file, reason: "binary-source" }); continue; }
        let content;
        try { content = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
        catch { unreviewedPaths.push({ path: file, reason: "invalid-utf8-source" }); continue; }
        entries.push({ path: file, blobSha, content });
    }
    return {
        baseSha: sha, entries, unreviewedPaths,
        sourceRange: { kind: "audit", sha, inventoryDigest, cursor: range.cursor,
            nextCursor: range.cursor + page.length < files.length ? range.cursor + page.length : null,
            totalPaths: files.length, pagePaths: page.length, eligiblePaths: entries.length, heldPaths: unreviewedPaths.length },
    };
}

export function sourceAuditContinuation(report, currentSha, runId, attempt, publicationResult) {
    if(report.sourceRange?.kind === "test-audit" && report.sourceRange?.manifestDigest) return planTestAuditContinuation(report,currentSha,runId,attempt,publicationResult);
    if (report.sourceRange?.kind === "test-audit") return testAuditContinuation(report,currentSha,runId,attempt);
    if (report.repository !== SOURCE_REPOSITORY || report.branch !== "main")
        throw new Error("Unexpected audit continuation repository.");
    exactSha(report.sha);
    exactSha(currentSha);
    if (!["reviewed", "no-reviewable-source"].includes(report.status))
        return { status: "incomplete-review-blocked" };
    const range = report.sourceRange;
    if (range?.kind !== "audit" || range.intake === "sentry-runtime") return { status: "not-a-weekly-audit" };
    if (range.sha !== report.sha || !/^[a-f0-9]{64}$/.test(range.inventoryDigest ?? "") ||
        !Number.isSafeInteger(range.cursor) || range.cursor < 0 || range.cursor % 48 ||
        !Number.isSafeInteger(range.totalPaths) || range.totalPaths < 1 || range.totalPaths > 10000 ||
        range.cursor >= range.totalPaths || range.pagePaths !== Math.min(48, range.totalPaths - range.cursor) ||
        range.nextCursor !== (range.cursor + range.pagePaths < range.totalPaths ? range.cursor + range.pagePaths : null))
        throw new Error("Audit continuation cursor or inventory mismatch.");
    if (currentSha !== report.sha)
        return { status: "incomplete-stale", remainingPaths: range.totalPaths - range.cursor - range.pagePaths };
    if (range.nextCursor === null) return { status: "inventory-exhausted" };
    if (!/^[1-9][0-9]{0,19}$/.test(runId ?? "") || !/^[1-9][0-9]{0,5}$/.test(attempt ?? ""))
        throw new Error("Invalid audit continuation run identity.");
    return {
        status: "continue",
        inputs: { branch: "main", scope: "source-audit", publish: String(report.publishRequested === true),
            audit_sha: report.sha, audit_digest: range.inventoryDigest, audit_cursor: String(range.nextCursor),
            audit_parent: `${runId}-${attempt}` },
    };
}

export function admitAuditResume(target, parent, revision, campaign) {
    if(target.range?.kind === "test-audit" && parent.sourceRange?.manifestDigest) return admitTestAuditParent(target,parent,revision,campaign?.manifestDigest,campaign?.publicationResult,campaign);
    if (!/^[1-9][0-9]{0,19}-[1-9][0-9]{0,5}$/.test(target.auditParent ?? "") ||
        parent.controllerRevision !== revision || parent.sha !== target.sha ||
        parent.sourceRange?.kind !== target.range.kind || parent.sourceRange?.inventoryDigest !== target.range.inventoryDigest ||
        parent.sourceRange?.nextCursor !== target.range.cursor || parent.publishRequested !== target.publish ||
        !["passed", "not-required"].includes(parent.formatting?.status))
        throw new Error("Audit parent record identity mismatch.");
    const continuation = sourceAuditContinuation(parent, target.sha, ...target.auditParent.split("-"));
    if (continuation.status !== "continue") throw new Error("Audit parent did not authorize continuation.");
    if (parent.formatting.status !== "passed") return target;
    if (parent.formatting.sha !== target.sha || parent.formatting.ref !== "refs/heads/main" ||
        !/^[1-9][0-9]{0,19}$/.test(parent.formatting.runId ?? "") ||
        !/^[1-9][0-9]{0,5}$/.test(parent.formatting.attempt ?? ""))
        throw new Error("Audit formatting identity mismatch.");
    return { ...target, upstream: { runId: parent.formatting.runId, attempt: parent.formatting.attempt } };
}

export function runtimeReviewCanAcknowledge(report) {
    return report?.publishRequested === true && !report.runtimeUnresolved &&
        ["reviewed", "publication-replay"].includes(report.status) && report.sourceRange?.intake === "sentry-runtime" &&
        report.formatting?.status === "passed" && Array.isArray(report.runtimeEvents) &&
        report.runtimeEvents.length > 0 && report.runtimeEvents.length <= 3 &&
        report.runtimeEvents.every(event => /^[1-9][0-9]{0,19}$/.test(event?.projectId ?? "") &&
            /^[a-f0-9]{32}$/.test(event?.eventId ?? "") && /^[a-f0-9]{64}$/.test(event?.bodySha256 ?? "")) &&
        Array.isArray(report.batches) && report.batches.length > 0 &&
        report.batches.every(batch => {
            try {
                const response = validateReviewReceipt(batch.sourceInput, batch.modelResponse);
                return ["repository", "sha", "branch"].every(key => batch.sourceInput[key] === report[key]) &&
                    batch.sourceInput.sourceFiles.length > 0 &&
                    batch.sourceInput.sourceFiles.every(file => response.readPaths.includes(file.path));
            } catch {
                return false;
            }
        }) &&
        Array.isArray(report.suppliedPaths) && report.suppliedPaths.length > 0 &&
        Array.isArray(report.readPaths) && report.readPaths.length > 0 &&
        report.suppliedPaths.every(file => report.readPaths.includes(file)) &&
        Array.isArray(report.unreviewedPaths) && report.unreviewedPaths.length === 0 &&
        Array.isArray(report.publications) && report.publications.length <= 3 &&
        Array.isArray(report.candidateOutcomes) && report.candidateOutcomes.length === report.publications.length &&
        report.candidateOutcomes.every(candidate => candidate?.outcome === "verified-for-publication");
}

export async function finalizeRuntimeReview({ report, publicationResult, acknowledge }) {
    if (report.runtimeUnresolved) throw new Error("Canonical runtime publication remains unresolved; evidence stays pending.");
    if (!runtimeReviewCanAcknowledge(report) ||
        (publicationResult !== "success" && !(publicationResult === "skipped" && report.publications.length === 0)))
        throw new Error("Runtime publication did not finish successfully; evidence remains pending.");
    await acknowledge();
    return { status: "runtime-evidence-acknowledged" };
}

export function admitRuntimeReplay({ original, replayRef, runtimeEvents, sha, controllerRevision, publications }) {
    if (!/^[1-9][0-9]{0,19}$/.test(replayRef?.runId ?? "") || !/^[1-9][0-9]{0,5}$/.test(replayRef?.attempt ?? "") ||
        (replayRef.sha !== undefined && replayRef.sha !== sha) ||
        (replayRef.controllerRevision !== undefined && replayRef.controllerRevision !== controllerRevision) ||
        original?.repository !== SOURCE_REPOSITORY || original.branch !== "main" || original.sha !== sha ||
        original.controllerRevision !== controllerRevision || original.publishRequested !== true || original.runtimeUnresolved ||
        !["reviewed", "no-reviewable-source"].includes(original.status) || original.sourceRange?.intake !== "sentry-runtime" ||
        !Array.isArray(original.publications) || original.publications.length > 3 ||
        !Array.isArray(runtimeEvents) || runtimeEvents.length === 0 || runtimeEvents.length > 3 ||
        canonicalJson(original.runtimeEvents) !== canonicalJson(runtimeEvents) ||
        (publications !== undefined && canonicalJson(original.publications) !== canonicalJson(publications)))
        throw new Error("Canonical runtime publication source, controller or event identity differs; unresolved evidence must not be replaced.");
    return { ...original, status: "publication-replay", replayOf: replayRef };
}

const transitionKeys = "branch cursor enabled imageDigest inventoryDigest kind manifestDigest pagePaths pageSize parent parentController priorChild priorFormatting priorImageDigest publish repository run source totalPaths verifierRevision".split(" ");
const formattingKeys = "attempt ref runId sha".split(" ");
const exactKeys = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify(keys);
const sha40 = (value) => typeof value === "string" && /^[a-f0-9]{40}$/.test(value);
const imageSha = (value) => typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
const hex64 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const runIdentity = (value) => typeof value === "string" && /^[1-9][0-9]{0,19}-[1-9][0-9]{0,5}$/.test(value);

const renewalKeys = "branch enabled imageDigest inventoryDigest kind manifestDigest parent parentController priorImageDigest publication publish repository source targetController verifierRevision".split(" ");
export async function loadTestAuditRenewal(context, readRecord = document) {
    let rawRecord;
    try {
        rawRecord = await readRecord(path.join(homedir(), "ci", "test-audit-renewal.json"), 8192);
    } catch (error) {
        if (error?.code === "ENOENT") return undefined;
        throw error;
    }
    if (!exactKeys(rawRecord, renewalKeys) ||
        rawRecord.kind !== "test-audit-controller-renewal" ||
        rawRecord.repository !== SOURCE_REPOSITORY || rawRecord.branch !== "main" ||
        typeof rawRecord.enabled !== "boolean" || typeof rawRecord.publish !== "boolean" ||
        !sha40(rawRecord.source) || !sha40(rawRecord.parentController) || !sha40(rawRecord.targetController) ||
        !sha40(rawRecord.verifierRevision) || !runIdentity(rawRecord.parent) ||
        !hex64(rawRecord.manifestDigest) || !hex64(rawRecord.inventoryDigest) ||
        !imageSha(rawRecord.priorImageDigest) || !imageSha(rawRecord.imageDigest) ||
        !["success","skipped","failure","cancelled","timed_out"].includes(rawRecord.publication))
        throw new Error("Test audit renewal record is malformed.");
    if (!rawRecord.enabled) return undefined;
    if (!runIdentity(`${context.runId}-${context.attempt}`) || !sha40(context.controllerRevision) ||
        !imageSha(context.imageDigest) || !sha40(context.verifierRevision))
        throw new Error("Test audit renewal context is malformed.");
    if (rawRecord.targetController !== context.controllerRevision || rawRecord.imageDigest !== context.imageDigest ||
        rawRecord.verifierRevision !== context.verifierRevision ||
        rawRecord.parentController === context.controllerRevision ||
        rawRecord.priorImageDigest === rawRecord.imageDigest)
        throw new Error("Test audit renewal runtime or controller context drifted.");
    return { ...rawRecord, controllerRevision: context.controllerRevision, recordSha256: sha256(JSON.stringify(rawRecord)) };
}
export async function loadTestAuditTransition(context, readRecord = document) {
    let rawRecord;
    try {
        rawRecord = await readRecord(path.join(root, "config/ci/test-audit-transition.json"));
    } catch (error) {
        if (error?.code === "ENOENT") return undefined;
        throw error;
    }
    if (!exactKeys(rawRecord, transitionKeys) ||
        rawRecord.kind !== "test-audit-controller-transition" ||
        rawRecord.repository !== SOURCE_REPOSITORY || rawRecord.branch !== "main" ||
        typeof rawRecord.enabled !== "boolean" || typeof rawRecord.publish !== "boolean" ||
        !sha40(rawRecord.source) || !sha40(rawRecord.parentController) || !sha40(rawRecord.verifierRevision) ||
        !runIdentity(rawRecord.parent) || !runIdentity(rawRecord.priorChild) || !runIdentity(rawRecord.run) ||
        !Number.isSafeInteger(rawRecord.cursor) || rawRecord.cursor < 0 ||
        rawRecord.pageSize !== 1 || rawRecord.pagePaths !== 1 ||
        !Number.isSafeInteger(rawRecord.totalPaths) || rawRecord.totalPaths < 1 ||
        rawRecord.cursor + rawRecord.pagePaths > rawRecord.totalPaths ||
        !hex64(rawRecord.manifestDigest) || !hex64(rawRecord.inventoryDigest) ||
        !imageSha(rawRecord.priorImageDigest) || !imageSha(rawRecord.imageDigest) ||
        !exactKeys(rawRecord.priorFormatting, formattingKeys) ||
        typeof rawRecord.priorFormatting.runId !== "string" ||
        !/^[1-9][0-9]{0,19}$/.test(rawRecord.priorFormatting.runId) ||
        typeof rawRecord.priorFormatting.attempt !== "string" ||
        !/^[1-9][0-9]{0,5}$/.test(rawRecord.priorFormatting.attempt) ||
        !sha40(rawRecord.priorFormatting.sha) || rawRecord.priorFormatting.ref !== "refs/heads/main")
        throw new Error("Test audit transition record is malformed.");
    if (!rawRecord.enabled) return undefined;
    if (!runIdentity(`${context.runId}-${context.attempt}`) || !sha40(context.controllerRevision) ||
        !imageSha(context.imageDigest) || !sha40(context.verifierRevision))
        throw new Error("Test audit transition context is malformed.");
    if (rawRecord.run !== `${context.runId}-${context.attempt}`) return undefined;
    if (rawRecord.imageDigest !== context.imageDigest || rawRecord.verifierRevision !== context.verifierRevision ||
        rawRecord.parentController === context.controllerRevision || rawRecord.verifierRevision === context.controllerRevision)
        throw new Error("Test audit transition runtime or controller context drifted.");
    return { ...rawRecord, controllerRevision: context.controllerRevision, recordSha256: sha256(JSON.stringify(rawRecord)) };
}

export function transitionMatchesFormatting(record, { sha, branch, upstream }) {
    return record?.enabled === true && record?.source === sha && record?.branch === branch && branch === "main" &&
        record?.priorFormatting?.sha === sha && record?.priorFormatting?.ref === "refs/heads/main" &&
        record?.priorFormatting?.runId === upstream?.runId &&
        record?.priorFormatting?.attempt === upstream?.attempt;
}

async function document(file, maximum = 512 * 1024) {
    const bytes = await readFile(file);

    if (bytes.length > maximum) throw new Error("Trusted input document exceeds its byte budget.");

    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

async function protectedConfig(name) {
    return document(path.join(homedir(), "ci", name));
}

async function secret(file) {
    if (!path.isAbsolute(file)) throw new Error("Credential path must be absolute.");
    const value = (await readFile(file, "utf8")).trim();

    if (value.length < 32 || value.length > 512 || /\s/.test(value))
        throw new Error("Invalid protected credential.");

    return value;
}

async function fetchJson(url, token, body, maximum = 256 * 1024) {
    if (body)
        for (const value of [
            token,
            ...Object.entries(process.env)
                .filter(([name]) => /TOKEN|SECRET|PASSWORD|API_KEY/i.test(name))
                .map(([, value]) => value),
        ])
            if (value && value.length >= 8 && body.includes(value))
                throw new Error("Payload contains configured credential material.");

    const options = {
        method: body ? "POST" : "GET",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(body ? 120000 : 30000),
    };

    if (body) options.body = body;
    const response = await fetch(url, options);
    const reader = response.body?.getReader();

    if (!reader) throw new Error("Service returned no response body.");

    const decoder = new TextDecoder("utf-8", { fatal: true });
    let text = "";
    let bytes = 0;

    for (;;) {
        const next = await reader.read();

        if (next.done) break;
        bytes += next.value.byteLength;

        if (bytes > maximum) {
            await reader.cancel();
            throw new Error("Service response exceeds its byte budget.");
        }

        text += decoder.decode(next.value, { stream: true });
    }

    text += decoder.decode();

    if (!response.ok) throw Object.assign(new Error(`Service request failed: HTTP ${response.status}.`), { status: response.status });

    return JSON.parse(text);
}

async function createController(github, controllerRevision, transition) {
    const head = async (branch) =>
        exactSha((await github.request("GET", `${prefix}/git/ref/heads/${branch}`)).object.sha);

    const inspector = await protectedConfig("omg-ci-inspector.json");
    const endpoint = sourceReviewEndpoint(inspector);
    const inspectorToken = await secret(inspector.tokenFile);
    const config = await protectedConfig("omg-cloud-ci.json");
    const policy = ciPolicy(config);
    const token = await secret(config.tokenFile);
    admitCloudCiRuntime(await fetchJson(new URL("/health", config.endpoint), token));
    const coder = await protectedConfig("omg-ci-coder.json");
    const codingEndpoint = coderEndpoint(coder);
    const codingToken = await secret(coder.tokenFile);
    const codingPolicy = { ...policy, bundleSha256: coder.bundleSha256 };
    const runId = process.env.GITHUB_RUN_ID;
    const attempt = process.env.GITHUB_RUN_ATTEMPT;

    if (
        ![runId, attempt].every(
            (value) => /^[1-9][0-9]*$/.test(value ?? "") && Number.isSafeInteger(Number(value)),
        )
    )
        throw new Error("Exact GitHub run identity is required.");

    const code = async (input, review, candidateIndex, testAuditTask) => {
            const request = parseCodingRequest({
                repository: input.repository,
                sha: input.sha,
                branch: input.branch,
                runId,
                attempt,
                source: input,
                ...(testAuditTask ? {testAuditTask} : {hypothesis:review,candidateIndex}),
            });

            const id = operationIdentity(request);

            const started = await fetchJson(
                new URL("/operations", codingEndpoint),
                codingToken,
                JSON.stringify(request),
            );

            if (started.id !== id) throw new Error("Coding operation start identity mismatch.");
            const deadline = Date.now() + (testAuditTask ? 120 : 110) * 60 * 1000;

            for (;;) {
                const state = await fetchJson(
                    new URL(`/operations/${id}`, codingEndpoint),
                    codingToken,
                    undefined,
                    testAuditTask ? 2 * 1024 * 1024 : 512 * 1024,
                );

                if (state.id !== id) throw new Error("Coding operation status identity mismatch.");

                if (state.status === "done") {
                    const adapted = admitCoderResult(state, request, codingPolicy);

                    return adapted ? { ...adapted, coding: { id, request } } : null;
                }

                if (!["queued", "running"].includes(state.status) || Date.now() >= deadline)
                    throw new Error("Coding operation did not complete; publication refused.");
                await setTimeout(5000);
            }
    };

    return {
        head,
        controllerRevision,
        format: async (sha, branch, upstream, requirePortableEvidence = false) => {
            const request = parseCloudCiRequest({
                repository: SOURCE_REPOSITORY,
                sha,
                ref: `refs/heads/${branch}`,
                runId: upstream?.runId ?? runId,
                attempt: upstream?.attempt ?? attempt,
            });

            try {
                return await admitFormattingRun({
                    sha,
                    branch,
                    upstream,
                    runId,
                    attempt,
                    imageDigest: policy.imageDigest,
                    priorImageDigest: transitionMatchesFormatting(transition, {
                        sha,
                        branch,
                        upstream,
                    })
                        ? transition.priorImageDigest
                        : undefined,
                    requirePortableEvidence,
                    fetchReceipt: (id) =>
                        fetchJson(new URL(`/runs/${id}/evidence`, config.endpoint), token),
                    startRun: async (startRequest) => {
                        await execute("bun", ["scripts/cloud-ci-mirror.mjs", sha]);

                        const id = `cl-${startRequest.runId}-${startRequest.attempt}-${sha}`;
                        const started = await fetchJson(
                            new URL("/runs", config.endpoint),
                            token,
                            JSON.stringify(startRequest),
                        );

                        if (started.id !== id || started.sha !== sha)
                            throw new Error("Formatting run identity mismatch.");
                        const deadline = Date.now() + 60 * 60 * 1000;

                        for (;;) {
                            if (Date.now() >= deadline)
                                throw new Error("Formatting run deadline exceeded.");
                            const state = await fetchJson(
                                new URL(`/runs/${id}`, config.endpoint),
                                token,
                            );

                            if (state.id !== id || state.sha !== sha)
                                throw new Error("Formatting run identity mismatch.");

                            if (["complete", "errored", "terminated"].includes(state.status)) break;

                            if (state.status === "unknown")
                                throw new Error("Formatting run state is unknown.");
                            await setTimeout(5000);
                        }
                    },
                    verifyLogs: async (id, format) => {
                        await verifyCloudCiObjects({ checks: [format] }, (key) =>
                            fetch(
                                new URL(
                                    `/runs/${id}/logs/${key.slice(`logs/${id}/`.length)}`,
                                    config.endpoint,
                                ),
                                {
                                    headers: { authorization: `Bearer ${token}` },
                                    redirect: "error",
                                    signal: AbortSignal.timeout(30000),
                                },
                            ),
                        );
                    },
                });
            } catch (error) {
                if (error instanceof CloudCiEngineFailure) throw error;
                return {
                    status: "blocked",
                    reason: "source-format-evidence-unavailable-or-rejected",
                    runId: request.runId,
                    attempt: request.attempt,
                    sha,
                    ref: request.ref,
                };
            }
        },
        collect: async (sha, _branch, range, options) => {
            if(range?.kind === "test-audit") {
                const manifest=JSON.parse(await readFile(path.join(root,"config/test-audit-backlog.json"),"utf8"));
                const page=await collectTestAuditPage({sha,manifest,cursor:range.cursor,pageSize:1,inventoryDigest:range.inventoryDigest,manifestDigest:range.resnapshotOf?range.manifestDigest:undefined,directory:root});
                const entries=page.rows.filter(row=>row.status==="selected").map(row=>({...row.request.source.sourceFiles[0],size:Buffer.byteLength(row.request.source.sourceFiles[0].content)}));
                return {baseSha:sha,entries,rows:page.rows,unreviewedPaths:page.rows.filter(row=>row.status==="held").map(row=>({path:row.id,reason:row.reason})),
                    sourceRange:{kind:"test-audit",sha,manifestDigest:testAuditManifestDigest(manifest),...(range.resnapshotOf?{resnapshotOf:range.resnapshotOf,qualification:range.qualification}:{}),inventoryDigest:page.inventoryDigest,cursor:page.cursor,nextCursor:page.nextCursor,totalPaths:page.total,pagePaths:page.rows.length,pageSize:1}};
            }
            if (range?.kind !== "runtime") return collectSources(github, sha, range);
            const collected = await collectRuntimeSources({ github, sha, directory: root, endpoint: config.endpoint, token,
                request: fetchJson, reviewRef: { runId, attempt, sha, controllerRevision }, ...options });
            if (collected.replayRef) {
                const { runId: originalRun, attempt: originalAttempt } = collected.replayRef;
                if (!/^[1-9][0-9]{0,19}$/.test(originalRun ?? "") || !/^[1-9][0-9]{0,5}$/.test(originalAttempt ?? ""))
                    throw new Error("Invalid canonical runtime review reference.");
                try {
                    collected.replayReport = await fetchJson(new URL(`/review-records/${originalRun}-${originalAttempt}`, config.endpoint), token, undefined, 2 * 1024 * 1024);
                } catch (error) {
                    if (!(error instanceof Error) || error.status !== 404) throw error;
                    collected.replayReport = null;
                }
            }
            return collected;
        },
        review: (input) => fetchJson(endpoint, inspectorToken, JSON.stringify(input), 128 * 1024),
        adapt: (input,review,candidateIndex) => code(input,review,candidateIndex),
        portableTest: (row, formatting) => admitPortableAuditRow(row, formatting, {
            receipt: id => fetchJson(new URL(`/runs/${id}/evidence`, config.endpoint), token, undefined, 2 * 1024 * 1024),
            report: (id, key) => fetch(new URL(`/runs/${id}/reports/${key.split("/")[2]}`, config.endpoint), {
                headers: { authorization: `Bearer ${token}` }, redirect: "error", signal: AbortSignal.timeout(30000),
            }),
        }, policy.imageDigest),
        audit: async (row) => {
            const adapted=await code(row.request.source,undefined,undefined,row.task);
            if(!adapted)return null;
            const request={repository:SOURCE_REPOSITORY,sha:row.request.sha,ref:"refs/heads/main",runId,attempt,
                testAudit:{proposal:adapted.proposal,verifierRevision:policy.verifierRevision}};
            const id=`cl-${runId}-${attempt}-${request.sha}-ta-${testAuditDigest(adapted.proposal).slice(0,16)}`;
            const receipt=await fetchJson(new URL(`/runs/${id}/receipt`,config.endpoint),token,undefined,2*1024*1024);
            await verifyCloudTestAudit(receipt,request,policy,(key)=>fetch(new URL(`/runs/${id}/${key.split("/")[0]}/${key.split("/")[2]}`,config.endpoint),{
                headers:{authorization:`Bearer ${token}`},redirect:"error",signal:AbortSignal.timeout(30000)}));
            return {request,id,coderOperationId:adapted.coding.id,coding:adapted.coding,readPaths:adapted.readPaths};
        },
        mirror: async (sha) => {
            await execute("bun", ["scripts/cloud-ci-mirror.mjs", sha]);
        },
        verify: async (adapted, sha, branch) => {
            const request = {
                repository: SOURCE_REPOSITORY,
                sha,
                ref: `refs/heads/${branch}`,
                runId,
                attempt,
                verification: {
                    proposal: adapted.proposal,
                    regression: adapted.regression,
                    verifierRevision: policy.verifierRevision,
                },
            };

            if (Buffer.byteLength(JSON.stringify(request)) > 64 * 1024)
                throw new Error("Verification request exceeds 64 KiB.");
            const id = `cl-${runId}-${attempt}-${sha}-v-${proposalDigest(adapted.proposal).slice(0, 16)}`;

            const codingState = await fetchJson(
                new URL(`/operations/${adapted.coding.id}`, codingEndpoint),
                codingToken,
                undefined,
                512 * 1024,
            );

            const current = admitCoderResult(codingState, adapted.coding.request, codingPolicy);

            if (
                !current ||
                current.proposalSha256 !== proposalDigest(adapted.proposal) ||
                JSON.stringify(current.regression) !== JSON.stringify(adapted.regression)
            )
                throw new Error("Coding proposal changed before verification admission.");

            const nativeReceipt = await fetchJson(
                new URL(`/runs/${id}/receipt`, config.endpoint),
                token,
            );

            const sources = await collectCandidateSources({
                github,
                sha,
                paths: [
                    ...new Set([
                        adapted.proposal.finding.path,
                        ...adapted.proposal.changes.map((change) => change.path),
                    ]),
                ],
            });

            const verified = verifyPublicationProof(
                nativeReceipt,
                request,
                config,
                adapted,
                sources,
            );

            await verifyCloudCiObjects(nativeReceipt, (key) =>
                fetch(
                    new URL(
                        `/runs/${id}/${key.split("/")[0]}/${key.split("/")[2]}`,
                        config.endpoint,
                    ),
                    {
                        headers: { authorization: `Bearer ${token}` },
                        redirect: "error",
                        signal: AbortSignal.timeout(30000),
                    },
                ),
            );

            return {
                ...verified,
                request,
                nativeReceipt,
                regression: adapted.regression,
                id,
                coding: adapted.coding,
            };
        },
    };
}

export async function main(args = process.argv.slice(2)) {
    const [mode, directory, flag] = args;

    if (
        !["collect", "publish", "continue", "recover"].includes(mode) ||
        !directory ||
        (flag !== undefined && flag !== "--publish") ||
        args.length > 3 ||
        (mode !== "publish" && flag)
    )
        throw new Error(
            "Usage: bun scripts/ai-review-flow.mjs <collect|publish|continue|recover> <output-directory> [--publish]",
        );
    const github = createGhClient();
    const revision = exactSha((await git(["rev-parse", "HEAD"])).trim());

    if (mode === "collect") {
        const event = await document(process.env.GITHUB_EVENT_PATH);
        let target = pinReviewTarget(reviewTarget(process.env.GITHUB_EVENT_NAME, event), process.env.GITHUB_SHA);
        let campaignManifest;
        if(target.range?.kind === "test-audit") {
            campaignManifest=JSON.parse(await readFile(path.join(root,"config/test-audit-backlog.json"),"utf8"));
            const digest=testAuditManifestDigest(campaignManifest);
            if(target.range.manifestDigest && target.range.manifestDigest!==digest)throw new Error("Campaign manifest drift");
            if(target.range.cursor>=campaignManifest.rows.length)throw new Error("Campaign cursor outside manifest");
            target={...target,range:{...target.range,sha:target.sha,manifestDigest:digest,totalPaths:campaignManifest.rows.length,pageSize:1,pagePaths:1,nextCursor:target.range.cursor+1<campaignManifest.rows.length?target.range.cursor+1:null}};
        }
        let transition;
        if (target.auditParent) {
            const config = await protectedConfig("omg-cloud-ci.json");
            const policy = ciPolicy(config);
            const token = await secret(config.tokenFile);
            transition = await loadTestAuditTransition({ runId: process.env.GITHUB_RUN_ID, attempt: process.env.GITHUB_RUN_ATTEMPT,
                controllerRevision: revision, imageDigest: policy.imageDigest, verifierRevision: policy.verifierRevision });
            const parent = await fetchJson(new URL(`/review-records/${target.auditParent}`, config.endpoint), token, undefined, 2 * 1024 * 1024);
            const renewal = target.range?.kind === "test-audit" && target.range?.resnapshot === true &&
                parent.controllerRevision !== revision
                ? await loadTestAuditRenewal({ runId: process.env.GITHUB_RUN_ID, attempt: process.env.GITHUB_RUN_ATTEMPT,
                    controllerRevision: revision, imageDigest: policy.imageDigest, verifierRevision: policy.verifierRevision })
                : undefined;
            const renewalApplies = renewal !== undefined &&
                parent.controllerRevision === renewal.parentController &&
                target.auditParent === renewal.parent;
            const mainSha = renewalApplies
                ? exactSha((await github.request("GET", `${prefix}/git/ref/heads/main`)).object.sha)
                : undefined;
            const priorChild = transition && target.range?.kind === "test-audit" &&
                transition.source === target.sha && transition.parent === target.auditParent
                ? await fetchJson(new URL(`/review-records/${transition.priorChild}`, config.endpoint), token, undefined, 2 * 1024 * 1024)
                : undefined;
            target = admitAuditResume(target, parent, revision, campaignManifest ? { transition, renewal: renewalApplies ? renewal : undefined, mainSha, priorChild,
                runId: process.env.GITHUB_RUN_ID, attempt: process.env.GITHUB_RUN_ATTEMPT,
                imageDigest: policy.imageDigest, verifierRevision: policy.verifierRevision,
                manifestDigest: testAuditManifestDigest(campaignManifest),
                publicationResult: await parentPublicationResult(github, target.auditParent, parent) } : undefined);
        }
        let report;
        if(campaignManifest){
            const config=await protectedConfig("omg-cloud-ci.json"),token=await secret(config.tokenFile);
            const prior=await findDuplicateTestAuditRecord({github,target,revision,manifestDigest:testAuditManifestDigest(campaignManifest),currentRunId:process.env.GITHUB_RUN_ID,
                loadRecord:(ref)=>fetchJson(new URL(`/review-records/${ref}`,config.endpoint),token,undefined,2*1024*1024)});
            if(prior) report={repository:SOURCE_REPOSITORY,branch:"main",sha:target.sha,baseSha:target.sha,status:"duplicate-noop",sourceRange:target.range,
                formatting:{status:"not-started",reason:"equivalent-campaign-row-already-recorded"},suppliedPaths:[],readPaths:[],unreviewedPaths:[],batches:[],publications:[],candidateOutcomes:[],testAudits:[],publishRequested:target.publish,
                duplicateOf:prior,coverageMeaning:"Duplicate campaign intake performed no inference, verification, continuation or coverage credit."};
        }
        report ??= await runReviewFlow({ target, io: await createController(github, revision, transition) });
        if(campaignManifest){report.campaignParent=target.auditParent??null;report.triggerSha=exactSha(process.env.GITHUB_SHA);report.campaignRun={runId:process.env.GITHUB_RUN_ID,attempt:process.env.GITHUB_RUN_ATTEMPT};}
        if (target.controllerTransition) report.controllerTransition = target.controllerTransition;
        report.controllerRevision = revision;
        await mkdir(directory, { recursive: true });
        await writeFile(path.join(directory, "review.json"), `${JSON.stringify(report)}\n`, {
            flag: "wx",
        });
        const config = await protectedConfig("omg-cloud-ci.json");

        ciPolicy(config);
        const record = reviewRecord(
            report,
            process.env.GITHUB_RUN_ID,
            process.env.GITHUB_RUN_ATTEMPT,
        );

        const stored = await fetchJson(
            new URL(`/review-records/${record.runId}-${record.attempt}`, config.endpoint),
            await secret(config.tokenFile),
            JSON.stringify(record),
        );

        if (stored.stored !== true) throw new Error("Private review record was not acknowledged.");
        process.stdout.write(
            `${JSON.stringify({
                sha: report.sha,
                status: report.status,
                formatting: report.formatting.status,
                supplied: report.suppliedPaths.length,
                read: report.readPaths.length,
                unreviewed: report.unreviewedPaths.length,
                verifiedCandidates: report.publications.length + (report.testAudits?.filter(audit=>audit.request.testAudit.proposal.purpose === "existing-test-strengthening").length ?? 0),
                publishRequested: report.publishRequested,
            })}\n`,
        );

        if (process.env.GITHUB_OUTPUT)
            await writeFile(
                process.env.GITHUB_OUTPUT,
                `controller-sha=${revision}\npublish=${report.publishRequested}\nverified=${report.publications.length + (report.testAudits?.filter(audit=>audit.request.testAudit.proposal.purpose === "existing-test-strengthening").length ?? 0)}\naudit-next=${["audit","test-audit"].includes(report.sourceRange?.kind) && report.sourceRange?.intake !== "sentry-runtime" && (report.sourceRange.nextCursor !== null || report.sourceRange.kind === "test-audit") && (report.sourceRange.kind === "test-audit" ? ["reviewed","incomplete-stale","format-blocked"].includes(report.status) : ["reviewed", "no-reviewable-source"].includes(report.status))}\ntest-audit=${report.sourceRange?.kind === "test-audit"}\nruntime-ack=${runtimeReviewCanAcknowledge(report)}\n`,
                { flag: "a" },
            );

        return;
    }

    const config = await protectedConfig("omg-cloud-ci.json");

    ciPolicy(config);
    const token = await secret(config.tokenFile);
    const runId = process.env.GITHUB_RUN_ID;
    const attempt = process.env.GITHUB_RUN_ATTEMPT;

    if (!/^[1-9][0-9]{0,19}$/.test(runId ?? "") || !/^[1-9][0-9]{0,5}$/.test(attempt ?? ""))
        throw new Error("Invalid review run identity.");

    const dispatchAudit=async(inputs)=>{
        const args=["api","--hostname","github.com","--method","POST",`${prefix}/actions/workflows/ai-review.yml/dispatches`,"-f","ref=main"];
        for(const[key,value]of Object.entries(inputs))args.push("-f",`inputs[${key}]=${value}`);
        await execute("gh",args);
    };
    if(mode === "recover"){
        const manifest=JSON.parse(await readFile(path.join(root,"config/test-audit-backlog.json"),"utf8"));
        const currentSha=exactSha((await github.request("GET",`${prefix}/git/ref/heads/main`)).object.sha);
        const policy=ciPolicy(config);
        const renewal=await loadTestAuditRenewal({runId,attempt,controllerRevision:revision,
            imageDigest:policy.imageDigest,verifierRevision:policy.verifierRevision});
        const recovered=await recoverTestAuditCampaign({github,currentSha,revision,renewal,
            imageDigest:policy.imageDigest,verifierRevision:policy.verifierRevision,
            manifestDigest:testAuditManifestDigest(manifest),currentRunId:runId,currentRunAttempt:attempt,dispatch:dispatchAudit,
            loadRecord:(ref)=>fetchJson(new URL(`/review-records/${ref}`,config.endpoint),token,undefined,2*1024*1024),
            loadIntent:(ref)=>fetchJson(new URL(`/review-records/${ref}/recovery-intent`,config.endpoint),token,undefined,64*1024),
            storeIntent:(ref,body)=>fetchJson(new URL(`/review-records/${ref}/recovery-intent`,config.endpoint),token,JSON.stringify(body),64*1024),
            rerun:(id)=>execute("gh",["api","--hostname","github.com","--method","POST",`${prefix}/actions/runs/${id}/rerun`])});
        process.stdout.write(`${JSON.stringify(recovered)}\n`);return;
    }

    const report = await fetchJson(
        new URL(`/review-records/${runId}-${attempt}`, config.endpoint),
        token,
        undefined,
        2 * 1024 * 1024,
    );

    if (
        report.controllerRevision !== revision ||
        report.repository !== SOURCE_REPOSITORY ||
        !Array.isArray(report.publications) ||
        report.publications.length > 3 || (report.testAudits !== undefined && (!Array.isArray(report.testAudits) || report.testAudits.length > 2))
    )
        throw new Error("Publication artifact has an untrusted controller identity.");

    let proofRunId = runId;
    let proofAttempt = attempt;
    if (report.replayOf) {
        const { runId: originalRun, attempt: originalAttempt } = report.replayOf;
        if (!/^[1-9][0-9]{0,19}$/.test(originalRun ?? "") || !/^[1-9][0-9]{0,5}$/.test(originalAttempt ?? ""))
            throw new Error("Invalid canonical runtime publication reference.");
        const original = await fetchJson(new URL(`/review-records/${originalRun}-${originalAttempt}`, config.endpoint), token, undefined, 2 * 1024 * 1024);
        admitRuntimeReplay({ original, replayRef: report.replayOf, runtimeEvents: report.runtimeEvents,
            sha: report.sha, controllerRevision: revision, publications: report.publications });
        proofRunId = originalRun;
        proofAttempt = originalAttempt;
    }

    if (mode === "continue") {
        if (report.runtimeEvents?.length) {
            const finalized = await finalizeRuntimeReview({ report, publicationResult: process.env.PUBLICATION_RESULT,
                acknowledge: () => acknowledgeRuntimeSources({ endpoint: config.endpoint, token, report, runId, attempt, request: fetchJson }) });
            process.stdout.write(`${JSON.stringify(finalized)}\n`);
            return;
        }
        const currentSha = exactSha((await github.request("GET", `${prefix}/git/ref/heads/main`)).object.sha);
        const continuation = sourceAuditContinuation(report, currentSha, runId, attempt, process.env.PUBLICATION_RESULT);
        if(report.sourceRange?.kind === "test-audit"){
            const dispatched=await dispatchTestAuditPlan({github,plan:continuation,dispatch:dispatchAudit,currentRunId:runId});
            process.stdout.write(`${JSON.stringify(dispatched)}\n`);return;
        }
        if (continuation.status === "continue") {
            const args = ["api", "--hostname", "github.com", "--method", "POST", `${prefix}/actions/workflows/ai-review.yml/dispatches`, "-f", "ref=main"];
            for (const [key, value] of Object.entries(continuation.inputs)) args.push("-f", `inputs[${key}]=${value}`);
            await execute("gh", args);
        }
        process.stdout.write(`${JSON.stringify(continuation)}\n`);
        return;
    }

    if (flag === "--publish" && report.publishRequested !== true)
        throw new Error("This review did not authorize publication.");
    const results = [];
    const coder = await protectedConfig("omg-ci-coder.json");
    const codingEndpoint = coderEndpoint(coder);
    const codingToken = await secret(coder.tokenFile);
    const codingPolicy = { ...ciPolicy(config), bundleSha256: coder.bundleSha256 };

    for (const publication of report.publications) {
        const { proposal, request, regression, id } = publication;
        const expectedId = `cl-${request.runId}-${request.attempt}-${proposal.baseSha}-v-${proposalDigest(proposal).slice(0, 16)}`;

        if (
            id !== expectedId ||
            request.runId !== proofRunId ||
            request.attempt !== proofAttempt ||
            proposal.baseSha !== report.sha ||
            proposal.branch !== report.branch ||
            proposalDigest(request.verification.proposal) !== proposalDigest(proposal)
        )
            throw new Error("Publication request identity mismatch.");
        const coding = publication.coding;
        const codingRequest = parseCodingRequest(coding?.request);

        if (
            coding.id !== operationIdentity(codingRequest) ||
            codingRequest.sha !== proposal.baseSha ||
            codingRequest.branch !== proposal.branch ||
            codingRequest.runId !== proofRunId ||
            codingRequest.attempt !== proofAttempt
        )
            throw new Error("Publication lacks exact skill-required coding provenance.");

        const codingState = await fetchJson(
            new URL(`/operations/${coding.id}`, codingEndpoint),
            codingToken,
            undefined,
            512 * 1024,
        );

        const coded = admitCoderResult(codingState, codingRequest, codingPolicy);

        if (
            !coded ||
            coded.proposalSha256 !== proposalDigest(proposal) ||
            JSON.stringify(coded.regression) !== JSON.stringify(regression)
        )
            throw new Error("Publication differs from the skill-required coding result.");
        const nativeReceipt = await fetchJson(
            new URL(`/runs/${id}/receipt`, config.endpoint),
            token,
        );

        const sources = await collectCandidateSources({
            github,
            sha: proposal.baseSha,
            paths: [
                ...new Set([
                    proposal.finding.path,
                    ...proposal.changes.map((change) => change.path),
                ]),
            ],
        });

        const verified = verifyPublicationProof(
            nativeReceipt,
            request,
            config,
            { proposal, regression },
            sources,
        );

        await verifyCloudCiObjects(nativeReceipt, (key) =>
            fetch(
                new URL(`/runs/${id}/${key.split("/")[0]}/${key.split("/")[2]}`, config.endpoint),
                {
                    headers: { authorization: `Bearer ${token}` },
                    redirect: "error",
                    signal: AbortSignal.timeout(30000),
                },
            ),
        );

        results.push(
            await publishAiReview({
                proposal,
                ...verified.policy,
                receipt: verified.receipt,
                github,
                publish: flag === "--publish",
            }),
        );
    }

    for(const audit of report.testAudits ?? []) {
        if(audit.request?.testAudit?.proposal?.purpose === "existing-test-sensitivity")continue;
        const {request,id,coding}=audit;
        const expectedId=`cl-${runId}-${attempt}-${report.sha}-ta-${testAuditDigest(request.testAudit.proposal).slice(0,16)}`;
        if(id!==expectedId || request.runId!==runId || request.attempt!==attempt || request.sha!==report.sha || request.ref!=="refs/heads/main")
            throw new Error("Test audit publication request identity mismatch.");
        const codingRequest=parseCodingRequest(coding?.request);
        if(!codingRequest.testAuditTask || coding.id!==audit.coderOperationId || coding.id!==operationIdentity(codingRequest) ||
            codingRequest.sha!==report.sha || codingRequest.runId!==runId || codingRequest.attempt!==attempt)
            throw new Error("Test audit lacks exact coding provenance.");
        const state=await fetchJson(new URL(`/operations/${coding.id}`,codingEndpoint),codingToken,undefined,2*1024*1024);
        const coded=admitCoderResult(state,codingRequest,codingPolicy);
        if(!coded || coded.proposalSha256!==testAuditDigest(request.testAudit.proposal))throw new Error("Test audit coder proposal changed.");
        const receipt=await fetchJson(new URL(`/runs/${id}/receipt`,config.endpoint),token,undefined,2*1024*1024);
        results.push(await publishTestAuditReview({github,request,receipt,policy:ciPolicy(config),publish:flag==="--publish",
            load:(key)=>fetch(new URL(`/runs/${id}/${key.split("/")[0]}/${key.split("/")[2]}`,config.endpoint),{
                headers:{authorization:`Bearer ${token}`},redirect:"error",signal:AbortSignal.timeout(30000)})}));
    }

    process.stdout.write(`${JSON.stringify({ publish: flag === "--publish", results })}\n`);
}

if (import.meta.main) await main();

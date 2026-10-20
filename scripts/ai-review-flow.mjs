import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { setTimeout } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Schema } from "effect";
import { collectCandidateSources } from "./ai-review-candidate.mjs";
import { admitCoderResult, coderEndpoint } from "./ai-coder-client.mjs";
import { parseCodingRequest, operationIdentity } from "../services/ci-coder/src/request.ts";
import { proposalDigest, publishAiReview } from "./ai-review-publication.mjs";
import { ciPolicy, verifyPublicationProof } from "./ai-review-proof.mjs";
import { createGhClient } from "./publish-ai-review.mjs";
import {
    verifyCloudCiObjects,
    parseCloudCiRequest,
    cloudCiPlanSha256,
} from "./cloud-ci-evidence.mjs";
import { expectedCloudChecks } from "../services/cloud-ci/runner/plan.mjs";
import {
    SOURCE_REPOSITORY,
    sourceChanges,
    isReviewSourcePath,
    createSourceReviewEvidence,
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

        if (Object.keys(input).some((key) => !["branch", "publish"].includes(key)))
            throw new Error("Unknown manual review input.");

        if (![undefined, false, true, "false", "true"].includes(input.publish))
            throw new Error("Invalid publication input.");

        return {
            branch: branchName(input.branch),
            sha: null,
            publish: input.publish === true || input.publish === "true",
        };
    }

    throw new Error("Unsupported review event.");
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
        else if (Buffer.byteLength(entry.diff) > 64000) reason = "diff-byte-budget-exceeded";

        if (reason) {
            unreviewedPaths.push({ path: entry.path, reason });
            continue;
        }

        if (batch.length === 12 || bytes + Buffer.byteLength(entry.diff) > 64000) {
            batches.push(batch);
            batch = [];
            bytes = 0;
        }

        if (batches.length >= 4) {
            unreviewedPaths.push({ path: entry.path, reason: "batch-budget-exceeded" });
            continue;
        }

        batch.push(entry);
        bytes += Buffer.byteLength(entry.diff);
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

    if (target.sha !== null && target.sha !== head) throw new Error("Review target is stale.");
    const sha = head;
    const formatting = await io.format(sha, branch, target.upstream);

    if (formatting.status !== "passed")
        return {
            repository: SOURCE_REPOSITORY,
            branch,
            sha,
            baseSha: null,
            status: "format-blocked",
            formatting,
            suppliedPaths: [],
            readPaths: [],
            unreviewedPaths: [],
            batches: [],
            publications: [],
            candidateOutcomes: [],
            coverageMeaning:
                "Source inventory and model review were not started because formatting evidence was not admitted.",
            publishRequested: target.publish,
        };

    const range =
        target.range ??
        (formatting.sourceBaseSha
            ? { kind: "push", baseSha: formatting.sourceBaseSha }
            : undefined);

    let collected;

    try {
        collected = await io.collect(sha, branch, range);
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
    };

    let candidateCount = 0;
    let mirrored = false;

    for (const entries of partition.batches) {
        const evidence = createSourceReviewEvidence({
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

    if (!response.ok) throw new Error(`Service request failed: HTTP ${response.status}.`);

    return JSON.parse(text);
}

async function createController(github) {
    const head = async (branch) =>
        exactSha((await github.request("GET", `${prefix}/git/ref/heads/${branch}`)).object.sha);

    const inspector = await protectedConfig("omg-ci-inspector.json");
    const endpoint = sourceReviewEndpoint(inspector);
    const inspectorToken = await secret(inspector.tokenFile);
    const config = await protectedConfig("omg-cloud-ci.json");
    const policy = ciPolicy(config);
    const token = await secret(config.tokenFile);
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

    return {
        head,
        format: async (sha, branch, upstream) => {
            const request = parseCloudCiRequest({
                repository: SOURCE_REPOSITORY,
                sha,
                ref: `refs/heads/${branch}`,
                runId: upstream?.runId ?? runId,
                attempt: upstream?.attempt ?? attempt,
            });

            const id = `cl-${request.runId}-${request.attempt}-${sha}`;

            try {
                if (!upstream) {
                    await execute("bun", ["scripts/cloud-ci-mirror.mjs", sha]);

                    const started = await fetchJson(
                        new URL("/runs", config.endpoint),
                        token,
                        JSON.stringify(request),
                    );

                    if (started.id !== id || started.sha !== sha)
                        throw new Error("Formatting run identity mismatch.");
                    const deadline = Date.now() + 40 * 60 * 1000;

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
                }

                const receipt = await fetchJson(
                    new URL(`/runs/${id}/evidence`, config.endpoint),
                    token,
                );
                const format = admitSourceFormatting(receipt, request, policy.imageDigest);

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

                const formatting = {
                    status: "passed",
                    runId: request.runId,
                    attempt: request.attempt,
                    sha,
                    ref: request.ref,
                    conclusion: receipt.conclusion,
                    sourceFormat: format,
                };

                if (receipt.sourceBaseSha)
                    formatting.sourceBaseSha = exactSha(receipt.sourceBaseSha);

                return formatting;
            } catch {
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
        collect: (sha, _branch, range) => collectSources(github, sha, range),
        review: (input) => fetchJson(endpoint, inspectorToken, JSON.stringify(input), 128 * 1024),
        adapt: async (input, review, candidateIndex) => {
            const request = parseCodingRequest({
                repository: input.repository,
                sha: input.sha,
                branch: input.branch,
                runId,
                attempt,
                source: input,
                hypothesis: review,
                candidateIndex,
            });

            const id = operationIdentity(request);

            const started = await fetchJson(
                new URL("/operations", codingEndpoint),
                codingToken,
                JSON.stringify(request),
            );

            if (started.id !== id) throw new Error("Coding operation start identity mismatch.");
            const deadline = Date.now() + 45 * 60 * 1000;

            for (;;) {
                const state = await fetchJson(
                    new URL(`/operations/${id}`, codingEndpoint),
                    codingToken,
                    undefined,
                    512 * 1024,
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
        !["collect", "publish"].includes(mode) ||
        !directory ||
        (flag !== undefined && flag !== "--publish") ||
        args.length > 3 ||
        (mode === "collect" && flag)
    )
        throw new Error(
            "Usage: bun scripts/ai-review-flow.mjs <collect|publish> <output-directory> [--publish]",
        );
    const github = createGhClient();
    const revision = exactSha((await git(["rev-parse", "HEAD"])).trim());

    if (mode === "collect") {
        const event = await document(process.env.GITHUB_EVENT_PATH);
        const target = reviewTarget(process.env.GITHUB_EVENT_NAME, event);
        const report = await runReviewFlow({ target, io: await createController(github) });
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
                verifiedCandidates: report.publications.length,
                publishRequested: report.publishRequested,
            })}\n`,
        );

        if (process.env.GITHUB_OUTPUT)
            await writeFile(
                process.env.GITHUB_OUTPUT,
                `controller-sha=${revision}\npublish=${report.publishRequested}\nverified=${report.publications.length}\n`,
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
        report.publications.length > 3
    )
        throw new Error("Publication artifact has an untrusted controller identity.");

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
            request.runId !== process.env.GITHUB_RUN_ID ||
            request.attempt !== process.env.GITHUB_RUN_ATTEMPT ||
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
            codingRequest.runId !== runId ||
            codingRequest.attempt !== attempt
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

    process.stdout.write(`${JSON.stringify({ publish: flag === "--publish", results })}\n`);
}

if (import.meta.main) await main();

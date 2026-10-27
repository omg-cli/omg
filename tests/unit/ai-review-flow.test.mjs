import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import * as reviewFlow from "../../scripts/ai-review-flow.mjs";
import { gitBlobSha, adaptReviewCandidate } from "../../scripts/ai-review-candidate.mjs";
import { proposalDigest, sha256, publishAiReview } from "../../scripts/ai-review-publication.mjs";
import { collectRuntimeSources, acknowledgeRuntimeSources } from "../../scripts/sentry-review-input.mjs";
import { runtimeServer } from "./fixtures/runtime-server.mjs";
import { cloudCiPlanSha256 } from "../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudChecks, expectedCloudReports } from "../../services/cloud-ci/runner/plan.mjs";
import { verifyPublicationProof } from "../../scripts/ai-review-proof.mjs";
import {
    reviewTarget,
    partitionReviewSources,
    validateReviewReceipt,
    runReviewFlow,
    reviewRecord,
    admitSourceFormatting,
    collectSources,
} from "../../scripts/ai-review-flow.mjs";

const sha = "a".repeat(40);
const repository = { full_name: "omg-cli/omg" };

test("weekly source audit targets current main with honest resumable audit identity", () => {
    assert.deepEqual(reviewTarget("schedule", { repository }), {
        branch: "main", sha: null, publish: true,
        range: { kind: "audit", cursor: 0 },
    });
    assert.deepEqual(reviewTarget("workflow_dispatch", {
        repository, inputs: { branch: "main", scope: "source-audit", publish: "true" },
    }), { branch: "main", sha: null, publish: true, range: { kind: "audit", cursor: 0 } });
    assert.throws(() => reviewTarget("workflow_dispatch", {
        repository, inputs: { branch: "main", scope: "source-audit", audit_cursor: "48" },
    }), /audit/i);
});

test("audit continuation covers the next immutable page and stops explicitly on current-head changes", () => {
    assert.equal(typeof reviewFlow.sourceAuditContinuation, "function");
    const report = {
        repository: repository.full_name, sha, branch: "main", status: "reviewed", publishRequested: true,
        sourceRange: { kind: "audit", sha, inventoryDigest: "b".repeat(64), cursor: 0, pagePaths: 48, totalPaths: 53, nextCursor: 48 },
    };
    assert.deepEqual(reviewFlow.sourceAuditContinuation(report, sha, "42", "1"), {
        status: "continue", inputs: { branch: "main", scope: "source-audit", publish: "true", audit_sha: sha,
            audit_digest: "b".repeat(64), audit_cursor: "48", audit_parent: "42-1" },
    });
    assert.deepEqual(reviewFlow.sourceAuditContinuation(report, "c".repeat(40), "42", "1"), {
        status: "incomplete-stale", remainingPaths: 5,
    });
    assert.deepEqual(reviewFlow.sourceAuditContinuation({ ...report,
        sourceRange: { ...report.sourceRange, cursor: 48, pagePaths: 5, nextCursor: null },
    }, sha, "43", "1"), { status: "inventory-exhausted" });
    assert.throws(() => reviewFlow.sourceAuditContinuation({ ...report,
        sourceRange: { ...report.sourceRange, nextCursor: 49 },
    }, sha, "42", "1"), /cursor|inventory/i);
});

test("an audit snapshot that became stale leaves an explicit incomplete receipt without model or CI calls", async () => {
    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: true, range: { kind: "audit", cursor: 48, inventoryDigest: "b".repeat(64) } },
        io: { head: async () => "c".repeat(40) },
    });
    assert.equal(result.status, "incomplete-stale");
    assert.equal(result.sha, sha);
    assert.equal(result.currentSha, "c".repeat(40));
    assert.deepEqual(result.readPaths, []);
    assert.deepEqual(result.publications, []);
    assert.match(result.coverageMeaning, /incomplete/);
});

test("a queued manual or scheduled trigger never reviews a later main head", async () => {
    assert.equal(typeof reviewFlow.pinReviewTarget, "function");
    for (const target of [
        reviewTarget("workflow_dispatch", { repository, inputs: { branch: "main" } }),
        reviewTarget("schedule", { repository, schedule: "*/15 * * * *" }),
        reviewTarget("schedule", { repository, schedule: "23 6 * * 1" }),
    ]) {
        const pinned = reviewFlow.pinReviewTarget(target, sha);
        assert.equal(pinned.sha, sha);
        const result = await runReviewFlow({ target: pinned, io: { head: async () => "b".repeat(40) } });
        assert.equal(result.status, "incomplete-stale");
        assert.equal(result.sha, sha);
        assert.equal(result.currentSha, "b".repeat(40));
        assert.deepEqual(result.publications, []);
        assert.match(result.coverageMeaning, /trigger|queued/);
        assert.equal(reviewRecord({ ...result, controllerRevision: "c".repeat(40) }, "42", "1").report.status, "incomplete-stale");
    }
});

test("audit resume admits all-held pages and reuses only passed exact formatting identities", () => {
    assert.equal(typeof reviewFlow.admitAuditResume, "function");
    const target = reviewTarget("workflow_dispatch", { repository, inputs: {
        branch: "main", scope: "source-audit", publish: "true", audit_sha: sha,
        audit_digest: "b".repeat(64), audit_cursor: "48", audit_parent: "42-1",
    } });
    const parent = { repository: repository.full_name, sha, controllerRevision: "d".repeat(40), branch: "main", status: "no-reviewable-source",
        publishRequested: true, formatting: { status: "not-required", reason: "no-admitted-source" },
        sourceRange: { kind: "audit", sha, inventoryDigest: "b".repeat(64), cursor: 0, pagePaths: 48, totalPaths: 53, nextCursor: 48 } };
    assert.equal(reviewFlow.admitAuditResume(target, parent, parent.controllerRevision).upstream, undefined);
    parent.status = "reviewed";
    parent.formatting = { status: "passed", runId: "40", attempt: "2", sha, ref: "refs/heads/main" };
    assert.deepEqual(reviewFlow.admitAuditResume(target, parent, parent.controllerRevision).upstream, { runId: "40", attempt: "2" });
    assert.throws(() => reviewFlow.admitAuditResume(target, { ...parent, controllerRevision: "e".repeat(40) }, parent.controllerRevision), /parent/i);
    assert.throws(() => reviewFlow.admitAuditResume(target, { ...parent, formatting: { ...parent.formatting, sha: "e".repeat(40) } }, parent.controllerRevision), /format/i);
});

test("held audit pages retain revalidated formatting for the next immutable page", async () => {
    const upstream = { runId: "40", attempt: "2" };
    const formatting = { status: "passed", ...upstream, sha, ref: "refs/heads/main" };
    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: true, upstream, range: { kind: "audit", cursor: 48 } },
        io: {
            head: async () => sha,
            collect: async () => ({ baseSha: sha, entries: [], unreviewedPaths: [],
                sourceRange: { kind: "audit", sha, inventoryDigest: "b".repeat(64), cursor: 48, pagePaths: 48, totalPaths: 100, nextCursor: 96 } }),
            format: async (sourceSha, branch, inherited) => {
                assert.equal(sourceSha, sha);
                assert.equal(branch, "main");
                assert.deepEqual(inherited, upstream);
                return formatting;
            },
        },
    });
    assert.equal(result.status, "no-reviewable-source");
    assert.deepEqual(result.formatting, formatting);
    const next = reviewFlow.sourceAuditContinuation(result, sha, "42", "1");
    assert.equal(next.status, "continue");
    const target = reviewTarget("workflow_dispatch", { repository, inputs: next.inputs });
    assert.deepEqual(reviewFlow.admitAuditResume(target, { ...result, controllerRevision: "d".repeat(40) }, "d".repeat(40)).upstream, upstream);
});

test("held audit pages stop when inherited formatting fails revalidation", async () => {
    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: true, upstream: { runId: "40", attempt: "2" }, range: { kind: "audit", cursor: 48 } },
        io: {
            head: async () => sha,
            collect: async () => ({ baseSha: sha, entries: [], unreviewedPaths: [],
                sourceRange: { kind: "audit", sha, inventoryDigest: "b".repeat(64), cursor: 48, pagePaths: 48, totalPaths: 100, nextCursor: 96 } }),
            format: async () => ({ status: "blocked", reason: "source-format-evidence-unavailable-or-rejected" }),
        },
    });
    assert.equal(result.status, "format-blocked");
    assert.equal(result.formatting.status, "blocked");
    assert.deepEqual(reviewFlow.sourceAuditContinuation(result, sha, "42", "1"), { status: "incomplete-review-blocked" });
});

test("audit flow sends exact immutable files without diff semantics and records partial model reads", async () => {
    const source = entry(0);
    const held = { path: "notes.txt", reason: "unsupported-source-type" };
    let supplied;
    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: false, range: { kind: "audit", cursor: 0 } },
        io: {
            head: async () => sha, format: async () => ({ status: "passed" }),
            collect: async () => ({ baseSha: sha, entries: [source], unreviewedPaths: [held],
                sourceRange: { kind: "audit", sha, cursor: 0, pagePaths: 2, totalPaths: 2, nextCursor: null, inventoryDigest: "b".repeat(64) } }),
            review: async (input) => {
                supplied = input;
                return { repository: input.repository, sha, branch: "main", model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
                    publication: "requires-verifier", suppliedPaths: [source.path], readPaths: [source.path], readDiff: false,
                    codeExecutions: 1, sourceToolCalls: 1, kind: "no-findings", summary: "No supported candidate in retrieved excerpts." };
            },
        },
    });
    assert.deepEqual(supplied.changedPaths, []);
    assert.equal(supplied.diff, "");
    assert.deepEqual(supplied.auditPaths, [source.path]);
    assert.deepEqual(result.unreviewedPaths, [held]);
    assert.deepEqual(result.readPaths, [source.path]);
    assert.match(result.coverageMeaning, /not whole-file or repository coverage/);
    assert.equal(result.sourceRange.totalPaths, 2);
});

test("runtime polling with no source events never starts formatting CI or model inference", async () => {
    const calls = [];
    const result = await runReviewFlow({
        target: reviewTarget("schedule", { repository, schedule: "*/15 * * * *" }),
        io: {
            head: async () => sha,
            collect: async (_sha, _branch, range) => { calls.push(range.kind); return {
                baseSha: sha, sourceRange: { kind: "audit", intake: "sentry-runtime" },
                entries: [], unreviewedPaths: [], runtimeEvents: [],
            }; },
            format: async () => { calls.push("format"); throw new Error("unexpected CI"); },
            review: async () => { calls.push("review"); throw new Error("unexpected model"); },
        },
    });
    assert.deepEqual(calls, ["runtime"]);
    assert.equal(result.formatting.status, "not-required");
    assert.equal(result.status, "no-reviewable-source");
    assert.deepEqual(result.runtimeEvents, []);
});

test("weekly workflow chains bounded pages only through a separate trusted dispatch job", () => {
    const workflow = Bun.YAML.parse(readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"));
    assert.deepEqual(workflow.on.schedule, [{ cron: "23 6 * * 1" }, { cron: "*/15 * * * *" }, {cron:"11 */6 * * *"}]);
    assert.equal(workflow.concurrency.group, "omg-ai-review-global");
    assert.equal(workflow.concurrency.queue, "max");
    assert.deepEqual(workflow.on.workflow_dispatch.inputs.scope.options, ["changes", "source-audit", "runtime-events", "test-audit", "issue"]);
    assert.match(workflow.jobs.review.if, /github.event_name == 'schedule'/);
    const continuation = workflow.jobs.continue;
    assert.equal(continuation.steps.find(step => step.uses?.startsWith("actions/checkout@")).with["fetch-depth"],
        workflow.jobs.review.steps.find(step => step.uses?.startsWith("actions/checkout@")).with["fetch-depth"]);
    assert.deepEqual(continuation.needs, ["review", "publish"]);
    assert.deepEqual(continuation.permissions, { contents: "read", actions: "write" });
    assert.match(continuation.if, /needs.publish.result == 'success'/);
    assert.match(continuation.if, /needs.publish.result == 'skipped'/);
    assert.equal(continuation.steps.some((step) => step.run?.includes("bun scripts/ai-review-flow.mjs continue .audit/ai-review")), true);
    assert.equal(JSON.stringify(continuation).includes("APP_PRIVATE_KEY"), false);
    assert.equal(JSON.stringify(continuation).includes("OMG_CI_CODER_TOKEN"), false);
    assert.match(continuation.if, /outputs.runtime-ack == 'true'/);
    const finalize = continuation.steps.find((step) => step.run?.includes("bun scripts/ai-review-flow.mjs continue .audit/ai-review"));
    assert.equal(finalize.env.PUBLICATION_RESULT, "${{ needs.publish.result }}");
});

test("actionlint queue compatibility applies only to the serialized trusted workflows", () => {
    const config = Bun.YAML.parse(readFileSync(new URL("../../.github/actionlint.yaml", import.meta.url), "utf8"));
    const paths = [".github/workflows/cloud-ci.yml", ".github/workflows/ai-review.yml", ".github/workflows/ai-fix-review.yml"];
    const diagnostic = 'unexpected key "queue" for "concurrency" section. expected one of "cancel-in-progress", "group"';
    assert.deepEqual(Object.keys(config), ["paths"]);
    assert.deepEqual(Object.keys(config.paths), paths);
    for (const file of paths) {
        const policy = config.paths[file];
        assert.deepEqual(Object.keys(policy), ["ignore"]);
        assert.equal(policy.ignore.length, 1);
        const compatible = new RegExp(policy.ignore[0]);
        assert.equal(compatible.test(diagnostic), true);
        assert.equal(compatible.test(diagnostic.replace('"queue"', '"queues"')), false);
        assert.equal(compatible.test(`another error ${diagnostic}`), false);
        const workflow = Bun.YAML.parse(readFileSync(new URL(`../../${file}`, import.meta.url), "utf8"));
        assert.equal(workflow.concurrency.queue, "max");
        assert.equal(workflow.concurrency["cancel-in-progress"], false);
    }
});

test("runtime evidence is acknowledged only after successful actual publication or an empty candidate set", async () => {
    assert.equal(typeof reviewFlow.finalizeRuntimeReview, "function");
    const acknowledged = [];
    const identity = { repository: "omg-cli/omg", sha, branch: "main" };
    const report = { ...identity, status: "reviewed", publishRequested: true, sourceRange: { intake: "sentry-runtime" },
        formatting: { status: "passed" }, batches: [{ sourceInput: { ...identity, sourceFiles: [{ path: "src/value.rs" }] },
            modelResponse: { ...identity, model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017", publication: "requires-verifier",
                codeExecutions: 1, sourceToolCalls: 1, readDiff: false, suppliedPaths: ["src/value.rs"], readPaths: ["src/value.rs"] } }],
        suppliedPaths: ["src/value.rs"], readPaths: ["src/value.rs"], unreviewedPaths: [],
        candidateOutcomes: [{ outcome: "verified-for-publication" }], publications: [{ proposal: {} }],
        runtimeEvents: [{ projectId: "1", eventId: "a".repeat(32), bodySha256: "b".repeat(64) }] };
    const acknowledge = async () => { acknowledged.push("ack"); };
    for (const publicationResult of ["failure", "cancelled", "skipped", undefined]) {
        await assert.rejects(() => reviewFlow.finalizeRuntimeReview({ report, publicationResult, acknowledge }), /publication/i);
        assert.deepEqual(acknowledged, []);
    }
    await assert.rejects(() => reviewFlow.finalizeRuntimeReview({ report: { ...report, publishRequested: false }, publicationResult: "success", acknowledge }), /publication/i);
    assert.deepEqual(acknowledged, []);
    await reviewFlow.finalizeRuntimeReview({ report, publicationResult: "success", acknowledge });
    await reviewFlow.finalizeRuntimeReview({ report: { ...report, publications: [], candidateOutcomes: [] }, publicationResult: "skipped", acknowledge });
    assert.deepEqual(acknowledged, ["ack", "ack"]);
});

test("pending runtime publication replays exact canonical proof without a new model verdict", async () => {
    assert.equal(typeof reviewFlow.admitRuntimeReplay, "function");
    const runtimeEvents = [{ projectId: "1", eventId: "a".repeat(32), bodySha256: "b".repeat(64) }];
    const original = { repository: repository.full_name, branch: "main", sha, controllerRevision: "d".repeat(40),
        status: "reviewed", formatting: { status: "passed" }, runtimeEvents, publishRequested: true,
        sourceRange: { kind: "audit", intake: "sentry-runtime" }, suppliedPaths: ["src/value.rs"], readPaths: ["src/value.rs"],
        unreviewedPaths: [], batches: [], candidateOutcomes: [], publications: [{ proposal: { exactProof: "original" } }] };
    const replayRef = { runId: "42", attempt: "1" };
    const options = { original, replayRef, runtimeEvents, sha, controllerRevision: original.controllerRevision };
    const replay = reviewFlow.admitRuntimeReplay(options);
    assert.deepEqual(replay.publications, original.publications);
    assert.deepEqual(replay.replayOf, replayRef);
    assert.throws(() => reviewFlow.admitRuntimeReplay({ ...options, runtimeEvents: [{ ...runtimeEvents[0], bodySha256: "e".repeat(64) }] }), /canonical|runtime/i);
    assert.throws(() => reviewFlow.admitRuntimeReplay({ ...options, sha: "e".repeat(40) }), /source|canonical/i);
    assert.throws(() => reviewFlow.admitRuntimeReplay({ ...options, controllerRevision: "e".repeat(40) }), /controller|canonical/i);
    assert.throws(() => reviewFlow.admitRuntimeReplay({ ...options,
        publications: [{ proposal: { exactProof: "forged replacement" } }],
    }), /canonical|proof/i);
    const calls = [];
    const result = await runReviewFlow({
        target: { branch: "main", sha: null, publish: true, range: { kind: "runtime" } },
        io: { head: async () => sha, controllerRevision: original.controllerRevision,
            collect: async () => ({ replayRef, replayReport: original, runtimeEvents, entries: [], unreviewedPaths: [] }),
            format: async () => { calls.push("format"); throw new Error("unexpected CI"); },
            review: async () => { calls.push("model"); return { kind: "no-findings" }; },
        },
    });
    assert.deepEqual(calls, []);
    assert.equal(result.status, "publication-replay");
    assert.deepEqual(result.publications, original.publications);
    const held = await runReviewFlow({
        target: { branch: "main", sha: null, publish: true, range: { kind: "runtime" } },
        io: { head: async () => "e".repeat(40), controllerRevision: original.controllerRevision,
            collect: async () => ({ replayRef, replayReport: original, runtimeEvents, entries: [], unreviewedPaths: [] }) },
    });
    assert.equal(held.runtimeUnresolved, true);
    assert.equal(held.status, "runtime-replay-held");
    assert.deepEqual(held.publications, []);
    await assert.rejects(() => reviewFlow.finalizeRuntimeReview({ report: held, publicationResult: "skipped", acknowledge: async () => calls.push("ack") }), /unresolved/i);
    assert.deepEqual(calls, []);
});

test("audit inventory pages cover the exact committed tree and hold unsupported cohorts", { timeout: 30000 }, async () => {
    assert.equal(typeof reviewFlow.collectAuditSources, "function");
    const directory = await mkdtemp(path.join(tmpdir(), "omg-audit-tree-"));
    try {
        const git = (...args) => execFileSync("git", ["-C", directory, ...args], { encoding: "utf8", windowsHide: true }).trim();
        git("init", "--initial-branch=main");
        for (let index = 0; index < 50; index++) await writeFile(path.join(directory, `source-${index}.rs`), `pub const VALUE: usize = ${index};\n`);
        await writeFile(path.join(directory, "notes.txt"), "unsupported\n");
        await writeFile(path.join(directory, "oversized.rs"), "x".repeat(256 * 1024 + 1));
        await writeFile(path.join(directory, "binary.rs"), Buffer.from([0, 1, 2]));
        git("add", "--all");
        git("-c", "user.name=Audit fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture");
        const commit = git("rev-parse", "HEAD");
        await writeFile(path.join(directory, "uncommitted.rs"), "not committed\n");
        const first = await reviewFlow.collectAuditSources(commit, { kind: "audit", cursor: 0 }, directory);
        assert.equal(first.sourceRange.totalPaths, 53);
        assert.equal(first.sourceRange.pagePaths, 48);
        assert.equal(first.sourceRange.nextCursor, 48);
        assert.equal(first.baseSha, commit);
        assert.deepEqual(first.unreviewedPaths.map(({ reason }) => reason).sort(), ["binary-source", "source-byte-budget-exceeded", "unsupported-source-type"]);
        const second = await reviewFlow.collectAuditSources(commit, {
            kind: "audit", cursor: first.sourceRange.nextCursor, inventoryDigest: first.sourceRange.inventoryDigest,
        }, directory);
        assert.equal(second.sourceRange.nextCursor, null);
        assert.equal(first.entries.length + second.entries.length, 50);
        assert.equal(new Set([...first.entries, ...second.entries].map(({ path }) => path)).size, 50);
        assert.equal(first.entries.every((entry) => entry.diff === undefined && entry.raw === undefined), true);
        await assert.rejects(() => reviewFlow.collectAuditSources(commit, { kind: "audit", cursor: 48, inventoryDigest: "f".repeat(64) }, directory), /inventory/i);
        await assert.rejects(() => reviewFlow.collectAuditSources(commit, { kind: "audit", cursor: 49 }, directory), /cursor/i);
    } finally { await rm(directory, { recursive: true, force: true }); }
});

test(
    "source collection includes product changes before a final config-only commit across the exact push range",
    { timeout: 15000 },
    async () => {
        const directory = await mkdtemp(path.join(tmpdir(), "omg-review-range-"));

        const git = (...args) =>
            execFileSync("git", args, {
                cwd: directory,
                encoding: "utf8",
                windowsHide: true,
            }).trim();

        try {
            git("init", "--quiet");
            git("config", "user.name", "Review test");
            git("config", "user.email", "review@example.invalid");
            git("config", "core.autocrlf", "false");
            await writeFile(path.join(directory, "product.mjs"), "pub const value: usize = 0;\n");
            git("add", ".");
            git("commit", "--quiet", "-m", "baseline");
            const before = git("rev-parse", "HEAD");
            await writeFile(path.join(directory, "product.mjs"), "pub const value: usize = 1;\n");
            git("add", ".");
            git("commit", "--quiet", "-m", "product change");
            const parent = git("rev-parse", "HEAD");
            await writeFile(path.join(directory, "config.txt"), "config\n");
            git("add", ".");
            git("commit", "--quiet", "-m", "config only");
            const head = git("rev-parse", "HEAD");

            const github = { request: async () => ({ sha: head, parents: [{ sha: parent }] }) };

            const result = await collectSources(
                github,
                head,
                { kind: "push", baseSha: before },
                directory,
            );

            assert.deepEqual(
                result.entries.map((entry) => entry.path),
                ["product.mjs"],
            );
            assert.equal(result.baseSha, before);
            assert.equal(result.entries[0].content, "pub const value: usize = 1;\n");
            assert.deepEqual(result.unreviewedPaths, [
                { path: "config.txt", reason: "unsupported-source-type" },
            ]);
            assert.deepEqual(result.sourceRange, { kind: "push", baseSha: before, headSha: head });
            await assert.rejects(
                collectSources(github, head, { kind: "push", baseSha: "HEAD^" }, directory),
                /exact commit SHA/,
            );
            await assert.rejects(
                collectSources(github, head, { kind: "push", baseSha: head }, directory),
                /coverage is blocked/,
            );
            await assert.rejects(
                collectSources(github, parent, { kind: "push", baseSha: head }, directory),
                /push base is not an ancestor/,
            );
            await assert.rejects(
                collectSources(
                    github,
                    head,
                    { kind: "pull-request", baseSha: before, headSha: parent },
                    directory,
                ),
                /head identity mismatch/,
            );
            const missingRange = { request: async () => [] };

            await assert.rejects(
                collectSources(missingRange, head, undefined, directory),
                /coverage is blocked/,
            );

            const pull = {
                merge_commit_sha: head,
                state: "closed",
                merged_at: "2026-10-20T00:00:00Z",
                head: { repo: repository },
                base: { sha: before, ref: "main", repo: repository },
            };

            const associated = await collectSources(
                { request: async () => [pull] },
                head,
                undefined,
                directory,
            );

            assert.deepEqual(
                associated.entries.map((entry) => entry.path),
                ["product.mjs"],
            );
            assert.equal(associated.sourceRange.kind, "pull-request");
            await assert.rejects(
                collectSources({ request: async () => [pull, pull] }, head, undefined, directory),
                /ambiguous/,
            );
            await assert.rejects(
                collectSources(
                    {
                        request: async () => [
                            { ...pull, head: { repo: { full_name: "attacker/fork" } } },
                        ],
                    },
                    head,
                    undefined,
                    directory,
                ),
                /associated PR/,
            );
        } finally {
            await rm(directory, { recursive: true, force: true });
        }
    },
);

test("format admission accepts a passed format step after later functional failure only at the exact upstream identity", () => {
    const request = {
        repository: repository.full_name,
        sha,
        ref: "refs/heads/main",
        runId: "123",
        attempt: "2",
    };

    const id = `cl-123-2-${sha}`;
    const image = `sha256:${"b".repeat(64)}`;

    const check = {
        name: "source-format",
        exitCode: 0,
        stdoutKey: `logs/${id}/source-format.stdout`,
        stderrKey: `logs/${id}/source-format.stderr`,
        stdoutSha256: sha256("formatted"),
        stderrSha256: sha256(""),
        reports: [],
    };

    const receipt = {
        id,
        ...request,
        conclusion: "failure",
        imageDigest: image,
        planSha256: cloudCiPlanSha256,
        requiredChecks: expectedCloudChecks(request.ref),
        checks: [check],
    };

    assert.deepEqual(admitSourceFormatting(receipt, request, image), check);
    assert.throws(
        () => admitSourceFormatting({ ...receipt, sha: "c".repeat(40) }, request, image),
        /identity/,
    );
    assert.throws(
        () => admitSourceFormatting({ ...receipt, attempt: "1" }, request, image),
        /identity/,
    );
    assert.throws(
        () =>
            admitSourceFormatting(
                { ...receipt, imageDigest: `sha256:${"c".repeat(64)}` },
                request,
                image,
            ),
        /image/,
    );
    assert.throws(
        () => admitSourceFormatting({ ...receipt, planSha256: "c".repeat(64) }, request, image),
        /plan/,
    );
    assert.throws(
        () =>
            admitSourceFormatting(
                { ...receipt, checks: [{ ...check, exitCode: 1 }] },
                request,
                image,
            ),
        /format/,
    );
    assert.throws(
        () => admitSourceFormatting({ ...receipt, checks: [] }, request, image),
        /format/,
    );
    assert.throws(
        () =>
            admitSourceFormatting(
                {
                    ...receipt,
                    checks: [{ ...check, stdoutKey: "logs/other/source-format.stdout" }],
                },
                request,
                image,
            ),
        /object/,
    );
});

test("unformatted source returns an explicit blocker before collecting source or requesting the model", async () => {
    const calls = [];
    const source = entry(0);

    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: true },
        io: {
            head: async () => sha,
            format: async () => {
                calls.push("format");

                return { status: "blocked", reason: "source-format-not-passed" };
            },
            collect: async () => {
                calls.push("collect");

                return { baseSha: "b".repeat(40), entries: [source], unreviewedPaths: [] };
            },
            review: async (input) => {
                calls.push("model");

                return {
                    repository: input.repository,
                    sha,
                    branch: "main",
                    model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
                    publication: "requires-verifier",
                    suppliedPaths: [source.path],
                    readPaths: [source.path],
                    readDiff: true,
                    codeExecutions: 1,
                    sourceToolCalls: 1,
                    kind: "no-findings",
                    summary: "No supported finding.",
                };
            },
        },
    });

    assert.deepEqual(calls, ["format"]);
    assert.equal(result.status, "format-blocked");
    assert.deepEqual(result.batches, []);
    assert.deepEqual(result.readPaths, []);
    assert.deepEqual(result.publications, []);
});

test("private R2 handoff binds exact run identity and rejects oversized source records", () => {
    const report = {
        repository: repository.full_name,
        sha,
        branch: "main",
        controllerRevision: "b".repeat(40),
    };

    assert.deepEqual(reviewRecord(report, "42", "1"), {
        repository: repository.full_name,
        runId: "42",
        attempt: "1",
        report,
    });
    assert.throws(() => reviewRecord(report, "42/other", "1"), /run identity/);
    assert.throws(
        () => reviewRecord({ ...report, repository: "attacker/fork" }, "42", "1"),
        /repository/,
    );
    assert.throws(
        () => reviewRecord({ ...report, source: "x".repeat(2 * 1024 * 1024) }, "42", "1"),
        /2 MiB/,
    );
});

test("workflow isolates write permission and excludes generated branches from the controller", () => {
    const workflow = Bun.YAML.parse(
        readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"),
    );

    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch", "schedule"]);
    assert.equal(workflow.on.workflow_run, undefined);
    assert.deepEqual(workflow.on.workflow_dispatch.inputs.branch.options, ["main"]);
    assert.equal(workflow.on.workflow_dispatch.inputs.publish.default, false);
    assert.deepEqual(workflow.permissions, { contents: "read" });
    assert.equal(workflow.concurrency["cancel-in-progress"], false);
    assert.equal(workflow.jobs.review["runs-on"], "ubuntu-24.04");
    assert.equal(workflow.jobs.publish["runs-on"], "ubuntu-24.04");
    for (const job of [workflow.jobs.review, workflow.jobs.publish]) {
        assert.ok(
            job.steps.some((step) =>
                step.run?.includes(
                    "https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/bun-linux-x64.zip",
                ),
            ),
        );
        assert.ok(
            job.steps.some((step) =>
                step.run?.includes(
                    "10702245766b225e70bbf6235fd6b47214fd94b4760d00ffaed8ab0df57ac235",
                ),
            ),
        );
        const setup = job.steps.find(
            (step) => step.name === "Create private OMG service configuration",
        );
        assert.ok(setup);
        assert.equal(setup.env.OMG_CI_API_TOKEN, "${{ secrets.OMG_CI_API_TOKEN }}");
        assert.equal(setup.env.OMG_CI_INSPECTOR_TOKEN, "${{ secrets.OMG_CI_INSPECTOR_TOKEN }}");
        assert.equal(setup.env.OMG_CI_CODER_TOKEN, "${{ secrets.OMG_CI_CODER_TOKEN }}");
        assert.match(setup.run, /mode: 0o600/);
    }
    assert.match(workflow.jobs.publish.if, /github.event_name == 'workflow_dispatch'/);
    assert.deepEqual(workflow.jobs.review.permissions,{contents:"read",actions:"read"});
    assert.deepEqual(workflow.jobs.publish.permissions, {
        contents: "read",
        actions: "read",
    });
    assert.match(workflow.jobs.review.if, /github.repository == 'omg-cli\/omg'/);
    assert.match(workflow.jobs.review.if, /github.ref_name == 'main'/);

    const checkout = workflow.jobs.review.steps.find((step) =>
        step.uses?.startsWith("actions/checkout@"),
    );

    assert.equal(checkout.with["persist-credentials"], false);
    assert.match(checkout.with.ref, /vars.OMG_CI_CONTROLLER_SHA/);
    assert.equal(
        [...workflow.jobs.review.steps, ...workflow.jobs.publish.steps].some((step) =>
            step.uses?.includes("artifact@"),
        ),
        false,
    );
    assert.match(workflow.jobs.publish.steps[0].with.ref, /needs.review.outputs.controller-sha/);
    assert.match(
        workflow.jobs.publish.steps.find(
            (step) =>
                step.name === "Re-fetch server proof and publish issues with verified fix PRs",
        ).run,
        /bun scripts\/ai-review-flow\.mjs publish \.audit\/ai-review --publish/,
    );
});

test("automatic review accepts only current fixed-repository branch pushes and failed CI", () => {
    assert.deepEqual(
        reviewTarget("push", {
            repository,
            ref: "refs/heads/main",
            before: "b".repeat(40),
            after: sha,
        }),
        {
            branch: "main",
            sha,
            publish: true,
            range: { kind: "push", baseSha: "b".repeat(40) },
        },
    );
    assert.deepEqual(
        reviewTarget("workflow_run", {
            repository,
            workflow_run: {
                head_repository: repository,
                head_branch: "main",
                head_sha: sha,
                conclusion: "failure",
                event: "push",
                name: "Cloudflare verification",
                id: 123,
                run_attempt: 2,
            },
        }),
        { branch: "main", sha, publish: true, upstream: { runId: "123", attempt: "2" } },
    );
    assert.throws(
        () => reviewTarget("push", { repository, ref: "refs/heads/ai-fix/a", after: sha }),
        /branch/,
    );
    assert.throws(
        () =>
            reviewTarget("workflow_run", {
                repository,
                workflow_run: {
                    head_repository: { full_name: "attacker/fork" },
                    head_branch: "main",
                    head_sha: sha,
                    conclusion: "failure",
                    event: "push",
                    name: "Cloudflare verification",
                },
            }),
        /repository/,
    );
});

function candidateFixture() {
    const source = entry(0);

    const input = {
        repository: repository.full_name,
        sha,
        branch: "main",
        changedPaths: [source.path],
        diff: source.diff,
        sourceFiles: [{ path: source.path, blobSha: source.blobSha, content: source.content }],
        ciFailures: [],
    };

    const candidate = {
        title: "Wrong value",
        impact: "The exported value is zero instead of one.",
        evidence: [
            {
                path: source.path,
                blobSha: source.blobSha,
                lineStart: 1,
                lineEnd: 1,
                quote: source.content.trim(),
            },
        ],
        proposedFix: {
            edits: [
                { path: source.path, oldText: "value: usize = 0", newText: "value: usize = 1" },
            ],
            regressionTest: {
                path: `tests/ci-review-${sha.slice(0, 12)}-1.rs`,
                content:
                    '#[path = "../src/value-0.rs"] mod value;\n#[test] fn value_is_one() { assert_eq!(value::value, 1); }\n',
                expectedTestName: "value_is_one",
            },
        },
    };

    const review = {
        kind: "candidates",
        summary: "One supported candidate.",
        candidates: [candidate],
    };

    const sources = new Map([
        [source.path, { mode: "100644", sha: source.blobSha, content: source.content }],
    ]);

    const adapted = adaptReviewCandidate({ input, review, candidateIndex: 0, sources });

    const response = {
        ...review,
        repository: input.repository,
        sha,
        branch: input.branch,
        candidates: [{ ...candidate, verification: "uncorroborated" }],
        model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
        publication: "requires-verifier",
        suppliedPaths: [source.path],
        readPaths: [source.path],
        readDiff: true,
        codeExecutions: 1,
        sourceToolCalls: 1,
    };

    return { source, input, review, sources, adapted, response };
}

test("candidate flow mirrors only exact source and waits for proof without publishing or host commands", async () => {
    const fixture = candidateFixture();
    const calls = [];

    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: true },
        io: {
            head: async () => sha,
            format: async () => ({ status: "passed" }),
            collect: async () => ({
                baseSha: "b".repeat(40),
                entries: [fixture.source],
                unreviewedPaths: [],
            }),
            review: async () => fixture.response,
            adapt: async (input, review, candidateIndex) => {
                calls.push("adapt");

                return adaptReviewCandidate({
                    input,
                    review,
                    candidateIndex,
                    sources: fixture.sources,
                });
            },
            mirror: async (value) => calls.push(`mirror:${value}`),
            verify: async (adapted, value, branch) => {
                calls.push(`verify:${value}:${branch}`);
                assert.equal(
                    adapted.proposal.changes[0].newContent,
                    "pub const value: usize = 1;\n",
                );

                return { receipt: { proof: "test boundary receipt" } };
            },
        },
    });

    assert.deepEqual(calls, [`mirror:${sha}`, "adapt", `verify:${sha}:main`]);
    assert.equal(result.publications.length, 1);
    assert.equal(result.publishRequested, true);
});

test("failed native verification cannot produce a publication receipt", async () => {
    const fixture = candidateFixture();
    const calls = [];
    await assert.rejects(
        () =>
            runReviewFlow({
                target: { branch: "main", sha, publish: true },
                io: {
                    head: async () => sha,
                    format: async () => ({ status: "passed" }),
                    collect: async () => ({
                        baseSha: "b".repeat(40),
                        entries: [fixture.source],
                        unreviewedPaths: [],
                    }),
                    review: async () => fixture.response,
                    adapt: async () => fixture.adapted,
                    mirror: async () => calls.push("mirror"),
                    verify: async () => {
                        calls.push("verify");
                        throw new Error("Native checks failed.");
                    },
                },
            }),
        /Native checks failed/,
    );
    assert.deepEqual(calls, ["mirror", "verify"]);
});

function proofFixture() {
    const { adapted, sources } = candidateFixture();

    const config = {
        endpoint: "https://omg-cloud-ci.latham.workers.dev/",
        imageDigest: `sha256:${"c".repeat(64)}`,
        verifierRevision: "d".repeat(40),
    };

    const request = {
        repository: repository.full_name,
        sha,
        ref: "refs/heads/main",
        runId: "42",
        attempt: "1",
        verification: { ...adapted, verifierRevision: config.verifierRevision },
    };

    const names = expectedCloudChecks(request.ref);

    const objectId = `cl-${request.runId}-${request.attempt}-${request.sha}-v-${proposalDigest(adapted.proposal).slice(0, 16)}`;

    const checks = names.map((name) => ({
        name,
        exitCode: 0,
        stdoutKey: `logs/${objectId}/${name}.stdout`,
        stderrKey: `logs/${objectId}/${name}.stderr`,
        stdoutSha256: "f".repeat(64),
        stderrSha256: "f".repeat(64),
        reports: expectedCloudReports(name).map((name) => ({
            name,
            key: `reports/${objectId}/${name}`,
            sha256: "f".repeat(64),
        })),
    }));

    const regression = {
        testName: adapted.regression.testName,
        tests: 1,
        failures: 0,
        exitCode: 0,
        errors: 0,
        skipped: 0,
        reportSha256: "e".repeat(64),
        stdoutSha256: "f".repeat(64),
        stderrSha256: "f".repeat(64),
        catalogSha256: "f".repeat(64),
        executableSha256: "f".repeat(64),
        compilerMessagesSha256: "f".repeat(64),
        sourceSha256: "f".repeat(64),
        recipeSha256: "f".repeat(64),
    };

    const receipt = {
        ...request,
        conclusion: "success",
        imageDigest: config.imageDigest,
        planSha256: cloudCiPlanSha256,
        requiredChecks: names,
        checks,
        verificationReports: ["baseline", "patched"].map((role) => ({
            name: `regression-${role}.json`,
            key: `reports/${objectId}/regression-${role}.json`,
            sha256: regression.reportSha256,
        })),
        verificationReceipt: {
            repository: repository.full_name,
            branch: "main",
            baseSha: sha,
            proposalSha256: proposalDigest(adapted.proposal),
            verifierRevision: config.verifierRevision,
            runId: 42,
            runAttempt: 1,
            baseline: {
                ...regression,
                exitCode: 101,
                failures: 1,
                assertionFailure: "Expected value one, got zero.",
                assertionFile: "src/value-0.rs",
                assertionLine: 1,
                assertionSourceSha256: sha256(sources.get("src/value-0.rs").content.split("\n")[0]),
            },
            patched: regression,
            portableChecks: checks.map((check) => ({
                name: check.name,
                exitCode: 0,
                reportSha256: sha256(JSON.stringify(check)),
            })),
            protectedPathsUnchanged: true,
        },
    };

    return { adapted, sources, config, request, receipt };
}

test("server proof binds trusted image, exact proposal, regression and all required checks", () => {
    const fixture = proofFixture();

    const verify = (receipt) =>
        verifyPublicationProof(
            receipt,
            fixture.request,
            fixture.config,
            fixture.adapted,
            fixture.sources,
        );

    assert.equal(
        verify(fixture.receipt).receipt.proposalSha256,
        proposalDigest(fixture.adapted.proposal),
    );
    assert.throws(
        () => verify({ ...fixture.receipt, imageDigest: `sha256:${"f".repeat(64)}` }),
        /image/,
    );
    assert.throws(() => verify({ ...fixture.receipt, verificationReceipt: null }), /proof/);
    assert.throws(() => verify({ ...fixture.receipt, planSha256: "0".repeat(64) }), /plan/);
    const altered = structuredClone(fixture.receipt);
    altered.verificationReceipt.proposalSha256 = "0".repeat(64);
    assert.throws(() => verify(altered), /digest/);
    const wrongRegression = structuredClone(fixture.receipt);
    wrongRegression.verificationReceipt.baseline.testName = "unrelated test";
    assert.throws(() => verify(wrongRegression), /Regression/);
    const missingCheck = structuredClone(fixture.receipt);
    missingCheck.verificationReceipt.portableChecks.pop();
    assert.throws(() => verify(missingCheck), /Portable check record digest/);
});

test("real runtime intake preserves a failed publication and replays its proof before acknowledging", async () => {
    const server = runtimeServer();
    const candidate = candidateFixture();
    const proof = proofFixture();
    const nativeRunId = server.stageNativeProof(proof.request, proof.receipt);
    const formatRequest = { repository: repository.full_name, sha, ref: "refs/heads/main", runId: "42", attempt: "1" };
    const formatId = `cl-42-1-${sha}`;
    server.stageNativeProof(formatRequest, { ...formatRequest, id: formatId, conclusion: "success",
        imageDigest: proof.config.imageDigest, planSha256: cloudCiPlanSha256, requiredChecks: expectedCloudChecks("refs/heads/main"),
        checks: proof.receipt.checks.map((check) => ({ ...check,
            stdoutKey: `logs/${formatId}/${check.name}.stdout`, stderrKey: `logs/${formatId}/${check.name}.stderr` })),
    });
    const controllerRevision = "e".repeat(40);
    const eventId = "b".repeat(32);
    assert.equal((await server.signedSend({ action: "triggered", data: { event: {
        event_id: eventId, issue_id: "12345", project: 789,
        url: `https://sentry.io/api/0/projects/omg-org/omg/events/${eventId}/`,
        environment: "production", release: "v0.1.0", tags: [["source_sha", sha]],
        exception: { values: [{ type: "panic", stacktrace: { frames: [{ filename: candidate.source.path, lineno: 1 }] } }] },
    } } })).status, 202);
    const author = { login: "github-actions[bot]", id: 41898282 };
    const blobs = new Map([[candidate.source.blobSha, candidate.source.content]]);
    const trees = new Map([["1".repeat(40), [{ path: candidate.source.path, mode: "100644", type: "blob", sha: candidate.source.blobSha, size: Buffer.byteLength(candidate.source.content) }]]]);
    const commits = new Map([[sha, { tree: { sha: "1".repeat(40) } }]]);
    const refs = new Map();
    const issues = [];
    const pulls = [];
    let pullAttempts = 0;
    const github = { async request(method, route, body) {
        const leaf = route.split("/").at(-1).split("?")[0];
        if (method === "GET") {
            if (route.endsWith("/git/ref/heads/main")) return { object: { sha } };
            if (route.includes("/git/ref/heads/ai-fix/")) return refs.get(route.split("/git/ref/heads/")[1]) ?? null;
            if (route.includes("/git/commits/")) return commits.get(leaf);
            if (route.includes("/git/trees/")) return { truncated: false, tree: trees.get(leaf) };
            if (route.includes("/git/blobs/")) return { encoding: "base64", content: Buffer.from(blobs.get(leaf)).toString("base64") };
            if (route.includes("/issues?")) return issues;
            if (route.includes("/pulls?")) return pulls;
        } else if (method === "POST") {
            if (route.endsWith("/issues")) {
                const issue = { number: 7, html_url: "https://github.com/omg-cli/omg/issues/7", state: "open", user: author, ...body };
                issues.push(issue); return issue;
            }
            if (route.endsWith("/git/blobs")) { const hash = gitBlobSha(body.content); blobs.set(hash, body.content); return { sha: hash }; }
            if (route.endsWith("/git/trees")) { const hash = sha256(JSON.stringify(body)).slice(0, 40); trees.set(hash, body.tree); return { sha: hash }; }
            if (route.endsWith("/git/commits")) {
                const hash = sha256(JSON.stringify(body)).slice(0, 40);
                const commit = { sha: hash, ...body, tree: { sha: body.tree }, parents: body.parents.map((sha) => ({ sha })) };
                commits.set(hash, commit); return commit;
            }
            if (route.endsWith("/git/refs")) { const ref = { object: { sha: body.sha } }; refs.set(body.ref.slice("refs/heads/".length), ref); return ref; }
            if (route.endsWith("/pulls")) {
                pullAttempts++;
                if (pullAttempts === 1) throw new Error("Injected GitHub publisher outage");
                const pull = { number: 8, html_url: "https://github.com/omg-cli/omg/pull/8", state: "open", user: author, ...body };
                pulls.push(pull); return pull;
            }
        }
        throw new Error(`Unexpected external GitHub operation ${method} ${route}`);
    } };
    let modelCalls = 0;
    const firstRef = { runId: "42", attempt: "1", sha, controllerRevision };
    const report = await runReviewFlow({ target: { branch: "main", sha, publish: true, range: { kind: "runtime" } }, io: {
        controllerRevision, head: async () => sha,
        collect: () => collectRuntimeSources({ ...server, github, sha, reviewRef: firstRef }),
        format: async () => ({ status: "passed", runId: "42", attempt: "1", sha, ref: "refs/heads/main",
            sourceFormat: admitSourceFormatting(await server.request(new URL(`/runs/${formatId}/evidence`, server.endpoint), server.token),
                formatRequest, proof.config.imageDigest) }),
        review: async () => { modelCalls++; return { ...candidate.response, readDiff: false }; },
        mirror: async (sourceSha) => assert.equal(sourceSha, sha),
        adapt: async (input, review, candidateIndex) => adaptReviewCandidate({ input, review, candidateIndex, sources: candidate.sources }),
        verify: async (adapted) => ({ ...verifyPublicationProof(proof.receipt, proof.request, proof.config, adapted, proof.sources),
            request: proof.request, nativeReceipt: proof.receipt, regression: adapted.regression }),
    } });
    report.controllerRevision = controllerRevision;
    const persist = async (report, ref) => server.request(new URL(`/review-records/${ref.runId}-${ref.attempt}`, server.endpoint), server.token,
        JSON.stringify(reviewRecord(report, ref.runId, ref.attempt)));
    assert.equal((await persist(report, firstRef)).stored, true);
    const policy = { verifierRevision: proof.config.verifierRevision, requiredChecks: expectedCloudChecks("refs/heads/main") };
    const previousLogin = process.env.OMG_CI_PUBLISHER_LOGIN;
    const previousId = process.env.OMG_CI_PUBLISHER_ID;
    process.env.OMG_CI_PUBLISHER_LOGIN = author.login; process.env.OMG_CI_PUBLISHER_ID = String(author.id);
    try {
        await assert.rejects(() => publishAiReview({ ...report.publications[0], ...policy, github, publish: true }), /publisher outage/);
        await assert.rejects(() => reviewFlow.finalizeRuntimeReview({ report, publicationResult: "failure",
            acknowledge: () => acknowledgeRuntimeSources({ ...server, report, runId: "42", attempt: "1" }) }), /publication/);
        const pending = await server.request(new URL("/sentry/events", server.endpoint), server.token);
        assert.equal(pending.events.length, 1);
        assert.deepEqual(pending.events[0].activeReview, firstRef);
        const nextRef = { ...firstRef, runId: "43" };
        const replay = await runReviewFlow({ target: { branch: "main", sha, publish: true, range: { kind: "runtime" } }, io: {
            controllerRevision, head: async () => sha,
            collect: async () => {
                const selected = await collectRuntimeSources({ ...server, github, sha, reviewRef: nextRef });
                assert.deepEqual(selected.replayRef, firstRef);
                return { ...selected, replayReport: await server.request(new URL("/review-records/42-1", server.endpoint), server.token) };
            },
            review: async () => { modelCalls++; return { kind: "no-findings" }; },
        } });
        assert.equal(modelCalls, 1);
        assert.equal(replay.status, "publication-replay");
        assert.deepEqual(replay.publications, report.publications);
        assert.equal((await persist(replay, nextRef)).stored, true);
        reviewFlow.admitRuntimeReplay({ original: report, replayRef: replay.replayOf, runtimeEvents: replay.runtimeEvents,
            sha, controllerRevision, publications: replay.publications });
        const publication = replay.publications[0];
        const freshNativeReceipt = await server.request(new URL(`/runs/${nativeRunId}/receipt`, server.endpoint), server.token);
        verifyPublicationProof(freshNativeReceipt, publication.request, proof.config,
            { proposal: publication.proposal, regression: publication.regression }, proof.sources);
        assert.equal((await publishAiReview({ ...publication, ...policy, github, publish: true })).action, "published");
        await reviewFlow.finalizeRuntimeReview({ report: replay, publicationResult: "success",
            acknowledge: () => acknowledgeRuntimeSources({ ...server, report: replay, runId: "43", attempt: "1" }) });
        assert.equal((await server.request(new URL("/sentry/events", server.endpoint), server.token)).events.length, 0);
        assert.equal(issues.length, 1);
        assert.equal(pulls.length, 1);
        assert.equal(refs.size, 1);
        assert.equal(server.requests.filter(({ path }) => path.endsWith("/ack")).length, 1);
    } finally {
        if (previousLogin === undefined) delete process.env.OMG_CI_PUBLISHER_LOGIN; else process.env.OMG_CI_PUBLISHER_LOGIN = previousLogin;
        if (previousId === undefined) delete process.env.OMG_CI_PUBLISHER_ID; else process.env.OMG_CI_PUBLISHER_ID = previousId;
    }
});

test("manual review is read-only by default and refuses arbitrary SHA or branch options", () => {
    assert.deepEqual(
        reviewTarget("workflow_dispatch", { repository, inputs: { branch: "main" } }),
        {
            branch: "main",
            sha: null,
            publish: false,
        },
    );
    assert.throws(
        () => reviewTarget("workflow_dispatch", { repository, inputs: { branch: "main", sha } }),
        /input/,
    );
    assert.throws(() => reviewTarget("pull_request", { repository }), /event/);
});

const entry = (index, overrides = {}) => {
    const content = `pub const value: usize = ${index};\n`;

    return {
        path: `src/value-${index}.rs`,
        content,
        blobSha: gitBlobSha(content),
        raw: `:100644 100644 ${"b".repeat(40)} ${gitBlobSha(content)} M\0src/value-${index}.rs\0`,
        numstat: `1\t1\tsrc/value-${index}.rs\0`,
        diff: `diff ${index}\n`,
        ...overrides,
    };
};

test("bounded batches retain every admitted file and explicitly account for overflow and unsupported files", () => {
    const result = partitionReviewSources(Array.from({ length: 50 }, (_, index) => entry(index)));
    assert.deepEqual(
        result.batches.map((batch) => batch.length),
        [12, 12, 12, 12],
    );
    assert.deepEqual(result.unreviewedPaths, [
        { path: "src/value-48.rs", reason: "batch-budget-exceeded" },
        { path: "src/value-49.rs", reason: "batch-budget-exceeded" },
    ]);
    const oversized = partitionReviewSources([entry(0, { content: "a".repeat(256 * 1024 + 1) }), entry(1)]);
    assert.equal(oversized.batches[0][0].path, "src/value-1.rs");
    assert.deepEqual(oversized.unreviewedPaths, [
        { path: "src/value-0.rs", reason: "source-byte-budget-exceeded" },
    ]);
});

test("diff and source byte limits split without claiming truncated evidence was reviewed", () => {
    const result = partitionReviewSources([
        entry(0, { diff: "x".repeat(40000) }),
        entry(1, { diff: "y".repeat(40000) }),
    ]);

    assert.equal(result.batches.length, 2);
    assert.equal(result.batches[0][0].diff.length, 40000);
    assert.throws(() => partitionReviewSources([entry(0), entry(0)]), /duplicate/i);
});

test("model read receipts reject fabricated reads and preserve explicit partial coverage", () => {
    const input = {
        repository: repository.full_name,
        sha,
        branch: "main",
        sourceFiles: [entry(0), entry(1)],
    };

    const response = {
        repository: repository.full_name,
        sha,
        branch: "main",
        model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
        publication: "requires-verifier",
        suppliedPaths: input.sourceFiles.map((file) => file.path),
        readPaths: ["src/value-0.rs"],
        readDiff: true,
        codeExecutions: 1,
        sourceToolCalls: 1,
        kind: "no-findings",
        summary: "No supported finding.",
    };

    assert.deepEqual(validateReviewReceipt(input, response).readPaths, ["src/value-0.rs"]);
    const reported = { ...input, ciFailures: [{ job: "GitHub issue #1011", step: "untrusted report", log: "Inspect the failing behavior" }] };
    for (const readCiFailures of [undefined, [], [1], [0, 0], ["0"]])
        assert.throws(() => validateReviewReceipt(reported, { ...response, readCiFailures }), /receipt/);
    assert.deepEqual(validateReviewReceipt(reported, { ...response, readCiFailures: [0] }).readCiFailures, [0]);
    assert.throws(
        () => validateReviewReceipt(input, { ...response, readPaths: ["shared/invented.mjs"] }),
        /receipt/,
    );
    assert.throws(
        () => validateReviewReceipt(input, { ...response, sha: "b".repeat(40) }),
        /identity/,
    );
});

test("complete larger Rust sources split into byte-bounded review batches", () => {
    const sources = [0, 1, 2].map(index => entry(index, {content: "a".repeat(100000)}));
    const result = partitionReviewSources(sources);
    assert.equal(result.unreviewedPaths.length, 0);
    assert.deepEqual(result.batches.map(batch => batch.length), [2, 1]);
    assert.deepEqual(result.batches.flat().map(file => file.content.length), [100000, 100000, 100000]);
});

test("stale target is rejected before model, mirror or verifier calls", async () => {
    const attempts = [];
    await assert.rejects(
        () =>
            runReviewFlow({
                target: { branch: "main", sha, publish: false },
                io: {
                    head: async () => "b".repeat(40),
                    collect: async () => attempts.push("collect"),
                    review: async () => attempts.push("review"),
                    mirror: async () => attempts.push("mirror"),
                },
            }),
        /stale/,
    );
    assert.deepEqual(attempts, []);
});

test("no-findings flow records actual read coverage and never mirrors or verifies", async () => {
    const attempts = [];
    const source = entry(0);

    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: false },
        io: {
            head: async () => sha,
            format: async () => ({ status: "passed" }),
            collect: async () => ({
                baseSha: "b".repeat(40),
                entries: [source],
                unreviewedPaths: [],
            }),
            review: async (input) => ({
                repository: input.repository,
                sha,
                branch: "main",
                model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
                publication: "requires-verifier",
                suppliedPaths: [source.path],
                readPaths: [source.path],
                readDiff: true,
                codeExecutions: 1,
                sourceToolCalls: 1,
                kind: "no-findings",
                summary: "No supported finding.",
            }),
            mirror: async () => attempts.push("mirror"),
            verify: async () => attempts.push("verify"),
        },
    });

    assert.deepEqual(result.readPaths, [source.path]);
    assert.equal(result.batches.length, 1);
    assert.deepEqual(result.publications, []);
    assert.deepEqual(attempts, []);
});

test("dedicated App token is scoped to the publisher and has no fallback", () => {
    const workflow = Bun.YAML.parse(readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"));
    const steps = workflow.jobs.publish.steps;
    const mint = steps.find((step) => step.id === "publisher-token");
    assert.equal(mint?.uses, "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510");
    assert.deepEqual(mint.with, {
        "client-id": "${{ vars.OMG_CI_PUBLISHER_APP_CLIENT_ID }}",
        "private-key": "${{ secrets.OMG_CI_PUBLISHER_APP_PRIVATE_KEY }}",
        owner: "omg-cli", repositories: "omg",
        "permission-contents": "write", "permission-issues": "write", "permission-pull-requests": "write",
    });
    assert.equal(mint.if, "needs.review.outputs.publish == 'true'");
    assert.equal(mint["continue-on-error"], undefined);
    const guard = steps.find((step) => step.name === "Require dedicated OMG GitHub App configuration");
    assert.ok(steps.indexOf(guard) < steps.indexOf(mint));
    assert.match(guard.run, /test -n/);
    assert.match(guard.run, /OMG_CI_PUBLISHER_LOGIN/);
    assert.match(guard.run, /OMG_CI_PUBLISHER_ID/);
    const publish = steps.find((step) => step.name === "Re-fetch server proof and publish issues with verified fix PRs");
    assert.ok(steps.indexOf(mint) < steps.indexOf(publish));
    assert.equal(publish.env.GH_TOKEN, "${{ steps.publisher-token.outputs.token }}");
    const preview = steps.find((step) => step.run === "bun scripts/ai-review-flow.mjs publish .audit/ai-review");
    assert.equal(preview.env.GH_TOKEN, "${{ github.token }}");
    assert.equal(preview.if, "needs.review.outputs.publish != 'true'");
    assert.equal(steps.some((step) => step.env?.PUBLISHER_TOKEN), false);
    assert.equal(JSON.stringify(workflow.jobs.review).includes("APP_PRIVATE_KEY"), false);
    assert.equal(JSON.stringify(workflow.jobs.review).includes("publisher-token"), false);
});

test("publisher preflight blocks missing credentials and invalid trusted bot identities", () => {
    const workflow = Bun.YAML.parse(readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"));
    const guard = workflow.jobs.publish.steps.find((step) => step.name === "Require dedicated OMG GitHub App configuration");
    assert.ok(guard, "publication must require dedicated App configuration");
    assert.equal(guard.if, "needs.review.outputs.publish == 'true'");
    assert.deepEqual(guard.env, {
        APP_CLIENT_ID: "${{ vars.OMG_CI_PUBLISHER_APP_CLIENT_ID }}",
        APP_PRIVATE_KEY: "${{ secrets.OMG_CI_PUBLISHER_APP_PRIVATE_KEY }}",
    });
    const valid = {
        APP_CLIENT_ID: "Iv1fixture",
        APP_PRIVATE_KEY: "fixture-private-key",
        OMG_CI_PUBLISHER_LOGIN: "omg-publisher[bot]",
        OMG_CI_PUBLISHER_ID: "123456",
    };
    const cases = [
        ["valid", {}, 0],
        ["missing client", { APP_CLIENT_ID: "" }, 1],
        ["missing key", { APP_PRIVATE_KEY: "" }, 1],
        ["missing login", { OMG_CI_PUBLISHER_LOGIN: "" }, 1],
        ["missing id", { OMG_CI_PUBLISHER_ID: "" }, 1],
        ["nonbot login", { OMG_CI_PUBLISHER_LOGIN: "human" }, 1],
        ["invalid id", { OMG_CI_PUBLISHER_ID: "abc" }, 1],
        ["zero id", { OMG_CI_PUBLISHER_ID: "0" }, 1],
    ];
    const bash = process.platform === "win32"
        ? path.join(process.env.ProgramFiles ?? "C:/Program Files", "Git/bin/bash.exe")
        : "bash";
    for (const [name, overrides, expected] of cases) {
        const result = spawnSync(bash, ["-c", guard.run], {
            env: { ...process.env, ...valid, ...overrides },
            encoding: "utf8",
            timeout: 5000,
        });
        assert.ifError(result.error);
        assert.equal(result.status, expected, `${name}: ${result.stderr}`);
    }
});

test("publisher retries the same trusted command at most three times and preserves terminal failure", () => {
    const workflow = Bun.YAML.parse(readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"));
    const step = workflow.jobs.publish.steps.find((step) => step.name === "Re-fetch server proof and publish issues with verified fix PRs");
    const bash = process.platform === "win32" ? path.join(process.env.ProgramFiles ?? "C:/Program Files", "Git/bin/bash.exe") : "bash";
    const stub = `calls=0\nbun() { [ "$*" = 'scripts/ai-review-flow.mjs publish .audit/ai-review --publish' ] || exit 99; calls=$((calls+1)); printf 'attempt:%s\\n' "$calls"; [ "$calls" -gt "$FAIL_UNTIL" ]; }\nsleep() { :; }\n`;
    for (const [failUntil, expectedStatus, expectedCalls] of [[0, 0, 1], [2, 0, 3], [3, 1, 3]]) {
        const result = spawnSync(bash, ["-c", stub + step.run], {
            env: { ...process.env, FAIL_UNTIL: String(failUntil) }, encoding: "utf8", timeout: 5000,
        });
        assert.ifError(result.error);
        assert.equal(result.status, expectedStatus, result.stderr);
        assert.equal(result.stdout.trim().split("\n").length, expectedCalls);
    }
});

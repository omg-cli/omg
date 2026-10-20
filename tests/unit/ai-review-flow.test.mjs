import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { gitBlobSha, adaptReviewCandidate } from "../../scripts/ai-review-candidate.mjs";
import { proposalDigest, sha256 } from "../../scripts/ai-review-publication.mjs";
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

    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
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
                    "https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-linux-x64.zip",
                ),
            ),
        );
        assert.ok(
            job.steps.some((step) =>
                step.run?.includes(
                    "a83d263767d839e4d2649ca8e35d07159c7afc99afdc96d731ced29e056dda0c",
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
    assert.equal(workflow.jobs.review.permissions, undefined);
    assert.deepEqual(workflow.jobs.publish.permissions, {
        contents: "write",
        issues: "write",
        "pull-requests": "write",
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
    assert.equal(
        workflow.jobs.publish.steps.find(
            (step) =>
                step.name === "Re-fetch server proof and publish issues with verified fix PRs",
        ).run,
        "bun scripts/ai-review-flow.mjs publish .audit/ai-review --publish",
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
    const oversized = partitionReviewSources([entry(0, { content: "a".repeat(24001) }), entry(1)]);
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
    assert.throws(
        () => validateReviewReceipt(input, { ...response, readPaths: ["shared/invented.mjs"] }),
        /receipt/,
    );
    assert.throws(
        () => validateReviewReceipt(input, { ...response, sha: "b".repeat(40) }),
        /identity/,
    );
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

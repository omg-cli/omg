import test from "node:test";
import assert from "node:assert/strict";
import { reviewTarget, runReviewFlow } from "../../scripts/ai-review-flow.mjs";
import { collectIssueSources, assertIssueUnchanged } from "../../scripts/github-issue-source.mjs";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";

const issue = { number: 1011, state: "open", title: "config validate reports success on invalid configuration",
    body: "`src/cli/config.rs:1` returns success after finding issues. Preserve assertions.",
    html_url: "https://github.com/omg-cli/omg/issues/1011" };
const source = "pub fn validate() -> bool { true }\n";
function api(value = issue) {
    return { request: async (method, route) => {
        assert.equal(method, "GET");
        assert.equal(route, "/repos/omg-cli/omg/issues/1011");
        return value;
    } };
}
async function fixture(run) {
    const directory = await mkdtemp(path.join(tmpdir(), "omg-issue-source-"));
    const git = (...args) => execFileSync("git", ["-c", "maintenance.auto=false", "-c", "gc.auto=0", ...args], {
        cwd: directory, encoding: "utf8", windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
    }).trim();
    try {
        git("init");
        await mkdir(path.join(directory, "src/cli"), { recursive: true });
        await writeFile(path.join(directory, "src/cli/config.rs"), source);
        git("add", ".");
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture");
        await run({ directory, sha: git("rev-parse", "HEAD"), git });
    } finally { await rm(directory, { recursive: true, force: true }); }
}

test("manual issue repair selects one exact OMG issue without audit inputs", () => {
    const event = { repository: { full_name: "omg-cli/omg" }, inputs: {
        branch: "main", scope: "issue", issue: "1011", publish: "true",
    } };
    assert.deepEqual(reviewTarget("workflow_dispatch", event), {
        branch: "main", sha: null, publish: true, range: { kind: "issue", issue: 1011 },
    });
    for (const issue of ["", "0", "-1", "1,2", "1011x", "9007199254740992"])
        assert.throws(() => reviewTarget("workflow_dispatch", {
            ...event, inputs: { ...event.inputs, issue },
        }), /issue/i);
    assert.throws(() => reviewTarget("workflow_dispatch", {
        ...event, inputs: { ...event.inputs, audit_cursor: "48" },
    }), /issue/i);
    assert.throws(() => reviewTarget("workflow_dispatch", {
        ...event, inputs: { ...event.inputs, scope: "changes" },
    }), /issue/i);
    const campaign = reviewTarget("workflow_dispatch", { repository: event.repository,
        inputs: { branch: "main", scope: "test-audit", issue: "", publish: "true" } });
    assert.equal(campaign.range.kind, "test-audit");
    assert.equal(campaign.range.cursor, 0);
});

test("issue source is the full committed blob, not an altered working file", async () => fixture(async ({ directory, sha, git }) => {
    await writeFile(path.join(directory, "src/cli/config.rs"), "uncommitted replacement");
    const result = await collectIssueSources({ github: api(), sha, number: 1011, directory });
    assert.deepEqual(result.entries, [{ path: "src/cli/config.rs", blobSha: git("rev-parse", `${sha}:src/cli/config.rs`),
        size: 35, content: source }]);
    assert.equal(result.sourceRange.intake, "github-issue");
    assert.equal(result.sourceRange.issue.number, 1011);
    assert.equal(result.sourceRange.nextCursor, null);
    assert.deepEqual(result.issueEvidence, [{ job: "GitHub issue #1011", step: "untrusted issue report",
        log: "Untrusted GitHub issue #1011; independently verify the reported behavior.\nconfig validate reports success on invalid configuration\n\n`src/cli/config.rs:1` returns success after finding issues. Preserve assertions." }]);
    await assertIssueUnchanged(api(), result.sourceRange);
    await assert.rejects(assertIssueUnchanged(api({ ...issue, body: issue.body + " changed" }), result.sourceRange), /changed/);
    await assert.rejects(assertIssueUnchanged(api({ ...issue, state: "closed" }), result.sourceRange), /Open OMG/);
}));

test("issue preflight refuses foreign, closed, PR, missing and oversized reports", async () => fixture(async ({ directory, sha }) => {
    for (const value of [{ ...issue, number: 12 }, { ...issue, state: "closed" },
        { ...issue, pull_request: {} }, { ...issue, html_url: "https://github.com/other/repo/issues/1011" },
        { ...issue, body: "x".repeat(8001) }, { ...issue, body: "No exact Rust source" },
        { ...issue, body: "`src/missing.rs`" }, { ...issue, body: "`src/../outside.rs`" }])
        await assert.rejects(collectIssueSources({ github: api(value), sha, number: 1011, directory }));
}));

test("issue preflight refuses oversized and symlink Git objects without partial coverage", async () => fixture(async ({ directory, git }) => {
    await writeFile(path.join(directory, "src/cli/config.rs"), "x".repeat(24001));
    git("add", ".");
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "oversized");
    await assert.rejects(collectIssueSources({ github: api(), sha: git("rev-parse", "HEAD"), number: 1011, directory }), /budget/);
    const blob = git("rev-parse", "HEAD:src/cli/config.rs");
    git("update-index", "--cacheinfo", `120000,${blob},src/cli/config.rs`);
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "symlink");
    await assert.rejects(collectIssueSources({ github: api(), sha: git("rev-parse", "HEAD"), number: 1011, directory }), /non-regular/);
}));

test("issue intake delivers complete untrusted evidence through the existing source review", async () => fixture(async ({ directory, sha }) => {
    const calls = [];
    const result = await runReviewFlow({
        target: { branch: "main", sha, publish: false, range: { kind: "issue", issue: 1011 } },
        io: {
            head: async () => sha,
            collect: async (_sha, _branch, range) => {
                calls.push("collect");
                assert.deepEqual(range, { kind: "issue", issue: 1011 });
                return collectIssueSources({ github: api(), sha, number: 1011, directory });
            },
            format: async () => { calls.push("format"); return { status: "passed" }; },
            review: async input => {
                calls.push("review");
                assert.equal(input.sourceFiles[0].content, "pub fn validate() -> bool { true }\n");
                assert.equal(input.ciFailures[0].job, "GitHub issue #1011");
                assert.equal(input.ciFailures[0].log.endsWith(issue.body), true);
                assert.deepEqual(input.changedPaths, []);
                assert.equal(input.diff, "");
                return { repository: "omg-cli/omg", sha, branch: "main", model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017",
                    publication: "requires-verifier", suppliedPaths: ["src/cli/config.rs"], readPaths: ["src/cli/config.rs"],
                    readDiff: false, codeExecutions: 1, sourceToolCalls: 1, kind: "no-findings", summary: "Fixture makes no repair claim." };
            },
        },
    });
    assert.deepEqual(calls, ["collect", "format", "review"]);
    assert.equal(result.status, "reviewed");
    assert.equal(result.sourceRange.issue.number, 1011);
    assert.deepEqual(result.publications, []);
}));

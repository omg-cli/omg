import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createHash } from "node:crypto";
import { SOURCE_REPOSITORY, createSourceAuditEvidence } from "./review-source-evidence.mjs";

const execute = promisify(execFile);
const digest = value => createHash("sha256").update(value).digest("hex");

function issueSnapshot(issue, number) {
    if (!Number.isSafeInteger(number) || number <= 0 || issue?.number !== number ||
        issue.state !== "open" || issue.pull_request ||
        issue.html_url !== `https://github.com/${SOURCE_REPOSITORY}/issues/${number}` ||
        typeof issue.title !== "string" || !issue.title || typeof issue.body !== "string")
        throw new Error("Open OMG issue identity is required");
    const content = `${issue.title}\n\n${issue.body}`;
    const log = `Untrusted GitHub issue #${number}; independently verify the reported behavior.\n${content}`;
    if (Buffer.byteLength(log, "utf8") > 8000)
        throw new Error("Complete issue exceeds the existing evidence budget");
    return { number, url: issue.html_url, contentSha256: digest(content), log };
}

export async function assertIssueUnchanged(github, range) {
    if (range?.intake !== "github-issue") return;
    const snapshot = issueSnapshot(await github.request("GET",
        `/repos/${SOURCE_REPOSITORY}/issues/${range.issue.number}`), range.issue.number);
    if (snapshot.contentSha256 !== range.issue.contentSha256 || snapshot.url !== range.issue.url)
        throw new Error("Source issue changed after collection");
}

export async function collectIssueSources({ github, sha, number, directory }) {
    if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error("Exact issue source SHA required");
    const snapshot = issueSnapshot(await github.request("GET",
        `/repos/${SOURCE_REPOSITORY}/issues/${number}`), number);
    const paths = [...new Set(snapshot.log.match(/\b(?:src|tests)\/(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+\.rs\b/g) ?? [])];
    if (!paths.length || paths.length > 12 || paths.some(file => file.split("/").some(p => p === "." || p === "..")))
        throw new Error("Issue must reference one to twelve complete Rust source files");
    const git = async args => (await execute("git", ["--no-pager", "--literal-pathspecs", ...args], {
        cwd: directory, encoding: "buffer", timeout: 30000, maxBuffer: 26000, windowsHide: true,
    })).stdout;
    const entries = [];
    for (const file of paths) {
        const listing = new TextDecoder("utf-8", { fatal: true }).decode(await git(["ls-tree", "-l", "-z", sha, "--", file]));
        const match = /^(100644|100755) blob ([a-f0-9]{40}) +([0-9]+)\t([^\0]+)\0$/.exec(listing);
        if (!match || match[4] !== file) throw new Error(`Issue source is missing or non-regular: ${file}`);
        const size = Number(match[3]);
        if (size > 24000) throw new Error(`Complete issue source exceeds existing budget: ${file}`);
        const bytes = await git(["show", `${sha}:${file}`]);
        if (bytes.length !== size) throw new Error("Issue source size mismatch");
        entries.push({ path: file, blobSha: match[2], size,
            content: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) });
    }
    const issueEvidence = [{ job: `GitHub issue #${number}`, step: "untrusted issue report", log: snapshot.log }];
    createSourceAuditEvidence({ sha, branch: "main",
        sourceFiles: entries.map(({ path, blobSha, content }) => ({ path, blobSha, content })), ciFailures: issueEvidence });
    const { log, ...issue } = snapshot;
    return { baseSha: sha, entries, unreviewedPaths: [], issueEvidence,
        sourceRange: { kind: "audit", intake: "github-issue", sha, issue,
            cursor: 0, nextCursor: null, pagePaths: entries.length, totalPaths: entries.length,
            inventoryDigest: digest(JSON.stringify(entries.map(({ path, blobSha }) => ({ path, blobSha })))) } };
}

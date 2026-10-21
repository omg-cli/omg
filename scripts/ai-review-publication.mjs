import { assertRustSourceChange } from "./rust-source-policy.mjs";
import { createHash } from "node:crypto";
import { Schema } from "effect";

export const REVIEW_REPOSITORY = "omg-cli/omg";
const sha40 = Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/));
const sha64 = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/));
const text = (maximum) => Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(maximum));

const count = Schema.Number.check(
    Schema.makeFilter(Number.isSafeInteger),
    Schema.isGreaterThanOrEqualTo(0),
);

const positive = count.check(Schema.isGreaterThan(0));

const identity = {
    repository: Schema.Literal(REVIEW_REPOSITORY),
    branch: Schema.Literal("main"),
    baseSha: sha40,
};

const finding = Schema.Struct({
    key: sha64,
    title: text(160),
    summary: text(4000),
    path: text(240),
    line: positive,
    sourceQuote: text(4000),
    reproduction: text(4000),
});

export const proposalSchema = Schema.Struct({
    ...identity,
    finding,
    changes: Schema.Array(
        Schema.Struct({
            path: text(240),
            originalBlobSha: Schema.NullOr(sha40),
            oldContentQuote: Schema.String.check(Schema.isMaxLength(4000)),
            newContent: text(64000),
            sha256: sha64,
        }),
    ).check(Schema.isMinLength(1), Schema.isMaxLength(8)),
});

const regression = {
    testName: text(500),
    exitCode: count,
    tests: positive,
    failures: count,
    errors: count,
    skipped: count,
    reportSha256: sha64,
    stdoutSha256: sha64,
    stderrSha256: sha64,
    catalogSha256: sha64,
    executableSha256: sha64,
    compilerMessagesSha256: sha64,
    sourceSha256: sha64,
    recipeSha256: sha64,
};

export const receiptSchema = Schema.Struct({
    ...identity,
    proposalSha256: sha64,
    verifierRevision: sha40,
    runId: positive,
    runAttempt: positive,
    baseline: Schema.Struct({
        ...regression,
        assertionFailure: text(4000),
        assertionFile: text(300),
        assertionLine: positive,
        assertionSourceSha256: sha64,
    }),
    patched: Schema.Struct(regression),
    portableChecks: Schema.Array(
        Schema.Struct({ name: text(200), exitCode: count, reportSha256: sha64 }),
    ).check(Schema.isMaxLength(20)),
    protectedPathsUnchanged: Schema.Literal(true),
});

export const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export function canonicalJson(value) {
    return JSON.stringify(value, (_, item) =>
        Schema.is(Schema.Record(Schema.String, Schema.Unknown))(item)
            ? Object.fromEntries(
                  Object.entries(item).sort(([first], [second]) => first.localeCompare(second)),
              )
            : item,
    );
}

export const proposalDigest = (proposal) => sha256(canonicalJson(proposal));

export const findingKey = (value) => sha256(`${value.path}\0${value.sourceQuote}`);

function decode(schema, input) {
    try {
        return Schema.decodeUnknownSync(schema, { onExcessProperty: "error" })(input);
    } catch {
        throw new Error("Invalid AI review publication document.");
    }
}

function allowedPath(value) {
    if (
        !/^[a-zA-Z0-9_./-]+$/.test(value) ||
        value.split("/").some((part) => !part || part === "." || part === "..")
    )
        return false;

    if (
        /(?:^|\/)(?:AGENTS|DEBUGGING|SECURITY|package|bun\.lock|vite\.config|vitest\.config|playwright\.config|wrangler|tsconfig)/i.test(
            value,
        )
    )
        return false;

    return /^src\/.+\.rs$/.test(value) || /^tests\/ai-review-[a-z0-9-]+\.rs$/.test(value);
}

function assertRegularSource(source) {
    if (
        !source ||
        source.mode !== "100644" ||
        !Schema.is(Schema.String)(source.content) ||
        source.content.includes("\0") ||
        Buffer.byteLength(source.content) > 128 * 1024
    )
        throw new Error("Source must be a bounded regular text blob.");
}

export function admitPublication({
    proposal: rawProposal,
    receipt: rawReceipt,
    sources,
    verifierRevision,
    requiredChecks,
}) {
    const proposal = decode(proposalSchema, rawProposal);
    const receipt = decode(receiptSchema, rawReceipt);

    if (
        !/^[a-f0-9]{40}$/.test(verifierRevision) ||
        !Array.isArray(requiredChecks) ||
        requiredChecks.length === 0 ||
        new Set(requiredChecks).size !== requiredChecks.length
    )
        throw new Error("Trusted verifier policy is required.");

    if (
        receipt.verifierRevision !== verifierRevision ||
        receipt.proposalSha256 !== proposalDigest(proposal)
    )
        throw new Error("Verifier or proposal digest mismatch.");

    for (const field of ["repository", "branch", "baseSha"])
        if (receipt[field] !== proposal[field]) throw new Error("Receipt identity mismatch.");

    if (
        receipt.baseline.exitCode !== 101 ||
        receipt.baseline.failures < 1 ||
        receipt.baseline.errors !== 0 ||
        receipt.baseline.skipped !== 0
    )
        throw new Error(
            "Baseline must contain an observed assertion failure, without setup errors or skips.",
        );

    if (
        receipt.patched.testName !== receipt.baseline.testName ||
        receipt.patched.tests !== receipt.baseline.tests ||
        receipt.patched.recipeSha256 !== receipt.baseline.recipeSha256 ||
        receipt.patched.sourceSha256 !== receipt.baseline.sourceSha256 ||
        receipt.patched.exitCode !== 0 ||
        receipt.patched.failures !== 0 ||
        receipt.patched.errors !== 0 ||
        receipt.patched.skipped !== 0
    )
        throw new Error("The same regression must pass after the patch.");
    const checks = new Map(receipt.portableChecks.map((check) => [check.name, check]));

    if (
        checks.size !== receipt.portableChecks.length ||
        receipt.portableChecks.some((check) => check.exitCode !== 0) ||
        requiredChecks.some((name) => !checks.has(name))
    )
        throw new Error("Required portable checks must pass.");

    if (findingKey(proposal.finding) !== proposal.finding.key)
        throw new Error("Finding key does not match its source evidence.");
    const anchor = sources.get(proposal.finding.path);
    assertRegularSource(anchor);

    const quote = anchor.content
        .split(/\r?\n/)
        .slice(proposal.finding.line - 1)
        .join("\n");

    if (!quote.startsWith(proposal.finding.sourceQuote))
        throw new Error("Source anchor does not match the reviewed line.");
    const assertionFile = receipt.baseline.assertionFile;
    const assertionContent =
        sources.get(assertionFile)?.content ??
        proposal.changes.find(
            (change) => change.path === assertionFile && change.originalBlobSha === null,
        )?.newContent;
    if (
        !assertionContent ||
        sha256(assertionContent.split("\n")[receipt.baseline.assertionLine - 1] ?? "") !==
            receipt.baseline.assertionSourceSha256 ||
        receipt.baseline.assertionLine > assertionContent.split("\n").length
    )
        throw new Error("Baseline assertion does not join the exact reviewed Rust source");
    const paths = new Set();
    let bytes = 0;

    for (const change of proposal.changes) {
        if (!allowedPath(change.path) || paths.has(change.path))
            throw new Error("Protected or duplicate patch path.");
        paths.add(change.path);
        const original = sources.get(change.path);

        if (change.path.startsWith("tests/") && (original || change.originalBlobSha !== null))
            throw new Error("Existing tests cannot be changed automatically.");

        if (change.originalBlobSha === null) {
            if (original || change.oldContentQuote !== "")
                throw new Error("New file already exists or claims old content.");
        } else {
            assertRegularSource(original);

            if (
                original.sha !== change.originalBlobSha ||
                !change.oldContentQuote ||
                !original.content.includes(change.oldContentQuote)
            )
                throw new Error("Original blob or old-content quote mismatch.");

            assertRustSourceChange(change.path, original.content, change.newContent);

            if (original.content === change.newContent)
                throw new Error("Patch contains an unchanged file.");
        }

        if (change.newContent.includes("\0") || sha256(change.newContent) !== change.sha256)
            throw new Error("New text content hash mismatch.");
        bytes += Buffer.byteLength(change.newContent);
    }

    if (bytes > 128 * 1024) throw new Error("Patch text budget exceeded.");

    return {
        proposal,
        receipt,
        headBranch: `ai-fix/${proposal.finding.key.slice(0, 16)}-${proposal.baseSha.slice(0, 12)}`,
        evidenceDigest: sha256(canonicalJson(receipt)),
    };
}

export function publicationBodies({ proposal, receipt, evidenceDigest }) {
    const { finding: item } = proposal;
    const sourceUrl = `https://github.com/${REVIEW_REPOSITORY}/blob/${proposal.baseSha}/${item.path}#L${item.line}`;
    const runUrl = `https://github.com/${REVIEW_REPOSITORY}/actions/runs/${receipt.runId}/attempts/${receipt.runAttempt}`;
    const marker = `<!-- ai-review:${item.key} -->`;

    const observation = (phase, result) =>
        `Captured ${phase} process result: exit ${result.exitCode}; report lists ${result.tests} ${result.tests === 1 ? "test" : "tests"}, ${result.failures} ${result.failures === 1 ? "failure" : "failures"}, ${result.errors} errors, ${result.skipped} skipped.`;

    const evidence = [
        marker,
        "Unconfirmed AI finding. Generated test semantics and the proposed fix require independent review.",
        "Model-reported impact (unconfirmed):",
        item.summary,
        `Source: ${sourceUrl}`,
        `Base branch: ${proposal.branch}. Base SHA: ${proposal.baseSha}.`,
        "Source quote:",
        `\n\`\`\`text\n${item.sourceQuote}\n\`\`\``,
        "Model-proposed reproduction (unconfirmed):",
        item.reproduction,
        observation("baseline", receipt.baseline),
        observation("patched", receipt.patched),
        "Baseline report's assertion text:",
        receipt.baseline.assertionFailure,
        `Verifier run: ${runUrl}`,
        `Verifier revision: ${receipt.verifierRevision}`,
        `Baseline report SHA-256: ${receipt.baseline.reportSha256}`,
        `Patched report SHA-256: ${receipt.patched.reportSha256}`,
        `Proposal SHA-256: ${receipt.proposalSha256}`,
        `Receipt SHA-256: ${evidenceDigest}`,
        "Hashes identify captured bytes; they do not confirm the reported bug or authenticate the generated test's meaning. Independent review must confirm that the assertion exercises the intended behavior and that the proposed change fixes it.",
        "Independent approval is required before merge. No automatic merge or deployment. Windows/native acceptance remains unproven.",
        ...receipt.portableChecks.map(
            (check) =>
                `${check.name}: exit ${check.exitCode}; report SHA-256 ${check.reportSha256}`,
        ),
    ].join("\n\n");

    return {
        issue: evidence,
        pullRequest: `<!-- ai-review-patch:${item.key}:${proposal.branch}:${proposal.baseSha} -->\n\nProposed fix for an unconfirmed AI finding.\n\n${evidence}`,
    };
}

const defaultPublisher = Object.freeze({ login: "github-actions[bot]", id: 41898282 });

function configuredPublisher() {
    const login = process.env.OMG_CI_PUBLISHER_LOGIN ?? "";
    const rawId = process.env.OMG_CI_PUBLISHER_ID ?? "";
    if (!login && !rawId) return defaultPublisher;
    const id = Number(rawId);
    if (
        !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?(?:\[bot\])?$/.test(login) ||
        !/^[1-9][0-9]*$/.test(rawId) ||
        !Number.isSafeInteger(id)
    )
        throw new Error("Invalid trusted publisher identity configuration.");
    return { login, id };
}

const publisherMatches = (author, expected) =>
    author?.login === expected.login && author?.id === expected.id;

export function findPublication(records, marker, publisher = defaultPublisher) {
    const matches = records.filter(
        (item) =>
            publisherMatches(item.user, publisher) &&
            Schema.is(Schema.String)(item.body) &&
            item.body.split(/\r?\n/)[0] === marker,
    );

    if (matches.length > 1)
        throw new Error("Ambiguous existing publication; human reconciliation required.");

    return matches[0];
}

const prefix = `/repos/${REVIEW_REPOSITORY}`;

async function listRecords(github, resource) {
    const records = [];

    for (let page = 1; page <= 20; page++) {
        const batch = await github.request(
            "GET",
            `${prefix}/${resource}?state=all&per_page=100&page=${page}`,
        );

        if (!Array.isArray(batch)) throw new Error("Invalid GitHub publication inventory.");
        records.push(...batch);

        if (batch.length < 100) return records;
    }

    throw new Error("Publication inventory exceeds bounded pagination.");
}

async function loadSources(github, proposal) {
    const commit = await github.request("GET", `${prefix}/git/commits/${proposal.baseSha}`);
    const tree = await github.request("GET", `${prefix}/git/trees/${commit.tree.sha}?recursive=1`);

    if (tree.truncated || !Array.isArray(tree.tree))
        throw new Error("Source tree inventory is incomplete.");
    const sources = new Map();

    for (const file of new Set([
        proposal.finding.path,
        ...proposal.changes.map((change) => change.path),
    ])) {
        const entry = tree.tree.find((item) => item.path === file);

        if (!entry) continue;

        if (entry.type !== "blob" || entry.mode !== "100644")
            throw new Error("Source is not a regular text blob.");
        const blob = await github.request("GET", `${prefix}/git/blobs/${entry.sha}`);

        if (
            blob.encoding !== "base64" ||
            !Schema.is(Schema.String)(blob.content) ||
            blob.content.length > 180000
        )
            throw new Error("Invalid or oversized source blob.");
        const bytes = Buffer.from(blob.content, "base64");
        const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        sources.set(file, { sha: entry.sha, mode: entry.mode, content });
    }

    return { sources, treeSha: commit.tree.sha, treeEntries: tree.tree };
}

async function verifyExistingBranch(github, ref, proposal, treeEntries, issue) {
    const commit = await github.request("GET", `${prefix}/git/commits/${ref.object.sha}`);

    if (
        !issue ||
        commit.message !==
            `AI review ${proposal.finding.key}\nProposal ${proposalDigest(proposal)}` ||
        commit.parents?.length !== 1 ||
        commit.parents[0].sha !== proposal.baseSha
    )
        throw new Error("Existing branch is not an identical interrupted publication.");
    const tree = await github.request("GET", `${prefix}/git/trees/${commit.tree.sha}?recursive=1`);

    if (tree.truncated || !Array.isArray(tree.tree))
        throw new Error("Existing branch tree is incomplete.");

    const expected = new Map(
        treeEntries.filter((item) => item.type !== "tree").map((item) => [item.path, item]),
    );

    const actual = new Map(
        tree.tree.filter((item) => item.type !== "tree").map((item) => [item.path, item]),
    );

    for (const change of proposal.changes) {
        const entry = actual.get(change.path);

        if (!entry || entry.type !== "blob" || entry.mode !== "100644")
            throw new Error("Existing branch changed file modes.");
        const blob = await github.request("GET", `${prefix}/git/blobs/${entry.sha}`);

        if (
            blob.encoding !== "base64" ||
            !Schema.is(Schema.String)(blob.content) ||
            blob.content.length > 180000 ||
            sha256(Buffer.from(blob.content, "base64")) !== change.sha256
        )
            throw new Error("Existing branch content differs from verified proposal.");
        expected.set(change.path, entry);
    }

    if (
        expected.size !== actual.size ||
        [...expected].some(([file, entry]) => {
            const found = actual.get(file);

            return (
                !found ||
                found.sha !== entry.sha ||
                found.mode !== entry.mode ||
                found.type !== entry.type
            );
        })
    )
        throw new Error("Existing branch changed protected paths.");

    return { sha: ref.object.sha, tree: { sha: commit.tree.sha } };
}

export async function publishAiReview({
    proposal: input,
    receipt,
    github,
    verifierRevision,
    requiredChecks,
    publish = false,
}) {
    const publisher = configuredPublisher();
    const proposal = decode(proposalSchema, input);
    const { sources, treeSha, treeEntries } = await loadSources(github, proposal);

    const admitted = admitPublication({
        proposal,
        receipt,
        sources,
        verifierRevision,
        requiredChecks,
    });

    const bodies = publicationBodies(admitted);

    const [issues, pulls] = await Promise.all([
        listRecords(github, "issues"),
        listRecords(github, "pulls"),
    ]);

    const issue = findPublication(
        issues.filter((item) => !item.pull_request),
        `<!-- ai-review:${proposal.finding.key} -->`,
        publisher,
    );

    const patchPrefix = `<!-- ai-review-patch:${proposal.finding.key}:${proposal.branch}:`;

    const patchMarkers = pulls
        .filter(
            (item) => publisherMatches(item.user, publisher) && Schema.is(Schema.String)(item.body),
        )
        .map((item) => item.body.split(/\r?\n/)[0])
        .filter(
            (marker) =>
                marker.startsWith(patchPrefix) &&
                /^[a-f0-9]{40} -->$/.test(marker.slice(patchPrefix.length)),
        );

    if (patchMarkers.length > 1)
        throw new Error("Ambiguous prior repair history; human reconciliation required.");
    const pull =
        patchMarkers.length === 1 ? findPublication(pulls, patchMarkers[0], publisher) : undefined;

    if (issue?.state === "closed" || pull?.state === "closed")
        return { action: "closed", issue, pull };

    if (pull) return { action: "existing", issue, pull };

    const checkHead = async () => {
        const current = await github.request("GET", `${prefix}/git/ref/heads/${proposal.branch}`);

        if (current.object.sha !== proposal.baseSha)
            throw new Error("Target branch is stale; recollect and verify before publication.");
    };

    await checkHead();

    if (!publish) return { action: "dry-run", headBranch: admitted.headBranch, bodies };
    const existingRef = await github.request(
        "GET",
        `${prefix}/git/ref/heads/${admitted.headBranch}`,
    );

    const resumedCommit = existingRef
        ? await verifyExistingBranch(github, existingRef, proposal, treeEntries, issue)
        : null;

    const openedIssue =
        issue ??
        (await github.request("POST", `${prefix}/issues`, {
            title: `[Unconfirmed AI finding] ${proposal.finding.title}`,
            body: bodies.issue,
        }));

    if (!publisherMatches(openedIssue.user, publisher))
        throw new Error("GitHub issue publisher identity mismatch.");

    let commit = resumedCommit;

    if (!commit) {
        const entries = [];

        for (const change of proposal.changes) {
            const blob = await github.request("POST", `${prefix}/git/blobs`, {
                content: change.newContent,
                encoding: "utf-8",
            });

            entries.push({ path: change.path, mode: "100644", type: "blob", sha: blob.sha });
        }

        const tree = await github.request("POST", `${prefix}/git/trees`, {
            base_tree: treeSha,
            tree: entries,
        });

        commit = await github.request("POST", `${prefix}/git/commits`, {
            message: `AI review ${proposal.finding.key}\nProposal ${proposalDigest(proposal)}`,
            tree: tree.sha,
            parents: [proposal.baseSha],
        });
        commit = { ...commit, tree: { sha: tree.sha } };
        await checkHead();
        await github.request("POST", `${prefix}/git/refs`, {
            ref: `refs/heads/${admitted.headBranch}`,
            sha: commit.sha,
        });
    }

    await checkHead();

    const openedPull = await github.request("POST", `${prefix}/pulls`, {
        title: `[Unconfirmed AI repair] ${proposal.finding.title}`,
        body: `${bodies.pullRequest}\n\nIssue: ${openedIssue.html_url}`,
        head: admitted.headBranch,
        base: proposal.branch,
        draft: false,
    });

    if (!publisherMatches(openedPull.user, publisher))
        throw new Error("GitHub PR publisher identity mismatch.");

    return {
        action: "published",
        issue: openedIssue,
        pull: openedPull,
        commitSha: commit.sha,
        treeSha: commit.tree.sha,
    };
}

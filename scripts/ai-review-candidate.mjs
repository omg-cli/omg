import { assertRustSourceChange } from "./rust-source-policy.mjs";
import { createHash } from "node:crypto";
import { Schema } from "effect";
import { findingKey, proposalSchema, sha256, REVIEW_REPOSITORY } from "./ai-review-publication.mjs";

const text = (limit) => Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(limit));
const sha40 = Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/));

const positive = Schema.Number.check(
    Schema.makeFilter(Number.isSafeInteger),
    Schema.isGreaterThan(0),
);

const sourceFile = Schema.Struct({
    path: text(300),
    blobSha: sha40,
    content: Schema.String.check(Schema.isMaxLength(24000)),
});

const inputSchema = Schema.Struct({
    repository: Schema.Literal(REVIEW_REPOSITORY),
    sha: sha40,
    branch: Schema.Literal("main"),
    changedPaths: Schema.Array(text(300)).check(Schema.isMinLength(1), Schema.isMaxLength(30)),
    diff: Schema.String.check(Schema.isMaxLength(64000)),
    sourceFiles: Schema.Array(sourceFile).check(Schema.isMinLength(1), Schema.isMaxLength(12)),
    ciFailures: Schema.Array(
        Schema.Struct({
            job: text(200),
            step: text(200),
            log: Schema.String.check(Schema.isMaxLength(8000)),
        }),
    ).check(Schema.isMaxLength(6)),
});

const candidateSchema = Schema.Struct({
    title: text(160),
    impact: text(2000),
    evidence: Schema.Array(
        Schema.Struct({
            path: text(300),
            blobSha: sha40,
            lineStart: positive,
            lineEnd: positive,
            quote: text(4000),
        }),
    ).check(Schema.isMinLength(1), Schema.isMaxLength(3)),
    proposedFix: Schema.NullOr(
        Schema.Struct({
            edits: Schema.Array(
                Schema.Struct({
                    path: text(300),
                    oldText: text(4000),
                    newText: Schema.String.check(Schema.isMaxLength(6000)),
                }),
            ).check(Schema.isMinLength(1), Schema.isMaxLength(3)),
            regressionTest: Schema.Struct({
                path: text(300),
                content: text(12000),
                expectedTestName: text(200),
            }),
        }),
    ),
});

const reviewSchema = Schema.Struct({
    kind: Schema.Literal("candidates"),
    summary: text(2000),
    candidates: Schema.Array(candidateSchema).check(Schema.isMinLength(1), Schema.isMaxLength(3)),
});

const sourceSchema = Schema.Struct({
    sha: sha40,
    mode: Schema.Literal("100644"),
    content: Schema.String.check(Schema.isMaxLength(24000)),
});

const parse = (schema, value) =>
    Schema.decodeUnknownSync(schema, { onExcessProperty: "error" })(value);

export function gitBlobSha(content) {
    return createHash("sha1")
        .update(`blob ${Buffer.byteLength(content)}\0`)
        .update(content)
        .digest("hex");
}

export function adaptReviewCandidate({
    input: rawInput,
    review: rawReview,
    candidateIndex,
    sources,
}) {
    const input = parse(inputSchema, rawInput);
    const review = parse(reviewSchema, rawReview);

    if (
        !Number.isSafeInteger(candidateIndex) ||
        candidateIndex < 0 ||
        candidateIndex >= review.candidates.length
    )
        throw new Error("Invalid candidate index.");

    if (
        new Set(input.sourceFiles.map((file) => file.path)).size !== input.sourceFiles.length ||
        new Set(input.changedPaths).size !== input.changedPaths.length
    )
        throw new Error("Duplicate review paths.");
    const original = new Map();

    for (const file of input.sourceFiles) {
        const actual = parse(sourceSchema, sources.get(file.path));

        if (
            actual.sha !== file.blobSha ||
            actual.content !== file.content ||
            gitBlobSha(actual.content) !== file.blobSha ||
            actual.content.includes("\0")
        )
            throw new Error("Review source differs from exact Git blob.");
        original.set(file.path, actual);
    }

    const candidate = review.candidates[candidateIndex];

    if (!candidate.evidence.some((item) => input.changedPaths.includes(item.path)))
        throw new Error("Finding must cite changed source.");

    for (const evidence of candidate.evidence) {
        const file = original.get(evidence.path);

        if (
            !file ||
            file.sha !== evidence.blobSha ||
            evidence.lineEnd < evidence.lineStart ||
            evidence.lineEnd - evidence.lineStart > 79 ||
            file.content
                .split("\n")
                .slice(evidence.lineStart - 1, evidence.lineEnd)
                .join("\n") !== evidence.quote
        )
            throw new Error("Source evidence quote or blob mismatch.");
    }

    const fix = candidate.proposedFix;

    if (!fix) throw new Error("This candidate has no verifiable repair.");
    const updated = new Map();
    const oldQuotes = new Map();

    for (const edit of fix.edits) {
        if (
            !/^src\/(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+\.rs$/.test(edit.path) ||
            /(?:^|\/)(?:AGENTS|DEBUGGING|SECURITY|package|vite\.config|vitest\.config|playwright\.config|wrangler|tsconfig)/i.test(
                edit.path,
            )
        )
            throw new Error("Candidate edit is outside automatic source scope.");
        const source = updated.get(edit.path) ?? original.get(edit.path)?.content;

        if (source === undefined) throw new Error("Edited source was not reviewed.");
        const position = source.indexOf(edit.oldText);

        if (
            position < 0 ||
            source.indexOf(edit.oldText, position + 1) >= 0 ||
            edit.oldText === edit.newText
        )
            throw new Error("Edit must replace one unique exact occurrence.");

        if (!oldQuotes.has(edit.path)) oldQuotes.set(edit.path, edit.oldText);
        updated.set(
            edit.path,
            source.slice(0, position) + edit.newText + source.slice(position + edit.oldText.length),
        );
    }

    const anchor = candidate.evidence.find((item) => input.changedPaths.includes(item.path));

    const finding = {
        title: candidate.title,
        summary: candidate.impact,
        path: anchor.path,
        line: anchor.lineStart,
        sourceQuote: anchor.quote,
        reproduction: `Regression case: ${fix.regressionTest.expectedTestName}. ${candidate.impact}`,
    };

    const key = findingKey(finding);
    const modelTest = fix.regressionTest;

    if (
        modelTest.path !== `tests/ci-review-${input.sha.slice(0, 12)}-${candidateIndex + 1}.rs` ||
        !modelTest.content.includes(modelTest.expectedTestName)
    )
        throw new Error("Regression test identity is not designated.");
    const testPath = `tests/ai-review-${key.slice(0, 16)}-${input.sha.slice(0, 12)}.rs`;

    if (sources.has(testPath) || sources.has(modelTest.path))
        throw new Error("Regression test must be new.");

    for (const [file, content] of updated)
        assertRustSourceChange(file, original.get(file).content, content);

    const changes = [...updated].map(([path, newContent]) => ({
        path,
        originalBlobSha: original.get(path).sha,
        oldContentQuote: oldQuotes.get(path),
        newContent,
        sha256: sha256(newContent),
    }));

    changes.push({
        path: testPath,
        originalBlobSha: null,
        oldContentQuote: "",
        newContent: modelTest.content,
        sha256: sha256(modelTest.content),
    });

    const proposal = parse(proposalSchema, {
        repository: REVIEW_REPOSITORY,
        branch: input.branch,
        baseSha: input.sha,
        finding: { ...finding, key },
        changes,
    });

    return { proposal, regression: { path: testPath, testName: modelTest.expectedTestName } };
}

export async function collectCandidateSources({ github, sha, paths }) {
    parse(sha40, sha);
    parse(Schema.Array(text(300)).check(Schema.isMinLength(1), Schema.isMaxLength(16)), paths);
    const prefix = `/repos/${REVIEW_REPOSITORY}`;
    const commit = await github.request("GET", `${prefix}/git/commits/${sha}`);
    parse(sha40, commit.tree.sha);
    const tree = await github.request("GET", `${prefix}/git/trees/${commit.tree.sha}?recursive=1`);

    if (tree.truncated || !Array.isArray(tree.tree))
        throw new Error("Source tree inventory is incomplete.");
    const sources = new Map();

    for (const path of new Set(paths)) {
        const entry = tree.tree.find((item) => item.path === path);

        if (!entry) continue;

        if (entry.mode !== "100644" || entry.type !== "blob")
            throw new Error("Review source must be a regular blob.");
        parse(sha40, entry.sha);
        const blob = await github.request("GET", `${prefix}/git/blobs/${entry.sha}`);

        const content = parse(
            Schema.Struct({ encoding: Schema.Literal("base64"), content: text(40000) }),
            { encoding: blob.encoding, content: blob.content },
        );

        const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
            Buffer.from(content.content, "base64"),
        );

        if (gitBlobSha(decoded) !== entry.sha)
            throw new Error("Git blob bytes do not match their identity.");
        sources.set(
            path,
            parse(sourceSchema, { sha: entry.sha, mode: entry.mode, content: decoded }),
        );
    }

    return sources;
}

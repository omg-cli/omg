import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
    parseSourceReviewArguments,
    createSourceReviewEvidence,
    sourceReviewEndpoint,
} from "../../scripts/review-source-evidence.mjs";

const sha = "a".repeat(40);
const baseSha = "b".repeat(40);

function fixture(content = 'pub const value: usize = "café";\n', file = "src/value.rs") {
    const bytes = Buffer.from(content);
    const blobSha = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");

    return {
        sha,
        baseSha,
        branch: "main",
        rawDiff: `:100644 100644 ${baseSha} ${blobSha} M\0${file}\0`,
        diff: `diff --git a/${file} b/${file}\n+${content}`,
        numstat: `1\t1\t${file}\0`,
        blobs: new Map([[blobSha, bytes]]),
    };
}

test("source review CLI accepts only exact commits and allowed target branches", () => {
    assert.deepEqual(
        parseSourceReviewArguments([
            "--sha",
            sha,
            "--base-sha",
            baseSha,
            "--branch",
            "main",
            "--snapshot-only",
        ]),
        { sha, baseSha, branch: "main", snapshotOnly: true },
    );
    assert.throws(
        () =>
            parseSourceReviewArguments([
                "--sha",
                "main",
                "--base-sha",
                baseSha,
                "--branch",
                "main",
            ]),
        /SHA/,
    );
    assert.throws(
        () =>
            parseSourceReviewArguments(["--sha", sha, "--base-sha", baseSha, "--branch", "topic"]),
        /branch/,
    );
    assert.throws(
        () =>
            parseSourceReviewArguments([
                "--sha",
                sha,
                "--base-sha",
                baseSha,
                "--branch",
                "main",
                "--run",
                "anything",
            ]),
        /Unknown/,
    );
});

test("source evidence preserves exact Git blob bytes, commit identity and coverage", () => {
    const value = fixture();
    const evidence = createSourceReviewEvidence(value);
    assert.deepEqual(evidence.suppliedPaths, ["src/value.rs"]);
    assert.deepEqual(evidence.reviewedPaths, []);
    assert.deepEqual(evidence.unreviewedPaths, [
        { path: "src/value.rs", reason: "not-read-by-model" },
    ]);
    assert.deepEqual(evidence.sourceInput, {
        repository: "omg-cli/omg",
        sha,
        branch: "main",
        changedPaths: ["src/value.rs"],
        diff: value.diff,
        sourceFiles: [
            {
                path: "src/value.rs",
                blobSha: [...value.blobs.keys()][0],
                content: 'pub const value: usize = "café";\n',
            },
        ],
        ciFailures: [],
    });
});

test("source evidence refuses binary files, symlinks and submodules", () => {
    const value = fixture();
    assert.throws(
        () => createSourceReviewEvidence({ ...value, numstat: "-\t-\tsrc/value.rs\0" }),
        /Binary/,
    );
    assert.throws(
        () =>
            createSourceReviewEvidence({
                ...value,
                rawDiff: value.rawDiff.replace(":100644 100644", ":100644 120000"),
            }),
        /Symlink|regular/,
    );
    assert.throws(
        () =>
            createSourceReviewEvidence({
                ...value,
                rawDiff: value.rawDiff.replace(":100644 100644", ":100644 160000"),
            }),
        /Submodule|regular/,
    );
});

test("source evidence refuses content and diff budget overflow without truncation", () => {
    assert.throws(() => createSourceReviewEvidence(fixture("x".repeat(24001))), /budget|large/);
    assert.throws(
        () => createSourceReviewEvidence({ ...fixture(), diff: "x".repeat(64001) }),
        /budget|large/,
    );
});

test("source evidence reports unsupported and deleted paths explicitly", () => {
    const value = fixture();
    const other = fixture("Documentation.\n", "README.md");
    const deleted = `:100644 000000 ${baseSha} ${"0".repeat(40)} D\0src/deleted.mjs\0`;

    const evidence = createSourceReviewEvidence({
        ...value,
        rawDiff: value.rawDiff + other.rawDiff + deleted,
        numstat: value.numstat + other.numstat + "0\t1\tsrc/deleted.mjs\0",
    });

    assert.deepEqual(evidence.unreviewedPaths, [
        { path: "README.md", reason: "unsupported-source-type" },
        { path: "src/deleted.mjs", reason: "deleted-at-reviewed-commit" },
        { path: "src/value.rs", reason: "not-read-by-model" },
    ]);
    assert.deepEqual(evidence.sourceInput.changedPaths, [
        "src/value.rs",
        "README.md",
        "src/deleted.mjs",
    ]);
});

test("source review reuses only the protected dedicated inspector hostname", () => {
    assert.equal(
        sourceReviewEndpoint({ endpoint: "https://omg-ci-inspector.owner.workers.dev/inspect" })
            .href,
        "https://omg-ci-inspector.owner.workers.dev/review",
    );
    assert.throws(
        () => sourceReviewEndpoint({ endpoint: "https://other.example/inspect" }),
        /dedicated/,
    );
});

test("source evidence rejects a substituted Git blob even when its claimed identity matches inventory", () => {
    const value = fixture();
    const [blobSha] = value.blobs.keys();
    assert.throws(
        () =>
            createSourceReviewEvidence({
                ...value,
                blobs: new Map([[blobSha, Buffer.from("substituted source")]]),
            }),
        /blob identity/,
    );
});

test("source evidence refuses more than twelve source files", () => {
    const values = Array.from({ length: 13 }, (_, index) =>
        fixture(`export const index = ${index};\n`, `src/file-${index}.mjs`),
    );

    const value = {
        ...values[0],
        rawDiff: values.map((item) => item.rawDiff).join(""),
        numstat: values.map((item) => item.numstat).join(""),
        blobs: new Map(values.flatMap((item) => [...item.blobs])),
    };

    assert.throws(() => createSourceReviewEvidence(value), /Source file budget exceeds 12/);
});

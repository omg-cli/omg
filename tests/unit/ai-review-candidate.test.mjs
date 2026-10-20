import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
    adaptReviewCandidate,
    collectCandidateSources,
} from "../../scripts/ai-review-candidate.mjs";
import {
    parseRustCatalog,
    parseRustExecution,
} from "../../services/cloud-ci/runner/rust-evidence.mjs";

const content = "pub const value: usize = 1;\n";
const sha = "a".repeat(40);

const blobSha = createHash("sha1")
    .update(`blob ${Buffer.byteLength(content)}\0${content}`)
    .digest("hex");

function fixture() {
    const input = {
        repository: "omg-cli/omg",
        sha,
        branch: "main",
        changedPaths: ["src/value.rs"],
        diff: "",
        sourceFiles: [{ path: "src/value.rs", blobSha, content }],
        ciFailures: [],
    };

    const review = {
        kind: "candidates",
        summary: "A reproducible value bug.",
        candidates: [
            {
                title: "Value is incorrect",
                impact: "The exported value is incorrect.",
                evidence: [
                    {
                        path: "src/value.rs",
                        blobSha,
                        lineStart: 1,
                        lineEnd: 1,
                        quote: content.trim(),
                    },
                ],
                proposedFix: {
                    edits: [
                        {
                            path: "src/value.rs",
                            oldText: "value: usize = 1",
                            newText: "value: usize = 2",
                        },
                    ],
                    regressionTest: {
                        path: "tests/ci-review-aaaaaaaaaaaa-1.rs",
                        content:
                            '#[path = "../src/value.rs"] mod value;\n#[test] fn value_returns_two() { assert_eq!(value::value, 2); }\n',
                        expectedTestName: "value_returns_two",
                    },
                },
            },
        ],
    };

    return {
        input,
        review,
        candidateIndex: 0,
        sources: new Map([["src/value.rs", { sha: blobSha, mode: "100644", content }]]),
    };
}

test("candidate adapter binds exact source bytes and constructs the unique replacement and new test", () => {
    const result = adaptReviewCandidate(fixture());
    assert.equal(result.proposal.baseSha, sha);
    assert.equal(result.proposal.changes[0].newContent, "pub const value: usize = 2;\n");
    assert.match(result.regression.path, /^tests\/ai-review-[a-f0-9]{16}-aaaaaaaaaaaa\.rs$/);
    assert.equal(result.proposal.changes[1].originalBlobSha, null);
    assert.equal(result.regression.testName, "value_returns_two");
});

for (const [name, mutate] of [
    [
        "stale source blob",
        (value) => {
            value.sources.get("src/value.rs").sha = "b".repeat(40);
        },
    ],
    [
        "forged source contents",
        (value) => {
            value.sources.get("src/value.rs").content = "pub const value: usize = 9;\n";
        },
    ],
    [
        "wrong source quote",
        (value) => {
            value.review.candidates[0].evidence[0].quote = "not real source";
        },
    ],
    [
        "ambiguous replacement",
        (value) => {
            value.review.candidates[0].proposedFix.edits[0].oldText = " ";
        },
    ],
    [
        "workflow edit",
        (value) => {
            value.review.candidates[0].proposedFix.edits[0].path = ".github/workflows/ci.yml";
        },
    ],
    [
        "existing test edit",
        (value) => {
            value.review.candidates[0].proposedFix.edits[0].path = "tests/unit/existing.test.mjs";
        },
    ],
    [
        "symlink source",
        (value) => {
            value.sources.get("src/value.rs").mode = "120000";
        },
    ],
    [
        "unbound source evidence",
        (value) => {
            value.input.changedPaths = ["shared/other.mjs"];
        },
    ],
    [
        "missing regression name",
        (value) => {
            value.review.candidates[0].proposedFix.regressionTest.expectedTestName =
                "different case";
        },
    ],
    [
        "null repair",
        (value) => {
            value.review.candidates[0].proposedFix = null;
        },
    ],
]) {
    test(`candidate adapter rejects ${String(name)}`, () => {
        const input = fixture();
        mutate(input);
        assert.throws(() => adaptReviewCandidate(input));
    });
}

test("candidate Git source collection validates actual Git blob identity", async () => {
    const github = {
        async request(method, route) {
            assert.equal(method, "GET");

            if (route.endsWith(`/git/commits/${sha}`)) return { tree: { sha: "b".repeat(40) } };

            if (route.includes("/git/trees/"))
                return {
                    truncated: false,
                    tree: [{ path: "src/value.rs", sha: blobSha, mode: "100644", type: "blob" }],
                };

            return { encoding: "base64", content: Buffer.from(content).toString("base64") };
        },
    };

    const sources = await collectCandidateSources({ github, sha, paths: ["src/value.rs"] });
    assert.equal(sources.get("src/value.rs")?.content, content);
});

const testName = "value_returns_two";
const rustSource = "#[test]\nfn value_returns_two() {\n    assert_eq!(1, 2);\n}\n";
const failure = () => ({
    stdout: `running 1 test\ntest ${testName} ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`,
    stderr: `thread '${testName}' panicked at tests/ai-review-case.rs:3:5:\nassertion \`left == right\` failed\n  left: 1\n right: 2\n`,
    exitCode: 101,
    testName,
    file: "tests/ai-review-case.rs",
    source: rustSource,
    catalog: parseRustCatalog(`${testName}: test\n`, testName),
});
test("Rust admission identifies the actual named source assertion failure", () => {
    const result = parseRustExecution(failure());
    assert.equal(result.failures, 1);
    assert.match(result.assertionFailure, /left == right/);
    assert.equal(result.assertionLine, 3);
});
test("Rust admission counts a passing intact case", () => {
    const input = failure();
    input.stdout = `running 1 test\ntest ${testName} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`;
    input.stderr = "";
    input.exitCode = 0;
    const result = parseRustExecution(input);
    assert.equal(result.tests, 1);
    assert.equal(result.failures, 0);
});
for (const [name, change] of [
    ["setup exception", { stderr: "could not load shared library" }],
    ["unrelated assertion", { testName: "different_case" }],
    ["skipped case", { stdout: "running 1 test\ntest value_returns_two ... ignored\n" }],
    ["missing test cases", { stdout: "running 0 tests\n" }],
    ["nonzero result without failure", { exitCode: 1 }],
    [
        "foreign XML report injection",
        { stdout: '<!DOCTYPE test [<!ENTITY x "fake">]><testsuites tests="1"/>' },
    ],
])
    test(`Rust admission rejects ${name}`, () => {
        assert.throws(() => parseRustExecution({ ...failure(), ...change }));
    });

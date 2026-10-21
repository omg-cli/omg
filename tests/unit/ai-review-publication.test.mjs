import test from "node:test";
import { Schema } from "effect";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
    admitPublication,
    publicationBodies,
    findPublication,
    findingKey,
    publishAiReview,
} from "../../scripts/ai-review-publication.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");

const canonical = (value) =>
    JSON.stringify(value, (_, item) =>
        Schema.is(Schema.Record(Schema.String, Schema.Unknown))(item)
            ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)))
            : item,
    );

const baseSha = "a".repeat(40);
const originalBlobSha = "b".repeat(40);
const verifierRevision = "c".repeat(40);
const source = "pub const value: usize = 1;\n";
const key = sha(`src/value.rs\0${source.trim()}`);

function fixture() {
    const proposal = {
        repository: "omg-cli/omg",
        branch: "main",
        baseSha,
        finding: {
            key,
            title: "Value is incorrect",
            summary: "The exported value is incorrect.",
            path: "src/value.rs",
            line: 1,
            sourceQuote: source.trim(),
            reproduction: "Calling value returns 1 instead of 2.",
        },
        changes: [
            {
                path: "src/value.rs",
                originalBlobSha,
                oldContentQuote: source.trim(),
                newContent: "pub const value: usize = 2;\n",
                sha256: sha("pub const value: usize = 2;\n"),
            },
        ],
    };

    const receipt = {
        repository: proposal.repository,
        branch: proposal.branch,
        baseSha,
        proposalSha256: sha(canonical(proposal)),
        verifierRevision,
        runId: 42,
        runAttempt: 1,
        baseline: {
            testName: "value_returns_two",
            exitCode: 101,
            tests: 1,
            failures: 1,
            errors: 0,
            skipped: 0,
            assertionFailure: "Expected 2, received 1",
            assertionFile: "src/value.rs",
            assertionLine: 1,
            assertionSourceSha256: sha(source.split("\n")[0]),
            reportSha256: "d".repeat(64),
            stdoutSha256: "f".repeat(64),
            stderrSha256: "f".repeat(64),
            catalogSha256: "f".repeat(64),
            executableSha256: "f".repeat(64),
            compilerMessagesSha256: "f".repeat(64),
            sourceSha256: "f".repeat(64),
            recipeSha256: "f".repeat(64),
        },
        patched: {
            testName: "value_returns_two",
            exitCode: 0,
            tests: 1,
            failures: 0,
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
        },
        portableChecks: [{ name: "portable-ci", exitCode: 0, reportSha256: "f".repeat(64) }],
        protectedPathsUnchanged: true,
    };

    return {
        proposal,
        receipt,
        verifierRevision,
        requiredChecks: ["portable-ci"],
        sources: new Map([
            ["src/value.rs", { sha: originalBlobSha, mode: "100644", content: source }],
        ]),
    };
}

test("verified publication retains exact identity and produces a deterministic isolated fix branch", () => {
    const result = admitPublication(fixture());
    assert.equal(result.headBranch, `ai-fix/${key.slice(0, 16)}-${baseSha.slice(0, 12)}`);
    assert.equal(result.proposal.baseSha, baseSha);
});

for (const [name, mutate] of [
    [
        "non-libtest baseline failure",
        (input) => {
            input.receipt.baseline.exitCode = 1;
        },
    ],
    [
        "changed regression recipe",
        (input) => {
            input.receipt.patched.recipeSha256 = "0".repeat(64);
        },
    ],
    [
        "changed regression source",
        (input) => {
            input.receipt.patched.sourceSha256 = "0".repeat(64);
        },
    ],
    [
        "missing compiler artifact identity",
        (input) => {
            delete input.receipt.baseline.executableSha256;
        },
    ],
    [
        "unjoined assertion source",
        (input) => {
            input.receipt.baseline.assertionSourceSha256 = "0".repeat(64);
        },
    ],

    [
        "wrong repository",
        (input) => {
            input.proposal.repository = "other/repo";
        },
    ],
    [
        "wrong branch",
        (input) => {
            input.proposal.branch = "attacker";
        },
    ],
    [
        "stale receipt SHA",
        (input) => {
            input.receipt.baseSha = "9".repeat(40);
        },
    ],
    [
        "different proposal digest",
        (input) => {
            input.receipt.proposalSha256 = "0".repeat(64);
        },
    ],
    [
        "different verifier",
        (input) => {
            input.receipt.verifierRevision = "9".repeat(40);
        },
    ],
    [
        "setup failure instead of assertion",
        (input) => {
            input.receipt.baseline.errors = 1;
        },
    ],
    [
        "no observed assertion",
        (input) => {
            input.receipt.baseline.assertionFailure = "";
        },
    ],
    [
        "different patched regression",
        (input) => {
            input.receipt.patched.testName = "unrelated test";
        },
    ],
    [
        "skipped patched test",
        (input) => {
            input.receipt.patched.skipped = 1;
        },
    ],
    [
        "failed portable check",
        (input) => {
            input.receipt.portableChecks[0].exitCode = 1;
        },
    ],
    [
        "missing portable check",
        (input) => {
            input.receipt.portableChecks = [];
        },
    ],
    [
        "changed protected paths",
        (input) => {
            input.receipt.protectedPathsUnchanged = false;
        },
    ],
    [
        "wrong original blob",
        (input) => {
            input.sources.get("src/value.rs").sha = "9".repeat(40);
        },
    ],
    [
        "wrong old content",
        (input) => {
            input.proposal.changes[0].oldContentQuote = "not the original";
        },
    ],
    [
        "symlink source",
        (input) => {
            input.sources.get("src/value.rs").mode = "120000";
        },
    ],
    [
        "incorrect new content hash",
        (input) => {
            input.proposal.changes[0].sha256 = "0".repeat(64);
        },
    ],
    [
        "workflow modification",
        (input) => {
            input.proposal.changes[0].path = ".github/workflows/ci.yml";
        },
    ],
    [
        "source traversal",
        (input) => {
            input.proposal.changes[0].path = "src/../src/value.rs";
        },
    ],
    [
        "existing test modification",
        (input) => {
            input.proposal.changes[0].path = "tests/ai-review-existing.rs";
        },
    ],
    [
        "wrong source line",
        (input) => {
            input.proposal.finding.line = 2;
        },
    ],
]) {
    test(`publication refuses ${String(name)} before trusting proof`, () => {
        const input = fixture();
        mutate(input);

        if (name !== "different proposal digest")
            input.receipt.proposalSha256 = sha(canonical(input.proposal));
        assert.throws(() => admitPublication(input));
    });
}

test("publication bodies identify unconfirmed findings and captured regression reports", () => {
    const body = publicationBodies(admitPublication(fixture()));
    assert.match(body.issue, /Expected 2, received 1/);
    assert.match(body.issue, /src\/value\.rs#L1/);
    assert.match(body.issue, /actions\/runs\/42\/attempts\/1/);
    assert.match(body.pullRequest, /Proposed fix/);
    assert.match(body.pullRequest, /dddddddddddddddd/);
    assert.match(body.issue, /Unconfirmed AI finding/);
    assert.match(body.issue, /Model-proposed reproduction \(unconfirmed\)/);
    assert.match(
        body.issue,
        /Captured baseline process result: exit 101; report lists 1 test, 1 failure, 0 errors, 0 skipped/,
    );
    assert.match(
        body.issue,
        /Captured patched process result: exit 0; report lists 1 test, 0 failures, 0 errors, 0 skipped/,
    );
    assert.match(body.issue, /Generated test semantics and the proposed fix require independent review/);
    assert.match(
        body.issue,
        /Hashes identify captured bytes; they do not confirm the reported bug/,
    );
    assert.match(body.issue, /No automatic merge or deployment/);
    assert.match(body.pullRequest, /Windows\/native acceptance remains unproven/);
});

test("deduplication respects closed bot records and ignores human marker spoofing", () => {
    const records = [
        { number: 1, body: "<!-- ai-review:key -->", user: { login: "human" }, state: "open" },
        {
            number: 2,
            body: "<!-- ai-review:key -->",
            user: { login: "github-actions[bot]", id: 41898282 },
            state: "closed",
        },
    ];

    assert.equal(findPublication(records, "<!-- ai-review:key -->").number, 2);
});

function githubFixture() {
    const writes = [];
    const state = {
        head: baseSha,
        issues: [],
        pulls: [],
        branch: null,
        author: { login: "github-actions[bot]", id: 41898282 },
        pullAuthor: null,
    };

    const github = {
        async request(method, route, body) {
            if (method !== "GET") {
                writes.push({ method, route, body });

                if (route.endsWith("/issues"))
                    return {
                        number: 7,
                        html_url: "https://github.com/omg-cli/omg/issues/7",
                        user: state.author,
                    };

                if (route.endsWith("/pulls"))
                    return {
                        number: 8,
                        html_url: "https://github.com/omg-cli/omg/pull/8",
                        user: state.pullAuthor ?? state.author,
                    };

                return { sha: "8".repeat(40) };
            }

            if (route.includes("/git/ref/heads/ai-fix/")) return state.branch;

            if (route.endsWith("/git/ref/heads/main")) return { object: { sha: state.head } };

            if (route.endsWith(`/git/commits/${baseSha}`)) return { tree: { sha: "7".repeat(40) } };

            if (route.includes("/git/trees/"))
                return {
                    truncated: false,
                    tree: [
                        {
                            path: "src/value.rs",
                            type: "blob",
                            mode: "100644",
                            sha: originalBlobSha,
                        },
                    ],
                };

            if (route.endsWith(`/git/blobs/${originalBlobSha}`))
                return { encoding: "base64", content: Buffer.from(source).toString("base64") };

            if (route.includes("/issues?")) return state.issues;

            if (route.includes("/pulls?")) return state.pulls;
            throw Error(`Unexpected fixture request ${method} ${route}`);
        },
    };

    return { github, writes, state };
}

test("dry run reads admission evidence and returns reviewable bodies without writes", async () => {
    const connection = githubFixture();
    const result = await publishAiReview({ ...fixture(), ...connection });
    assert.equal(result.action, "dry-run");
    assert.match(result.bodies.issue, /Value is incorrect|exported value/);
    assert.equal(connection.writes.length, 0);
});

test("publication creates only a scoped tree, new ref, issue and regular PR", async () => {
    const connection = githubFixture();
    const result = await publishAiReview({ ...fixture(), ...connection, publish: true });
    assert.equal(result.action, "published");
    const pr = connection.writes.find((item) => item.route.endsWith("/pulls"));
    assert.equal(pr.body.draft, false);
    assert.equal(pr.body.title, "[Unconfirmed AI repair] Value is incorrect");
    assert.equal(
        connection.writes.find((item) => item.route.endsWith("/issues")).body.title,
        "[Unconfirmed AI finding] Value is incorrect",
    );
    assert.equal(pr.body.base, "main");
    const tree = connection.writes.find((item) => item.route.endsWith("/git/trees"));
    assert.deepEqual(
        tree.body.tree.map(({ path, mode, type }) => ({ path, mode, type })),
        [{ path: "src/value.rs", mode: "100644", type: "blob" }],
    );
    assert.equal(
        connection.writes.some(
            (item) => item.method === "PATCH" || /merge|reviews/.test(item.route),
        ),
        false,
    );
});

test("stale target is rejected without publication", async () => {
    const connection = githubFixture();
    connection.state.head = "9".repeat(40);
    await assert.rejects(publishAiReview({ ...fixture(), ...connection, publish: true }), /stale/i);
    assert.equal(connection.writes.length, 0);
});

test("closed prior issue blocks replay without reopening or publishing", async () => {
    const connection = githubFixture();
    connection.state.issues = [
        {
            number: 7,
            state: "closed",
            body: `<!-- ai-review:${key} -->`,
            user: { login: "github-actions[bot]", id: 41898282 },
        },
    ];
    const result = await publishAiReview({ ...fixture(), ...connection, publish: true });
    assert.equal(result.action, "closed");
    assert.equal(connection.writes.length, 0);
});

test("interrupted publication resumes an identical owned branch without another ref", async () => {
    const connection = githubFixture();
    connection.state.branch = { object: { sha: "8".repeat(40) } };
    connection.state.issues = [
        {
            number: 7,
            state: "open",
            html_url: "https://github.com/omg-cli/omg/issues/7",
            body: `<!-- ai-review:${key} -->`,
            user: { login: "github-actions[bot]", id: 41898282 },
        },
    ];
    const request = connection.github.request.bind(connection.github);
    connection.github.request = async (method, route, body) => {
        if (method === "GET" && route.endsWith(`/git/commits/${"8".repeat(40)}`))
            return {
                parents: [{ sha: baseSha }],
                tree: { sha: "6".repeat(40) },
                message: `AI review ${key}\nProposal ${fixture().receipt.proposalSha256}`,
            };

        if (method === "GET" && route.includes(`/git/trees/${"6".repeat(40)}`))
            return {
                truncated: false,
                tree: [{ path: "src/value.rs", type: "blob", mode: "100644", sha: "5".repeat(40) }],
            };

        if (method === "GET" && route.endsWith(`/git/blobs/${"5".repeat(40)}`))
            return {
                encoding: "base64",
                content: Buffer.from("pub const value: usize = 2;\n").toString("base64"),
            };

        return request(method, route, body);
    };

    const result = await publishAiReview({ ...fixture(), ...connection, publish: true }).catch(
        (error) => ({ action: "rejected", reason: error.message }),
    );

    assert.equal(result.action, "published");
    assert.deepEqual(
        connection.writes.map((item) => item.route),
        ["/repos/omg-cli/omg/pulls"],
    );
});

test("an existing unrecognized fix branch is never overwritten", async () => {
    const connection = githubFixture();
    connection.state.branch = { object: { sha: "8".repeat(40) } };
    const request = connection.github.request.bind(connection.github);
    connection.github.request = async (method, route, body) => {
        if (method === "GET" && route.endsWith(`/git/commits/${"8".repeat(40)}`))
            return {
                parents: [{ sha: baseSha }],
                tree: { sha: "6".repeat(40) },
                message: "Human change",
            };

        return request(method, route, body);
    };

    await assert.rejects(
        publishAiReview({ ...fixture(), ...connection, publish: true }),
        /existing branch/i,
    );
    assert.equal(connection.writes.length, 0);
});

test("model wording changes cannot create another source finding", () => {
    const item = fixture().proposal.finding;
    assert.equal(
        findingKey({ ...item, reproduction: "The model rephrased the same reproduction." }),
        findingKey(item),
    );
});

test("embedded publication markers cannot spoof another finding", () => {
    const found = findPublication(
        [
            {
                number: 7,
                state: "open",
                body: "Untrusted explanation\n<!-- ai-review:key -->",
                user: { login: "github-actions[bot]", id: 41898282 },
            },
        ],
        "<!-- ai-review:key -->",
    );

    assert.equal(found, undefined);
    assert.equal(
        findPublication(
            [
                {
                    number: 8,
                    state: "open",
                    body: "<!-- ai-review:key -->\nEvidence",
                    user: { login: "github-actions[bot]", id: 41898282 },
                },
            ],
            "<!-- ai-review:key -->",
        ).number,
        8,
    );
});

test("a closed repair on an earlier base is respected instead of opening another PR", async () => {
    const connection = githubFixture();
    connection.state.pulls = [
        {
            number: 8,
            state: "closed",
            body: `<!-- ai-review-patch:${key}:main:${"9".repeat(40)} -->`,
            user: { login: "github-actions[bot]", id: 41898282 },
        },
    ];
    const result = await publishAiReview({ ...fixture(), ...connection, publish: true });
    assert.equal(result.action, "closed");
    assert.equal(connection.writes.length, 0);
});

test("publication preserves existing inline Rust tests and conditional attributes", () => {
    const original =
        "pub const value: usize = 1;\n#[cfg(test)]\nmod tests { #[test] fn existing() { assert_eq!(super::value, 1); } }\n";
    for (const replacement of [
        original.replace("assert_eq!(super::value, 1)", "assert!(true)"),
        original.split("#[cfg(test)]")[0],
        original.replace("#[cfg(test)]", "#[cfg(any())]\n#[cfg(test)]"),
    ]) {
        const input = fixture();
        input.sources.get("src/value.rs").content = original;
        input.receipt.baseline.assertionSourceSha256 = sha(original.split("\n")[0]);
        input.proposal.changes[0].newContent = replacement;
        input.proposal.changes[0].sha256 = sha(replacement);
        input.receipt.proposalSha256 = sha(canonical(input.proposal));
        assert.throws(() => admitPublication(input), /existing Rust tests|conditional attributes/);
    }
    const input = fixture();
    input.sources.get("src/value.rs").content = original;
    input.receipt.baseline.assertionSourceSha256 = sha(original.split("\n")[0]);
    input.proposal.changes[0].newContent = original.replace("value: usize = 1", "value: usize = 2");
    input.proposal.changes[0].sha256 = sha(input.proposal.changes[0].newContent);
    input.receipt.proposalSha256 = sha(canonical(input.proposal));
    assert.equal(admitPublication(input).proposal.changes.length, 1);
});

async function withPublisherIdentity(login, id, operation) {
    const keys = ["OMG_CI_PUBLISHER_LOGIN", "OMG_CI_PUBLISHER_ID"];
    const previous = keys.map((key) => process.env[key]);
    for (const [index, value] of [login, id].entries()) {
        if (value === undefined) delete process.env[keys[index]];
        else process.env[keys[index]] = value;
    }
    try {
        return await operation();
    } finally {
        keys.forEach((key, index) => {
            if (previous[index] === undefined) delete process.env[key];
            else process.env[key] = previous[index];
        });
    }
}

test("deduplication rejects the same login with the wrong numeric GitHub actor ID", () => {
    assert.equal(
        findPublication(
            [
                {
                    body: "<!-- ai-review:key -->",
                    user: { login: "github-actions[bot]", id: 7 },
                },
            ],
            "<!-- ai-review:key -->",
        ),
        undefined,
    );
});

test("explicit trusted App identity replays its own open and closed publications without writes", async () => {
    await withPublisherIdentity("omg-repair[bot]", "123456", async () => {
        for (const state of ["open", "closed"]) {
            const connection = githubFixture();
            const user = { login: "omg-repair[bot]", id: 123456 };
            connection.state.issues = [
                { number: 7, state, user, body: `<!-- ai-review:${key} -->` },
            ];
            connection.state.pulls = [
                { number: 8, state, user, body: `<!-- ai-review-patch:${key}:main:${baseSha} -->` },
            ];
            const result = await publishAiReview({ ...fixture(), ...connection, publish: true });
            assert.equal(result.action, state === "closed" ? "closed" : "existing");
            assert.equal(connection.writes.length, 0);
        }
    });
});

test("partial or invalid trusted actor configuration fails before writes", async () => {
    for (const [login, id] of [
        ["omg-repair[bot]", undefined],
        [undefined, "123456"],
        ["bad\nactor", "123456"],
        ["omg-repair[bot]", "0"],
        ["omg-repair[bot]", "1.5"],
        ["omg-repair[bot]", "9007199254740992"],
    ]) {
        await withPublisherIdentity(login, id, async () => {
            const connection = githubFixture();
            await assert.rejects(
                publishAiReview({ ...fixture(), ...connection, publish: true }),
                /publisher.*identity/i,
            );
            assert.equal(connection.writes.length, 0);
        });
    }
});

test("actual issue response author must match both trusted fields before subsequent writes", async () => {
    await withPublisherIdentity("omg-repair[bot]", "123456", async () => {
        for (const author of [
            { login: "omg-repair[bot]", id: 7 },
            { login: "other[bot]", id: 123456 },
        ]) {
            const connection = githubFixture();
            connection.state.author = author;
            await assert.rejects(
                publishAiReview({ ...fixture(), ...connection, publish: true }),
                /publisher.*identity/i,
            );
            assert.deepEqual(
                connection.writes.map((entry) => entry.route),
                ["/repos/omg-cli/omg/issues"],
            );
        }
    });
});

test("an App publication is accepted only with actual matching issue and PR response authors", async () => {
    await withPublisherIdentity("omg-repair[bot]", "123456", async () => {
        const connection = githubFixture();
        connection.state.author = { login: "omg-repair[bot]", id: 123456 };
        assert.equal(
            (await publishAiReview({ ...fixture(), ...connection, publish: true })).action,
            "published",
        );
        const wrongPull = githubFixture();
        wrongPull.state.author = connection.state.author;
        wrongPull.state.pullAuthor = { login: "omg-repair[bot]", id: 7 };
        await assert.rejects(
            publishAiReview({ ...fixture(), ...wrongPull, publish: true }),
            /publisher.*identity/i,
        );
    });
});

test("model proposal fields cannot choose the trusted publication actor", async () => {
    await withPublisherIdentity(undefined, undefined, async () => {
        const connection = githubFixture();
        connection.state.author = { login: "omg-repair[bot]", id: 123456 };
        await assert.rejects(
            publishAiReview({
                ...fixture(),
                ...connection,
                publish: true,
                publisherAuthor: connection.state.author,
            }),
            /publisher.*identity/i,
        );
    });
});

test("only the trusted publisher job supplies the explicit actor policy", () => {
    const workflow = Bun.YAML.parse(
        readFileSync(new URL("../../.github/workflows/ai-review.yml", import.meta.url), "utf8"),
    );
    assert.deepEqual(workflow.jobs.publish.env, {
        OMG_CI_PUBLISHER_LOGIN: "${{ vars.OMG_CI_PUBLISHER_LOGIN }}",
        OMG_CI_PUBLISHER_ID: "${{ vars.OMG_CI_PUBLISHER_ID }}",
    });
    assert.equal(workflow.jobs.review.env?.OMG_CI_PUBLISHER_LOGIN, undefined);
    assert.equal(workflow.jobs.review.env?.OMG_CI_PUBLISHER_ID, undefined);
    assert.equal(workflow.on.workflow_dispatch.inputs.publish.default, false);
});

import assert from "node:assert/strict";
import { test } from "bun:test";
import { Session } from "@opencode/schema/session";
import { createCodingActions, type CodingState } from "../src/tools";
import { createRequiredSkillsPlugin } from "../src/skills";
import { parseCodingRequest } from "../src/request";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";

async function fixture(deliver = true) {
    const content =
        "// fixture line\n".repeat(1700) +
        "#[test]\nfn selected_case() { assert_eq!(value(), 1); }\n" +
        "pub fn value() -> u32 { 1 }\n".repeat(25);
    const sha = "a".repeat(40),
        path = "src/fixture.rs",
        blobSha = gitBlobSha(content);
    const request = parseCodingRequest({
        repository: "omg-cli/omg",
        sha,
        branch: "main",
        runId: "44",
        attempt: "1",
        source: {
            repository: "omg-cli/omg",
            sha,
            branch: "main",
            changedPaths: [],
            auditPaths: [path],
            diff: "",
            sourceFiles: [{ path, blobSha, content }],
            ciFailures: [],
        },
        testAuditTask: {
            path,
            target: "lib",
            testName: "module::selected_case",
            originalBlobSha: blobSha,
        },
    });
    const skills = await createRequiredSkillsPlugin(),
        sessionID = Session.ID.create();
    if (deliver) skills.contextHook({ sessionID, system: [] });
    let state: CodingState = { calls: 0, reads: [], verifiedDigests: [] };
    const actions = createCodingActions({
        getRequest: async () => request,
        skills,
        update: async (change) => (state = change(state)),
        env: {
            CI_API_TOKEN: "x".repeat(32),
            CI_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`,
            CI_VERIFIER_REVISION: "c".repeat(40),
            CI_SERVICE: {
                fetch: async () => {
                    throw new Error("Navigation must not execute verification");
                },
            },
        },
    });
    return {
        actions,
        request,
        context: { sessionID, signal: new AbortController().signal },
        state: () => state,
    };
}

test("recovered audit context locates the exact selected test without scanning the file", async () => {
    const f = await fixture();
    const context = JSON.parse(
        (await f.actions.read_context.execute({}, f.context)).content,
    );
    assert.deepEqual(context.testAuditTask, f.request.testAuditTask);
    assert.deepEqual(context.testWindows, [
        { path: "src/fixture.rs", start: 1692, lines: 37 },
    ]);
    const files = JSON.parse(
        (await f.actions.list_sources.execute({}, f.context)).content,
    ).files;
    assert.equal(files[0].lines, 1728);
    const read = JSON.parse(
        (await f.actions.read_source.execute(context.testWindows[0], f.context))
            .content,
    );
    assert.ok(read.content.includes("fn selected_case()"));
    assert.equal(f.state().calls, 3);
    assert.equal(f.state().reads.length, 1);
});

test("literal source search is skill-gated, bounded and grants no fabricated read evidence", async () => {
    const f = await fixture(false);
    assert.equal(typeof f.actions.find_source, "object");
    await assert.rejects(
        f.actions.find_source.execute(
            { path: "src/fixture.rs", needle: "fn selected_case(" },
            f.context,
        ),
    );
    const valid = await fixture();
    const match = JSON.parse(
        (
            await valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle: "fn selected_case(" },
                valid.context,
            )
        ).content,
    );
    assert.deepEqual(match, {
        path: "src/fixture.rs",
        lines: 1728,
        totalMatches: 1,
        matches: [1702],
    });
    const many = JSON.parse(
        (
            await valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle: "pub fn value()" },
                valid.context,
            )
        ).content,
    );
    assert.equal(many.matches.length, 20);
    assert.equal(many.totalMatches, 25);
    const literal = JSON.parse(
        (
            await valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle: ".*" },
                valid.context,
            )
        ).content,
    );
    assert.deepEqual(literal.matches, []);
    await assert.rejects(
        valid.actions.find_source.execute(
            { path: "../secret", needle: "value" },
            valid.context,
        ),
    );
    for (const needle of ["", "x\ny", "x".repeat(201)])
        await assert.rejects(
            valid.actions.find_source.execute(
                { path: "src/fixture.rs", needle },
                valid.context,
            ),
        );
    assert.equal(valid.state().reads.length, 0);
});

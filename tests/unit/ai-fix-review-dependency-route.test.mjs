import test from "node:test";
import assert from "node:assert/strict";
import { reviewAiFix, dependencyRepairPublication } from "../../scripts/ai-fix-review.mjs";

function dependencyFixture() {
    const base = "38f9a30d7d246cd1dcfc8d6dd266259acad24082";
    const head = "9555dc49ca7a0fbdf32dc912ca75a626a8a8dad7";
    const plan = "f4b8ccbd88316f861bb0c287a2f342629c6197e0cb529c4b17ab045613ac1952";
    const pull = {
        number: 983, state: "open", draft: false,
        title: "fix(deps): cloud-generated dependency audit repairs",
        user: { login: "omg-ci-publisher[bot]", id: 345568822 },
        body: [
            "Cloudflare OpenCode selected these updates using the mandatory Potato, Ponytail, Rust and TDD skill bundle. The separate hosted verifier applied Cargo's exact resolution; the model had no GitHub write credential.",
            "- ctutils: 0.4.2 to 0.4.4",
            "",
            "Evidence: https://github.com/omg-cli/omg/actions/runs/39959925030",
            "Cloud operation: cl-39959925030-1-38f9a30d7d246cd1dcfc8d6dd266259acad24082-s-80b89c330bf3483022949c4535a8ab3aa31a617c72d915f70a78c31c1978f404",
            "Advisory database: f7b2f6bc663452200bbe639ebb75e0c762b3422b",
            `Plan SHA256: ${plan}`,
            "",
            "Executed: real baseline audit failure, patched audit with zero findings against the same database, cargo metadata --locked, and all existing cargo-deny policy checks. Only Cargo.lock changes. Native, QEMU, coverage and all normal PR checks still must pass. This dependency proof is not Rust test sensitivity credit. Human review and merge remain required.",
        ].join("\n"),
        base: { ref: "main", sha: base, repo: { full_name: "omg-cli/omg" } },
        head: { ref: `ai/dependencies-${base.slice(0, 12)}-${plan.slice(0, 12)}`, sha: head, repo: { full_name: "omg-cli/omg" } },
    };
    const state = { posts: [], saved: [], routes: [] };
    const github = { async request(method, route, data) {
        state.routes.push(route);
        if (method === "POST") state.posts.push({ route, data });
        if (method === "GET" && route.endsWith("/pulls/983")) return structuredClone(pull);
        if (method === "GET" && route.includes("/check-runs?")) return { check_runs: [] };
        throw new Error(`Unexpected GitHub route ${route}`);
    } };
    const services = {
        ciJson: async () => { throw new Error("dependency lane must not read generic proof"); },
        ciRaw: async () => { throw new Error("dependency lane must not read raw proof"); },
        inspectPatch: async () => { throw new Error("dependency lane must not request a patch verdict"); },
        admitQemu: async () => { throw new Error("dependency lane must not admit QEMU"); },
        saveReview: async (record) => { state.saved.push(record); },
    };
    return { github, services, number: 983, expectedHead: head, publisher: pull.user,
        policy: {}, approve: true, state, pull };
}

test("dependency lock repair PR983 is explicitly unsupported, never generic Rust review, and never approved", async () => {
    const input = dependencyFixture();
    const result = await reviewAiFix(input);
    assert.deepEqual(result, {
        action: "unsupported",
        publication: "dependency-lock-repair",
        number: 983,
        headSha: input.expectedHead,
        reason: "Dependency lock repair uses its separate verified audit evidence contract; this lane records no approval. Human review and merge remain required.",
    });
    assert.deepEqual(input.state.routes, ["/repos/omg-cli/omg/pulls/983"]);
    assert.equal(input.state.posts.length, 0);
    assert.equal(input.state.saved.length, 0);
});

test("dependency class predicate binds the exact branch, plan digest, publisher and head", () => {
    const input = dependencyFixture();
    assert.equal(dependencyRepairPublication(input.pull, input.publisher, input.expectedHead), true);
    assert.equal(dependencyRepairPublication({ ...input.pull, head: { ...input.pull.head, sha: "9".repeat(40) } },
        input.publisher, input.expectedHead), false);
    assert.equal(dependencyRepairPublication({ ...input.pull, body: `<!-- ai-review-patch:${"a".repeat(64)}:main:${input.pull.base.sha} -->\n${input.pull.body}` },
        input.publisher, input.expectedHead), false);
    assert.equal(dependencyRepairPublication({ ...input.pull, body: `Proof purpose: existing-test-strengthening\n${input.pull.body}` },
        input.publisher, input.expectedHead), false);
});

for (const [name, mutate] of [
    ["missing plan digest", (pull) => { pull.body = pull.body.replace(/^Plan SHA256: .*$/m, ""); }],
    ["plan digest not bound to branch", (pull) => { pull.body = pull.body.replace(/^Plan SHA256: .*$/m, `Plan SHA256: ${"0".repeat(64)}`); }],
    ["head moved", (pull) => { pull.head.sha = "9".repeat(40); }],
    ["title changed", (pull) => { pull.title = "fix: unrelated"; }],
    ["generic marker added", (pull) => { pull.body = `<!-- ai-review-patch:${"a".repeat(64)}:main:${pull.base.sha} -->\n${pull.body}`; }],
    ["test-audit marker added", (pull) => { pull.body = `Proof purpose: existing-test-strengthening\n${pull.body}`; }],
    ["different publisher", (pull) => { pull.user = { login: "attacker", id: 1 }; }],
]) test(`dependency lookalike ${name} still rejects without approval or write`, async () => {
    const input = dependencyFixture();
    mutate(input.pull);
    await assert.rejects(reviewAiFix(input));
    assert.equal(input.state.posts.length, 0);
    assert.equal(input.state.saved.length, 0);
});

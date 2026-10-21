import test from "node:test";
import assert from "node:assert/strict";
import { decideAiFixReview } from "../../scripts/ai-fix-review.mjs";
import { admitPublishedTree, gitBlobSha } from "../../scripts/ai-fix-review.mjs";

const head = "a".repeat(40);
const base = "b".repeat(40);
const key = "c".repeat(64);
const repository = { full_name: "omg-cli/omg" };
const names = ["CI Success", "Instrumented coverage tests", "Generate Coverage Report", "Orchestration tests, types and dry builds", "QEMU behavioral verification / QEMU matrix result"];
function fixture() {
    return {
        expectedHead: head,
        publisher: { login: "omg-ci-publisher[bot]", id: 345568822 },
        pull: {
            state: "open", draft: false, number: 42,
            user: { login: "omg-ci-publisher[bot]", id: 345568822 },
            base: { ref: "main", sha: base, repo: repository },
            head: { ref: `ai-fix/${key.slice(0, 16)}-${base.slice(0, 12)}`, sha: head, repo: repository },
            body: `<!-- ai-review-patch:${key}:main:${base} -->\n\nProposal SHA-256: ${"d".repeat(64)}\n\nReceipt SHA-256: ${"e".repeat(64)}`,
        },
        checks: names.map((name) => ({ name, head_sha: head, status: "completed", conclusion: "success", app: { id: 15368, slug: "github-actions" } })),
    };
}

test("green App-authored PR still cannot approve without independent semantic and raw proof admission", () => {
    const decision = decideAiFixReview(fixture());
    assert.equal(decision.action, "blocked");
    assert.match(decision.reason, /independent.*proof/i);
});

for (const [name, mutate] of [
    ["old event head", (x) => { x.expectedHead = base; }],
    ["lookalike author login", (x) => { x.pull.user.login = "impostor[bot]"; }],
    ["lookalike author id", (x) => { x.pull.user.id = 1; }],
    ["Actions self author", (x) => { x.pull.user = { login: "github-actions[bot]", id: 41898282 }; x.publisher = x.pull.user; }],
    ["fork repository", (x) => { x.pull.head.repo = { full_name: "attacker/omg" }; }],
    ["nonpublication branch", (x) => { x.pull.head.ref = "ai-fix/anything"; }],
    ["forged base marker", (x) => { x.pull.body = x.pull.body.replace(base, head); }],
    ["missing proposal digest", (x) => { x.pull.body = x.pull.body.replace(/Proposal SHA-256:.*/, ""); }],
    ["missing receipt digest", (x) => { x.pull.body = x.pull.body.replace(/Receipt SHA-256:.*/, ""); }],
    ["missing coverage", (x) => { x.checks.splice(1, 1); }],
    ["stale check head", (x) => { x.checks[0].head_sha = base; }],
    ["skipped QEMU", (x) => { x.checks[4].conclusion = "skipped"; }],
    ["spoofed check producer", (x) => { x.checks[0].app.id = 1; }],
    ["ambiguous duplicate checks", (x) => { x.checks.push(x.checks[0]); }],
]) {
    test(`rejects ${name}`, () => {
        const input = fixture();
        mutate(input);
        assert.equal(decideAiFixReview(input).action, "reject");
    });
}

test("an old approval never admits a replacement harmful head", () => {
    const input = fixture();
    input.pull.head.sha = "f".repeat(40);
    input.reviews = [{ state: "APPROVED", commit_id: head }];
    assert.equal(decideAiFixReview(input).action, "reject");
});

function treeFixture() {
    const content = "pub const VALUE: u8 = 2;\n";
    const original = { path: "src/value.rs", mode: "100644", type: "blob", sha: base };
    const untouched = { path: "tests/value.rs", mode: "100644", type: "blob", sha: "1".repeat(40) };
    return {
        proposal: { changes: [{ path: original.path, originalBlobSha: base, newContent: content }] },
        baseTree: { truncated: false, tree: [original, untouched] },
        headTree: { truncated: false, tree: [{ ...original, sha: gitBlobSha(content) }, untouched] },
    };
}

test("published tree admits exactly the verified patch and unchanged tests", () => {
    assert.equal(admitPublishedTree(treeFixture()), true);
});

for (const [name, mutate] of [
    ["unverified production edit", (x) => { x.headTree.tree[0].sha = "9".repeat(40); }],
    ["weakened existing test", (x) => { x.headTree.tree[1] = { ...x.headTree.tree[1], sha: head }; }],
    ["removed existing test", (x) => { x.headTree.tree.pop(); }],
    ["extra workflow", (x) => { x.headTree.tree.push({ path: ".github/workflows/evil.yml", type: "blob", mode: "100644", sha: head }); }],
    ["changed executable mode", (x) => { x.headTree.tree[0].mode = "100755"; }],
    ["truncated inventory", (x) => { x.headTree.truncated = true; }],
    ["wrong original blob", (x) => { x.proposal.changes[0].originalBlobSha = head; }],
]) {
    test(`published tree rejects ${name}`, () => {
        const input = treeFixture();
        mutate(input);
        assert.throws(() => admitPublishedTree(input));
    });
}

import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import * as publication from "../../scripts/ai-review-publication.mjs";
import { ciPolicy } from "../../scripts/ai-review-proof.mjs";
import { testAuditProofFixture } from "./fixtures/test-audit-proof.mjs";
import { testAuditPublicationProposal } from "../../scripts/test-audit-publication.mjs";
import { runReviewFlow, reviewRecord } from "../../scripts/ai-review-flow.mjs";
import { verifyCloudTestAudit } from "../../scripts/cloud-test-audit-evidence.mjs";
import { runtimeServer } from "./fixtures/runtime-server.mjs";
import { fetchCi } from "../../services/cloud-ci/src/http.ts";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const blob = (value) => createHash("sha1").update(`blob ${Buffer.byteLength(value)}\0${value}`).digest("hex");
const original = "#[test]\nfn checks_value() {\n    let actual = value();\n    assert!(actual > 0);\n}\n";
const stronger = original.replace("}\n", "    assert_eq!(actual, 2);\n}\n");
const intact = "pub fn value() -> u32 { 2 }\n";
const fault = "pub fn value() -> u32 { 1 }\n";
const proposal = { purpose: "existing-test-strengthening", repository: "omg-cli/omg", branch: "main", baseSha: "a".repeat(40),
    test: { path: "tests/value.rs", testName: "checks_value", originalBlobSha: blob(original), originalContent: original,
        newContent: stronger, sha256: hash(stronger), assertionLine: 5 },
    fault: { path: "src/value.rs", originalBlobSha: blob(intact), oldContentQuote: "2", newContent: fault, sha256: hash(fault) } };

test("existing-test publication uses its separate proof adapter and cannot bypass raw admission", async () => {
    expect(typeof publication.publishTestAuditReview).toBe("function");
    const calls = [];
    const github = { request: async (method, route) => { calls.push({ method, route }); throw new Error("No source transport expected before invalid proof rejection"); } };
    let error;
    try {
        await publication.publishTestAuditReview({ github, request: { testAudit: { proposal, verifierRevision: "d".repeat(40) } },
            receipt: {}, policy: { imageDigest: "sha256:"+"e".repeat(64), verifierRevision: "d".repeat(40) },
            load: async () => { throw new Error("Invalid proof must not load raw bytes"); }, publish: true });
    } catch (failure) { error = failure; }
    expect(error?.message).toMatch(/audit|identity|Cloudflare|request|Missing key/i);
    expect(error).not.toBeInstanceOf(TypeError);
    expect(calls.filter((call) => call.method === "POST")).toEqual([]);
});

function githubFixture(proof) {
    const calls = [];
    const author = { login: "github-actions[bot]", id: 41898282 };
    const files = new Map([[proof.proposal.test.path, proof.original], [proof.proposal.fault.path, proof.production]]);
    const github = { async request(method, route, body) {
        calls.push({ method, route, body });
        if (method === "GET") {
            if (route.includes("/git/commits/")) return { tree: { sha: "e".repeat(40) } };
            if (route.includes("/git/trees/")) return { truncated: false, tree: [...files].map(([path, content]) => ({ path, type: "blob", mode: "100644", sha: blob(content) })) };
            if (route.includes("/git/blobs/")) {
                const value = [...files.values()].find((value) => route.endsWith(blob(value)));
                return { encoding: "base64", content: Buffer.from(value).toString("base64") };
            }
            if (route.includes("/issues?") || route.includes("/pulls?")) return [];
            if (route.endsWith("/git/ref/heads/main")) return { object: { sha: proof.proposal.baseSha } };
            if (route.includes("/git/ref/heads/ai-fix/")) return null;
        }
        if (method === "POST") {
            if (route.endsWith("/issues")) return { user: author, html_url: "https://github.com/omg-cli/omg/issues/1000" };
            if (route.endsWith("/pulls")) return { user: author, html_url: "https://github.com/omg-cli/omg/pull/1001" };
            return { sha: "f".repeat(40) };
        }
        throw new Error("Unexpected test publication route");
    } };
    return { github, calls };
}

test("coordinator audit handoff persists and freshly readmits actual server proof before test-only publication", async () => {
    const proof = testAuditProofFixture();
    const server = runtimeServer();
    expect(server.stageNativeProof(proof.request, proof.receipt)).toBe(proof.id);
    for (const [key, value] of proof.objects) server.objects.set(key, value);
    const rawReads = [];
    const load = async (key) => {
        rawReads.push(key);
        const [kind, id, name] = key.split("/");
        return fetchCi(new Request(new URL(`/runs/${id}/${kind}/${name}`, server.endpoint), {
            headers: { Authorization: `Bearer ${server.token}` },
        }), server.env);
    };
    const receipt = () => server.request(new URL(`/runs/${proof.id}/receipt`, server.endpoint), server.token);
    const task = { path: proof.proposal.test.path, testName: proof.proposal.test.testName,
        originalBlobSha: proof.proposal.test.originalBlobSha };
    let audits = 0;
    const report = await runReviewFlow({
        target: { branch: "main", sha: proof.request.sha, publish: true, range: { kind: "test-audit" } },
        io: {
            head: async () => proof.request.sha,
            collect: async () => ({ baseSha: proof.request.sha,
                sourceRange: { kind: "test-audit", sha: proof.request.sha, inventoryDigest: "b".repeat(64),
                    cursor: 0, totalPaths: 1, pagePaths: 1, nextCursor: null, pageSize: 1 },
                entries: [{ path: task.path }], rows: [{ id: "selected-existing-test", status: "selected", task }],
                unreviewedPaths: [] }),
            format: async () => ({ status: "passed" }),
            audit: async (row) => {
                audits++;
                expect(row.task).toEqual(task);
                await verifyCloudTestAudit(await receipt(), proof.request, proof.policy, load);
                return { request: proof.request, id: proof.id, coderOperationId: "fixture-coder-operation", readPaths: [task.path] };
            },
            review: async () => { throw new Error("Defect review must not receive the existing-test audit task"); },
        },
    });
    expect(audits).toBe(1);
    expect(report.testAuditOutcomes).toEqual([{ id: "selected-existing-test", status: "verified-strengthening", proofId: proof.id }]);
    const record = reviewRecord({ ...report, controllerRevision: proof.policy.verifierRevision }, "42", "1");
    const recordUrl = new URL("/review-records/42-1", server.endpoint);
    await server.request(recordUrl, server.token, JSON.stringify(record));
    const durable = await server.request(recordUrl, server.token);
    expect(durable.testAudits).toEqual(record.report.testAudits);
    const saved = durable.testAudits[0];
    const state = githubFixture(proof);
    const result = await publication.publishTestAuditReview({ request: saved.request, receipt: await receipt(),
        policy: proof.policy, load, github: state.github, publish: true });
    expect(result.action).toBe("published");
    expect(rawReads).toHaveLength(2 * proof.objects.size);
    expect(server.requests.filter(({ path }) => path.endsWith("/receipt"))).toHaveLength(2);
    expect(state.calls.find(({ method, route }) => method === "POST" && route.endsWith("/git/trees")).body.tree
        .map(({ path }) => path)).toEqual([task.path]);
    expect(state.calls.find(({ method, route }) => method === "POST" && route.endsWith("/git/blobs")).body.content)
        .toBe(proof.proposal.test.newContent);
    expect(JSON.stringify(state.calls.filter(({ method }) => method === "POST"))).not.toContain(proof.proposal.fault.newContent);
});

test("actual four-state raw readmission publishes only the strengthened existing test", async () => {
    const proof = testAuditProofFixture();
    const state = githubFixture(proof);
    const loaded = [];
    const result = await publication.publishTestAuditReview({ ...proof, github: state.github,
        load: (key) => { loaded.push(key); return proof.load(key); }, publish: true });
    expect(result.action).toBe("published");
    expect(loaded).toHaveLength(proof.objects.size);
    const tree = state.calls.find((call) => call.method === "POST" && call.route.endsWith("/git/trees"));
    expect(tree.body.tree.map((entry) => entry.path)).toEqual([proof.proposal.test.path]);
    expect(state.calls.find((call) => call.method === "POST" && call.route.endsWith("/git/blobs")).body.content).toBe(proof.proposal.test.newContent);
    const publicWrites = JSON.stringify(state.calls.filter((call) => call.method === "POST"));
    expect(publicWrites).not.toContain(proof.proposal.fault.newContent);
    const pull = state.calls.find((call) => call.method === "POST" && call.route.endsWith("/pulls"));
    expect(pull.body.body).toContain("Proof purpose: existing-test-strengthening");
    expect(pull.body.body).toContain("oldIntact: exit 0");
    expect(pull.body.body).toContain("strongerFault: exit 101");
});

test("missing or corrupted actual four-state raw bytes prevent every GitHub mutation", async () => {
    for (const replacement of [null, "corrupted"] ) {
        const proof = testAuditProofFixture();
        const state = githubFixture(proof);
        const key = proof.receipt.testAuditReports[2].key;
        if (replacement === null) proof.objects.delete(key); else proof.objects.set(key, replacement);
        await expect(publication.publishTestAuditReview({ ...proof, github: state.github, publish: true })).rejects.toThrow();
        expect(state.calls.filter((call) => call.method === "POST")).toEqual([]);
    }
});

test("adequate existing-test sensitivity evidence cannot authorize a test-strengthening publication", async () => {
    const proof = testAuditProofFixture();
    const state = githubFixture(proof);
    proof.proposal.purpose = "existing-test-sensitivity";
    proof.proposal.test.newContent = proof.original;
    proof.proposal.test.sha256 = hash(proof.original);
    proof.proposal.test.assertionLine = 4;
    await expect(publication.publishTestAuditReview({ ...proof, github: state.github, publish: true,
        load: async () => { throw new Error("Sensitivity evidence must not enter publication raw admission"); },
    })).rejects.toThrow("sensitivity evidence cannot authorize publication");
    expect(state.calls).toEqual([]);
});

test("audit-only publication admits an actual 200 KiB existing test with full raw proof", async () => {
    const proof = testAuditProofFixture({ paddingBytes: 200 * 1024 });
    expect(Buffer.byteLength(proof.original)).toBeGreaterThan(200 * 1024);
    const state = githubFixture(proof);
    const result = await publication.publishTestAuditReview({ ...proof, github: state.github, publish: true });
    expect(result.action).toBe("published");
    expect(state.calls.find(call => call.method === "POST" && call.route.endsWith("/git/blobs")).body.content)
        .toBe(proof.proposal.test.newContent);
    expect(state.calls.find(call => call.method === "POST" && call.route.endsWith("/git/trees")).body.tree.map(file => file.path))
        .toEqual([proof.proposal.test.path]);
});

test("audit-only Git reads reject oversized, substituted and invalid UTF-8 bytes before publication", async () => {
    for (const bytes of [Buffer.alloc(256*1024+1, 120), Buffer.from("substituted source"), Buffer.from([0xff])]) {
        const proof = testAuditProofFixture();
        const state = githubFixture(proof);
        const request = state.github.request;
        state.github.request = (method, route, body) => method === "GET" && route.includes("/git/blobs/")
            ? Promise.resolve({ encoding: "base64", content: bytes.toString("base64") }) : request(method, route, body);
        await expect(publication.publishTestAuditReview({ ...proof, github: state.github, publish: true })).rejects.toThrow();
        expect(state.calls.filter(call => call.method === "POST")).toEqual([]);
    }
});

test("an interrupted 200 KiB audit publication resumes its identical owned branch without rewriting source", async () => {
    const proof = testAuditProofFixture({ paddingBytes: 200*1024 });
    const state = githubFixture(proof);
    const preview = await publication.publishTestAuditReview({ ...proof, github: state.github, publish: false });
    const normalized = testAuditPublicationProposal(proof.request.testAudit);
    const request = state.github.request;
    const existingTree = "9".repeat(40);
    const commitSha = "8".repeat(40);
    const author = { login: "github-actions[bot]", id: 41898282 };
    state.calls.length = 0;
    state.github.request = async (method, route, body) => {
        if (method === "GET") {
            if (route.includes("/issues?")) return [{ user: author, state: "open", body: preview.bodies.issue,
                html_url: "https://github.com/omg-cli/omg/issues/1000" }];
            if (route.endsWith(`/git/ref/heads/${preview.headBranch}`)) return { object: { sha: commitSha } };
            if (route.endsWith(`/git/commits/${commitSha}`)) return { message: `AI review ${normalized.finding.key}\nProposal ${publication.proposalDigest(normalized)}`,
                parents: [{ sha: proof.request.sha }], tree: { sha: existingTree } };
            if (route.includes(`/git/trees/${existingTree}`)) return { truncated: false, tree: [
                { path: proof.proposal.test.path, mode: "100644", type: "blob", sha: blob(proof.proposal.test.newContent) },
                { path: proof.proposal.fault.path, mode: "100644", type: "blob", sha: blob(proof.production) },
            ] };
            if (route.endsWith(`/git/blobs/${blob(proof.proposal.test.newContent)}`))
                return { encoding: "base64", content: Buffer.from(proof.proposal.test.newContent).toString("base64") };
        }
        return request(method, route, body);
    };
    expect((await publication.publishTestAuditReview({ ...proof, github: state.github, publish: true })).action).toBe("published");
    expect(state.calls.filter(call => call.method === "POST").map(call => call.route.split("/").at(-1))).toEqual(["pulls"]);
});

test("shared ci policy preserves the trusted endpoint through actual test-audit publication", async () => {
    const proof = testAuditProofFixture();
    const state = githubFixture(proof);
    const loaded = [];
    const result = await publication.publishTestAuditReview({ ...proof, policy: ciPolicy(proof.policy),
        github: state.github, load: (key) => { loaded.push(key); return proof.load(key); }, publish: true });
    expect(result.action).toBe("published");
    expect(loaded).toHaveLength(proof.objects.size);
    const pull = state.calls.find((call) => call.method === "POST" && call.route.endsWith("/pulls"));
    expect(pull.body.body).toContain("Proof purpose: existing-test-strengthening");
});

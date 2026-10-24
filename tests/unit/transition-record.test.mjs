import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadTestAuditTransition, transitionMatchesFormatting } from "../../scripts/ai-review-flow.mjs";
import { sha256 } from "../../scripts/ai-review-publication.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const fixed = path.join(root, "config/ci/test-audit-transition.json");
const raw = JSON.parse(await readFile(fixed, "utf8"));
const context = { runId: "39871147004", attempt: "2", controllerRevision: "c".repeat(40),
    imageDigest: raw.imageDigest, verifierRevision: raw.verifierRevision };
const reader = (value) => async (file) => {
    expect(file).toBe(fixed);
    return structuredClone(value);
};

test("default reader uses the fixed checked-in record without modifying it", async () => {
    expect(await loadTestAuditTransition({ ...context, runId: "1" })).toBeUndefined();
    expect(JSON.parse(await readFile(fixed, "utf8"))).toEqual(raw);
});
test("disabled record never grants a transition", async () => {
    expect(await loadTestAuditTransition(context, reader({ ...raw, enabled: false }))).toBeUndefined();
});
test("missing record grants no transition", async () => {
    expect(await loadTestAuditTransition(context, async (file) => {
        expect(file).toBe(fixed);
        throw Object.assign(new Error("missing"), { code: "ENOENT" });
    })).toBeUndefined();
});
test("malformed and unreadable records remain failures", async () => {
    await expect(loadTestAuditTransition(context, reader({ ...raw, enabled: true, extra: "x" }))).rejects.toThrow("malformed");
    await expect(loadTestAuditTransition(context, async () => { throw new SyntaxError("bad JSON"); })).rejects.toThrow("bad JSON");
    for (const priorFormatting of [{ ...raw.priorFormatting, runId: 39808913262 }, { ...raw.priorFormatting, attempt: 3 }])
        await expect(loadTestAuditTransition(context, reader({ ...raw, enabled: false, priorFormatting }))).rejects.toThrow("malformed");
});
test("another run and attempt cannot use the recorded authorization", async () => {
    const read = reader({ ...raw, enabled: true });
    expect(await loadTestAuditTransition({ ...context, runId: "1" }, read)).toBeUndefined();
    expect(await loadTestAuditTransition({ ...context, attempt: "3" }, read)).toBeUndefined();
});
test("runtime and controller drift reject before admission", async () => {
    const read = reader({ ...raw, enabled: true });
    await expect(loadTestAuditTransition({ ...context, imageDigest: `sha256:${"0".repeat(64)}` }, read)).rejects.toThrow("drifted");
    await expect(loadTestAuditTransition({ ...context, controllerRevision: raw.parentController }, read)).rejects.toThrow("drifted");
    await expect(loadTestAuditTransition({ ...context, controllerRevision: raw.verifierRevision }, read)).rejects.toThrow("drifted");
});
test("derived controller and semantic record hash bind the actual immutable checkout", async () => {
    const enabled = { ...raw, enabled: true };
    const record = await loadTestAuditTransition(context, reader(enabled));
    expect(record.controllerRevision).toBe(context.controllerRevision);
    expect(record.recordSha256).toBe(sha256(JSON.stringify(enabled)));
});
test("formatter matching requires enabled literal source, branch and inherited identity", () => {
    const record = { ...raw, enabled: true };
    const upstream = { runId: raw.priorFormatting.runId, attempt: raw.priorFormatting.attempt };
    expect(transitionMatchesFormatting(record, { sha: raw.source, branch: "main", upstream })).toBe(true);
    expect(transitionMatchesFormatting({ ...record, enabled: false }, { sha: raw.source, branch: "main", upstream })).toBe(false);
    expect(transitionMatchesFormatting(record, { sha: raw.source, branch: "release", upstream })).toBe(false);
    expect(transitionMatchesFormatting(record, { sha: "0".repeat(40), branch: "main", upstream })).toBe(false);
    expect(transitionMatchesFormatting(record, { sha: raw.source, branch: "main", upstream: { ...upstream, attempt: "4" } })).toBe(false);
});

import { test, expect } from "bun:test";
import { createHash } from "node:crypto";
import { collectRuntimeSources, acknowledgeRuntimeSources } from "../../scripts/sentry-review-input.mjs";

const sha = "a".repeat(40);
const content = "pub fn value() -> u8 { 1 }\n";
const blobSha = createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0${content}`).digest("hex");
const event = {
    kind: "sentry-runtime", organization: "omg", projectId: "12", issueId: "34",
    eventId: "b".repeat(32), bodySha256: "c".repeat(64), sourceSha: "d".repeat(40),
    release: "omg@0.1.0", environment: "production", errorTypes: [], frames: [{ path: "src/value.rs", line: 1 }],
};
const reviewRef = { runId: "123", attempt: "1", sha, controllerRevision: "e".repeat(40) };

function fixture(events = [event], sourceContent = content) {
    const calls = [];
    const sourceBlob = createHash("sha1").update(`blob ${Buffer.byteLength(sourceContent)}\0`).update(sourceContent).digest("hex");
    const github = { async request(method, route) {
        if (route.endsWith(`/git/commits/${sha}`)) return { tree: { sha: "e".repeat(40) } };
        if (route.includes("/git/trees/")) return { truncated: false, tree: [{ path: "src/value.rs", mode: "100644", type: "blob", sha: sourceBlob, size: Buffer.byteLength(sourceContent) }] };
        if (route.endsWith(`/git/blobs/${sourceBlob}`)) return { encoding: "base64", content: Buffer.from(sourceContent).toString("base64") };
        throw new Error(`Unexpected GitHub route ${route}`);
    } };
    const fetcher = async (url, options) => {
        calls.push({ url: String(url), options });
        return Response.json(String(url).endsWith("/ack") ? { acknowledged: true } : String(url).endsWith("/reserve") ? { activeReview: JSON.parse(options.body).activeReview } : { events, cursor: null });
    };
    const request = async (url, token, body) => {
        const response = await fetcher(url, { headers: { authorization: `Bearer ${token}` }, redirect: "error", body });
        if (!response.ok) throw new Error("Service unavailable");
        return response.json();
    };
    return { github, fetcher, request, calls, sha, reviewRef, endpoint: "https://omg-cloud-ci.latham.workers.dev/", token: "private-test-token" };
}

test("runtime leads retain historical identity while reviewing exact current-main blobs", async () => {
    const input = fixture();
    const result = await collectRuntimeSources(input);
    expect(result.entries).toEqual([{ path: "src/value.rs", blobSha, content }]);
    expect(result.runtimeEvidence).toEqual([event]);
    expect(result.sourceRange).toEqual({ kind: "audit", baseSha: sha, headSha: sha, intake: "sentry-runtime" });
    expect(result.runtimeEvents).toEqual([{ projectId: "12", eventId: event.eventId, bodySha256: event.bodySha256 }]);
    expect(new URL(input.calls[0].url).searchParams.get("limit")).toBe("1");
});

test("a pending runtime event with no current source is held explicitly without a fake source", async () => {
    const result = await collectRuntimeSources(fixture([{ ...event, frames: [{ path: "src/removed.rs", line: 2 }] }]));
    expect(result.entries).toEqual([]);
    expect(result.unreviewedPaths).toEqual([{ path: "src/removed.rs", reason: "runtime-source-unavailable" }]);
    expect(result.runtimeEvents).toHaveLength(1);
});

test("runtime evidence rejects traversal and arbitrary extra payload before reading source", async () => {
    for (const invalid of [{ ...event, frames: [{ path: "src/../secrets.rs", line: 1 }] }, { ...event, message: "raw user data" }])
        await expect(collectRuntimeSources(fixture([invalid]))).rejects.toThrow();
});

test("runtime polling refuses redirect/provider errors and does not silently lose evidence", async () => {
    const input = fixture();
    await expect(collectRuntimeSources({ ...input, request: async () => { throw new Error("Service unavailable"); } })).rejects.toThrow();
    await expect(collectRuntimeSources({ ...input, endpoint: "https://attacker.example/" })).rejects.toThrow();
});

test("runtime acknowledgment names only the durably stored review and exact event digest", async () => {
    const input = fixture();
    const report = await collectRuntimeSources(input);
    await acknowledgeRuntimeSources({ ...input, report, runId: "123", attempt: "1" });
    expect(JSON.parse(input.calls.at(-1).options.body)).toEqual({ bodySha256: event.bodySha256, reviewRunId: "123", attempt: "1" });
    expect(input.calls.at(-1).url).toEndWith(`/sentry/events/12/${event.eventId}/ack`);
    await expect(acknowledgeRuntimeSources({ ...input, report, runId: "../123", attempt: "1" })).rejects.toThrow();
});

test("empty runtime queue does not query source or admit fabricated evidence", async () => {
    const input = fixture([]);
    input.github.request = async () => { throw new Error("No source lookup is needed"); };
    const result = await collectRuntimeSources(input);
    expect(result.entries).toEqual([]);
    expect(result.runtimeEvents).toEqual([]);
    expect(result.runtimeEvidence).toEqual([]);
    expect(input.calls).toHaveLength(1);
});

test("a bounded runtime wave acknowledges only its selected event", async () => {
    const input = fixture([event, { ...event, eventId: "f".repeat(32) }]);
    const result = await collectRuntimeSources(input);
    expect(result.runtimeEvidence).toEqual([event]);
    await acknowledgeRuntimeSources({ ...input, report: result, runId: "123", attempt: "1" });
    expect(input.calls.filter((call) => call.url.endsWith("/ack"))).toHaveLength(1);
    expect(input.calls.at(-1).url).toContain(event.eventId);
});

test("unknown release attribution remains explicit and can produce a reproducible lead", async () => {
    const unknown = { ...event, sourceSha: null, release: null };
    const result = await collectRuntimeSources(fixture([unknown]));
    expect(result.entries).toEqual([{ path: "src/value.rs", blobSha, content }]);
    expect(result.runtimeEvidence[0].sourceSha).toBeNull();
    expect(result.runtimeEvidence[0].release).toBeNull();
});

test("oversized owned source is held before strict collection and cannot poison the pending queue", async () => {
    let outcome;
    try {
        const result = await collectRuntimeSources(fixture([event], "x".repeat(24001)));
        outcome = { entries: result.entries, held: result.unreviewedPaths };
    } catch (error) { outcome = { error: error.name }; }
    expect(outcome).toEqual({ entries: [], held: [{ path: "src/value.rs", reason: "source-byte-budget-exceeded" }] });
});

test("unreadable runtime source has a held reason while provider failures still fail the run", async () => {
    for (const [bytes, reason] of [["pub fn bad() {}\0", "binary-source"], [Buffer.from([0xff]), "invalid-utf8-source"]]) {
        const result = await collectRuntimeSources(fixture([event], bytes));
        expect(result.entries).toEqual([]);
        expect(result.unreviewedPaths).toEqual([{ path: "src/value.rs", reason }]);
    }
    const unavailable = fixture();
    unavailable.github.request = async () => { throw new Error("Provider unavailable"); };
    await expect(collectRuntimeSources(unavailable)).rejects.toThrow("Provider unavailable");
});

test("runtime work reserves its durable owner before reading any source", async () => {
    const input = fixture();
    const original = input.github.request;
    input.github.request = (...args) => {
        expect(input.calls.some((call) => call.url.endsWith("/reserve"))).toBe(true);
        return original(...args);
    };
    await collectRuntimeSources(input);
    expect(JSON.parse(input.calls[1].options.body)).toEqual({ bodySha256: event.bodySha256, activeReview: reviewRef, expectedActiveReview: null });
});

test("an existing runtime owner is replayed rather than replaced by a fresh no-findings review", async () => {
    const activeReview = { ...reviewRef, runId: "999" };
    const input = fixture([{ ...event, activeReview }]);
    input.github.request = async () => { throw new Error("Existing work must not be reinferred"); };
    const result = await collectRuntimeSources(input);
    expect(result.replayRef).toEqual(activeReview);
    expect(result.entries).toEqual([]);
    expect(result.runtimeEvents).toEqual([{ projectId: event.projectId, eventId: event.eventId, bodySha256: event.bodySha256 }]);
    expect(input.calls).toHaveLength(2);
    expect(input.calls[1].url).toEndWith("/review-records/999-1");
});

test("only a terminal original attempt and definite missing review permit reservation recovery", async () => {
    const activeReview = { ...reviewRef, runId: "999" };
    const input = fixture([{ ...event, activeReview }]);
    const originalRequest = input.request;
    input.request = (url, ...args) => String(url).includes("/review-records/")
        ? Promise.reject(Object.assign(new Error("Missing review"), { status: 404 })) : originalRequest(url, ...args);
    const originalGithub = input.github.request;
    input.github.request = (method, route) => route.includes("/actions/runs/999/attempts/1")
        ? Promise.resolve({ id: 999, run_attempt: 1, status: "completed", conclusion: "failure", head_sha: sha,
            head_branch: "main", path: ".github/workflows/ai-review.yml", repository: { full_name: "omg-cli/omg" } })
        : originalGithub(method, route);
    const result = await collectRuntimeSources(input);
    expect(result.entries).toEqual([{ path: "src/value.rs", blobSha, content }]);
    const claim = input.calls.find((call) => call.url.endsWith("/reserve"));
    expect(JSON.parse(claim.options.body).expectedActiveReview).toEqual(activeReview);
});

test("running or mismatched original attempts retain the reservation and provider outages never count as missing", async () => {
    for (const change of [{ status: "in_progress" }, { head_sha: "f".repeat(40) }, { run_attempt: 2 }, { path: ".github/workflows/other.yml" }]) {
        const input = fixture([{ ...event, activeReview: { ...reviewRef, runId: "999" } }]);
        const originalRequest = input.request;
        input.request = (url, ...args) => String(url).includes("/review-records/")
            ? Promise.reject(Object.assign(new Error("Missing review"), { status: 404 })) : originalRequest(url, ...args);
        input.github.request = async () => ({ id: 999, run_attempt: 1, status: "completed", head_sha: sha,
            head_branch: "main", path: ".github/workflows/ai-review.yml", repository: { full_name: "omg-cli/omg" }, ...change });
        const result = await collectRuntimeSources(input);
        expect(result.replayRef.runId).toBe("999");
        expect(input.calls.some((call) => call.url.endsWith("/reserve"))).toBe(false);
    }
    const unavailable = fixture([{ ...event, activeReview: { ...reviewRef, runId: "999" } }]);
    const originalRequest = unavailable.request;
    unavailable.request = (url, ...args) => String(url).includes("/review-records/")
        ? Promise.reject(Object.assign(new Error("Provider outage"), { status: 503 })) : originalRequest(url, ...args);
    await expect(collectRuntimeSources(unavailable)).rejects.toThrow("Provider outage");
    expect(unavailable.calls.some((call) => call.url.endsWith("/reserve"))).toBe(false);
});

test("format-block recovery requires explicit no-inference proof and the exact terminal original attempt", async () => {
    const activeReview = { ...reviewRef, runId: "999" };
    const report = { repository: "omg-cli/omg", branch: "main", sha,
        controllerRevision: activeReview.controllerRevision, status: "format-blocked",
        formatting: { status: "blocked" }, sourceRange: { intake: "sentry-runtime" }, publishRequested: true,
        modelInferencePerformed: false, nativeVerificationPerformed: false,
        publications: [], batches: [], candidateOutcomes: [], readPaths: [],
        runtimeEvents: [{ projectId: event.projectId, eventId: event.eventId, bodySha256: event.bodySha256 }] };
    for (const [change, attempt, expectedRecovery] of [
        [{}, {}, true], [{}, { status: "in_progress" }, false], [{}, { run_attempt: 2 }, false],
        [{ publications: [{ verified: true }] }, {}, false], [{ modelInferencePerformed: true }, {}, false],
        [{ modelInferencePerformed: undefined }, {}, false], [{ nativeVerificationPerformed: true }, {}, false],
        [{ batches: [{}] }, {}, false], [{ readPaths: ["src/value.rs"] }, {}, false],
        [{ status: "reviewed" }, {}, false], [{ publishRequested: false }, {}, false],
        [{ sha: "f".repeat(40) }, {}, false], [{ runtimeEvents: [{ ...report.runtimeEvents[0], bodySha256: "f".repeat(64) }] }, {}, false],
    ]) {
        const input = fixture([{ ...event, activeReview }]);
        const originalRequest = input.request;
        input.request = (url, ...args) => String(url).includes("/review-records/")
            ? Promise.resolve({ ...report, ...change }) : originalRequest(url, ...args);
        const originalGithub = input.github.request;
        input.github.request = (method, route) => route.includes("/actions/runs/")
            ? Promise.resolve({ id: 999, run_attempt: 1, status: "completed", head_sha: sha,
                head_branch: "main", path: ".github/workflows/ai-review.yml", repository: { full_name: "omg-cli/omg" }, ...attempt })
            : originalGithub(method, route);
        const result = await collectRuntimeSources(input);
        expect(Boolean(result.replayRef)).toBe(!expectedRecovery);
        expect(input.calls.some((call) => call.url.endsWith("/reserve"))).toBe(expectedRecovery);
    }
});

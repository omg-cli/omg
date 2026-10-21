import { test, expect } from "bun:test";
import * as reviewFlow from "../../scripts/ai-review-flow.mjs";
import { acknowledgeRuntimeSources } from "../../scripts/sentry-review-input.mjs";
import { runtimeServer } from "./fixtures/runtime-server.mjs";

const sha = "a".repeat(40);
const eventId = "b".repeat(32);

async function fixture(change = {}, persist = true) {
    const server = runtimeServer();
    expect((await server.signedSend({ action: "triggered", data: { event: {
        event_id: eventId, issue_id: "12345", project: 789, environment: "production",
        url: `https://sentry.io/api/0/projects/omg-org/omg/events/${eventId}/`,
        exception: { values: [{ type: "RuntimeError", stacktrace: { frames: [{ filename: "src/value.rs", lineno: 1 }] } }] },
    } } })).status).toBe(202);
    const event = await server.request(new URL(`/sentry/events/789/${eventId}`, server.endpoint), server.token);
    const report = { repository: "omg-cli/omg", branch: "main", sha, status: "reviewed", publishRequested: true,
        sourceRange: { kind: "audit", intake: "sentry-runtime" }, formatting: { status: "passed" },
        runtimeEvents: [{ projectId: event.projectId, eventId, bodySha256: event.bodySha256 }],
        suppliedPaths: ["src/value.rs"], readPaths: ["src/value.rs"], unreviewedPaths: [],
        batches: [{ sourceInput: { repository: "omg-cli/omg", branch: "main", sha, sourceFiles: [{ path: "src/value.rs" }] },
            modelResponse: { repository: "omg-cli/omg", branch: "main", sha, kind: "no-findings",
                model: "@cf/deepseek-ai/deepseek-v4.1-flash-1017", publication: "requires-verifier", codeExecutions: 1,
                sourceToolCalls: 1, readDiff: false, suppliedPaths: ["src/value.rs"], readPaths: ["src/value.rs"] } }],
        candidateOutcomes: [], publications: [], ...change };
    if (persist) {
        expect(await server.request(new URL("/review-records/123-1", server.endpoint), server.token,
            JSON.stringify({ repository: "omg-cli/omg", runId: "123", attempt: "1", report }))).toEqual({ stored: true });
        expect(await server.request(new URL("/review-records/123-1", server.endpoint), server.token)).toEqual(report);
    }
    const acknowledge = () => acknowledgeRuntimeSources({ ...server, report, runId: "123", attempt: "1" });
    return { server, report, acknowledge };
}

for (const [name, change] of [
    ["format-blocked before inference", { status: "format-blocked", formatting: { status: "blocked" }, batches: [], readPaths: [] }],
    ["generic no-reviewable-source", { status: "no-reviewable-source", formatting: { status: "not-required" }, batches: [], readPaths: [] }],
    ["unresolved canonical replay", { status: "runtime-replay-held", runtimeUnresolved: true }],
    ["coverage-blocked", { status: "coverage-blocked" }], ["stale source", { status: "incomplete-stale" }],
    ["unread source", { unreviewedPaths: [{ path: "src/value.rs", reason: "not-read-by-model" }] }],
    ["no real read batch", { batches: [] }], ["no source read", { readPaths: [] }],
    ["a placeholder batch without a read receipt", { batches: [{}] }],
    ["unresolved coding candidate", { candidateOutcomes: [{ outcome: "coding-agent-produced-no-repair" }] }],
    ["verification budget exhausted", { candidateOutcomes: [{ outcome: "verification-budget-exceeded" }] }],
    ["preview", { publishRequested: false }],
]) test(`durable ${name} never acknowledges or loses its pending runtime event`, async () => {
    const { server, report, acknowledge } = await fixture(change);
    expect(reviewFlow.runtimeReviewCanAcknowledge(report)).toBe(false);
    await expect(reviewFlow.finalizeRuntimeReview({ report, publicationResult: "skipped", acknowledge })).rejects.toThrow();
    expect(server.requests.filter(({ path }) => path.endsWith("/ack"))).toHaveLength(0);
    expect((await server.request(new URL("/sentry/events", server.endpoint), server.token)).events).toHaveLength(1);
    expect(server.objects.has(`sentry/events/789/${eventId}.json`)).toBe(true);
});

for (const status of ["reviewed", "publication-replay"])
    test(`completed ${status} can acknowledge only after its exact durable report exists`, async () => {
        const { server, report, acknowledge } = await fixture({ status });
        expect(reviewFlow.runtimeReviewCanAcknowledge(report)).toBe(true);
        expect(await reviewFlow.finalizeRuntimeReview({ report, publicationResult: "skipped", acknowledge }))
            .toEqual({ status: "runtime-evidence-acknowledged" });
        expect((await server.request(new URL("/sentry/events", server.endpoint), server.token)).events).toEqual([]);
        expect(server.objects.has(`sentry/events/789/${eventId}.json`)).toBe(true);
        const missing = await fixture({ status }, false);
        await expect(reviewFlow.finalizeRuntimeReview({ ...missing, publicationResult: "skipped" })).rejects.toThrow("HTTP 409");
        expect((await missing.server.request(new URL("/sentry/events", missing.server.endpoint), missing.server.token)).events).toHaveLength(1);
    });

test("failed publication preserves completed review evidence for replay", async () => {
    const { server, report, acknowledge } = await fixture({ publications: [{ proposal: {} }],
        candidateOutcomes: [{ outcome: "verified-for-publication" }] });
    for (const publicationResult of ["failure", "cancelled", "skipped", undefined])
        await expect(reviewFlow.finalizeRuntimeReview({ report, publicationResult, acknowledge })).rejects.toThrow();
    expect(server.requests.filter(({ path }) => path.endsWith("/ack"))).toHaveLength(0);
    expect(await reviewFlow.finalizeRuntimeReview({ report, publicationResult: "success", acknowledge }))
        .toEqual({ status: "runtime-evidence-acknowledged" });
});

import { collectCandidateSources } from "./ai-review-candidate.mjs";
import { runtimeEvidencePageSchema, runtimeReviewRefSchema } from "../services/ci-inspector/src/runtime-evidence.ts";

function serviceEndpoint(endpoint) {
    const url = new URL(endpoint);
    if (url.origin !== "https://omg-cloud-ci.latham.workers.dev" || url.pathname !== "/" || url.search || url.hash || url.username || url.password)
        throw new Error("Runtime evidence requires the trusted OMG verifier endpoint.");
    return url;
}

async function recoverableReservation({ activeReview, github, url, token, request }) {
    try {
        await request(new URL(`/review-records/${activeReview.runId}-${activeReview.attempt}`, url), token, undefined, 2 * 1024 * 1024);
        return false;
    } catch (error) {
        if (error.status !== 404) throw error;
    }
    const run = await github.request("GET", `/repos/omg-cli/omg/actions/runs/${activeReview.runId}/attempts/${activeReview.attempt}`);
    return String(run.id) === activeReview.runId && String(run.run_attempt) === activeReview.attempt &&
        run.status === "completed" && run.repository?.full_name === "omg-cli/omg" &&
        run.path === ".github/workflows/ai-review.yml" && run.head_branch === "main" && run.head_sha === activeReview.sha;
}

export async function collectRuntimeSources({ github, sha, endpoint, token, request, reviewRef }) {
    if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error("Invalid runtime review source identity.");
    const owner = runtimeReviewRefSchema.parse(reviewRef);
    if (owner.sha !== sha) throw new Error("Runtime reservation source mismatch.");
    const url = serviceEndpoint(endpoint);
    const runtimeEvidence = [];
    let cursor = null;
    for (let page = 0; page < 5; page++) {
        const query = new URL("/sentry/poll", url);
        query.searchParams.set("limit", "1");
        const result = runtimeEvidencePageSchema.parse(await request(query, token, "{}", 128 * 1024));
        const selected = result.events[0];
        if (selected) {
            const { activeReview, ...evidence } = selected;
            const runtimeEvents = [{ projectId: evidence.projectId, eventId: evidence.eventId, bodySha256: evidence.bodySha256 }];
            if (activeReview && JSON.stringify(activeReview) !== JSON.stringify(owner) &&
                !await recoverableReservation({ activeReview, github, url, token, request }))
                return { baseSha: sha, sourceRange: { kind: "audit", baseSha: sha, headSha: sha, intake: "sentry-runtime" },
                    entries: [], unreviewedPaths: [], runtimeEvents, runtimeEvidence: [evidence], replayRef: activeReview };
            const reservation = await request(new URL(`/sentry/events/${evidence.projectId}/${evidence.eventId}/reserve`, url), token,
                JSON.stringify({ bodySha256: evidence.bodySha256, activeReview: owner, expectedActiveReview: activeReview ?? null }), 16384);
            if (JSON.stringify(runtimeReviewRefSchema.parse(reservation.activeReview)) !== JSON.stringify(owner))
                throw new Error("Runtime reservation response identity mismatch.");
            runtimeEvidence.push(evidence);
        }
        cursor = result.cursor;
        if (runtimeEvidence.length || !cursor) break;
    }
    const paths = [...new Set(runtimeEvidence.flatMap((event) => event.frames.map((frame) => frame.path)))];
    const sources = new Map();
    const held = new Map();
    for (let offset = 0; offset < paths.length; offset += 16)
        for (const [file, source] of await collectCandidateSources({ github, sha, paths: paths.slice(offset, offset + 16), onHeld: (file, reason) => held.set(file, reason) }))
            sources.set(file, source);
    const entries = [];
    const unreviewedPaths = [];
    for (const file of paths) {
        const source = sources.get(file);
        const reason = held.get(file) ?? (!source ? "runtime-source-unavailable" : Buffer.byteLength(source.content) > 24000 ? "source-byte-budget-exceeded" : null);
        if (reason) unreviewedPaths.push({ path: file, reason });
        else entries.push({ path: file, blobSha: source.sha, content: source.content });
    }
    return {
        baseSha: sha,
        sourceRange: { kind: "audit", baseSha: sha, headSha: sha, intake: "sentry-runtime" },
        entries, unreviewedPaths, runtimeEvidence,
        runtimeEvents: runtimeEvidence.map(({ projectId, eventId, bodySha256 }) => ({ projectId, eventId, bodySha256 })),
    };
}

export async function acknowledgeRuntimeSources({ endpoint, token, request, report, runId, attempt }) {
    const url = serviceEndpoint(endpoint);
    if (!/^[1-9][0-9]{0,19}$/.test(runId) || !/^[1-9][0-9]{0,5}$/.test(attempt))
        throw new Error("Invalid durable runtime review identity.");
    for (const event of report.runtimeEvents ?? []) {
        if (!/^[1-9][0-9]{0,19}$/.test(event.projectId) || !/^[a-f0-9]{32}$/.test(event.eventId) || !/^[a-f0-9]{64}$/.test(event.bodySha256))
            throw new Error("Invalid runtime acknowledgment identity.");
        await request(new URL(`/sentry/events/${event.projectId}/${event.eventId}/ack`, url), token,
            JSON.stringify({ bodySha256: event.bodySha256, reviewRunId: runId, attempt }), 16384);
    }
}

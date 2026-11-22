import { expect, test } from "bun:test";
import { readCheckpoint, recoverCheckpoint } from "../../advisories/scripts/operator";
import { stageCheckpoint, stageOperatorFetcher } from "../transport";
import { CANONICAL_ORIGIN, STAGE_ORIGIN } from "../stage-identity";

const binding = { digest:"a".repeat(64), endpoint:"https://advisories.example", instance_id:"1".repeat(32), session_id:"afb732ac-68e4-4549-98ec-e89224449b75" };

test("stage credentials cannot leave the fixed protected origin or follow a redirect", async () => {
    let calls = 0;
    const init = { method: "POST", redirect: "error" } satisfies RequestInit;
    const fetcher = stageOperatorFetcher("fixture-id", "fixture-secret", async (input, options) => {
        calls++;
        expect(String(input)).toBe(STAGE_ORIGIN + "/internal/ingest");
        expect(options?.redirect).toBe("error");
        expect(new Headers(options?.headers).get("cf-access-client-secret")).toBe("fixture-secret");
        return Response.redirect(CANONICAL_ORIGIN + "/internal/ingest");
    });
    for (const url of [
        CANONICAL_ORIGIN + "/internal/ingest", "https://other.example/internal/ingest",
        STAGE_ORIGIN + "/internal/ingest?target=other", STAGE_ORIGIN + "/v1/status",
    ]) await expect(fetcher(new URL(url), init)).rejects.toThrow("destination refused");
    await expect(fetcher(new URL(STAGE_ORIGIN + "/internal/ingest"), { ...init, redirect: "follow" })).rejects.toThrow("destination refused");
    expect(calls).toBe(0);
    await expect(fetcher(new URL(STAGE_ORIGIN + "/internal/ingest"), init)).rejects.toThrow("redirect refused");
    expect(calls).toBe(1);
    const canonical = { ...binding, endpoint: CANONICAL_ORIGIN };
    const checkpoint = recoverCheckpoint(canonical);
    const envelope = { transport_endpoint: STAGE_ORIGIN, checkpoint };
    expect(() => stageCheckpoint(checkpoint)).toThrow("transport");
    expect(() => readCheckpoint(envelope, canonical)).toThrow();
    expect(readCheckpoint(stageCheckpoint(envelope), canonical)).toEqual(checkpoint);
});

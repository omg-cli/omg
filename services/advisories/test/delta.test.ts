import { test, expect } from "bun:test";
import { deltaBatch } from "../src/delta";
import { cveUrl } from "../src/domain";
const time = "2026-11-13T01:00:00.000Z";
function event(ids: string[]) {
    return {
        fetchTime: time,
        numberOfChanges: ids.length,
        new: ids.map((id) => ({
            cveId: id,
            githubLink: cveUrl(id),
            dateUpdated: time,
        })),
        updated: [],
        error: [],
    };
}
test("streamed delta drains oversized events across bounded checkpoint batches", async () => {
    const raw = JSON.stringify([
        event(Array.from({ length: 10 }, (_, i) => `CVE-2026-${1234 + i}`)),
    ]);
    const one = await deltaBatch(new Response(raw).body, null);
    expect(one.batch.length).toBe(4);
    expect(one.caughtUp).toBe(false);
    const last = one.batch.at(-1);
    if (!last) throw new Error("missing batch");
    const two = await deltaBatch(new Response(raw).body, {
        event: time,
        offset: last.offset,
    });
    expect(two.batch[0]?.item.id).toBe("CVE-2026-1238");
    expect(two.caughtUp).toBe(false);
    const three = await deltaBatch(new Response(raw).body, {
        event: time,
        offset: 8,
    });
    expect(three.batch.length).toBe(2);
    expect(three.caughtUp).toBe(true);
});

test("production batch drains 128 changes before resuming from its last committed offset", async () => {
    const raw = JSON.stringify([
        event(Array.from({ length: 129 }, (_, i) => `CVE-2026-${1234 + i}`)),
    ]);

    const first = await deltaBatch(new Response(raw).body, null, 128);

    expect(first.batch).toHaveLength(128);
    expect(first.batch.at(-1)?.item.id).toBe("CVE-2026-1361");
    expect(first.caughtUp).toBe(false);

    const remaining = await deltaBatch(new Response(raw).body, { event: time, offset: 128 }, 128);

    expect(remaining.batch.map(({ item }) => item.id)).toEqual(["CVE-2026-1362"]);
    expect(remaining.caughtUp).toBe(true);
    await expect(deltaBatch(new Response(raw).body, null, 129)).rejects.toThrow("invalid delta batch limit");
});

test("malformed streams and missing replay history fail closed", async () => {
    await expect(
        deltaBatch(
            new Response(
                JSON.stringify([event(["CVE-2026-1234"])]).slice(0, -1),
            ).body,
            null,
        ),
    ).rejects.toThrow();
    await expect(
        deltaBatch(
            new Response(JSON.stringify([event(["CVE-2026-1234"])])).body,
            { event: "2026-10-01T00:00:00.000Z", offset: 0 },
        ),
    ).rejects.toThrow("continuity");
    await expect(
        deltaBatch(new Response('{"wrong":{}}').body, null),
    ).rejects.toThrow("root");
});

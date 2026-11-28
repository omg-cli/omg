import { JSONParser } from "@streamparser/json";
import { LIMITS, parseDelta, type DeltaItem } from "./domain";
export type Cursor = { event: string; offset: number };
export type Pending = { item: DeltaItem; offset: number };
export async function deltaBatch(
    body: ReadableStream<Uint8Array> | null,
    cursor: Cursor | null,
    limit = LIMITS.deltaRecords,
) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 128)
        throw new Error("invalid delta batch limit");
    if (!body) throw new Error("missing delta body");
    const parser = new JSONParser({
        paths: ["$.*"],
        keepStack: false,
        stringBufferSize: 64 * 1024,
    });
    const candidates: Pending[] = [];
    let count = 0;
    let events = 0;
    const range: { oldest: string | null } = { oldest: null };
    let total = 0;
    let eventBytes = 0;
    parser.onValue = ({ value, parent, key }) => {
        if (!Array.isArray(parent) || typeof key !== "number")
            throw new Error("invalid delta root");
        eventBytes = 0;
        events++;
        if (events > 100_000) throw new Error("too many delta events");
        const entries = parseDelta(JSON.stringify([value]));
        let event = "";
        let offset = 0;
        for (const item of entries) {
            range.oldest =
                range.oldest === null || item.event < range.oldest
                    ? item.event
                    : range.oldest;
            if (item.event !== event) {
                event = item.event;
                offset = 0;
            }
            offset++;
            if (
                cursor &&
                (item.event < cursor.event ||
                    (item.event === cursor.event && offset <= cursor.offset))
            )
                continue;
            count++;
            const entry: Pending = { item, offset };
            let low = 0;
            let high = candidates.length;
            while (low < high) {
                const mid = (low + high) >>> 1;
                const current = candidates[mid]!.item;
                const cmp =
                    item.event < current.event
                        ? -1
                        : item.event > current.event
                          ? 1
                          : item.id < current.id
                            ? -1
                            : item.id > current.id
                              ? 1
                              : 0;
                if (cmp < 0) high = mid;
                else low = mid + 1;
            }
            if (low < limit) {
                candidates.splice(low, 0, entry);
                if (candidates.length > limit) candidates.pop();
            }
        }
    };
    const reader = body.getReader();
    try {
        while (true) {
            const chunk = await reader.read();
            if (chunk.done) break;
            total += chunk.value.byteLength;
            eventBytes += chunk.value.byteLength;
            if (total > 64 * 1024 * 1024 || eventBytes > 8 * 1024 * 1024) {
                await reader.cancel();
                throw new Error("delta stream exceeds budget");
            }
            parser.write(chunk.value);
        }
        if (!parser.isEnded) parser.end();
    } catch (error) {
        await reader.cancel();
        throw error;
    } finally {
        reader.releaseLock();
    }
    if (range.oldest === null)
        throw new Error("empty delta log cannot prove continuity");
    if (cursor && cursor.event < range.oldest)
        throw new Error(
            "delta continuity lost; baseline reconciliation required",
        );
    return { batch: candidates, caughtUp: count <= limit };
}

import {
    LIMITS,
    SOURCES,
    boundedBody,
    parseArch,
    parseKev,
    sha256,
    object,
    string,
    date,
    type Feed,
} from "./domain";
import { Store, type Command } from "./storage";
import { deltaBatch } from "./delta";
export type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;
export async function upstream(
    url: string,
    etag: string | null,
    fetcher: Fetcher,
): Promise<Response> {
    const response = await fetcher(url, {
        headers: etag ? { "If-None-Match": etag } : {},
        redirect: "manual",
        signal: AbortSignal.timeout(20_000),
    });
    if (response.status !== 304 && !response.ok)
        throw new Error(`upstream HTTP ${response.status}`);
    return response;
}
export async function refreshSnapshot(
    store: Store,
    source: "arch" | "kev",
    fetcher: Fetcher,
    now: string,
) {
    const checkpoint = await store.checkpoint(source);
    if (!checkpoint) throw new Error("missing migration");
    const response = await upstream(SOURCES[source], checkpoint.etag, fetcher);
    if (response.status === 304) {
        if (!checkpoint.object_key)
            throw new Error("304 without stored snapshot");
        await store.sql.batch([
            {
                sql: "UPDATE source_checkpoint SET checked_at=?,complete=1,error=NULL WHERE source=?",
                values: [now, source],
            },
        ]);
        return;
    }
    const raw = await boundedBody(response.body, LIMITS.feed);
    const revision = source === "arch" ? now : parseKev(raw).revision;
    if (source === "arch") parseArch(raw);
    if (
        source === "kev" &&
        checkpoint.revision &&
        revision < checkpoint.revision
    )
        throw new Error("KEV revision rollback");
    const hash = await sha256(raw);
    const key = `${source}/${hash}.json`;
    if (checkpoint.payload_sha256 !== hash) await store.raw.put(key, raw);
    const annotations: Command[] = [];
    if (source === "kev" && checkpoint.payload_sha256 !== hash) {
        const entries = JSON.stringify(parseKev(raw).entries);
        if (new TextEncoder().encode(entries).byteLength > 1_900_000)
            throw new Error("KEV annotations exceed D1 string budget");
        annotations.push(
            { sql: "DELETE FROM kev_annotation", values: [] },
            {
                sql: "INSERT INTO kev_annotation(cve_id,payload_json,catalog_sha256) SELECT json_extract(value,'$.cveID'),value,? FROM json_each(?)",
                values: [hash, entries],
            },
        );
    }
    await store.sql.batch([
        ...annotations,
        {
            sql: "UPDATE source_checkpoint SET checked_at=?,fetched_at=?,etag=?,complete=1,bootstrap_complete=1,error=NULL,object_key=?,payload_sha256=?,revision=? WHERE source=?",
            values: [
                now,
                now,
                response.headers.get("etag"),
                key,
                hash,
                revision,
                source,
            ],
        },
    ]);
}
export async function refreshCves(
    store: Store,
    fetcher: Fetcher,
    now: string,
    batchSize = LIMITS.deltaRecords,
) {
    const checkpoint = await store.checkpoint("cve");
    if (!checkpoint) throw new Error("missing migration");
    const response = await upstream(
        SOURCES.cve,
        checkpoint.complete ? checkpoint.etag : null,
        fetcher,
    );
    if (response.status === 304) {
        await store.sql.batch([
            {
                sql: "UPDATE source_checkpoint SET checked_at=?,error=NULL WHERE source=?",
                values: [now, "cve"],
            },
        ]);
        return;
    }
    let cursor: { event: string; offset: number } | null = null;
    if (checkpoint.cursor) {
        const parsed = object(JSON.parse(checkpoint.cursor));
        cursor = { event: date(parsed.event), offset: Number(parsed.offset) };
        if (!Number.isSafeInteger(cursor.offset) || cursor.offset < 0)
            throw new Error("invalid cursor");
    }
    const { batch, caughtUp } = await deltaBatch(
        response.body,
        cursor,
        batchSize,
    );
    for (const { item } of batch) {
        const record = await upstream(item.url, null, fetcher);
        await store.cve(
            await boundedBody(record.body, LIMITS.cveRecord),
            now,
            item.id,
        );
    }
    const last = batch.at(-1);
    const nextCursor = last
        ? JSON.stringify({ event: last.item.event, offset: last.offset })
        : checkpoint.cursor;
    await store.sql.batch([
        {
            sql: "UPDATE source_checkpoint SET cursor=?,checked_at=?,fetched_at=?,etag=?,complete=?,error=NULL WHERE source=?",
            values: [
                nextCursor,
                now,
                now,
                caughtUp ? response.headers.get("etag") : null,
                Number(caughtUp),
                "cve",
            ],
        },
    ]);
}
export async function refresh(
    store: Store,
    fetcher: Fetcher,
    now = new Date().toISOString(),
    batchSize = LIMITS.deltaRecords,
) {
    for (const source of ["arch", "kev", "cve"] satisfies Feed[]) {
        const owner = crypto.randomUUID();
        if (!(await store.lease(source, owner, now))) continue;
        const writer = store.writer(source, owner);
        await writer.sql.batch([
            {
                sql: "INSERT INTO ingestion_run(id,source,started_at) VALUES(?,?,?)",
                values: [owner, source, now],
            },
        ]);
        try {
            if (source === "cve")
                await refreshCves(writer, fetcher, now, batchSize);
            else await refreshSnapshot(writer, source, fetcher, now);
            await writer.sql.batch([
                {
                    sql: "UPDATE ingestion_run SET finished_at=? WHERE id=?",
                    values: [now, owner],
                },
            ]);
        } catch (error) {
            const message =
                error instanceof Error
                    ? error.message.slice(0, 200)
                    : "ingestion failed";
            await writer.sql.batch([
                {
                    sql: "UPDATE source_checkpoint SET error=?,complete=0 WHERE source=?",
                    values: [message, source],
                },
                {
                    sql: "UPDATE ingestion_run SET finished_at=?,error=? WHERE id=?",
                    values: [now, message, owner],
                },
            ]);
            console.error(
                JSON.stringify({
                    event: "ingestion_failed",
                    source,
                    error: message,
                }),
            );
        } finally {
            await store.release(source, owner);
        }
    }
    await store.sql.batch([
        {
            sql: "DELETE FROM ingestion_run WHERE started_at < ?",
            values: [
                new Date(Date.parse(now) - 7 * 24 * 60 * 60_000).toISOString(),
            ],
        },
    ]);
}
export function parseBatch(value: unknown): string[] {
    const batch = object(value);
    if (
        batch.source !== "cve" ||
        !Array.isArray(batch.records) ||
        batch.records.length === 0 ||
        batch.records.length > LIMITS.records
    )
        throw new Error("invalid ingest batch");
    return batch.records.map((item) => string(item));
}

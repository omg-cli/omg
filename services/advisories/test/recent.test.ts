import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { handle } from "../src/service";
import { Store, type Sql, type Command } from "../src/storage";
import { object } from "../src/domain";
import { cachedRead } from "../src/cache";

const now = "2026-11-16T12:00:00.000Z";
function setup() {
    const db = new Database(":memory:");
    for (const name of ["0001_advisories.sql", "0002_baseline_member_counter.sql", "0003_recent_cves.sql", "0006_baseline_publisher_proof.sql"])
        db.exec(readFileSync(new NodeURL(`../migrations/${name}`, import.meta.url), "utf8"));
    const sql: Sql = {
        first: async <T>(query: string, values: (string | number | null)[] = []) =>
            db.query<T, (string | number | null)[]>(query).get(...values),
        all: async <T>(query: string, values: (string | number | null)[] = []) =>
            db.query<T, (string | number | null)[]>(query).all(...values),
        batch: async (commands: Command[]) => {
            db.transaction(() => {
                for (const command of commands) db.query(command.sql).run(...command.values);
            })();
        },
    };
    const objects = new Map<string, string>();
    const store = new Store(sql, {
        put: async (key, value) => { objects.set(key, value); },
        get: async (key) => {
            const value = objects.get(key);
            return value === undefined ? null : { text: async () => value };
        },
    });
    db.query("UPDATE source_checkpoint SET checked_at=?,complete=1,bootstrap_complete=1").run(now);
    const get = (path: string, headers?: HeadersInit, time = now) =>
        handle(new Request(`https://advisories.example${path}`, { headers }), store, undefined, time);
    const add = (id: string, modified: string, state = "PUBLISHED") => store.cve(JSON.stringify({
        dataType: "CVE_RECORD", dataVersion: "5.2",
        cveMetadata: { cveId: id, state, dateUpdated: modified, datePublished: modified }, containers: { cna: {} },
    }), now);
    return { db, store, get, add };
}

test("recent CVEs paginate tied revisions in a fixed rolling window and retain old records", async () => {
    const { get, add, db } = setup();
    for (const id of ["CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002"])
        await add(id, "2026-11-15T00:00:00Z");
    await add("CVE-2020-1000", "2026-10-16T12:00:00Z");
    await add("CVE-2026-1003", "2026-10-17T12:00:00Z", "REJECTED");
    await add("CVE-2026-1004", "2026-11-17T00:00:00Z");
    const first = await get("/v1/cves/recent?limit=2");
    expect(first.status).toBe(200);
    const body = object(await first.json());
    expect(body).toMatchObject({ complete: true, as_of: now, window_start: "2026-10-17T12:00:00.000Z" });
    expect(body.records).toMatchObject([{ id: "CVE-2026-1002" }, { id: "CVE-2026-1001" }]);
    expect(typeof body.next_cursor).toBe("string");
    const next = object(await (await get(`/v1/cves/recent?limit=2&cursor=${encodeURIComponent(String(body.next_cursor))}`, undefined, "2026-11-16T12:01:00.000Z")).json());
    expect(next.as_of).toBe(now);
    expect(next.records).toMatchObject([{ id: "CVE-2026-1000" }, { id: "CVE-2026-1003", state: "REJECTED" }]);
    expect(next.next_cursor).toBeNull();
    expect((await get("/v1/cves/CVE-2020-1000")).status).toBe(200);
    expect(db.query("SELECT COUNT(*) AS n FROM source_record").get()).toEqual({ n: 6 });
});

test("recent CVEs reject malformed bounds and cursors and expose incomplete sources", async () => {
    const { get, db } = setup();
    for (const query of ["limit=0", "limit=101", "limit=01", "limit=1&limit=2", "days=300", "cursor=oops", "cursor=" + "a".repeat(1025)])
        expect((await get(`/v1/cves/recent?${query}`)).status).toBe(400);
    const future = btoa(JSON.stringify({ as_of: "2027-01-01T00:00:00.000Z", modified_at: now, id: "CVE-2026-1000" }));
    expect((await get(`/v1/cves/recent?cursor=${encodeURIComponent(future)}`)).status).toBe(400);
    db.exec("UPDATE source_checkpoint SET bootstrap_complete=0 WHERE source='cve'");
    expect(object(await (await get("/v1/cves/recent")).json()).complete).toBe(false);
});

test("public CVE reads support representation ETags but never cache private or stale responses", async () => {
    const { get, add, db } = setup();
    await add("CVE-2026-1000", now);
    const first = await get("/v1/cves/CVE-2026-1000");
    expect(first.headers.get("cache-control")).toBe("public, max-age=60, must-revalidate");
    const etag = first.headers.get("etag");
    expect(etag).toMatch(/^"[a-f0-9]{64}"$/);
    expect((await get("/v1/cves/CVE-2026-1000", { "if-none-match": String(etag) })).status).toBe(304);
    db.query("INSERT INTO kev_annotation VALUES(?,?,?)").run("CVE-2026-1000", '{"cveID":"CVE-2026-1000"}', "a".repeat(64));
    const changed = await get("/v1/cves/CVE-2026-1000", { "if-none-match": String(etag) });
    expect(changed.status).toBe(200);
    expect(changed.headers.get("etag")).not.toBe(etag);
    const near = await get("/v1/cves/CVE-2026-1000", undefined, "2026-11-16T12:29:50.000Z");
    expect(near.headers.get("cache-control")).toBe("public, max-age=10, must-revalidate");
    for (const response of [
        await get("/v1/status"), await get("/v1/cves/CVE-2026-9999"),
        await get("/internal/ingest"), await get("/v1/cves/CVE-2026-1000", { authorization: "Bearer private" }),
        await get("/v1/cves/CVE-2026-1000", undefined, "2026-11-16T12:30:01.000Z"),
    ]) expect(response.headers.get("cache-control")).toBe("no-store");
});

test("an edge entry expires before its freshness claim and cache failure falls back to origin", async () => {
    const request = new Request("https://advisories.example/v1/cves/CVE-2026-1000");
    const milliseconds = Date.parse(now);
    const entry = new Response("cached", { headers: { Expires: new Date(milliseconds + 1000).toUTCString() } });
    let loads = 0;
    const load = async () => { loads++; return new Response("origin"); };
    const cache = { match: async () => entry.clone(), put: async () => {} };
    expect(await (await cachedRead(request, cache, load, milliseconds)).text()).toBe("cached");
    expect(loads).toBe(0);
    expect(await (await cachedRead(request, cache, load, milliseconds + 1000)).text()).toBe("origin");
    expect(loads).toBe(1);
    const unavailable = { ...cache, match: async (): Promise<Response> => { throw new Error("fixture cache unavailable"); } };
    expect(await (await cachedRead(request, unavailable, load, milliseconds)).text()).toBe("origin");
    expect(loads).toBe(2);
});

test("edge cache keys stay on the request origin and bound the URL sent to cache storage", async () => {
    const origin = "https://advisories.example";
    const request = new Request(`${origin}/v1/cves/recent?limit=2`);
    const anotherPage = new Request(`${origin}/v1/cves/recent?limit=3`);
    const preview = new Request("http://[::1]:8787/v1/cves/recent?limit=2");
    const oversized = new Request(`${origin}/v1/cves/recent?cursor=${"a".repeat(8192)}`);
    const oversizedHost = new Request(`https://${"a".repeat(254)}/v1/cves/recent`);
    const unsupportedHost = new Request("https://under_score.example/v1/cves/recent");
    const reads: string[] = [];
    const writes: string[] = [];
    const loads: string[] = [];
    const cache: Pick<Cache, "match" | "put"> = {
        match: async (key) => {
            reads.push(new Request(key).url);
            return undefined;
        },
        put: async (key) => { writes.push(new Request(key).url); },
    };
    const load = async (input: Request) => {
        loads.push(input.url);
        return new Response(input.url, { headers: { "Cache-Control": "public, max-age=60" } });
    };
    const requests = [request, anotherPage, preview, oversized, oversizedHost, unsupportedHost];
    for (const input of requests)
        expect(await (await cachedRead(input, cache, load)).text()).toBe(input.url);
    expect(loads).toEqual(requests.map((input) => input.url));
    expect(reads).toEqual(writes);
    expect(reads).toHaveLength(3);
    expect(reads[0]).toMatch(/^https:\/\/advisories\.example\/\.omg\/advisory-cache\/v1\/[a-f0-9]{64}$/);
    expect(reads[1]).not.toBe(reads[0]);
    expect(reads[2]).toMatch(/^http:\/\/\[::1\]:8787\/\.omg\/advisory-cache\/v1\/[a-f0-9]{64}$/);
});

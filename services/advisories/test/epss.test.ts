import { test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { Store, type Sql, type Command } from "../src/storage";
import { epss } from "../src/epss";
import { handle } from "../src/service";
import { object } from "../src/domain";

const id = "CVE-2021-23337";
const now = "2026-11-17T02:00:00.000Z";
function setup() {
    const db = new Database(":memory:");
    for (const name of ["0001_advisories.sql", "0004_epss_cache.sql"])
        db.exec(readFileSync(new NodeURL(`../migrations/${name}`, import.meta.url), "utf8"));
    const sql: Sql = {
        first: async <T>(text: string, values: (string | number | null)[] = []) => db.query<T, (string | number | null)[]>(text).get(...values),
        all: async <T>(text: string, values: (string | number | null)[] = []) => db.query<T, (string | number | null)[]>(text).all(...values),
        batch: async (commands: Command[]) => { db.transaction(() => { for (const command of commands) db.query(command.sql).run(...command.values); })(); },
    };
    db.exec(`INSERT INTO source_record VALUES('${id}','cve','https://example.test','5.2','PUBLISHED',NULL,'${now}','${now}','hash','key',1,1)`);
    let clock = now;
    return { db, store: new Store(sql, { put: async () => {}, get: async () => null }, () => clock), setClock: (value: string) => { clock = value; } };
}
function payload(score = "0.000000000") {
    return { status: "OK", "status-code": 200, total: 1, offset: 0, data: [{ cve: id, epss: score, percentile: "0.100000000", date: "2026-11-16", "time-series": [{ epss: "0.2", percentile: "0.9", date: "2026-11-15" }] }] };
}
test("EPSS caches genuine zero scores and bounded history in real SQLite", async () => {
    const { store, db } = setup();
    try {
        let calls = 0;
        const fetcher = async (url: string, init?: RequestInit) => {
            calls++;
            expect(url).toBe(`https://api.first.org/data/v1/epss?cve=${id}&scope=time-series`);
            expect(init?.redirect).toBe("manual");
            expect(init?.signal).toBeDefined();
            return Response.json(payload());
        };
        const first = await epss(store, id, now, fetcher);
        expect(first.status).toBe("scored");
        expect(first.score?.epss).toBe(0);
        expect(first.history.length).toBe(2);
        expect(await epss(store, id, now, fetcher)).toEqual(first);
        expect(calls).toBe(1);
        expect(db.query("SELECT count(*) AS n FROM epss_cache").get()).toEqual({ n: 1 });
    } finally { db.close(); }
});
test("missing EPSS scores and transport failures never become zero", async () => {
    for (const missing of [true, false]) {
        const { store, db } = setup();
        try {
            const result = await epss(store, id, now, async () => missing ? Response.json({ status: "OK", "status-code": 200, total: 0, offset: 0, data: [] }) : new Response(null, { status: 503 }));
            expect(result.status).toBe(missing ? "missing" : "unavailable");
            expect(result.score).toBeNull();
            expect(result.history).toEqual([]);
        } finally { db.close(); }
    }
});
test("malformed, mismatched, partial and future EPSS evidence is unavailable", async () => {
    for (const change of ["id", "score", "future", "duplicate", "partial", "oversize"]) {
        const { store, db } = setup();
        try {
            const value = payload();
            const row = value.data[0];
            if (!row) throw new Error("missing fixture row");
            if (change === "id") row.cve = "CVE-2021-99999";
            if (change === "score") row.epss = "NaN";
            if (change === "future") row.date = "2026-11-18";
            if (change === "duplicate") row["time-series"].push({ epss: "0.2", percentile: "0.9", date: "2026-11-15" });
            if (change === "partial") value.total = 2;
            const result = await epss(store, id, now, async () => change === "oversize" ? new Response("x".repeat(64 * 1024 + 1)) : Response.json(value));
            expect(result.status).toBe("unavailable");
            expect(result.score).toBeNull();
        } finally { db.close(); }
    }
});
test("failed refresh preserves last history, backs off and recovers", async () => {
    const { store, db, setClock } = setup();
    try {
        await epss(store, id, now, async () => Response.json(payload("0.25")));
        const later = "2026-11-17T09:00:00.000Z";
        setClock(later);
        let calls = 0;
        const unavailable = async () => { calls++; throw new Error("offline"); };
        const failed = await epss(store, id, later, unavailable);
        expect(failed.status).toBe("unavailable");
        expect(failed.score).toBeNull();
        expect(failed.history[0]?.epss).toBe(0.25);
        await epss(store, id, later, unavailable);
        expect(calls).toBe(1);
        const recoveredAt = "2026-11-17T09:02:00.000Z";
        setClock(recoveredAt);
        expect((await epss(store, id, recoveredAt, async () => Response.json(payload("0.4")))).score?.epss).toBe(0.4);
    } finally { db.close(); }
});
test("unknown CVEs do not trigger upstream lookups or cache writes", async () => {
    const { store, db } = setup();
    try {
        await expect(epss(store, "CVE-2026-9999999", now, async () => { throw new Error("must not fetch"); })).rejects.toThrow("CVE unavailable");
        expect(db.query("SELECT count(*) AS n FROM epss_cache").get()).toEqual({ n: 0 });
    } finally { db.close(); }
});
test("EPSS history rolls at thirty days and stale scores stay unavailable", async () => {
    const { store, db, setClock } = setup();
    try {
        const value = payload("0.3");
        const row = value.data[0];
        if (!row) throw new Error("missing fixture row");
        row.date = "2026-11-17";
        row["time-series"] = Array.from({ length: 30 }, (_, index) => ({ epss: "0.2", percentile: "0.9", date: new Date(Date.parse("2026-11-17T00:00:00Z") - (index + 1) * 86400000).toISOString().slice(0, 10) }));
        const first = await epss(store, id, now, async () => Response.json(value));
        expect(first.history.length).toBe(30);
        expect(first.history.at(-1)?.date).toBe("2026-10-19");
        const later = "2026-11-20T02:00:00.000Z";
        setClock(later);
        const stale = await epss(store, id, later, async () => Response.json(value));
        expect(stale.status).toBe("unavailable");
        expect(stale.score).toBeNull();
        expect(stale.history.at(-1)?.date).toBe("2026-10-22");
    } finally { db.close(); }
});
test("EPSS refresh respects another writer and rejects an expired lease atomically", async () => {
    const { store, db, setClock } = setup();
    try {
        expect(await store.lease(`epss:${id}`, "other", now)).toBeTrue();
        let calls = 0;
        const fetcher = async () => { calls++; return Response.json(payload("0.25")); };
        expect((await epss(store, id, now, fetcher)).status).toBe("unavailable");
        expect(calls).toBe(0);
        await store.release(`epss:${id}`, "other");
        await epss(store, id, now, fetcher);
        const previous = db.query("SELECT * FROM epss_cache").get();
        const later = "2026-11-17T09:00:00.000Z";
        setClock(later);
        await expect(epss(store, id, later, async () => {
            setClock("2026-11-17T09:11:00.000Z");
            return Response.json(payload("0.5"));
        })).rejects.toThrow();
        expect(db.query("SELECT * FROM epss_cache").get()).toEqual(previous);
    } finally { db.close(); }
});
test("EPSS HTTP routing supports ETags and rejects invalid queries without upstream work", async () => {
    const { store, db } = setup();
    try {
        let calls = 0;
        const fetcher = async () => { calls++; return Response.json(payload("0.25")); };
        const url = `https://advisories.example/v1/epss/${id}`;
        const response = await handle(new Request(url), store, undefined, now, fetcher);
        expect(response.status).toBe(200);
        expect(object(await response.json()).status).toBe("scored");
        expect(response.headers.get("Cache-Control")).toContain("public");
        const etag = response.headers.get("ETag");
        if (!etag) throw new Error("missing EPSS ETag");
        const conditional = await handle(new Request(url, { headers: { "If-None-Match": etag } }), store, undefined, now, fetcher);
        expect(conditional.status).toBe(304);
        expect(await conditional.text()).toBe("");
        const invalid = await handle(new Request(`${url}?cve=other`), store, undefined, now, fetcher);
        expect(invalid.status).toBe(400);
        expect(invalid.headers.get("Cache-Control")).toBe("no-store");
        db.exec("UPDATE epss_cache SET error=1");
        const unavailable = await handle(new Request(url), store, undefined, now, fetcher);
        expect(object(await unavailable.json()).status).toBe("unavailable");
        expect(unavailable.headers.get("Cache-Control")).toBe("no-store");
        expect(calls).toBe(1);
    } finally { db.close(); }
});

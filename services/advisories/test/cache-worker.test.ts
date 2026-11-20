import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { unstable_splitSqlQuery } from "wrangler";
import { Store, d1Sql, type Sql } from "../src/storage";
import { recentCves } from "../src/recent";
import { object } from "../src/domain";

test("real Worker caches public reads, isolates private reads and uses indexed recent pages", async () => {
    const build = await Bun.build({
        entrypoints: [fileURLToPath(new NodeURL("../src/index.ts", import.meta.url))], target: "browser",
    });
    expect(build.success).toBe(true);
    const output = build.outputs[0];
    if (!output) throw new Error("missing Worker bundle");
    const runtime = new Miniflare(convertV4MiniflareOptions({
        modules: true, script: await output.text(), compatibilityDate: "2026-11-13",
        d1Databases: ["DB"], r2Buckets: ["RAW"],
        bindings: { CVE_BATCH_SIZE: "32" },
    }));
    try {
        const db = await runtime.getD1Database("DB");
        for (const name of ["0001_advisories.sql", "0002_baseline_member_counter.sql", "0004_epss_cache.sql", "0006_baseline_publisher_proof.sql"]) {
            const source = await readFile(new NodeURL(`../migrations/${name}`, import.meta.url), "utf8");
            await db.batch(unstable_splitSqlQuery(source).map((query) => db.prepare(query)));
        }
        const raw = await runtime.getR2Bucket("RAW");
        const sql = d1Sql(db);
        const store = new Store(sql, raw);
        const now = new Date().toISOString();
        await db.prepare("UPDATE source_checkpoint SET checked_at=?,complete=1,bootstrap_complete=1").bind(now).run();
        const id = "CVE-2026-9999";
        await store.cve(JSON.stringify({
            dataType: "CVE_RECORD", dataVersion: "5.2",
            cveMetadata: { cveId: id, state: "PUBLISHED", dateUpdated: now, datePublished: now },
            containers: { cna: {} },
        }), now);
        const worker = await runtime.getWorker();
        const url = `https://advisories.example/v1/cves/${id}`;
        const first = await worker.fetch(url);
        expect(first.status).toBe(200);
        expect(first.headers.get("cache-control")).toMatch(/^public, max-age=\d+, must-revalidate$/);
        const tag = first.headers.get("etag");
        expect(object(await first.json()).kev).toBeNull();
        await db.prepare("INSERT INTO kev_annotation VALUES(?,?,?)").bind(id, JSON.stringify({ cveID: id }), "a".repeat(64)).run();
        const hit = await worker.fetch(url);
        expect(object(await hit.json()).kev).toBeNull();
        expect((await worker.fetch(url, { headers: { "if-none-match": String(tag) } })).status).toBe(304);
        const bypass = await worker.fetch(url, { headers: { authorization: "Bearer private" } });
        expect(bypass.headers.get("cache-control")).toBe("no-store");
        expect(object(await bypass.json()).kev).toEqual({ cveID: id });
        const refreshed = await worker.fetch(url, { headers: { "cache-control": "no-cache" } });
        expect(object(await refreshed.json()).kev).toEqual({ cveID: id });
        expect(refreshed.headers.get("etag")).not.toBe(tag);
        expect((await worker.fetch("https://advisories.example/v1/status")).headers.get("cache-control")).toBe("no-store");

        await db.prepare("INSERT INTO epss_cache VALUES(?,?,?,?,0)").bind(id, now, now, JSON.stringify({
            status: "OK", "status-code": 200, total: 1, offset: 0,
            data: [{ cve: id, epss: "0.25", percentile: "0.9", date: now.slice(0, 10), "time-series": [] }],
        })).run();
        const epssUrl = `https://advisories.example/v1/epss/${id}`;
        const scored = await worker.fetch(epssUrl);
        const epssTag = scored.headers.get("etag");
        expect(object(await scored.json()).status).toBe("scored");
        expect(scored.headers.get("cache-control")).toContain("public");
        expect((await worker.fetch(epssUrl, { headers: { "if-none-match": String(epssTag) } })).status).toBe(304);
        await db.prepare("UPDATE epss_cache SET error=1 WHERE cve_id=?").bind(id).run();
        expect(object(await (await worker.fetch(epssUrl)).json()).status).toBe("scored");
        const failedEpss = object(await (await worker.fetch(epssUrl, { headers: { "cache-control": "no-cache" } })).json());
        expect(failedEpss.status).toBe("unavailable");
        expect(failedEpss.score).toBeNull();

        await db.prepare("INSERT INTO source_record SELECT 'CVE-2020-'||(1000+value),'cve','https://example.invalid','5.2','PUBLISHED','2020-01-01T00:00:00.000Z','2020-01-01T00:00:00.000Z',?,'hash','fixture',1,1 FROM json_each(?)")
            .bind(now, JSON.stringify(Array.from({ length: 4096 }, (_, n) => n))).run();
        const migration = await readFile(new NodeURL("../migrations/0003_recent_cves.sql", import.meta.url), "utf8");
        const index = await db.prepare(migration).run();
        let rowsRead = 0;
        const measured: Sql = { ...sql, all: async <T>(query: string, values: (string | number | null)[] = []) => {
            const result = await db.prepare(query).bind(...values).all<T>();
            rowsRead += result.meta.rows_read;
            return result.results;
        } };
        const page = await recentCves(new URL("https://advisories.example/v1/cves/recent?limit=2"), measured, now);
        expect(page.records.map((record) => record.id)).toEqual([id]);
        expect(rowsRead).toBeLessThanOrEqual(12);
        process.stdout.write(`recent D1 page: ${JSON.stringify({ totalRecords: 4097, returned: page.records.length, rowsRead, migrationRowsRead: index.meta.rows_read, migrationRowsWritten: index.meta.rows_written })}\n`);
        await db.prepare("UPDATE source_checkpoint SET bootstrap_complete=0 WHERE source='cve'").run();
        await store.cve(JSON.stringify({
            dataType: "CVE_RECORD", dataVersion: "5.2",
            cveMetadata: { cveId: "CVE-2026-10000", state: "PUBLISHED", dateUpdated: now, datePublished: now },
            containers: { cna: {} },
        }), now);
        const recentUrl = "https://advisories.example/v1/cves/recent";
        const recent = await worker.fetch(recentUrl);
        expect(object(await recent.json())).toMatchObject({
            complete: false, records: [{ id }, { id: "CVE-2026-10000" }],
        });
        // These requests have the same pathname and different public representations.
        const narrowerUrl = `${recentUrl}?limit=1`;
        const narrower = await worker.fetch(narrowerUrl);
        expect(narrower.status).toBe(200);
        expect(narrower.headers.get("etag")).not.toBe(recent.headers.get("etag"));
        expect(object(await narrower.json())).toMatchObject({ records: [{ id }] });
        const conditional = await worker.fetch(narrowerUrl, {
            headers: { "if-none-match": String(narrower.headers.get("etag")) },
        });
        expect(conditional.status).toBe(304);
        const invalidPage = await worker.fetch(`${recentUrl}?limit=0`);
        expect(invalidPage.status).toBe(400);
        expect(invalidPage.headers.get("cache-control")).toBe("no-store");
    } finally {
        await runtime.dispose();
    }
}, 30_000);

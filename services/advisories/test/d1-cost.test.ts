import { expect, test } from "bun:test";
import { mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { unstable_splitSqlQuery } from "wrangler";
import { handle } from "../src/service";
import { d1Sql, Store, type Sql } from "../src/storage";
import { object } from "../src/domain";

const token = "baseline-cost-fixture-token-at-least-32-characters";
const now = "2026-11-13T02:00:00.000Z";

async function directoryBytes(path: string): Promise<number> {
    let bytes = 0;
    for (const entry of await readdir(path, { withFileTypes: true })) {
        const child = join(path, entry.name);
        bytes += entry.isDirectory() ? await directoryBytes(child) : (await stat(child)).size;
    }
    return bytes;
}

async function measureImport(count: number) {
    const scratch = await mkdtemp(join(tmpdir(), "omg-advisory-counter-cost-"));
    const runtime = new Miniflare(convertV4MiniflareOptions({
        modules: true,
        script: "export default { fetch() { return new Response('fixture'); } };",
        compatibilityDate: "2026-11-13",
        d1Databases: ["DB"],
        resourcePersistencePath: scratch,
    }));
    try {
        const db = await runtime.getD1Database("DB");
        const initial = await readFile(new URL("../migrations/0001_advisories.sql", import.meta.url).pathname, "utf8");
        await db.batch(unstable_splitSqlQuery(initial).map((statement) => db.prepare(statement)));
        const counter = await readFile(new URL("../migrations/0002_baseline_member_counter.sql", import.meta.url).pathname, "utf8");
        await db.batch(unstable_splitSqlQuery(counter).map((statement) => db.prepare(statement)));
        let rowsRead = 0;
        const measured = {
            prepare: db.prepare.bind(db),
            batch: async <T = unknown>(
                statements: D1PreparedStatement[],
            ): Promise<D1Result<T>[]> => {
                const result = await db.batch<T>(statements);
                rowsRead += result.reduce((sum, row) => sum + row.meta.rows_read, 0);
                return result;
            },
        } satisfies Pick<D1Database, "prepare" | "batch">;
        const sql = d1Sql(measured);
        const store = new Store(sql, { put: async () => {}, get: async () => null }, () => now);
        const post = async (path: string, payload: unknown) => {
            const response = await handle(new Request(`https://advisories.example${path}`, {
                method: "POST",
                headers: { authorization: `Bearer ${token}` },
                body: JSON.stringify(payload),
            }), store, token, now);
            expect(response.status).toBe(200);
            return object(await response.json());
        };
        const baseline = await post("/internal/baseline/start", { digest: "a".repeat(64), baseline_at: now });
        rowsRead = 0;
        for (let offset = 0; offset < count; offset += 8) {
            const records = Array.from({ length: Math.min(8, count - offset) }, (_, index) => JSON.stringify({
                dataType: "CVE_RECORD",
                dataVersion: "5.2",
                cveMetadata: {
                    cveId: `CVE-2026-${1000 + offset + index}`,
                    state: "PUBLISHED",
                    dateUpdated: now,
                    datePublished: now,
                },
                containers: { cna: {} },
            }));
            await post("/internal/ingest", { source: "cve", records, baseline });
        }
        const mutationRowsRead = rowsRead;
        const receipt = await db.prepare("SELECT accepted FROM baseline_receipt").first<{ accepted: number }>();
        expect(receipt?.accepted).toBe(count);
        let statusRows = 0;
        const statusSql: Sql = {
            ...sql,
            first: async <T>(query: string, values: (string | number | null)[] = []) => {
                const result = await db.prepare(query).bind(...values).all<T>();
                statusRows += result.meta.rows_read;
                return result.results[0] ?? null;
            },
            all: async <T>(query: string, values: (string | number | null)[] = []) => {
                const result = await db.prepare(query).bind(...values).all<T>();
                statusRows += result.meta.rows_read;
                return result.results;
            },
        };
        const status = await handle(new Request("https://advisories.example/v1/status"), new Store(statusSql, store.raw), undefined, now);
        const body = object(await status.json());
        expect(object(body.baseline).imported).toBe(count);
        expect(body.bootstrap_complete).toBe(false);
        const scratchBytes = await directoryBytes(scratch);
        expect(scratchBytes).toBeLessThanOrEqual(50 * 1024 ** 2);
        return { count, mutationRowsRead, statusRows, scratchBytes };
    } finally {
        try {
            await runtime.dispose();
        } finally {
            await rm(scratch, { recursive: true, force: true });
        }
    }
}

test("D1 baseline mutations have a linear read budget and status has a constant read budget", async () => {
    const small = await measureImport(128);
    const large = await measureImport(256);
    process.stdout.write(`D1 rows_read ${JSON.stringify({ small, large })}\n`);
    expect(small.mutationRowsRead).toBeLessThanOrEqual(32 * small.count);
    expect(large.mutationRowsRead).toBeLessThanOrEqual(32 * large.count);
    expect(large.mutationRowsRead).toBeLessThanOrEqual(2 * small.mutationRowsRead + 32);
    expect(small.statusRows).toBeLessThanOrEqual(16);
    expect(large.statusRows).toBeLessThanOrEqual(16);
}, 30_000);

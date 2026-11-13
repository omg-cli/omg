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

function largeCveFixture(id = "CVE-2026-1234", bytes = 2_402_038): string {
    const description = {lang: "en", value: "Generated structured CNA/ADP fixture; preserve UTF8 é and raw whitespace."};
    const payload = {
        dataType: "CVE_RECORD", dataVersion: "5.2",
        cveMetadata: {cveId: id, state: "PUBLISHED", dateUpdated: "2026-11-13T02:00:00.000Z", datePublished: "2026-11-11T00:00:00Z"},
        containers: {
            cna: {
                providerMetadata: {orgId: "00000000-0000-4000-8000-000000000001", shortName: "fixture-CNA"},
                descriptions: [description],
                affected: [{vendor: "fixture-vendor", product: "fixture-product", defaultStatus: "unaffected",
                    versions: Array.from({length: 11_000}, (_, index) => ({version: `${index}.0.0`, status: "affected", lessThan: `${index + 1}.0.0`, versionType: "semver"}))}],
            },
            adp: [{providerMetadata: {orgId: "00000000-0000-4000-8000-000000000002", shortName: "fixture-ADP"},
                affected: Array.from({length: 1_600}, (_, index) => ({vendor: `vendor-${index}`, product: `product-${index}`, versions: [{version: `${index}.1`, status: "affected"}]}))}],
        },
    };
    const encode = () => `\n${JSON.stringify(payload, null, 2)}\n`;
    const padding = bytes - Buffer.byteLength(encode());
    if (padding < 0) throw new Error("large CVE fixture structure exceeds requested byte size");
    description.value += "x".repeat(padding);
    const raw = encode();
    if (Buffer.byteLength(raw) !== bytes) throw new Error("large CVE fixture byte size mismatch");
    return raw;
}

test("real workerd route roundtrips a structured 2.4 MB CVE through private R2 and small D1 rows", async () => {
    const {sha256, string} = await import("../src/domain");
    const build = await Bun.build({entrypoints: [new URL("../src/index.ts", import.meta.url).pathname], target: "browser"});
    expect(build.success).toBe(true);
    const output = build.outputs[0];
    if (!output) throw new Error("missing bundled real Worker entrypoint");
    const scratch = await mkdtemp(join(tmpdir(), "omg-advisory-large-worker-"));
    const runtime = new Miniflare(convertV4MiniflareOptions({modules: true, script: await output.text(),
        compatibilityDate: "2026-11-13", d1Databases: ["DB"], r2Buckets: ["RAW"],
        bindings: {INGEST_TOKEN: token, CVE_BATCH_SIZE: "32"}, resourcePersistencePath: scratch}));
    try {
        const db = await runtime.getD1Database("DB");
        for (const name of ["0001_advisories.sql", "0002_baseline_member_counter.sql"]) {
            const source = await readFile(new URL(`../migrations/${name}`, import.meta.url).pathname, "utf8");
            await db.batch(unstable_splitSqlQuery(source).map((statement) => db.prepare(statement)));
        }
        const worker = await runtime.getWorker();
        const initialStatus = await worker.fetch("https://advisories.example/v1/status");
        expect(initialStatus.status).toBe(200);
        expect(object(await initialStatus.json()).bootstrap_complete).toBe(false);
        const raw = largeCveFixture();
        const hash = await sha256(raw);
        const wire = JSON.stringify({source: "cve", records: [raw]});
        expect(Buffer.byteLength(raw)).toBe(2_402_038);
        expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(4 * 1024 ** 2);
        const started = performance.now();
        const imported = await worker.fetch("https://advisories.example/internal/ingest", {method: "POST", headers: {authorization: `Bearer ${token}`}, body: wire});
        expect(imported.status).toBe(200);
        const response = await worker.fetch("https://advisories.example/v1/cves/CVE-2026-1234");
        expect(response.status).toBe(200);
        const encodedResponse = await response.text();
        expect(Buffer.byteLength(encodedResponse)).toBeLessThanOrEqual(4 * 1024 ** 2);
        const body = object(JSON.parse(encodedResponse));
        expect(string(body.payload_json)).toBe(raw);
        expect(await sha256(string(body.payload_json))).toBe(hash);
        expect(object(body.provenance).payload_sha256).toBe(hash);
        expect(body.package_applicability).toBe("unknown");
        const row = await db.prepare("SELECT *,length(id)+length(source)+length(source_url)+length(schema_version)+length(state)+length(published_at)+length(modified_at)+length(fetched_at)+length(payload_sha256)+length(object_key) AS scalar_bytes FROM source_record").first<{object_key: string; payload_sha256: string; scalar_bytes: number}>();
        if (!row) throw new Error("large CVE metadata pointer missing");
        expect(row.payload_sha256).toBe(hash);
        expect(row.scalar_bytes).toBeLessThan(1024);
        const bucket = await runtime.getR2Bucket("RAW");
        expect(await (await bucket.get(row.object_key))?.text()).toBe(raw);
        const over = JSON.stringify({source: "cve", records: [largeCveFixture("CVE-2026-1235", 3 * 1024 ** 2 + 1)]});
        expect(Buffer.byteLength(over)).toBeLessThan(4 * 1024 ** 2);
        const refused = await worker.fetch("https://advisories.example/internal/ingest", {method: "POST", headers: {authorization: `Bearer ${token}`}, body: over});
        expect(refused.status).toBe(400);
        expect(await db.prepare("SELECT id FROM source_record WHERE id=?").bind("CVE-2026-1235").first()).toBe(null);
        const status = object(await (await worker.fetch("https://advisories.example/v1/status")).json());
        expect(status.bootstrap_complete).toBe(false);
        const scratchBytes = await directoryBytes(scratch);
        expect(scratchBytes).toBeLessThanOrEqual(50 * 1024 ** 2);
        process.stdout.write(`large CVE real workerd ${JSON.stringify({rawBytes: Buffer.byteLength(raw), wireBytes: Buffer.byteLength(wire), responseBytes: Buffer.byteLength(encodedResponse), scalarBytes: row.scalar_bytes, scratchBytes, routeWallMilliseconds: performance.now() - started, cpuAndIsolateRss: "not measured by this binding test"})}\n`);
    } finally {
        try {
            await runtime.dispose();
        } finally {
            await rm(scratch, {recursive: true, force: true});
        }
    }
}, 30_000);

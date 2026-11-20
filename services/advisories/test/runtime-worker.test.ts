import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { unstable_splitSqlQuery } from "wrangler";
import { ZipWriter, Uint8ArrayWriter, TextReader } from "@zip.js/zip.js/lib/zip-core-native.js";

test("real Worker parses vendor ZIP/YAML, persists D1/R2 evidence and never HTTP-caches partial coverage", async () => {
    const jobToken = `ghs_12345_fixture.header-${"a".repeat(475)}.signature_fixture`;
    const zip = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false, useCompressionStream: true, level: 6 });
    await zip.add(`ruby-advisory-db-${"a".repeat(40)}/rubies/ruby/CVE-2026-12345.yml`, new TextReader('cve: "2026-12345"\ntitle: Interpreter vulnerability\npatched_versions:\n  - ">= 3.2.1"\n'));
    await zip.add(`ruby-advisory-db-${"a".repeat(40)}/rubies/ruby/CVE-2007-5162.yml`, new TextReader('cve: "2007-5162"\ntitle: Historical patched interpreter vulnerability\npatched_versions:\n  - "~> 1.8.5.114"\n  - ">= 1.8.6.111"\n'));
    const bytes = await zip.close();
    const build = await Bun.build({ entrypoints: [fileURLToPath(new NodeURL("../src/index.ts", import.meta.url))], target: "browser" });
    expect(build.success).toBe(true);
    const output = build.outputs[0]; if (!output) throw new Error("missing Worker bundle");
    let requests = 0;
    let nodeRequests = 0;
    const runtime = new Miniflare(convertV4MiniflareOptions({
        modules: true, script: await output.text(), compatibilityDate: "2026-11-13", d1Databases: ["DB"], r2Buckets: ["RAW"],
        bindings: { RUNTIME_REFRESH_SECRET: "runtime-refresh-only-workerd-secret-at-least-32" },
        outboundService: async (request) => {
            requests++;
            const url = new URL(request.url);
            if (url.hostname === "api.github.com" && url.pathname === "/repos/rubysec/ruby-advisory-db/commits/master") return Response.json({ sha: "a".repeat(40) });
            if (url.hostname === "codeload.github.com" && url.pathname === `/rubysec/ruby-advisory-db/zip/${"a".repeat(40)}`) return new Response(bytes);
            if (url.hostname === "api.github.com" && url.pathname === "/repos/oven-sh/bun/security-advisories") {
                expect(request.headers.get("authorization")).toBe(`Bearer ${jobToken}`);
                return Response.json([]);
            }
            if (url.hostname === "raw.githubusercontent.com" && url.pathname === "/nodejs/security-wg/main/vuln/core/index.json") {
                nodeRequests++;
                if (nodeRequests > 1) expect(request.headers.get("cache-control")).toBe("no-cache");
                return Response.json({ "1": { cve: ["CVE-2026-12345"], vulnerable: "3.x", patched: ">=3.2.1", description: "fixture" } });
            }
            return new Response("unexpected fixture URL", { status: 404 });
        },
    }));
    try {
        const db = await runtime.getD1Database("DB");
        for (const name of ["0001_advisories.sql", "0002_baseline_member_counter.sql", "0003_recent_cves.sql", "0004_epss_cache.sql", "0005_runtime_sources.sql", "0006_baseline_publisher_proof.sql"]) {
            const source = await readFile(new NodeURL(`../migrations/${name}`, import.meta.url), "utf8");
            await db.batch(unstable_splitSqlQuery(source).map((query) => db.prepare(query)));
        }
        const worker = await runtime.getWorker();
        const url = "https://advisories.example/v1/runtimes/ruby?version=3.2.0&vendor=ruby-lang&os=linux&arch=x86_64";
        const first = await worker.fetch(url);
        expect(first.status).toBe(200); expect(first.headers.get("cache-control")).toBe("no-store");
        const body = await first.json();
        expect(body).toMatchObject({ coverage: "partial", findings: [{ id: "CVE-2026-12345", applicability: "applicable" }], sources: [{ revision: "a".repeat(40), complete: true }] });
        expect(requests).toBe(2);
        const row = await db.prepare("SELECT object_key,payload_sha256 FROM runtime_source").first<{ object_key: string; payload_sha256: string }>();
        expect(row?.payload_sha256).toMatch(/^[a-f0-9]{64}$/);
        const raw = await runtime.getR2Bucket("RAW"); expect(await raw.get(row?.object_key ?? "missing")).not.toBeNull();
        const second = await worker.fetch(url); expect(second.status).toBe(200); expect(requests).toBe(2);
        expect(await second.json()).toEqual(body);
        await worker.fetch(url, { headers: { "cache-control": "no-cache" } });
        expect(requests).toBe(2);
        const refreshed = await worker.fetch("https://advisories.example/internal/runtime-refresh", { method: "POST", headers: { authorization: "Bearer runtime-refresh-only-workerd-secret-at-least-32" }, body: JSON.stringify({ runtime: "bun", github_token: jobToken }) });
        expect(refreshed.status).toBe(200); expect(await refreshed.json()).toMatchObject({ runtime: "bun", refreshed: true });
        expect(refreshed.headers.get("cache-control")).toBe("no-store"); expect(requests).toBe(3);
        const nodeUrl = "https://advisories.example/v1/runtimes/node?version=3.2.0&vendor=nodejs&os=linux&arch=x86_64";
        await worker.fetch(nodeUrl); await worker.fetch(nodeUrl, { headers: { "cache-control": "no-cache" } });
        expect(nodeRequests).toBe(2); expect(requests).toBe(5);
    } finally { await runtime.dispose(); }
}, 30_000);

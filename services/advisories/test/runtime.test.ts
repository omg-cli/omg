import { test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { Store, type Sql, type Command } from "../src/storage";
import { handle } from "../src/service";
import { object } from "../src/domain";
import { sha256 } from "../src/domain";
import { ZipWriter, Uint8ArrayWriter, TextReader } from "@zip.js/zip.js/lib/zip-core-native.js";

const now = "2026-11-17T02:00:00.000Z";
const nodeUrl = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json";
function setup() {
    const db = new Database(":memory:");
    db.exec(readFileSync(new NodeURL("../migrations/0001_advisories.sql", import.meta.url), "utf8"));
    db.exec(readFileSync(new NodeURL("../migrations/0005_runtime_sources.sql", import.meta.url), "utf8"));
    const sql: Sql = {
        first: async <T>(text: string, values: (string | number | null)[] = []) => db.query<T, (string | number | null)[]>(text).get(...values),
        all: async <T>(text: string, values: (string | number | null)[] = []) => db.query<T, (string | number | null)[]>(text).all(...values),
        batch: async (commands: Command[]) => { db.transaction(() => { for (const command of commands) db.query(command.sql).run(...command.values); })(); },
    };
    const objects = new Map<string, string>();
    let clock = now;
    const store = new Store(sql, { put: async (key, value) => { objects.set(key, value); }, get: async (key) => { const value = objects.get(key); return value === undefined ? null : { text: async () => value }; } }, () => clock);
    return { store, db, objects, setClock: (value: string) => { clock = value; } };
}
function request(runtime = "node", version = "20.10.0", vendor = "nodejs", headers?: HeadersInit) {
    return new Request(`https://advisories.example/v1/runtimes/${runtime}?version=${encodeURIComponent(version)}&vendor=${vendor}&os=linux&arch=x86_64`, { headers });
}
test("runtime Node route reports affected and fixed versions with source provenance", async () => {
    const { store, db } = setup();
    try {
        const fetcher = async (url: string) => {
            expect(url).toBe(nodeUrl);
            return Response.json({ "1": { cve: ["CVE-2026-12345"], vulnerable: "20.x", patched: ">=20.11.0", description: "fixture vulnerability", severity: "high", ref: "https://nodejs.org/en/blog/vulnerability/fixture" } });
        };
        const affected = await handle(request(), store, undefined, now, fetcher);
        expect(affected.status).toBe(200);
        const body = object(await affected.json());
        expect(body.coverage).toBe("assessed");
        expect(body.identity).toEqual({ runtime: "node", vendor: "nodejs", version: "20.10.0", os: "linux", arch: "x86_64" });
        expect(body.findings).toMatchObject([{ id: "CVE-2026-12345", applicability: "applicable" }]);
        expect(body.sources).toMatchObject([{ name: "Node.js core advisories", url: nodeUrl, complete: true }]);
        const fixed = object(await (await handle(request("node", "20.11.0"), store, undefined, now, fetcher)).json());
        expect(fixed.coverage).toBe("assessed");
        expect(fixed.findings).toEqual([]);
    } finally { db.close(); }
});

const nodePayload = { "1": { cve: ["CVE-2026-12345"], vulnerable: "20.x || 18.x", patched: ">=20.11.0 || >=18.20.0 <19", description: "fixture", severity: "high" } };
async function report(store: Store, runtime: string, version: string, vendor: string, fetcher: (url: string, init?: RequestInit) => Promise<Response>, at = now, force = false) {
    return object(await (await handle(request(runtime, version, vendor, force ? { "cache-control": "no-cache" } : undefined), store, undefined, at, fetcher)).json());
}
async function zipFixture(repo: string, files: Record<string, string>) {
    const writer = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false, useCompressionStream: true, level: 0 });
    for (const [path, raw] of Object.entries(files)) await writer.add(`${repo.split("/")[1]}-${"a".repeat(40)}/${path}`, new TextReader(raw));
    return await writer.close();
}
async function archiveFetcher(repo: string, files: Record<string, string>, fallback?: (url: string) => Promise<Response>) {
    const bytes = await zipFixture(repo, files);
    return async (url: string) => {
        if (url.startsWith(`https://api.github.com/repos/${repo}/commits/`)) return Response.json({ sha: "a".repeat(40) });
        if (url === `https://codeload.github.com/${repo}/zip/${"a".repeat(40)}`) return new Response(bytes);
        if (fallback) return fallback(url);
        throw new Error(`unexpected fixture URL ${url}`);
    };
}
function advisory(name: string, range: string, fixes?: string) {
    return { ghsa_id: "GHSA-abcd-1234-abcd", cve_id: "CVE-2026-12345", summary: "publisher fixture", severity: "high", vulnerabilities: [{ package: { name }, vulnerable_version_range: range, patched_versions: fixes }], html_url: "https://github.com/security/advisories/GHSA-abcd-1234-abcd" };
}
function cve(id: string, vendor: string, product: string, lower: string, upper: string) {
    return { dataType: "CVE_RECORD", dataVersion: "5.2", cveMetadata: { cveId: id, state: "PUBLISHED", dateUpdated: now, datePublished: now }, containers: { cna: { affected: [{ vendor, product, defaultStatus: "unaffected", versions: [{ version: lower, lessThan: upper, versionType: "semver", status: "affected" }] }] } } };
}

test("all runtime routes report Unknown with evidence gaps when providers fail", async () => {
    const vendors = { node: "nodejs", python: "cpython", go: "golang", rust: "rust-lang", ruby: "ruby-lang", java: "temurin", bun: "oven-sh", pi: "earendil-works", deno: "denoland", zig: "ziglang", dotnet: "microsoft", erlang: "erlang", php: "php", swift: "swiftlang" };
    const { store, db } = setup();
    try { for (const [runtime, vendor] of Object.entries(vendors)) {
        const response = await handle(request(runtime, "20.0.0", vendor), store, undefined, now, async () => new Response("unavailable", { status: 503 }));
        expect(response.status).toBe(200);
        const body = object(await response.json());
        expect(body.coverage).toBe("unknown"); expect(body.gaps).not.toEqual([]); expect(body.identity).toMatchObject({ runtime, vendor });
        expect(response.headers.get("cache-control")).toBe("no-store");
    } } finally { db.close(); }
});
test("runtime identity rejects duplicate or extra parameters and does not guess vendors", async () => {
    const { store, db } = setup(); let calls = 0;
    const fetcher = async () => { calls++; return Response.json(nodePayload); };
    try {
        for (const extra of ["&version=20.0.0", "&component=sdk", "&os=windows"]) expect((await handle(new Request(`${request().url}${extra}`), store, undefined, now, fetcher)).status).toBe(400);
        const unknown = await report(store, "node", "20.10.0", "npm", fetcher);
        expect(unknown.coverage).toBe("unknown"); expect(calls).toBe(0);
    } finally { db.close(); }
});
test("Node retains CVE-less disclosures and unsupported ranges as possible risks", async () => {
    const { store, db } = setup();
    try {
        const body = await report(store, "node", "20.10.0", "nodejs", async () => Response.json({ "7": { cve: [], vulnerable: "20.x", patched: "unparsed vendor prose", description: "disclosed issue without a CVE" } }));
        expect(body.coverage).toBe("partial"); expect(body.findings).toMatchObject([{ id: "NODE-CORE-7", applicability: "possible" }]);
    } finally { db.close(); }
});
test("source hashes remain stable on revalidation and change only with content; stale errors retain last good evidence", async () => {
    const { store, db, setClock } = setup(); let payload = nodePayload; let fail = false;
    const fetcher = async () => fail ? new Response(null, { status: 503 }) : Response.json(payload, { headers: { etag: '"revision"' } });
    try {
        const first = await report(store, "node", "20.10.0", "nodejs", fetcher);
        const hash = object((first.sources as unknown[])[0]).payload_sha256;
        const later = "2026-11-17T02:01:00.000Z"; setClock(later);
        const refreshed = await report(store, "node", "20.10.0", "nodejs", fetcher, later, true);
        expect(object((refreshed.sources as unknown[])[0]).payload_sha256).toBe(hash);
        expect(object((refreshed.sources as unknown[])[0]).checked_at).toBe(later);
        payload = { "1": { ...nodePayload["1"], description: "changed disclosure" } };
        const changed = await report(store, "node", "20.10.0", "nodejs", fetcher, later, true);
        expect(object((changed.sources as unknown[])[0]).payload_sha256).not.toBe(hash);
        const row = db.query<{ object_key: string }, []>("SELECT object_key FROM runtime_source").get();
        fail = true; const stale = "2026-11-17T03:00:00.000Z"; setClock(stale);
        const failed = await handle(request(), store, undefined, stale, fetcher); const body = object(await failed.json());
        expect(body.coverage).toBe("partial"); expect(body.findings).toMatchObject([{ id: "CVE-2026-12345" }]);
        expect(object((body.sources as unknown[])[0]).complete).toBe(false); expect(failed.headers.get("cache-control")).toBe("no-store");
        expect(db.query<{ object_key: string }, []>("SELECT object_key FROM runtime_source").get()?.object_key).toBe(row?.object_key);
    } finally { db.close(); }
});
test("assessed runtime HTTP freshness is bounded and no-cache reaches upstream", async () => {
    const { store, db } = setup(); let calls = 0;
    try {
        const fetcher = async (_url: string, init?: RequestInit) => { calls++; if (calls > 1) expect(new Headers(init?.headers).get("cache-control")).toBe("no-cache"); return Response.json(nodePayload); };
        const first = await handle(request(), store, undefined, now, fetcher);
        expect(first.headers.get("cache-control")).toBe("public, max-age=60, must-revalidate");
        await handle(request(), store, undefined, now, fetcher); expect(calls).toBe(1);
        await handle(request("node", "20.10.0", "nodejs", { "cache-control": "no-cache" }), store, undefined, now, fetcher); expect(calls).toBe(2);
    } finally { db.close(); }
});

test("concurrent forced runtime revalidation retains a genuinely fresh verified snapshot", async () => {
    const { store, db, setClock } = setup();
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    try {
        const first = await report(store, "node", "20.10.0", "nodejs", async () => Response.json(nodePayload));
        const later = "2026-11-17T02:01:00.000Z";
        setClock(later);
        const owner = report(store, "node", "20.10.0", "nodejs", async () => {
            entered.resolve();
            await release.promise;
            return Response.json(nodePayload);
        }, later, true);
        try {
            await entered.promise;
            let contenderFetches = 0;
            const concurrent = await report(store, "node", "20.10.0", "nodejs", async () => {
                contenderFetches++;
                return new Response(null, { status: 503 });
            }, later, true);
            expect(concurrent.coverage).toBe("assessed");
            expect(concurrent.findings).toEqual(first.findings);
            expect(concurrent.gaps).toEqual([]);
            expect(concurrent.sources).toEqual(first.sources);
            expect(concurrent.checked_at).toBe(now);
            expect(contenderFetches).toBe(0);
            expect(db.query<{ successful_at: string; error: string | null }, []>("SELECT successful_at,error FROM runtime_source").get())
                .toEqual({ successful_at: now, error: null });
        } finally { release.resolve(); await owner; }
    } finally { release.resolve(); db.close(); }
});

test("busy runtime refresh never certifies stale failed missing or corrupt prior evidence", async () => {
    for (const state of ["stale", "failed", "missing", "corrupt"] as const) {
        const { store, db, objects, setClock } = setup();
        try {
            if (state !== "missing") {
                await report(store, "node", "20.10.0", "nodejs", async () => Response.json(nodePayload));
            }
            const at = state === "stale" ? "2026-11-17T02:31:00.000Z" : "2026-11-17T02:01:00.000Z";
            setClock(at);
            if (state === "failed") {
                await report(store, "node", "20.10.0", "nodejs", async () => new Response(null, { status: 503 }), at, true);
            }
            if (state === "corrupt") {
                const key = db.query<{ object_key: string }, []>("SELECT object_key FROM runtime_source").get()?.object_key;
                if (!key) throw new Error("missing controlled source object");
                objects.set(key, "{}");
            }
            const lease = `runtime:${await sha256("v1:node:core")}`;
            expect(await store.lease(lease, "controlled-refresh-owner", at)).toBe(true);
            let fetched = false;
            const response = await handle(request("node", "20.10.0", "nodejs", { "cache-control": "no-cache" }), store, undefined, at, async () => {
                fetched = true;
                return Response.json(nodePayload);
            });
            const body = object(await response.json());
            expect(body.coverage).toBe(state === "stale" || state === "failed" ? "partial" : "unknown");
            expect(body.gaps).not.toEqual([]);
            expect(response.headers.get("cache-control")).toBe("no-store");
            expect(fetched).toBe(false);
            if (state === "stale" || state === "failed") {
                expect(body.findings).toMatchObject([{ id: "CVE-2026-12345" }]);
                expect(body.sources).toMatchObject([{ checked_at: now, complete: false }]);
            } else {
                expect(body.sources).toEqual([]);
            }
            await store.release(lease, "controlled-refresh-owner");
        } finally { db.close(); }
    }
});
test("Go uses both exact OSV standard-library and toolchain coordinates with full pagination", async () => {
    const { store, db } = setup(); const queries: Record<string, unknown>[] = [];
    try {
        const body = await report(store, "go", "1.24.0", "golang", async (url, init) => {
            expect(url).toBe("https://api.osv.dev/v1/query"); const query = object(JSON.parse(String(init?.body))); queries.push(query);
            if (query.page_token === "next") return Response.json({ vulns: [{ id: "GO-2026-1112", summary: "page two" }] });
            return Response.json({ vulns: [{ id: "GO-2026-1111", aliases: ["CVE-2026-12345"], summary: "page one" }], next_page_token: "next" });
        });
        expect(body.coverage).toBe("assessed"); expect((body.sources as unknown[]).length).toBe(2); expect(queries.length).toBe(4);
        expect(queries.map((query) => object(query.package).name)).toEqual(["stdlib", "stdlib", "toolchain", "toolchain"]);
        expect(queries.every((query) => query.version === "1.24.0" && object(query.package).ecosystem === "Go")).toBe(true);
    } finally { db.close(); }
});
test("fresh Go OSV evidence ignores object key order but binds every field and ordered array", async () => {
    const { store, db } = setup();
    const reverseKeys=(value:unknown):unknown=>{
        if(Array.isArray(value))return value.map(reverseKeys);
        if(value!==null && typeof value==="object")return Object.fromEntries(Object.entries(object(value)).reverse().map(([key,item])=>[key,reverseKeys(item)]));
        return value;
    };
    let variant="original";
    const fetcher=async(url:string,init?:RequestInit)=>{
        expect(url).toBe("https://api.osv.dev/v1/query");
        const query=object(JSON.parse(String(init?.body))),name=object(query.package).name;
        const record={id:name==="stdlib"?"GO-2026-1111":"GO-2026-1112",summary:"Exact Go disclosure",modified:now,
            aliases:[name==="stdlib"?"CVE-2026-12345":"CVE-2026-12346"],database_specific:{severity:"HIGH"},
            affected:[{package:{ecosystem:"Go",name},ranges:[{type:"SEMVER",events:[{introduced:"0"},{fixed:variant==="field"?"1.29.0":"1.28.0"}]}],
                ecosystem_specific:{imports:[{path:"net/http",symbols:variant==="array"?["Server.Serve","Serve"]:["Serve","Server.Serve"]}]}}]};
        return Response.json({vulns:[variant==="keys"?reverseKeys(record):record]});
    };
    const hashes=(value:Record<string,unknown>)=>{
        const sources=value.sources;if(!Array.isArray(sources))throw new Error("missing controlled OSV source receipts");
        return sources.map(source=>object(source).payload_sha256);
    };
    try {
        const first=await report(store,"go","1.27.1","golang",fetcher,now,true);
        variant="keys";
        const reordered=await report(store,"go","1.27.1","golang",fetcher,now,true);
        expect(first.coverage).toBe("assessed");expect(reordered.coverage).toBe("assessed");
        expect(reordered.findings).toEqual(first.findings);
        expect(hashes(reordered)).toEqual(hashes(first));
        for(const changed of ["field","array"]){
            variant=changed;
            const update=await report(store,"go","1.27.1","golang",fetcher,now,true);
            expect(update.coverage).toBe("assessed");expect(update.findings).toEqual(first.findings);
            expect(hashes(update)).not.toEqual(hashes(first));
        }
    }finally{db.close();}
});
test("Pi scans its actual npm package and cyclic OSV pagination cannot become clean", async () => {
    const { store, db } = setup();
    try {
        const body = await report(store, "pi", "0.50.0", "earendil-works", async (_url, init) => { const query = object(JSON.parse(String(init?.body))); expect(query.package).toEqual({ ecosystem: "npm", name: "@earendil-works/pi-coding-agent" }); return Response.json({ next_page_token: "cycle" }); });
        expect(body.coverage).toBe("unknown"); expect(body.sources).toEqual([]);
    } finally { db.close(); }
});
test("Bun and Deno publisher advisories distinguish affected, fixed and withdrawn", async () => {
    for (const [runtime, vendor, name] of [["bun", "oven-sh", "bun"], ["deno", "denoland", "Deno"]]) {
        if (!runtime || !vendor || !name) throw new Error("missing fixture identity");
        const { store, db } = setup();
        try {
            const fetcher = async () => Response.json([advisory(name, ">=1.0.0 <1.2.0"), { ...advisory(name, "*"), ghsa_id: "GHSA-abcd-1234-efgh", cve_id: "CVE-2026-12346", withdrawn_at: now }]);
            expect((await report(store, runtime, "1.1.0", vendor, fetcher)).findings).toMatchObject([{ id: "CVE-2026-12345", applicability: "applicable" }]);
            expect((await report(store, runtime, "1.2.0", vendor, fetcher)).findings).toEqual([]);
        } finally { db.close(); }
    }
});
test("publisher disclosures without applicability entries remain possible risks", async () => {
    for (const { runtime, vendor, version } of [
        { runtime: "bun", vendor: "oven-sh", version: "1.1.0" },
        { runtime: "deno", vendor: "denoland", version: "1.1.0" },
        { runtime: "php", vendor: "php", version: "8.2.33" },
        { runtime: "erlang", vendor: "erlang", version: "28.5.0.8" },
    ]) {
        const { store, db } = setup();
        try {
            const row = { ...advisory(runtime, "*"), vulnerabilities: [] };
            const body = await report(store, runtime, version, vendor, async (url) =>
                url.endsWith("otp_versions.table")
                    ? new Response("OTP-28.5.0.8 : ssl-11.6.0.7 # compiler-9.0.1 :")
                    : Response.json([row]));
            expect(body.coverage).toBe("partial");
            expect(body.findings).toMatchObject([{ id: row.cve_id, applicability: "possible",
                urls: expect.arrayContaining([row.html_url]) }]);
            expect(body.gaps).not.toEqual([]);
            if (!Array.isArray(body.sources)) throw new Error("missing publisher sources");
            expect(body.sources.length).toBe(runtime === "erlang" ? 2 : 1);
            expect(body.sources.every((value) => object(value).complete === true)).toBe(true);
        } finally { db.close(); }
    }
});

test("empty publisher lists and withdrawn incomplete disclosures do not fabricate findings", async () => {
    for (const rows of [[], [{ ...advisory("bun", "*"), vulnerabilities: [], withdrawn_at: now }]]) {
        const { store, db } = setup();
        try {
            const body = await report(store, "bun", "1.1.0", "oven-sh", async () => Response.json(rows));
            expect(body.coverage).toBe("assessed");
            expect(body.findings).toEqual([]);
            expect(body.gaps).toEqual([]);
        } finally { db.close(); }
    }
});

test("PHP maintenance-branch fixes are not ORed into a false affected result", async () => {
    const { store, db } = setup();
    try {
        const row = advisory("ext-standard", "<8.2.34", "8.2.34"); row.vulnerabilities.push({ package: { name: "ext-standard" }, vulnerable_version_range: "<8.3.35", patched_versions: "8.3.35" });
        const fetcher = async () => Response.json([row]);
        expect((await report(store, "php", "8.2.34", "php", fetcher)).findings).toEqual([]);
        expect((await report(store, "php", "8.2.33", "php", fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
    } finally { db.close(); }
});
test("Erlang resolves four-component OTP and application release versions", async () => {
    const { store, db } = setup();
    try {
        const row = advisory("ssl", ">=7.0", "11.7.8, 11.6.0.7");
        const fetcher = async (url: string) => url.endsWith("otp_versions.table") ? new Response("OTP-28.5.0.8 : ssl-11.6.0.7 # compiler-9.0.1 :\nOTP-28.5.0.7 : ssl-11.6.0.6 # compiler-9.0.1 :") : Response.json([row]);
        expect((await report(store, "erlang", "28.5.0.8", "erlang", fetcher)).findings).toEqual([]);
        expect((await report(store, "erlang", "28.5.0.7", "erlang", fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
    } finally { db.close(); }
});
test("Zig and Swift empty publisher lists remain explicitly Unknown", async () => {
    const { store, db } = setup();
    try { for (const [runtime, vendor] of [["zig", "ziglang"], ["swift", "swiftlang"]]) {
        if (!runtime || !vendor) throw new Error("missing fixture");
        const body = await report(store, runtime, "1.0.0", vendor, async () => Response.json([]));
        expect(body.coverage).toBe("unknown"); expect(body.gaps).not.toEqual([]); expect(body.sources).toMatchObject([{ complete: true }]);
    } } finally { db.close(); }
});
test("Ruby YAML and Rust TOML apply exact toolchain ranges without matching third-party packages", async () => {
    for (const runtime of ["ruby", "rust"]) {
        const { store, db } = setup();
        try {
            const ruby = runtime === "ruby";
            const fetcher = await archiveFetcher(ruby ? "rubysec/ruby-advisory-db" : "rustsec/advisory-db", ruby ? { "rubies/ruby/CVE-2026-12345.yml": 'cve: "2026-12345"\ntitle: Ruby interpreter fixture\npatched_versions:\n  - ">= 3.2.1"\nunaffected_versions:\n  - "< 3.2.0"\n' } : { "rust/std/RUSTSEC-2026-0001.md": '```toml\n[advisory]\nid = "RUSTSEC-2026-0001"\n[versions]\npatched = [">= 1.58.1"]\nunaffected = []\n```\n# Standard library fixture\n' });
            const vendor = ruby ? "ruby-lang" : "rust-lang";
            expect((await report(store, runtime, ruby ? "3.2.0" : "1.58.0", vendor, fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
            expect((await report(store, runtime, ruby ? "3.2.1" : "1.58.1", vendor, fetcher)).findings).toEqual([]);
        } finally { db.close(); }
    }
});
test("CPython Git-only records use vendor CVE numeric applicability and preserve unsupported findings", async () => {
    const { store, db } = setup();
    try {
        const fetcher = await archiveFetcher("psf/advisory-database", { "advisories/python/PSF-2026-1.json": JSON.stringify({ id: "PSF-2026-1", aliases: ["CVE-2026-12345", "CVE-2026-12346"], summary: "CPython core issue", affected: [{ ranges: [{ type: "GIT", events: [] }] }] }) }, async (url) => url.endsWith("CVE-2026-12345.json") ? Response.json(cve("CVE-2026-12345", "Python Software Foundation", "CPython", "3.12.0", "3.12.9")) : Response.json(cve("CVE-2026-12346", "unknown", "unknown", "0", "4")));
        const affected = await report(store, "python", "3.12.8", "cpython", fetcher);
        expect(affected.findings).toMatchObject([{ id: "CVE-2026-12345", applicability: "applicable" }, { id: "CVE-2026-12346", applicability: "possible" }]);
        const fixed = await report(store, "python", "3.12.9", "cpython", fetcher);
        expect(fixed.findings).toMatchObject([{ id: "CVE-2026-12346", applicability: "possible" }]);
        expect((fixed.findings as unknown[]).length).toBe(1);
    } finally { db.close(); }
});
test(".NET compares SDK-bundled runtime versions with runtime CVE ranges", async () => {
    const { store, db } = setup();
    try {
        const fetcher = async (url: string) => url.includes("releases.json") ? Response.json({ "channel-version": "9.0", releases: [ { "release-version": "9.0.0", sdk: { version: "9.0.100" }, runtime: { version: "9.0.0" } }, { "release-version": "9.0.1", sdk: { version: "9.0.101" }, runtime: { version: "9.0.1" }, security: true, "cve-list": [{ "cve-id": "CVE-2026-12345" }] } ] }) : Response.json(cve("CVE-2026-12345", "Microsoft", ".NET", "9.0.0", "9.0.1"));
        expect((await report(store, "dotnet", "9.0.100", "microsoft", fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
        expect((await report(store, "dotnet", "9.0.101", "microsoft", fetcher)).findings).toEqual([]);
    } finally { db.close(); }
});
test(".NET includes SDK-only security releases when the bundled runtime has not changed", async () => {
    const { store, db } = setup();
    try {
        const fetcher = async (url: string) => url.includes("releases.json") ? Response.json({ "channel-version": "9.0", releases: [
            { "release-version": "9.0.0", sdk: { version: "9.0.100" }, runtime: { version: "9.0.0" } },
            { "release-version": "9.0.0", sdks: [{ version: "9.0.101" }], runtime: { version: "9.0.0" }, security: true, "cve-list": [{ "cve-id": "CVE-2026-12345" }] },
        ] }) : Response.json(cve("CVE-2026-12345", "Microsoft", ".NET SDK", "9.0.100", "9.0.101"));
        expect((await report(store, "dotnet", "9.0.100", "microsoft", fetcher)).findings).toMatchObject([{ id: "CVE-2026-12345", applicability: "applicable" }]);
        expect((await report(store, "dotnet", "9.0.101", "microsoft", fetcher)).findings).toEqual([]);
    } finally { db.close(); }
});
test(".NET includes ASP.NET-only security releases and compares the installed ASP.NET component", async () => {
    const { store, db } = setup();
    try {
        const fetcher = async (url: string) => url.includes("releases.json") ? Response.json({ "channel-version": "9.0", releases: [
            { "release-version": "9.0.0", sdk: { version: "9.0.100" }, runtime: { version: "9.0.0" }, aspnetcore: { version: "9.0.0" } },
            { "release-version": "9.0.1", runtime: { version: "9.0.0" }, aspnetcore: { version: "9.0.1" }, security: true, "cve-list": [{ "cve-id": "CVE-2026-12345" }] },
        ] }) : Response.json(cve("CVE-2026-12345", "Microsoft", "ASP.NET Core", "9.0.0", "9.0.1"));
        expect((await report(store, "dotnet", "9.0.100", "microsoft", fetcher)).findings).toMatchObject([{ id: "CVE-2026-12345", applicability: "applicable" }]);
    } finally { db.close(); }
});
test("Temurin verifies official asset digest and preserves partial exact-build evidence", async () => {
    const { store, db } = setup();
    try {
        const raw = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", metadata: { component: { name: "Eclipse Temurin" } }, vulnerabilities: [{ id: "CVE-2026-12345", description: "Temurin fixture", affects: [{ ref: "pkg:github/openjdk/jdk", versions: [{ range: "vers:generic/21.0.1" }] }] }] });
        const digest = await sha256(raw);
        const fetcher = async (url: string) => url.endsWith("/latest") ? Response.json({ tag_name: "vdr-fixture", assets: [{ name: "temurin-vdr-fixture.json", digest: `sha256:${digest}`, size: new TextEncoder().encode(raw).length, browser_download_url: "https://github.com/adoptium/temurin-vdr-generator/releases/download/fixture/temurin-vdr-fixture.json" }] }) : new Response(raw);
        expect((await report(store, "java", "21.0.1+12", "temurin", fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
        expect((await report(store, "java", "21.0.2+13", "temurin", fetcher)).findings).toEqual([]);
        expect((await report(store, "java", "21", "temurin", fetcher)).coverage).toBe("unknown");
    } finally { db.close(); }
});
test("competing and expired fenced runtime refreshes cannot publish authoritative evidence", async () => {
    const { store, db, setClock } = setup();
    try {
        const lease = `runtime:${await sha256("v1:node:core")}`;
        expect(await store.lease(lease, "competing-owner", now)).toBe(true);
        const locked = await report(store, "node", "20.10.0", "nodejs", async () => { throw new Error("must not fetch under another owner's lease"); });
        expect(locked.coverage).toBe("unknown"); await store.release(lease, "competing-owner");
        const expired = await report(store, "node", "20.10.0", "nodejs", async () => { setClock("2026-11-17T02:11:00.000Z"); return Response.json(nodePayload); });
        expect(expired.coverage).toBe("unknown"); expect(db.query<{ n: number }, []>("SELECT COUNT(*) n FROM runtime_source").get()?.n).toBe(0);
    } finally { db.close(); }
});

test("publisher pagination consumes every page and rejects repeated page identities", async () => {
    const { store, db } = setup(); let pages = 0;
    try {
        const body = await report(store, "bun", "1.0.0", "oven-sh", async (url) => {
            pages++;
            if (url.endsWith("page=2")) return Response.json([advisory("bun", "<1.1.0")]);
            return Response.json(Array.from({ length: 100 }, (_, index) => ({ ...advisory("bun", "<0.1.0"), ghsa_id: `GHSA-abcd-${index.toString(16).padStart(4, "0")}-abcd`, cve_id: null })));
        });
        expect(pages).toBe(2); expect(body.coverage).toBe("assessed"); expect(body.findings).toMatchObject([{ id: "CVE-2026-12345" }]);
        await handle(refreshRequest({ runtime: "bun", github_token: jobToken }), store, undefined, now, async () => Response.json(Array.from({ length: 100 }, (_, index) => ({ ...advisory("bun", "<0.1.0"), ghsa_id: `GHSA-abcd-${index.toString(16).padStart(4, "0")}-abcd`, cve_id: null }))), refreshSecret);
        const failed = await report(store, "bun", "1.0.0", "oven-sh", async () => { throw new Error("failure backoff must reuse retained evidence"); });
        expect(failed.coverage).toBe("partial"); expect(failed.findings).toMatchObject([{ id: "CVE-2026-12345" }]);
    } finally { db.close(); }
});
test("trusted 304 revalidation retains source content hash and malformed replacements preserve good snapshots", async () => {
    const { store, db } = setup();
    try {
        const first = await report(store, "node", "20.10.0", "nodejs", async () => Response.json(nodePayload, { headers: { etag: '"a"' } }));
        const hash = object((first.sources as unknown[])[0]).payload_sha256;
        const checked = await report(store, "node", "20.10.0", "nodejs", async (_url, init) => { expect(new Headers(init?.headers).get("if-none-match")).toBe('"a"'); return new Response(null, { status: 304 }); }, now, true);
        expect(checked.coverage).toBe("assessed"); expect(object((checked.sources as unknown[])[0]).payload_sha256).toBe(hash);
        const failed = await report(store, "node", "20.10.0", "nodejs", async () => Response.json({ "1": { vulnerable: "*" } }), now, true);
        expect(failed.coverage).toBe("partial"); expect(object((failed.sources as unknown[])[0]).payload_sha256).toBe(hash);
        expect(failed.findings).toMatchObject([{ id: "CVE-2026-12345" }]);
    } finally { db.close(); }
});
test("incomplete CVE applicability refresh cannot replace a previously complete snapshot", async () => {
    const { store, db } = setup(); let fail = false;
    try {
        const fetcher = await archiveFetcher("psf/advisory-database", { "advisories/python/PSF-2026-1.json": JSON.stringify({ id: "PSF-2026-1", aliases: ["CVE-2026-12345", "CVE-2026-12346"], summary: "Python fixture" }) }, async (url) => {
            if (fail && url.endsWith("CVE-2026-12346.json")) return new Response(null, { status: 503 });
            const id = url.endsWith("CVE-2026-12345.json") ? "CVE-2026-12345" : "CVE-2026-12346";
            return Response.json(cve(id, "Python Software Foundation", "CPython", "3.12.0", fail ? "3.12.8" : "3.12.9"));
        });
        await report(store, "python", "3.12.8", "cpython", fetcher);
        const first = db.query<{ object_key: string }, []>("SELECT object_key FROM runtime_source WHERE cache_key LIKE 'v1:cve5:%'").get();
        fail = true; const partial = await report(store, "python", "3.12.8", "cpython", fetcher, now, true);
        expect(partial.coverage).toBe("partial"); expect((partial.sources as unknown[]).some((value) => object(value).complete === false)).toBe(true);
        expect(db.query<{ object_key: string }, []>("SELECT object_key FROM runtime_source WHERE cache_key LIKE 'v1:cve5:%'").get()?.object_key).toBe(first?.object_key);
    } finally { db.close(); }
});

test("Ruby four-component Gem patch requirements exclude historical vulnerabilities from modern releases", async () => {
    const { store, db } = setup();
    try {
        const fetcher = await archiveFetcher("rubysec/ruby-advisory-db", {
            "rubies/ruby/CVE-2007-5162.yml": 'cve: "2007-5162"\ntitle: Historical Net HTTPS issue\npatched_versions:\n  - "~> 1.8.5.114"\n  - ">= 1.8.6.111"\n',
        });
        expect((await report(store, "ruby", "3.3.0", "ruby-lang", fetcher)).findings).toEqual([]);
    } finally { db.close(); }
});

const refreshSecret = "runtime-refresh-only-fixture-secret-at-least-32";
const jobToken = `ghs_${"a".repeat(36)}`;
function refreshRequest(body: unknown, secret = refreshSecret) {
    return new Request("https://advisories.example/internal/runtime-refresh", { method: "POST", headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" }, body: JSON.stringify(body) });
}
test("runtime refresh uses its separate secret and sends ephemeral job credentials only to approved GitHub API requests", async () => {
    const { store, db, objects } = setup();
    try {
        let calls = 0;
        const fetcher = async (url: string, init?: RequestInit) => {
            calls++; expect(url).toBe("https://api.github.com/repos/oven-sh/bun/security-advisories?per_page=100&page=1");
            expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${jobToken}`);
            expect(init?.redirect).toBe("manual"); return Response.json([]);
        };
        const result = await handle(refreshRequest({ runtime: "bun", github_token: jobToken }), store, "different-bootstrap-credential-at-least-32", now, fetcher, refreshSecret);
        expect(result.status).toBe(200); expect(result.headers.get("cache-control")).toBe("no-store");
        expect(await result.json()).toMatchObject({ runtime: "bun", refreshed: true, coverage: "assessed" }); expect(calls).toBe(1);
        expect([...objects.values()].some((value) => value.includes(jobToken) || value.includes(refreshSecret))).toBe(false);
        const sqlRows = JSON.stringify(db.query("SELECT * FROM runtime_source").all());
        expect(sqlRows.includes(jobToken) || sqlRows.includes(refreshSecret)).toBe(false);
        const denied = await handle(refreshRequest({ runtime: "bun", github_token: jobToken }, "bootstrap-credential-at-least-32"), store, "bootstrap-credential-at-least-32", now, fetcher, refreshSecret);
        expect(denied.status).toBe(401); expect(calls).toBe(1);
        expect((await handle(refreshRequest({ runtime: "bun", github_token: jobToken }), store, refreshSecret, now, fetcher)).status).toBe(401);
    } finally { db.close(); }
});
test("runtime refresh refuses arbitrary URLs, personal tokens and unsupported runtime selectors", async () => {
    const { store, db } = setup(); let calls = 0;
    const personalTokenFixture = "ghp_" + "fixturefake" + "0".repeat(25);
    expect(personalTokenFixture).toMatch(/^ghp_[A-Za-z0-9]{36}$/);
    try {
        for (const body of [{ runtime: "bun", github_token: jobToken, url: "https://example.com" }, { runtime: "bun", github_token: personalTokenFixture }, { runtime: "../node", github_token: jobToken }]) {
            const response = await handle(refreshRequest(body), store, undefined, now, async () => { calls++; return Response.json([]); }, refreshSecret);
            expect(response.status).toBe(400);
        }
        expect(calls).toBe(0);
    } finally { db.close(); }
});
test("rate-limited GitHub source responses expose only bounded numeric diagnostic headers", async () => {
    const { store, db } = setup();
    try {
        const body = await report(store, "bun", "1.1.0", "oven-sh", async () => new Response(jobToken, { status: 403, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "1794891075", "retry-after": "15" } }));
        expect(body.coverage).toBe("unknown");
        expect(JSON.stringify(body.gaps)).toContain("GitHub rate limit remaining=0 reset=1794891075 retry_after=15");
        expect(JSON.stringify(body)).not.toContain(jobToken);
    } finally { db.close(); }
});
test("ephemeral GitHub credentials are absent from Temurin assets and every release-asset redirect", async () => {
    const { store, db } = setup(); const seen: string[] = [];
    try {
        const raw = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", metadata: { component: { name: "Eclipse Temurin" } }, vulnerabilities: [] });
        const digest = await sha256(raw);
        const fetcher = async (url: string, init?: RequestInit) => {
            seen.push(url); const authorization = new Headers(init?.headers).get("authorization");
            expect(init?.redirect).toBe("manual");
            if (url.endsWith("/latest")) {
                expect(authorization).toBe(`Bearer ${jobToken}`);
                return Response.json({ tag_name: "fixture", assets: [{ name: "temurin-vdr-fixture.json", digest: `sha256:${digest}`, size: new TextEncoder().encode(raw).length, browser_download_url: "https://github.com/adoptium/temurin-vdr-generator/releases/download/fixture/temurin-vdr-fixture.json" }] });
            }
            expect(authorization).toBeNull();
            if (url.startsWith("https://github.com/")) return new Response(null, { status: 302, headers: { location: "https://release-assets.githubusercontent.com/fixture" } });
            return new Response(raw);
        };
        const response = await handle(refreshRequest({ runtime: "java", github_token: jobToken }), store, undefined, now, fetcher, refreshSecret);
        expect(await response.json()).toMatchObject({ runtime: "java", refreshed: true, coverage: "unknown" });
        expect(seen.length).toBe(3);
    } finally { db.close(); }
});
test("upstream credential reflections and transport errors cannot persist or return the job token", async () => {
    for (const reflected of [true, false]) {
        const { store, db, objects } = setup();
        try {
            const response = await handle(refreshRequest({ runtime: "bun", github_token: jobToken }), store, undefined, now, async () => {
                if (!reflected) throw new Error(`transport refused ${jobToken}`);
                return Response.json([{ ...advisory("bun", "*"), summary: jobToken }]);
            }, refreshSecret);
            const body = object(await response.json());
            expect(body.refreshed).toBe(false); expect(JSON.stringify(body)).not.toContain(jobToken);
            expect([...objects.values()].join("")).not.toContain(jobToken);
            expect(JSON.stringify(db.query("SELECT * FROM runtime_source").all())).not.toContain(jobToken);
        } finally { db.close(); }
    }
});
test("runtime refresh authentication happens before body parsing and GitHub redirects are not followed", async () => {
    const { store, db } = setup(); let calls = 0;
    try {
        const denied = new Request("https://advisories.example/internal/runtime-refresh", { method: "POST", body: "invalid JSON" });
        expect((await handle(denied, store, undefined, now, async () => { calls++; return Response.json([]); }, refreshSecret)).status).toBe(401);
        const result = await handle(refreshRequest({ runtime: "bun", github_token: jobToken }), store, undefined, now, async (_url, init) => {
            calls++; expect(init?.redirect).toBe("manual");
            return new Response(null, { status: 302, headers: { location: "https://attacker.invalid" } });
        }, refreshSecret);
        expect(await result.json()).toMatchObject({ refreshed: false, coverage: "unknown" }); expect(calls).toBe(1);
    } finally { db.close(); }
});
test("Ruby genuine Gem requirements preserve exclusion and pessimistic range semantics", async () => {
    const { store, db } = setup();
    try {
        const fetcher = await archiveFetcher("rubysec/ruby-advisory-db", { "rubies/ruby/CVE-2026-12345.yml": 'cve: "2026-12345"\ntitle: Interpreter fixture\npatched_versions:\n  - "~> 3.2.0, != 3.2.1"\n' });
        expect((await report(store, "ruby", "3.2.1", "ruby-lang", fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
        expect((await report(store, "ruby", "3.2.2", "ruby-lang", fetcher)).findings).toEqual([]);
        expect((await report(store, "ruby", "3.3.0", "ruby-lang", fetcher)).findings).toMatchObject([{ applicability: "applicable" }]);
    } finally { db.close(); }
});
test("public post-consent revalidation rereads fresh GitHub snapshots without poisoning or extending their checked time", async () => {
    const { store, db, setClock } = setup(); let calls = 0;
    try {
        const primed = await handle(refreshRequest({ runtime: "bun", github_token: jobToken }), store, undefined, now, async () => { calls++; return Response.json([advisory("bun", "<1.2.0")]); }, refreshSecret);
        expect(await primed.json()).toMatchObject({ refreshed: true }); expect(calls).toBe(1);
        const later = "2026-11-17T02:02:00.000Z"; setClock(later);
        const response = await handle(request("bun", "1.1.0", "oven-sh", { "cache-control": "no-cache" }), store, undefined, later, async () => { calls++; return new Response(null, { status: 403 }); });
        const body = object(await response.json()); expect(body.coverage).toBe("assessed"); expect(body.sources).toMatchObject([{ checked_at: now, complete: true }]); expect(calls).toBe(1);
        const row = db.query<{ successful_at: string; error: string | null }, []>("SELECT successful_at,error FROM runtime_source").get();
        expect(row).toEqual({ successful_at: now, error: null });
        const expired = "2026-11-17T02:31:00.000Z"; setClock(expired);
        const stale = await handle(request("bun", "1.1.0", "oven-sh", { "cache-control": "no-cache" }), store, undefined, expired, async () => { calls++; return new Response(null, { status: 403 }); });
        expect(object(await stale.json()).coverage).toBe("partial"); expect(stale.headers.get("cache-control")).toBe("no-store"); expect(calls).toBe(2);
    } finally { db.close(); }
});

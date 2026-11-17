import { satisfies, valid, validRange, compare } from "semver";
import { parseDocument } from "yaml";
import { parse as parseToml } from "smol-toml";
import { ZipReader, Uint8ArrayReader } from "@zip.js/zip.js/lib/zip-core-native.js";
import { Requirement as RubyRequirement } from "@renovatebot/ruby-semver/dist/ruby/requirement.js";
import { Version as RubyVersion } from "@renovatebot/ruby-semver/dist/ruby/version.js";
import { boundedBody, cveId, cveUrl, date, decodeUtf8, object, parseCve, sha256, string } from "./domain";
import { type Fetcher } from "./ingestion";
import { type Store } from "./storage";

const MINUTE = 60_000;
const SOURCE_TTL = 30 * MINUTE;
const SOURCE_BYTES = 8 * 1024 * 1024;
const MAX_FINDINGS = 512;
const VENDORS = {
    node: "nodejs", python: "cpython", go: "golang", rust: "rust-lang", ruby: "ruby-lang",
    java: "temurin", bun: "oven-sh", pi: "earendil-works", deno: "denoland", zig: "ziglang",
    dotnet: "microsoft", erlang: "erlang", php: "php", swift: "swiftlang",
};
type Runtime = keyof typeof VENDORS;
export type RuntimeIdentity = { runtime: Runtime; vendor: string; version: string; os: string; arch: string };
export type RuntimeFinding = { id: string; summary: string; applicability: "applicable" | "possible"; severity: string | null; urls: string[] };
type SourceReceipt = { name: string; url: string; revision: string | null; payload_sha256: string; checked_at: string; complete: boolean };
type SourceRow = { cache_key: string; source_url: string; checked_at: string; successful_at: string | null; revision: string | null; payload_sha256: string | null; object_key: string | null; error: string | null };
type Previous = { raw: string; revision: string | null };
type Produced = Previous & ({ complete: true } | { complete: false; gap: string });
type Loaded = { raw: string; receipt: SourceReceipt };
type Producer = (previous: Previous | null) => Promise<Produced>;

function runtimeName(value: string): Runtime {
    switch (value) {
        case "node": case "python": case "go": case "rust": case "ruby": case "java": case "bun":
        case "pi": case "deno": case "zig": case "dotnet": case "erlang": case "php": case "swift": return value;
        default: throw new Error("invalid runtime name");
    }
}
function identity(url: URL): RuntimeIdentity {
    const match = /^\/v1\/runtimes\/([a-z]+)$/.exec(url.pathname);
    if (!match?.[1]) throw new Error("invalid runtime route");
    const runtime = runtimeName(match[1]);
    const keys = [...url.searchParams.keys()].sort();
    if (keys.join(",") !== "arch,os,vendor,version") throw new Error("invalid runtime query");
    const vendor = url.searchParams.get("vendor") ?? "";
    const version = url.searchParams.get("version") ?? "";
    const os = url.searchParams.get("os") ?? "";
    const arch = url.searchParams.get("arch") ?? "";
    if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(vendor) || !/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$/.test(version) ||
        !["linux", "macos", "windows"].includes(os) || !["x86_64", "aarch64"].includes(arch))
        throw new Error("invalid runtime identity");
    return { runtime, vendor, version, os, arch };
}
function text(value: unknown, limit = 256): string {
    return string(value).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, " ").trim().slice(0, limit);
}
function safeUrl(value: unknown): string | null {
    if (typeof value !== "string" || value.length > 1024 || /[\u0000-\u0020\u007f-\u009f]/.test(value)) return null;
    try {
        const url = new URL(value);
        if (url.protocol !== "https:" || url.username || url.password || url.port || !url.hostname.includes(".") ||
            /^(?:localhost|127\.|10\.|192\.168\.|169\.254\.|\[)/.test(url.hostname)) return null;
        return url.href;
    } catch { return null; }
}
function findingId(value: unknown): string {
    const id = string(value);
    if (!/^(?:CVE-\d{4}-\d{4,19}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|GO-\d{4}-\d{4,8}|RUSTSEC-\d{4}-\d{4,8}|PSF-\d{4}-\d{1,8}|NODE-CORE-\d{1,9}|RUBY-CORE-[A-Za-z0-9._-]{1,100}|DOTNET-SECURITY-[A-Za-z0-9.+_-]{1,80}|MAL-\d{4}-\d{1,10})$/.test(id))
        throw new Error("unsupported advisory identifier");
    return id;
}
function reference(id: string): string {
    if (id.startsWith("CVE-")) return `https://www.cve.org/CVERecord?id=${id}`;
    if (id.startsWith("NODE-CORE-")) return `https://github.com/nodejs/security-wg/blob/main/vuln/core/${id.slice(10)}.json`;
    if (id.startsWith("RUBY-CORE-")) return `https://github.com/rubysec/ruby-advisory-db/blob/master/rubies/ruby/${id.slice(10)}.yml`;
    if (id.startsWith("DOTNET-SECURITY-")) return `https://github.com/dotnet/core/tree/main/release-notes/${id.slice(16).split(".").slice(0, 2).join(".")}`;
    return `https://osv.dev/vulnerability/${id}`;
}
function array(value: unknown, limit = 4096): unknown[] {
    if (!Array.isArray(value) || value.length > limit) throw new Error("invalid bounded source array");
    return value;
}
function semverMatch(version: string, requirement: unknown): boolean | null {
    if (typeof requirement !== "string" || !requirement.trim() || requirement.length > 2048 || !valid(version)) return null;
    const range = validRange(requirement);
    return range === null ? null : satisfies(version, range, { includePrerelease: true });
}
function numeric(value: string): number[] | null {
    if (!/^\d{1,9}(?:\.\d{1,9}){0,3}$/.test(value)) return null;
    return value.split(".").map(Number);
}
function numericCompare(a: string, b: string): number | null {
    const left = numeric(a), right = numeric(b);
    if (!left || !right) return null;
    for (let i = 0; i < Math.max(left.length, right.length); i++) {
        const difference = (left[i] ?? 0) - (right[i] ?? 0);
        if (difference !== 0) return difference < 0 ? -1 : 1;
    }
    return 0;
}
function numericRange(version: string, range: unknown): boolean | null {
    if (typeof range !== "string" || range.length > 2048) return null;
    const alternatives = range.split("||");
    if (alternatives.length > 32) return null;
    let unknown = false;
    for (const alternative of alternatives) {
        const terms = alternative.trim().replace(/,/g, " ").match(/(?:>=|<=|>|<|=)?\s*\d+(?:\.\d+){0,3}/g);
        if (!terms || terms.length > 16 || alternative.replace(/(?:>=|<=|>|<|=)?\s*\d+(?:\.\d+){0,3}/g, "").replace(/[\s,]/g, "") !== "") { unknown = true; continue; }
        let matched = true;
        for (const term of terms) {
            const match = /^(>=|<=|>|<|=)?\s*(\d+(?:\.\d+){0,3})$/.exec(term.trim());
            if (!match?.[2]) { unknown = true; matched = false; break; }
            const compared = numericCompare(version, match[2]);
            if (compared === null) { unknown = true; matched = false; break; }
            const operator = match[1] ?? "=";
            if (!(operator === ">=" ? compared >= 0 : operator === "<=" ? compared <= 0 : operator === ">" ? compared > 0 : operator === "<" ? compared < 0 : compared === 0)) matched = false;
        }
        if (matched) return true;
    }
    return unknown ? null : false;
}

class Assessment {
    readonly findings = new Map<string, RuntimeFinding>();
    readonly gaps = new Set<string>();
    readonly sources = new Map<string, SourceReceipt>();
    gap(value: string) { if (this.gaps.size < 64) this.gaps.add(value.slice(0, 1024)); }
    add(idValue: unknown, summary: unknown, applicability: "applicable" | "possible", severity: unknown, urls: unknown[] = []) {
        const id = findingId(idValue);
        const accepted = [...new Set([reference(id), ...urls.map(safeUrl).filter((url): url is string => url !== null)])].slice(0, 4);
        const previous = this.findings.get(id);
        if (!previous && this.findings.size >= MAX_FINDINGS) { this.gap("Advisory finding limit reached; coverage remains incomplete"); return; }
        this.findings.set(id, { id, summary: text(summary), applicability: previous?.applicability === "applicable" ? "applicable" : applicability,
            severity: typeof severity === "string" ? text(severity, 64) : previous?.severity ?? null,
            urls: [...new Set([...(previous?.urls ?? []), ...accepted])].slice(0, 4) });
    }
    source(receipt: SourceReceipt) {
        const key = `${receipt.name}\0${receipt.url}`;
        if (!this.sources.has(key) && this.sources.size >= 16) throw new Error("source receipt limit reached");
        this.sources.set(key, receipt);
    }
}

class Sources {
    readonly signal = AbortSignal.timeout(25_000);
    private requests = 0;
    constructor(readonly store: Store, readonly fetcher: Fetcher, readonly now: string, readonly force: boolean, readonly assessment: Assessment, private readonly credential?: string) {}
    async response(url: string, init: RequestInit = {}): Promise<Response> {
        if (++this.requests > 768) throw new Error("runtime source request budget exceeded");
        this.signal.throwIfAborted();
        const parsed = new URL(url);
        if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port ||
            !["raw.githubusercontent.com", "api.github.com", "codeload.github.com", "api.osv.dev", "builds.dotnet.microsoft.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(parsed.hostname))
            throw new Error("unapproved runtime source origin");
        return this.fetcher(url, { ...init, redirect: "manual", signal: this.signal,
            headers: { "User-Agent": "omg-advisories/1.0", Accept: "application/json", ...(this.force ? { "Cache-Control": "no-cache" } : {}), ...init.headers } });
    }
    async json(url: string, init?: RequestInit, limit = SOURCE_BYTES): Promise<unknown> {
        const response = await this.response(url, init);
        if (response.status !== 200) throw await this.failure(response, url);
        return JSON.parse(await boundedBody(response.body, limit));
    }
    async failure(response: Response, url: string): Promise<Error> {
        await response.body?.cancel();
        let diagnostic = "";
        if (new URL(url).origin === "https://api.github.com" && [403, 429].includes(response.status)) {
            const number = (header: string) => {
                const value = response.headers.get(header);
                return value !== null && /^\d{1,12}$/.test(value) ? value : "unknown";
            };
            diagnostic = `; GitHub rate limit remaining=${number("x-ratelimit-remaining")} reset=${number("x-ratelimit-reset")} retry_after=${number("retry-after")}`;
        }
        return new Error(`source HTTP ${response.status}${diagnostic}`);
    }
    async read(key: string, name: string, url: string, produce: Producer): Promise<Loaded | null> {
        const cacheKey = `v1:${key}`;
        const read = () => this.store.sql.first<SourceRow>("SELECT * FROM runtime_source WHERE cache_key=?", [cacheKey]);
        let cached = await read();
        const stored = async (row: SourceRow | null): Promise<Loaded | null> => {
            if (!row?.object_key || !row.payload_sha256 || !row.successful_at || row.source_url !== url) return null;
            if (!/^[a-f0-9]{64}$/.test(row.payload_sha256) || !row.object_key.startsWith("runtime/")) throw new Error("invalid runtime cache pointer");
            const raw = await this.store.raw.get(row.object_key);
            if (!raw) throw new Error("runtime source object missing");
            const body = await raw.text();
            if (new TextEncoder().encode(body).length > SOURCE_BYTES || await sha256(body) !== row.payload_sha256) throw new Error("runtime cache payload mismatch");
            JSON.parse(body);
            const checked = date(row.successful_at);
            const fresh = checked <= this.now && Date.parse(this.now) - Date.parse(checked) <= SOURCE_TTL;
            return { raw: body, receipt: { name, url, revision: row.revision, payload_sha256: row.payload_sha256, checked_at: checked, complete: fresh && row.error === null } };
        };
        const use = (loaded: Loaded | null) => {
            if (loaded) {
                this.assessment.source(loaded.receipt);
                if (!loaded.receipt.complete) this.assessment.gap(`${name} is stale or unavailable; retained last successful snapshot: ${url}`);
            } else this.assessment.gap(`${name} is unavailable: ${url}`);
            return loaded;
        };
        let previous = await stored(cached);
        const scheduledGitHubSource = key.startsWith("ghsa:") || ["python:psf", "rust:components", "ruby:mri", "java:temurin-vdr"].includes(key);
        if (!this.credential && scheduledGitHubSource && previous?.receipt.complete) return use(previous);
        const age = cached ? Date.parse(this.now) - Date.parse(cached.checked_at) : Infinity;
        if (!this.force && age >= 0 && age < (cached?.error ? MINUTE : SOURCE_TTL)) return use(previous);
        const lease = `runtime:${await sha256(cacheKey)}`, owner = crypto.randomUUID();
        if (!await this.store.lease(lease, owner, this.now)) {
            this.assessment.gap(`${name} refresh is already in progress`);
            if (previous) previous.receipt.complete = false;
            return use(previous);
        }
        try {
            cached = await read(); previous = await stored(cached);
            let incoming: Produced;
            try {
                incoming = await produce(previous ? { raw: previous.raw, revision: previous.receipt.revision } : null);
                if (new TextEncoder().encode(incoming.raw).length > SOURCE_BYTES) throw new Error("runtime source body exceeds limit");
                if (this.credential && incoming.raw.includes(this.credential)) throw new Error("source reflected a refresh credential");
                JSON.parse(incoming.raw);
                if (incoming.revision !== null && (incoming.revision.length > 256 || /[\u0000-\u001f\u007f]/.test(incoming.revision))) throw new Error("invalid source revision");
            } catch (error) {
                const message = error instanceof Error ? error.message : "unknown source failure";
                const reason = text(this.credential ? message.replaceAll(this.credential, "[redacted]") : message, 160);
                await this.store.writer(lease, owner).sql.batch([{
                    sql: "INSERT INTO runtime_source(cache_key,source_url,checked_at,error) VALUES(?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET checked_at=excluded.checked_at,error=excluded.error",
                    values: [cacheKey, url, this.now, reason],
                }]);
                this.assessment.gap(`${name} refresh failed (${reason}): ${url}`);
                if (previous) previous.receipt.complete = false;
                return use(previous);
            }
            const hash = await sha256(incoming.raw), keyHash = await sha256(cacheKey);
            const objectKey = `runtime/${keyHash}/${hash}.json`;
            if (cached?.payload_sha256 !== hash) await this.store.raw.put(objectKey, incoming.raw);
            if (!incoming.complete && cached?.error === null && previous) {
                await this.store.writer(lease, owner).sql.batch([{ sql: "UPDATE runtime_source SET checked_at=?,error=? WHERE cache_key=?", values: [this.now, incoming.gap, cacheKey] }]);
            } else await this.store.writer(lease, owner).sql.batch([{
                sql: "INSERT INTO runtime_source(cache_key,source_url,checked_at,successful_at,revision,payload_sha256,object_key,error) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET source_url=excluded.source_url,checked_at=excluded.checked_at,successful_at=excluded.successful_at,revision=excluded.revision,payload_sha256=excluded.payload_sha256,object_key=excluded.object_key,error=excluded.error",
                values: [cacheKey, url, this.now, this.now, incoming.revision, hash, objectKey, incoming.complete ? null : incoming.gap],
            }]);
            if (!incoming.complete) this.assessment.gap(incoming.gap);
            return use({ raw: incoming.raw, receipt: { name, url, revision: incoming.revision, payload_sha256: hash, checked_at: this.now, complete: incoming.complete } });
        } finally { await this.store.release(lease, owner); }
    }
    jsonSource(key: string, name: string, url: string, validate?: (value: unknown) => void) {
        return this.read(key, name, url, async (previous) => {
            const response = await this.response(url, { headers: previous?.revision ? { "If-None-Match": previous.revision } : {} });
            if (response.status === 304 && previous) return { ...previous, complete: true };
            if (response.status !== 200) { await response.body?.cancel(); throw new Error(`source HTTP ${response.status}`); }
            const raw = await boundedBody(response.body, SOURCE_BYTES);
            const payload: unknown = JSON.parse(raw);
            validate?.(payload);
            return { raw, revision: response.headers.get("etag"), complete: true };
        });
    }
    textSource(key: string, name: string, url: string) {
        return this.read(key, name, url, async (previous) => {
            const response = await this.response(url, { headers: previous?.revision ? { "If-None-Match": previous.revision } : {} });
            if (response.status === 304 && previous) return { ...previous, complete: true };
            if (response.status !== 200) { await response.body?.cancel(); throw new Error(`source HTTP ${response.status}`); }
            return { raw: JSON.stringify({ text: await boundedBody(response.body, SOURCE_BYTES) }), revision: response.headers.get("etag"), complete: true };
        });
    }
    archive(key: string, name: string, repo: string, branch: string, select: RegExp, validate?: (raw: string) => void) {
        const sourceUrl = `https://github.com/${repo}/tree/${branch}`;
        return this.read(key, name, sourceUrl, async (previous) => {
            const commit = object(await this.json(`https://api.github.com/repos/${repo}/commits/${branch}`));
            const revision = string(commit.sha);
            if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error("invalid upstream commit identity");
            if (previous?.revision === revision) return { ...previous, complete: true };
            const response = await this.response(`https://codeload.github.com/${repo}/zip/${revision}`);
            if (response.status !== 200 || !response.body) { await response.body?.cancel(); throw new Error(`source archive HTTP ${response.status}`); }
            const reader = response.body.getReader(), chunks: Uint8Array[] = [];
            let bytes = 0;
            try {
                for (;;) {
                    const part = await reader.read();
                    if (part.done) break;
                    bytes += part.value.byteLength;
                    if (bytes > 16 * 1024 * 1024) { await reader.cancel(); throw new Error("source archive exceeds compressed limit"); }
                    chunks.push(part.value);
                }
            } finally { reader.releaseLock(); }
            const compressed = new Uint8Array(bytes);
            let offset = 0;
            for (const chunk of chunks) { compressed.set(chunk, offset); offset += chunk.length; }
            const zip = new ZipReader(new Uint8ArrayReader(compressed), { useWebWorkers: false, useCompressionStream: true, checkCrc32: true, checkOverlappingEntry: true });
            const files: { path: string; raw: string }[] = [];
            const names = new Set<string>();
            let entries = 0, total = 0;
            const prefix = `${repo.split("/")[1]}-${revision}/`;
            try {
                for await (const entry of zip.getEntriesGenerator()) {
                    if (++entries > 32768) throw new Error("source archive entry budget exceeded");
                    if (entry.directory || !entry.filename.startsWith(prefix)) continue;
                    const path = entry.filename.slice(prefix.length);
                    if (!select.test(path)) continue;
                    if (entry.encrypted || entry.uncompressedSize > 1024 * 1024 || entry.uncompressedSize < 1 || files.length >= 4096 || names.has(path))
                        throw new Error("invalid selected advisory archive entry");
                    names.add(path);
                    const content: Uint8Array[] = [];
                    let size = 0;
                    await entry.getData(new WritableStream<Uint8Array>({ write(chunk) {
                        size += chunk.byteLength; total += chunk.byteLength;
                        if (size > 1024 * 1024 || total > SOURCE_BYTES) throw new Error("source archive expansion exceeds limit");
                        content.push(chunk);
                    } }), { signal: this.signal, checkCrc32: true, useWebWorkers: false, useCompressionStream: true });
                    if (size !== entry.uncompressedSize) throw new Error("source archive decoded size mismatch");
                    const decoded = new Uint8Array(size); let position = 0;
                    for (const chunk of content) { decoded.set(chunk, position); position += chunk.length; }
                    const raw = decodeUtf8(decoded);
                    validate?.(raw);
                    files.push({ path, raw });
                }
            } finally { await zip.close(); }
            if (!files.length) throw new Error("source archive has no expected advisories");
            return { raw: JSON.stringify(files.sort((a, b) => a.path.localeCompare(b.path))), revision, complete: true };
        });
    }
}

async function node(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const url = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json";
    const source = await sources.jsonSource("node:core", "Node.js core advisories", url, (payload) => {
        const entries = Object.entries(object(payload));
        if (!entries.length || entries.length > 4096) throw new Error("invalid Node advisory index");
        for (const [key, value] of entries) {
            if (!/^\d{1,9}$/.test(key)) throw new Error("invalid Node advisory key");
            const row = object(value);
            string(row.vulnerable); string(row.patched);
            for (const id of array(row.cve, 32)) cveId(id);
        }
    });
    if (!source) return;
    const records = Object.entries(object(JSON.parse(source.raw)));
    if (records.length === 0 || records.length > 4096) throw new Error("invalid Node advisory index");
    for (const [key, value] of records) {
        if (!/^\d{1,9}$/.test(key)) throw new Error("invalid Node advisory key");
        const row = object(value);
        const vulnerable = semverMatch(identity.version, row.vulnerable);
        const patched = semverMatch(identity.version, row.patched);
        if (vulnerable === false || patched === true) continue;
        const certain = vulnerable === true && patched === false;
        if (!certain) result.gap("Node advisory index contains an unsupported applicability range");
        const ids = array(row.cve, 32);
        for (const id of ids.length ? ids : [`NODE-CORE-${key}`])
            result.add(id, row.description ?? "Published Node.js core advisory", certain ? "applicable" : "possible", row.severity, [row.ref, url]);
    }
}
async function osv(identity: RuntimeIdentity, sources: Sources, result: Assessment, ecosystem: string, packageName: string) {
    const url = "https://api.osv.dev/v1/query";
    const loaded = await sources.read(`osv:${ecosystem}:${packageName}:${identity.version}`, `OSV ${ecosystem} ${packageName}`, url, async () => {
        let token: string | null = null;
        const tokens = new Set<string>(), ids = new Set<string>(), rows: unknown[] = [];
        let bytes = 2;
        for (let page = 0; page < 20; page++) {
            const body: { package: { ecosystem: string; name: string }; version: string; page_token?: string } = { package: { ecosystem, name: packageName }, version: identity.version };
            if (token !== null) body.page_token = token;
            const response = object(await sources.json(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }));
            for (const value of response.vulns === undefined ? [] : array(response.vulns)) {
                const row = object(value), id = findingId(row.id);
                if (ids.has(id) || rows.length >= 4096) throw new Error("duplicate or excessive OSV findings");
                bytes += new TextEncoder().encode(JSON.stringify(row)).length + 1;
                if (bytes > SOURCE_BYTES) throw new Error("OSV paginated source exceeds limit");
                ids.add(id); rows.push(row);
            }
            if (response.next_page_token === undefined || response.next_page_token === "") return { raw: JSON.stringify(rows.sort((a, b) => string(object(a).id).localeCompare(string(object(b).id)))), revision: null, complete: true };
            token = string(response.next_page_token);
            if (token.length > 4096 || tokens.has(token)) throw new Error("invalid OSV pagination");
            tokens.add(token);
        }
        throw new Error("OSV pagination budget exceeded; complete result unavailable");
    });
    if (!loaded) return;
    for (const value of array(JSON.parse(loaded.raw))) {
        const row = object(value);
        if (row.withdrawn !== undefined && date(row.withdrawn) <= sources.now) continue;
        const aliases = row.aliases === undefined ? [] : array(row.aliases, 64);
        const id = aliases.find((alias) => typeof alias === "string" && /^CVE-\d{4}-\d{4,19}$/.test(alias)) ?? row.id;
        const refs = row.references === undefined ? [] : array(row.references, 128).map((ref) => object(ref).url);
        const specific = row.database_specific === undefined ? {} : object(row.database_specific);
        result.add(id, row.summary ?? "Published vulnerability affecting this exact runtime version", "applicable", specific.severity, refs);
    }
}

async function github(identity: RuntimeIdentity, sources: Sources, result: Assessment, repo: string, knownNames: string[], completeAuthority = true, components: Map<string, string> | null = null) {
    const url = `https://api.github.com/repos/${repo}/security-advisories`;
    const loaded = await sources.read(`ghsa:${repo}`, `${repo} publisher advisories`, url, async () => {
        const rows: unknown[] = [], ids = new Set<string>();
        let bytes = 2;
        for (let page = 1; page <= 20; page++) {
            const batch = array(await sources.json(`${url}?per_page=100&page=${page}`), 100);
            for (const value of batch) {
                const row = object(value), id = findingId(row.ghsa_id);
                if (ids.has(id)) throw new Error("duplicate publisher advisory across pages");
                bytes += new TextEncoder().encode(JSON.stringify(row)).length + 1;
                if (bytes > SOURCE_BYTES) throw new Error("publisher paginated source exceeds limit");
                ids.add(id); rows.push(row);
            }
            if (batch.length < 100) return { raw: JSON.stringify(rows.sort((a, b) => string(object(a).ghsa_id).localeCompare(string(object(b).ghsa_id)))), revision: null, complete: true };
        }
        throw new Error("publisher advisory pagination budget exceeded");
    });
    if (!loaded) return;
    if (!completeAuthority) result.gap(`${repo} has no established complete runtime applicability feed; empty publisher results are not clean coverage`);
    for (const value of array(JSON.parse(loaded.raw))) {
        const row = object(value);
        if (row.withdrawn_at !== null && row.withdrawn_at !== undefined && date(row.withdrawn_at) <= sources.now) continue;
        const entries = array(row.vulnerabilities, 256).map(object);
        const hasRuntimeEntry = entries.some((entry) => knownNames.includes(string(object(entry.package).name)));
        let applicable = false, possible = false;
        for (const entry of entries) {
            const packageRow = object(entry.package), name = string(packageRow.name);
            const componentVersion = components?.get(name);
            if (!knownNames.includes(name) && !componentVersion) {
                if (identity.runtime === "erlang" && hasRuntimeEntry) continue;
                possible = true; result.gap(`${repo} declares a component whose installed version is not established`); continue;
            }
            const assessedVersion = componentVersion ?? identity.version;
            let match = identity.runtime === "erlang" ? numericRange(assessedVersion, entry.vulnerable_version_range) : semverMatch(assessedVersion, entry.vulnerable_version_range);
            const fixes = typeof entry.patched_versions === "string" ? entry.patched_versions.split(",").map((item) => item.trim()).filter(Boolean) : [];
            if (identity.runtime === "erlang") {
                const version = numeric(assessedVersion);
                if (!version) match = null;
                const branch = fixes.filter((fix) => numeric(fix)?.[0] === version?.[0] && (!componentVersion || numeric(fix)?.[1] === version?.[1]));
                if (branch.some((fix) => { const order = numericCompare(assessedVersion, fix); return order !== null && order >= 0; })) match = false;
                if (match === true && fixes.length && !branch.length && version && fixes.every((fix) => (numeric(fix)?.[0] ?? Infinity) < (version[0] ?? 0))) match = null;
            } else if (identity.runtime === "php" && fixes.length) {
                const selected = numeric(identity.version), parsedFixes = fixes.map(numeric);
                const same = parsedFixes.some((fix) => fix && selected && fix[0] === selected[0] && fix[1] === selected[1]);
                const hasSameBranchEntry = entries.some((other) => typeof other.patched_versions === "string" && other.patched_versions.split(",").some((fix) => { const parts = numeric(fix.trim()); return parts && selected && parts[0] === selected[0] && parts[1] === selected[1]; }));
                if (hasSameBranchEntry && !same) continue;
                if (!same && match === true) match = null;
            }
            if (match === true) applicable = true;
            if (match === null) { possible = true; result.gap(`${repo} has unsupported or ambiguous branch/component applicability`); }
        }
        if (applicable || possible) result.add(row.cve_id ?? row.ghsa_id, row.summary ?? "Published runtime security advisory", applicable && completeAuthority ? "applicable" : "possible", row.severity, [row.html_url, url]);
    }
}

function rubyMatch(version: string, requirement: unknown): boolean | null {
    if (typeof requirement !== "string" || !requirement.trim() || requirement.length > 2048 || requirement.split(",").length > 16) return null;
    try { return new RubyRequirement(...requirement.split(",")).isSatisfiedBy(new RubyVersion(version)); }
    catch { return null; }
}
function versionLists(version: string, value: unknown, ruby = false): { matched: boolean; unsupported: boolean } {
    let matched = false, unsupported = false;
    for (const requirement of value === undefined ? [] : array(value, 64)) {
        const result = ruby ? rubyMatch(version, requirement) : semverMatch(version, requirement);
        if (result === true) matched = true;
        if (result === null) unsupported = true;
    }
    return { matched, unsupported };
}
async function ruby(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const parse = (raw: string) => {
        const document = parseDocument(raw, { uniqueKeys: true, schema: "core" });
        if (document.errors.length || document.warnings.length) throw new Error("unsupported Ruby advisory YAML");
        const row = object(document.toJS({ maxAliasCount: 0 }));
        versionLists(identity.version, row.patched_versions, true); versionLists(identity.version, row.unaffected_versions, true);
        return row;
    };
    const loaded = await sources.archive("ruby:mri", "RubySec MRI interpreter advisories", "rubysec/ruby-advisory-db", "master", /^rubies\/ruby\/[A-Za-z0-9_.-]+\.ya?ml$/, parse);
    if (!loaded) return;
    for (const file of array(JSON.parse(loaded.raw))) {
        const row = parse(string(object(file).raw));
        const patched = versionLists(identity.version, row.patched_versions, true);
        const unaffected = versionLists(identity.version, row.unaffected_versions, true);
        if (patched.matched || unaffected.matched) continue;
        const uncertain = patched.unsupported || unaffected.unsupported;
        if (uncertain) result.gap("MRI advisory contains an unsupported Ruby version requirement");
        const stem = string(object(file).path).split("/").at(-1)?.replace(/\.ya?ml$/, "");
        const id = row.cve === undefined ? row.ghsa === undefined ? `RUBY-CORE-${stem}` : `GHSA-${string(row.ghsa).replace(/^GHSA-/, "")}` : `CVE-${string(row.cve).replace(/^CVE-/, "")}`;
        result.add(id, row.title ?? "MRI interpreter advisory", uncertain ? "possible" : "applicable", null, [row.url, loaded.receipt.url]);
    }
    result.gap("MRI interpreter records do not establish the versions of every gem bundled by a prebuilt Ruby distribution");
}
async function rust(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const parse = (raw: string) => {
        const block = /^```toml\r?\n([\s\S]*?)\r?\n```/.exec(raw);
        if (!block?.[1]) throw new Error("invalid Rust toolchain advisory TOML fence");
        const document = object(parseToml(block[1]));
        const advisory = object(document.advisory), versions = object(document.versions);
        findingId(advisory.id); versionLists(identity.version, versions.patched); versionLists(identity.version, versions.unaffected);
        return { block, advisory, versions };
    };
    const loaded = await sources.archive("rust:components", "RustSec toolchain component advisories", "rustsec/advisory-db", "main", /^rust\/(?:std|cargo|rustdoc)\/[A-Za-z0-9_.-]+\.md$/, parse);
    if (!loaded) return;
    for (const value of array(JSON.parse(loaded.raw))) {
        const raw = string(object(value).raw);
        const { block, advisory, versions } = parse(raw);
        if (advisory.withdrawn !== undefined) {
            const withdrawn = advisory.withdrawn instanceof Date ? advisory.withdrawn.toISOString() : `${string(advisory.withdrawn)}T00:00:00Z`;
            if (date(withdrawn) <= sources.now) continue;
        }
        const patched = versionLists(identity.version, versions.patched);
        const unaffected = versionLists(identity.version, versions.unaffected);
        if (patched.matched || unaffected.matched) continue;
        const heading = raw.slice(block[0].length).split(/\r?\n/).find((line) => line.startsWith("# "))?.slice(2) ?? "Rust toolchain component vulnerability";
        const uncertain = patched.unsupported || unaffected.unsupported;
        if (uncertain) result.gap("Rust toolchain component has an unsupported release range");
        result.add(advisory.id, heading, uncertain ? "possible" : "applicable", typeof advisory.cvss === "string" ? advisory.cvss : null, [advisory.url, loaded.receipt.url]);
    }
    result.gap("RustSec toolchain component records are supplemental; complete compiler and bundled-tool applicability is not established by this source");
}

type CveState = "affected" | "unaffected" | "unknown";
type DotnetComponents = { sdk: string; runtime: string; aspnet: string | null };
function cveState(payload: unknown, selected: RuntimeIdentity, dotnet?: DotnetComponents): CveState {
    const parsed = parseCve(JSON.stringify(payload));
    if (parsed.state === "REJECTED") return "unaffected";
    if (!parsed.supported) return "unknown";
    const cna = object(object(object(payload).containers).cna);
    const rows = cna.affected === undefined ? [] : array(cna.affected, 256);
    let matchedProduct = false, affected = false, unknown = false;
    for (const item of rows) {
        const row = object(item);
        const vendor = typeof row.vendor === "string" ? row.vendor.toLowerCase() : "";
        const product = typeof row.product === "string" ? row.product.toLowerCase() : "";
        const productMatches = selected.runtime === "python"
            ? ["python software foundation", "psf", "python"].includes(vendor) && ["python", "cpython"].includes(product)
            : selected.runtime === "dotnet" ? vendor === "microsoft" && /^(?:\.net|\.net core|asp\.net core|asp\.net|microsoft \.net)/.test(product)
                : false;
        if (!productMatches) continue;
        matchedProduct = true;
        const assessedVersion = dotnet ? product.includes("sdk") ? dotnet.sdk : product.includes("asp.net") || product.includes("aspnet") ? dotnet.aspnet : dotnet.runtime : selected.version;
        if (assessedVersion === null) { unknown = true; continue; }
        let status: CveState = row.defaultStatus === "affected" ? "affected" : row.defaultStatus === "unaffected" ? "unaffected" : "unknown";
        let explicit: CveState | null = null;
        for (const versionValue of row.versions === undefined ? [] : array(row.versions, 256)) {
            const version = object(versionValue), first = string(version.version);
            let matches: boolean | null;
            const lower = first === "*" ? 0 : numericCompare(assessedVersion, first);
            if (version.lessThan !== undefined || version.lessThanOrEqual !== undefined) {
                if (!["python", "semver", "custom"].includes(string(version.versionType))) { unknown = true; continue; }
                const upper = numericCompare(assessedVersion, string(version.lessThan ?? version.lessThanOrEqual));
                matches = lower === null || upper === null ? null : lower >= 0 && (version.lessThan !== undefined ? upper < 0 : upper <= 0);
            } else matches = first === "*" ? true : lower === null ? null : lower === 0;
            if (matches === null) { unknown = true; continue; }
            if (!matches) continue;
            let current: CveState = version.status === "affected" ? "affected" : version.status === "unaffected" ? "unaffected" : "unknown";
            let previousChange: string | null = null;
            for (const changeValue of version.changes === undefined ? [] : array(version.changes, 256)) {
                const change = object(changeValue), at = string(change.at), order = numericCompare(assessedVersion, at);
                if (order === null) { current = "unknown"; break; }
                if (previousChange !== null && numericCompare(at, previousChange) !== 1) { current = "unknown"; break; }
                previousChange = at;
                if (order >= 0) current = change.status === "affected" ? "affected" : change.status === "unaffected" ? "unaffected" : "unknown";
            }
            if (explicit !== null && explicit !== current) { unknown = true; current = "unknown"; }
            explicit = current;
        }
        if (explicit !== null) status = explicit;
        if (status === "affected") affected = true;
        if (status === "unknown") unknown = true;
    }
    return affected ? "affected" : !matchedProduct || unknown ? "unknown" : "unaffected";
}
async function cveRecords(sources: Sources, result: Assessment, ids: string[]) {
    const allIds = [...new Set(ids.map(cveId))].sort();
    const chosen = allIds.slice(0, 512);
    const key = `cve5:${await sha256(chosen.join("\n"))}`;
    const loaded = await sources.read(key, "CVEProject vendor applicability records", "https://github.com/CVEProject/cvelistV5", async (previous) => {
        const records: Record<string, unknown> = previous ? object(JSON.parse(previous.raw)) : {};
        let bytes = new TextEncoder().encode(JSON.stringify(records)).length;
        let failures = allIds.length - chosen.length;
        for (let start = 0; start < chosen.length; start += 8) {
            const batch = chosen.slice(start, start + 8);
            const outcomes = await Promise.allSettled(batch.map(async (id) => {
                const payload = await sources.json(cveUrl(id), undefined, 1024 * 1024);
                const parsed = parseCve(JSON.stringify(payload), id);
                if (!parsed.supported) throw new Error("unsupported CVE schema");
                return { id, payload };
            }));
            for (const outcome of outcomes) {
                if (outcome.status === "fulfilled") {
                    const { id, payload } = outcome.value;
                    const removed = records[id] === undefined ? 0 : new TextEncoder().encode(JSON.stringify(records[id])).length;
                    const added = new TextEncoder().encode(JSON.stringify(payload)).length + (records[id] === undefined ? id.length + 4 : 0);
                    if (bytes - removed + added > SOURCE_BYTES - 2) failures++;
                    else { records[id] = payload; bytes += added - removed; }
                } else failures++;
            }
            if (sources.signal.aborted) { failures += chosen.length - start - batch.length; break; }
        }
        const raw = JSON.stringify(Object.fromEntries(Object.entries(records).sort(([a], [b]) => a.localeCompare(b))));
        return failures ? { raw, revision: null, complete: false, gap: `CVEProject applicability lookup is incomplete (${failures} records unavailable or over budget)` } : { raw, revision: null, complete: true };
    });
    if (!loaded) { result.gap("Vendor CVE applicability records are unavailable"); return {}; }
    return object(JSON.parse(loaded.raw));
}
async function python(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const loaded = await sources.archive("python:psf", "PSF CPython advisories", "psf/advisory-database", "main", /^advisories\/python\/[A-Za-z0-9_.-]+\.json$/, (raw) => {
        const row = object(JSON.parse(raw)); findingId(row.id);
        if (row.aliases !== undefined) array(row.aliases, 64);
    });
    if (!loaded) return;
    const records = array(JSON.parse(loaded.raw)).map((file) => object(JSON.parse(string(object(file).raw))));
    const ids = records.flatMap((row) => row.aliases === undefined ? [] : array(row.aliases, 64).filter((id): id is string => typeof id === "string" && /^CVE-\d{4}-\d{4,19}$/.test(id)));
    const cves = await cveRecords(sources, result, ids);
    for (const row of records) {
        if (row.withdrawn !== undefined && date(row.withdrawn) <= sources.now) continue;
        const aliases = row.aliases === undefined ? [] : array(row.aliases, 64);
        const refs = row.references === undefined ? [] : array(row.references, 128).map((value) => object(value).url);
        const ids = aliases.filter((item): item is string => typeof item === "string" && /^CVE-\d{4}-\d{4,19}$/.test(item));
        for (const id of ids.length ? ids : [string(row.id)]) {
            const state = cves[id] !== undefined ? cveState(cves[id], identity) : "unknown";
            if (state === "unaffected") continue;
            if (state === "unknown") result.gap("Some CPython records have Git-only or unsupported version applicability; no package-name substitution was made");
            result.add(id, row.summary ?? "Published CPython advisory", state === "affected" ? "applicable" : "possible", null, refs);
        }
    }
    result.gap("CPython core advisories do not establish complete applicability for libraries bundled by python-build-standalone");
}

async function erlang(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const url = "https://raw.githubusercontent.com/erlang/otp/master/otp_versions.table";
    const loaded = await sources.textSource("erlang:component-versions", "Erlang OTP component release table", url);
    let components: Map<string, string> | null = null;
    if (loaded) {
        const raw = string(object(JSON.parse(loaded.raw)).text);
        const prefix = `OTP-${identity.version} `;
        const lines = raw.split(/\r?\n/).filter((line) => line.startsWith(prefix));
        if (lines.length === 1) {
            const line = lines[0];
            if (line === undefined) throw new Error("missing OTP release row");
            const data = line.slice(prefix.length).replace(/^\s*:\s*/, "").replace(/:\s*$/, "").replace(/#/g, " ");
            components = new Map();
            for (const entry of data.trim().split(/\s+/)) {
                const match = /^([a-z][a-z0-9_]*)-(\d+(?:\.\d+){0,3})$/.exec(entry);
                if (!match?.[1] || !match[2] || components.has(match[1])) throw new Error("invalid OTP component version row");
                components.set(match[1], match[2]);
            }
        } else result.gap("Exact OTP release is absent or ambiguous in the component table");
    }
    await github(identity, sources, result, "erlang/otp", ["OTP", "Erlang/OTP"], true, components);
}

async function dotnet(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const parts = numeric(identity.version);
    if (!parts || parts.length !== 3) { result.gap("Exact .NET SDK release identity is unresolved"); return; }
    const channel = `${parts[0]}.${parts[1]}`;
    const url = `https://builds.dotnet.microsoft.com/dotnet/release-metadata/${channel}/releases.json`;
    const loaded = await sources.jsonSource(`dotnet:${channel}`, "Microsoft .NET SDK and runtime release metadata", url, (value) => {
        const row = object(value);
        if (row["channel-version"] !== channel) throw new Error(".NET release channel mismatch");
        array(row.releases, 2048);
    });
    if (!loaded) return;
    const payload = object(JSON.parse(loaded.raw));
    if (payload["channel-version"] !== channel) throw new Error(".NET release channel mismatch");
    const releases = array(payload.releases, 2048).map(object);
    const selected = releases.filter((release) => {
        const sdks = [...(release.sdk === undefined ? [] : [release.sdk]), ...(release.sdks === undefined ? [] : array(release.sdks, 128))];
        return sdks.some((sdk) => object(sdk).version === identity.version);
    });
    if (selected.length !== 1) { result.gap("Exact .NET SDK has no unique upstream SDK-to-component release mapping"); return; }
    const release = selected[0];
    if (!release) throw new Error("missing selected .NET release");
    const components: DotnetComponents = { sdk: identity.version, runtime: string(object(release.runtime).version), aspnet: release.aspnetcore === undefined ? null : string(object(release.aspnetcore).version) };
    if (!valid(components.runtime) || (components.aspnet !== null && !valid(components.aspnet))) throw new Error("invalid .NET component release identity");
    const later = releases.filter((row) => {
        if (typeof row["release-date"] === "string" && string(row["release-date"]) > sources.now.slice(0, 10)) { result.gap(".NET metadata includes a future release"); return false; }
        const sdks = [...(row.sdk === undefined ? [] : [row.sdk]), ...(row.sdks === undefined ? [] : array(row.sdks, 128))];
        const candidates: [string | null, string | null][] = [
            [row.runtime === undefined ? null : string(object(row.runtime).version), components.runtime],
            [row.aspnetcore === undefined ? null : string(object(row.aspnetcore).version), components.aspnet],
            ...sdks.map((sdk): [string, string] => [string(object(sdk).version), components.sdk]),
        ];
        let advances = false;
        for (const [version, installed] of candidates) {
            if (version === null || installed === null) continue;
            if (!valid(version)) result.gap(".NET metadata contains unsupported component versions");
            else if (compare(version, installed) > 0) advances = true;
        }
        return advances;
    });
    const ids: string[] = [];
    for (const row of later) {
        const cves = row["cve-list"] === undefined ? [] : array(row["cve-list"], 256);
        for (const item of cves) ids.push(cveId(object(item)["cve-id"]));
        if (row.security === true && !cves.length) {
            result.gap("Microsoft marks a later release as security-related without machine-readable CVE identifiers");
            result.add(`DOTNET-SECURITY-${string(row["release-version"])}`, "Microsoft published a later security release without CVE applicability identifiers", "possible", null, [url]);
        }
    }
    const cves = await cveRecords(sources, result, ids);
    for (const id of [...new Set(ids)]) {
        const state = cves[id] === undefined ? "unknown" : cveState(cves[id], identity, components);
        if (state === "unaffected") continue;
        if (state === "unknown") result.gap("Some Microsoft security fixes lack exact SDK/runtime/component applicability; release-list membership alone is not proof of an affected version");
        result.add(id, ".NET security fix published after the selected SDK or one of its bundled components", state === "affected" ? "applicable" : "possible", null, [url]);
    }
}

async function java(identity: RuntimeIdentity, sources: Sources, result: Assessment) {
    const version = identity.version.split("+")[0] ?? "";
    if ((numeric(version)?.length ?? 0) < 3) { result.gap("Temurin requires an exact upstream patch/build identity; a Java feature number does not establish applicability"); return; }
    const url = "https://api.github.com/repos/adoptium/temurin-vdr-generator/releases/latest";
    const loaded = await sources.read("java:temurin-vdr", "Eclipse Adoptium Temurin vulnerability disclosure report", url, async (previous) => {
        const release = object(await sources.json(url));
        const revision = string(release.tag_name);
        const assets = array(release.assets, 128).map(object).filter((asset) => /^temurin-vdr-[A-Za-z0-9_-]+\.json$/.test(string(asset.name)));
        if (assets.length !== 1) throw new Error("Temurin VDR asset is missing or ambiguous");
        const asset = assets[0];
        if (!asset) throw new Error("missing Temurin VDR asset");
        const digest = string(asset.digest).replace(/^sha256:/, "");
        if (!/^[a-f0-9]{64}$/.test(digest) || typeof asset.size !== "number" || asset.size < 1 || asset.size > SOURCE_BYTES) throw new Error("invalid Temurin VDR asset bounds or digest");
        if (previous?.revision === revision && await sha256(previous.raw) === digest) return { ...previous, complete: true };
        let next = string(asset.browser_download_url);
        if (!next.startsWith("https://github.com/adoptium/temurin-vdr-generator/releases/download/")) throw new Error("invalid Temurin VDR download origin");
        let raw: string | null = null;
        for (let redirects = 0; redirects <= 3; redirects++) {
            const response = await sources.response(next);
            if (response.status === 200) { raw = await boundedBody(response.body, SOURCE_BYTES); break; }
            if (![301, 302, 303, 307, 308].includes(response.status)) { await response.body?.cancel(); throw new Error(`Temurin VDR HTTP ${response.status}`); }
            const location = response.headers.get("location"); await response.body?.cancel();
            if (!location) throw new Error("missing Temurin VDR redirect");
            const redirect = new URL(location, next);
            if (!["release-assets.githubusercontent.com", "objects.githubusercontent.com"].includes(redirect.hostname)) throw new Error("unapproved Temurin VDR redirect");
            next = redirect.href;
        }
        if (raw === null || new TextEncoder().encode(raw).length !== asset.size || await sha256(raw) !== digest) throw new Error("Temurin VDR bytes do not match the official asset");
        return { raw, revision, complete: true };
    });
    if (!loaded) return;
    const payload = object(JSON.parse(loaded.raw));
    if (payload.bomFormat !== "CycloneDX" || !["1.5", "1.6", "1.7"].includes(string(payload.specVersion)) || object(object(payload.metadata).component).name !== "Eclipse Temurin")
        throw new Error("invalid Temurin vulnerability disclosure report");
    for (const value of array(payload.vulnerabilities)) {
        const row = object(value);
        let affected = false, possible = false;
        for (const item of row.affects === undefined ? [] : array(row.affects, 128)) {
            const target = object(item);
            if (target.ref !== "pkg:github/openjdk/jdk") { possible = true; continue; }
            for (const entry of target.versions === undefined ? [] : array(target.versions, 256)) {
                const range = object(entry);
                if (typeof range.range !== "string" || !range.range.startsWith("vers:generic/")) { possible = true; continue; }
                const versions = range.range.slice("vers:generic/".length).split("|");
                if (versions.length > 128) throw new Error("Temurin VDR version list exceeds limit");
                for (const declared of versions) {
                    const oldJava = /^8u(\d+)$/.exec(declared);
                    const candidate = oldJava?.[1] ? `8.0.${oldJava[1]}` : declared;
                    const order = numericCompare(version, candidate);
                    if (order === 0) affected = true;
                    else if (order !== null && order < 0 && numeric(version)?.[0] === numeric(candidate)?.[0]) possible = true;
                    else if (order === null) possible = true;
                }
            }
        }
        if (row.affects === undefined || array(row.affects, 128).length === 0) possible = true;
        if (affected || possible) {
            const source = row.source === undefined ? {} : object(row.source);
            result.add(row.id, row.description ?? "Temurin/OpenJDK published vulnerability", affected ? "applicable" : "possible", null, [source.url, url]);
        }
    }
    result.gap("Temurin VDR enumerates affected upstream releases; omitted builds, older branch versions and bundled components are not established as unaffected");
}

export async function refreshRuntime(input: unknown, store: Store, now: string, fetcher: Fetcher) {
    const body = object(input);
    if (Object.keys(body).sort().join(",") !== "github_token,runtime") throw new Error("invalid runtime refresh fields");
    const runtime = runtimeName(string(body.runtime));
    const token = string(body.github_token);
    if (!/^ghs_[A-Za-z0-9]{20,255}$/.test(token)) throw new Error("invalid ephemeral GitHub installation token");
    let version: string, sourceUrl: string;
    switch (runtime) {
        case "python": version = "3.12.14"; sourceUrl = "https://github.com/psf/advisory-database/tree/main"; break;
        case "rust": version = "1.85.0"; sourceUrl = "https://github.com/rustsec/advisory-db/tree/main"; break;
        case "ruby": version = "3.3.0"; sourceUrl = "https://github.com/rubysec/ruby-advisory-db/tree/master"; break;
        case "java": version = "21.0.1+12"; sourceUrl = "https://api.github.com/repos/adoptium/temurin-vdr-generator/releases/latest"; break;
        case "bun": version = "1.1.0"; sourceUrl = "https://api.github.com/repos/oven-sh/bun/security-advisories"; break;
        case "deno": version = "1.40.0"; sourceUrl = "https://api.github.com/repos/denoland/deno/security-advisories"; break;
        case "zig": version = "0.13.0"; sourceUrl = "https://api.github.com/repos/ziglang/zig/security-advisories"; break;
        case "erlang": version = "27.0"; sourceUrl = "https://api.github.com/repos/erlang/otp/security-advisories"; break;
        case "php": version = "8.3.0"; sourceUrl = "https://api.github.com/repos/php/php-src/security-advisories"; break;
        case "swift": version = "5.10.0"; sourceUrl = "https://api.github.com/repos/swiftlang/swift/security-advisories"; break;
        default: throw new Error("invalid runtime refresh selector");
    }
    const approved = new Set([
        "/repos/psf/advisory-database/commits/main", "/repos/rustsec/advisory-db/commits/main",
        "/repos/rubysec/ruby-advisory-db/commits/master", "/repos/adoptium/temurin-vdr-generator/releases/latest",
        "/repos/oven-sh/bun/security-advisories", "/repos/denoland/deno/security-advisories",
        "/repos/ziglang/zig/security-advisories", "/repos/erlang/otp/security-advisories",
        "/repos/php/php-src/security-advisories", "/repos/swiftlang/swift/security-advisories",
    ]);
    const authenticated: Fetcher = (url, init = {}) => {
        const target = new URL(url), headers = new Headers(init.headers);
        headers.delete("authorization");
        if (target.origin === "https://api.github.com") {
            if (target.username || target.password || !approved.has(target.pathname) || (init.method ?? "GET") !== "GET")
                throw new Error("invalid authenticated source request");
            headers.set("Authorization", `Bearer ${token}`);
        }
        return fetcher(url, { ...init, headers, redirect: "manual" });
    };
    const url = new URL(`https://advisories.invalid/v1/runtimes/${runtime}`);
    url.search = new URLSearchParams({ vendor: VENDORS[runtime], version, os: "linux", arch: "x86_64" }).toString();
    const report = await runtimeReport(url, store, now, authenticated, true, token);
    const refreshed = report.sources.some((source) => source.url === sourceUrl) && report.sources.every((source) => source.complete) &&
        !report.gaps.some((gap) => gap.startsWith("Runtime evidence could not be established") || gap.includes("refresh failed") || gap.includes("refresh is already in progress"));
    return { schema_version: 1, runtime, refreshed, coverage: report.coverage, checked_at: report.checked_at, sources: report.sources, gaps: report.gaps };
}

export async function runtimeReport(url: URL, store: Store, now: string, fetcher: Fetcher, force = false, credential?: string) {
    const selected = identity(url);
    date(now);
    const result = new Assessment();
    const sources = new Sources(store, fetcher, now, force, result, credential);
    if (selected.vendor !== VENDORS[selected.runtime]) result.gap(`Vendor mapping is not established; expected ${VENDORS[selected.runtime]} for ${selected.runtime}`);
    else if (!valid(selected.version) && !(["java", "erlang"].includes(selected.runtime) && numeric(selected.version.split("+")[0] ?? "")))
        result.gap("Exact upstream runtime release identity is unresolved; aliases and unsupported version forms cannot establish applicability");
    else {
        try {
            switch (selected.runtime) {
                case "node": await node(selected, sources, result); break;
                case "go": await osv(selected, sources, result, "Go", "stdlib"); await osv(selected, sources, result, "Go", "toolchain"); break;
                case "pi": await osv(selected, sources, result, "npm", "@earendil-works/pi-coding-agent"); break;
                case "bun": await github(selected, sources, result, "oven-sh/bun", ["bun"]); break;
                case "deno": await github(selected, sources, result, "denoland/deno", ["Deno", "deno"]); break;
                case "erlang": await erlang(selected, sources, result); break;
                case "php": await github(selected, sources, result, "php/php-src", ["PHP", "php", "php-src", "core", "ext-standard"]); break;
                case "zig": await github(selected, sources, result, "ziglang/zig", ["Zig", "zig"], false); break;
                case "swift": await github(selected, sources, result, "swiftlang/swift", ["Swift", "swift"], false); break;
                case "python": await python(selected, sources, result); break;
                case "rust": await rust(selected, sources, result); break;
                case "ruby": await ruby(selected, sources, result); break;
                case "java": await java(selected, sources, result); break;
                case "dotnet": await dotnet(selected, sources, result); break;
                default: { const exhaustive: never = selected.runtime; throw new Error(`unsupported runtime ${exhaustive}`); }
            }
        } catch (error) { result.gap(`Runtime evidence could not be established: ${error instanceof Error ? text(error.message, 200) : "source failure"}`); }
    }
    const receipts = [...result.sources.values()].sort((a, b) => a.name.localeCompare(b.name));
    if (!receipts.length && !result.gaps.size) result.gap("No authoritative source evidence was established");
    if (receipts.some((source) => !source.complete)) result.gap("One or more required source snapshots are incomplete or stale");
    const findings = [...result.findings.values()].sort((a, b) => a.id.localeCompare(b.id));
    const report = { schema_version: 1, identity: selected,
        checked_at: receipts.reduce((oldest, source) => source.checked_at < oldest ? source.checked_at : oldest, now),
        coverage: result.gaps.size ? findings.length ? "partial" : "unknown" : "assessed",
        findings, gaps: [...result.gaps].sort(), sources: receipts };
    if (new TextEncoder().encode(JSON.stringify(report)).length > 2 * 1024 * 1024) throw new Error("runtime report exceeds limit");
    return report;
}

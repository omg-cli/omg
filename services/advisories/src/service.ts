import {
    LIMITS,
    SOURCES,
    boundedBody,
    cveId,
    object,
    date,
    parseCve,
    sha256,
} from "./domain";
import { ingestCveGroups, parseBatch, refreshSource } from "./ingestion";
import { Store, type Checkpoint, type RecordRow, type Sql } from "./storage";
import { recentCves } from "./recent";
import { epss } from "./epss";
import { runtimeReport, refreshRuntime } from "./runtime";
import { type Fetcher } from "./ingestion";
import { publicResponse } from "./cache";
import { BaselineBusyError, baselineImportCommands, verifyBaseline } from "./baseline";

type PackageAdvisoryRow = {
    id: string;
    ecosystem: string;
    package_name: string;
    is_malware: number;
    summary: string | null;
    severity: string | null;
    aliases_json: string;
    fixed_versions_json: string;
    modified_at: string | null;
    epss: number | null;
    epss_percentile: number | null;
    in_kev: number;
    in_euvd: number;
};

type PackageAdvisory = {
    id: string;
    ecosystem: string;
    package_name: string;
    is_malware: boolean;
    summary: string | null;
    severity: string | null;
    aliases: string[];
    fixed_versions: string[];
    modified_at: string | null;
    epss: number | null;
    epss_percentile: number | null;
    in_kev: boolean;
    in_euvd: boolean;
};

function parseStringArray(raw: string): string[] {
    try {
        const parsed: unknown = JSON.parse(raw);
        return Array.isArray(parsed)
            ? parsed.filter((item): item is string => typeof item === "string")
            : [];
    } catch {
        return [];
    }
}

const PACKAGE_QUERY_CHUNK = 30;

async function queryPackageAdvisories(
    sql: Sql,
    pairs: readonly { ecosystem: string; name: string }[],
    limit: number,
): Promise<PackageAdvisory[]> {
    const chunks: { ecosystem: string; name: string }[][] = [];
    for (let i = 0; i < pairs.length; i += PACKAGE_QUERY_CHUNK) {
        chunks.push(pairs.slice(i, i + PACKAGE_QUERY_CHUNK));
    }
    const perChunk = await Promise.all(
        chunks.map((chunk) => {
            const predicates = chunk
                .map(() => "(a.ecosystem_lower = ? AND a.package_name_lower = ?)")
                .join(" OR ");
            const values: (string | number)[] = chunk.flatMap((p) => [p.ecosystem, p.name]);
            values.push(limit);
            return sql.all<PackageAdvisoryRow>(
                `SELECT a.id, a.ecosystem, a.package_name, a.is_malware, a.summary, a.severity,
                        a.aliases_json, a.fixed_versions_json, a.modified_at,
                        MAX(ep.epss) AS epss,
                        MAX(ep.percentile) AS epss_percentile,
                        MAX(CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS in_kev,
                        MAX(CASE WHEN ev.cve_id IS NOT NULL THEN 1 ELSE 0 END) AS in_euvd
                 FROM osv_package_advisory a
                 LEFT JOIN osv_package_alias al ON al.advisory_id = a.id
                 LEFT JOIN epss_scores ep ON ep.cve_id = a.id OR ep.cve_id = al.cve_id
                 LEFT JOIN kev_annotation k ON k.cve_id = a.id OR k.cve_id = al.cve_id
                 LEFT JOIN euvd_exploited ev ON ev.cve_id = a.id OR ev.cve_id = al.cve_id
                 WHERE ${predicates}
                 GROUP BY a.id
                 ORDER BY a.is_malware DESC, in_kev DESC, COALESCE(MAX(ep.epss), 0) DESC, a.modified_at DESC
                 LIMIT ?`,
                values,
            );
        }),
    );
    const merged = perChunk.flat().map((row): PackageAdvisory => ({
        id: row.id,
        ecosystem: row.ecosystem,
        package_name: row.package_name,
        is_malware: row.is_malware === 1,
        summary: row.summary,
        severity: row.severity,
        aliases: parseStringArray(row.aliases_json),
        fixed_versions: parseStringArray(row.fixed_versions_json),
        modified_at: row.modified_at,
        epss: row.epss,
        epss_percentile: row.epss_percentile,
        in_kev: row.in_kev === 1,
        in_euvd: row.in_euvd === 1,
    }));
    merged.sort((a, b) => {
        if (a.is_malware !== b.is_malware) return a.is_malware ? -1 : 1;
        if (a.in_kev !== b.in_kev) return a.in_kev ? -1 : 1;
        const epssDiff = (b.epss ?? 0) - (a.epss ?? 0);
        if (epssDiff !== 0) return epssDiff;
        const am = a.modified_at ?? "";
        const bm = b.modified_at ?? "";
        return bm < am ? -1 : bm > am ? 1 : 0;
    });
    return merged.slice(0, limit);
}
async function authorized(
    request: Request,
    token: string | undefined,
): Promise<boolean> {
    if (!token || token.length < 32) return false;
    const provided =
        request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
    if (provided.length > 1024) return false;
    const encoder = new TextEncoder();
    const algorithm = { name: "HMAC", hash: "SHA-256" };
    const expected = await crypto.subtle.importKey(
        "raw",
        encoder.encode(token),
        algorithm,
        false,
        ["verify"],
    );
    const supplied = await crypto.subtle.importKey(
        "raw",
        encoder.encode(provided || "missing"),
        algorithm,
        false,
        ["sign"],
    );
    const message = encoder.encode("omg-advisories-ingest-v1");
    const signature = await crypto.subtle.sign("HMAC", supplied, message);
    return crypto.subtle.verify("HMAC", expected, signature, message);
}
type BaselineSession = {
    digest: string;
    instance_id: string;
    session_id: string;
    endpoint: string;
    baseline_at: string;
};
async function baselineSession(
    store: Store,
    binding: Record<string, unknown>,
    endpoint: string,
): Promise<BaselineSession> {
    const row = await store.sql.first<BaselineSession>(
        "SELECT * FROM baseline_receipt WHERE digest=?",
        [typeof binding.digest === "string" ? binding.digest : ""],
    );
    const active = await store.checkpoint("cve");
    if (
        !row ||
        row.instance_id !== binding.instance_id ||
        row.session_id !== binding.session_id ||
        row.endpoint !== endpoint ||
        binding.endpoint !== endpoint ||
        active?.baseline_digest !== row.digest
    )
        throw new Error("invalid baseline session binding");
    return row;
}
function fresh(checkpoint: Checkpoint, now: string) {
    return (
        checkpoint.checked_at !== null &&
        Date.parse(now) - Date.parse(checkpoint.checked_at) <= 30 * 60_000
    );
}
export async function handle(
    request: Request,
    store: Store,
    token?: string,
    now = new Date().toISOString(),
    fetcher: Fetcher = (url, init) => fetch(url, init),
    runtimeRefreshSecret?: string,
): Promise<Response> {
    return publicResponse(request, await route(request, store, token, now, fetcher, runtimeRefreshSecret), now);
}
async function route(
    request: Request,
    store: Store,
    token: string | undefined,
    now: string,
    fetcher: Fetcher,
    runtimeRefreshSecret: string | undefined,
): Promise<Response> {
    const url = new URL(request.url);
    try {
        if (url.pathname === "/internal/cve-refresh") {
            if (request.method !== "POST") return Response.json({ error: "method not allowed" }, { status: 405 });
            if (!await authorized(request, token)) return Response.json({ error: "unauthorized" }, { status: 401 });
            const input = object(JSON.parse(await boundedBody(request.body, 1024)));
            if (Object.keys(input).length) throw new Error("invalid CVE refresh fields");
            if (!await refreshSource(store, "cve", fetcher, now, 32)) return Response.json({ error: "ingestion busy" }, { status: 409 });
            const checkpoint = await store.checkpoint("cve");
            if (!checkpoint) throw new Error("missing migration");
            return Response.json({ schema_version: 1, source: "cve", complete: !!checkpoint.complete && !checkpoint.error,
                cursor: checkpoint.cursor, checked_at: checkpoint.checked_at, bootstrap_complete: checkpoint.bootstrap_complete === 1,
                error: checkpoint.error }, { status: checkpoint.error ? 503 : 200 });
        }
        if (url.pathname === "/internal/baseline/verify") {
            if (request.method !== "POST") return Response.json({ error: "method not allowed" }, { status: 405 });
            if (!await authorized(request, runtimeRefreshSecret)) return Response.json({ error: "unauthorized" }, { status: 401 });
            const input: unknown = JSON.parse(await boundedBody(request.body, 4096));
            return Response.json(await verifyBaseline(input, store, url.origin, now, fetcher));
        }
        if (url.pathname === "/internal/runtime-refresh") {
            if (request.method !== "POST") return Response.json({ error: "method not allowed" }, { status: 405 });
            if (!await authorized(request, runtimeRefreshSecret)) return Response.json({ error: "unauthorized" }, { status: 401 });
            const input: unknown = JSON.parse(await boundedBody(request.body, 4096));
            return Response.json(await refreshRuntime(input, store, now, fetcher));
        }
        if (url.pathname === "/internal/ingest") {
            if (request.method !== "POST")
                return Response.json(
                    { error: "method not allowed" },
                    { status: 405 },
                );
            if (!(await authorized(request, token)))
                return Response.json(
                    { error: "unauthorized" },
                    { status: 401 },
                );
            const input = object(
                JSON.parse(await boundedBody(request.body, LIMITS.batch)),
            );
            const records = parseBatch(input, input.baseline === undefined ? LIMITS.records : 64);
            const binding =
                input.baseline === undefined ? null : object(input.baseline);
            const owner = crypto.randomUUID();
            if (!(await store.lease("cve", owner, now)))
                return Response.json(
                    { error: "ingestion busy" },
                    { status: 409 },
                );
            try {
                const writer = store.writer("cve", owner);
                const baseline = binding
                    ? await baselineSession(writer, binding, url.origin)
                    : null;
                const parsed = records.map((raw) => {
                    const record = parseCve(raw);
                    return { id: record.id, supported: record.supported, raw };
                });
                if (baseline && new Set(parsed.map((record) => record.id)).size === parsed.length && parsed.every((record) => record.supported)) {
                    const after = await baselineImportCommands(writer, baseline.session_id, parsed);
                    await writer.cveBatch(parsed, now, after, "packed");
                } else {
                    if (records.length > LIMITS.records) throw new Error("invalid duplicate or unsupported large ingest batch");
                    await ingestCveGroups(
                        parsed,
                        async ({ id, raw }) => {
                            const after = baseline ? await baselineImportCommands(writer, baseline.session_id, [{ id, raw }]) : [];
                            await writer.cve(raw, now);
                            if (after.length) await writer.sql.batch(after);
                        },
                    );
                }
            } finally {
                await store.release("cve", owner);
            }
            return Response.json({ accepted: records.length });
        }
        if (url.pathname === "/internal/baseline/start") {
            if (request.method !== "POST")
                return Response.json(
                    { error: "method not allowed" },
                    { status: 405 },
                );
            if (!(await authorized(request, token)))
                return Response.json(
                    { error: "unauthorized" },
                    { status: 401 },
                );
            const receipt = object(
                JSON.parse(await boundedBody(request.body, 4096)),
            );
            if (
                typeof receipt.digest !== "string" ||
                !/^[a-f0-9]{64}$/.test(receipt.digest)
            )
                throw new Error("invalid baseline digest");
            const baseline = date(receipt.baseline_at);
            const existing = await store.sql.first<BaselineSession>(
                "SELECT * FROM baseline_receipt WHERE digest=?",
                [receipt.digest],
            );
            if (existing) {
                await baselineSession(
                    store,
                    {
                        ...receipt,
                        instance_id: receipt.instance_id ?? existing.instance_id,
                        session_id: receipt.session_id ?? existing.session_id,
                        endpoint: receipt.endpoint ?? existing.endpoint,
                    },
                    url.origin,
                );
                return Response.json({ started: true, ...existing });
            }
            if (receipt.instance_id !== undefined || receipt.session_id !== undefined)
                throw new Error("invalid baseline resume instance");
            const instance = await store.sql.first<{ id: string }>(
                "SELECT id FROM database_instance",
            );
            if (!instance) throw new Error("missing database instance");
            const session = crypto.randomUUID();
            const owner = crypto.randomUUID();
            if (!(await store.lease("cve", owner, now)))
                return Response.json(
                    { error: "ingestion busy" },
                    { status: 409 },
                );
            try {
                await store.writer("cve", owner).sql.batch([
                    {
                        sql: "INSERT INTO baseline_receipt(digest,instance_id,session_id,endpoint,baseline_at,accepted,exhausted) VALUES(?,?,?,?,?,0,0)",
                        values: [receipt.digest, instance.id, session, url.origin, baseline],
                    },
                    {
                        sql: "UPDATE source_checkpoint SET cursor=?,baseline_digest=?,complete=0,bootstrap_complete=0,error=NULL,etag=NULL WHERE source=?",
                        values: [
                            JSON.stringify({ event: baseline, offset: 0 }),
                            receipt.digest,
                            "cve",
                        ],
                    },
                ]);
            } finally {
                await store.release("cve", owner);
            }
            return Response.json({
                started: true,
                digest: receipt.digest,
                instance_id: instance.id,
                session_id: session,
                endpoint: url.origin,
            });
        }
        if (url.pathname === "/internal/baseline") {
            if (request.method !== "POST")
                return Response.json(
                    { error: "method not allowed" },
                    { status: 405 },
                );
            if (!(await authorized(request, token)))
                return Response.json(
                    { error: "unauthorized" },
                    { status: 401 },
                );
            const receipt = object(
                JSON.parse(await boundedBody(request.body, 4096)),
            );
            if (
                typeof receipt.digest !== "string" ||
                !/^[a-f0-9]{64}$/.test(receipt.digest) ||
                !Number.isSafeInteger(receipt.accepted) ||
                typeof receipt.accepted !== "number" ||
                receipt.accepted < 1 ||
                receipt.exhausted !== true
            )
                throw new Error("invalid baseline receipt");
            const baseline = date(receipt.baseline_at);
            const finished = date(receipt.finished_at);
            const started = await baselineSession(store, receipt, url.origin);
            if (!started || started.baseline_at !== baseline)
                throw new Error("invalid baseline receipt");
            const owner = crypto.randomUUID();
            if (!(await store.lease("cve", owner, now)))
                return Response.json(
                    { error: "ingestion busy" },
                    { status: 409 },
                );
            try {
                await baselineSession(store, receipt, url.origin);
                const checkpoint = await store.checkpoint("cve");
                if (
                    !checkpoint?.complete ||
                    checkpoint.baseline_digest !== receipt.digest ||
                    !checkpoint.checked_at ||
                    checkpoint.error ||
                    !fresh(checkpoint, now) ||
                    checkpoint.checked_at < finished ||
                    !checkpoint.cursor
                )
                    throw new Error("delta catchup required");
                const cursor = object(JSON.parse(checkpoint.cursor));
                if (date(cursor.event) < baseline)
                    throw new Error("delta precedes baseline");
                const unsupported = await store.sql.first<{ count: number }>(
                    "SELECT COUNT(*) AS count FROM source_record WHERE supported=0",
                );
                if (unsupported?.count)
                    throw new Error("unsupported records prevent completeness");
                const imported = await store.sql.first<{
                    count: number;
                    accepted: number;
                }>(
                    "SELECT COUNT(*) AS count,(SELECT accepted FROM baseline_receipt WHERE session_id=?) AS accepted FROM baseline_member WHERE session_id=?",
                    [started.session_id, started.session_id],
                );
                if (
                    !imported ||
                    imported.count !== receipt.accepted ||
                    imported.count !== imported.accepted
                )
                    throw new Error("invalid baseline member count");
                const proof = await store.sql.first<{ phase: string }>("SELECT phase FROM baseline_publisher_proof WHERE session_id=?", [started.session_id]);
                const verified = proof?.phase === "verified";
                await store.writer("cve", owner).sql.batch([
                    {
                        sql: "UPDATE baseline_receipt SET accepted=?,exhausted=1,caught_up=1,completed_at=? WHERE session_id=?",
                        values: [imported.count, now, started.session_id],
                    },
                    {
                        sql: "UPDATE source_checkpoint SET bootstrap_complete=? WHERE source=?",
                        values: [Number(verified), "cve"],
                    },
                ]);
                return Response.json({
                    bootstrap_complete: verified,
                    archive_verified: verified,
                    imported: imported.count,
                    caught_up: true,
                });
            } finally {
                await store.release("cve", owner);
            }
        }
        if (request.method === "POST" && url.pathname === "/v1/packages/audit") {
            const raw = await boundedBody(request.body, 256 * 1024);
            const body = object(JSON.parse(raw));
            const pkgs = Array.isArray(body.packages) ? body.packages : null;
            if (!pkgs || pkgs.length === 0 || pkgs.length > 500) {
                return Response.json({ error: "packages must be a non-empty array of up to 500 items" }, { status: 400 });
            }
            const seen = new Set<string>();
            const pairs: { ecosystem: string; name: string }[] = [];
            for (const item of pkgs) {
                const entry = object(item);
                if (typeof entry.ecosystem !== "string" || typeof entry.name !== "string" || !entry.ecosystem.trim() || !entry.name.trim()) {
                    return Response.json({ error: "each package requires non-empty ecosystem and name" }, { status: 400 });
                }
                const ecosystem = entry.ecosystem.trim().toLowerCase();
                const name = entry.name.trim().toLowerCase();
                const dedupKey = `${ecosystem}\0${name}`;
                if (!seen.has(dedupKey)) {
                    seen.add(dedupKey);
                    pairs.push({ ecosystem, name });
                }
            }
            const rows = await queryPackageAdvisories(store.sql, pairs, 1000);
            return Response.json({
                schema_version: 1,
                checked_at: now,
                queried: pairs.length,
                malware_count: rows.filter((r) => r.is_malware).length,
                kev_count: rows.filter((r) => r.in_kev).length,
                findings: rows,
            });
        }
        if (request.method !== "GET")
            return Response.json(
                { error: "method not allowed" },
                { status: 405 },
            );
        if (url.pathname === "/v1/packages/check") {
            const ecosystem = (url.searchParams.get("ecosystem") ?? "").trim().toLowerCase();
            const name = (url.searchParams.get("name") ?? "").trim().toLowerCase();
            if (!ecosystem || !name || ecosystem.length > 64 || name.length > 256) {
                return Response.json({ error: "ecosystem and name query parameters are required" }, { status: 400 });
            }
            const rows = await queryPackageAdvisories(store.sql, [{ ecosystem, name }], 200);
            return Response.json({
                schema_version: 1,
                checked_at: now,
                ecosystem,
                name,
                malware: rows.some((r) => r.is_malware),
                actively_exploited: rows.some((r) => r.in_kev || r.in_euvd),
                advisories: rows,
            });
        }
        const eolMatch = /^\/v1\/eol(?:\/([a-z0-9-]+))?$/.exec(url.pathname);
        if (eolMatch) {
            const product = eolMatch[1];
            const cycles = product
                ? await store.sql.all("SELECT product,cycle,eol,lts,latest,release_date,support,updated_at FROM runtime_eol WHERE product=? ORDER BY release_date DESC NULLS LAST, cycle DESC", [product])
                : await store.sql.all("SELECT product,cycle,eol,lts,latest,release_date,support,updated_at FROM runtime_eol ORDER BY product ASC, release_date DESC NULLS LAST");
            return Response.json({
                schema_version: 1,
                checked_at: now,
                product: product ?? "all",
                cycles,
            });
        }
        if (url.pathname === "/v1/status") {
            const [checkpoints, baseline] = await Promise.all([
                store.sql.all<Checkpoint>(
                    "SELECT * FROM source_checkpoint ORDER BY source",
                ),
                store.sql.first<{
                    imported: number;
                    caught_up: number;
                    archive_verified: number;
                }>(
                    "SELECT r.accepted AS imported,r.caught_up,CASE WHEN p.phase='verified' AND p.verified_at IS NOT NULL THEN 1 ELSE 0 END AS archive_verified FROM baseline_receipt r JOIN source_checkpoint c ON c.baseline_digest=r.digest LEFT JOIN baseline_publisher_proof p ON p.session_id=r.session_id WHERE c.source='cve'",
                ),
            ]);
            return Response.json({
                schema_version: 1,
                baseline: {
                    imported: baseline?.imported ?? 0,
                    caught_up: baseline?.caught_up === 1,
                    archive_verified: baseline?.archive_verified === 1,
                },
                bootstrap_complete:
                    checkpoints.find((c) => c.source === "cve")
                        ?.bootstrap_complete === 1,
                feeds: checkpoints.map((c) => ({
                    ...c,
                    complete:
                        !!c.complete &&
                        !!c.bootstrap_complete &&
                        !c.error &&
                        fresh(c, now),
                    fresh: fresh(c, now),
                })),
                package_applicability: "Arch feed only; AUR mapping unknown",
            });
        }
        if (url.pathname.startsWith("/v1/runtimes/")) {
            const force = /(?:^|,)\s*(?:no-cache|max-age\s*=\s*0)\s*(?:,|$)/i.test(request.headers.get("cache-control") ?? "");
            return Response.json(await runtimeReport(url, store, now, fetcher, force));
        }
        const epssMatch = /^\/v1\/epss\/(CVE-\d{4}-\d{4,19})$/.exec(url.pathname);
        if (epssMatch?.[1]) {
            if (url.search) throw new Error("invalid EPSS query");
            if (!await store.sql.first("SELECT id FROM source_record WHERE id=?", [epssMatch[1]]))
                return Response.json({ error: "CVE unavailable", status: "unavailable" }, { status: 404 });
            return Response.json(await epss(store, epssMatch[1], now, fetcher));
        }
        if (url.pathname === "/v1/arch/advisories") {
            const checkpoint = await store.checkpoint("arch");
            if (!checkpoint?.object_key)
                return Response.json(
                    { error: "snapshot unavailable", complete: false },
                    { status: 503 },
                );
            const raw = await store.raw.get(checkpoint.object_key);
            if (!raw) throw new Error("snapshot object missing");
            return Response.json({
                schema_version: 1,
                source: "arch-security",
                source_url: SOURCES.arch,
                fetched_at: checkpoint.fetched_at,
                checked_at: checkpoint.checked_at,
                complete:
                    !!checkpoint.complete &&
                    !checkpoint.error &&
                    fresh(checkpoint, now),
                payload_sha256: checkpoint.payload_sha256,
                payload_json: await raw.text(),
            });
        }
        if (url.pathname === "/v1/bundles/hot") {
            const [recent, kevs, checkpoints] = await Promise.all([
                store.sql.all<RecordRow & { kev_payload_json: string | null }>(
                    "SELECT r.id,r.source,r.source_url,r.schema_version,r.state,r.published_at,r.modified_at,r.fetched_at,r.payload_sha256,r.object_key,r.normalization_version,r.supported,k.payload_json AS kev_payload_json FROM source_record r LEFT JOIN kev_annotation k ON k.cve_id=r.id ORDER BY r.modified_at DESC,r.id DESC LIMIT 50",
                ),
                store.sql.all<{ cve_id: string; payload_json: string }>(
                    "SELECT cve_id,payload_json FROM kev_annotation ORDER BY cve_id DESC LIMIT 200",
                ),
                store.sql.all<Checkpoint>(
                    "SELECT * FROM source_checkpoint WHERE source IN ('cve','kev')",
                ),
            ]);
            const cve = checkpoints.find((row) => row.source === "cve") ?? null;
            const kev = checkpoints.find((row) => row.source === "kev") ?? null;
            return Response.json({
                schema_version: 1,
                generated_at: now,
                cve_checked_at: cve?.checked_at ?? null,
                kev_checked_at: kev?.checked_at ?? null,
                recent_count: recent.length,
                kev_count: kevs.length,
                recent: recent.map(({ kev_payload_json, ...rec }) => ({
                    ...rec,
                    kev: kev_payload_json ? JSON.parse(kev_payload_json) : null,
                })),
                kev_latest: kevs.map((k) => ({ cve_id: k.cve_id, kev: JSON.parse(k.payload_json) })),
            });
        }
        if (url.pathname === "/v1/cves/recent") {
            const [page, checkpoint] = await Promise.all([
                recentCves(url, store.sql, now),
                store.checkpoint("cve"),
            ]);
            return Response.json({
                schema_version: 1, ...page,
                checked_at: checkpoint?.checked_at ?? null,
                complete: !!checkpoint?.complete && !!checkpoint.bootstrap_complete &&
                    !checkpoint.error && fresh(checkpoint, now),
                package_applicability: "unknown",
            });
        }
        const match = /^\/v1\/cves\/(CVE-\d{4}-\d{4,19})$/.exec(url.pathname);
        if (match?.[1]) {
            const id = cveId(match[1]);
            const [joined, checkpoints] = await Promise.all([
                store.sql.first<
                    RecordRow & {
                        kev_payload_json: string | null;
                    }
                >(
                    "SELECT r.id,r.source,r.source_url,r.schema_version,r.state,r.published_at,r.modified_at,r.fetched_at,r.payload_sha256,r.object_key,r.normalization_version,r.supported,k.payload_json AS kev_payload_json FROM source_record r LEFT JOIN kev_annotation k ON k.cve_id=r.id WHERE r.id=?",
                    [id],
                ),
                store.sql.all<Checkpoint>(
                    "SELECT * FROM source_checkpoint WHERE source IN ('cve','kev')",
                ),
            ]);
            if (!joined)
                return Response.json(
                    { error: "CVE unavailable", complete: false },
                    { status: 404 },
                );
            const {
                kev_payload_json: kevPayloadJson,
                ...record
            } = joined;
            const raw = await store.raw
                .get(record.object_key)
                .catch((cause: unknown) => {
                    throw new Error("CVE storage unavailable", { cause });
                });
            if (!raw) throw new Error("CVE object missing");
            const payload = await raw.text();
            if (
                raw.verifiedSha256 !== record.payload_sha256 &&
                (await sha256(payload)) !== record.payload_sha256
            )
                throw new Error("CVE stored payload failed integrity");
            const kev = checkpoints.find((row) => row.source === "kev") ?? null;
            const cve = checkpoints.find((row) => row.source === "cve") ?? null;
            return Response.json({
                schema_version: 1,
                payload_json: payload,
                provenance: record,
                cve_checked_at: cve?.checked_at ?? null,
                cve_complete: !!cve?.complete && !!cve.bootstrap_complete &&
                    !cve.error && fresh(cve, now),
                kev: kevPayloadJson ? JSON.parse(kevPayloadJson) : null,
                kev_checked_at: kev?.checked_at,
                kev_complete: kev
                    ? !!kev.complete && !kev.error && fresh(kev, now)
                    : false,
                package_applicability: "unknown",
            });
        }
        return Response.json({ error: "not found" }, { status: 404 });
    } catch (error) {
        if (error instanceof BaselineBusyError) return Response.json({ error: "ingestion busy" }, { status: 409 });
        const invalid =
            error instanceof Error &&
            /invalid|expected|exceeds|missing publication|mismatch|catchup|baseline|completeness/.test(
                error.message,
            );
        if (!invalid && url.pathname.startsWith("/internal/")) {
            const reasons: string[] = [];
            let cause: unknown = error;
            for (let depth = 0; depth < 3 && cause instanceof Error; depth++) {
                let message = cause.message;
                for (const secret of [token, runtimeRefreshSecret]) {
                    if (secret) message = message.replaceAll(secret, "[redacted]");
                }
                reasons.push(message.replace(/ghs_[A-Za-z0-9._-]+/g, "[redacted]").slice(0, 300));
                cause = cause.cause;
            }
            console.error(JSON.stringify({ event: "internal_advisory_failure", path: url.pathname, reasons }));
        }
        return Response.json(
            {
                error: invalid
                    ? "invalid or incomplete input"
                    : "service unavailable",
                complete: false,
            },
            { status: invalid ? 400 : 503 },
        );
    }
}

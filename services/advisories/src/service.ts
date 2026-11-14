import {
    LIMITS,
    SOURCES,
    boundedBody,
    cveId,
    object,
    date,
    sha256,
    parseCve,
} from "./domain";
import { parseBatch } from "./ingestion";
import { Store, type Checkpoint, type RecordRow } from "./storage";
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
): Promise<Response> {
    const url = new URL(request.url);
    try {
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
            const records = parseBatch(input);
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
                for (const raw of records) {
                    await writer.cve(raw, now);
                    if (baseline)
                        await writer.sql.batch([
                            {
                                sql: "INSERT INTO baseline_member(session_id,cve_id,payload_sha256) VALUES(?,?,?) ON CONFLICT(session_id,cve_id) DO NOTHING",
                                values: [baseline.session_id, parseCve(raw).id, await sha256(raw)],
                            },
                            {
                                sql: "UPDATE baseline_receipt SET caught_up=0,completed_at=NULL WHERE session_id=?",
                                values: [baseline.session_id],
                            },
                        ]);
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
                await store.writer("cve", owner).sql.batch([
                    {
                        sql: "UPDATE baseline_receipt SET accepted=?,exhausted=1,caught_up=1,completed_at=? WHERE session_id=?",
                        values: [imported.count, now, started.session_id],
                    },
                    {
                        sql: "UPDATE source_checkpoint SET bootstrap_complete=0 WHERE source=?",
                        values: ["cve"],
                    },
                ]);
                return Response.json({
                    bootstrap_complete: false,
                    archive_verified: false,
                    imported: imported.count,
                    caught_up: true,
                });
            } finally {
                await store.release("cve", owner);
            }
        }
        if (request.method !== "GET")
            return Response.json(
                { error: "method not allowed" },
                { status: 405 },
            );
        if (url.pathname === "/v1/status") {
            const checkpoints = await store.sql.all<Checkpoint>(
                "SELECT * FROM source_checkpoint ORDER BY source",
            );
            const baseline = await store.sql.first<{
                imported: number;
                caught_up: number;
            }>(
                "SELECT r.accepted AS imported,r.caught_up FROM baseline_receipt r JOIN source_checkpoint c ON c.baseline_digest=r.digest WHERE c.source='cve'",
            );
            return Response.json({
                schema_version: 1,
                baseline: {
                    imported: baseline?.imported ?? 0,
                    caught_up: baseline?.caught_up === 1,
                    archive_verified: false,
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
        const match = /^\/v1\/cves\/(CVE-\d{4}-\d{4,19})$/.exec(url.pathname);
        if (match?.[1]) {
            const id = cveId(match[1]);
            const record = await store.sql.first<RecordRow>(
                "SELECT * FROM source_record WHERE id=?",
                [id],
            );
            if (!record)
                return Response.json(
                    { error: "CVE unavailable", complete: false },
                    { status: 404 },
                );
            const raw = await store.raw.get(record.object_key);
            if (!raw) throw new Error("CVE object missing");
            const kev = await store.checkpoint("kev");
            const annotation = await store.sql.first<{ payload_json: string }>(
                "SELECT payload_json FROM kev_annotation WHERE cve_id=?",
                [id],
            );
            return Response.json({
                schema_version: 1,
                payload_json: await raw.text(),
                provenance: record,
                kev: annotation ? JSON.parse(annotation.payload_json) : null,
                kev_checked_at: kev?.checked_at,
                kev_complete: kev
                    ? !!kev.complete && !kev.error && fresh(kev, now)
                    : false,
                package_applicability: "unknown",
            });
        }
        return Response.json({ error: "not found" }, { status: 404 });
    } catch (error) {
        const invalid =
            error instanceof Error &&
            /invalid|expected|exceeds|missing publication|mismatch|catchup|baseline|completeness/.test(
                error.message,
            );
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

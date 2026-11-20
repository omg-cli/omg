import { boundedBody, cveId, date, object, string } from "./domain";
import { type Fetcher } from "./ingestion";
import { type Store } from "./storage";

const DAY = 24 * 60 * 60_000;
const EMPTY = JSON.stringify({ status: "OK", "status-code": 200, total: 0, offset: 0, data: [] });
type CacheRow = { checked_at: string; fetched_at: string | null; payload_json: string; error: number };
type Score = { epss: number; percentile: number; date: string };

function probability(value: unknown): number {
    const text = string(value);
    if (!/^(?:0(?:\.\d{1,12})?|1(?:\.0{1,12})?)$/.test(text))
        throw new Error("invalid EPSS probability");
    return Number(text);
}
function score(value: unknown, now: string): Score {
    const row = object(value);
    const day = string(row.date);
    if (!/^\d{4}-\d\d-\d\d$/.test(day) || date(`${day}T00:00:00Z`).slice(0, 10) !== day || day > now.slice(0, 10))
        throw new Error("invalid EPSS score date");
    return { epss: probability(row.epss), percentile: probability(row.percentile), date: day };
}
function parseEpss(raw: string, id: string, now: string) {
    if (new TextEncoder().encode(raw).length > 64 * 1024) throw new Error("EPSS body exceeds limit");
    const body = object(JSON.parse(raw));
    if (body.status !== "OK" || body["status-code"] !== 200 || body.offset !== 0 ||
        !Array.isArray(body.data) || ![0, 1].includes(Number(body.total)) || body.total !== body.data.length)
        throw new Error("invalid or partial EPSS response");
    if (body.data.length === 0) return { latest: null, history: [] };
    const row = object(body.data[0]);
    if (cveId(row.cve) !== id || !Array.isArray(row["time-series"]) || row["time-series"].length > 30)
        throw new Error("invalid EPSS identity or history");
    const current = score(row, now);
    const scores = [current, ...row["time-series"].map((value: unknown) => score(value, now))];
    if (new Set(scores.map((item) => item.date)).size !== scores.length || scores.some((item) => item.date > current.date))
        throw new Error("invalid EPSS history dates");
    const start = new Date(Date.parse(`${now.slice(0, 10)}T00:00:00Z`) - 29 * DAY).toISOString().slice(0, 10);
    return { latest: current, history: scores.filter((item) => item.date >= start).sort((a, b) => b.date.localeCompare(a.date)) };
}
function result(row: CacheRow | null, id: string, now: string, busy = false) {
    const evidence = row ? parseEpss(row.payload_json, id, now) : null;
    const latest = evidence?.latest;
    const unavailable = busy || !row || !!row.error || (latest !== null && latest !== undefined && Date.parse(now) - Date.parse(`${latest.date}T00:00:00Z`) > 2 * DAY);
    return {
        schema_version: 1,
        as_of: now,
        source: "FIRST EPSS",
        source_url: `https://api.first.org/data/v1/epss?cve=${id}&scope=time-series`,
        attribution: "EPSS by FIRST.org and the EPSS Special Interest Group",
        cve: id,
        checked_at: row?.checked_at ?? null,
        fetched_at: row?.fetched_at ?? null,
        status: unavailable ? "unavailable" : latest ? "scored" : "missing",
        score: unavailable ? null : latest ?? null,
        history: evidence?.history ?? [],
        interpretation: "Probability of observed exploitation in the next 30 days; not proof of applicability, safety or current exploitation",
    };
}
export async function epss(store: Store, id: string, now: string, fetcher: Fetcher) {
    cveId(id);
    date(now);
    if (!await store.sql.first("SELECT id FROM source_record WHERE id=?", [id]))
        throw new Error("CVE unavailable");
    const read = () => store.sql.first<CacheRow>("SELECT * FROM epss_cache WHERE cve_id=?", [id]);
    const fresh = (row: CacheRow | null) => row !== null && Date.parse(row.checked_at) <= Date.parse(now) &&
        Date.parse(now) - Date.parse(row.checked_at) < (row.error ? 60_000 : 6 * 60 * 60_000);
    let cached = await read();
    if (fresh(cached)) return result(cached, id, now);
    const owner = crypto.randomUUID(), lease = `epss:${id}`;
    if (!await store.lease(lease, owner, now)) return result(cached, id, now, true);
    try {
        cached = await read();
        if (fresh(cached)) return result(cached, id, now);
        let raw = cached?.payload_json ?? EMPTY;
        let error = 0;
        try {
            const response = await fetcher(`https://api.first.org/data/v1/epss?cve=${id}&scope=time-series`, {
                redirect: "manual", signal: AbortSignal.timeout(20_000),
                headers: { "User-Agent": "omg-advisories/1.0", Accept: "application/json" },
            });
            if (response.status !== 200) {
                await response.body?.cancel();
                throw new Error("EPSS upstream unavailable");
            }
            const incoming = await boundedBody(response.body, 64 * 1024);
            parseEpss(incoming, id, now);
            raw = incoming;
        } catch (failure) {
            console.error("epss_refresh_failed", { cve: id, reason: failure instanceof Error ? failure.message : "unknown failure" });
            error = 1;
        }
        const row: CacheRow = { checked_at: now, fetched_at: error ? cached?.fetched_at ?? null : now, payload_json: raw, error };
        await store.writer(lease, owner).sql.batch([{
            sql: "INSERT INTO epss_cache(cve_id,checked_at,fetched_at,payload_json,error) VALUES(?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET checked_at=excluded.checked_at,fetched_at=excluded.fetched_at,payload_json=excluded.payload_json,error=excluded.error",
            values: [id, row.checked_at, row.fetched_at, row.payload_json, row.error],
        }]);
        return result(row, id, now);
    } finally {
        await store.release(lease, owner);
    }
}

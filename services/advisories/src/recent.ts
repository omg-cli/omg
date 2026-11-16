import { cveId, date, object } from "./domain";
import { type Sql, type RecordRow } from "./storage";

const WINDOW = 30 * 24 * 60 * 60_000;
export async function recentCves(url: URL, sql: Sql, now: string) {
    for (const key of url.searchParams.keys()) {
        if (!["limit", "cursor"].includes(key) || url.searchParams.getAll(key).length !== 1)
            throw new Error("invalid recent query");
    }
    const limitText = url.searchParams.get("limit") ?? "100";
    if (!/^(?:[1-9]\d?|100)$/.test(limitText)) throw new Error("invalid recent limit");
    const limit = Number(limitText);
    let asOf = now, modified = now, id = "\uffff";
    const cursor = url.searchParams.get("cursor");
    if (cursor !== null) {
        try {
            if (!cursor || cursor.length > 1024) throw new Error("invalid cursor size");
            const value = object(JSON.parse(atob(cursor)));
            if (Object.keys(value).sort().join(",") !== "as_of,id,modified_at")
                throw new Error("invalid cursor fields");
            asOf = date(value.as_of);
            modified = date(value.modified_at);
            id = cveId(value.id);
            if (asOf !== value.as_of || modified !== value.modified_at ||
                asOf > now || Date.parse(now) - Date.parse(asOf) > 60 * 60_000 ||
                modified > asOf || Date.parse(modified) < Date.parse(asOf) - WINDOW)
                throw new Error("invalid cursor bounds");
        } catch {
            throw new Error("invalid recent cursor");
        }
    }
    const windowStart = new Date(Date.parse(asOf) - WINDOW).toISOString();
    const rows = await sql.all<RecordRow>(
        "SELECT * FROM source_record WHERE modified_at>=? AND modified_at<=? AND (modified_at,id)<(?,?) ORDER BY modified_at DESC,id DESC LIMIT ?",
        [windowStart, asOf, modified, id, limit + 1],
    );
    const records = rows.slice(0, limit);
    const last = records.at(-1);
    return {
        window_start: windowStart,
        as_of: asOf,
        records,
        next_cursor: rows.length > limit && last ? btoa(JSON.stringify({
            as_of: asOf, modified_at: last.modified_at, id: last.id,
        })) : null,
    };
}

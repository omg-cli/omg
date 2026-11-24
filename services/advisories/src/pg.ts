import postgres from "postgres";
import type { Command, Sql } from "./storage";

/**
 * Translates the bounded SQLite/D1 SQL subset used by omg-advisories into
 * PostgreSQL SQL ($1..$n placeholders, clock_timestamp UTC formatting, and
 * jsonb_array_elements for json_each/json_extract).
 */
export function translateSqlForPostgres(input: string): string {
    let idx = 0;
    let out = "";
    let inSingleQuote = false;
    for (let i = 0; i < input.length; i++) {
        const ch = input[i]!;
        if (ch === "'") {
            out += ch;
            if (inSingleQuote && input[i + 1] === "'") {
                out += "'";
                i++;
            } else {
                inSingleQuote = !inSingleQuote;
            }
            continue;
        }
        if (!inSingleQuote && ch === "?") {
            out += `$${++idx}`;
            continue;
        }
        out += ch;
    }

    // 1. SQLite UTC ISO-8601 timestamp helper
    out = out.replaceAll(
        "strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        `to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`,
    );

    // 2. json_each($N) with explicit alias (e.g. "FROM json_each($1) j") — ignore SQL keywords
    out = out.replace(
        /FROM\s+json_each\((\$\d+)\)\s+(?!(?:WHERE|ON|JOIN|CROSS|LEFT|RIGHT|INNER|OUTER|ORDER|GROUP|LIMIT|UNION|SET|VALUES)\b)([a-zA-Z_][a-zA-Z0-9_]*)\b/gi,
        (_m, param: string, alias: string) =>
            `FROM jsonb_array_elements(${param}::jsonb) AS ${alias}(value)`,
    );

    // 3. json_each($N) without alias (e.g. "FROM json_each($2)")
    out = out.replace(
        /FROM\s+json_each\((\$\d+)\)/gi,
        (_m, param: string) =>
            `FROM jsonb_array_elements(${param}::jsonb) AS _je(value)`,
    );

    // 4. json_extract(<expr>, '$.field') -> (<expr>->>'field')
    out = out.replace(
        /json_extract\(\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*,\s*'\$\.([a-zA-Z0-9_]+)'\s*\)/gi,
        (_m, target: string, field: string) => {
            const col = target === "value" ? "_je.value" : target;
            return `(${col}->>'${field}')`;
        },
    );

    // 5. Bare `value` projection from unaliased json_each (kev_annotation payload_json)
    out = out.replace(/,value,/g, ",_je.value::text,");

    // 6. SQLite disambiguation clause "WHERE 1 ON CONFLICT"
    out = out.replace(/\bWHERE\s+1\s+ON\s+CONFLICT\b/gi, "WHERE true ON CONFLICT");

    // 7. Avoid transferring duplicate payload_jsonb over the wire on /v1/cves/:id (payload_raw is used)
    out = out.replace(
        "SELECT r.*, k.payload_json AS kev_payload_json FROM source_record r",
        "SELECT r.id,r.source,r.source_url,r.schema_version,r.state,r.published_at,r.modified_at,r.fetched_at,r.payload_sha256,r.object_key,r.normalization_version,r.supported,r.payload_raw,k.payload_json AS kev_payload_json FROM source_record r",
    );

    return out;
}

function normalizeRow<T>(row: Record<string, unknown> | undefined): T | null {
    if (!row) return null;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(row)) {
        // postgres.js returns int8 (e.g. COUNT(*), BIGINT) as string when fetch_types=false
        if (typeof v === "string" && /^-?\d+$/.test(v) && (k === "count" || k === "members" || k === "blobs" || k === "unsupported" || k === "asset_size")) {
            out[k] = Number(v);
        } else {
            out[k] = v;
        }
    }
    return out as T;
}

export interface QueryTags {
    readonly application: string;
    readonly route: string;
    readonly target?: "primary" | "replica";
}

export function formatSqlCommenter(tags?: QueryTags): string {
    if (!tags) return "";
    const parts: string[] = [];
    const safe = (v: string) => encodeURIComponent(v).replaceAll("'", "%27");
    parts.push(`application='${safe(tags.application)}'`);
    parts.push(`route='${safe(tags.route)}'`);
    if (tags.target) parts.push(`target='${safe(tags.target)}'`);
    return ` /*${parts.join(",")}*/`;
}

export function pgSql(connectionString: string, tags?: QueryTags): Sql & { close(): Promise<void> } {
    const client = postgres(connectionString, {
        max: 2,
        // Hyperdrive + PgBouncer use transaction-mode pooling; disable server prepares
        prepare: false,
        fetch_types: false,
    });
    const suffix = formatSqlCommenter(tags);

    return {
        inlinePayloads: true,
        async first<T>(sql: string, values: (string | number | null)[] = []): Promise<T | null> {
            const rows = await client.unsafe(translateSqlForPostgres(sql) + suffix, values);
            return normalizeRow<T>(rows[0] as Record<string, unknown> | undefined);
        },
        async all<T>(sql: string, values: (string | number | null)[] = []): Promise<T[]> {
            const rows = await client.unsafe(translateSqlForPostgres(sql) + suffix, values);
            return rows.map((r) => normalizeRow<T>(r as Record<string, unknown>)!);
        },
        async batch(commands: Command[]): Promise<void> {
            if (!commands.length) return;
            await client.begin(async (tx) => {
                for (const cmd of commands) {
                    await tx.unsafe(translateSqlForPostgres(cmd.sql) + suffix, cmd.values);
                }
            });
        },
        async close(): Promise<void> {
            await client.end({ timeout: 5 });
        },
    };
}

import { parseCve, sha256, cveUrl } from "./domain";
export type Command = { sql: string; values: (string | number | null)[] };
export interface Sql {
    first<T>(
        sql: string,
        values?: (string | number | null)[],
    ): Promise<T | null>;
    all<T>(sql: string, values?: (string | number | null)[]): Promise<T[]>;
    batch(commands: Command[]): Promise<void>;
}
export interface RawStore {
    put(key: string, value: string): Promise<unknown>;
    get(key: string): Promise<{ text(): Promise<string> } | null>;
}
export function d1Sql(db: Pick<D1Database, "prepare" | "batch">): Sql {
    return {
        first: (sql, values = []) =>
            db
                .prepare(sql)
                .bind(...values)
                .first(),
        all: async <T>(sql: string, values: (string | number | null)[] = []) =>
            (
                await db
                    .prepare(sql)
                    .bind(...values)
                    .all<T>()
            ).results,
        batch: async (commands) => {
            await db.batch(
                commands.map((c) => db.prepare(c.sql).bind(...c.values)),
            );
        },
    };
}
export type Checkpoint = {
    source: string;
    cursor: string | null;
    baseline_digest: string | null;
    checked_at: string | null;
    fetched_at: string | null;
    etag: string | null;
    complete: number;
    bootstrap_complete: number;
    error: string | null;
    object_key: string | null;
    payload_sha256: string | null;
    revision: string | null;
};
export type RecordRow = {
    id: string;
    source_url: string;
    schema_version: string;
    state: string;
    published_at: string | null;
    modified_at: string;
    fetched_at: string;
    payload_sha256: string;
    object_key: string;
    normalization_version: number;
    supported: number;
};
export class Store {
    constructor(
        readonly sql: Sql,
        readonly raw: RawStore,
        readonly clock?: () => string,
    ) {}
    writer(source: string, owner: string): Store {
        const sql = this.sql;
        return new Store(
            {
                first: sql.first.bind(sql),
                all: sql.all.bind(sql),
                batch: (commands) => sql.batch([
                    {
                        sql: "INSERT INTO mutation_fence(id,valid) VALUES(1,CASE WHEN EXISTS(SELECT 1 FROM ingestion_lease WHERE source=? AND owner=? AND expires_at>COALESCE(?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))) THEN 1 ELSE 0 END) ON CONFLICT(id) DO UPDATE SET valid=excluded.valid",
                        values: [source, owner, this.clock?.() ?? null],
                    },
                    ...commands,
                ]),
            },
            this.raw,
            this.clock,
        );
    }
    checkpoint(source: string) {
        return this.sql.first<Checkpoint>(
            "SELECT * FROM source_checkpoint WHERE source=?",
            [source],
        );
    }
    async lease(source: string, owner: string, now: string): Promise<boolean> {
        await this.sql.batch([
            {
                sql: "INSERT INTO ingestion_lease(source,owner,expires_at) VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE ingestion_lease.expires_at < ?",
                values: [
                    source,
                    owner,
                    new Date(Date.parse(now) + 600_000).toISOString(),
                    now,
                ],
            },
        ]);
        const row = await this.sql.first<{ owner: string }>(
            "SELECT owner FROM ingestion_lease WHERE source=?",
            [source],
        );
        return row?.owner === owner;
    }
    async release(source: string, owner: string) {
        await this.sql.batch([
            {
                sql: "DELETE FROM ingestion_lease WHERE source=? AND owner=?",
                values: [source, owner],
            },
        ]);
    }
    async cve(
        raw: string,
        fetchedAt: string,
        expectedId?: string,
    ): Promise<void> {
        const record = parseCve(raw, expectedId);
        const hash = await sha256(raw);
        const old = await this.sql.first<RecordRow>(
            "SELECT * FROM source_record WHERE id=?",
            [record.id],
        );
        if (old && old.modified_at > record.modified) return;
        if (old?.payload_sha256 === hash) {
            if (!old.supported)
                throw new Error(
                    "unsupported CVE schema or state preserved as partial",
                );
            return;
        }
        if (old && old.modified_at === record.modified)
            throw new Error("conflicting equal CVE revision");
        const key = `cve/${record.id}/${hash}.json`;
        await this.raw.put(key, raw);
        await this.sql.batch([
            {
                sql: "INSERT INTO source_record(id,source,source_url,schema_version,state,published_at,modified_at,fetched_at,payload_sha256,object_key,normalization_version,supported) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET source_url=excluded.source_url,schema_version=excluded.schema_version,state=excluded.state,published_at=excluded.published_at,modified_at=excluded.modified_at,fetched_at=excluded.fetched_at,payload_sha256=excluded.payload_sha256,object_key=excluded.object_key,normalization_version=excluded.normalization_version,supported=excluded.supported WHERE excluded.modified_at > source_record.modified_at",
                values: [
                    record.id,
                    "cve",
                    cveUrl(record.id),
                    record.schema,
                    record.state,
                    record.published,
                    record.modified,
                    fetchedAt,
                    hash,
                    key,
                    1,
                    Number(record.supported),
                ],
            },
            {
                sql: "INSERT INTO cve(id,state,modified_at,payload_sha256) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,modified_at=excluded.modified_at,payload_sha256=excluded.payload_sha256 WHERE excluded.modified_at > cve.modified_at",
                values: [record.id, record.state, record.modified, hash],
            },
        ]);
        if (!record.supported) {
            await this.sql.batch([
                {
                    sql: "UPDATE source_checkpoint SET complete=0,error=? WHERE source=?",
                    values: ["unsupported CVE schema or state", "cve"],
                },
            ]);
            throw new Error(
                "unsupported CVE schema or state preserved as partial",
            );
        }
    }
}

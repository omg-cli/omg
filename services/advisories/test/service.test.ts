import { test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { handle } from "../src/service";
import { Store, type Sql, type Command, type Checkpoint } from "../src/storage";
import { refreshCves, refreshSnapshot } from "../src/ingestion";
import {
    SOURCES,
    cveUrl,
    parseCve,
    sha256,
    boundedBody,
    parseDelta,
    object,
} from "../src/domain";
const now = "2026-11-13T02:00:00.000Z";
const token = "test-ingest-token-at-least-32-characters";
function setup(counterMigration = true) {
    const db = new Database(":memory:");
    db.exec(
        require("fs").readFileSync(
            new URL("../migrations/0001_advisories.sql", import.meta.url),
            "utf8",
        ),
    );
    if (counterMigration)
        db.exec(
            require("fs").readFileSync(
                new URL("../migrations/0002_baseline_member_counter.sql", import.meta.url),
                "utf8",
            ),
        );
    const sql: Sql = {
        first: async <T>(
            text: string,
            values: (string | number | null)[] = [],
        ) => db.query<T, (string | number | null)[]>(text).get(...values),
        all: async <T>(text: string, values: (string | number | null)[] = []) =>
            db.query<T, (string | number | null)[]>(text).all(...values),
        batch: async (commands: Command[]) => {
            db.transaction(() => {
                for (const command of commands)
                    db.query(command.sql).run(...command.values);
            })();
        },
    };
    const objects = new Map<string, string>();
    const raw = {
        put: async (key: string, value: string) => {
            objects.set(key, value);
        },
        get: async (key: string) => {
            const value = objects.get(key);
            return value === undefined ? null : { text: async () => value };
        },
    };
    return { store: new Store(sql, raw, () => now), objects, db };
}
function cve(
    state = "PUBLISHED",
    modified = "2026-11-12T00:00:00.000Z",
    schema = "5.2",
) {
    return JSON.stringify({
        dataType: "CVE_RECORD",
        dataVersion: schema,
        cveMetadata: {
            cveId: "CVE-2026-1234",
            state,
            dateUpdated: modified,
            datePublished: "2026-11-11T00:00:00Z",
        },
        containers: {
            cna: { title: "original" },
            adp: [{ providerMetadata: { shortName: "CVE" } }],
        },
    });
}
const arch = JSON.stringify([
    {
        name: "AVG-1",
        packages: ["foo"],
        status: "Vulnerable",
        severity: "High",
        type: "test",
        affected: "1:2-3",
        fixed: "1:2-4",
        issues: ["CVE-2026-1234"],
        advisories: [],
        ticket: null,
    },
]);
const req = (path: string, method = "GET", body?: string, auth?: string) =>
    new Request(`https://advisories.example${path}`, {
        method,
        body,
        headers: auth ? { authorization: `Bearer ${auth}` } : {},
    });
async function json(response: Response) {
    return object(await response.json());
}
test("public status is readable before bootstrap and never claims completeness", async () => {
    const { store, db } = setup();
    const response = await handle(req("/v1/status"), store, undefined, now);
    expect(response.status).toBe(200);
    expect((await json(response)).bootstrap_complete).toBe(false);
    db.close();
});
test("CNA and ADP survive ingest and rejected updates cannot be resurrected by old revisions", async () => {
    const { store, db } = setup();
    await store.cve(cve(), now);
    await store.cve(cve("REJECTED", now), now);
    await store.cve(cve(), now);
    const response = await handle(
        req("/v1/cves/CVE-2026-1234"),
        store,
        undefined,
        now,
    );
    const body = await json(response);
    expect(object(object(JSON.parse(String(body.payload_json))).cveMetadata).state).toBe("REJECTED");
    expect(object(JSON.parse(String(body.payload_json))).containers).toEqual(
        JSON.parse(cve()).containers,
    );
    db.close();
});
test("idempotent hashes do not rewrite objects and conflicting equal revisions fail closed", async () => {
    const { store, objects, db } = setup();
    await store.cve(cve(), now);
    await store.cve(cve(), now);
    expect(objects.size).toBe(1);
    await expect(store.cve(cve("REJECTED"), now)).rejects.toThrow(
        "conflicting",
    );
    db.close();
});
test("unknown schema is retained but cannot become complete on replay", async () => {
    const { store, db } = setup();
    await expect(store.cve(cve("PUBLISHED", now, "99"), now)).rejects.toThrow(
        "unsupported",
    );
    await expect(store.cve(cve("PUBLISHED", now, "99"), now)).rejects.toThrow(
        "unsupported",
    );
    expect(
        await store.sql.first<{ supported: number }>(
            "SELECT supported FROM source_record",
        ),
    ).toEqual({ supported: 0 });
    db.close();
});
test("raw persistence failure never commits an index pointer", async () => {
    const { store, db } = setup();
    const broken = new Store(store.sql, {
        get: store.raw.get,
        put: async () => {
            throw new Error("R2 failure");
        },
    });
    await expect(broken.cve(cve(), now)).rejects.toThrow("R2 failure");
    expect(await store.sql.first("SELECT * FROM cve")).toBe(null);
    db.close();
});
test("expired leases can be recovered and active leases prevent concurrent writers", async () => {
    const { store, db } = setup();
    expect(await store.lease("cve", "one", now)).toBe(true);
    expect(await store.lease("cve", "two", now)).toBe(false);
    expect(await store.lease("cve", "two", "2026-11-13T02:11:00.000Z")).toBe(
        true,
    );
    await store.release("cve", "one");
    expect(await store.lease("cve", "three", "2026-11-13T02:11:01.000Z")).toBe(
        false,
    );
    db.close();
});
test("public routes cannot mutate and private authorization happens before body parsing", async () => {
    const { store, objects, db } = setup();
    expect(
        (await handle(req("/v1/status", "POST", "bad"), store, token, now))
            .status,
    ).toBe(405);
    expect(
        (
            await handle(
                req("/internal/ingest", "POST", "bad"),
                store,
                token,
                now,
            )
        ).status,
    ).toBe(401);
    expect(
        (
            await handle(
                req(
                    "/internal/ingest",
                    "POST",
                    JSON.stringify({ source: "cve", records: [cve()] }),
                    token,
                ),
                store,
                token,
                now,
            )
        ).status,
    ).toBe(200);
    expect(objects.size).toBe(1);
    db.close();
});
test("oversize bodies cancel and CVE IDs and filenames must match", async () => {
    await expect(boundedBody(new Response("12345").body, 4)).rejects.toThrow(
        "exceeds",
    );
    expect(() => parseCve(cve(), "CVE-2026-9999")).toThrow("mismatch");
    expect(() =>
        parseDelta(
            JSON.stringify([
                {
                    fetchTime: now,
                    new: [
                        {
                            cveId: "CVE-2026-1234",
                            githubLink: "https://evil.test/x",
                            dateUpdated: now,
                        },
                    ],
                    updated: [],
                    error: [],
                    numberOfChanges: 1,
                },
            ]),
        ),
    ).toThrow("untrusted");
});
test("Arch envelope retains upstream issues and 304 revalidation updates freshness", async () => {
    const { store, db } = setup();
    await refreshSnapshot(
        store,
        "arch",
        async () => new Response(arch, { headers: { etag: '"1"' } }),
        now,
    );
    let response = await handle(
        req("/v1/arch/advisories"),
        store,
        undefined,
        now,
    );
    let body = await json(response);
    expect(body.complete).toBe(true);
    expect(JSON.parse(String(body.payload_json))).toEqual(JSON.parse(arch));
    expect(body.payload_sha256).toMatch(/^[a-f0-9]{64}$/);
    const later = "2026-11-13T03:00:00.000Z";
    response = await handle(
        req("/v1/arch/advisories"),
        store,
        undefined,
        later,
    );
    expect((await json(response)).complete).toBe(false);
    await refreshSnapshot(
        store,
        "arch",
        async (_url, init) => {
            expect(new Headers(init?.headers).get("if-none-match")).toBe('"1"');
            return new Response(null, { status: 304 });
        },
        later,
    );
    body = await json(
        await handle(req("/v1/arch/advisories"), store, undefined, later),
    );
    expect(body.complete).toBe(true);
    expect(body.fetched_at).toBe(now);
    db.close();
});
test("delta checkpoint stays unchanged after a bounded batch fails and succeeds on replay", async () => {
    const { store, db } = setup();
    const delta = JSON.stringify([
        {
            fetchTime: now,
            numberOfChanges: 1,
            new: [
                {
                    cveId: "CVE-2026-1234",
                    githubLink: cveUrl("CVE-2026-1234"),
                    dateUpdated: now,
                },
            ],
            updated: [],
            error: [],
        },
    ]);
    await expect(
        refreshCves(
            store,
            async (url) =>
                url === SOURCES.cve
                    ? new Response(delta)
                    : new Response("failure", { status: 503 }),
            now,
        ),
    ).rejects.toThrow("503");
    expect((await store.checkpoint("cve"))?.cursor).toBe(null);
    await refreshCves(
        store,
        async (url) => new Response(url === SOURCES.cve ? delta : cve()),
        now,
    );
    const checkpoint = await store.checkpoint("cve");
    expect(checkpoint?.complete).toBe(1);
    expect(checkpoint?.bootstrap_complete).toBe(0);
    db.close();
});
test("incomplete baseline cannot finalize", async () => {
    const { store, db } = setup();
    const response = await handle(
        req(
            "/internal/baseline",
            "POST",
            JSON.stringify({
                digest: "a".repeat(64),
                baseline_at: now,
                accepted: 1,
                exhausted: true,
            }),
            token,
        ),
        store,
        token,
        now,
    );
    expect(response.status).toBe(400);
    expect((await store.checkpoint("cve"))?.bootstrap_complete).toBe(0);
    db.close();
});
test("baseline tracks imported members and catchup without claiming archive completeness", async () => {
    const { store, db } = setup();
    const digest = "b".repeat(64);
    const baseline = "2026-11-13T00:00:00.000Z";
    const start = () =>
        handle(
            req(
                "/internal/baseline/start",
                "POST",
                JSON.stringify({ digest, baseline_at: baseline }),
                token,
            ),
            store,
            token,
            now,
        );
    const started = await start();
    expect(started.status).toBe(200);
    const binding = await json(started);
    const imported = await handle(req("/internal/ingest", "POST", JSON.stringify({source:"cve",records:[cve()],baseline:binding}),token), store,token,now);
    expect(imported.status).toBe(200);
    const delta = JSON.stringify([
        {
            fetchTime: "2026-11-12T23:59:00.000Z",
            numberOfChanges: 1,
            new: [
                {
                    cveId: "CVE-2026-1234",
                    githubLink: cveUrl("CVE-2026-1234"),
                    dateUpdated: now,
                },
            ],
            updated: [],
            error: [],
        },
        {
            fetchTime: now,
            numberOfChanges: 1,
            new: [
                {
                    cveId: "CVE-2026-1234",
                    githubLink: cveUrl("CVE-2026-1234"),
                    dateUpdated: now,
                },
            ],
            updated: [],
            error: [],
        },
    ]);
    await refreshCves(
        store,
        async (url) => new Response(url === SOURCES.cve ? delta : cve()),
        now,
    );
    const cursor = (await store.checkpoint("cve"))?.cursor;
    expect((await start()).status).toBe(200);
    expect((await store.checkpoint("cve"))?.cursor).toBe(cursor);
    const finish = await handle(
        req(
            "/internal/baseline",
            "POST",
            JSON.stringify({
                digest,
                baseline_at: baseline,
                ...binding,
                accepted: 1,
                exhausted: true,
                finished_at: now,
            }),
            token,
        ),
        store,
        token,
        now,
    );
    expect(finish.status).toBe(200);
    expect((await store.checkpoint("cve"))?.bootstrap_complete).toBe(0);
    expect((await json(finish)).archive_verified).toBe(false);
    expect(
        await store.sql.first<{ accepted: number; exhausted: number }>(
            "SELECT accepted,exhausted FROM baseline_receipt",
        ),
    ).toEqual({ accepted: 1, exhausted: 1 });
    const replay = await handle(
        req("/internal/ingest", "POST", JSON.stringify({ source: "cve", records: [cve()], baseline: binding }), token),
        store,
        token,
        now,
    );
    expect(replay.status).toBe(200);
    expect(await store.sql.first<{ accepted: number; caught_up: number; completed_at: string | null }>(
        "SELECT accepted,caught_up,completed_at FROM baseline_receipt",
    )).toEqual({ accepted: 1, caught_up: 0, completed_at: null });
    db.close();
});
test("KEV annotation replacement removes withdrawn entries and rejects older catalogs", async () => {
    const { store, db } = setup();
    await store.cve(cve(), now);
    const catalog = (version: string, entries: unknown[]) =>
        JSON.stringify({
            catalogVersion: version,
            dateReleased: now,
            count: entries.length,
            vulnerabilities: entries,
        });
    await refreshSnapshot(
        store,
        "kev",
        async () =>
            new Response(
                catalog("2026.11.13", [
                    { cveID: "CVE-2026-1234", vendorProject: "fixture" },
                ]),
            ),
        now,
    );
    expect(
        (
            await json(
                await handle(
                    req("/v1/cves/CVE-2026-1234"),
                    store,
                    undefined,
                    now,
                ),
            )
        ).kev,
    ).toEqual({ cveID: "CVE-2026-1234", vendorProject: "fixture" });
    await refreshSnapshot(
        store,
        "kev",
        async () => new Response(catalog("2026.11.14", [])),
        now,
    );
    expect(
        (
            await json(
                await handle(
                    req("/v1/cves/CVE-2026-1234"),
                    store,
                    undefined,
                    now,
                ),
            )
        ).kev,
    ).toBe(null);
    await expect(
        refreshSnapshot(
            store,
            "kev",
            async () => new Response(catalog("2026.11.12", [])),
            now,
        ),
    ).rejects.toThrow("rollback");
    db.close();
});
test("upstream redirects are rejected with the Workers-supported manual redirect policy", async () => {
    const { store, db } = setup();
    await expect(
        refreshSnapshot(
            store,
            "arch",
            async (_url, init) => {
                expect(init?.redirect).toBe("manual");
                return new Response(null, {
                    status: 302,
                    headers: { location: "https://untrusted.example" },
                });
            },
            now,
        ),
    ).rejects.toThrow("302");
    expect((await store.checkpoint("arch"))?.object_key).toBe(null);
    db.close();
});
test("expired writer cannot overwrite snapshot after another owner commits", async () => {
    const { store, db } = setup();
    await store.lease("arch", "old", now);
    let deliver: (value: Response) => void = () => { throw new Error("not ready"); };
    const pending = new Promise<Response>((resolve) => { deliver = resolve; });
    const old = refreshSnapshot(store.writer("arch", "old"), "arch", async () => pending, now);
    await Bun.sleep(0);
    const later = "2026-11-13T02:11:00.000Z";
    await store.lease("arch", "new", later);
    await refreshSnapshot(store.writer("arch", "new"), "arch", async () => new Response(arch.replace("AVG-1", "AVG-2")), later);
    deliver(new Response(arch));
    await expect(old).rejects.toThrow("CHECK constraint failed");
    expect((await store.checkpoint("arch"))?.checked_at).toBe(later);
    db.close();
});
test("payload_json preserves exact wire bytes for independent SHA verification", async () => {
    const { store, db } = setup();
    const raw = JSON.stringify(JSON.parse(arch), null, 2) + "\n";
    await refreshSnapshot(store, "arch", async () => new Response(raw), now);
    const body = await json(await handle(req("/v1/arch/advisories"), store, undefined, now));
    expect(body.payload_json).toBe(raw);
    expect(await sha256(String(body.payload_json))).toBe(String(body.payload_sha256));
    db.close();
});
test("UTF8 BOM is rejected instead of silently changing hashed bytes", async () => {
    await expect(boundedBody(new Response(new Uint8Array([239,187,191,91,93])).body, 10)).rejects.toThrow("BOM");
});
test("inflated operator baseline receipt cannot certify unimported archive members", async () => {
    const { store, db } = setup();
    const digest = "c".repeat(64);
    const post = (path: string, payload: unknown) => handle(req(path, "POST", JSON.stringify(payload), token), store, token, now);
    const binding = await json(await post("/internal/baseline/start", { digest, baseline_at: now }));
    await store.sql.batch([{ sql: "UPDATE source_checkpoint SET complete=1,checked_at=?,cursor=? WHERE source='cve'", values:[now,JSON.stringify({event:now,offset:0})] }]);
    const result = await post("/internal/baseline", {...binding,digest, baseline_at:now, accepted:400000, exhausted:true, finished_at:now});
    expect(result.status).toBe(400);
    expect((await store.checkpoint("cve"))?.bootstrap_complete).toBe(0);
    db.close();
});
test("expired same-owner transaction rolls back all mutations using commit-time clock", async () => {
    const { store, db } = setup();
    let clock = now;
    const timed = new Store(store.sql, store.raw, () => clock);
    await timed.lease("cve", "one", now);
    const writer = timed.writer("cve", "one");
    clock = "2026-11-13T02:10:00.000Z";
    await expect(writer.sql.batch([
        {sql:"UPDATE source_checkpoint SET cursor='corrupt' WHERE source='cve'",values:[]},
        {sql:"UPDATE source_checkpoint SET error='stale failure',complete=0 WHERE source='cve'",values:[]},
    ])).rejects.toThrow("CHECK constraint failed");
    expect((await store.checkpoint("cve"))?.cursor).toBe(null);
    expect((await store.checkpoint("cve"))?.error).toBe(null);
    db.close();
});
test("stale KEV writer cannot delete annotations or record a stale error", async () => {
    const { store, db } = setup();
    await store.lease("kev", "old", now);
    const stale = store.writer("kev", "old");
    const later = "2026-11-13T02:11:00.000Z";
    await store.lease("kev", "new", later);
    const current = store.writer("kev", "new");
    await current.sql.batch([{sql:"INSERT INTO kev_annotation VALUES(?,?,?)",values:["CVE-2026-1234",'{}',"new"]}]);
    await expect(stale.sql.batch([
        {sql:"DELETE FROM kev_annotation",values:[]},
        {sql:"UPDATE source_checkpoint SET error='old failure',complete=0 WHERE source='kev'",values:[]},
    ])).rejects.toThrow("CHECK constraint failed");
    expect(await store.sql.first<{catalog_sha256:string}>("SELECT catalog_sha256 FROM kev_annotation")).toEqual({catalog_sha256:"new"});
    expect((await store.checkpoint("kev"))?.error).toBe(null);
    db.close();
});
test("baseline resume is bound to database instance, endpoint and distinct server-counted members", async () => {
    const {store,db} = setup();
    const other = setup();
    const digest = "d".repeat(64);
    const post = (path:string,payload:unknown, target=store, host="advisories.example") => handle(new Request(`https://${host}${path}`,{method:"POST",headers:{authorization:`Bearer ${token}`},body:JSON.stringify(payload)}),target,token,now);
    const binding = await json(await post("/internal/baseline/start",{digest,baseline_at:now}));
    expect((await post("/internal/baseline/start",{...binding,baseline_at:now},other.store)).status).toBe(400);
    expect((await post("/internal/baseline/start",{...binding,baseline_at:now},store,"other.example")).status).toBe(400);
    expect((await post("/internal/ingest",{source:"cve",records:[cve(),cve()],baseline:binding})).status).toBe(200);
    expect(await store.sql.first<{count:number}>("SELECT COUNT(*) AS count FROM baseline_member")).toEqual({count:1});
    expect((await post("/internal/ingest",{source:"cve",records:[cve()],baseline:{...binding,session_id:"wrong"}})).status).toBe(400);
    expect((await store.checkpoint("cve"))?.bootstrap_complete).toBe(0);
    db.close(); other.db.close();
});
test("counter migration reconciles existing members and enforces atomic append-only counting", async () => {
    const { store, db } = setup(false);
    try {
        await store.sql.batch([
            {
                sql: "INSERT INTO baseline_receipt(digest,instance_id,session_id,endpoint,baseline_at,accepted,exhausted) VALUES(?,?,?,?,?,?,0)",
                values: ["e".repeat(64), "fixture-instance", "fixture-session", "https://advisories.example", now, 99],
            },
            {
                sql: "INSERT INTO baseline_member VALUES(?,?,?)",
                values: ["fixture-session", "CVE-2026-1234", "first"],
            },
            {
                sql: "INSERT INTO baseline_member VALUES(?,?,?)",
                values: ["fixture-session", "CVE-2026-1235", "second"],
            },
        ]);
        db.exec(require("fs").readFileSync(new URL("../migrations/0002_baseline_member_counter.sql", import.meta.url), "utf8"));
        const count = () => store.sql.first<{ accepted: number }>("SELECT accepted FROM baseline_receipt");
        expect(await count()).toEqual({ accepted: 2 });
        const insert = {
            sql: "INSERT INTO baseline_member VALUES(?,?,?) ON CONFLICT(session_id,cve_id) DO NOTHING",
            values: ["fixture-session", "CVE-2026-1236", "third"],
        };
        await store.sql.batch([insert]);
        await store.sql.batch([insert]);
        expect(await count()).toEqual({ accepted: 3 });
        await expect(store.sql.batch([{
            sql: "UPDATE baseline_member SET payload_sha256='changed'",
            values: [],
        }])).rejects.toThrow("append-only");
        await expect(store.sql.batch([{
            sql: "DELETE FROM baseline_member",
            values: [],
        }])).rejects.toThrow("append-only");
        await expect(store.sql.batch([
            { ...insert, values: ["fixture-session", "CVE-2026-1237", "rollback"] },
            { sql: "INSERT INTO missing_table VALUES(1)", values: [] },
        ])).rejects.toThrow("missing_table");
        expect(await count()).toEqual({ accepted: 3 });
        expect(await store.sql.first<{ count: number }>("SELECT COUNT(*) AS count FROM baseline_member")).toEqual({ count: 3 });
    } finally {
        db.close();
    }
});
test("baseline finalization rejects a maintained counter that differs from actual membership", async () => {
    const { store, db } = setup();
    try {
        const post = (path: string, payload: unknown) => handle(
            req(path, "POST", JSON.stringify(payload), token), store, token, now,
        );
        const binding = await json(await post("/internal/baseline/start", {
            digest: "f".repeat(64), baseline_at: now,
        }));
        expect((await post("/internal/ingest", {
            source: "cve", records: [cve()], baseline: binding,
        })).status).toBe(200);
        await store.sql.batch([
            { sql: "UPDATE baseline_receipt SET accepted=2", values: [] },
            {
                sql: "UPDATE source_checkpoint SET complete=1,checked_at=?,cursor=? WHERE source='cve'",
                values: [now, JSON.stringify({ event: now, offset: 0 })],
            },
        ]);
        const response = await post("/internal/baseline", {
            ...binding, baseline_at: now, finished_at: now, accepted: 1, exhausted: true,
        });
        expect(response.status).toBe(400);
        expect((await store.checkpoint("cve"))?.bootstrap_complete).toBe(0);
        expect(await store.sql.first<{ caught_up: number }>("SELECT caught_up FROM baseline_receipt")).toEqual({ caught_up: 0 });
    } finally {
        db.close();
    }
});

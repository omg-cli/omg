import { test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { handle } from "../../advisories/src/service";
import { Store, type Sql, type Command } from "../../advisories/src/storage";
import type { Fetcher } from "../../advisories/src/ingestion";
import { object } from "../../advisories/src/domain";
import { handleStage } from "../stage";
import { CANONICAL_ORIGIN, STAGE_MODE, STAGE_ORIGIN } from "../stage-identity";

const now = "2026-11-13T02:00:00.000Z";
const ingestToken = "controlled-ingest-token-at-least-32-characters";
const refreshToken = "controlled-refresh-token-at-least-32-characters";
const githubToken = `ghs_12345_fixture.header-${"A".repeat(475)}.signature_fixture`;
const archiveDigest = "a".repeat(64);
const commit = "1".repeat(40), rootTree = "2".repeat(40), cvesTree = "3".repeat(40);
const yearTree = "4".repeat(40), groupTree = "5".repeat(40);
const raw = JSON.stringify({ dataType: "CVE_RECORD", dataVersion: "5.2", cveMetadata: {
    cveId: "CVE-2026-1234", state: "PUBLISHED", dateUpdated: "2026-11-12T00:00:00.000Z",
    datePublished: "2026-11-11T00:00:00.000Z",
}, containers: { cna: { title: "controlled archive member" } } });

function setup() {
    const db = new Database(":memory:");
    const migrations = new NodeURL("../../advisories/migrations/", import.meta.url);
    for (const name of readdirSync(migrations).filter((name) => name.endsWith(".sql")).sort())
        db.exec(readFileSync(new NodeURL(name, migrations), "utf8"));
    const sql: Sql = {
        first: async <T>(text: string, values: (string | number | null)[] = []) => db.query<T, (string | number | null)[]>(text).get(...values),
        all: async <T>(text: string, values: (string | number | null)[] = []) => db.query<T, (string | number | null)[]>(text).all(...values),
        batch: async (commands: Command[]) => { db.transaction(() => {
            for (const command of commands) db.query(command.sql).run(...command.values);
        })(); },
    };
    const objects = new Map<string, string>();
    const store = new Store(sql, {
        put: async (key, value) => { objects.set(key, value); },
        get: async (key) => {
            const value = objects.get(key);
            return value === undefined ? null : { text: async () => value };
        },
    }, () => now);
    return { db, store, objects };
}

function request(path: string, body: unknown, token: string) {
    return new Request(`https://advisories.example${path}`, {
        method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify(body),
    });
}

async function binding(store: Store) {
    const started = await handle(request("/internal/baseline/start", {
        digest: archiveDigest, baseline_at: "2026-11-13T00:00:00.000Z",
    }, ingestToken), store, ingestToken, now);
    expect(started.status).toBe(200);
    const value: unknown = await started.json();
    if (!value || typeof value !== "object" || !("session_id" in value)) throw new Error("missing test baseline session");
    return value;
}

async function publisherFetcher() {
    const bytes = new TextEncoder().encode(raw);
    const header = new TextEncoder().encode(`blob ${bytes.length}\0`);
    const object = new Uint8Array(header.length + bytes.length);
    object.set(header); object.set(bytes, header.length);
    const blob = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", object)), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const calls: string[] = [];
    const entry = (path: string, type: "tree" | "blob", sha: string) => ({ path, type, sha, mode: type === "tree" ? "040000" : "100644" });
    const payloads = new Map<string, unknown>([
        ["/repos/CVEProject/cvelistV5/releases/tags/cve_2026-11-13_0000Z", { tag_name: "cve_2026-11-13_0000Z", assets: [{
            name: "2026-11-13_all_CVEs_at_midnight.zip.zip", digest: `sha256:${archiveDigest}`, size: 100,
        }] }],
        ["/repos/CVEProject/cvelistV5/git/ref/tags/cve_2026-11-13_0000Z", { object: { type: "commit", sha: commit } }],
        [`/repos/CVEProject/cvelistV5/git/commits/${commit}`, { sha: commit, tree: { sha: rootTree } }],
        [`/repos/CVEProject/cvelistV5/git/trees/${rootTree}`, { sha: rootTree, truncated: false, tree: [entry("cves", "tree", cvesTree)] }],
        [`/repos/CVEProject/cvelistV5/git/trees/${cvesTree}`, { sha: cvesTree, truncated: false, tree: [entry("2026", "tree", yearTree)] }],
        [`/repos/CVEProject/cvelistV5/git/trees/${yearTree}`, { sha: yearTree, truncated: false, tree: [entry("1xxx", "tree", groupTree)] }],
        [`/repos/CVEProject/cvelistV5/git/trees/${groupTree}`, { sha: groupTree, truncated: false, tree: [entry("CVE-2026-1234.json", "blob", blob)] }],
    ]);
    const fetcher: Fetcher = async (input, init) => {
        const url = new URL(input);
        expect(url.origin).toBe("https://api.github.com");
        expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${githubToken}`);
        expect(init?.redirect).toBe("manual");
        calls.push(url.pathname);
        const payload = payloads.get(url.pathname);
        if (!payload) throw new Error(`unexpected publisher request: ${url.pathname}`);
        return Response.json(payload);
    };
    return { fetcher, calls, blob, payloads };
}

test("private staging proves the canonical session through promotion and reverse binding", async () => {
    const incumbent = setup(), stage = setup();
    try {
        const prior = await binding(incumbent.store);
        const previousDatabase = incumbent.db.serialize();
        const id = stage.db.query<{id:string}, []>("SELECT id FROM database_instance").get()?.id;
        if (!id) throw new Error("missing fixture stage instance");
        const aud = "a".repeat(64);
        const access = { access: { aud, getIdentity: async () => undefined } };
        const policy = { STAGE_MODE, STAGE_ACCESS_AUD: aud, STAGE_DATABASE_INSTANCE_ID: id,
            STAGE_INGEST_TOKEN: ingestToken, STAGE_RUNTIME_REFRESH_SECRET: refreshToken };
        const publisher = await publisherFetcher();
        const start = { digest: archiveDigest, baseline_at: "2026-11-13T00:00:00.000Z" };
        const stagePost = (path: string, payload: unknown, token = ingestToken, origin = STAGE_ORIGIN) =>
            new Request(origin + path, { method: "POST", body: JSON.stringify(payload),
                headers: { authorization: `Bearer ${token}`, "content-type": "application/json",
                    "x-forwarded-host": "attacker.example", "cf-access-jwt-assertion": "fixture-untrusted-header" } });
        const route = (req: Request, store = stage.store) =>
            handleStage(req, access, policy, () => store, now, publisher.fetcher);
        const req = () => stagePost("/internal/baseline/start", start);
        const forbiddenStore = () => { throw new Error("unexpected storage access"); };
        expect((await handleStage(req(), {}, policy, forbiddenStore, now)).status).toBe(403);
        expect((await handleStage(req(), access, { ...policy, STAGE_ACCESS_AUD: "b".repeat(64) }, forbiddenStore, now)).status).toBe(403);
        expect((await handleStage(req(), access, { ...policy, STAGE_MODE: "disabled" }, forbiddenStore, now)).status).toBe(503);
        expect((await route(stagePost("/internal/baseline/start", start, ingestToken, CANONICAL_ORIGIN))).status).toBe(403);
        expect((await route(req(), incumbent.store)).status).toBe(503);
        expect((await route(req())).status).toBe(503);
        expect(stage.db.query("SELECT COUNT(*) AS count FROM baseline_receipt").get()).toEqual({count:0});
        expect(stage.objects.size).toBe(0);
        stage.objects.set(`stage-isolation/${id}`, "");
        expect((await route(stagePost("/internal/baseline/start", start, "wrong-token"))).status).toBe(401);
        expect(stage.db.query("SELECT COUNT(*) AS count FROM baseline_receipt").get()).toEqual({count:0});

        const started = await route(req());
        expect(started.status).toBe(200);
        expect(started.headers.get("cache-control")).toBe("no-store");
        const canonical = object(await started.json());
        expect(canonical).toMatchObject({ endpoint: CANONICAL_ORIGIN, instance_id: id });
        const payload = { source: "cve", records: [raw], baseline: canonical };
        expect((await route(stagePost("/internal/ingest", { ...payload, baseline: prior }))).status).toBe(400);
        expect(stage.objects.size).toBe(1);
        expect((await route(stagePost("/internal/ingest", payload))).status).toBe(200);
        const originalObjects = stage.objects.size;
        expect(await (await route(stagePost("/internal/baseline/start", { ...start, ...canonical }))).json()).toMatchObject(canonical);
        expect((await route(stagePost("/internal/ingest", payload))).status).toBe(200);
        expect(stage.objects.size).toBe(originalObjects);
        expect(stage.db.query("SELECT accepted FROM baseline_receipt").get()).toEqual({accepted:1});

        const proof = { ...canonical, release_tag: "cve_2026-11-13_0000Z",
            asset: "2026-11-13_all_CVEs_at_midnight.zip.zip", github_token: githubToken };
        expect((await route(stagePost("/internal/baseline/verify", proof))).status).toBe(401);
        expect(await (await route(stagePost("/internal/baseline/verify", proof, refreshToken))).json()).toMatchObject({
            phase: "awaiting_import", expected_count: 1, pending_trees: 0,
        });
        stage.db.query("UPDATE source_checkpoint SET complete=1,checked_at=?,cursor=? WHERE source='cve'").run(now, JSON.stringify({event:now,offset:0}));
        expect((await route(stagePost("/internal/baseline", { ...canonical, ...start, finished_at: now, accepted: 1, exhausted: true }))).status).toBe(200);
        expect(await (await route(stagePost("/internal/baseline/verify", proof, refreshToken))).json()).toMatchObject({
            phase: "verified", verified_count: 1, pending_trees: 0,
        });

        const status = (store: Store) => handle(new Request(CANONICAL_ORIGIN + "/v1/status"), store, undefined, now);
        const verifyAtCanonical = (store: Store) => handle(stagePost("/internal/baseline/verify", proof, refreshToken, CANONICAL_ORIGIN),
            store, ingestToken, now, publisher.fetcher, refreshToken);
        const upstreamCalls = publisher.calls.length;
        expect(await (await verifyAtCanonical(stage.store)).json()).toMatchObject({ phase: "verified", verified_count: 1 });
        expect(await (await status(stage.store)).json()).toMatchObject({ bootstrap_complete: true });
        expect((await verifyAtCanonical(incumbent.store)).status).toBe(400);
        expect(await (await status(incumbent.store)).json()).toMatchObject({ baseline: { imported: 0, archive_verified: false }, bootstrap_complete: false });
        expect(incumbent.db.serialize()).toEqual(previousDatabase);
        expect(incumbent.objects.size).toBe(0);
        expect(publisher.calls.length).toBe(upstreamCalls);
    } finally {
        incumbent.db.close();
        stage.db.close();
    }
});

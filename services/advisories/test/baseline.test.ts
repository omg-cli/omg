import { test, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { handle } from "../src/service";
import { Store, type Sql, type Command } from "../src/storage";
import type { Fetcher } from "../src/ingestion";
import { baselineImportCommands, gitBlobSha1 } from "../src/baseline";

const now = "2026-11-13T02:00:00.000Z";
const ingestToken = "controlled-ingest-token-at-least-32-characters";
const refreshToken = "controlled-refresh-token-at-least-32-characters";
const githubToken = `ghs_${"A".repeat(40)}`;
const archiveDigest = "a".repeat(64);
const commit = "1".repeat(40), rootTree = "2".repeat(40), cvesTree = "3".repeat(40);
const yearTree = "4".repeat(40), groupTree = "5".repeat(40);
const raw = JSON.stringify({ dataType: "CVE_RECORD", dataVersion: "5.2", cveMetadata: {
    cveId: "CVE-2026-1234", state: "PUBLISHED", dateUpdated: "2026-11-12T00:00:00.000Z",
    datePublished: "2026-11-11T00:00:00.000Z",
}, containers: { cna: { title: "controlled archive member" } } });

function setup() {
    const db = new Database(":memory:");
    const migrations = new NodeURL("../migrations/", import.meta.url);
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

test("authenticated publisher proof enumerates official nonrecursive Git membership instead of trusting operator exhaustion", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store);
        const publisher = await publisherFetcher();
        const response = await handle(request("/internal/baseline/verify", {
            ...baseline, release_tag: "cve_2026-11-13_0000Z",
            asset: "2026-11-13_all_CVEs_at_midnight.zip.zip", github_token: githubToken,
        }, refreshToken), fixture.store, ingestToken, now, publisher.fetcher, refreshToken);
        expect(response.status).toBe(200);
        const proof = await response.json();
        expect(proof).toMatchObject({ expected_count: 1, phase: "awaiting_import", archive_verified: false });
        expect(publisher.calls).toContain(`/repos/CVEProject/cvelistV5/git/trees/${groupTree}`);
        expect(JSON.stringify(proof)).not.toContain(githubToken);
    } finally { fixture.db.close(); }
});

async function verify(store: Store, baseline: object, fetcher: Fetcher, changes: Record<string, unknown> = {}) {
    return handle(request("/internal/baseline/verify", { ...baseline,
        release_tag: "cve_2026-11-13_0000Z", asset: "2026-11-13_all_CVEs_at_midnight.zip.zip",
        github_token: githubToken, ...changes,
    }, refreshToken), store, ingestToken, now, fetcher, refreshToken);
}
async function ingest(store: Store, baseline: object, payload = raw) {
    return handle(request("/internal/ingest", { source: "cve", baseline, records: [payload] }, ingestToken), store, ingestToken, now);
}
async function finish(fixture: ReturnType<typeof setup>, baseline: object) {
    fixture.db.query("UPDATE source_checkpoint SET complete=1,error=NULL,checked_at=?,cursor=? WHERE source='cve'").run(now, JSON.stringify({event:now,offset:0}));
    return handle(request("/internal/baseline", { ...baseline, baseline_at: "2026-11-13T00:00:00.000Z", finished_at: now, accepted: 1, exhausted: true }, ingestToken), fixture.store, ingestToken, now);
}

test("publisher certification binds original imports while retaining newer delta payloads", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        const newer = raw.replace("2026-11-12T00:00:00.000Z", "2026-11-13T01:00:00.000Z").replace("controlled archive member", "newer delta revision");
        await fixture.store.cve(newer, now);
        expect((await ingest(fixture.store, baseline)).status).toBe(200);
        expect((await finish(fixture, baseline)).status).toBe(200);
        const response = await verify(fixture.store, baseline, publisher.fetcher);
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ phase: "verified", expected_count: 1, verified_count: 1, pending_trees: 0, archive_verified: true });
        const row = fixture.db.query<{object_key:string}, []>("SELECT object_key FROM source_record").get();
        expect(row && fixture.objects.get(row.object_key)).toBe(newer);
        const status = await handle(new Request("https://advisories.example/v1/status"), fixture.store, undefined, now);
        expect(await status.json()).toMatchObject({ baseline: { imported: 1, archive_verified: true }, bootstrap_complete: true });
        expect(await (await finish(fixture, baseline)).json()).toMatchObject({ bootstrap_complete: true, archive_verified: true });
        expect(JSON.stringify([...fixture.objects.values()])).not.toContain(githubToken);
        expect((await ingest(fixture.store, baseline)).status).toBe(200);
        expect(fixture.db.query<{bootstrap_complete:number}, []>("SELECT bootstrap_complete FROM source_checkpoint WHERE source='cve'").get()?.bootstrap_complete).toBe(0);
        expect(await (await verify(fixture.store, baseline, publisher.fetcher)).json()).toMatchObject({phase:"awaiting_import",archive_verified:false});
    } finally { fixture.db.close(); }
});

test("legacy members without original Git identities require exact replay", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        const session = fixture.db.query<{session_id:string}, []>("SELECT session_id FROM baseline_receipt").get();
        if (!session) throw new Error("missing fixture session");
        const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw)))].map((b) => b.toString(16).padStart(2,"0")).join("");
        fixture.db.query("INSERT INTO baseline_member VALUES(?,?,?)").run(session.session_id, "CVE-2026-1234", hash);
        expect((await finish(fixture, baseline)).status).toBe(200);
        expect(await (await verify(fixture.store, baseline, publisher.fetcher)).json()).toMatchObject({phase:"awaiting_import",archive_verified:false});
        expect((await ingest(fixture.store, baseline)).status).toBe(200);
        expect((await finish(fixture, baseline)).status).toBe(200);
        expect(await (await verify(fixture.store, baseline, publisher.fetcher)).json()).toMatchObject({phase:"verified",archive_verified:true});
        expect(fixture.db.query<{accepted:number}, []>("SELECT accepted FROM baseline_receipt").get()?.accepted).toBe(1);
    } finally { fixture.db.close(); }
});

test("publisher proof requires fresh delta catchup after import exhaustion", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        expect((await ingest(fixture.store, baseline)).status).toBe(200);
        expect((await finish(fixture, baseline)).status).toBe(200);
        fixture.db.exec("UPDATE source_checkpoint SET checked_at='2026-11-13T01:00:00.000Z' WHERE source='cve'");
        expect(await (await verify(fixture.store, baseline, publisher.fetcher)).json()).toMatchObject({phase:"awaiting_catchup",verified_count:1,archive_verified:false});
        fixture.db.query("UPDATE source_checkpoint SET checked_at=? WHERE source='cve'").run(now);
        expect(await (await verify(fixture.store, baseline, publisher.fetcher)).json()).toMatchObject({phase:"verified",archive_verified:true});
    } finally { fixture.db.close(); }
});

for (const malformed of ["digest", "truncated", "duplicate", "wrong-path", "symlink", "blob-mismatch"] as const) {
    test(`publisher proof refuses ${malformed} without enabling completeness`, async () => {
        const fixture = setup();
        try {
            const baseline = await binding(fixture.store), publisher = await publisherFetcher();
            expect((await ingest(fixture.store, baseline)).status).toBe(200);
            expect((await finish(fixture, baseline)).status).toBe(200);
            const group = `/repos/CVEProject/cvelistV5/git/trees/${groupTree}`;
            if (malformed === "digest") publisher.payloads.set("/repos/CVEProject/cvelistV5/releases/tags/cve_2026-11-13_0000Z", {tag_name:"cve_2026-11-13_0000Z", assets:[{name:"2026-11-13_all_CVEs_at_midnight.zip.zip",digest:`sha256:${"b".repeat(64)}`,size:100}]});
            else {
                const item = { path: malformed === "wrong-path" ? "CVE-2025-1234.json" : "CVE-2026-1234.json", type:"blob", mode:malformed === "symlink" ? "120000":"100644", sha:malformed === "blob-mismatch" ? "f".repeat(40):publisher.blob };
                publisher.payloads.set(group, {sha:groupTree,truncated:malformed === "truncated",tree:malformed === "duplicate"?[item,item]:[item]});
            }
            expect((await verify(fixture.store, baseline, publisher.fetcher)).status).toBe(400);
            expect(fixture.db.query<{bootstrap_complete:number}, []>("SELECT bootstrap_complete FROM source_checkpoint WHERE source='cve'").get()?.bootstrap_complete).toBe(0);
        } finally { fixture.db.close(); }
    });
}

test("verification authorizes before input and refuses operator manifests or arbitrary URLs", async () => {
    const fixture = setup();
    try {
        let calls = 0;
        const fetcher: Fetcher = async () => { calls++; throw new Error("unexpected fetch"); };
        expect((await handle(request("/internal/baseline/verify", {github_token:githubToken}, ingestToken), fixture.store, ingestToken, now, fetcher, refreshToken)).status).toBe(401);
        const baseline = await binding(fixture.store);
        expect((await verify(fixture.store, baseline, fetcher, {manifest:["CVE-2026-1234"],url:"https://attacker.example"})).status).toBe(400);
        expect(calls).toBe(0);
    } finally { fixture.db.close(); }
});

test("failed publisher fetches redact credentials and cannot advance proof state", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store);
        const response = await verify(fixture.store, baseline, async () => { throw new Error(`provider failed ${githubToken}`); });
        expect(response.status).toBe(503);
        expect(await response.text()).not.toContain(githubToken);
        expect(fixture.db.query<{count:number}, []>("SELECT COUNT(*) AS count FROM baseline_publisher_proof").get()?.count).toBe(0);
    } finally { fixture.db.close(); }
});

test("commit-time lease expiry prevents fetched publisher state becoming authority", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        const response = await verify(fixture.store, baseline, async (url, init) => {
            const result = await publisher.fetcher(url, init);
            fixture.db.exec("UPDATE ingestion_lease SET expires_at='2026-11-13T01:00:00.000Z'");
            return result;
        });
        expect(response.status).toBe(503);
        expect(fixture.db.query<{count:number}, []>("SELECT COUNT(*) AS count FROM baseline_publisher_proof").get()?.count).toBe(0);
    } finally { fixture.db.close(); }
});

test("original Git blob identities include the UTF8 byte-length header", async () => {
    expect(await gitBlobSha1("")).toBe("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    expect(await gitBlobSha1("hello\n")).toBe("ce013625030ba8dba906f756967f9e9ca394464a");
});

test("publisher traversal resumes bounded work without fetching completed trees again", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        const groups = Array.from({length:12}, (_, index) => ({path:`${index}xxx`,type:"tree",mode:"040000",sha:(index+100).toString(16).padStart(40,"0")}));
        publisher.payloads.set(`/repos/CVEProject/cvelistV5/git/trees/${yearTree}`, {sha:yearTree,truncated:false,tree:groups});
        for (const group of groups) publisher.payloads.set(`/repos/CVEProject/cvelistV5/git/trees/${group.sha}`, {sha:group.sha,truncated:false,tree:[]});
        const first = await verify(fixture.store, baseline, publisher.fetcher);
        expect(first.status).toBe(200);
        expect(await first.json()).toMatchObject({phase:"traversing",pending_trees:6,expected_count:0,verified_count:0,archive_verified:false});
        const alreadyFetched = [...publisher.calls];
        const second = await verify(fixture.store, baseline, publisher.fetcher);
        expect(second.status).toBe(200);
        expect(await second.json()).toMatchObject({phase:"awaiting_import",pending_trees:0,archive_verified:false});
        expect(publisher.calls.slice(alreadyFetched.length).some((path) => alreadyFetched.includes(path))).toBe(false);
        expect(publisher.calls).toHaveLength(18); // four metadata/root reads plus fourteen queued trees
    } finally { fixture.db.close(); }
});

test("import exhaustion with extra members cannot certify publisher membership", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        expect((await ingest(fixture.store, baseline)).status).toBe(200);
        expect((await ingest(fixture.store, baseline, raw.replace("CVE-2026-1234", "CVE-2026-1235"))).status).toBe(200);
        fixture.db.query("UPDATE baseline_receipt SET exhausted=1,caught_up=1,completed_at=?").run(now);
        const response = await verify(fixture.store, baseline, publisher.fetcher);
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({complete:false});
        expect(fixture.db.query<{bootstrap_complete:number}, []>("SELECT bootstrap_complete FROM source_checkpoint WHERE source='cve'").get()?.bootstrap_complete).toBe(0);
    } finally { fixture.db.close(); }
});

test("missing publisher members remain awaiting import despite operator exhaustion", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store), publisher = await publisherFetcher();
        fixture.db.query("UPDATE baseline_receipt SET exhausted=1,caught_up=1,completed_at=?").run(now);
        expect(await (await verify(fixture.store, baseline, publisher.fetcher)).json()).toMatchObject({phase:"awaiting_import",expected_count:1,verified_count:0,archive_verified:false});
    } finally { fixture.db.close(); }
});

test("replay conflict checks probe exact member keys instead of scanning the imported corpus", async () => {
    const fixture = setup();
    try {
        const plans: string[] = [];
        const sql: Sql = { ...fixture.store.sql, first: async <T>(text: string, values: (string | number | null)[] = []) => {
            plans.push(...fixture.db.query<{detail:string}, (string | number | null)[]>(`EXPLAIN QUERY PLAN ${text}`).all(...values).map((row) => row.detail));
            return fixture.store.sql.first<T>(text, values);
        } };
        await baselineImportCommands(new Store(sql, fixture.store.raw), "controlled-session", [{id:"CVE-2026-1234",raw}]);
        expect(plans.join("\n")).toContain("session_id=? AND cve_id=?");
        expect(plans.some((plan) => plan.endsWith("(session_id=?)"))).toBe(false);
    } finally { fixture.db.close(); }
});

test("publisher proof reports an active writer as retryable without upstream fetches or ownership changes", async () => {
    const fixture = setup();
    try {
        const baseline = await binding(fixture.store);
        await fixture.store.lease("cve", "active-import-owner", now);
        let fetched = 0;
        const response = await verify(fixture.store, baseline, async () => {
            fetched++;
            throw new Error("busy proof must not fetch");
        });
        expect(response.status).toBe(409);
        expect(response.headers.get("Cache-Control")).toBe("no-store");
        expect(fetched).toBe(0);
        expect(fixture.db.query<{owner:string}, []>("SELECT owner FROM ingestion_lease WHERE source='cve'").get()?.owner).toBe("active-import-owner");
        expect(fixture.db.query<{count:number}, []>("SELECT COUNT(*) AS count FROM baseline_publisher_proof").get()?.count).toBe(0);
    } finally { fixture.db.close(); }
});

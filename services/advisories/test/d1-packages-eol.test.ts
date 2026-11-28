import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { URL as NodeURL } from "node:url";
import { handle } from "../src/service";
import { Store, d1ReadSql, d1WriteSql, type Sql } from "../src/storage";

function sqliteStore(): { store: Store; db: Database } {
    const db = new Database(":memory:");
    for (const name of [
        "0001_advisories.sql",
        "0002_baseline_member_counter.sql",
        "0003_recent_cves.sql",
        "0004_epss_cache.sql",
        "0005_runtime_sources.sql",
        "0006_baseline_publisher_proof.sql",
        "0007_packages_and_enrichment.sql",
        "0008_cve_enrichment.sql",
    ]) {
        db.exec(readFileSync(new NodeURL(`../migrations/${name}`, import.meta.url), "utf8"));
    }
    const sql: Sql = {
        first: async <T>(query: string, values: (string | number | null)[] = []) =>
            (db.query(query).get(...values) as T | null) ?? null,
        all: async <T>(query: string, values: (string | number | null)[] = []) =>
            db.query(query).all(...values) as T[],
        batch: async (commands) => {
            db.transaction(() => {
                for (const c of commands) db.query(c.sql).run(...c.values);
            })();
        },
    };
    const raw = new Map<string, string>();
    const store = new Store(sql, {
        put: async (key, value) => {
            raw.set(key, value);
        },
        get: async (key) => {
            const text = raw.get(key);
            return text === undefined ? null : { text: async () => text };
        },
    });
    return { store, db };
}

test("D1 packages/check, chunked packages/audit, and eol routes return ranked enriched findings", async () => {
    const { store, db } = sqliteStore();
    const now = "2026-11-27T12:00:00.000Z";
    db.query(
        "INSERT INTO osv_package_advisory(id,ecosystem,package_name,ecosystem_lower,package_name_lower,is_malware,summary,severity,aliases_json,fixed_versions_json,modified_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    ).run(
        "GHSA-aaaa-bbbb-cccc",
        "npm",
        "Left-Pad",
        "npm",
        "left-pad",
        0,
        "Prototype issue",
        "HIGH",
        JSON.stringify(["CVE-2026-1111"]),
        JSON.stringify(["1.3.1"]),
        "2026-11-26T00:00:00.000Z",
    );
    db.query("INSERT INTO osv_package_alias(advisory_id,cve_id) VALUES(?,?)").run(
        "GHSA-aaaa-bbbb-cccc",
        "CVE-2026-1111",
    );
    db.query("INSERT INTO epss_scores(cve_id,epss,percentile,score_date) VALUES(?,?,?,?)").run(
        "CVE-2026-1111",
        0.82,
        0.99,
        "2026-11-26",
    );
    db.query("INSERT INTO kev_annotation(cve_id,payload_json,catalog_sha256) VALUES(?,?,?)").run(
        "CVE-2026-1111",
        JSON.stringify({ cveID: "CVE-2026-1111" }),
        "a".repeat(64),
    );
    db.query(
        "INSERT INTO osv_package_advisory(id,ecosystem,package_name,ecosystem_lower,package_name_lower,is_malware,summary,severity,aliases_json,fixed_versions_json,modified_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    ).run(
        "MAL-2026-0001",
        "npm",
        "evil-pkg",
        "npm",
        "evil-pkg",
        1,
        "Malicious package",
        "CRITICAL",
        "[]",
        "[]",
        "2026-11-25T00:00:00.000Z",
    );
    db.query(
        "INSERT INTO runtime_eol(product,cycle,eol,lts,latest,release_date,support,updated_at) VALUES(?,?,?,?,?,?,?,?)",
    ).run("nodejs", "22", "2027-04-30", 1, "22.14.0", "2024-04-24", "2025-10-21", now);

    const checkRes = await handle(
        new Request("https://advisories.example/v1/packages/check?ecosystem=NPM&name=left-pad"),
        store,
        undefined,
        now,
    );
    expect(checkRes.status).toBe(200);
    const checkBody = (await checkRes.json()) as {
        malware: boolean;
        actively_exploited: boolean;
        advisories: { id: string; aliases: string[]; fixed_versions: string[]; in_kev: boolean; epss: number }[];
    };
    expect(checkBody.malware).toBe(false);
    expect(checkBody.actively_exploited).toBe(true);
    expect(checkBody.advisories[0]).toMatchObject({
        id: "GHSA-aaaa-bbbb-cccc",
        aliases: ["CVE-2026-1111"],
        fixed_versions: ["1.3.1"],
        in_kev: true,
        epss: 0.82,
    });

    // Test >30 packages to exercise chunked D1 parameter batching + deduplication + ranking.
    const packages = [
        { ecosystem: "npm", name: "left-pad" },
        { ecosystem: "npm", name: "left-pad" },
        ...Array.from({ length: 35 }, (_, i) => ({ ecosystem: "npm", name: `clean-${i}` })),
        { ecosystem: "npm", name: "evil-pkg" },
    ];
    const auditRes = await handle(
        new Request("https://advisories.example/v1/packages/audit", {
            method: "POST",
            body: JSON.stringify({ packages }),
        }),
        store,
        undefined,
        now,
    );
    expect(auditRes.status).toBe(200);
    const auditBody = (await auditRes.json()) as {
        queried: number;
        malware_count: number;
        kev_count: number;
        findings: { id: string; is_malware: boolean; in_kev: boolean }[];
    };
    expect(auditBody.queried).toBe(37);
    expect(auditBody.malware_count).toBe(1);
    expect(auditBody.kev_count).toBe(1);
    expect(auditBody.findings.map((f) => f.id)).toEqual(["MAL-2026-0001", "GHSA-aaaa-bbbb-cccc"]);

    const eolRes = await handle(
        new Request("https://advisories.example/v1/eol/nodejs"),
        store,
        undefined,
        now,
    );
    expect(eolRes.status).toBe(200);
    const eolBody = (await eolRes.json()) as { product: string; cycles: { cycle: string }[] };
    expect(eolBody.product).toBe("nodejs");
    expect(eolBody.cycles.map((c) => c.cycle)).toEqual(["22"]);
});

test("d1ReadSql and d1WriteSql select appropriate D1 read-replication sessions", () => {
    const constraints: (string | undefined)[] = [];
    const fakeExecutor = {
        prepare: () => ({ bind: () => ({ first: async () => null, all: async () => ({ results: [] }) }) }),
        batch: async () => [],
    } as unknown as Pick<D1Database, "prepare" | "batch">;
    const fakeDb = {
        ...fakeExecutor,
        withSession: (constraint?: string) => {
            constraints.push(constraint);
            return fakeExecutor;
        },
    };
    d1ReadSql(fakeDb);
    d1WriteSql(fakeDb);
    expect(constraints).toEqual(["first-unconstrained", "first-primary"]);
});

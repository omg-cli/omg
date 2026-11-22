import { expect, test } from "bun:test";
import { admit } from "../admission";
import { STAGE_MODE } from "../stage-identity";

const account = "f1e95b3e1b502cf366dfc81a863695fa";
const worker = "omg-advisories-stage-20261121-1d6c61c4";
const d1 = "11111111-1111-4111-a111-111111111111";
const oldD1 = "98202f8c-7d5f-4de9-8ddd-cea35fd95d09";
const unknownD1 = "22222222-2222-4222-a222-222222222222";
const r2 = `${worker}-raw`, oldR2 = "omg-advisories-raw";
const draft = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
const stub = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";
const prod = "cccccccc-cccc-4ccc-accc-cccccccccccc";
const vars = { STAGE_MODE, STAGE_ENABLE_CRON: "false", STAGE_ACCESS_AUD: "a".repeat(64), STAGE_DATABASE_INSTANCE_ID: "b".repeat(32) };
const approved = { account_id: account, worker, d1_id: d1, r2_bucket: r2, r2_jurisdiction: "default" };
const config = {
    account_id: account, name: worker, main: "stage.ts", workers_dev: false, preview_urls: false, vars,
    d1_databases: [{ binding: "DB", database_id: d1, database_name: worker }],
    r2_buckets: [{ binding: "RAW", bucket_name: r2 }],
};
const paths = {
    stage: `workers/scripts/${worker}`,
    prod: "workers/scripts/omg-advisories",
};

function stores(db: string, raw: string) {
    return [{ type: "d1", name: "DB", id: db }, { type: "r2_bucket", name: "RAW", bucket_name: raw }];
}

function fixture() {
    const actual = [...stores(d1, r2), ...Object.entries(vars).map(([name, text]) => ({ type: "plain_text", name, text }))];
    const data = new Map<string, unknown>([
        [`${paths.stage}/subdomain`, { enabled: false, previews_enabled: false }],
        [`${paths.stage}/deployments`, { deployments: [{ versions: [{ version_id: stub, percentage: 100 }] }] }],
        [`${paths.prod}/deployments`, { deployments: [{ versions: [{ version_id: prod, percentage: 100 }] }] }],
        [`${paths.stage}/versions/${draft}`, { id: draft, resources: { bindings: actual } }],
        [`${paths.stage}/versions/${stub}`, { id: stub, resources: { bindings: [{ name: "STAGE_MODE", type: "plain_text", text: "disabled" }] } }],
        [`${paths.prod}/versions/${prod}`, { id: prod, resources: { bindings: stores(oldD1, oldR2) } }],
        [`d1/database/${d1}`, { uuid: d1, name: worker }],
        [`r2/buckets/${r2}`, { jurisdiction: "default", name: r2, storage_class: "Standard" }],
    ]);
    const calls: string[] = [];
    const fetcher = async (url: string, init: RequestInit) => {
        const prefix = `https://api.cloudflare.com/client/v4/accounts/${account}/`;
        expect(url.startsWith(prefix)).toBe(true);
        expect(init.redirect).toBe("error");
        expect(init.method ?? "GET").toBe("GET");
        const path = url.slice(prefix.length);
        calls.push(path);
        return data.has(path) ? Response.json({ success: true, result: data.get(path) }) : new Response(null, { status: 404 });
    };
    return { data, fetcher, actual, calls };
}

test("admission verifies the approved intended and off-traffic effective bindings", async () => {
    const f = fixture();
    expect(await admit(approved, config, draft, "fixture-read-only", f.fetcher)).toEqual({
        phase: "admitted_off_traffic", version: draft, stage_d1_id: d1, stage_r2_bucket: r2, incumbent_version: prod,
    });
    expect(f.calls).toHaveLength(8);
});

test("unapproved or wrong intended stores are refused before querying Cloudflare", async () => {
    const f = fixture();
    for (const [manifest, intended] of [
        [{ ...approved, d1_id: oldD1 }, config], [{ ...approved, r2_bucket: oldR2 }, config],
        [approved, { ...config, d1_databases: [{ ...config.d1_databases[0], database_id: unknownD1 }] }],
        [approved, { ...config, workers_dev: true }], [approved, { ...config, routes: [] }],
    ] as const) await expect(admit(manifest, intended, draft, "fixture-read-only", f.fetcher)).rejects.toThrow();
    expect(f.calls).toHaveLength(0);
});

test("admission rejects wrong, missing, duplicate, live incumbent, and already-routed bindings", async () => {
    for (const [db, raw] of [[unknownD1, r2], [oldD1, r2], [d1, oldR2]]) {
        const f = fixture();
        f.actual.splice(0, 2, ...stores(db ?? "", raw ?? ""));
        await expect(admit(approved, config, draft, "fixture-read-only", f.fetcher)).rejects.toThrow("effective");
    }
    for (const [path, value] of [
        [`${paths.stage}/subdomain`, { enabled: false, previews_enabled: true }],
        [`${paths.stage}/subdomain`, { enabled: true, previews_enabled: false }],
        [`${paths.stage}/deployments`, { deployments: [{ versions: [{ version_id: draft, percentage: 100 }] }] }],
        [`${paths.stage}/versions/${stub}`, { id: stub, resources: { bindings: stores(d1, r2) } }],
        [`${paths.prod}/versions/${prod}`, { id: prod, resources: { bindings: stores(d1, r2) } }],
        [`r2/buckets/${r2}`, { name: r2, jurisdiction: "eu", storage_class: "Standard" }],
        [`d1/database/${d1}`, { uuid: unknownD1, name: worker }],
    ] as const) {
        const f = fixture();
        f.data.set(path, value);
        await expect(admit(approved, config, draft, "fixture-read-only", f.fetcher)).rejects.toThrow();
    }
    const duplicate = fixture();
    duplicate.actual.push(...stores(d1, r2));
    await expect(admit(approved, config, draft, "fixture-read-only", duplicate.fetcher)).rejects.toThrow();
    const absent = fixture();
    absent.data.delete(`${paths.stage}/versions/${draft}`);
    await expect(admit(approved, config, draft, "fixture-read-only", absent.fetcher)).rejects.toThrow();
});

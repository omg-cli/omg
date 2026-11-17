import { expect, test } from "bun:test";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { unstable_splitSqlQuery } from "wrangler";
import { object, sha256 } from "../src/domain";
import { gitBlobSha1 } from "../src/baseline";

const token="controlled-packed-baseline-token-at-least-32";
const payload=(id:string,title:string,modified="2026-11-12T00:00:00.000Z")=>JSON.stringify({dataType:"CVE_RECORD",dataVersion:"5.2",cveMetadata:{cveId:id,state:"PUBLISHED",dateUpdated:modified,datePublished:"2026-11-11T00:00:00.000Z"},containers:{cna:{title}}});

test("actual baseline ingest packs large exact originals once while ordinary newer revisions remain individual",async()=>{
    const build=await Bun.build({entrypoints:[fileURLToPath(new NodeURL("../src/index.ts",import.meta.url))],target:"browser"});
    expect(build.success).toBe(true);
    const bundle=build.outputs[0];if(!bundle)throw new Error("missing packed writer Worker bundle");
    const runtime=new Miniflare(convertV4MiniflareOptions({modules:true,script:await bundle.text(),compatibilityDate:"2026-11-13",d1Databases:["DB"],r2Buckets:["RAW"],bindings:{CVE_BATCH_SIZE:"32",INGEST_TOKEN:token}}));
    try {
        const db=await runtime.getD1Database("DB"),raw=await runtime.getR2Bucket("RAW");
        const directory=new NodeURL("../migrations/",import.meta.url);
        for(const name of (await readdir(directory)).filter(name=>name.endsWith(".sql")).sort())
            await db.batch(unstable_splitSqlQuery(await readFile(new NodeURL(name,directory),"utf8")).map(query=>db.prepare(query)));
        const worker=await runtime.getWorker();
        const post=(path:string,body:unknown)=>worker.fetch(`https://advisories.example${path}`,{method:"POST",headers:{authorization:`Bearer ${token}`,"content-type":"application/json"},body:JSON.stringify(body)});
        const start=await post("/internal/baseline/start",{digest:"b".repeat(64),baseline_at:"2026-11-13T00:00:00.000Z"});
        expect(start.status).toBe(200);const baseline=object(await start.json());
        const first=payload("CVE-2026-6100","x".repeat(2_600_000)),second=payload("CVE-2026-6101","original café ☕");
        const imported=await post("/internal/ingest",{source:"cve",records:[first,second],baseline});
        expect(imported.status).toBe(200);
        const objects=await raw.list({prefix:"cve-pack-v1/"});
        expect(objects.objects).toHaveLength(1);
        expect((await raw.list({prefix:"cve/"})).objects).toHaveLength(0);
        for(const [id,expected] of new Map([["CVE-2026-6100",first],["CVE-2026-6101",second]])){
            const response=await worker.fetch(`https://advisories.example/v1/cves/${id}`);
            expect(response.status).toBe(200);expect(object(await response.json()).payload_json).toBe(expected);
            const ledger=await db.prepare("SELECT payload_sha256,git_blob_sha1 FROM baseline_import_blob WHERE cve_id=?").bind(id).first<{payload_sha256:string;git_blob_sha1:string}>();
            expect(ledger).toEqual({payload_sha256:await sha256(expected),git_blob_sha1:await gitBlobSha1(expected)});
        }
        const replay=await post("/internal/ingest",{source:"cve",records:[first,second],baseline});
        expect(replay.status).toBe(200);expect((await raw.list({prefix:"cve-pack-v1/"})).objects).toHaveLength(1);
        const newer=payload("CVE-2026-6101","newer ordinary delta","2026-11-13T00:00:00.000Z");
        expect((await post("/internal/ingest",{source:"cve",records:[newer]})).status).toBe(200);
        expect((await raw.list({prefix:"cve/"})).objects).toHaveLength(1);
        expect(object(await (await worker.fetch("https://advisories.example/v1/cves/CVE-2026-6101")).json()).payload_json).toBe(newer);
        expect(await db.prepare("SELECT payload_sha256,git_blob_sha1 FROM baseline_import_blob WHERE cve_id=?").bind("CVE-2026-6101").first<{payload_sha256:string;git_blob_sha1:string}>())
            .toEqual({payload_sha256:await sha256(second),git_blob_sha1:await gitBlobSha1(second)});
    }finally{await runtime.dispose();}
});

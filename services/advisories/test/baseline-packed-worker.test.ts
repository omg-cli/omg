import { expect, test } from "bun:test";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { unstable_splitSqlQuery } from "wrangler";
import { Store, d1Sql } from "../src/storage";
import { object, sha256 } from "../src/domain";

const payload=(id:string,title:string)=>JSON.stringify({dataType:"CVE_RECORD",dataVersion:"5.2",
    cveMetadata:{cveId:id,state:"PUBLISHED",dateUpdated:"2026-11-12T00:00:00.000Z",datePublished:"2026-11-11T00:00:00.000Z"},
    containers:{cna:{title}}});

test("actual Worker reads original UTF8 packed ranges and legacy CVEs, refusing altered packed bytes",async()=>{
    const build=await Bun.build({entrypoints:[fileURLToPath(new NodeURL("../src/index.ts",import.meta.url))],target:"browser"});
    expect(build.success).toBe(true);
    const bundle=build.outputs[0];if(!bundle)throw new Error("missing controlled Worker bundle");
    const runtime=new Miniflare(convertV4MiniflareOptions({modules:true,script:await bundle.text(),compatibilityDate:"2026-11-13",d1Databases:["DB"],r2Buckets:["RAW"],bindings:{CVE_BATCH_SIZE:"32"}}));
    try {
        const db=await runtime.getD1Database("DB"),raw=await runtime.getR2Bucket("RAW");
        const directory=new NodeURL("../migrations/",import.meta.url);
        for(const name of (await readdir(directory)).filter(name=>name.endsWith(".sql")).sort()){
            const source=await readFile(new NodeURL(name,directory),"utf8");
            await db.batch(unstable_splitSqlQuery(source).map(query=>db.prepare(query)));
        }
        const store=new Store(d1Sql(db),raw),now=new Date().toISOString();
        const first=payload("CVE-2026-6000","café ☕"),second=payload("CVE-2026-6001","second original record"),legacy=payload("CVE-2026-6002","legacy individual object");
        for(const value of [first,second,legacy])await store.cve(value,now);
        const packed=first+second,key=`cve-pack-v1/${await sha256(packed)}.raw`;
        await raw.put(key,packed);
        const firstLength=new TextEncoder().encode(first).length,secondLength=new TextEncoder().encode(second).length;
        await db.batch([
            db.prepare("UPDATE source_record SET object_key=? WHERE id=?").bind(`${key}#0:${firstLength}:${await sha256(first)}`,"CVE-2026-6000"),
            db.prepare("UPDATE source_record SET object_key=? WHERE id=?").bind(`${key}#${firstLength}:${secondLength}:${await sha256(second)}`,"CVE-2026-6001"),
        ]);
        const worker=await runtime.getWorker();
        for(const [id,expected] of new Map([["CVE-2026-6000",first],["CVE-2026-6001",second],["CVE-2026-6002",legacy]])){
            const response=await worker.fetch(`https://advisories.example/v1/cves/${id}`);
            expect(response.status).toBe(200);
            const body=object(await response.json());
            expect(body.payload_json).toBe(expected);
            expect(object(body.provenance).payload_sha256).toBe(await sha256(expected));
        }
        await db.prepare("UPDATE source_record SET object_key=? WHERE id=?")
            .bind(`${key}#${firstLength}:${secondLength}:${await sha256(second)}`,"CVE-2026-6000").run();
        expect((await worker.fetch("https://advisories.example/v1/cves/CVE-2026-6000")).status).toBe(503);
        await db.prepare("UPDATE source_record SET object_key=? WHERE id=?")
            .bind(`${key}#0:${firstLength}:${await sha256(first)}`,"CVE-2026-6000").run();
        await raw.put(key,packed.replace("☕","☀"));
        expect((await worker.fetch("https://advisories.example/v1/cves/CVE-2026-6000")).status).toBe(503);
        expect((await worker.fetch("https://advisories.example/v1/cves/CVE-2026-6002")).status).toBe(200);
    }finally{await runtime.dispose();}
});

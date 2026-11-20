import { expect, spyOn, test } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { Store, type Command, type Sql } from "../src/storage";

const now="2026-11-13T02:00:00.000Z";
const row=(id:string,modified=now,title="first",schema="5.2")=>({id,raw:JSON.stringify({dataType:"CVE_RECORD",dataVersion:schema,cveMetadata:{cveId:id,state:"PUBLISHED",dateUpdated:modified,datePublished:now},containers:{cna:{title}}})});
function fixture() {
    const db=new Database(":memory:");
    const directory=fileURLToPath(new NodeURL("../migrations/",import.meta.url));
    for(const name of readdirSync(directory).filter(v=>v.endsWith(".sql")).sort()) db.exec(readFileSync(new NodeURL(name,new NodeURL("../migrations/",import.meta.url)),"utf8"));
    let clock=now,firsts=0,alls=0,batches=0,maxBinds=0;
    let put=async (_key:string,_raw:string)=>{};
    const sql:Sql={
        first:async<T>(text:string,values:(string|number|null)[]=[])=>{firsts++;return db.query<T,(string|number|null)[]>(text).get(...values);},
        all:async<T>(text:string,values:(string|number|null)[]=[])=>{alls++;maxBinds=Math.max(maxBinds,values.length);return db.query<T,(string|number|null)[]>(text).all(...values);},
        batch:async(commands:Command[])=>{batches++;db.transaction(()=>{for(const command of commands){maxBinds=Math.max(maxBinds,command.values.length);db.query(command.sql).run(...command.values);}})();},
    };
    const store=new Store(sql,{put:async(key,raw)=>put(key,raw),get:async()=>null},()=>clock);
    return {db,store,writer:store.writer("cve","owner"),clock:(value:string)=>{clock=value;},put:(value:typeof put)=>{put=value;},reset:()=>{firsts=alls=batches=maxBinds=0;},counts:()=>({firsts,alls,batches,maxBinds})};
}

test("64 distinct supported baseline records use one read and one fenced metadata batch",async()=>{
    const f=fixture();try{
        await f.store.lease("cve","owner",now);f.reset();let active=0,peak=0;
        f.put(async()=>{active++;peak=Math.max(peak,active);await Bun.sleep(1);active--;});
        await f.writer.cveBatch(Array.from({length:64},(_,i)=>row(`CVE-2026-${1000+i}`)),now);
        expect(f.counts()).toEqual({firsts:0,alls:1,batches:1,maxBinds:64});
        expect(peak).toBe(6);expect(active).toBe(0);
        expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:64});
        expect(f.db.query("SELECT count(*) n FROM cve").get()).toEqual({n:64});
    }finally{f.db.close();}
});

test("bulk prevalidation preserves newer records and rejects every equal-date conflict before R2 writes",async()=>{
    const f=fixture();try{
        await f.store.lease("cve","owner",now);
        await f.writer.cve(row("CVE-2026-1001","2026-11-14T00:00:00.000Z").raw,now);
        await f.writer.cve(row("CVE-2026-1002").raw,now);
        f.reset();let writes=0;f.put(async()=>{writes++;});
        await expect(f.writer.cveBatch([row("CVE-2026-1000"),row("CVE-2026-1002",now,"conflict")],now)).rejects.toThrow("conflicting equal");
        expect(writes).toBe(0);expect(f.counts().batches).toBe(0);
        await f.writer.cveBatch([row("CVE-2026-1001"),row("CVE-2026-1002")],now);
        expect(writes).toBe(0);
        expect(f.db.query("SELECT modified_at FROM source_record WHERE id='CVE-2026-1001'").get()).toEqual({modified_at:"2026-11-14T00:00:00.000Z"});
    }finally{f.db.close();}
});

test("bulk R2 failure settles all started writes before rejecting without metadata or after commands",async()=>{
    const f=fixture();try{
        await f.store.lease("cve","owner",now);f.reset();let active=0,settled=0,started=0;
        f.put(async()=>{started++;active++;try{if(started===2)throw new Error("R2 unavailable");await Bun.sleep(15);}finally{active--;settled++;}});
        await expect(f.writer.cveBatch(Array.from({length:8},(_,i)=>row(`CVE-2026-${1000+i}`)),now,[{sql:"UPDATE source_checkpoint SET complete=1 WHERE source='cve'",values:[]}])).rejects.toThrow("R2 unavailable");
        expect(started).toBe(6);expect(settled).toBe(6);expect(active).toBe(0);expect(f.counts().batches).toBe(0);
        expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:0});
    }finally{f.db.close();}
});

test("expired writer fences and failing metadata keep source pointers and attached membership atomic",async()=>{
    for(const fault of ["expired","metadata"]) {
        const f=fixture();try{
            await f.store.lease("cve","owner",now);
            f.put(async()=>{if(fault==="expired")f.clock("2026-11-13T02:11:00.000Z");});
            const after=[{sql:"UPDATE source_checkpoint SET complete=1 WHERE source='cve'",values:[]}];
            if(fault==="metadata")after.push({sql:"INSERT INTO table_that_does_not_exist VALUES(1)",values:[]});
            await expect(f.writer.cveBatch([row("CVE-2026-1000")],now,after)).rejects.toThrow();
            expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:0});
            expect(f.db.query("SELECT count(*) n FROM cve").get()).toEqual({n:0});
            expect(f.db.query("SELECT complete FROM source_checkpoint WHERE source='cve'").get()).toEqual({complete:0});
        }finally{f.db.close();}
    }
});


test("bulk R2 phase waits for old-row reads and finishes before fenced metadata commit", async () => {
    const f=fixture();
    try {
        await f.store.lease("cve","owner",now);
        let readFinished=false, active=0, peak=0, puts=0;
        const original=f.store.sql;
        const sql:Sql={...original,
            all:async<T>(text:string,values:(string|number|null)[]=[])=>{
                await Bun.sleep(5);
                const rows=await original.all<T>(text,values);readFinished=true;return rows;
            },
            batch:async(commands:Command[])=>{
                expect(readFinished).toBe(true);expect(active).toBe(0);expect(puts).toBe(19);
                await original.batch(commands);
            },
        };
        const store=new Store(sql,{get:async()=>null,put:async()=>{
            expect(readFinished).toBe(true);active++;peak=Math.max(peak,active);
            expect(active).toBeLessThanOrEqual(6);
            try {await Bun.sleep(1);puts++;}finally{active--;}
        }},()=>now);
        await store.writer("cve","owner").cveBatch(Array.from({length:19},(_,i)=>row(`CVE-2026-${2000+i}`)),now);
        expect(peak).toBe(6);expect(puts).toBe(19);expect(active).toBe(0);
    }finally{f.db.close();}
});

test("a slow baseline put does not idle completed R2 slots or commit metadata early", async () => {
    const f=fixture();
    const slow=Promise.withResolvers<void>(), seventh=Promise.withResolvers<void>();
    let work:Promise<void>|undefined;
    try {
        await f.store.lease("cve","owner",now);f.reset();
        let active=0,peak=0,started=0,settled=0;
        f.put(async()=>{
            const position=++started;
            active++;peak=Math.max(peak,active);
            try {
                if(position===1)await slow.promise;
                else {if(position===7)seventh.resolve();await Bun.sleep(1);}
            }finally{active--;settled++;}
        });
        work=f.writer.cveBatch(Array.from({length:19},(_,i)=>row(`CVE-2026-${3000+i}`)),now);
        const seventhBeforeSlow=await Promise.race([seventh.promise.then(()=>true),Bun.sleep(100).then(()=>false)]);
        const beforeRelease={active,batches:f.counts().batches};
        slow.resolve();await work;
        expect(seventhBeforeSlow).toBe(true);
        expect(beforeRelease.active).toBeGreaterThanOrEqual(1);
        expect(beforeRelease.batches).toBe(0);
        expect(peak).toBe(6);expect(active).toBe(0);expect(settled).toBe(19);
        expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:19});
    }finally{slow.resolve();await work;f.db.close();}
});

test("a refilled R2 slot failure drains its slow peer and starts no further writes", async () => {
    const f=fixture(),slow=Promise.withResolvers<void>(),failed=Promise.withResolvers<void>();
    let work:Promise<unknown>|undefined;
    try {
        await f.store.lease("cve","owner",now);f.reset();
        let active=0,started=0,settled=0;
        f.put(async()=>{
            const position=++started;active++;
            try {
                if(position===1)await slow.promise;
                else if(position===7){failed.resolve();throw new Error("refilled slot failed");}
                else await Bun.sleep(5);
            }finally{active--;settled++;}
        });
        work=f.writer.cveBatch(Array.from({length:19},(_,i)=>row(`CVE-2026-${4000+i}`)),now)
            .then(()=>{throw new Error("failed R2 transaction unexpectedly committed");},error=>error);
        await failed.promise;
        await Bun.sleep(10);
        const observed={started,active,batches:f.counts().batches};
        slow.resolve();
        expect(await work).toBeInstanceOf(Error);
        expect(String(await work)).toContain("refilled slot failed");
        expect(observed).toEqual({started:7,active:1,batches:0});
        expect(started).toBe(7);expect(active).toBe(0);expect(settled).toBe(7);
        expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:0});
    }finally{slow.resolve();await work;f.db.close();}
});

test("baseline phase diagnostics contain only fixed counts and finite durations", async () => {
    const f=fixture(),log=spyOn(console,"info").mockImplementation(()=>{});
    try {
        await f.store.lease("cve","owner",now);
        await f.writer.cveBatch([row("CVE-2026-5000")],now);
        expect(log).toHaveBeenCalledTimes(1);
        const metric:unknown=JSON.parse(String(log.mock.calls[0]?.[0]));
        expect(metric).toEqual({event:"baseline_write_phases",records:1,changed:1,
            prepare_ms:expect.any(Number),read_ms:expect.any(Number),raw_ms:expect.any(Number),metadata_ms:expect.any(Number)});
        if(!metric || typeof metric!=="object")throw new Error("missing structured baseline metric");
        for(const [name,value] of Object.entries(metric)){
            if(name.endsWith("_ms")){expect(Number.isFinite(value)).toBe(true);expect(value).toBeGreaterThanOrEqual(0);}
        }
        expect(JSON.stringify(metric)).not.toContain("CVE-");
    }finally{log.mockRestore();f.db.close();}
});

test("packed baseline writes keep originals and metadata atomic through R2 and fenced SQL failures",async()=>{
    for(const fault of ["raw","expired","metadata","conflict"]){
        const f=fixture();
        try {
            await f.store.lease("cve","owner",now);
            if(fault==="conflict")await f.writer.cve(row("CVE-2026-7000").raw,now);
            f.reset();let writes=0;
            f.put(async()=>{
                writes++;
                if(fault==="raw")throw new Error("packed R2 unavailable");
                if(fault==="expired")f.clock("2026-11-13T02:11:00.000Z");
            });
            const after=[{sql:"UPDATE source_checkpoint SET complete=1 WHERE source='cve'",values:[]}];
            if(fault==="metadata")after.push({sql:"INSERT INTO missing_packed_metadata_table VALUES(1)",values:[]});
            await expect(f.writer.cveBatch([row("CVE-2026-7000",now,"replacement"),row("CVE-2026-7001")],now,after,"packed")).rejects.toThrow();
            expect(writes).toBe(fault==="conflict"?0:1);
            expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:fault==="conflict"?1:0});
            expect(f.db.query("SELECT count(*) n FROM cve").get()).toEqual({n:fault==="conflict"?1:0});
            expect(f.db.query("SELECT complete FROM source_checkpoint WHERE source='cve'").get()).toEqual({complete:0});
        }finally{f.db.close();}
    }
});

test("64 packed originals make one immutable put and exact per-CVE pointers with no replay writes",async()=>{
    const f=fixture();try{
        await f.store.lease("cve","owner",now);f.reset();
        const writes=new Map<string,string>();
        f.put(async(key,raw)=>{writes.set(key,raw);});
        const records=Array.from({length:64},(_,index)=>row(`CVE-2026-${8000+index}`));
        await f.writer.cveBatch(records,now,[],"packed");
        expect(writes.size).toBe(1);
        const [key]=writes.keys();expect(key).toMatch(/^cve-pack-v1\/[a-f0-9]{64}\.raw$/);
        expect(key && writes.get(key)).toBe(records.map(record=>record.raw).join(""));
        const rows=f.db.query<{object_key:string;payload_sha256:string},[]>("SELECT object_key,payload_sha256 FROM source_record ORDER BY id").all();
        expect(rows).toHaveLength(64);
        for(const row of rows){expect(row.object_key.startsWith(`${key}#`)).toBe(true);expect(row.object_key.endsWith(`:${row.payload_sha256}`)).toBe(true);}
        f.put(async()=>{throw new Error("unchanged packed replay attempted raw write");});
        await f.writer.cveBatch(records,now,[],"packed");
        expect(f.db.query("SELECT count(*) n FROM source_record").get()).toEqual({n:64});
    }finally{f.db.close();}
});

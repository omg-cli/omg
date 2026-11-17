import { expect, test } from "bun:test";
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

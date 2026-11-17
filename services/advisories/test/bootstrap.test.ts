import { expect, test } from "bun:test";
import { operatorPost, recoverCheckpoint, readCheckpoint, verifyIngestReply, proofProgress, type OperatorFetcher } from "../scripts/operator";

const binding = { digest:"a".repeat(64), endpoint:"https://advisories.example", instance_id:"1".repeat(32), session_id:"afb732ac-68e4-4549-98ec-e89224449b75" };
test("lost state recovery replays from zero with exact supplied session and archive bindings", () => {
    const recovered = recoverCheckpoint(binding);
    expect(recovered).toEqual({ digest:binding.digest, next_entry:0, accepted:0, exhausted:false, finished_at:null, baseline:binding });
    expect(() => readCheckpoint({...recovered, baseline:{...binding, endpoint:"https://other.example"}}, binding)).toThrow("binding");
    expect(() => readCheckpoint({...recovered, accepted:132600}, binding)).toThrow("position");
    expect(() => readCheckpoint({...recovered, exhausted:true}, binding)).toThrow();
});

test("idempotent operator transport retries connection loss and rate limits with byte-identical bodies", async () => {
    const bodies:string[] = [], waits:number[] = [];
    const fetcher:OperatorFetcher = async (_input, init) => {
        bodies.push(String(init?.body));
        if (bodies.length===1) throw new TypeError("connection interrupted after commit");
        if (bodies.length===2) return new Response("busy",{status:429, headers:{"retry-after":"2"}});
        return Response.json({accepted:1});
    };
    const reply = await operatorPost({endpoint:new URL(binding.endpoint),token:"operator-fixture-token-at-least-32-characters",path:"/internal/ingest",body:'{"records":["exact bytes"]}',fetcher,sleep:async ms => { waits.push(ms); }});
    expect(reply).toEqual({accepted:1});
    expect(new Set(bodies).size).toBe(1);
    expect(waits).toEqual([1000,2000]);
});

test("operator retry budget stops permanent failures and never echoes credentials", async () => {
    let calls=0;
    const token="operator-fixture-token-at-least-32-characters";
    const operation=operatorPost({endpoint:new URL(binding.endpoint),token,path:"/internal/ingest",body:"{}",fetcher:async()=>{calls++;throw new Error(token);},sleep:async()=>{}});
    await expect(operation).rejects.toThrow("progress retained");
    try { await operation; } catch(error) { expect(String(error)).not.toContain(token); }
    expect(calls).toBe(5);
    calls=0;
    await expect(operatorPost({endpoint:new URL(binding.endpoint),token,path:"/internal/ingest",body:"{}",fetcher:async()=>{calls++;return new Response("denied",{status:401});},sleep:async()=>{}})).rejects.toThrow("401");
    expect(calls).toBe(1);
});

test("successful HTTP without the exact accepted count cannot advance an archive checkpoint", () => {
    expect(()=>verifyIngestReply({accepted:7},8)).toThrow("accepted count");
    expect(()=>verifyIngestReply({accepted:"8"},8)).toThrow("accepted count");
    expect(verifyIngestReply({accepted:8},8)).toBeUndefined();
});

test("a response-body connection failure retries the same idempotent request", async () => {
    let calls=0;
    const reply=await operatorPost({endpoint:new URL(binding.endpoint),token:"operator-fixture-token-at-least-32-characters",path:"/internal/ingest",body:"{}",sleep:async()=>{},fetcher:async()=>{
        calls++;
        return calls===1 ? new Response(new ReadableStream({start(controller){controller.error(new Error("body disconnected"));}})) : Response.json({accepted:8});
    }});
    expect(reply.accepted).toBe(8);
    expect(calls).toBe(2);
});

test("operator progress never treats partial membership or an assertion as archive certification",()=>{
    const expected={digest:binding.digest,release_tag:"cve_2026-11-13_0000Z",asset:"2026-11-13_all_CVEs_at_midnight.zip.zip"};
    const partial={...expected,commit_sha:"1".repeat(40),schema_version:1,phase:"awaiting_import",expected_count:424926,verified_count:132600,pending_trees:0,archive_verified:false};
    expect(proofProgress(partial,expected).archive_verified).toBe(false);
    expect(()=>proofProgress({...partial,digest:"b".repeat(64)},expected)).toThrow("binding");
    expect(()=>proofProgress({...partial,archive_verified:true},expected)).toThrow("certification");
    expect(()=>proofProgress({...partial,phase:["awaiting_import"]},expected)).toThrow("progress");
    expect(()=>proofProgress({...partial,phase:"verified",archive_verified:true},expected)).toThrow("certification");
    expect(()=>proofProgress({...partial,phase:"verified",archive_verified:true,verified_count:424926,pending_trees:1},expected)).toThrow("certification");
    expect(proofProgress({...partial,phase:"verified",archive_verified:true,verified_count:424926},expected).archive_verified).toBe(true);
});

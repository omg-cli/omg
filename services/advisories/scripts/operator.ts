import { boundedBody, date, object } from "../src/domain";
import type { ArchiveState } from "./archive";
export type BaselineBinding = { digest:string; endpoint:string; instance_id:string; session_id:string };
export type Checkpoint = ArchiveState & { baseline:BaselineBinding };
export type OperatorFetcher = (input:Parameters<typeof fetch>[0],init?:Parameters<typeof fetch>[1])=>ReturnType<typeof fetch>;
export function baselineBinding(value:unknown, digest:string, endpoint:string):BaselineBinding {
    const input=object(value);
    if(input.digest!==digest || input.endpoint!==endpoint || !/^[a-f0-9]{64}$/.test(digest)
        || typeof input.instance_id!=="string" || !/^[a-f0-9]{32}$/.test(input.instance_id)
        || typeof input.session_id!=="string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(input.session_id)) throw new Error("invalid baseline binding");
    const url=new URL(endpoint);
    if(url.protocol!=="https:" || url.origin!==endpoint) throw new Error("invalid baseline endpoint binding");
    return {digest,endpoint,instance_id:input.instance_id,session_id:input.session_id};
}
export function recoverCheckpoint(binding:BaselineBinding):Checkpoint {
    const checked=baselineBinding(binding,binding.digest,binding.endpoint);
    return {digest:checked.digest,next_entry:0,accepted:0,exhausted:false,finished_at:null,baseline:checked};
}
export function readCheckpoint(value:unknown, binding:BaselineBinding):Checkpoint {
    const saved=object(value), baseline=object(saved.baseline);
    if (saved.digest!==binding.digest || baseline.digest!==binding.digest || baseline.endpoint!==binding.endpoint || baseline.instance_id!==binding.instance_id || baseline.session_id!==binding.session_id)
        throw new Error("invalid resume binding");
    if (!Number.isSafeInteger(saved.next_entry) || !Number.isSafeInteger(saved.accepted)
        || Number(saved.next_entry)<0 || Number(saved.next_entry)>1_000_000 || Number(saved.accepted)<0 || Number(saved.accepted)>Number(saved.next_entry)
        || typeof saved.exhausted!=="boolean" || !(saved.finished_at===null || typeof saved.finished_at==="string")
        || (saved.exhausted && (Number(saved.accepted)===0 || saved.finished_at===null)) || (!saved.exhausted && saved.finished_at!==null)) throw new Error("invalid resume position");
    return {digest:binding.digest,next_entry:Number(saved.next_entry),accepted:Number(saved.accepted),exhausted:saved.exhausted,finished_at:saved.finished_at===null?null:date(saved.finished_at),baseline:baselineBinding(baseline,binding.digest,binding.endpoint)};
}
export async function operatorPost(options:{endpoint:URL;token:string;path:string;body:string;fetcher?:OperatorFetcher;sleep?:(ms:number)=>Promise<void>}) {
    const fetcher=options.fetcher??fetch, sleep=options.sleep??Bun.sleep;
    for(let attempt=0;attempt<5;attempt++) {
        let reply:Response;
        try {
            reply=await fetcher(new URL(options.path,options.endpoint),{method:"POST",redirect:"error",signal:AbortSignal.timeout(60_000),headers:{authorization:`Bearer ${options.token}`,"content-type":"application/json"},body:options.body});
        } catch {
            if(attempt===4) throw new Error("ingest transport failed after bounded retries; progress retained");
            await sleep(Math.min(30_000,1000*2**attempt));
            continue;
        }
        if(reply.ok) {
            let raw:string;
            try { raw=await boundedBody(reply.body,16*1024); }
            catch {
                if(attempt===4) throw new Error("ingest response transport failed after bounded retries; progress retained");
                await sleep(Math.min(30_000,1000*2**attempt));
                continue;
            }
            try { return object(JSON.parse(raw)); }
            catch { throw new Error("invalid bounded ingest response; progress retained"); }
        }
        const retryAfter=reply.headers.get("retry-after");
        await reply.body?.cancel();
        if(![409,429,500,502,503,504].includes(reply.status)||attempt===4) throw new Error(`ingest HTTP ${reply.status}; progress retained`);
        const seconds=retryAfter!==null && /^\d+$/.test(retryAfter)?Number(retryAfter):NaN;
        const requested=Number.isFinite(seconds)?seconds*1000:retryAfter===null?NaN:Date.parse(retryAfter)-Date.now();
        await sleep(Math.min(30_000,Math.max(1000*2**attempt,Number.isFinite(requested)?requested:0)));
    }
    throw new Error("operator request failed; progress retained");
}
export function verifyIngestReply(value:unknown,expected:number):void {
    if(object(value).accepted!==expected) throw new Error("ingest accepted count mismatch; progress retained");
}

export function proofProgress(value:unknown, expected:{digest:string;release_tag:string;asset:string}) {
    const reply=object(value);
    if(reply.digest!==expected.digest || reply.release_tag!==expected.release_tag || reply.asset!==expected.asset
        || typeof reply.commit_sha!=="string" || !/^[a-f0-9]{40}$/.test(reply.commit_sha)) throw new Error("baseline proof publisher binding mismatch");
    const phase=reply.phase;
    if(reply.schema_version!==1 || (phase!=="traversing" && phase!=="reconciling" && phase!=="awaiting_import" && phase!=="awaiting_catchup" && phase!=="verified")
        || !Number.isSafeInteger(reply.expected_count) || Number(reply.expected_count)<0 || Number(reply.expected_count)>1_000_000
        || !Number.isSafeInteger(reply.verified_count) || Number(reply.verified_count)<0 || Number(reply.verified_count)>Number(reply.expected_count)
        || !Number.isSafeInteger(reply.pending_trees) || Number(reply.pending_trees)<0 || Number(reply.pending_trees)>1_000_000
        || typeof reply.archive_verified!=="boolean") throw new Error("invalid baseline proof progress");
    if(reply.archive_verified!==(phase==="verified") || (phase==="verified" && (Number(reply.expected_count)===0 || reply.verified_count!==reply.expected_count || reply.pending_trees!==0)))
        throw new Error("inconsistent baseline proof certification");
    return {schema_version:1,phase,expected_count:Number(reply.expected_count),verified_count:Number(reply.verified_count),pending_trees:Number(reply.pending_trees),archive_verified:reply.archive_verified,digest:expected.digest,release_tag:expected.release_tag,asset:expected.asset,commit_sha:reply.commit_sha};
}

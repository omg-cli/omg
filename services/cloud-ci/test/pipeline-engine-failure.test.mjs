import {expect,test} from 'bun:test';
import {fileURLToPath} from 'node:url';
test('actual RunnerGroup engine failures alone earn the internal-error category',async()=>{
const pipeline=fileURLToPath(new URL('../src/pipeline.ts',import.meta.url));
const runnerGroup=fileURLToPath(new URL('../node_modules/@cloudflare/ci/src/pipeline/runner-group.ts',import.meta.url));
const plan=fileURLToPath(new URL('../runner/plan.mjs',import.meta.url));
const source=`
import assert from 'node:assert/strict';
import {CI} from ${JSON.stringify(pipeline)};
import {RunnerGroup} from ${JSON.stringify(runnerGroup)};
import {cloudCiChecks} from ${JSON.stringify(plan)};
export default {async fetch(request,env){
const mode=new URL(request.url).pathname.slice(1);
const sha='a'.repeat(40),id='cl-123-1-'+sha;
const input={repository:'omg-cli/omg',sha,ref:'refs/heads/main',runId:'123',attempt:'1'};
const receiptPath='receipts/123-1/'+sha+'.json';
await env.BUCKET.put('runs/'+id+'/request.json',JSON.stringify(input));
const engine=new Error('engine unavailable');engine.name='WorkflowInternalError';
const nested=new Error('outer runner failure');nested.cause=engine;
const failure=mode==='engine'?engine:mode==='message-spoof'?new Error('WorkflowInternalError'):mode==='nested'?nested:mode==='plain'?{name:'WorkflowInternalError'}:new Error('ordinary runner failure');
const step={async do(name,config,callback){return callback({attempt:1});}};
const ci=new CI({}, {BACKUP_BUCKET:env.BUCKET,CI_IMAGE_DIGEST:'sha256:'+'b'.repeat(64)});
const group=new RunnerGroup();
try{
await ci.pipeline({instanceId:id,payload:{sha,ref:input.ref}},step,{runner:(options,inherited)=>group.run(options,inherited,()=>Promise.reject(failure))});
return Response.json({mode,unexpected:'resolved'},{status:500});
}catch(error){
const receipt=await (await env.BUCKET.get(receiptPath)).json();
assert.equal(receipt.conclusion,'failure');
assert.deepEqual(receipt.requiredChecks,cloudCiChecks);
assert.deepEqual(receipt.checks,[]);
return Response.json({mode,errorName:error.name,causeName:error.cause?.name,receipt},{status:500});
}
}};`;
const built=await Bun.build({entrypoints:['fixture:entry'],target:'browser',external:['node:*'],plugins:[{name:'explicit Workflow invocation fixture',setup(build){
build.onResolve({filter:/^fixture:entry$/},()=>({path:'entry',namespace:'fixture'}));
build.onLoad({filter:/.*/,namespace:'fixture'},()=>({contents:source,loader:'ts'}));
build.onResolve({filter:/^@cloudflare\/sandbox$/},()=>({path:'sandbox',namespace:'fixture-base'}));
build.onResolve({filter:/^cloudflare:workers$/},()=>({path:'base',namespace:'fixture-base'}));
build.onLoad({filter:/.*/,namespace:'fixture-base'},({path})=>({contents:path==='sandbox'?`export const getSandbox=()=>{throw new Error('Unexpected container call in engine failure fixture')};export class OperationInterruptedError extends Error{constructor(context){super('fixture operation interrupted');this.name='OperationInterruptedError';this.context=context;}}`:`export class WorkflowEntrypoint{constructor(ctx,env){this.env=env;}} export class DurableObject{} export class WorkerEntrypoint{} export class RpcTarget{}; export const tracing=undefined;`,loader:'js'}));
}}]});
expect(built.success,built.logs.join('\n')).toBe(true);
const worker=await built.outputs[0].text();
const modes=['engine','message-spoof','nested','plain','ordinary'];
const program=`import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL('../node_modules/wrangler/package.json',import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BUCKET'],script:${JSON.stringify(worker)}}));
let timer;
const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Workerd engine failure fixture exceeded 20 seconds')),20_000);});
try{const results=await Promise.race([deadline,(async()=>{const results=[];for(const mode of ${JSON.stringify(modes)}){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);results.push({mode,status:response.status,body:await response.json()});}return results;})()]);console.log(JSON.stringify(results));}finally{clearTimeout(timer);await mf.dispose();}`;
const child=Bun.spawn(['node','--input-type=module','-'],{stdin:new TextEncoder().encode(program),stdout:'pipe',stderr:'pipe',timeout:25_000,killSignal:'SIGKILL'});
const [code,output,errors]=await Promise.all([child.exited,new Response(child.stdout).text(),new Response(child.stderr).text()]);
expect(code,errors).toBe(0);
const results=JSON.parse(output);
const byMode=Object.fromEntries(results.map(result=>[result.mode,result]));
expect(byMode.engine.status).toBe(500);
expect(byMode.engine.body.errorName).toBe('CiRunnerFailure');
expect(byMode.engine.body.causeName).toBe('WorkflowInternalError');
expect(byMode.engine.body.receipt.failureCategory).toBe('workflow-internal-error');
for(const mode of ['message-spoof','nested','plain','ordinary']){
expect(byMode[mode].status).toBe(500);
expect(byMode[mode].body.errorName).toBe('CiRunnerFailure');
expect(byMode[mode].body.receipt.failureCategory).toBeUndefined();
}
expect(byMode.plain.body.causeName).toBe('WorkflowInternalError');
},30_000);
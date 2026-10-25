import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'bun:test';
import {pathToFileURL,fileURLToPath} from 'node:url';
const c=fileURLToPath(new URL('../../../',import.meta.url)).replace(/\\/g,'/').replace(/\/$/,'');
async function prove(mode,mutate=false){
let mutations=0;
const source=`
import {DurableObject} from 'cloudflare:workers';
import {OperationInterruptedError} from ${JSON.stringify(c+'/services/cloud-ci/node_modules/@cloudflare/sandbox/dist/index.js')};
import {CI} from ${JSON.stringify(c+'/services/cloud-ci/src/pipeline.ts')};
const mode=${JSON.stringify(mode)},sha='a'.repeat(40),id='cl-123-1-'+sha;
const receiptKey='receipts/123-1/'+sha+'.json';
const input={repository:'omg-cli/omg',sha,ref:'refs/heads/main',runId:'123',attempt:'1'};
export class Counter extends DurableObject{
 async increment(key){const n=(await this.ctx.storage.get(key)??0)+1;await this.ctx.storage.put(key,n);return n;}
 async read(){return {producer:await this.ctx.storage.get('producer')??0,consumer:await this.ctx.storage.get('consumer')??0};}
}
export class Interrupter extends DurableObject{
 async fail(){
  await this.env.COUNTER.getByName('counts').increment('producer');
  const context={reason:mode==='transport_disposed'?'transport_disposed':mode==='unknown-reason'?'recovery_exhausted':'runtime_replaced',operation:'sandbox.exec',phase:'rpc_call',admitted:'unknown',retryable:mode!=='nonretryable'};
  const response={code:mode==='wrong-code'?'UNRELATED_ERROR':'OPERATION_INTERRUPTED',message:'synthetic actual SDK failure',timestamp:'2026-10-25T00:00:00.000Z',context:mode==='malformed'?{reason:'runtime_replaced',retryable:true}:context};
  if(mode==='plain-object')throw {errorResponse:response};
  throw new OperationInterruptedError(response);
 }
}
function sandboxFor(env,name){
 const text=name.startsWith('source-format-')?'source format clean\\n':'';
 return {
  async exec(command,options){
   if(name.startsWith('rust-portable-tests'.slice(0,16)+'-')&&options?.cwd==='/workspace')return env.INTERRUPTER.getByName('interrupt').fail();
   return {success:true,exitCode:0,stdout:'',stderr:''};
  },
  async createBackup(){return {id:'synthetic-snapshot-'+name,dir:'/workspace'};},
  async restoreBackup(){},
  async listFiles(){return {files:[{absolutePath:'/tmp/ci-step.out',size:new TextEncoder().encode(text).length},{absolutePath:'/tmp/ci-step.err',size:0}]};},
  async readFile(path){return {content:path.endsWith('.out')?text:''};},
  async destroy(){},
 };
}
const provider={assertSource(){},create(){return {getSourceCheckout:async()=>({kind:'archive',url:'https://synthetic.invalid/source'}),startStepNotification:async()=>null,listTreeBlobs:async()=>null};}};
export class Probe extends CI{
 constructor(ctx,env){
  const counter=env.COUNTER.getByName('counts');
  const bucket={get:(...args)=>env.BUCKET.get(...args),put:async(key,...args)=>{if(key===receiptKey)await counter.increment('consumer');return env.BUCKET.put(key,...args);}};
  super(ctx,{...env,BACKUP_BUCKET:bucket,SANDBOX:{make:name=>sandboxFor(env,name)},CI_IMAGE_DIGEST:'sha256:'+'b'.repeat(64)});
 }
 static getProvider(){return provider;}
 async run(event,step){
  if(mode!=='unknown-checkpoint')return super.run(event,step);
  const fault={do:async(name,...args)=>{const value=await step.do(name,...args);return name==='rust-portable-tests'?'unrecognized-checkpoint':value;}};
  return super.run(event,fault);
 }
}
export default{async fetch(request,env){
 await env.BUCKET.put('runs/'+id+'/request.json',JSON.stringify(input));
 const counter=env.COUNTER.getByName('counts');
 const instance=await env.PROBE.create({id,params:{provider:'fixture',providerData:{},owner:'omg-cli',repo:'omg',sha,ref:input.ref,event:{type:'push'}}});
 const wait=async(minimum)=>{for(let n=0;n<400;n++){const counts=await counter.read();const status=await instance.status();if(status.status==='errored'){const stored=await env.BUCKET.get(receiptKey);if(counts.consumer>=minimum&&stored)return {counts,status,receipt:await stored.json()};throw Error('Workflow errored before actual pipeline failure receipt: '+JSON.stringify({counts,status}));}if(status.status==='complete')throw Error('Interruption incorrectly succeeded');await new Promise(resolve=>setTimeout(resolve,25));}throw Error('Actual CIWorkflow verification deadline');};
 const before=await wait(1);
 let after=null;
 if(mode==='runtime_replaced'||mode==='transport_disposed'){
  await instance.restart({from:{name:'preserve-failure'}});
  after=await wait(2);
 }
 const objects={};
 for(const check of before.receipt.checks)for(const key of [check.stdoutKey,check.stderrKey]){const obj=await env.BUCKET.get(key);if(obj)objects[key]=await obj.text();}
 return Response.json({label:'SYNTHETIC LOCAL WORKERD: actual SDK/RPC/CIWorkflow/pipeline; no containers/native/cloud acceptance',mode,before,after,objects});
}};`;
const built=await Bun.build({entrypoints:['actual-ci:entry'],target:'browser',external:['cloudflare:workers','node:*'],plugins:[{name:'actual production CI path with sandbox transport fixture',setup(build){
 build.onLoad({filter:/ci-workflow\.ts$/},({path})=>{if(!mutate)return;const code=readFileSync(path,'utf8');const anchor='throw decodeOperationInterrupted(stored);';assert.equal(code.split(anchor).length-1,1,'mutation must reach actual production decoder');mutations++;return {contents:code.replace(anchor,"throw new Error('mutation: dropped interruption');"),loader:'ts'};});
 build.onResolve({filter:/^actual-ci:entry$/},()=>({path:'entry',namespace:'actual-ci'}));
 build.onLoad({filter:/.*/,namespace:'actual-ci'},()=>({contents:source,loader:'ts'}));
 build.onResolve({filter:/^@cloudflare\/sandbox$/},()=>({path:'transport',namespace:'actual-ci-sandbox'}));
 build.onLoad({filter:/.*/,namespace:'actual-ci-sandbox'},()=>({contents:'export const getSandbox=(namespace,name)=>namespace.make(name);',loader:'js'}));
}}]});
assert.equal(built.success,true,JSON.stringify(built.logs));
const worker=await built.outputs[0].text();
const program=`import {createRequire} from 'node:module';const require=createRequire(${JSON.stringify(pathToFileURL(c+'/services/cloud-ci/node_modules/wrangler/package.json').href)});const {Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BUCKET'],durableObjects:{COUNTER:{className:'Counter',useSQLite:true},INTERRUPTER:{className:'Interrupter',useSQLite:true}},workflows:{PROBE:{name:'actual-ci-interruption-proof',className:'Probe'}},script:${JSON.stringify(worker)}}));try{const response=await mf.dispatchFetch('https://synthetic.invalid');console.log(await response.text());}finally{await mf.dispose();}`;
const child=Bun.spawn(['node','--input-type=module','-'],{stdin:new TextEncoder().encode(program),stdout:'pipe',stderr:'pipe',timeout:30000,killSignal:'SIGKILL'});
const [exit,output,stderr]=await Promise.all([child.exited,new Response(child.stdout).text(),new Response(child.stderr).text()]);
assert.equal(exit,0,stderr);
const result=JSON.parse(output.trim().split('\n').at(-1));
if(mutate)assert.equal(mutations,1,'mutation was not applied exactly once');
assert.equal(result.before.receipt.conclusion,'failure');
assert.equal(result.before.counts.producer,1);
const retryable=['runtime_replaced','transport_disposed'].includes(mode);
if(retryable){
 assert.equal(result.before.receipt.failureCategory,'workflow-internal-error','actual production checkpoint did not preserve SDK interruption');
 assert.deepEqual(result.before.counts,{producer:1,consumer:1});
 assert.deepEqual(result.after.counts,{producer:1,consumer:2});
 assert.equal(result.after.receipt.failureCategory,'workflow-internal-error');
}else assert.equal(result.before.receipt.failureCategory,undefined,'malformed or terminal interruption earned recovery');
const {admitFormattingRun}=await import(pathToFileURL(c+'/scripts/ai-review-flow.mjs').href);
const prior=(result.after??result.before).receipt,original=JSON.stringify(prior),starts=[];
const stopped=new Error('synthetic stop after actual guarded refresh request');
const error=await admitFormattingRun({sha:prior.sha,branch:'main',upstream:{runId:prior.runId,attempt:prior.attempt},runId:'124',attempt:'1',imageDigest:prior.imageDigest,requirePortableEvidence:true,fetchReceipt:async(id)=>id===prior.id?prior:null,startRun:async(request)=>{starts.push(request);throw stopped;},verifyLogs:async(_id,check)=>{const {verifyCloudCiObjects}=await import(pathToFileURL(c+'/scripts/cloud-ci-evidence.mjs').href);await verifyCloudCiObjects({checks:[check]},async(key)=>{assert.equal(Object.hasOwn(result.objects,key),true,'produced log object missing');return new Response(result.objects[key]);});}}).catch(error=>error);
assert.equal(JSON.stringify(prior),original);
assert.equal(starts.length,retryable?1:0);
if(retryable){assert.equal(error,stopped);assert.equal(starts[0].runId,'124');assert.equal(starts[0].attempt,'1');assert.equal(starts[0].sha,prior.sha);}
else{const {CloudCiEngineFailure}=await import(pathToFileURL(c+'/scripts/cloud-ci-evidence.mjs').href);assert.ok(error instanceof Error);assert.equal(error instanceof CloudCiEngineFailure,false);}
}
for(const mode of ['runtime_replaced','transport_disposed','nonretryable','wrong-code','malformed','plain-object','unknown-reason','unknown-checkpoint']){
 test(`actual interruption recovery: ${mode}`,()=>prove(mode),40_000);
}
test('removing actual checkpoint reconstruction restores the missing-category failure',async()=>{
 await assert.rejects(prove('runtime_replaced',true),error=>error.code==='ERR_ASSERTION'&&error.message.includes('actual production checkpoint did not preserve SDK interruption'));
},40_000);

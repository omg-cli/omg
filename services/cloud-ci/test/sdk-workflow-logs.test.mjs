import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

const fixture = String.raw`
const mode = MODE;
const bytes = new Uint8Array(310_001).map((_, index) => index % 256);
const events=[];
let destroyed=false;
let starts=0;let polls=0;let streamCalls=0;let startDisposals=0;let pollDisposals=0;let resolvedPolls=0;
function owned(value,kind){if(mode==='plain-process')return value;let disposed=false;return Object.assign(value,{[Symbol.dispose](){assert.equal(disposed,false,'process result must be disposed exactly once');disposed=true;if(kind==='start')startDisposals++;else pollDisposals++;events.push(kind+'-dispose');}}); }
const sandbox={
 async exec(command){return {exitCode:0,stdout:'preview',stderr:''};},
 async startProcess(){starts++;return owned({id:'fixture-process',waitForExit:async()=>{streamCalls++;if(mode==='exit-stream-disposed')throw new Error('WritableStream RPC stub was disposed without calling close()');return {exitCode:0};}},'start');},
 async getProcess(id){assert.equal(id,'fixture-process');polls++;if(mode==='process-read-failure')throw new Error('fixture status RPC failed');if(mode==='process-read-hang')return new Promise(()=>{});if(mode==='process-missing')return null;
 const result=mode==='process-timeout'?{id,status:'running'}:mode==='process-nonzero'?{id,status:'failed',exitCode:7}:mode==='process-signal'?{id,status:'killed',exitCode:null}:mode==='process-invalid-zero'?{id,status:'failed',exitCode:0}:mode==='process-unknown'?{id,status:'unknown'}:mode==='process-identity'?{id:'other-process',status:'completed',exitCode:0}:mode==='exit-stream-disposed'&&polls===1?{id,status:'running'}:{id,status:'completed',exitCode:0};
 if(mode==='process-read-late')await new Promise(resolve=>setTimeout(resolve,30));
 resolvedPolls++;return owned(result,'poll');},
 async createBackup(){return {id:'actual-snapshot',dir:'/workspace'};},
 async listFiles(){const size=mode==='inline'?5:bytes.length+(mode==='length-mismatch'?1:0);return {files:[{absolutePath:'/tmp/ci-step.out',size},{absolutePath:'/tmp/ci-step.err',size}]};},
 async readFile(path,options){
   if(mode==='inline'){assert.equal(options.encoding,'utf-8');return {content:'small'};}
   assert.equal(options.encoding,'none');
   return {content:new ReadableStream({start(c){if(mode==='read-failure')c.error(new Error('fixture source read failed'));else {c.enqueue(bytes);c.close();}}})};
 },
 async readFileStream(){return new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('data: SSE metadata, not raw bytes'));c.close();}});},
 async destroy(){await new Promise(resolve=>setTimeout(resolve,0));destroyed=true;events.push('destroy');},
};
globalThis.fixtureSandbox=sandbox;
const objects=new Map();
const bucket={
 async put(key,body){
   if(mode==='write-failure'||(mode==='partial-write-failure'&&key.endsWith('/stderr')))throw new Error('fixture R2 write failed');
   await env.BUCKET.put(key,body);
   const value=new Uint8Array(await (await env.BUCKET.get(key)).arrayBuffer());
   objects.set(key,value);events.push('put');return {};
 },
 async get(key){
   if(mode==='missing')return null;
   const value=objects.get(key);if(!value)return null;
   return env.BUCKET.get(key);
 },
};
const provider={
 assertSource(){},
 create(){return {getSourceCheckout:async()=>({kind:'archive',url:'https://fixture.invalid/source'}),startStepNotification:async()=>null};},
};
let checkpoint;
class Fixture extends CIWorkflow{
 static getProvider(){return provider;}
 async pipeline(event,step,ci){
   const output=await ci.runner({name:'large-unit-output',command:'trusted fixture',config:{commandTimeoutMs:mode==='process-timeout'||mode==='process-read-hang'||mode==='process-read-late'?5:10000}});
   assert.equal(output.snapshot.id,'actual-snapshot');
   for(const log of [output.logs.stdout,output.logs.stderr]){
     if(mode==='inline')assert.equal(log,'small');
     else assert.deepEqual(new Uint8Array(await new Response(log).arrayBuffer()),bytes);
   }
   assert.equal(typeof output.runner,'function');
 }
}
const step={async do(name,config,callback){
 const output=await callback({attempt:1});
 // A direct byte stream has a separate supported platform path; nested state
 // uses structured serialization and must contain no stream instances.
 checkpoint=structuredClone(output);
 assert.equal(destroyed,true,'container cleanup must complete before checkpoint');
 events.push('checkpoint');return checkpoint;
}};
const workflow=new Fixture({}, {BACKUP_BUCKET:bucket});
let failure;
try{await workflow.run({instanceId:'fixture-run',payload:{provider:'fixture',providerData:{},owner:'fixed',repo:'repo',sha:'a'.repeat(40),ref:'refs/heads/main',event:{type:'push'}}},step);}catch(error){failure=error;}
if(mode==='process-read-late')await new Promise(resolve=>setTimeout(resolve,50));
assert.equal(starts,1,'a status wait must never restart the command');
assert.equal(startDisposals,mode==='plain-process'?0:1,'start result capabilities must be released');
assert.equal(pollDisposals,mode==='plain-process'?0:resolvedPolls,'every resolved poll result must release its capabilities, including after timeout');
if(mode==='ok'||mode==='inline'||mode==='exit-stream-disposed'||mode==='plain-process'){
 assert.equal(failure,undefined,failure?.stack);
 if(mode==='exit-stream-disposed'){assert.equal(streamCalls,0);assert.equal(polls,2);}
 assert.equal(objects.size,mode==='inline'?0:2);assert.equal(destroyed,true);
 assert.ok(events.indexOf('destroy')<events.indexOf('checkpoint'));
 for(const value of objects.values())assert.deepEqual(value,bytes);
 if(mode==='inline')assert.equal(checkpoint.logs.stdout,'small');
 else assert.equal(typeof checkpoint.logs.stdout.r2Key,'string');
}else{
 assert.ok(failure,'storage failure must fail closed');assert.equal(destroyed,true,'failure must still destroy sandbox');
 if(mode==='missing')assert.match(failure.message,/missing/i);
 if(mode==='write-failure'||mode==='partial-write-failure')assert.match(failure.message,/write failed/i);
 if(mode==='partial-write-failure')assert.equal(objects.size,1);
 if(mode==='read-failure')assert.match(failure.message,/read failed/i);
 if(mode==='process-missing')assert.equal(failure.message,'large-unit-output failed: CI process identity unavailable (expected string, received missing)');
 if(mode==='process-identity')assert.equal(failure.message,'large-unit-output failed: CI process identity unavailable (expected string, received string)');
 if(mode==='process-read-failure')assert.match(failure.message,/status RPC failed/i);
 if(mode==='process-timeout'||mode==='process-read-hang'||mode==='process-read-late')assert.match(failure.message,/timed out/i);
 if(mode.startsWith('process-'))assert.equal(objects.size,0,'unconfirmed completion must not publish logs or a snapshot');
}
return Response.json({mode,destroyed,objects:objects.size,events});
`;

for (const modes of [
  [
    "ok",
    "inline",
    "missing",
    "write-failure",
    "partial-write-failure",
    "read-failure",
    "length-mismatch",
  ],
  ["exit-stream-disposed", "process-nonzero", "process-signal", "process-invalid-zero"],
  [
    "process-missing",
    "process-read-failure",
    "process-read-hang",
    "process-read-late",
    "plain-process",
    "process-timeout",
    "process-unknown",
    "process-identity",
  ],
]) {
  test(`actual SDK execution and R2 cleanup: ${modes.join(", ")}`, async () => {
    const sdk = fileURLToPath(
      new URL("../node_modules/@cloudflare/ci/src/pipeline/ci-workflow.ts", import.meta.url),
    );

    const source = `import assert from 'node:assert/strict';\nimport {CIWorkflow} from ${JSON.stringify(sdk)};\nexport default {async fetch(request,env){try {\n${fixture.replace("MODE", "new URL(request.url).pathname.slice(1)")}\n}catch(error){return new Response(error.stack,{status:500});}}};`;

    const built = await Bun.build({
      entrypoints: ["fixture:entry"],
      target: "browser",
      external: ["node:*"],
      plugins: [
        {
          name: "explicit SDK transport fixtures",
          setup(build) {
            build.onResolve({ filter: /^fixture:entry$/ }, () => ({
              path: "entry",
              namespace: "fixture",
            }));
            build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
              contents: source,
              loader: "ts",
            }));
            build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({
              path: "sandbox",
              namespace: "stub",
            }));
            build.onResolve({ filter: /^cloudflare:workers$/ }, () => ({
              path: "base",
              namespace: "stub",
            }));
            build.onLoad({ filter: /.*/, namespace: "stub" }, ({ path }) => ({
              contents:
                path === "sandbox"
                  ? "export const getSandbox=()=>globalThis.fixtureSandbox;"
                  : "export class WorkflowEntrypoint{constructor(ctx,env){this.env=env;}}",
              loader: "js",
            }));
          },
        },
      ],
    });

    expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
    const worker = await built.outputs[0].text();

    const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BUCKET'],script:${JSON.stringify(worker)}}));
try{const results=[];for(const mode of ${JSON.stringify(modes)}){const r=await mf.dispatchFetch('https://fixture.invalid/'+mode);results.push({mode,status:r.status,body:await r.text()});}console.log(JSON.stringify(results));}finally{await mf.dispose();}`;

    const child = Bun.spawn(["node", "--input-type=module", "-"], {
      stdin: new TextEncoder().encode(program),
      stdout: "pipe",
      stderr: "pipe",
    });

    const [code, output, errors] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);

    expect(code, errors).toBe(0);
    const results = JSON.parse(output);
    expect(results.map((result) => result.mode)).toEqual(modes);

    for (const result of results) {
      expect(result.status, `${result.mode}: ${result.body}`).toBe(200);
      expect(JSON.parse(result.body).destroyed).toBe(true);
    }
  });
}

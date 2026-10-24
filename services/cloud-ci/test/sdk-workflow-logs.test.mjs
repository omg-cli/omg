import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

const fixture = String.raw`
const mode = MODE;
const bytes = new Uint8Array(310_001).map((_, index) => index % 256);
const events=[];
let destroyed=false;
let executions=0;let backgroundCalls=0;let backups=0;
const startedAt=Date.now();
const invalidExits={
 'command-signal':null,'command-missing-exit':undefined,'command-negative':-1,
 'command-fractional':0.5,'command-nan':NaN,'command-infinite':Infinity,
 'command-string':'0','command-unsafe':Number.MAX_SAFE_INTEGER+1,
};
const sandbox={
 async exec(command,options){
   if(!command.startsWith('(trusted fixture)'))return {success:true,exitCode:0,stdout:'preview',stderr:''};
   executions++;assert.equal(options.cwd,'/workspace');assert.equal(options.env.CI,'true');
   assert.equal(options.timeout,shortDeadline?5:10000);
   if(mode==='command-read-hang'||mode==='command-timeout')return new Promise(()=>{});
   if(mode==='command-read-late')await new Promise(resolve=>setTimeout(resolve,30));
   if(mode==='command-read-failure')throw new Error('fixture command RPC failed');
   if(mode==='command-interrupted'||mode==='command-interrupted-retryable')throw new OperationInterruptedError({reason:'runtime_replaced',operation:'sandbox.exec',phase:'execute',admitted:false,retryable:mode.endsWith('-retryable')});
   const exitCode=Object.hasOwn(invalidExits,mode)?invalidExits[mode]:mode==='command-nonzero'?7:0;
   return {success:mode==='command-invalid-zero'?false:mode==='command-invalid-nonzero'?true:exitCode===0,exitCode:mode==='command-invalid-nonzero'?7:exitCode,stdout:'',stderr:''};
 },
 async startProcess(){backgroundCalls++;throw new Error('finite command must not use background process');},
 async getProcess(){backgroundCalls++;throw new Error('finite command must not poll process status');},
 async createBackup(){backups++;return {id:'actual-snapshot',dir:'/workspace'};},
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
const shortDeadline=['finite-quiet-completed','command-read-hang','command-read-late','command-timeout'].includes(mode);
class Fixture extends CIWorkflow{
 static getProvider(){return provider;}
 async pipeline(event,step,ci){
   const output=await ci.runner({name:'large-unit-output',command:'trusted fixture',config:{commandTimeoutMs:shortDeadline?5:10000}});
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
if(mode==='command-read-late')await new Promise(resolve=>setTimeout(resolve,50));
assert.equal(executions,1,'a completion wait must never restart the command');
assert.equal(backgroundCalls,0,'finite command completion must not depend on background status');
if(['finite-quiet-completed','ok','inline','telemetry-throw','empty-command-output'].includes(mode)){
 assert.equal(failure,undefined,failure?.stack);
 assert.equal(backups,1);assert.equal(objects.size,mode==='inline'?0:2);assert.equal(destroyed,true);
 assert.ok(events.indexOf('destroy')<events.indexOf('checkpoint'));
 for(const value of objects.values())assert.deepEqual(value,bytes);
 if(mode==='inline')assert.equal(checkpoint.logs.stdout,'small');
 else assert.equal(typeof checkpoint.logs.stdout.r2Key,'string');
}else{
 assert.ok(failure,'unconfirmed completion or storage failure must fail closed');assert.equal(destroyed,true,'failure must still destroy sandbox');
 if(mode==='missing')assert.match(failure.message,/missing/i);
 if(mode==='write-failure'||mode==='partial-write-failure')assert.match(failure.message,/write failed/i);
 if(mode==='partial-write-failure')assert.equal(objects.size,1);
 if(mode==='read-failure')assert.match(failure.message,/read failed/i);
 if(mode==='command-read-failure')assert.match(failure.message,/command RPC failed/i);
 if(mode.startsWith('command-interrupted'))assert.match(failure.message,/fixture operation interrupted/i);
 if(['command-timeout','command-read-hang','command-read-late'].includes(mode)){
   assert.match(failure.message,/timed out/i);assert.ok(Date.now()-startedAt<250,'completion keeps its original deadline');
 }
 if(Object.hasOwn(invalidExits,mode))assert.match(failure.message,/terminal exit code unavailable/i);
 if(mode==='command-invalid-zero'||mode==='command-invalid-nonzero')assert.match(failure.message,/inconsistent command completion/i);
 if(mode.startsWith('command-')){assert.equal(backups,0,'unconfirmed or failed completion must not snapshot');assert.equal(objects.size,0,'unconfirmed completion must not publish logs');}
}
return Response.json({mode,destroyed,objects:objects.size,events,telemetry});
`;

let workerPromise;

for (const modes of [
  ["finite-quiet-completed"],
  ["ok"],
  ["inline"],
  ["telemetry-throw"],
  ["missing"],
  ["write-failure"],
  ["partial-write-failure"],
  ["read-failure"],
  ["length-mismatch"],
  ["empty-command-output"],
  ["command-nonzero"],
  ["command-signal"],
  ["command-invalid-zero"],
  ["command-invalid-nonzero"],
  ["command-missing-exit"],
  ["command-negative"],
  ["command-fractional"],
  ["command-nan"],
  ["command-infinite"],
  ["command-string"],
  ["command-unsafe"],
  ["command-interrupted"],
  ["command-interrupted-retryable"],
  ["command-read-failure"],
  ["command-read-hang"],
  ["command-read-late"],
  ["command-timeout"],
]) {
  test(`actual SDK execution and R2 cleanup: ${modes.join(", ")}`, async () => {
    const sdk = fileURLToPath(
      new URL("../node_modules/@cloudflare/ci/src/pipeline/ci-workflow.ts", import.meta.url),
    );

    const source = `import assert from 'node:assert/strict';\nimport { OperationInterruptedError } from "@cloudflare/sandbox";\nimport {CIWorkflow} from ${JSON.stringify(sdk)};\nexport default {async fetch(request,env){const requestMode=new URL(request.url).pathname.slice(1);const originalLog=console.log;const telemetry=[];console.log=requestMode==='telemetry-throw'?()=>{throw new Error('fixture telemetry failure');}:(...args)=>{telemetry.push(args);};try {\n${fixture.replace("MODE", "requestMode")}\n}catch(error){return new Response(error.stack,{status:500});}finally{console.log=originalLog;}}};`;

    workerPromise ??= Bun.build({
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
                  ? "export const getSandbox=()=>globalThis.fixtureSandbox;export class OperationInterruptedError extends Error{constructor(context){super('fixture operation interrupted');this.name='OperationInterruptedError';this.context=context;}}"
                  : "export class WorkflowEntrypoint{constructor(ctx,env){this.env=env;}}",
              loader: "js",
            }));
          },
        },
      ],
    }).then(async (built) => {
      expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
      return built.outputs[0].text();
    });
    const worker = await workerPromise;

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
      const body = JSON.parse(result.body);
      expect(body.destroyed, result.mode).toBe(true);
      if (["finite-quiet-completed", "ok", "inline", "empty-command-output"].includes(result.mode)) {
        expect(body.telemetry.length, result.mode).toBe(1);
        const [line] = body.telemetry[0];
        expect(typeof line, result.mode).toBe("string");
        expect(line.length, result.mode).toBeLessThanOrEqual(256);
        expect(JSON.parse(line), result.mode).toEqual({
          event: "ci-checkpoint-reached",
          step: "large-unit-output",
          stdout: result.mode === "inline" ? "inline" : "r2",
          stderr: result.mode === "inline" ? "inline" : "r2",
          snapshot: true,
        });
      } else if (result.mode === "telemetry-throw") {
        expect(body.telemetry.length, result.mode).toBe(0);
      } else if (result.mode === "missing") {
        expect(body.telemetry.length, result.mode).toBe(1);
      } else {
        expect(body.telemetry.length, result.mode).toBe(0);
      }
    }
  });
}

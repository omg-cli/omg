import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("actual getSandbox waits for configuration before admitting preflight", async () => {
  const sdk = fileURLToPath(
    new URL("../node_modules/@cloudflare/sandbox/dist/sandbox-DlkunMi0.js", import.meta.url),
  );

  const source = `import assert from 'node:assert/strict';
import {r as getSandbox,V as OperationInterruptedError} from ${JSON.stringify(sdk)};
export default {async fetch(){try{
 let release,configurations=0,commands=0;
 const configured=new Promise(resolve=>release=resolve);
 const stub={configure:async()=>{configurations++;await configured;},execWithSessionToken:async command=>{commands++;return {exitCode:0,stdout:command,stderr:''};}};
 const namespace={idFromName:name=>({name}),get:()=>stub};
 const sandbox=getSandbox(namespace,'configuration-barrier-fixture',{transport:'rpc',enableDefaultSession:false});
 const pending=sandbox.exec('test -c /dev/fuse');
 await Promise.resolve();await Promise.resolve();
 assert.equal(configurations,1,'implicit setup must be dispatched exactly once');
 assert.equal(commands,0,'preflight must wait for the actual implicit configure acknowledgement');
 release();const result=await pending;
 assert.equal(configurations,1,'one handle must not duplicate implicit setup');
 assert.equal(commands,1);assert.equal(result.exitCode,0);
 let failedConfigurations=0,failedCommands=0,acquisitions=0;
 const original=new Error('Connection closed: this Durable Object instance is no longer active. Reconnect or retry the request.');original.retryable=true;
 const failedNamespace={idFromName:name=>({name}),get:()=>{const generation=++acquisitions;return {
  configure:async()=>{failedConfigurations++;if(generation===1)throw original;},
  execWithSessionToken:async()=>{failedCommands++;assert.equal(generation,2);return {exitCode:0};},
 };}};
 const interrupted=getSandbox(failedNamespace,'configuration-failure-fixture',{transport:'rpc',enableDefaultSession:false});
 let failure;try{await interrupted.exec('test -c /dev/fuse');}catch(error){failure=error;}
 assert.ok(failure instanceof OperationInterruptedError,'configuration rejection must reach the caller as a typed interruption');
 assert.equal(failure.context.operation,'sandbox.configure');assert.equal(failure.cause,original);
 assert.equal(failedCommands,0,'failed configuration cannot admit any command');
 assert.equal(acquisitions,1,'SDK readiness must not introduce automatic recovery');
 const fresh=getSandbox(failedNamespace,'configuration-failure-fixture',{transport:'rpc',enableDefaultSession:false});
 assert.equal((await fresh.exec('test -c /dev/fuse')).exitCode,0);
 assert.equal(failedConfigurations,2,'failed optimistic cache must not suppress fresh-stub configuration');
 assert.equal(failedCommands,1);
 return Response.json({configurations,commands,failedConfigurations,failedCommands,acquisitions});
}catch(error){return Response.json({error:error.stack},{status:500});}}};`;

  const built = await Bun.build({
    entrypoints: ["fixture:entry"],
    target: "browser",
    external: ["node:*", "cloudflare:workers"],
    plugins: [
      {
        name: "actual SDK configuration fixture",
        setup(build) {
          build.onResolve({ filter: /^fixture:entry$/ }, () => ({
            path: "entry",
            namespace: "fixture",
          }));
          build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
            contents: source,
            loader: "js",
          }));
        },
      },
    ],
  });

  expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
  const worker = await built.outputs[0].text();
  const program = `import{createRequire}from'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});const{Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(worker)}}));try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.text()}));}finally{await mf.dispose();}`;

  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    windowsHide: true,
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
  const result = JSON.parse(output);
  expect(result.status, result.body).toBe(200);
}, 30000);

test("actual runner deadline rejects late configuration without submitting preflight", async () => {
  const runner = fileURLToPath(
    new URL("../node_modules/@cloudflare/ci/src/ci/runners/sandbox.ts", import.meta.url),
  );

  const errors = fileURLToPath(
    new URL("../node_modules/@cloudflare/sandbox/dist/index.js", import.meta.url),
  );

  const source = `import assert from 'node:assert/strict';
import {SandboxRunner} from ${JSON.stringify(runner)};
export default {async fetch(){try{
 let release,preflights=0,starts=0,destroyed=0,lateCancels=0;
 const configured=new Promise(resolve=>release=resolve);
 const namespace={idFromName:name=>({name}),get:()=>({async cancel(){lateCancels++;throw new Error('expired invocation must not start cancellation');}})};
 globalThis.fixtureSandbox={waitForConfiguration:()=>configured,exec:async()=>{preflights++;return {exitCode:0};},startProcess:async()=>{starts++;throw new Error('late command forbidden');},destroy:async()=>{destroyed++;}};
 let failure;try{await new SandboxRunner({SANDBOX:namespace}).run({instanceId:'deadline-fixture',attempt:1,label:'deadline',command:'must not run',source:{kind:'archive',url:'https://fixture.invalid/source'},deadlineMs:Date.now()+15});}catch(error){failure=error;}
 release();for(let turn=0;turn<5;turn++)await Promise.resolve();
 assert.equal(preflights,0,'late configure acknowledgement must never submit preflight');
 assert.equal(starts,0);assert.equal(destroyed,0,'expired invocation cannot start a late cleanup RPC');
 assert.equal(lateCancels,0,'a valid namespace must receive no cancellation after expiry');
 assert.match(failure?.message??'',/CI sandbox deadline expired/);
 return Response.json({preflights,starts,destroyed,lateCancels});
}catch(error){return Response.json({error:error.stack},{status:500});}}};`;

  const built = await Bun.build({
    entrypoints: ["fixture:entry"],
    target: "browser",
    external: ["node:*", "cloudflare:workers"],
    plugins: [
      {
        name: "actual runner readiness deadline fixture",
        setup(build) {
          build.onResolve({ filter: /^fixture:entry$/ }, () => ({
            path: "entry",
            namespace: "fixture",
          }));
          build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
            contents: source,
            loader: "js",
          }));
          build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({
            path: "sandbox",
            namespace: "stub",
          }));
          build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
            contents: `export {OperationInterruptedError} from ${JSON.stringify(errors)};export const getSandbox=()=>globalThis.fixtureSandbox;`,
            loader: "js",
          }));
        },
      },
    ],
  });

  expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
  const worker = await built.outputs[0].text();
  const program = `import{createRequire}from'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});const{Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(worker)}}));try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.text()}));}finally{await mf.dispose();}`;

  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    windowsHide: true,
    stdin: new TextEncoder().encode(program),
    stdout: "pipe",
    stderr: "pipe",
  });

  const [code, output, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect(code, stderr).toBe(0);
  const result = JSON.parse(output);
  expect(result.status, result.body).toBe(200);
}, 30000);

test("actual runner requires fresh durable cancellation ACK before handing off output", async () => {
  const runner = fileURLToPath(
    new URL("../node_modules/@cloudflare/ci/src/ci/runners/sandbox.ts", import.meta.url),
  );

  const source = `import assert from 'node:assert/strict';
import {SandboxRunner} from ${JSON.stringify(runner)};
export default {async fetch(){try{for(const mode of ['ack','pending','rejected','primary','nonzero','non-error']){
 let starts=0,cancels=0,oldDestroys=0,actorName;
 const events=[];
 const namespace={idFromName:name=>({name}),get(id){assert.equal(id.name,actorName);events.push('fresh-stub');return {async cancel(){cancels++;events.push('durable-fence');if(mode==='pending')return new Promise(()=>{});if(['rejected','primary','nonzero','non-error'].includes(mode))throw new Error('cleanup ACK rejected');events.push('teardown-ack');}};}};
 globalThis.fixtureSandboxFactory=(ns,name)=>{assert.equal(ns,namespace);actorName=name;return {
  async waitForConfiguration(){},async exec(){return {exitCode:0,stdout:'preview',stderr:''};},
  async startProcess(){starts++;if(mode==='primary')throw new Error('primary command error');if(mode==='non-error')throw 'literal primary failure';return {id:'original-process'};},
  async getProcess(id){assert.equal(id,'original-process');return {id,status:mode==='nonzero'?'failed':'completed',exitCode:mode==='nonzero'?7:0};},
  async createBackup(){return {id:'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',dir:'/workspace'};},
  async persistCiLogs(){events.push('logs-committed');return {logs:{stdout:'out',stderr:'err'}};},
  async destroy(){oldDestroys++;throw new Error('old handle is unusable');},
 };};
 let result,failure;try{result=await Promise.race([new SandboxRunner({SANDBOX:namespace}).run({instanceId:'cleanup-ack-fixture',label:'unit',attempt:1,command:'one command',source:{kind:'archive',url:'https://fixture.invalid/source'},deadlineMs:Date.now()+100}),new Promise((_,reject)=>setTimeout(()=>reject(new Error('fixture runner did not settle after cleanup deadline')),250))]);}catch(error){failure=error;}
 assert.equal(starts,1,'SETUP: actual runner must launch the isolated command');if(!['primary','nonzero','non-error'].includes(mode))assert.ok(events.includes('logs-committed'),'SETUP: actual runner must finish its logs before cleanup: '+JSON.stringify({events,failure:String(failure)}));
 assert.equal(cancels,1,'one fresh same-actor cancellation ACK is mandatory');assert.equal(oldDestroys,0,'cleanup cannot reuse the command handle');assert.equal(starts,1);
 if(mode==='ack'){assert.equal(failure,undefined,failure?.stack);assert.equal(result.exitCode,0);assert.ok(events.indexOf('logs-committed')<events.indexOf('durable-fence'));assert.equal(events.at(-1),'teardown-ack');}
 else if(mode==='nonzero'){assert.equal(failure,undefined,'cleanup rejection must not mask a command failure result');assert.equal(result.exitCode,7);assert.deepEqual(result.preview,{stdout:'preview',stderr:'preview'});assert.equal(events.includes('logs-committed'),false);}
 else if(mode==='non-error'){assert.equal(failure,'literal primary failure');assert.equal(result,undefined);}
 else {assert.equal(result,undefined,'unacknowledged cleanup cannot return successful output');assert.match(failure?.message??'',mode==='primary'?/primary command error/:mode==='pending'?/deadline expired/:/cleanup ACK rejected/);if(mode==='primary')assert.equal(failure.cause?.message,'cleanup ACK rejected','primary failure must retain cleanup failure context');}
}return new Response('ok');}catch(error){return new Response(error.stack,{status:500});}}};`;

  const built = await Bun.build({
    entrypoints: ["fixture:entry"],
    target: "browser",
    external: ["node:*", "cloudflare:workers"],
    plugins: [
      {
        name: "actual runner cleanup acknowledgement",
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
          build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
            contents: `export {OperationInterruptedError} from ${JSON.stringify(fileURLToPath(new URL("../node_modules/@cloudflare/sandbox/dist/index.js", import.meta.url)))};export const getSandbox=(...args)=>globalThis.fixtureSandboxFactory(...args);`,
            loader: "js",
          }));
        },
      },
    ],
  });

  expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
  const worker = await built.outputs[0].text();
  const program = `import{createRequire}from'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});const{Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(worker)}}));try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.text()}));}finally{await mf.dispose();}`;

  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    windowsHide: true,
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
  const result = JSON.parse(output);
  expect(result.status, result.body).toBe(200);
}, 30000);

test("actual Sandbox RPC startup backs off rate admission without replaying commands", async () => {
  const sdk = fileURLToPath(
    new URL("../node_modules/@cloudflare/sandbox/dist/sandbox-DlkunMi0.js", import.meta.url),
  );

  const nativeReasons = [
    "container_starting",
    "container_unhealthy",
    "container_replaced",
    "rpc_upgrade_failed",
    "no_container_instance_available",
    "max_container_instances_exceeded",
    "container_unreachable",
  ];

  const modes = [
    "happy",
    "rate-once",
    "rate-cause",
    "rate-persistent",
    "rate-expired",
    "cancelled",
    "generic",
    "near-match",
    "command-failure",
    "forged-rate",
    "unrelated-native",
    "native-unknown",
    "rpc-serialized-rate",
    "cause-startup",
    "cause-rehydration",
    "cause-default",
    "cause-unflagged",
    "cause-absent",
    ...nativeReasons.map((reason) => "native-" + reason),
  ];

  const source = `import assert from 'node:assert/strict';
import {n as Sandbox,z as ContainerUnavailableError,FixtureControlClient,FixtureSandboxError,FixtureCreateError} from ${JSON.stringify(sdk)};
import {RpcTarget,newWorkersWebSocketRpcResponse} from 'capnweb';
import {DurableObject} from 'cloudflare:workers';
const unavailable=reason=>new ContainerUnavailableError({code:'CONTAINER_UNAVAILABLE',message:'isolated typed startup error',context:{reason,retryable:true},httpStatus:503,timestamp:new Date().toISOString()});
export class StartupFault extends DurableObject {async fail(mode){
 if(!mode)throw unavailable('container_start_rate_limited');
 const original=new Error('isolated startup transport failure');original.name='RPC.disconnected';
 if(mode!=='cause-unflagged'){original.retryable=true;original.overloaded=false;}
 const response={code:mode==='cause-default'?'TUNNEL_NOT_FOUND':'INTERNAL_ERROR',message:'isolated factory error',context:{phase:'startup'},httpStatus:500,timestamp:new Date().toISOString()};
 if(mode==='cause-absent')throw FixtureCreateError(response);
 if(mode==='cause-default')throw FixtureCreateError(response,{cause:original});
 let starts=0,commands=0;
 const actor={ctx:{container:{running:false}},containerTimeouts:{portReadyTimeoutMS:60000,waitIntervalMS:300},getState:async()=>({status:'stopped'}),toContainerStartError:Sandbox.prototype.toContainerStartError,async startAndWaitForPorts(){starts++;throw original;}};
 if(mode!=='cause-rehydration')try{await Sandbox.prototype.startContainerForRPC.call(actor);}catch(error){error.fixtureStarts=starts;error.fixtureCommands=commands;throw error;}
 const client=new FixtureControlClient({stub:{fetch:async()=>{commands++;throw new Error('startup failure must precede upgrade');}},startContainer:()=>Sandbox.prototype.startContainerForRPC.call(actor)});
 try{await client.commands.execute('isolated command');}catch(error){error.fixtureStarts=starts;error.fixtureCommands=commands;throw error;}finally{await client.disconnect();}
}}

export default {async fetch(request,env){
const mode=new URL(request.url).pathname.slice(1), phrase='You are requesting too many containers per second';
if(mode.startsWith('cause-')){
 let failure;try{await env.STARTUP_FAULT.getByName('cause-fixture').fail(mode);}catch(error){failure=error;}
 assert.ok(failure,'actual DO RPC must propagate the factory failure');
 assert.equal(failure.name,'SandboxError');assert.equal(failure.errorResponse.code,mode==='cause-default'?'TUNNEL_NOT_FOUND':'INTERNAL_ERROR');
 if(mode==='cause-absent'){assert.equal(failure.cause,undefined);assert.equal(failure.retryable,undefined);}
 else{
  const causes=[];let current=failure;for(let depth=0;current&&depth<5;depth++){causes.push(current);current=current.cause;}
  const original=causes.find(error=>error.name==='RPC.disconnected');
  assert.ok(original,'original startup cause must survive actual factory, connection and DO RPC');
  assert.equal(original.message,'isolated startup transport failure');
  assert.equal(original.retryable,mode==='cause-unflagged'?undefined:true);
  assert.equal(original.overloaded,mode==='cause-unflagged'?undefined:false);
  assert.equal(failure.retryable,undefined,'factory must not manufacture a retry policy');
  if(mode!=='cause-default'){assert.equal(failure.fixtureStarts,1);assert.equal(failure.fixtureCommands,0);}
 }
 return Response.json({mode,code:failure.errorResponse.code,causePreserved:mode!=='cause-absent',manufacturedRetry:false});
}
const nativeReasons=${JSON.stringify(nativeReasons)},nativeReason=mode.slice('native-'.length),nativePositive=mode.startsWith('native-')&&nativeReasons.includes(nativeReason);
const realNow=Date.now,realSetTimeout=globalThis.setTimeout,realClearTimeout=globalThis.clearTimeout;
let clock=1_000_000,starts=0,commands=0,upgrades=0,settled=false,result,failure,sequence=0;
const timers=new Map(),delays=[],events=[],startupErrors=[];
Date.now=()=>clock;
globalThis.setTimeout=(callback,delay=0)=>{const id=++sequence;timers.set(id,{callback,delay});return id;};
globalThis.clearTimeout=id=>timers.delete(id);
const actor={ctx:{container:{running:false}},containerTimeouts:{portReadyTimeoutMS:60_000,waitIntervalMS:300},getState:async()=>({status:'stopped'}),
 toContainerStartError(error){startupErrors.push({message:error.message,cause:error.cause?.message,nativeReason:error.context?.reason});return Sandbox.prototype.toContainerStartError.call(this,error);},
 async startAndWaitForPorts(options){starts++;events.push({phase:'platform-start',attempt:starts,at:clock});assert.equal(options.cancellationOptions.instanceGetTimeoutMS,8000);assert.equal(options.cancellationOptions.portReadyTimeoutMS,60000);assert.equal(options.cancellationOptions.waitInterval,300);
  if(mode==='cancelled'&&starts>1)throw new Error('CI sandbox was cancelled');
  if(mode==='generic')throw new Error('no such image');
  if(mode==='near-match')throw new Error('Too many requests for an unrelated API');
  if(mode==='forged-rate')throw {message:'forged startup metadata',code:'CONTAINER_UNAVAILABLE',context:{reason:'container_start_rate_limited',retryable:true}};
  if(mode==='unrelated-native')throw new FixtureSandboxError({code:'INTERNAL_ERROR',message:'isolated unrelated SDK error',context:{reason:'container_start_rate_limited',retryable:true},httpStatus:500,timestamp:new Date().toISOString()});
  if(mode==='native-unknown')throw unavailable('unrecognized');
  if(mode==='rpc-serialized-rate'){try{await env.STARTUP_FAULT.getByName('fixture').fail();}catch(error){events.push({phase:'serialized-error',sameSdkClass:error instanceof ContainerUnavailableError,codeType:typeof error.code});throw error;}}
  if(nativePositive&&starts===1)throw unavailable(nativeReason);
  if(mode==='rate-expired')clock+=106_000;
  if(mode!=='happy'&&!nativePositive&&(starts===1||mode==='rate-persistent'||mode==='rate-expired'))throw mode==='rate-cause'?new Error('wrapped startup failure',{cause:new Error(phrase.toUpperCase())}):new Error(phrase);
 }};
class Commands extends RpcTarget {execute(command){assert.equal(command,'isolated command');commands++;if(mode==='command-failure')throw new Error(phrase);return {exitCode:0,stdout:'isolated result'};}}
const commandTarget=new Commands();
class Main extends RpcTarget {get commands(){return commandTarget;}}
const client=new FixtureControlClient({
 stub:{fetch:async request=>{upgrades++;return newWorkersWebSocketRpcResponse(request,new Main());}},
 startContainer:()=>Sandbox.prototype.startContainerForRPC.call(actor),
});
try{
 const pending=client.commands.execute('isolated command').then(value=>{result=value;settled=true;},error=>{failure=error;settled=true;});
 for(let turns=0;!settled&&turns<1000;turns++){
  await new Promise(resolve=>realSetTimeout(resolve,1));
  if(!settled&&upgrades===0&&timers.size){const [id,timer]=timers.entries().next().value;timers.delete(id);clock+=timer.delay;delays.push(timer.delay);timer.callback();}
 }
 assert.equal(settled,true,'queued command must settle within the fixture');await pending;
 const recovered=['rate-once','rate-cause'].includes(mode)||nativePositive;
 if(mode==='happy'){assert.equal(failure,undefined,'SETUP: real queued RPC command must complete');assert.deepEqual(result,{exitCode:0,stdout:'isolated result'});assert.equal(starts,1);assert.equal(commands,1);assert.equal(upgrades,1);assert.deepEqual(delays,[]);}
 else if(recovered){assert.ok(starts>=1,'SETUP: actual platform startup hook must run');assert.ok(nativePositive?startupErrors.some(error=>error.nativeReason===nativeReason):startupErrors.some(error=>[error.message,error.cause].some(text=>text?.toLowerCase()===phrase.toLowerCase())),'SETUP: exact platform or native fault must reach the real classifier');assert.equal(failure,undefined,'startup admission should recover before executing the queued command: '+JSON.stringify({starts,commands,upgrades,delays,error:String(failure)}));assert.deepEqual(result,{exitCode:0,stdout:'isolated result'});assert.equal(starts,2);assert.equal(commands,1);assert.deepEqual(delays,[3000]);}
 else {assert.ok(failure,'negative control must reject');assert.equal(commands,mode==='command-failure'?1:0);
  if(mode==='rate-persistent'){assert.equal(failure.code,'CONTAINER_UNAVAILABLE');assert.equal(failure.context.reason,'container_start_rate_limited');assert.equal(clock-1_000_000,105000);assert.equal(starts,7);}
  if(mode==='rate-expired'){assert.equal(starts,1);assert.equal(delays.length,0);}
  if(['generic','near-match','forged-rate','rpc-serialized-rate','unrelated-native'].includes(mode)){assert.equal(starts,1);assert.equal(delays.length,0);assert.notEqual(failure.code,'CONTAINER_UNAVAILABLE');}
  if(mode==='native-unknown'){assert.equal(starts,1);assert.equal(delays.length,0);assert.equal(failure.context.reason,'unrecognized');}
  if(mode==='cancelled'){assert.equal(starts,2);assert.deepEqual(delays,[3000]);}
  if(mode==='command-failure'){assert.equal(starts,2);assert.equal(upgrades,1);assert.deepEqual(delays,[3000]);}
 }
 return Response.json({mode,starts,commands,upgrades,delays,elapsed:clock-1_000_000,events,startupErrors});
}catch(error){return Response.json({error:error.stack,mode,starts,commands,upgrades,delays,events,startupErrors},{status:500});}
finally{await client.disconnect();Date.now=realNow;globalThis.setTimeout=realSetTimeout;globalThis.clearTimeout=realClearTimeout;}
}};`;

  const built = await Bun.build({
    entrypoints: ["fixture:entry"],
    target: "browser",
    external: ["node:*", "cloudflare:workers"],
    plugins: [
      {
        name: "actual SDK startup fixture",
        setup(build) {
          build.onResolve({ filter: /^fixture:entry$/ }, () => ({
            path: "entry",
            namespace: "fixture",
          }));
          build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
            contents: source,
            loader: "js",
          }));
          build.onLoad({ filter: /sandbox-DlkunMi0\.js$/ }, async ({ path }) => ({
            contents:
              (await Bun.file(path).text()) +
              "\nexport {ContainerControlClient as FixtureControlClient,SandboxError as FixtureSandboxError,createErrorFromResponse as FixtureCreateError};",
            loader: "js",
          }));
        },
      },
    ],
  });

  expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
  const worker = await built.outputs[0].text();
  const program = `import{createRequire}from'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});const{Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],durableObjects:{STARTUP_FAULT:{className:'StartupFault',useSQLite:true}},script:${JSON.stringify(worker)}}));try{const rows=[];for(const mode of ${JSON.stringify(modes)}){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);rows.push({mode,status:response.status,body:await response.text()});}console.log(JSON.stringify(rows));}finally{await mf.dispose();}`;

  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    windowsHide: true,
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
  const rows = JSON.parse(output);
  console.log(JSON.stringify(rows));
  expect(rows.map((row) => row.mode)).toEqual(modes);

  for (const row of rows) expect(row.status, `${row.mode}: ${row.body}`).toBe(200);
}, 30000);

const fixture = String.raw`
const mode = MODE;
const processReplay=mode.startsWith('process-replay');
const processRestart=mode.startsWith('process-replay-after-restart');
const sdkStartTime=mode==='process-replay-after-restart-sdk-start-time';
const admissionMetadata=mode.startsWith('process-admission-metadata-');
const processNegative=processRestart&&!['process-replay-after-restart','process-replay-after-restart-sdk-start-time'].includes(mode);
let observationStarted;
const observationBegun=new Promise(resolve=>observationStarted=resolve);
let lostInvocationFailure;
const localBucket=mode.endsWith('-local-true')?true:mode.endsWith('-local-false')?false:undefined;
const completionReplay=mode.startsWith('completion-replay');
const replaySuccess=['completion-replay','completion-replay-local-true','completion-replay-local-false','completion-replay-serialized'].includes(mode);
function stepInterruption(){
 const message='Attempt failed due to internal workflows error';
 if(mode.includes('serialized'))return mode.endsWith('-wrong-class')?new TypeError(message):new Error(mode.endsWith('-lookalike')?message+' extra':message);
 return Object.assign(new Error('fixture step commit interrupted'),{name:['completion-generic','completion-replay-generic'].includes(mode)?'Error':'WorkflowInternalError'});
}
let replaying=false;
const completionInterrupted=mode.startsWith('completion-interrupted');
const primitiveCheckpoint=mode.startsWith('primitive-')&&mode!=='primitive-step-output';
const cachedCheckpoint={exitCode:0,logs:{stdout:'cache hit: reusing fixture snapshot',stderr:''},snapshot:{id:'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',dir:'/workspace',localBucket:false},cachePointer:{key:'cache/fixture',createdAt:'2026-10-26T00:00:00.000Z',sizeBytes:4096},cacheHit:true};
const budgetMode = mode.startsWith('preparation-');
const observationMode = mode.startsWith('observe-');
const initializationMode = mode.startsWith('initialize-');
const rawConfigureMode=mode.startsWith('initialize-raw-configure');
const inactiveMessage='Connection closed: this Durable Object instance is no longer active. Reconnect or retry the request.';
let configurations=0;
const freshStubMode = mode.startsWith('observe-fresh-');
let acquisitions=0;let firstAcquisition;let preflights=0;
const terminalMode=mode.startsWith('terminal-');
let backups=0,commits=0,terminalFaults=0;
const previewMode = mode.startsWith('timeout-preview-');
const processDeadlineMode = ['process-timeout','process-read-hang','process-read-late'].includes(mode);
const clockedTimers = previewMode || processDeadlineMode;
let outerExpired=false;
let lateTailSettled=false;
let clock = mode==='preparation-invalid'?NaN:1_000_000;
let outerDeadline;
const timers=new Map();let timerSequence=0;
if(budgetMode||clockedTimers||observationMode||mode==='initialize-raw-configure-expired')Date.now=()=>clock;
if(clockedTimers){
 globalThis.setTimeout=(callback,delay=0)=>{const id=++timerSequence;timers.set(id,{at:clock+Math.max(0,delay),callback});return id;};
 globalThis.clearTimeout=(id)=>{timers.delete(id);};
}
const bytes = new Uint8Array(mode.startsWith("size-")?Number(mode.slice(5)):310_001).map((_, index) => index % 256);
const events=[];
const pendingRpcData=new Set();
let rpcDataCalls=0;
let destroyed=false;
let starts=0;let checkouts=0;let polls=0;let streamCalls=0;let startDisposals=0;let pollDisposals=0;let resolvedPolls=0;let processCommand='';let metadataCalls=0;let metadataReads=0;let metadataDisposals=0;
let metadataArrived;const metadataArrival=new Promise(resolve=>metadataArrived=resolve);
const sdkProcessHost={
 async resolveExecution(){return 'fixture-session';},serializeExecutionContext(value){return value;},getProcessSessionBinding(){return 'fixture-session';},buildExecutionRequestOptions(){return {};},
 createProcessFromDTO:FixtureSdkSandbox.prototype.createProcessFromDTO,
 client:{processes:{async startProcess(command){return {processId:'fixture-process',pid:123,command};},async getProcess(){return {process:{id:'fixture-process',pid:123,command:processCommand,status:replaying?'completed':'running',exitCode:replaying?0:undefined,startTime:new Date(1000000).toISOString()}};}}},
};
function owned(value,kind){if(mode==='plain-process')return value;let disposed=false;return Object.assign(value,{[Symbol.dispose](){assert.equal(disposed,false,'process result must be disposed exactly once');disposed=true;if(kind==='start')startDisposals++;else if(kind==='metadata')metadataDisposals++;else pollDisposals++;events.push(kind+'-dispose');}}); }
const sandbox={
 async waitForConfiguration(){},
 async exec(command){if(command.includes('fixture.invalid/source'))checkouts++;if(command.includes('ci-step.err')){if(mode==='timeout-preview-hang')return new Promise(()=>{});if(mode==='timeout-preview-failure')throw new Error('PRIVATE_RPC_PAYLOAD');if(mode==='timeout-preview-late'){await new Promise(resolve=>setTimeout(resolve,1200));lateTailSettled=true;}}return {exitCode:0,stdout:command.includes('ci-step.out')?'actual stdout canary':command.includes('ci-step.err')?'actual stderr canary':'preview',stderr:''};},
 async startProcess(command){if(mode==='process-admission')assert.equal(processKeys.length,1,'execution ownership must be durable before starting a command');processCommand=command;starts++;return owned(sdkStartTime?await FixtureSdkSandbox.prototype.startProcess.call(sdkProcessHost,command,{autoCleanup:false}):{id:'fixture-process',command,startTime:new Date(1000000),waitForExit:async()=>{streamCalls++;if(mode==='exit-stream-disposed')throw new Error('WritableStream RPC stub was disposed without calling close()');return {exitCode:0};}},'start');},
 async getProcess(id){assert.equal(id,'fixture-process');
 const admission=processKeys.length?await env.BUCKET.get(processKeys[0]):null;
 if(admission&&(await admission.json()).state==='preparing'){
  metadataCalls++;assert.equal(starts,1,'canonical metadata must follow the single acknowledged launch');assert.equal(startDisposals,mode==='plain-process'?0:1,'launch ownership must be released before reading canonical metadata');
  if(admissionMetadata&&mode.endsWith('-missing'))return null;
  if(admissionMetadata&&mode.endsWith('-read-failure'))throw new Error('fixture canonical metadata failed');
  if(admissionMetadata&&mode.endsWith('-late')){await new Promise(resolve=>realSetTimeout(resolve,1100));metadataArrived();}
  metadataReads++;
  return owned(sdkStartTime?await FixtureSdkSandbox.prototype.getProcess.call(sdkProcessHost,id):{id:admissionMetadata&&mode.endsWith('-changed-id')?'other-process':id,command:admissionMetadata&&mode.endsWith('-changed-command')?'different command':processCommand,startTime:new Date(1000000),status:'running'},'metadata');
 }
 if(mode==='preparation-clamp')clock+=6000;polls++;
 if(processReplay&&!replaying){observationStarted();return new Promise(()=>{});}
 if(processReplay&&replaying&&mode.endsWith('-missing-process'))return null;
 if(mode==='process-admission'){assert.equal(processKeys.length,1,'a started command needs durable admission before observation');events.push('observed-process');}
 if(freshStubMode){
  if(mode==='observe-fresh-deadline')clock+=8500;
  const cause=Object.assign(new Error('Connection closed: this Durable Object instance is no longer active. Reconnect or retry the request.'),{retryable:true,...(mode==='observe-fresh-overload'?{overloaded:true}:{})});
  throw new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:mode==='observe-fresh-cancel'?'fixture cancelled actor':mode==='observe-fresh-overload'?'fixture overloaded actor':'fixture inactive original stub',context:{reason:mode==='observe-fresh-cancel'?'sandbox_destroyed':'runtime_replaced',operation:'sandbox.getProcess',phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()},{cause});
 }
 if(observationMode){
  if(polls===1||(mode==='observe-persistent'&&polls===2)){
   if(mode==='observe-deadline')clock+=10001;
   if(mode==='observe-generic')throw new Error('fixture ordinary observation failure');
   if(mode==='observe-raw-inactive')throw new Error(inactiveMessage);
   if(mode==='observe-lookalike')throw Object.assign(new Error('fixture structured lookalike'),{code:'OPERATION_INTERRUPTED',context:{reason:'runtime_replaced',operation:'sandbox.getProcess',phase:'durable_object_call',admitted:'unknown'}});
   throw new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:'fixture structured observation interruption',context:{reason:mode==='observe-wrong-reason'?'sandbox_destroyed':'runtime_replaced',operation:mode==='observe-wrong-operation'?'sandbox.startProcess':'sandbox.getProcess',phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()});
  }
  if(mode==='observe-missing')return null;
  if(mode==='observe-identity'){resolvedPolls++;return owned({id:'other-process',status:'completed',exitCode:0},'poll');}
  if(mode==='observe-nonzero'){resolvedPolls++;return owned({id,status:'failed',exitCode:7},'poll');}
 }
if(mode==='process-read-failure')throw new Error('fixture status RPC failed');if(mode==='process-read-hang')return new Promise(()=>{});if(mode==='process-missing')return null;
 const result=mode==='process-timeout'||previewMode?{id,status:'running'}:mode==='process-nonzero'?{id,status:'failed',exitCode:7}:mode==='process-signal'?{id,status:'killed',exitCode:null}:mode==='process-invalid-zero'?{id,status:'failed',exitCode:0}:mode==='process-unknown'?{id,status:'unknown'}:mode==='process-identity'?{id:'other-process',status:'completed',exitCode:0}:mode==='exit-stream-disposed'&&polls===1?{id,status:'running'}:{id,status:'completed',exitCode:0};
 if(mode==='process-read-late')await new Promise(resolve=>setTimeout(resolve,30));
 resolvedPolls++;return owned(sdkStartTime?await FixtureSdkSandbox.prototype.getProcess.call(sdkProcessHost,id):processReplay?{...result,...(mode.endsWith('-nonzero')?{status:'failed',exitCode:7}:{}),command:processCommand,startTime:new Date(mode.endsWith('-changed-process')?2000000:1000000)}:result,'poll');},
 async createBackup(){const id='aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';await env.BUCKET.put('backups/'+id+'/data.sqsh','fixture archive');await env.BUCKET.put('backups/'+id+'/meta.json',JSON.stringify({id,dir:'/workspace'}));return {id,dir:'/workspace',...(localBucket===undefined?{}:{localBucket})};},
 async listFiles(){const size=mode==='inline'?5:bytes.length+(mode==='length-mismatch'?1:0);return {files:[{absolutePath:'/tmp/ci-step.out',size},{absolutePath:'/tmp/ci-step.err',size}]};},
 async readFile(path,options){
   if(mode==='inline'){assert.equal(options.encoding,'none');return {content:new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('small'));c.close();}})};}
   assert.equal(options.encoding,'none');
   return {content:new ReadableStream({start(c){if(mode==='read-failure')c.error(new Error('fixture source read failed'));else {c.enqueue(bytes);c.close();}}})};
 },
 async readFileStream(){return new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('data: SSE metadata, not raw bytes'));c.close();}});},
 async destroy(){await new Promise(resolve=>setTimeout(resolve,0));destroyed=true;events.push('destroy');},
};
let cleanupCancels=0,physicalName;
const namespace={idFromName:name=>({name}),get(id){assert.equal(id.name,physicalName,'cleanup must freshly address the current physical actor');return {async cancel(){cleanupCancels++;events.push('cancel-fence');await sandbox.destroy();events.push('cancel-ack');}};}};
globalThis.fixtureSandbox=sandbox;
globalThis.fixtureSandboxFactory=(namespace,name,options)=>{
 physicalName=name;
 if(initializationMode){
  const generation=++acquisitions;
  if(generation===1)firstAcquisition={namespace,name,options};
  else{assert.equal(generation,2,'initialization and observation share one replacement allowance');assert.equal(namespace,firstAcquisition.namespace);assert.equal(name,firstAcquisition.name);assert.deepEqual(options,firstAcquisition.options);}
  const interruption=operation=>new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:'fixture initialization interruption',context:{reason:'runtime_replaced',operation,phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()},{cause:Object.assign(new Error('fixture provider reset'),{retryable:true,...(mode==='initialize-overload'?{overloaded:true}:{})})});
  return Object.assign(Object.create(sandbox),{
   async waitForConfiguration(){
    configurations++;
    if(rawConfigureMode&&(generation===1||mode==='initialize-raw-configure-persistent')){
     if(mode==='initialize-raw-configure-expired')clock+=1200000;
     const error=new Error(mode==='initialize-raw-configure-cancel'?'CI sandbox was cancelled':mode==='initialize-raw-configure-lookalike'?'Connection closed: unrelated instance is no longer active.':inactiveMessage);
     if(mode==='initialize-raw-configure-overload')error.overloaded=true;
     throw error;
    }
    if(generation===1&&mode==='initialize-configure')throw interruption('sandbox.configure');
   },
   async exec(command,...args){
    if(command==='test -c /dev/fuse'){
     preflights++;
     if(generation===1&&mode!=='initialize-configure'&&!rawConfigureMode||mode==='initialize-persistent'){
      if(mode==='initialize-raw')throw new Error('Connection closed: this Durable Object instance is no longer active. Reconnect or retry the request.');
      throw interruption(mode==='initialize-wrong-operation'?'sandbox.startProcess':'sandbox.exec');
     }
    }
    if(command.includes('fixture.invalid/source')&&mode==='initialize-checkout'){checkouts++;throw interruption('sandbox.exec');}
    return sandbox.exec(command,...args);
   },
   async startProcess(...args){if(mode==='initialize-start'){starts++;throw interruption('sandbox.startProcess');}return sandbox.startProcess(...args);},
   async getProcess(id){if(mode==='initialize-then-observe'||mode==='initialize-raw-configure-then-observe'){polls++;throw interruption('sandbox.getProcess');}return sandbox.getProcess(id);},
  });
 }
 if(terminalMode){
  const generation=++acquisitions;
  if(generation===1)firstAcquisition={namespace,name,options};
  else {assert.equal(namespace,firstAcquisition.namespace);assert.equal(name,firstAcquisition.name);assert.deepEqual(options,firstAcquisition.options);}
  const fault=()=>{
   terminalFaults++;
   if(mode==='terminal-expired')Date.now=()=>Number.MAX_SAFE_INTEGER;
   if(mode==='terminal-generic')throw new Error('ordinary finalization failure');
   if(mode==='terminal-lookalike')throw new Error(inactiveMessage+' extra');
   if(mode==='terminal-cancel')throw new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:inactiveMessage,context:{reason:'sandbox_destroyed',operation:'sandbox.createBackup',phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()});
   const error=new Error(inactiveMessage);if(mode==='terminal-overload')error.overloaded=true;throw error;
  };
  return Object.assign(Object.create(sandbox),{
   async waitForConfiguration(){configurations++;if(mode==='terminal-spent'&&generation===1||mode==='terminal-configure-fails'&&generation===2)fault();},
   async startProcess(...args){assert.equal(generation,mode==='terminal-spent'?2:1,'fresh finalization must never launch');return sandbox.startProcess(...args);},
   async exec(command,...args){if(generation>1&&command.includes('fixture.invalid/source'))assert.equal(mode,'terminal-spent','fresh finalization must never checkout');if(mode==='terminal-preview'&&generation===1&&command.includes('ci-step.out'))fault();return sandbox.exec(command,...args);},
   async getProcess(id){
    if(generation>1&&mode!=='terminal-spent'){
     polls++;
     if(mode==='terminal-proof-expired')Date.now=()=>Number.MAX_SAFE_INTEGER;
     if(mode==='terminal-missing')return null;
     resolvedPolls++;return owned({id:mode==='terminal-identity'?'other-process':id,status:mode==='terminal-running'?'running':mode==='terminal-unknown'?'unknown':'completed',exitCode:mode==='terminal-exit'?7:0},'poll');
    }
    return sandbox.getProcess(id);
   },
   async createBackup(){backups++;if(mode!=='terminal-preview'&&!mode.startsWith('terminal-logs')&&(generation===1||['terminal-second','terminal-spent'].includes(mode)))fault();return sandbox.createBackup();},
   async persistCiLogs(...args){commits++;const result=await sandbox.persistCiLogs(...args);if(mode==='terminal-logs'&&generation===1)fault();return result;},
  });
 }
 if(!freshStubMode)return sandbox;
 acquisitions++;
 if(acquisitions===1){firstAcquisition={namespace,name,options};return sandbox;}
 assert.equal(acquisitions,2,'observation recovery must acquire exactly one replacement stub');
 assert.equal(namespace,firstAcquisition.namespace,'replacement must use the same namespace');
 assert.equal(name,firstAcquisition.name,'replacement must use the same owned actor identity');
 assert.deepEqual(options,firstAcquisition.options,'replacement must preserve transport/session/timeouts');
 return Object.assign(Object.create(sandbox),{
  async startProcess(){throw new Error('replacement stub must never start a second command');},
  async exec(command,...args){assert.equal(command.includes('fixture.invalid/source'),false,'replacement must never repeat checkout');return sandbox.exec(command,...args);},
  async getProcess(id){
   assert.equal(id,'fixture-process','replacement must retrieve the original process');polls++;
   if(mode==='observe-fresh-deadline')clock+=1501;
   if(mode==='observe-fresh-second-fault')throw new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:'fixture replacement observation failed',context:{reason:'runtime_replaced',operation:'sandbox.getProcess',phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()});
   if(mode==='observe-fresh-missing')return null;
   resolvedPolls++;return owned({id,status:mode==='observe-fresh-nonzero'?'failed':'completed',exitCode:mode==='observe-fresh-nonzero'?7:0},'poll');
  },
 });
};
const objects=new Map();
const completionKeys=[];
const processKeys=[];
const bucket={
 async head(key){return env.BUCKET.head(key);},
 async delete(key){return env.BUCKET.delete(key);},
 async put(key,body,options){
   if(key.startsWith('native-processes/')){if(!processKeys.includes(key))processKeys.push(key);if(mode==='process-admission'){assert.equal(body.includes('fixture-private-value'),false,'process admission must not persist resolved environment values');events.push('process-admitted');}if(mode.endsWith('-claim-race')&&JSON.parse(body).recoveryClaimed&&options.onlyIf.etagMatches)await env.BUCKET.put(key,body);return env.BUCKET.put(key,body,options);}
   if(key.startsWith('native-completions/')){
    completionKeys.push(key);
 if(mode.startsWith('receipt-collision-')){const prior=JSON.parse(body);if(mode==='receipt-collision-deadline')prior.deadlineMs++;else prior.output.logSizes.stdout++;await env.BUCKET.put(key,JSON.stringify(prior));}
    return env.BUCKET.put(key,body,options);
   }
   if(mode==='collision')return null;
   assert.equal(options.onlyIf.etagDoesNotMatch,'*');
   if(mode==='write-failure'||(mode==='partial-write-failure'&&key.endsWith('/stderr')))throw new Error('fixture R2 write failed');
   if(mode==='terminal-logs-partial'&&key.endsWith('/stderr')&&terminalFaults++===0)throw new Error(inactiveMessage);
   await env.BUCKET.put(key,body,options);
   assert.equal(destroyed,false,'actor must remain alive through R2 commit');
   const value=new Uint8Array(await (await env.BUCKET.get(key)).arrayBuffer());
   objects.set(key,value);events.push('put');return {};
 },
 async get(key){
   if(key.startsWith('native-completions/')||key.startsWith('native-processes/')||key.startsWith('backups/'))return env.BUCKET.get(key);
   if(mode==='missing')return null;
   const value=objects.get(key);if(!value)return null;
   return env.BUCKET.get(key);
 },
};
const provider={
 assertSource(){},
 create(){return {getSourceCheckout:async()=>{if(budgetMode)clock+=mode==='preparation-exhausted'?21000:15000;return {kind:'archive',url:'https://fixture.invalid/source'};},startStepNotification:async()=>null};},
};
let checkpoint,restoredOutputs=0;
class Fixture extends CIWorkflow{
 static getProvider(){return provider;}
 async pipeline(event,step,ci){
   const output=await ci.runner({name:replaying&&(mode==='completion-replay-wrong-label'||mode==='process-replay-after-restart-wrong-label')?'other-unit-output':'large-unit-output',command:replaying&&(mode==='completion-replay-wrong-command'||mode==='process-replay-after-restart-wrong-command')?'changed trusted fixture':'trusted fixture',env:mode==='process-admission'?{PRIVATE_DATA:'fixture-private-value'}:replaying&&(mode==='completion-replay-wrong-env'||mode==='process-replay-after-restart-wrong-env')?{CHANGED:'1'}:undefined,config:budgetMode?{timeout:30000,commandTimeoutMs:10000}:{...((completionReplay||processReplay)&&mode!=='completion-replay-default-retries'?{retries:{limit:0,delay:0}}:{}),commandTimeoutMs:admissionMetadata&&mode.endsWith('-late')?1000:previewMode||mode==='process-timeout'||mode==='process-read-hang'||mode==='process-read-late'?5:10000}});
   restoredOutputs++;
   if(mode==='primitive-cache-hit'){assert.equal(output.exitCode,0);assert.deepEqual(output.logs,cachedCheckpoint.logs);assert.deepEqual(output.snapshot,cachedCheckpoint.snapshot);assert.deepEqual(output.cachePointer,cachedCheckpoint.cachePointer);assert.equal(output.cacheHit,true);assert.equal(typeof output.runner,'function');return;}
   assert.deepEqual(output.snapshot,{id:'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',dir:'/workspace',...(localBucket===undefined?{}:{localBucket})},'snapshot restore metadata must survive ordinary and recovered output');
   for(const log of [output.logs.stdout,output.logs.stderr]){
     if(mode==='inline')assert.equal(await new Response(log).text(),'small');
     else assert.equal(Buffer.compare(Buffer.from(await new Response(log).arrayBuffer()),Buffer.from(bytes)),0);
   }
   assert.equal(typeof output.runner,'function');
 }
}
const step={async do(name,config,callback){
 if(primitiveCheckpoint){
   const malformed={...cachedCheckpoint};
   if(mode==='primitive-invalid-json')return '{';
   if(mode==='primitive-null')return 'null';
   if(mode==='primitive-number')return '1';
   if(mode==='primitive-empty-object')return '{}';
   if(mode==='primitive-non-string')return cachedCheckpoint;
   if(mode==='primitive-extra-field')malformed.unexpected=true;
   if(mode==='primitive-log-type')malformed.logs={stdout:42,stderr:''};
   if(mode==='primitive-exit-type')malformed.exitCode='0';
   return JSON.stringify(malformed);
 }
 if(budgetMode)outerDeadline=Date.now()+config.timeout;
 let timer;
 if(replaying&&completionReplay)throw stepInterruption();
 if(processRestart&&replaying&&!name.endsWith('-resume'))throw new Error(mode.endsWith('-generic')?'fixture ordinary workflow rejection':'Attempt failed due to internal workflows error');
 if(mode==='completion-before-callback')throw Object.assign(new Error('fixture step commit interrupted before callback'),{name:'WorkflowInternalError'});
 const operation=callback({attempt:(mode==='completion-replay-wrong-attempt'||mode==='process-replay-after-restart-wrong-attempt')?2:1});
 if(processReplay&&!replaying){
   await observationBegun;
   if(processRestart){void operation.catch(error=>{lostInvocationFailure=error;});return new Promise(()=>{});}
   replaying=true;
   void operation.catch(error=>{lostInvocationFailure=error;});
   throw new Error('Attempt failed due to internal workflows error');
 }
 const output=await(previewMode?Promise.race([operation,new Promise((_,reject)=>{timer=setTimeout(()=>{outerExpired=true;reject(new Error('fixture outer step expired'));},1500);})]).finally(()=>clearTimeout(timer)):operation);
 if(budgetMode)assert.ok(Date.now()<outerDeadline,'callback must finish before its finite outer deadline');
 // A direct byte stream has a separate supported platform path; nested state
 // uses structured serialization and must contain no stream instances.
 assert.equal(typeof output,'string','runner step must checkpoint a primitive JSON string');
 if(mode.startsWith('rpc-data-lifetimes'))assert.equal(pendingRpcData.size,0,'all RPC data results must be disposed before checkpoint');
 checkpoint=JSON.parse(output);
 if(mode.startsWith('completion-')&&!completionReplay){
   if(!completionInterrupted){
   assert.equal(completionKeys.length,1,'success must commit exactly one immutable completion record');
   const key=completionKeys[0];
   const receipt=await(await env.BUCKET.get(key)).json();
   if(mode==='completion-missing')await env.BUCKET.delete(key);
   if(mode==='completion-wrong-identity'){receipt.identity='b'.repeat(64);await env.BUCKET.put(key,JSON.stringify(receipt));}
   if(mode==='completion-invalid-local'){receipt.output.snapshot.localBucket='true';await env.BUCKET.put(key,JSON.stringify(receipt));}
   if(mode==='completion-nonzero'){receipt.output.exitCode=7;await env.BUCKET.put(key,JSON.stringify(receipt));}
   if(mode==='completion-log-tampered'){const original=await env.BUCKET.get(receipt.output.logs.stdout.r2Key);const bytes=new Uint8Array(await original.arrayBuffer());bytes[Math.floor(bytes.length/2)]^=1;await env.BUCKET.put(receipt.output.logs.stdout.r2Key,bytes);}
   if(mode==='completion-expired')Date.now=()=>Number.MAX_SAFE_INTEGER;
   if(mode==='completion-snapshot-missing')await env.BUCKET.delete('backups/'+receipt.output.snapshot.id+'/data.sqsh');
   }
   throw stepInterruption();
 }
 assert.equal(destroyed,true,'container cleanup must complete before checkpoint');assert.equal(cleanupCancels,1,'one fresh cancellation must fence and acknowledge teardown before checkpoint');assert.ok(events.includes('cancel-ack'));
 events.push('checkpoint');return output;
}};
sandbox.env={BACKUP_BUCKET:bucket};
assert.equal(typeof CiSandbox.prototype.persistCiLogs,'function','recovery must retain immutable logs before checkpoint');
sandbox.persistCiLogs=CiSandbox.prototype.persistCiLogs.bind(sandbox);
if(mode.startsWith('rpc-data-lifetimes'))for(const name of ['exec','restoreBackup','createBackup','persistCiLogs']){
 const call=sandbox[name];if(typeof call!=='function')continue;
 sandbox[name]=async(...args)=>{
  const value=await call.apply(sandbox,args);if(value===null||typeof value!=='object')return value;
  const owned={...value};pendingRpcData.add(owned);rpcDataCalls++;
  if(mode==='rpc-data-lifetimes-read-failure'&&name==='createBackup')Object.defineProperty(owned,'id',{enumerable:true,get(){throw new Error('fixture snapshot getter rejected');}});
  Object.defineProperty(owned,Symbol.dispose,{value(){assert.ok(pendingRpcData.delete(owned),'RPC data result disposed exactly once');}});
  return owned;
 };
}
const execute=async()=>{
const workflow=new Fixture(ctx, {BACKUP_BUCKET:bucket,SANDBOX:namespace});
let failure;
const event={instanceId:'fixture-'+mode,payload:{provider:'fixture',providerData:{},owner:'fixed',repo:'repo',sha:'a'.repeat(40),ref:'refs/heads/main',event:{type:'push'}}};
try{const execution=workflow.run(event,step);
if(processRestart){
 void execution.catch(error=>{lostInvocationFailure=error;});
 await observationBegun;replaying=true;
 if(mode.endsWith('-wrong-run'))event.instanceId+='-other';
 if(mode.endsWith('-wrong-source'))event.payload.sha='b'.repeat(40);
 const key=processKeys[0];
 if(mode.endsWith('-missing-admission'))await env.BUCKET.delete(key);
 else if(/-(?:wrong-hash|wrong-actor|changed-deadline|claimed)$/.test(mode)){
  const record=await(await env.BUCKET.get(key)).json();
  if(mode.endsWith('-wrong-hash'))record.identity='b'.repeat(64);
  if(mode.endsWith('-wrong-actor'))record.process.physicalRunnerId='ci1-c-'+'b'.repeat(56);
  if(mode.endsWith('-changed-deadline'))record.deadlineMs++;
  if(mode.endsWith('-claimed'))record.recoveryClaimed=true;
  await env.BUCKET.put(key,JSON.stringify(record));
 }
 if(mode.endsWith('-expired'))Date.now=()=>Number.MAX_SAFE_INTEGER;
 await new Fixture(ctx,{BACKUP_BUCKET:bucket,SANDBOX:namespace}).run(event,step);
}else await execution;
if(completionReplay){
 replaying=true;
 if(['completion-replay-expired','completion-replay-serialized-expired'].includes(mode))Date.now=()=>Number.MAX_SAFE_INTEGER;
 if(mode==='completion-replay-wrong-run')event.instanceId+='-other';
 if(mode==='completion-replay-wrong-source')event.payload.sha='b'.repeat(40);
 if(['completion-replay-missing','completion-replay-serialized-missing'].includes(mode))await env.BUCKET.delete(completionKeys[0]);
 if(mode==='completion-replay-old-version'){const o=await env.BUCKET.get(completionKeys[0]);const receipt=await o.json();receipt.version=1;await env.BUCKET.put(completionKeys[0],JSON.stringify(receipt));}
 if(mode==='completion-replay-nonfinite-deadline'){const o=await env.BUCKET.get(completionKeys[0]);const receipt=await o.json();receipt.deadlineMs=null;await env.BUCKET.put(completionKeys[0],JSON.stringify(receipt));}
 if(mode==='completion-replay-deadline-tampered'){const o=await env.BUCKET.get(completionKeys[0]);const receipt=await o.json();receipt.deadlineMs++;await env.BUCKET.put(completionKeys[0],JSON.stringify(receipt));}
 if(mode==='completion-replay-wrong-hash'){const o=await env.BUCKET.get(completionKeys[0]);const receipt=await o.json();receipt.identity='b'.repeat(64);await env.BUCKET.put(completionKeys[0],JSON.stringify(receipt));}
 if(['completion-replay-log-tampered','completion-replay-serialized-log-tampered'].includes(mode)){const key=[...objects.keys()][0];await env.BUCKET.put(key,'tampered');}
 if(mode==='completion-replay-snapshot-missing')await env.BUCKET.delete('backups/aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa/data.sqsh');
 await new Fixture(ctx, {BACKUP_BUCKET:bucket,SANDBOX:namespace}).run(event,step);
}}catch(error){failure=error;}
assert.equal(metadataDisposals,mode==='plain-process'?0:metadataReads,'canonical metadata results must be disposed before publication');
if(admissionMetadata){
 if(mode.endsWith('-late')){await metadataArrival;await new Promise(resolve=>realSetTimeout(resolve,0));assert.equal(metadataReads,1);assert.equal(metadataDisposals,1,'late canonical metadata must release its capability after the deadline');}
 assert.ok(failure,'invalid canonical metadata must fail closed');assert.match(failure.message,mode.endsWith('-late')?/CI sandbox deadline expired/:mode.endsWith('-read-failure')?/fixture canonical metadata failed/:/CI process admission identity mismatch/);
 assert.equal(metadataCalls,1);assert.equal(starts,1);assert.equal(checkouts,1);assert.equal(completionKeys.length,0);assert.equal(objects.size,0);assert.equal(restoredOutputs,0);
 const admission=await env.BUCKET.get(processKeys[0]);assert.equal((await admission.json()).state,'preparing','unconfirmed metadata cannot become a started admission');
 assert.equal(cleanupCancels,1);assert.equal(destroyed,true);return Response.json({mode,failed:true,starts,checkouts,metadataCalls,destroyed});
}
if(processReplay){
 if(processNegative){
  assert.ok(failure,'unconfirmed process recovery must fail closed');
  const observed=mode.endsWith('-missing-process')||mode.endsWith('-changed-process')||mode.endsWith('-nonzero');
  if(observed){assert.match(failure.message,mode.endsWith('-nonzero')?/failed with exit code 7/:mode.endsWith('-missing-process')?/CI process missing/:/Running process identity changed/);assert.doesNotMatch(failure.message,/Attempt failed due to internal workflows error/);}
  else if(mode.endsWith('-claim-race'))assert.match(failure.message,/Running process recovery already claimed/);
  else assert.match(failure.message,mode.endsWith('-generic')?/fixture ordinary workflow rejection/:/Attempt failed due to internal workflows error/);
  if(!observed)assert.equal(polls,1,'invalid admission cannot observe a process');
  assert.equal(starts,1);assert.equal(checkouts,1);assert.equal(completionKeys.length,0);assert.equal(objects.size,0);
  if(!destroyed)await namespace.get(namespace.idFromName(physicalName)).cancel();
  assert.equal(cleanupCancels,1);assert.equal(destroyed,true);
  return Response.json({mode,failed:true,starts,checkouts,polls,destroyed});
 }
 assert.equal(failure,undefined,failure?.stack);
 assert.equal(lostInvocationFailure,undefined,'the lost callback must never complete a second execution');
 assert.equal(starts,1,'recovery must not launch the command again');assert.equal(checkouts,1,'recovery must not repeat checkout');
 assert.equal(metadataReads,1,'recovery must reuse the one canonical process admission');
 assert.equal(restoredOutputs,1);assert.equal(completionKeys.length,1);assert.equal(cleanupCancels,1);assert.equal(destroyed,true);
 return Response.json({mode,starts,checkouts,restoredOutputs,destroyed});
}
if(mode==='process-admission'){
 assert.equal(failure,undefined,failure?.stack);
 assert.equal(starts,1);assert.equal(checkouts,1);assert.equal(processKeys.length,1);
 assert.equal(metadataReads,1);
 assert.ok(events.indexOf('process-admitted')<events.indexOf('observed-process'));
 assert.equal(destroyed,true);assert.equal(cleanupCancels,1);
 return Response.json({mode,starts,checkouts,admissions:processKeys.length,destroyed});
}
if(mode.startsWith('rpc-data-lifetimes')){
 if(mode==='rpc-data-lifetimes-read-failure')assert.match(failure?.message??'',/fixture snapshot getter rejected/);
 else assert.equal(failure,undefined,failure?.stack);
 assert.ok(rpcDataCalls>=(failure?5:6),'exercise preflight, checkout, previews, snapshot and log RPC results');
 assert.equal(pendingRpcData.size,0,'RPC data must be released on successful or rejected reads');assert.equal(starts,1);assert.equal(checkouts,1);
 return Response.json({mode,rpcDataCalls,destroyed});
}
if(primitiveCheckpoint){
 assert.equal(starts,0,'checkpoint restoration must not execute the command callback');assert.equal(checkouts,0);assert.equal(cleanupCancels,0);assert.equal(objects.size,0);assert.equal(completionKeys.length,0);
 if(mode==='primitive-cache-hit'){assert.equal(failure,undefined,failure?.stack);assert.equal(restoredOutputs,1);}
 else {assert.ok(failure instanceof Error,'malformed checkpoint must fail closed before domain output');assert.equal(failure.name,'CiRunnerFailure');assert.ok(failure.cause instanceof Error);assert.equal(failure.cause.name,mode==='primitive-invalid-json'?'SyntaxError':'ZodError');assert.equal(restoredOutputs,0,'invalid checkpoint cannot reach pipeline domain consumers');}
 return Response.json({mode,failed:Boolean(failure),starts,checkouts,destroyed});
}
if(initializationMode){
 const rawBlocked=['initialize-raw-configure-overload','initialize-raw-configure-cancel','initialize-raw-configure-lookalike','initialize-raw-configure-expired'].includes(mode);
 const blocked=rawBlocked||['initialize-overload','initialize-raw','initialize-wrong-operation'].includes(mode);
 const rawFailed=rawBlocked||['initialize-raw-configure-persistent','initialize-raw-configure-then-observe'].includes(mode);
 const failed=rawFailed||blocked||['initialize-persistent','initialize-then-observe','initialize-checkout','initialize-start'].includes(mode);
 assert.equal(acquisitions,blocked?1:2,'only trusted initialization may bind one fresh same-actor handle');
 assert.equal(preflights,rawConfigureMode?(rawBlocked||mode==='initialize-raw-configure-persistent'?0:1):mode==='initialize-configure'?1:blocked?1:2);
 assert.equal(starts,blocked||mode==='initialize-persistent'||mode==='initialize-checkout'||mode==='initialize-raw-configure-persistent'?0:1,'initialization must never replay a candidate command');
 assert.equal(checkouts,blocked||mode==='initialize-persistent'||mode==='initialize-raw-configure-persistent'?0:1,'checkout remains outside initialization recovery');
 if(rawConfigureMode)assert.equal(configurations,blocked?1:2,'only one fresh configuration handle is permitted');
 assert.equal(destroyed,mode!=='initialize-raw-configure-expired');
 assert.equal(cleanupCancels,mode==='initialize-raw-configure-expired'?0:1,'expired configuration cannot initiate late cleanup; every unexpired invocation requires cancellation ACK');
 assert.equal(Boolean(failure),failed,failure?.stack);
 assert.equal(objects.size,failed?0:2,'failed recovery cannot publish success');
 if(mode==='initialize-then-observe'||mode==='initialize-raw-configure-then-observe')assert.equal(polls,1,'initialization consumes the existing observation allowance');
 return Response.json({mode,acquisitions,preflights,starts,checkouts,polls,failed,destroyed});
}
if(terminalMode){
 const blocked=['terminal-overload','terminal-cancel','terminal-generic','terminal-lookalike','terminal-expired'].includes(mode);
 const failed=blocked||['terminal-missing','terminal-identity','terminal-running','terminal-unknown','terminal-exit','terminal-second','terminal-spent','terminal-configure-fails','terminal-proof-expired'].includes(mode);
 assert.equal(acquisitions,blocked?1:2,'all stages share exactly one same-actor recovery');
 assert.equal(starts,1);assert.equal(checkouts,1,'terminal recovery cannot replay checkout or launch');
 assert.equal(Boolean(failure),failed,failure?.stack);
 if(mode.startsWith('terminal-logs')){assert.equal(backups,1,'acknowledged snapshot must never be recreated after log failure');assert.equal(commits,2);}
 if(!failed){assert.equal(polls,2,'fresh finalization must independently reobserve original completion');assert.equal(objects.size,2);assert.equal(destroyed,true);}
}
if(freshStubMode){
 const noReconnect=['observe-fresh-cancel','observe-fresh-overload'].includes(mode);
 assert.equal(acquisitions,noReconnect?1:2,'inactive observation must acquire a distinct fresh stub; cancellation and overload must not reconnect');
 assert.equal(polls,noReconnect?1:2,'fresh-stub recovery has one observation allowance');
 assert.equal(checkouts,1,'fresh-stub recovery must not repeat checkout');
 assert.equal(starts,1,'fresh-stub recovery must not restart the original command');
}
if(completionReplay){assert.equal(checkouts,1,'replay recovery must never repeat source checkout');assert.equal(events.filter(event=>event==='destroy').length,1,'replay recovery must not wake or destroy the completed actor again');}
if(previewMode)assert.equal(outerExpired,false,'timeout feedback must settle before the finite outer step clock');
if(mode==='timeout-preview-late'){await new Promise(resolve=>setTimeout(resolve,250));assert.equal(lateTailSettled,true,'late plain exec response must settle without retaining capabilities');}
if(mode==='process-read-late')await new Promise(resolve=>setTimeout(resolve,50));
assert.equal(starts,mode==='completion-before-callback'||mode==='preparation-exhausted'||mode==='preparation-invalid'?0:1,'a status wait must never restart the command');
assert.equal(startDisposals,mode==='completion-before-callback'||mode==='plain-process'||mode==='preparation-exhausted'||mode==='preparation-invalid'?0:1,'start result capabilities must be released');
assert.equal(pollDisposals,mode==='plain-process'?0:resolvedPolls,'every resolved poll result must release its capabilities, including after timeout');
if(['primitive-step-output','terminal-backup','terminal-preview','terminal-logs','terminal-logs-partial','observe-raw-inactive','completion-serialized'].includes(mode)||replaySuccess||completionInterrupted||mode==='observe-once'||mode==='observe-fresh-success'||mode.startsWith('size-')||mode.startsWith('ok')||mode==='inline'||mode==='exit-stream-disposed'||mode==='plain-process'){
 assert.equal(failure,undefined,failure?.stack);
 if(completionReplay||completionInterrupted)assert.equal(completionKeys.length,1,'recovery must use exactly one committed completion record');
 if(mode==='observe-once'){assert.equal(polls,2);assert.equal(checkouts,1,'observation recovery must not replay checkout');}
 if(mode==='exit-stream-disposed'){assert.equal(streamCalls,0);assert.equal(polls,2);}
 assert.equal(objects.size,2);assert.equal(destroyed,true);
 if(!completionInterrupted&&mode!=='completion-serialized')assert.ok(events.indexOf('destroy')<events.indexOf('checkpoint'));
 else assert.equal(events.includes('checkpoint'),false,'recovery must not repeat the failed step callback');
 assert.ok(events.lastIndexOf('put')<events.indexOf('destroy'),'both log commits must precede actor destruction');
 for(const value of objects.values())assert.equal(Buffer.compare(Buffer.from(value),Buffer.from(mode==='inline'?new TextEncoder().encode('small'):bytes)),0);
 assert.equal(typeof checkpoint.logs.stdout.r2Key,'string');
}else{
 assert.ok(failure,'storage failure must fail closed');const neverStarted=['completion-before-callback','preparation-exhausted','preparation-invalid'].includes(mode);const cleanupExpired=['terminal-expired','terminal-proof-expired','preparation-clamp'].includes(mode);assert.equal(destroyed,!neverStarted&&!cleanupExpired,'only admitted cleanup before invocation expiry may acknowledge teardown');assert.equal(cleanupCancels,neverStarted||cleanupExpired?0:1,'no late cleanup RPC may start after expiry; unexpired failures still require cancellation ACK');if(neverStarted){assert.equal(starts,0,'preparation rejection cannot launch commands');assert.equal(checkouts,0,'preparation rejection cannot fetch source');assert.equal(objects.size,0,'preparation rejection cannot publish output');}
 if(mode.includes('serialized')){assert.equal(failure.name,'CiRunnerFailure');assert.equal(failure.output,mode.endsWith('-lookalike')?'Attempt failed due to internal workflows error extra':'Attempt failed due to internal workflows error','invalid completion must retain the original step error');}
 else if(mode.startsWith('completion-'))assert.match(failure.message,/fixture step commit interrupted/,'invalid completion must retain the original step error');
 if(budgetMode){assert.match(failure.message,mode==='preparation-invalid'?/deadline must be finite/:mode==='preparation-exhausted'?/budget exhausted before process launch/:/completion timed out/);if(mode!=='preparation-invalid')assert.ok(Date.now()<outerDeadline,'budget failure and cleanup must precede outer expiry');assert.equal(objects.size,0,'late command success must not publish output');}
 if(observationMode&&!freshStubMode){
  assert.equal(polls,['observe-generic','observe-raw-inactive','observe-lookalike','observe-wrong-reason','observe-wrong-operation','observe-deadline'].includes(mode)?1:2,'only one exact interrupted query may be observed again');
  assert.equal(checkouts,1,'failed observation recovery must not replay checkout');
  if(mode==='observe-raw-inactive')assert.equal(failure.output,inactiveMessage);
  else if(mode==='observe-generic')assert.match(failure.message,/ordinary observation failure/);
  else if(mode==='observe-lookalike')assert.match(failure.message,/structured lookalike/);
  else if(mode==='observe-missing')assert.match(failure.message,/CI process missing/);
  else if(mode==='observe-identity')assert.match(failure.message,/CI process identity mismatch/);
  else if(mode==='observe-nonzero')assert.match(failure.message,/exit code 7/);
  else if(mode==='observe-deadline')assert.ok(clock>=1010000);
  else assert.match(failure.message,/structured observation interruption/);
  assert.equal(objects.size,0,'unconfirmed process completion cannot create passing output');
 }
 if(freshStubMode){
  assert.equal(objects.size,0,'unconfirmed replacement result cannot publish passing output');
  assert.match(failure.message,mode==='observe-fresh-missing'?/CI process missing/:mode==='observe-fresh-nonzero'?/exit code 7/:mode==='observe-fresh-second-fault'?/replacement observation failed/:mode==='observe-fresh-deadline'?/exit code 124/:mode==='observe-fresh-cancel'?/cancelled actor/:/overloaded actor/);
 }
 if(mode.startsWith('receipt-collision-'))assert.match(failure.message,/receipt collision/);
 if(mode==='collision')assert.match(failure.message,/already exists/);
 if(mode==='missing')assert.match(failure.message,/missing/i);
 if(mode==='write-failure'||mode==='partial-write-failure')assert.match(failure.message,/write failed/i);
 if(mode==='partial-write-failure')assert.equal(objects.size,1);
 if(mode==='read-failure')assert.match(failure.message,/read failed/i);
 if(mode==='process-read-failure'){assert.match(failure.message,/status RPC failed/i);assert.doesNotMatch(failure.message,/exit code 124/);}
 if(mode==='process-missing'||mode==='process-identity'){
  const expectedReason=mode==='process-missing'?'missing':'identity mismatch';
  const match=/CI process (missing|identity mismatch): (\{[^\n]+\})/.exec(failure.message);
  assert.ok(match,'process failures must distinguish missing state from identity mismatch');
  assert.equal(match[1],expectedReason);
  const detail=JSON.parse(match[2]);
  assert.ok(Number.isSafeInteger(detail.elapsedMs)&&detail.elapsedMs>=0&&detail.elapsedMs<=10000);
  assert.deepEqual({...detail,elapsedMs:0},{polls:1,elapsedMs:0,expectedId:'fixture-process',observedIdType:mode==='process-missing'?'absent':'string'});
 }
 if(mode==='process-timeout'||mode==='process-read-hang'||mode==='process-read-late'||mode==='preparation-clamp'){
  if(processDeadlineMode)assert.ok(polls>0,'deadline fixture must reach process observation');
  assert.match(failure.message,/failed with exit code 124/);
  assert.match(failure.message,/actual stdout canary/);
  assert.match(failure.message,/actual stderr canary/);
  assert.match(failure.message,/CI process completion timed out/);
 }
 if(previewMode){assert.match(failure.message,/failed with exit code 124/);assert.match(failure.message,/actual stdout canary/);assert.match(failure.message,mode==='timeout-preview-failure'?/preview RPC failed/:/preview deadline exceeded/);assert.match(failure.message,/CI process completion timed out/);assert.doesNotMatch(failure.message,/PRIVATE_RPC_PAYLOAD/);}
 if(mode.startsWith('process-'))assert.equal(objects.size,0,'unconfirmed completion must not publish logs or a snapshot');
}
return Response.json({mode,destroyed,objects:objects.size,events});
};
if(!clockedTimers)return await execute();
let settled=false;
const execution=execute();
execution.then(()=>{settled=true;},()=>{settled=true;});
while(!settled){
 await new Promise(resolve=>realSetTimeout(resolve,0));
 if(settled)break;
 if(processDeadlineMode&&polls===0)continue;
 const next=[...timers].sort((left,right)=>left[1].at-right[1].at)[0];
 assert.ok(next,'unfinished preview execution must have a scheduled clock event');
 timers.delete(next[0]);clock=next[1].at;next[1].callback();
}
return await execution;
`;

for (const modes of [
  ["process-replay-after-restart"],
  ["process-replay-after-restart-sdk-start-time"],
  [
    "process-admission-metadata-missing",
    "process-admission-metadata-changed-id",
    "process-admission-metadata-changed-command",
    "process-admission-metadata-read-failure",
  ],
  ["process-admission-metadata-late"],
  [
    "process-replay-after-restart-wrong-source",
    "process-replay-after-restart-wrong-command",
    "process-replay-after-restart-wrong-env",
    "process-replay-after-restart-wrong-attempt",
    "process-replay-after-restart-wrong-run",
    "process-replay-after-restart-wrong-label",
  ],
  [
    "process-replay-after-restart-wrong-hash",
    "process-replay-after-restart-wrong-actor",
    "process-replay-after-restart-changed-deadline",
    "process-replay-after-restart-missing-admission",
    "process-replay-after-restart-expired",
    "process-replay-after-restart-claimed",
    "process-replay-after-restart-claim-race",
  ],
  [
    "process-replay-after-restart-missing-process",
    "process-replay-after-restart-changed-process",
    "process-replay-after-restart-nonzero",
    "process-replay-after-restart-generic",
  ],
  ["process-replay-serialized"],
  ["process-admission"],
  ["rpc-data-lifetimes"],
  ["rpc-data-lifetimes-read-failure"],
  ["terminal-backup"],
  ["terminal-preview"],
  ["terminal-logs"],
  ["terminal-logs-partial"],
  ["terminal-missing", "terminal-identity"],
  ["terminal-running", "terminal-unknown"],
  ["terminal-exit", "terminal-second"],
  [
    "terminal-overload",
    "terminal-cancel",
    "terminal-generic",
    "terminal-lookalike",
    "terminal-expired",
  ],
  ["terminal-spent"],
  ["terminal-configure-fails", "terminal-proof-expired"],
  ["initialize-configure"],
  ["initialize-raw-configure"],
  ["initialize-raw-configure-persistent"],
  ["initialize-raw-configure-then-observe"],
  [
    "initialize-raw-configure-overload",
    "initialize-raw-configure-cancel",
    "initialize-raw-configure-lookalike",
    "initialize-raw-configure-expired",
  ],
  ["observe-raw-inactive"],
  ["initialize-preflight"],
  ["initialize-persistent"],
  ["initialize-then-observe"],
  ["initialize-overload", "initialize-raw", "initialize-wrong-operation"],
  ["initialize-checkout"],
  ["initialize-start"],
  ["primitive-step-output"],
  [
    "primitive-cache-hit",
    "primitive-invalid-json",
    "primitive-null",
    "primitive-number",
    "primitive-empty-object",
    "primitive-non-string",
    "primitive-extra-field",
    "primitive-log-type",
    "primitive-exit-type",
  ],
  ["completion-replay", "completion-replay-local-true", "completion-replay-local-false"],
  ["completion-serialized"],
  ["completion-replay-serialized"],
  [
    "completion-replay-serialized-lookalike",
    "completion-replay-serialized-wrong-class",
    "completion-replay-serialized-missing",
    "completion-replay-serialized-expired",
    "completion-replay-serialized-log-tampered",
  ],
  [
    "completion-replay-wrong-run",
    "completion-replay-wrong-label",
    "completion-replay-old-version",
    "completion-replay-nonfinite-deadline",
    "completion-replay-wrong-command",
    "completion-replay-wrong-env",
    "completion-replay-wrong-source",
    "completion-replay-deadline-tampered",
    "completion-replay-wrong-attempt",
    "completion-replay-expired",
    "completion-replay-missing",
    "completion-replay-wrong-hash",
    "completion-replay-log-tampered",
    "completion-replay-snapshot-missing",
    "completion-replay-generic",
    "completion-replay-default-retries",
  ],
  [
    "completion-interrupted",
    "completion-interrupted-local-true",
    "completion-interrupted-local-false",
  ],
  ["ok-local-true", "ok-local-false"],
  ["receipt-collision-deadline", "receipt-collision-output"],
  [
    "completion-missing",
    "completion-wrong-identity",
    "completion-nonzero",
    "completion-invalid-local",
    "completion-log-tampered",
    "completion-snapshot-missing",
    "completion-generic",
    "completion-before-callback",
    "completion-expired",
  ],
  ["observe-once"],
  ["observe-fresh-success"],
  ["observe-fresh-nonzero"],
  ["observe-fresh-missing"],
  ["observe-fresh-second-fault"],
  ["observe-fresh-deadline"],
  ["observe-fresh-cancel"],
  ["observe-fresh-overload"],
  [
    "observe-persistent",
    "observe-generic",
    "observe-lookalike",
    "observe-missing",
    "observe-identity",
  ],
  ["observe-nonzero", "observe-wrong-reason", "observe-wrong-operation", "observe-deadline"],
  ["timeout-preview-hang"],
  ["timeout-preview-failure"],
  ["timeout-preview-late"],
  ["preparation-exhausted"],
  ["preparation-clamp"],
  ["preparation-invalid"],
  [
    "ok",
    "inline",
    "size-0",
    "size-299999",
    "size-300000",
    "size-300001",
    "collision",
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

    const source = `import {OperationInterruptedError,FixtureSdkSandbox} from '@cloudflare/sandbox';\nimport assert from 'node:assert/strict';\nimport {Buffer} from 'node:buffer';\nimport {CIWorkflow} from ${JSON.stringify(sdk)};\nimport {CiSandbox} from ${JSON.stringify(fileURLToPath(new URL("../node_modules/@cloudflare/ci/src/ci/sandbox.ts", import.meta.url)))};\nexport default {async fetch(request,env,ctx){const realNow=Date.now,realSetTimeout=globalThis.setTimeout,realClearTimeout=globalThis.clearTimeout;try {\n${fixture.replace("MODE", "new URL(request.url).pathname.slice(1)")}\n}catch(error){return new Response(error.stack,{status:500});}finally{Date.now=realNow;globalThis.setTimeout=realSetTimeout;globalThis.clearTimeout=realClearTimeout;}}};`;

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
            build.onResolve({ filter: /^cloudflare:workers$/ }, (args) =>
              args.importer.includes("@cloudflare/ci/")
                ? { path: "base", namespace: "stub" }
                : { path: "cloudflare:workers", external: true },
            );
            build.onLoad({ filter: /.*/, namespace: "stub" }, ({ path }) => ({
              contents:
                path === "sandbox"
                  ? `export {OperationInterruptedError,Sandbox as FixtureSdkSandbox} from ${JSON.stringify(fileURLToPath(new URL("../node_modules/@cloudflare/sandbox/dist/index.js", import.meta.url)))};export class Sandbox{};export const getSandbox=(...args)=>globalThis.fixtureSandboxFactory(...args);`
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
const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BUCKET'],script:${JSON.stringify(worker)}}));
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
      expect(JSON.parse(result.body).destroyed).toBe(
        !(result.mode.startsWith("primitive-") && result.mode !== "primitive-step-output") &&
          ![
            "completion-before-callback",
            "preparation-exhausted",
            "preparation-invalid",
            "initialize-raw-configure-expired",
            "terminal-expired",
            "terminal-proof-expired",
            "preparation-clamp",
          ].includes(result.mode),
      );
    }
  }, 30000);
}

test("actor RPC reconciles identical immutable log commits and partial pairs", async () => {
  const actorSource = fileURLToPath(
    new URL("../node_modules/@cloudflare/ci/src/ci/sandbox.ts", import.meta.url),
  );

  const source = `import{CiSandbox}from ${JSON.stringify(actorSource)};
const size=350126;const prefix='logs/fixture-rpc/native/ci1-c-'+ 'a'.repeat(56);
export class Actor extends CiSandbox{
 mode='normal';async setMode(mode){this.mode=mode;}
 async listFiles(){return{files:['out','err'].map(x=>({absolutePath:'/tmp/ci-step.'+x,size}))};}
 async readFile(){const mode=this.mode;return{content:new ReadableStream({start(c){const bytes=new Uint8Array(mode==='truncated'?size-1:size).map((_,i)=>i%256);if(mode==='different')bytes[0]=42;c.enqueue(bytes);c.close();}})};}
}
export default{async fetch(request,env){
 const actor=env.ACTOR.getByName('logs');
 const result=await actor.persistCiLogs(prefix);
 for(const stream of ['stdout','stderr']){
  if(typeof result.logs[stream].r2Key!=='string')throw Error('RPC must return only persisted handles');
  const value=await env.BACKUP_BUCKET.get(result.logs[stream].r2Key);
  if(!value||value.size!==size)throw Error('RPC returned before exact log object committed');
  const bytes=new Uint8Array(await value.arrayBuffer());
  if(bytes.some((v,i)=>v!==i%256))throw Error('Full log bytes differ');
 }
 const before=await env.BACKUP_BUCKET.head(prefix+'/stdout');
 await actor.persistCiLogs(prefix);
 const after=await env.BACKUP_BUCKET.head(prefix+'/stdout');
 if(before.etag!==after.etag||before.uploaded.getTime()!==after.uploaded.getTime())throw Error('Identical retry rewrote immutable object');
 await env.BACKUP_BUCKET.delete(prefix+'/stderr');
 await actor.persistCiLogs(prefix);
 if(!(await env.BACKUP_BUCKET.head(prefix+'/stderr')))throw Error('Partial pair was not completed');
 for(const mode of ['different','truncated']){await actor.setMode(mode);let rejected=false;try{await actor.persistCiLogs(prefix);}catch{rejected=true;}if(!rejected)throw Error('Different actual incoming bytes accepted: '+mode);}
 await actor.setMode('normal');
 await env.BACKUP_BUCKET.put(prefix+'/stderr',new Uint8Array(size-1));
 let sizeRejected=false;try{await actor.persistCiLogs(prefix);}catch{sizeRejected=true;}if(!sizeRejected)throw Error('Existing size mismatch accepted');
 let invalid=false;try{await actor.persistCiLogs('arbitrary/key');}catch(error){invalid=error.message.includes('Invalid CI log identity');}
 if(!invalid)throw Error('Arbitrary log key accepted');
 return Response.json({size,keys:Object.keys(result.logs),reconciled:true,invalid});}};`;

  const built = await Bun.build({
    entrypoints: ["fixture:actor"],
    target: "browser",
    external: ["cloudflare:workers", "node:*"],
    plugins: [
      {
        name: "actor file source fixture",
        setup(build) {
          build.onResolve({ filter: /^fixture:actor$/ }, () => ({
            path: "entry",
            namespace: "fixture",
          }));
          build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
            contents: source,
            loader: "ts",
          }));
          build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({
            path: "base",
            namespace: "stub",
          }));
          build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
            contents:
              "import{DurableObject}from'cloudflare:workers';export class Sandbox extends DurableObject{}",
            loader: "js",
          }));
        },
      },
    ],
  });

  expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
  const worker = await built.outputs[0].text();
  const program = `import{createRequire}from'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});const{Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BACKUP_BUCKET'],durableObjects:{ACTOR:{className:'Actor',useSQLite:true}},script:${JSON.stringify(worker)}}));try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.text()}));}finally{await mf.dispose();}`;

  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    stdin: new TextEncoder().encode(program),
    stdout: "pipe",
    stderr: "pipe",
  });

  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect(code, stderr).toBe(0);
  const result = JSON.parse(stdout);
  expect(result.status, result.body).toBe(200);
  expect(JSON.parse(result.body)).toEqual({
    size: 350126,
    keys: ["stdout", "stderr"],
    reconciled: true,
    invalid: true,
  });
}, 30000);

test("actual Artifacts provider releases each repository capability after its final operation", async () => {
  const provider = new URL(
    "../node_modules/@cloudflare/ci/src/artifacts/source-control.ts",
    import.meta.url,
  );

  const fixture = `import assert from 'node:assert/strict';
import {CloudflareArtifactsSourceControlProvider} from ${JSON.stringify(provider.href)};
const source={owner:'fixture',repo:'repo',sha:'a'.repeat(40),providerData:{namespace:'fixture'}};
for(const mode of ['checkout','credentials','push','token-failure','token-read-failure','tree','commit-failure','tree-failure','missing-commit','get-failure']){
 const events=[];let disposed=0,live=true;
 const pendingData=new Set();
 function own(value){pendingData.add(value);Object.defineProperty(value,Symbol.dispose,{value(){assert.ok(pendingData.delete(value),'Artifacts data result is released exactly once');}});return value;}
 const failure=new Error('literal repository operation failure');
 const repo={
  [Symbol.dispose](){assert.equal(live,true,'a repository capability is released exactly once');live=false;disposed++;events.push('dispose');},
  async createToken(scope,ttl){assert.equal(live,true);events.push('token-start');assert.equal(scope,mode==='push'?'write':'read');assert.equal(ttl,3600);await Promise.resolve();assert.equal(live,true,'capability must survive the awaited token operation');if(mode==='token-failure')throw failure;events.push('token-end');return own(mode==='token-read-failure'?{get plaintext(){throw failure;}}:{plaintext:'literal-read-token'});},
  async readCommit(sha){assert.equal(live,true);assert.equal(sha,source.sha);events.push('commit');if(mode==='commit-failure')throw failure;if(mode==='missing-commit')return null;return own({treeHash:'b'.repeat(40)});},
  async readTree(hash){assert.equal(live,true);events.push('tree:'+hash);await Promise.resolve();assert.equal(live,true,'capability must survive the whole recursive tree walk');if(hash==='b'.repeat(40))return own([{name:'src',mode:'040000',hash:'c'.repeat(40),type:'tree'},{name:'package.json',mode:'100644',hash:'d'.repeat(40),type:'blob'}]);assert.equal(hash,'c'.repeat(40));if(mode==='tree-failure')throw failure;return own([{name:'main.ts',mode:'100644',hash:'e'.repeat(40),type:'blob'}]);},
 };
 const instance=new CloudflareArtifactsSourceControlProvider({CLOUDFLARE_ACCOUNT_ID:'f'.repeat(32),ARTIFACTS:{async get(name){assert.equal(name,'repo');events.push('get');if(mode==='get-failure')throw failure;return repo;}}},{owner:'fixture',repo:'repo'});
 let output,error;
 try{output=mode==='credentials'?await instance.getStepCredentialEnv(source):mode==='push'?await instance.getPushCredentials(source):['tree','commit-failure','tree-failure','missing-commit'].includes(mode)?await instance.listTreeBlobs(source,['src/**','package.json']):await instance.getSourceCheckout(source);}catch(value){error=value;}
 assert.equal(pendingData.size,0,mode+': Artifacts RPC data must be released before returning');
 if(mode==='get-failure'){assert.equal(error,failure);assert.equal(disposed,0);assert.deepEqual(events,['get']);continue;}
 assert.equal(disposed,1,mode+': acquired repository capability must be released before the caller receives its result');assert.equal(events.at(-1),'dispose');
 if(mode==='token-failure'){assert.equal(error,failure);assert.deepEqual(events,['get','token-start','dispose']);continue;}
 if(mode==='token-read-failure'){assert.equal(error,failure);assert.deepEqual(events,['get','token-start','token-end','dispose']);continue;}
 assert.equal(error,undefined);
 if(['commit-failure','tree-failure','missing-commit'].includes(mode)){assert.equal(output,null);continue;}
 if(mode==='tree'){assert.deepEqual(output,[{path:'src/main.ts',sha:'e'.repeat(40)},{path:'package.json',sha:'d'.repeat(40)}]);assert.deepEqual(events,['get','commit','tree:'+'b'.repeat(40),'tree:'+'c'.repeat(40),'dispose']);}
 else{const remote='https://'+'f'.repeat(32)+'.artifacts.cloudflare.net/git/fixture/repo.git';assert.deepEqual(output,mode==='checkout'?{kind:'git',remote,token:'literal-read-token',sha:source.sha}:mode==='credentials'?{ARTIFACTS_REMOTE:remote,ARTIFACTS_TOKEN:'literal-read-token'}:{remote,token:'literal-read-token'});assert.deepEqual(events,['get','token-start','token-end','dispose']);}
}
`;

  const child = Bun.spawn([process.execPath, "--eval", fixture], {
    windowsHide: true,
    stdout: "pipe",
    stderr: "pipe",
  });

  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect({ exitCode, stdout, stderr }).toEqual({ exitCode: 0, stdout: "", stderr: "" });
});

test("actual SDK preparation recovers only typed Artifacts failures before one command", async () => {
  const sdkRoot = new URL("../node_modules/@cloudflare/ci/src/", import.meta.url);

  const fixture = `import {mock} from 'bun:test';
import assert from 'node:assert/strict';
const modes=['once','token-once','persistent','wrong-code','wrong-number','untyped','command-failure','expired','expires-after-first'];
let mode,gets,tokens,starts,completions,clock,acquired,disposed,admissions,discards;
const warnings=[];console.warn=(...values)=>warnings.push(values);
await mock.module(${JSON.stringify(new URL("ci/runners/sandbox.ts", sdkRoot).href)},()=>({SandboxRunner:class {async run(input){starts++;assert.equal(input.source.sha,'a'.repeat(40));assert.equal(input.instanceId,'prepare-fixture');assert.equal(input.attempt,1);return {exitCode:mode==='command-failure'?1:0,logs:{stdout:'fixture',stderr:''},preview:{stdout:'fixture',stderr:''},snapshot:{id:'fixture-backup',dir:'/workspace'}};}}}));
await mock.module(${JSON.stringify(new URL("pipeline/completion.ts", sdkRoot).href)},()=>({persistCompletion:async()=>{completions++;},beginExecution:async()=>{admissions++;return null;},discardProcessAdmission:async()=>{discards++;},recordStartedProcess:async()=>{throw new Error('preparation fixture must not journal a mocked process');},claimProcessRecovery:async()=>{throw new Error('preparation fixture must not recover a mocked process');}}));
const {runCiStep}=await import(${JSON.stringify(new URL("ci/capabilities.ts", sdkRoot).href)});
const {cloudflareArtifacts}=await import(${JSON.stringify(new URL("source-control-adapter.ts", sdkRoot).href)});
const realNow=Date.now;Date.now=()=>clock;
for(mode of modes){gets=0;tokens=0;starts=0;completions=0;acquired=0;disposed=0;admissions=0;discards=0;clock=realNow();const deadline=mode==='expired'?clock-1:clock+10000;
const failure=Object.assign(new Error('PRIVATE_PROVIDER_ERROR'),{name:mode==='untyped'?'Error':'ArtifactsError',code:mode==='wrong-code'?'INVALID_INPUT':'INTERNAL_ERROR',numericCode:mode==='wrong-number'?10100:10400});
const env={CLOUDFLARE_ACCOUNT_ID:'a'.repeat(32),ARTIFACTS:{async get(){gets++;if(mode==='expires-after-first')clock=deadline;if(mode==='persistent'||mode==='wrong-code'||mode==='wrong-number'||mode==='untyped'||mode==='expires-after-first'||(mode==='once'&&gets===1))throw failure;acquired++;let live=true;return {[Symbol.dispose](){assert.equal(live,true);live=false;disposed++;},async createToken(){assert.equal(live,true);tokens++;if(mode==='token-once'&&tokens===1)throw failure;return {plaintext:'PRIVATE_FIXTURE_TOKEN'};}};}}};
let output,error;try{output=await runCiStep(env,cloudflareArtifacts({owner:'fixture',repo:'repo'}),{provider:'cloudflare-artifacts',providerData:{namespace:'fixture'},source:{owner:'fixture',repo:'repo',sha:'a'.repeat(40)},instanceId:'prepare-fixture',attempt:1,label:'unit',command:'one command',deadlineMs:deadline});}catch(value){error=value;}
assert.equal(disposed,acquired,'every acquired capability must be released across preparation success and rejection');
assert.equal(admissions,mode==='expired'?0:1,'each unexpired execution requires one admission');assert.equal(discards,completions,'only a sealed completion may discard its admission');
if(mode==='once'||mode==='token-once'){assert.equal(error,undefined,'typed transient preparation should recover');assert.equal(gets,2);assert.equal(starts,1);assert.equal(completions,1);assert.equal(output.exitCode,0);}
else if(mode==='command-failure'){assert.ok(error);assert.equal(gets,1);assert.equal(starts,1);assert.equal(completions,0);}
else {assert.ok(error,mode);assert.equal(starts,0,mode);assert.equal(completions,0,mode);assert.equal(gets,mode==='persistent'?2:mode==='expired'?0:1,mode);}
}
Date.now=realNow;assert.doesNotMatch(JSON.stringify(warnings),/PRIVATE_/);
`;

  const child = Bun.spawn([process.execPath, "--eval", fixture], {
    windowsHide: true,
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    stdout: "pipe",
    stderr: "pipe",
  });

  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);

  expect({ exitCode, stdout, stderr }).toEqual({ exitCode: 0, stdout: "", stderr: "" });
});

for (const modes of [
  ["success", "clean"],
  ["native-retryable"],
  [
    "native-false",
    "native-string",
    "native-object",
    "native-overloaded",
    "native-nested-overloaded",
    "native-cancelled",
    "native-spent",
    "native-expired",
  ],
  ["native-checkout", "native-start"],
  ["cancel-failed", "cancel-pending", "cancel-expired", "hash-expired", "replacement-cancelled"],
  ["overloaded", "expired", "ttl", "auth", "lookalike"],
  ["initialization-used", "replacement-failed", "observation-failed", "checkout-failed"],
]) {
  test(
    "isolated restore recovery fences old actor before replacement: " + modes.join(", "),
    async () => {
      const runner = fileURLToPath(
        new URL("../node_modules/@cloudflare/ci/src/ci/runners/sandbox.ts", import.meta.url),
      );

      const identity = fileURLToPath(
        new URL("../node_modules/@cloudflare/ci/src/ci/runners/runner-id.ts", import.meta.url),
      );

      const errors = fileURLToPath(
        new URL("../node_modules/@cloudflare/sandbox/dist/index.js", import.meta.url),
      );

      const source = `import assert from 'node:assert/strict';
import {SandboxRunner} from ${JSON.stringify(runner)};
import {createRunnerId} from ${JSON.stringify(identity)};
import {OperationInterruptedError} from ${JSON.stringify(errors)};
export default {async fetch(request){try{
 const mode=new URL(request.url).pathname.slice(1);
 const inactive='Connection closed: this Durable Object instance is no longer active. Reconnect or retry the request.';
 const realNow=Date.now,realTimer=setTimeout;
 let clock=1000000;let cancelPending=false;Date.now=()=>clock;
 globalThis.setTimeout=(callback,delay,...args)=>mode==='cancel-pending'&&cancelPending?realTimer(()=>{clock=input.deadlineMs;callback(...args);},0):delay===1000?realTimer(()=>{clock+=1000;callback(...args);},0):realTimer(callback,delay,...args);
 const input={instanceId:'restore-fixture',attempt:1,label:'source-format',command:'one trusted command',source:{kind:'archive',url:'https://fixture.invalid/source'},deadlineMs:clock+10000,restore:{id:'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',dir:'/workspace'}};
 const tuple=['omg-ci-runner',1,'ci',input.instanceId,input.label,1];
 const expected=async values=>'ci1-c-'+[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(values))))].map(value=>value.toString(16).padStart(2,'0')).join('').slice(0,56);
 const original=await expected(tuple),replacement=await expected([...tuple,'incarnation',1]);
 const originalDigest=crypto.subtle.digest.bind(crypto.subtle);
 assert.equal(await createRunnerId(input),original,'incarnation zero identity must preserve existing physical IDs');
 assert.equal(await createRunnerId({...input,incarnation:1}),replacement,'explicit replacement identity is part of the single input object');
 crypto.subtle.digest=async (algorithm,data)=>{const value=await originalDigest(algorithm,data);if(mode==='hash-expired'&&new TextDecoder().decode(data).includes('incarnation'))clock=input.deadlineMs;return value;};
 const actors=new Map([[original,{workspace:'original partial bytes',cancelled:false}],[replacement,{workspace:'empty replacement',cancelled:mode==='replacement-cancelled'}]]);
 const acquisitions=[],events=[];let configurations=0,preflights=0,restores=0,cancels=0,checkouts=0,starts=0,polls=0,persisted=0;
 let cancelAck=false;let pendingOriginalWork=false;let restoreFenceStarted=false,finalCancellations=0;let restoreFault;
 const namespace={idFromName:name=>({name}),get(id){assert.ok(actors.has(id.name),'cancellation can address only a preowned physical actor');return {async cancel(){
  if(id.name!==original||restoreFenceStarted||!['success','native-retryable','cancel-failed','cancel-pending','cancel-expired','hash-expired','replacement-cancelled','replacement-failed','observation-failed','checkout-failed'].includes(mode)){
   finalCancellations++;actors.get(id.name).cancelled=true;pendingOriginalWork=false;events.push('destroy:'+id.name);return;
  }
  restoreFenceStarted=true;
  cancels++;if(mode==='cancel-pending')cancelPending=true;events.push('cancel-start');assert.equal(acquisitions.filter(name=>name===replacement).length,0,'replacement cannot be acquired before durable cancellation ACK');
  await Promise.resolve();assert.equal(acquisitions.filter(name=>name===replacement).length,0,'pending cancel cannot admit replacement');
  if(mode==='cancel-failed')throw new Error('durable cancellation rejected');
  if(mode==='cancel-pending')return new Promise(()=>{});
  actors.get(original).cancelled=true;pendingOriginalWork=false;cancelAck=true;events.push('cancel-ack');
  if(mode==='cancel-expired')clock=input.deadlineMs;
 }};}};
 globalThis.fixtureSandboxFactory=(ns,name,options)=>{
  assert.equal(ns,namespace);assert.ok(actors.has(name),'only preowned actor IDs may be acquired');
  assert.deepEqual(options,{transport:'rpc',enableDefaultSession:false,containerTimeouts:{portReadyTimeoutMS:60000}});
  acquisitions.push(name);const actor=actors.get(name);
  if(name===replacement){assert.equal(cancelAck,true,'replacement acquisition requires prior durable fence and teardown');assert.equal(pendingOriginalWork,false);assert.notEqual(actor,actors.get(original));}
  const active=()=>{if(actor.cancelled)throw new Error('CI sandbox was cancelled');};
  return {
   async waitForConfiguration(){configurations++;events.push('configure:'+name);active();if((mode==='initialization-used'||mode==='native-spent')&&configurations===1)throw new Error(inactive);},
   async exec(command){active();if(command==='test -c /dev/fuse'){preflights++;return {exitCode:0,stdout:'',stderr:''};}if(command.includes('fixture.invalid/source')){checkouts++;if(mode==='checkout-failed')throw new Error(inactive);if(mode==='native-checkout')throw Object.assign(new Error('opaque checkout fault'),{retryable:true,overloaded:false});}return {exitCode:0,stdout:'literal command output',stderr:''};},
   async restoreBackup(backup){active();assert.deepEqual(backup,input.restore);restores++;events.push('restore:'+name);if(name===original&&!['clean','native-checkout','native-start'].includes(mode)){
    pendingOriginalWork=true;if(mode==='expired'||mode==='native-expired')clock=input.deadlineMs;
    const error=new Error(mode==='ttl'?'Backup has expired':mode==='auth'?'Unauthorized backup credential':mode==='lookalike'?'Connection closed: unrelated instance is no longer active.':inactive);
    if(mode==='overloaded')error.cause={overloaded:true};
    if(mode.startsWith('native-')){error.message='opaque provider fault';error.retryable=mode==='native-false'?false:mode==='native-string'?'true':true;error.overloaded=mode==='native-overloaded';if(mode==='native-nested-overloaded')error.cause={overloaded:true};if(mode==='native-object'){restoreFault={retryable:true,overloaded:false};throw restoreFault;}if(mode==='native-cancelled'){restoreFault=new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:'cancelled actor must not recover',context:{reason:'sandbox_destroyed',operation:'sandbox.restoreBackup',phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()});restoreFault.retryable=true;throw restoreFault;}restoreFault=error;}throw error;
   }if(mode==='replacement-failed')throw new Error(inactive);actor.workspace='restored literal dependency bytes';},
   async startProcess(){active();starts++;if(mode==='native-start')throw Object.assign(new Error('opaque process-start fault'),{retryable:true,overloaded:false});assert.equal(actor.workspace,'restored literal dependency bytes');return {id:'one-process'};},
   async getProcess(id){active();assert.equal(id,'one-process');polls++;if(mode==='observation-failed')throw new OperationInterruptedError({code:'OPERATION_INTERRUPTED',message:'post-restore status interruption',context:{reason:'runtime_replaced',operation:'sandbox.getProcess',phase:'durable_object_call',admitted:'unknown',retryable:false},httpStatus:409,timestamp:new Date().toISOString()});return {id,status:'completed',exitCode:0};},
   async createBackup(){active();return input.restore;},
   async persistCiLogs(key){active();persisted++;assert.equal(key,'logs/'+input.instanceId+'/native/'+original,'physical replacement cannot change logical log identity');return {logs:{stdout:{r2Key:key+'/stdout'},stderr:{r2Key:key+'/stderr'}},logSizes:{stdout:1,stderr:0}};},
   async destroy(){events.push('destroy:'+name);},
  };
 };
 let output,failure;try{const execution=new SandboxRunner({SANDBOX:namespace}).run(input);output=await(mode==='cancel-pending'?Promise.race([execution,new Promise((_,reject)=>realTimer(()=>reject(new Error('fixture pending cancellation exceeded initialization deadline')),100))]):execution);}catch(error){failure=error;}finally{Date.now=realNow;globalThis.setTimeout=realTimer;crypto.subtle.digest=originalDigest;}
 if(mode==='cancel-pending')assert.match(failure?.message??'',/^CI sandbox deadline expired$/);
 if(mode==='native-retryable'){assert.ok(restoreFault instanceof Error,'fixture must supply a genuine Error at the runner boundary');assert.equal(restoreFault.retryable,true,'native retryable boolean must reach the runner fixture');assert.equal(restoreFault.overloaded,false,'native overload flag must remain false');}
 const blockedBeforeFence=['overloaded','expired','ttl','auth','lookalike','initialization-used','native-false','native-string','native-object','native-overloaded','native-nested-overloaded','native-cancelled','native-spent','native-expired','native-checkout','native-start'].includes(mode);
 const succeeded=['success','clean','native-retryable'].includes(mode);
 assert.equal(cancels,mode==='clean'||blockedBeforeFence?0:1,'only admitted inactive or native retryable restore may consume the one fenced replacement');
 assert.equal(finalCancellations,['cancel-pending','cancel-expired','hash-expired','expired','native-expired'].includes(mode)?0:1,'final cleanup must freshly fence the actual current incarnation within the original deadline');
 assert.equal(acquisitions.filter(name=>name===replacement).length,mode==='clean'||blockedBeforeFence||mode==='cancel-failed'||mode==='cancel-pending'||mode==='cancel-expired'||mode==='hash-expired'?0:1);
 assert.equal(checkouts,succeeded||mode==='observation-failed'||mode==='checkout-failed'||mode==='native-checkout'||mode==='native-start'?1:0,'checkout is never replayed');
 assert.equal(starts,succeeded||mode==='observation-failed'||mode==='native-start'?1:0,'candidate command is never replayed');
 assert.equal(persisted,succeeded?1:0,'failed isolated recovery cannot publish success');
 assert.equal(Boolean(failure),!succeeded,failure?.stack);
 if(succeeded){assert.equal(output.exitCode,0);assert.deepEqual(output.snapshot,input.restore);assert.equal(restores,mode==='clean'?1:2);}
 if(mode==='success'||mode==='native-retryable'){assert.equal(actors.get(original).workspace,'original partial bytes');assert.equal(actors.get(replacement).workspace,'restored literal dependency bytes');assert.ok(events.indexOf('cancel-ack')<events.indexOf('configure:'+replacement));}
 if(mode==='initialization-used'||mode==='native-spent')assert.equal(acquisitions.length,2,'initialization consumes the same existing allowance, not an additional restore budget');
 if(mode==='observation-failed'){assert.equal(polls,1);assert.equal(acquisitions.length,2,'restore recovery consumes the existing status-observation allowance');}
 return Response.json({mode,acquisitions,configurations,preflights,restores,cancels,checkouts,starts,polls,persisted,failed:Boolean(failure)});
 }catch(error){return Response.json({error:error.stack},{status:500});}}};`;

      const built = await Bun.build({
        entrypoints: ["fixture:entry"],
        target: "browser",
        external: ["node:*", "cloudflare:workers"],
        plugins: [
          {
            name: "actual isolated restore runner fixture",
            setup(build) {
              build.onResolve({ filter: /^fixture:entry$/ }, () => ({
                path: "entry",
                namespace: "fixture",
              }));
              build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({
                contents: source,
                loader: "js",
              }));
              build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({
                path: "sandbox",
                namespace: "stub",
              }));
              build.onLoad({ filter: /.*/, namespace: "stub" }, () => ({
                contents: `export {OperationInterruptedError} from ${JSON.stringify(errors)};export const getSandbox=(...args)=>globalThis.fixtureSandboxFactory(...args);`,
                loader: "js",
              }));
            },
          },
        ],
      });

      expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
      const worker = await built.outputs[0].text();
      const program = `import{createRequire}from'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});const{Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(worker)}}));try{const rows=[];for(const mode of ${JSON.stringify(modes)}){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);rows.push({mode,status:response.status,body:await response.text()});}console.log(JSON.stringify(rows));}finally{await mf.dispose();}`;

      const child = Bun.spawn(["node", "--input-type=module", "-"], {
        windowsHide: true,
        stdin: new TextEncoder().encode(program),
        stdout: "pipe",
        stderr: "pipe",
      });

      const [code, output, errorsOut] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);

      expect(code, errorsOut).toBe(0);
      const rows = JSON.parse(output);
      console.log(JSON.stringify(rows));

      for (const row of rows) expect(row.status, `${row.mode}: ${row.body}`).toBe(200);
    },
    30000,
  );
}

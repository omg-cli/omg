import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("exported Sandbox cancellation acknowledges teardown and preserves its durable fence", async () => {
  const entry = fileURLToPath(new URL("../src/index.ts", import.meta.url));
  const source = `import assert from 'node:assert/strict';
import {CiSandbox} from ${JSON.stringify(entry)};
export class Actor extends CiSandbox {
 async inspect(){
  let refusal;
  try{await this.startProcess('must-not-start');}catch(error){refusal=error.message;}
  return {fenced:await this.ctx.storage.get('omg:runner-teardown'),stopped:await this.ctx.storage.get('fixture:stopped'),refusal};
 }
 async failStop(){await this.ctx.storage.put('fixture:fail-stop',true);}
}
export default {async fetch(request,env){try{
 for(const mode of ['success','rejected']){
  const id=env.ACTOR.idFromName(mode);
  const actor=env.ACTOR.get(id);
  if(mode==='rejected')await actor.failStop();
  let failure;
  try{await actor.cancel();}catch(error){failure=error.message;}
  assert.equal(failure,mode==='rejected'?'fixture stop refused':undefined);
  const state=await env.ACTOR.get(id).inspect();
  assert.equal(state.fenced,true);
  assert.equal(state.stopped,mode==='success'?true:undefined);
  assert.equal(state.refusal,'Runner teardown refuses container start');
 }
 return Response.json({acknowledged:true,rejectedStopPreserved:true,fenced:true});
}catch(error){return new Response(error.stack,{status:500});}}};`;
  const built = await Bun.build({
    entrypoints: ["fixture:entry"], target: "browser",
    external: ["cloudflare:workers", "node:*"],
    plugins: [{ name: "exported actor RPC fixture", setup(build) {
      build.onResolve({ filter: /^fixture:entry$/ }, () => ({ path: "entry", namespace: "fixture" }));
      build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({ contents: source, loader: "ts" }));
      build.onResolve({ filter: /^@cloudflare\/ci\/worker$/ }, () => ({ path: "base", namespace: "platform" }));
      build.onLoad({ filter: /.*/, namespace: "platform" }, () => ({ loader: "js", contents: `
import {DurableObject} from 'cloudflare:workers';
export class CiSandbox extends DurableObject {
 async destroy(){
  if(await this.ctx.storage.get('fixture:fail-stop'))throw new Error('fixture stop refused');
  await this.ctx.storage.put('fixture:stopped',true);
 }
}` }));
    }}],
  });
  expect(built.success, built.logs.map(log => log.message).join("\n")).toBe(true);
  const worker = await built.outputs[0].text();
  const program = `import{createRequire}from'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const{Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BACKUP_BUCKET'],durableObjects:{ACTOR:{className:'Actor',useSQLite:true}},script:${JSON.stringify(worker)}}));
try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.text()}));}finally{await mf.dispose();}`;
  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  expect(code, stderr).toBe(0);
  const result = JSON.parse(stdout);
  expect(result.status, result.body).toBe(200);
  expect(JSON.parse(result.body)).toEqual({ acknowledged: true, rejectedStopPreserved: true, fenced: true });
}, 30000);

import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("failed cleanup cannot replace an immutable command error", async () => {
  const runner = fileURLToPath(new URL("../node_modules/@cloudflare/ci/src/ci/runners/sandbox.ts", import.meta.url));
  const entry = `import {SandboxRunner} from ${JSON.stringify(runner)};
export default {async fetch(request){
 const mode=new URL(request.url).pathname.slice(1);let causeReads=0;
 const original=new Error('original command failed');
 if(mode==='frozen')Object.freeze(original);
 if(mode==='readonly')Object.defineProperty(original,'cause',{value:new Error('earlier failure'),writable:false});
 if(mode==='accessor')Object.defineProperty(original,'cause',{get(){causeReads++;throw new Error('cause getter must not run');}});
 let launches=0,cancellations=0,caught;
 globalThis.fixtureSandbox={async waitForConfiguration(){},async exec(){return {success:true,exitCode:0,stdout:'',stderr:''};},async startProcess(){launches++;throw original;}};
 const namespace={idFromName:name=>({toString:()=>name}),get:()=>({async cancel(){cancellations++;throw new Error('cleanup failed');}})};
 try{await new SandboxRunner({SANDBOX:namespace}).run({instanceId:'immutable-error',attempt:1,label:'fixture',command:'fixture',source:{kind:'archive',url:'https://fixture.invalid/source'},timeoutMs:10000});}catch(error){caught=error;}
 return Response.json({sameError:caught===original,message:caught?.message,launches,cancellations,causeReads,cleanupCause:Object.getOwnPropertyDescriptor(caught,'cause')?.value?.message??null});
}};`;
  const built = await Bun.build({
    entrypoints: ["fixture:entry"], target: "browser", external: ["node:*"],
    plugins: [{ name: "immutable command failure", setup(build) {
      build.onResolve({ filter: /^fixture:entry$/ }, () => ({ path: "entry", namespace: "fixture" }));
      build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({ contents: entry, loader: "ts" }));
      build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({ path: "sandbox", namespace: "transport" }));
      build.onLoad({ filter: /.*/, namespace: "transport" }, () => ({ contents: "export class OperationInterruptedError extends Error{};export const getSandbox=()=>globalThis.fixtureSandbox;", loader: "js" }));
    } }],
  });
  expect(built.success, built.logs.map(log => log.message).join("\n")).toBe(true);
  const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(await built.outputs[0].text())}}));
try{const rows=[];for(const mode of ['mutable','frozen','readonly','accessor']){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);rows.push({status:response.status,body:await response.json()});}console.log(JSON.stringify(rows));}finally{await mf.dispose();}`;
  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    windowsHide: true, stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe", timeout: 15000,
  });
  const [exit, output, errors] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
  expect(exit, errors).toBe(0);
  expect(JSON.parse(output)).toEqual(["cleanup failed", null, "earlier failure", null].map(cleanupCause => ({
    status: 200, body: { sameError: true, message: "original command failed", launches: 1, cancellations: 1, causeReads: 0, cleanupCause },
  })));
});

import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real Durable Object storage admits one concurrent inference and releases the next interval", async () => {
  const path = fileURLToPath(new URL("../src/model-pacer.ts", import.meta.url));
  const source = `export {ModelPacer} from ${JSON.stringify(path)};
export default {async fetch(request,env){
 const model='@cf/deepseek-ai/deepseek-v4.1-flash-1017';
 const first=env.MODEL_PACER.getByName('shared');
 const results=await Promise.all(Array.from({length:8},()=>first.admit(model)));
 const second=await env.MODEL_PACER.getByName('shared').admit(model);
 let rejected=false;try{await first.admit('unconfigured-model');}catch(error){rejected=error.message.includes('Unsupported paced model');}
 await new Promise(resolve=>setTimeout(resolve,12100));
 const renewed=await env.MODEL_PACER.getByName('shared').admit(model);
 return Response.json({grants:results.filter(r=>r.granted).length,denials:results.filter(r=>!r.granted&&r.waitMs>0&&r.waitMs<=12000).length,secondDenied:!second.granted,rejected,renewed});
}};`;
  const built = await Bun.build({
    entrypoints: ["fixture:entry"], target: "browser", external: ["cloudflare:workers"],
    plugins: [{ name: "real model admission fixture", setup(build) {
      build.onResolve({ filter: /^fixture:entry$/ }, () => ({ path: "entry", namespace: "fixture" }));
      build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({ contents: source, loader: "ts" }));
    } }],
  });
  expect(built.success, built.logs.map(log => log.message).join("\n")).toBe(true);
  const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],durableObjects:{MODEL_PACER:{className:'ModelPacer',useSQLite:true}},script:${JSON.stringify(await built.outputs[0].text())}}));
try{const response=await mf.dispatchFetch('https://fixture.invalid/');console.log(JSON.stringify({status:response.status,body:await response.json()}));}finally{await mf.dispose();}`;
  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    windowsHide: true, stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe",
    timeout: 20000, killSignal: "SIGKILL",
  });
  const [exit, output, errors] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  expect(exit, errors).toBe(0);
  expect(JSON.parse(output)).toEqual({ status: 200, body: {
    grants: 1, denials: 7, secondDenied: true, rejected: true, renewed: { granted: true },
  } });
}, 25000);

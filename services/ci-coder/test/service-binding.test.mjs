import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("real service binding polls CI and refuses redirects without following them", async () => {
  const entry = `import {pollCodingVerification} from ${JSON.stringify(fileURLToPath(new URL("../src/tools.ts", import.meta.url)))};
export default {async fetch(request,env){
 const mode=new URL(request.url).pathname.slice(1),sha='a'.repeat(40),digest='b'.repeat(64),id='cl-123-1-'+sha;
 let state={calls:0,reads:[],verifiedDigests:[],proposal:{proposalSha256:digest,proposal:{},regression:{}},
   verificationJob:{id,proposalSha256:digest,sessionId:'fixture',continuationId:'fixture-followup',deadline:Date.now()+60000,status:'pending'}};
 const result=await pollCodingVerification({
   getRequest:async()=>({repository:'omg-cli/omg',sha,branch:'main',runId:'123',attempt:'1'}),
   env:{CI_SERVICE:env.CI_SERVICE,CI_API_TOKEN:mode==='redirect'?'fixture-redirect':'fixture-ok',CI_VERIFIER_REVISION:'c'.repeat(40),CI_IMAGE_DIGEST:'sha256:'+digest},
   update:async change=>(state=change(state)),
 },new AbortController().signal);
 return Response.json({result});
}};`;
  const built = await Bun.build({
    entrypoints: ["fixture:entry"],
    plugins: [{ name: "service binding fixture", setup(build) {
      build.onResolve({ filter: /^fixture:entry$/ }, () => ({ path: "entry", namespace: "fixture" }));
      build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({ contents: entry, loader: "ts", resolveDir: fileURLToPath(new URL("..", import.meta.url)) }));
    } }],
    target: "browser", external: ["node:*", "cloudflare:*"],
  });
  expect(built.success, built.logs.join("\n")).toBe(true);
  const backend = `export default {fetch(request){
 if(request.headers.get('authorization')==='Bearer fixture-redirect')return new Response(null,{status:302,headers:{location:'https://must-not-follow.invalid/'}});
 return Response.json({id:'cl-123-1-'+'a'.repeat(40),sha:'a'.repeat(40),status:'running'});
}};`;
  const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({workers:[
 {name:'caller',modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],script:${JSON.stringify(await built.outputs[0].text())},serviceBindings:{CI_SERVICE:'backend'}},
 {name:'backend',modules:true,compatibilityDate:'2026-10-20',script:${JSON.stringify(backend)}}
]}));
try{const results=[];for(const mode of ['ok','redirect']){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);if(!response.ok)throw new Error('Fixture request failed: '+response.status);results.push(await response.json());}console.log(JSON.stringify(results));}finally{await mf.dispose();}`;
  const child = Bun.spawn(["node", "--input-type=module", "-"], {
    stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe", timeout: 25000, killSignal: "SIGKILL",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  expect(code, stderr).toBe(0);
  const [normal, redirect] = JSON.parse(stdout);
  expect(normal.result.status, JSON.stringify(normal)).toBe("pending");
  expect(redirect.result.status).toBe("failed");
  expect(redirect.result.reason).toBe("Verification service failed: HTTP 302");
}, 30000);

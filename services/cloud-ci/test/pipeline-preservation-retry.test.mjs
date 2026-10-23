import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("actual pipeline retries consumed streamed logs after a transient R2 failure", async () => {
    const pipeline = fileURLToPath(new URL("../src/pipeline.ts", import.meta.url));
    const source = `
import assert from 'node:assert/strict';
import { CI } from ${JSON.stringify(pipeline)};
import { cloudCiChecks } from ${JSON.stringify(fileURLToPath(new URL("../runner/plan.mjs", import.meta.url)))};
const hash=async text=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))),b=>b.toString(16).padStart(2,'0')).join('');
export default {async fetch(request,env){
  const mode=new URL(request.url).pathname.slice(1);
  const sha='a'.repeat(40), id='cl-123-1-'+sha;
  const input={repository:'omg-cli/omg',sha,ref:'refs/heads/main',runId:'123',attempt:'1'};
  const receiptPath='receipts/123-1/'+sha+'.json';
  const xml='<testsuite tests="1" failures="0" errors="0" skipped="0"/>';
  const raw='unicode-α-'+ 'x'.repeat(310001)+'\\n';
  const expected=new Map();
  const reportNames=['rust-pgp-license-junit.xml','rust-debian-pure-junit.xml'];
  const failKey=mode==='report'?'reports/'+id+'/'+reportNames[0]:'logs/'+id+'/frozen-dependencies.'+(mode==='stderr'?'stderr':'stdout');
  let failures=0;
  const attempts={};
  await env.BUCKET.put('runs/'+id+'/request.json',JSON.stringify(input));
  const bucket={
    get:(...args)=>env.BUCKET.get(...args),
    async put(key,value,options){
      if(mode!=='parallel-failure' && key===failKey && (mode==='permanent'||failures===0)){failures++;throw new Error('fixture transient R2 PUT failure');}
      return env.BUCKET.put(key,value,options);
    },
  };
  const step={async do(name,config,callback){
    const limit=config.retries?.limit??0;
    for(let attempt=1;;attempt++){
      attempts[name]=attempt;
      try{return await callback({attempt});}catch(error){if(attempt>limit)throw error;}
    }
  }};
  async function run(options){
    const name=options.name;
    const heavy=['rust-portable-tests','script-contracts'].includes(name);
    assert.equal(options.config.timeout,heavy?2_400_000:1_200_000);
    assert.equal(options.config.commandTimeoutMs,heavy?2_370_000:1_170_000);
    if(mode==='parallel-failure' && name==='script-contracts') throw new Error('fixture script command failed');
    if(mode==='parallel-failure' && name==='rust-portable-tests') await new Promise(resolve=>setTimeout(resolve,20));
    assert.equal(options.env.OMG_DIAGNOSTIC_RUN_ID,id);
    assert.equal(options.env.OMG_CI_LEAF_STEP,name);
    const reports=name==='rust-portable-tests'?reportNames.map(name=>'OMG_REPORT='+JSON.stringify({name,content:xml})).join('\\n')+'\\n':'';
    const stdout=raw+reports, stderr='stderr-'+raw;
    expected.set(name,{stdout,stderr});
    await env.BUCKET.put('fixture/'+name+'.stdout',stdout);
    await env.BUCKET.put('fixture/'+name+'.stderr',stderr);
    const out=await env.BUCKET.get('fixture/'+name+'.stdout');
    const err=await env.BUCKET.get('fixture/'+name+'.stderr');
    return {exitCode:0,logs:{stdout:mode==='inline'?stdout:out.body,stderr:mode==='inline'?stderr:err.body},runner:run};
  }
  const ci=new CI({}, {BACKUP_BUCKET:bucket,CI_IMAGE_DIGEST:'sha256:'+'b'.repeat(64)});
  try{
    await ci.pipeline({instanceId:id,payload:{sha,ref:input.ref}},step,{runner:run});
    const receipt=await (await env.BUCKET.get(receiptPath)).json();
    assert.equal(receipt.conclusion,'success');
    assert.deepEqual(receipt.checks.map(check=>check.name),cloudCiChecks);
    assert.deepEqual(receipt.checks.flatMap(check=>check.reports.map(report=>report.name)),reportNames);
    for(const check of receipt.checks){
      const bytes=expected.get(check.name);
      assert.equal(await (await env.BUCKET.get(check.stdoutKey)).text(),bytes.stdout);
      assert.equal(await (await env.BUCKET.get(check.stderrKey)).text(),bytes.stderr);
      assert.equal(check.stdoutSha256,await hash(bytes.stdout));
      assert.equal(check.stderrSha256,await hash(bytes.stderr));
      for(const report of check.reports){
        assert.equal(await (await env.BUCKET.get(report.key)).text(),xml);
        assert.equal(report.sha256,await hash(xml));
      }
    }
    assert.equal(failures,1);
    assert.equal(attempts[mode==='report'?'preserve-rust-portable-tests':'preserve-frozen-dependencies'],2);
    return Response.json({mode,checks:receipt.checks.length,failures,attempts});
  }catch(error){
    const receipt=await env.BUCKET.get(receiptPath);
    return Response.json({mode,error:String(error),receipt:receipt?await receipt.json():null,failures},{status:500});
  }
}};`;
    const built = await Bun.build({
        entrypoints: ["fixture:entry"], target: "browser", external: ["node:*"],
        plugins: [{ name: "explicit Workflow invocation fixture", setup(build) {
            build.onResolve({ filter: /^fixture:entry$/ }, () => ({ path: "entry", namespace: "fixture" }));
            build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({ contents: source, loader: "ts" }));
            build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({ path: "sandbox", namespace: "fixture-base" }));
            build.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "base", namespace: "fixture-base" }));
            build.onLoad({ filter: /.*/, namespace: "fixture-base" }, ({ path }) => ({
                contents: path === "sandbox" ? "export const getSandbox=()=>{throw new Error('Unexpected container call in preservation fixture')};export class OperationInterruptedError extends Error{constructor(context){super('fixture operation interrupted');this.name='OperationInterruptedError';this.context=context;}}"
                    : "export class WorkflowEntrypoint{constructor(ctx,env){this.env=env;}} export class DurableObject{} export class WorkerEntrypoint{} export class RpcTarget{}; export const tracing=undefined;",
                loader: "js",
            }));
        } }],
    });
    expect(built.success, built.logs.join("\n")).toBe(true);
    const worker = await built.outputs[0].text();
    const modes = ["stdout", "stderr", "report", "inline", "permanent", "parallel-failure"];
    const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BUCKET'],script:${JSON.stringify(worker)}}));
let timer;
const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Workerd preservation fixture exceeded 20 seconds')),20_000);});
try{const results=await Promise.race([deadline,(async()=>{const results=[];for(const mode of ${JSON.stringify(modes)}){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);results.push({mode,status:response.status,body:await response.json()});}return results;})()]);console.log(JSON.stringify(results));}finally{clearTimeout(timer);await mf.dispose();}`;
    const child = Bun.spawn(["node", "--input-type=module", "-"], {
        stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe",
        timeout: 25_000, killSignal: "SIGKILL",
    });
    const [code, output, errors] = await Promise.all([
        child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
    ]);
    expect(code, errors).toBe(0);
    const results = JSON.parse(output);
    for (const result of results) {
        if (result.mode === "permanent") {
            expect(result.status).toBe(500);
            expect(result.body.receipt.conclusion).toBe("failure");
            expect(result.body.failures).toBe(3);
        } else if (result.mode === "parallel-failure") {
            expect(result.status).toBe(500);
            expect(result.body.receipt.conclusion).toBe("failure");
            expect(result.body.error).toContain("fixture script command failed");
            expect(result.body.receipt.checks.map(check => check.name)).toEqual([
                "frozen-dependencies", "source-format", "rust-portable-tests",
            ]);
            expect(result.body.receipt.checks.every(check => check.exitCode === 0)).toBe(true);
            expect(result.body.receipt.checks.at(-1).reports.map(report => report.name)).toEqual([
                "rust-pgp-license-junit.xml", "rust-debian-pure-junit.xml",
            ]);
        } else {
            expect(result.status, JSON.stringify(result.body)).toBe(200);
            expect(result.body.checks).toBe(7);
        }
    }
}, 30_000);

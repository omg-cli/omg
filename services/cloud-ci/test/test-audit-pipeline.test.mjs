import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

test("actual workflow preserves four exact audit reports and rejects incomplete or substituted evidence", async () => {
    const source = `
import {CI} from ${JSON.stringify(fileURLToPath(new URL("../src/pipeline.ts", import.meta.url)))};
import {parseStart,runIdentity,receiptKey} from ${JSON.stringify(fileURLToPath(new URL("../src/contract.ts", import.meta.url)))};
import {testAuditDigest} from ${JSON.stringify(fileURLToPath(new URL("../src/test-audit-contract.ts", import.meta.url)))};
import {decodeVerificationEnvironment} from ${JSON.stringify(fileURLToPath(new URL("../runner/verification-envelope.mjs", import.meta.url)))};
import {createHash} from 'node:crypto';
const hash=value=>createHash('sha256').update(value).digest('hex');
const blob=value=>createHash('sha1').update('blob '+Buffer.byteLength(value)+'\\0'+value).digest('hex');
export default {async fetch(request,env){
 const mode=new URL(request.url).pathname.slice(1),sha='a'.repeat(40),sensitivity=mode.startsWith('sensitivity');
 const original='#[test]\\nfn check() {\\n assert!(true);\\n}\\n';
 const stronger=sensitivity?original:original.replace('}\\n',' assert_eq!(1,1);\\n}\\n');
 const proposal={purpose:sensitivity?'existing-test-sensitivity':'existing-test-strengthening',repository:'omg-cli/omg',branch:'main',baseSha:sha,
  test:{path:'tests/check.rs',testName:'check',originalBlobSha:blob(original),originalContent:original,newContent:stronger,sha256:hash(stronger),assertionLine:sensitivity?3:4},
  fault:{path:'src/value.rs',originalBlobSha:'b'.repeat(40),oldContentQuote:'2',newContent:'pub const VALUE:u32=1;',sha256:hash('pub const VALUE:u32=1;')}};
 const input=parseStart({repository:proposal.repository,sha,ref:'refs/heads/main',runId:'123',attempt:'1',testAudit:{verifierRevision:'d'.repeat(40),proposal}});
 const id=runIdentity(input),phases=sensitivity?['oldIntact','oldFault']:['oldIntact','oldFault','strongerFault','strongerIntact'];
 const raw=Object.fromEntries(phases.map(phase=>[phase,JSON.stringify({fixture:'controller transport',phase})]));
 const common={testName:'check',exitCode:0,tests:1,failures:0,errors:0,skipped:0,stdoutSha256:hash('stdout'),stderrSha256:hash('stderr'),catalogSha256:hash('catalog'),executableSha256:hash('exe'),compilerMessagesSha256:hash('compiler'),recipeSha256:hash('recipe')};
 const receipt={purpose:proposal.purpose,repository:proposal.repository,branch:'main',baseSha:sha,proposalSha256:testAuditDigest(proposal),verifierRevision:input.testAudit.verifierRevision,runId:123,runAttempt:1,
  ...Object.fromEntries(phases.map(phase=>[phase,{...common,reportSha256:hash(raw[phase]),sourceSha256:hash(phase.startsWith('old')?original:stronger),
   ...(phase===(sensitivity?'oldFault':'strongerFault')?{exitCode:101,failures:1,assertionFile:'tests/check.rs',assertionLine:sensitivity?3:4,assertionSourceSha256:hash(sensitivity?' assert!(true);':' assert_eq!(1,1);'),assertionFailure:'assertion \\u0060left == right\\u0060 failed'}:{})}])),
  protectedPathsUnchanged:true,faultRestored:true,changedPaths:sensitivity?[]:['tests/check.rs'],fileHashes:sensitivity?[]:[{path:'tests/check.rs',sha256:hash(stronger)}]};
 await env.BUCKET.put('runs/'+id+'/request.json',JSON.stringify(input));
 let leafChecks=0;
 const run=async options=>{
  let stdout='';
  if(['test-audit-four-state','test-audit-sensitivity'].includes(options.name)){
   stdout='OMG_TEST_AUDIT='+JSON.stringify(receipt)+'\\n';
   for(const phase of phases){if(mode.endsWith('missing')&&phase==='oldFault')continue;
    stdout+='OMG_REPORT='+JSON.stringify({name:'test-audit-'+phase+'.json',content:mode==='corrupt'&&phase==='strongerFault'?'other':raw[phase]})+'\\n';}
   if(mode==='duplicate')stdout+='OMG_TEST_AUDIT='+JSON.stringify(receipt)+'\\n';
  }else if(options.name!=='frozen-dependencies'){
   if(decodeVerificationEnvironment(options.env).testAudit.proposalSha256)throw new Error('Unexpected normalized field');
   leafChecks++;
  }
  return {exitCode:0,logs:{stdout,stderr:''},runner:run};
 };
 const ci=new CI({}, {BACKUP_BUCKET:env.BUCKET,CI_IMAGE_DIGEST:'sha256:'+'e'.repeat(64),CI_VERIFIER_REVISION:'d'.repeat(40)});
 try{await ci.pipeline({instanceId:id,payload:{sha,ref:input.ref}},{do:async(name,config,callback)=>callback()}, {runner:run});}
 catch(error){return Response.json({error:String(error),receipt:await(await env.BUCKET.get(receiptKey(input))).json()},{status:500});}
 return Response.json({receipt:await(await env.BUCKET.get(receiptKey(input))).json(),leafChecks});
}};`;
    const built = await Bun.build({ entrypoints: ["fixture:entry"], target: "browser", external: ["node:*"], plugins: [{ name: "audit workflow transport", setup(build) {
        build.onResolve({ filter: /^fixture:entry$/ }, () => ({ path: "entry", namespace: "fixture" }));
        build.onLoad({ filter: /.*/, namespace: "fixture" }, () => ({ contents: source, loader: "ts" }));
        build.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({ path: "sandbox", namespace: "fixture-base" }));
        build.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "base", namespace: "fixture-base" }));
        build.onLoad({ filter: /.*/, namespace: "fixture-base" }, ({ path }) => ({ contents: path === "sandbox" ? "export const getSandbox=()=>{throw new Error('No native fixture execution')};export class OperationInterruptedError extends Error{constructor(context){super('fixture operation interrupted');this.name='OperationInterruptedError';this.context=context;}}"
            : "export class WorkflowEntrypoint{constructor(ctx,env){this.env=env;}} export class DurableObject{} export class WorkerEntrypoint{} export class RpcTarget{}; export const tracing=undefined;", loader: "js" }));
    } }] });
    expect(built.success, built.logs.join("\n")).toBe(true);
    const program = `import {createRequire} from 'node:module';const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');const mf=new Miniflare(convertV4MiniflareOptions({modules:true,compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],r2Buckets:['BUCKET'],script:${JSON.stringify(await built.outputs[0].text())}}));
try{const results=[];for(const mode of ['valid','missing','corrupt','duplicate','sensitivity','sensitivity-missing']){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);results.push({mode,status:response.status,body:await response.json()});}console.log(JSON.stringify(results));}finally{await mf.dispose();}`;
    const child = Bun.spawn(["node", "--input-type=module", "-"], { stdin: new TextEncoder().encode(program), stdout: "pipe", stderr: "pipe", timeout: 25_000, killSignal: "SIGKILL" });
    const [code, output, errors] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
    expect(code, errors).toBe(0);
    for (const { mode, status, body } of JSON.parse(output)) {
        const success = ["valid", "sensitivity"].includes(mode);
        expect(status, JSON.stringify(body)).toBe(success ? 200 : 500);
        expect(body.receipt.conclusion).toBe(success ? "success" : "failure");
        if (success) {
            expect(body.receipt.testAuditReceipt.purpose).toBe(mode === "sensitivity" ? "existing-test-sensitivity" : "existing-test-strengthening");
            expect(body.receipt.testAuditReports).toHaveLength(mode === "sensitivity" ? 2 : 4);
            if (mode === "sensitivity") {
                expect(body.receipt.testAuditReceipt.changedPaths).toEqual([]);
                expect(body.receipt.testAuditReceipt.strongerFault).toBeUndefined();
            }
            expect(body.receipt.verificationReceipt).toBeNull();
            expect(body.receipt.checks).toHaveLength(7);
            expect(body.leafChecks).toBe(6);
        }
    }
}, 30_000);

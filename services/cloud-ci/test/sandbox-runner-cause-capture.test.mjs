import { expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

const sdk = (path) => JSON.stringify(fileURLToPath(new URL(`../node_modules/@cloudflare/ci/src/${path}`, import.meta.url)));
const owner = "cl-40220918875-1-7c321c2a19a9e50f85a2610eb5140cae001e7443";
const leaf = "script-contracts";
const secret = "fixture-only-secret";

const worker = `
import {DurableObject} from 'cloudflare:workers';
import {SandboxRunner} from ${sdk("ci/runners/sandbox.ts")};
import {withStepNotification} from ${sdk("ci/step-notification.ts")};
import {operationInterruptedFrom} from ${sdk("pipeline/operation-interrupted.ts")};
const owner=${JSON.stringify(owner)};
export class ErrorFixture extends DurableObject {
  mode=''; commands=0; destroyed=0;
  async configure(value){this.mode=value.sandboxName.name;}
  async execWithSessionToken(command){return {success:true,exitCode:0,stdout:'',stderr:''};}
  async startProcess(command){
    if(!command.startsWith('(fixture-main-'))return {success:true,exitCode:0,stdout:'',stderr:''};
    this.commands++;
    if(command.startsWith('(fixture-main-ordinary)'))throw new Error('ordinary literal failure');
    const error=new Error('Durable Object reset because its code was updated. '+${JSON.stringify(secret)});
    Object.defineProperty(error,'retryable',{value:true,enumerable:true});
    throw error;
  }
  async destroy(){this.destroyed++;}
  async cancel(){await this.destroy();}
  async stats(){return {commands:this.commands,destroyed:this.destroyed};}
}
export default {async fetch(request,env){
  const mode=new URL(request.url).pathname.slice(1);
  if(!['reset','ordinary'].includes(mode))return new Response('unknown fixture',{status:400});
  let actor='';
  const namespace={idFromName(name){actor=name;return env.FIXTURE.idFromName(name);},get(id){return env.FIXTURE.get(id);}};
  const runner=new SandboxRunner({SANDBOX:namespace});
  let rawCause=null;let rawAdmission=null;let failure;const reports=[];
  try{
    await withStepNotification({handle:{async fail(value){reports.push(value);},async succeed(){throw new Error('failure fixture cannot succeed');}},label:'script-contracts-'+mode,command:'fixture-main',sensitiveValues:[${JSON.stringify(secret)}]},
      async()=>{try{return {...await runner.run({instanceId:owner,attempt:1,label:'script-contracts-'+mode,command:'fixture-main-'+mode,source:{kind:'archive',url:'https://fixture.invalid/source'},ttlSeconds:3600,timeoutMs:10000,extraEnv:{OMG_DIAGNOSTIC_RUN_ID:owner,OMG_CI_LEAF_STEP:${JSON.stringify(leaf)}}}),cacheHit:false};}
        catch(error){rawCause=error.cause?.message??null;rawAdmission=error.context??null;throw error;}},
      async execution=>execution);
  }catch(error){failure=error;}
  const stats=await env.FIXTURE.get(env.FIXTURE.idFromName(actor)).stats();
  return Response.json({mode,owner,actor,sandboxId:env.FIXTURE.idFromName(actor).toString(),rawCause,rawAdmission,message:failure?.message??null,name:failure?.name??null,recoveryAdmitted:operationInterruptedFrom(failure)!==undefined,stats,reports});
}};
`;

test("actual SDK boundary keeps the redacted Durable Object cause and correlation", async () => {
  const built = await Bun.build({entrypoints:["fixture:entry"],target:"browser",external:["cloudflare:workers","node:*"],plugins:[{name:"real-sdk-boundary",setup(build){build.onResolve({filter:/^fixture:entry$/},()=>({path:"entry",namespace:"fixture"}));build.onLoad({filter:/.*/,namespace:"fixture"},()=>({contents:worker,loader:"ts"}));}}]});
  expect(built.success, built.logs.map((entry) => entry.message).join("\n")).toBe(true);
  const script = await built.outputs[0].text();
  const program = `import {createRequire} from 'node:module';
const require=createRequire(${JSON.stringify(new URL("../node_modules/wrangler/package.json", import.meta.url).href)});
const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const mf=new Miniflare(convertV4MiniflareOptions({handleStructuredLogs:({message})=>console.error(message),modules:true,script:${JSON.stringify(script)},compatibilityDate:'2026-10-20',compatibilityFlags:['nodejs_compat'],durableObjects:{FIXTURE:{className:'ErrorFixture',useSQLite:true}}}));
try{const rows=[];for(const mode of ['reset','ordinary']){const response=await mf.dispatchFetch('https://fixture.invalid/'+mode);if(response.status!==200)throw new Error(await response.text());rows.push(await response.json());}console.log(JSON.stringify(rows));}finally{await mf.dispose();}`;
  const child = Bun.spawn(["node", "--input-type=module", "-"], {stdin:new TextEncoder().encode(program),stdout:"pipe",stderr:"pipe"});
  const deadline = setTimeout(() => child.kill(), 30_000);
  let code, output, errors;
  try { [code, output, errors] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]); } finally { clearTimeout(deadline); }
  expect(code, errors).toBe(0);
  const rows = JSON.parse(output);
  expect(rows.map((row) => row.mode)).toEqual(["reset", "ordinary"]);
  for (const row of rows) {
    expect(row.stats.commands, row.mode).toBe(1);
    expect(row.stats.destroyed, row.mode).toBe(1);
    expect(row.recoveryAdmitted, row.mode).toBe(false);
    expect(row.reports.length, row.mode).toBe(1);
  }
  expect(rows[0].rawCause).toBe(`Durable Object reset because its code was updated. ${secret}`);
  expect(rows[0].rawAdmission.admitted).toBe("unknown");
  expect(rows[0].rawAdmission.retryable).toBe(false);
  const reported = rows[0].reports[0].error;
  expect(reported).toContain("Durable Object reset because its code was updated.");
  expect(reported).not.toContain(secret);
  expect(reported).toContain("run=40220918875");
  expect(reported).toContain("attempt=1");
  expect(reported).toContain("source=7c321c2a19a9e50f85a2610eb5140cae001e7443");
  expect(reported).toContain(`leaf=${leaf}`);
  expect(reported).toContain(`runnerId=${rows[0].actor}`);
  expect(reported).toContain(`actor=${rows[0].sandboxId}`);
  expect(rows[1].reports[0].error).toBe("ordinary literal failure");
});

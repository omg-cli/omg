import { lstat, readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { isGitHubInstallationToken, object, string } from "../src/domain";
import { CANONICAL_ORIGIN, STAGE_ORIGIN } from "../src/stage-identity";
import { baselineBinding, operatorPost, proofProgress, readCheckpoint, requireCheckpointTransport, stageOperatorFetcher } from "./operator";

const { values }=parseArgs({options:{state:{type:"string"},"release-tag":{type:"string"},asset:{type:"string"},stage:{type:"boolean",default:false},"max-steps":{type:"string",default:"20"},"delay-ms":{type:"string",default:"0"},help:{type:"boolean",default:false}},strict:true});
if(values.help) {
    process.stdout.write("bun scripts/verify-baseline.ts --state PATH --release-tag TAG --asset NAME [--stage] [--max-steps 20] [--delay-ms 0]\nRequires an ephemeral ghs_ GITHUB_TOKEN and RUNTIME_REFRESH_SECRET (or stage-only credentials with --stage) through environment only. The server derives publisher membership; operator counts and manifests cannot certify coverage. Stops when awaiting import/catchup or after its bounded serial step budget.\n");
    process.exit(0);
}
async function run() {
    if(!values.state || !values["release-tag"] || !values.asset) throw new Error("state, release-tag and asset required");
    const steps=Number(values["max-steps"]),delay=Number(values["delay-ms"]);
    if(!Number.isSafeInteger(steps)||steps<1||steps>1000||!Number.isSafeInteger(delay)||delay<0||delay>60000) throw new Error("invalid proof operator bounds");
    const info=await lstat(values.state);
    if(!info.isFile()||info.isSymbolicLink()||info.size>16*1024) throw new Error("state must be a bounded regular file");
    const saved=object(JSON.parse(await readFile(values.state,"utf8")));
    const stage=values.stage===true;
    requireCheckpointTransport(saved,stage);
    const rawBinding=object(saved.baseline);
    const binding=baselineBinding(rawBinding,string(saved.digest),stage?CANONICAL_ORIGIN:string(rawBinding.endpoint));
    if(!stage && binding.endpoint===STAGE_ORIGIN) throw new Error("the stage endpoint requires explicit stage mode");
    readCheckpoint(saved,binding);
    const secret=stage?process.env.STAGE_RUNTIME_REFRESH_SECRET:process.env.RUNTIME_REFRESH_SECRET, githubToken=process.env.GITHUB_TOKEN;
    if(!secret || secret.length<32 || !isGitHubInstallationToken(githubToken)) throw new Error("separate proof secret and ephemeral GitHub installation token required through environment");
    const endpoint=new URL(stage?STAGE_ORIGIN:binding.endpoint);
    const fetcher=stage?stageOperatorFetcher(process.env.STAGE_ACCESS_CLIENT_ID,process.env.STAGE_ACCESS_CLIENT_SECRET):undefined;
    const body=JSON.stringify({...binding,release_tag:values["release-tag"],asset:values.asset,github_token:githubToken});
    for(let step=0;step<steps;step++) {
        const progress=proofProgress(await operatorPost({endpoint,token:secret,path:"/internal/baseline/verify",body,fetcher}),{digest:binding.digest,release_tag:values["release-tag"],asset:values.asset});
        process.stdout.write(JSON.stringify({...progress,step:step+1})+"\n");
        if(["verified","awaiting_import","awaiting_catchup"].includes(String(progress.phase))) return;
        if(delay>0 && step+1<steps) await Bun.sleep(delay);
    }
}
run().catch(error=>{process.stderr.write(`${error instanceof Error?error.message:"baseline proof operator failed"}\n`);process.exitCode=1;});

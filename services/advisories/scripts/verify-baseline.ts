import { lstat, readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { object, string } from "../src/domain";
import { baselineBinding, operatorPost, proofProgress, readCheckpoint } from "./operator";

const { values }=parseArgs({options:{state:{type:"string"},"release-tag":{type:"string"},asset:{type:"string"},"max-steps":{type:"string",default:"20"},"delay-ms":{type:"string",default:"0"},help:{type:"boolean",default:false}},strict:true});
if(values.help) {
    process.stdout.write("bun scripts/verify-baseline.ts --state PATH --release-tag TAG --asset NAME [--max-steps 20] [--delay-ms 0]\nRequires RUNTIME_REFRESH_SECRET and an ephemeral ghs_ GITHUB_TOKEN through environment only. The server derives publisher membership; operator counts and manifests cannot certify coverage. Stops when awaiting import/catchup or after its bounded serial step budget.\n");
    process.exit(0);
}
async function run() {
    if(!values.state || !values["release-tag"] || !values.asset) throw new Error("state, release-tag and asset required");
    const steps=Number(values["max-steps"]),delay=Number(values["delay-ms"]);
    if(!Number.isSafeInteger(steps)||steps<1||steps>1000||!Number.isSafeInteger(delay)||delay<0||delay>60000) throw new Error("invalid proof operator bounds");
    const info=await lstat(values.state);
    if(!info.isFile()||info.isSymbolicLink()||info.size>16*1024) throw new Error("state must be a bounded regular file");
    const saved=object(JSON.parse(await readFile(values.state,"utf8")));
    const rawBinding=object(saved.baseline);
    const binding=baselineBinding(rawBinding,string(saved.digest),string(rawBinding.endpoint));
    readCheckpoint(saved,binding);
    const secret=process.env.RUNTIME_REFRESH_SECRET, githubToken=process.env.GITHUB_TOKEN;
    if(!secret || secret.length<32 || !githubToken || !/^ghs_[a-zA-Z0-9]{20,255}$/.test(githubToken)) throw new Error("separate proof secret and ephemeral GitHub installation token required through environment");
    const body=JSON.stringify({...binding,release_tag:values["release-tag"],asset:values.asset,github_token:githubToken});
    for(let step=0;step<steps;step++) {
        const progress=proofProgress(await operatorPost({endpoint:new URL(binding.endpoint),token:secret,path:"/internal/baseline/verify",body}),{digest:binding.digest,release_tag:values["release-tag"],asset:values.asset});
        process.stdout.write(JSON.stringify({...progress,step:step+1})+"\n");
        if(["verified","awaiting_import","awaiting_catchup"].includes(String(progress.phase))) return;
        if(delay>0 && step+1<steps) await Bun.sleep(delay);
    }
}
run().catch(error=>{process.stderr.write(`${error instanceof Error?error.message:"baseline proof operator failed"}\n`);process.exitCode=1;});

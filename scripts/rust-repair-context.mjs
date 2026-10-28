import {execFile} from "node:child_process";
import {promisify} from "node:util";
import {createHash} from "node:crypto";
import {sourceReviewInputSchema, REVIEW_SOURCE_BYTES} from "../services/ci-inspector/src/review-contract.ts";

const execute=promisify(execFile);

export async function collectRustRepairContext({source,directory}) {
    const input=sourceReviewInputSchema.parse(source);
    const rust=input.sourceFiles.filter(file=>file.path.startsWith("src/")&&file.path.endsWith(".rs"));
    if(!rust.length)return [];
    const paths=new Set(["Cargo.toml","src/lib.rs"]);
    for(const file of rust) {
        const parts=file.path.split("/");
        for(let end=2;end<parts.length;end++)paths.add(parts.slice(0,end).join("/")+"/mod.rs");
    }
    const context=[];
    const git=async args=>(await execute("git",["--no-pager","--literal-pathspecs",...args],{
        cwd:directory,encoding:"buffer",timeout:30000,maxBuffer:REVIEW_SOURCE_BYTES+8192,windowsHide:true,
    })).stdout;
    for(const path of paths) {
        if(input.sourceFiles.some(file=>file.path===path))continue;
        const listing=new TextDecoder("utf-8",{fatal:true}).decode(await git(["ls-tree","-l","-z",input.sha,"--",path]));
        if(!listing&&path.endsWith("/mod.rs"))continue;
        if(!listing)throw new Error(`Rust API context missing: ${path}`);
        const match=/^(100644|100755) blob ([a-f0-9]{40}) +([0-9]+)\t([^\0]+)\0$/.exec(listing);
        if(!match||match[4]!==path)throw new Error(`Rust API context is non-regular: ${path}`);
        const size=Number(match[3]);
        if(size>REVIEW_SOURCE_BYTES)throw new Error(`Rust API context exceeds existing source budget: ${path}`);
        const bytes=await git(["show",`${input.sha}:${path}`]);
        if(bytes.includes(0)||bytes.length!==size||createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex")!==match[2])
            throw new Error("Rust API context Git blob mismatch");
        context.push({path,blobSha:match[2],content:new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(bytes)});
        if(context.length+input.sourceFiles.length>12)throw new Error("Rust API context exceeds existing twelve-file budget");
    }
    return context;
}

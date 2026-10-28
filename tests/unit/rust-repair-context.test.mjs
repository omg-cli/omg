import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp, mkdir, writeFile, rm} from "node:fs/promises";
import {execFileSync} from "node:child_process";
import {tmpdir} from "node:os";
import path from "node:path";
import {collectRustRepairContext} from "../../scripts/rust-repair-context.mjs";

async function fixture(run) {
    const directory = await mkdtemp(path.join(tmpdir(), "omg-rust-context-"));
    const git = (...args) => execFileSync("git", ["-c", "maintenance.auto=false", "-c", "gc.auto=0", ...args],
        {cwd:directory,encoding:"utf8",windowsHide:true,stdio:["pipe","pipe","pipe"]}).trim();
    const commit = () => {git("add", ".");git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-m","context");return git("rev-parse","HEAD");};
    try {
        git("init");
        await mkdir(path.join(directory,"src/core/env"),{recursive:true});
        const files = {"Cargo.toml":'[package]\nname="fixture"\nversion="0.0.0"\n[lib]\nname="fixture_api"\n',
            "src/lib.rs":"pub mod core;\n", "src/core/mod.rs":"pub mod env;\n",
            "src/core/env/mod.rs":"pub mod team;\n", "src/core/env/team.rs":"pub struct Workspace;\n"};
        for(const [file,content] of Object.entries(files))await writeFile(path.join(directory,file),content);
        const sha=commit(), target="src/core/env/team.rs";
        const source={repository:"omg-cli/omg",sha,branch:"main",changedPaths:[],auditPaths:[target],diff:"",ciFailures:[],
            sourceFiles:[{path:target,blobSha:git("rev-parse",`${sha}:${target}`),content:files[target]}]};
        await run({directory,git,commit,files,source});
    } finally {
        assert.equal(path.dirname(directory),tmpdir());
        await rm(directory,{recursive:true,force:true});
    }
}

test("Rust repair context contains complete committed Cargo and public export blobs without widening editable source", async()=>fixture(async({directory,git,files,source})=>{
    await writeFile(path.join(directory,"Cargo.toml"),'uncommitted manifest');
    const before=JSON.stringify(source);
    const context=await collectRustRepairContext({source,directory});
    assert.deepEqual(context,["Cargo.toml","src/lib.rs","src/core/mod.rs","src/core/env/mod.rs"].map(file=>({
        path:file,blobSha:git("rev-parse",`${source.sha}:${file}`),content:files[file],
    })));
    assert.equal(JSON.stringify(source),before);
    assert.equal(context.some(file=>file.path===source.sourceFiles[0].path),false);
}));

test("Rust context fails closed on a missing manifest and non-regular context objects", async()=>fixture(async({directory,git,commit,source})=>{
    git("rm","Cargo.toml");
    let sha=commit();
    await assert.rejects(collectRustRepairContext({source:{...source,sha},directory}),/missing/i);
    await writeFile(path.join(directory,"Cargo.toml"),'[package]\n');
    sha=commit();
    const blob=git("rev-parse",`${sha}:Cargo.toml`);
    git("update-index","--cacheinfo",`120000,${blob},Cargo.toml`);
    git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-m","symlink");
    await assert.rejects(collectRustRepairContext({source:{...source,sha:git("rev-parse","HEAD")},directory}),/non-regular/i);
}));

test("Rust context rejects oversized blobs and does not attach Cargo context to another language", async()=>fixture(async({directory,commit,source})=>{
    await writeFile(path.join(directory,"Cargo.toml"),"x".repeat(256*1024+1));
    const sha=commit();
    await assert.rejects(collectRustRepairContext({source:{...source,sha},directory}),/budget/i);
    const other={...source,changedPaths:["src/value.js"],auditPaths:undefined,
        sourceFiles:[{...source.sourceFiles[0],path:"src/value.js"}]};
    assert.deepEqual(await collectRustRepairContext({source:other,directory}),[]);
}));

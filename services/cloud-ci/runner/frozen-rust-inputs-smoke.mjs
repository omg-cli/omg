import assert from "node:assert/strict";
import { mkdtemp, writeFile, chmod, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { preparePortable } from "./portable-process.mjs";
import { freezeRustInputs } from "./frozen-rust-inputs.mjs";

assert.equal(process.platform, "linux");
assert.equal(process.getuid(), 0);
const workspace = await mkdtemp("/tmp/omg-frozen-inputs-");
const home = path.join(workspace, "home");
const options = { home, protectedRoots: ["/opt/omg-ci"] };
try {
    await chmod(workspace, 0o755);
    preparePortable(workspace, [], options);
    const files = ["target/artifact", ".ci-cargo/dependency", "node_modules/dependency"].map((file) => path.join(workspace, file));
    for (const file of files) await writeFile(file, "compiled input");
    preparePortable(workspace, [], options);
    const frozen = await freezeRustInputs(workspace);
    const invoke = (locked) => {
        const program = `import assert from 'node:assert/strict';import{writeFileSync}from'node:fs';for(const file of ${JSON.stringify(files)}){if(${locked})assert.throws(()=>writeFileSync(file,'poison'),error=>['EACCES','EPERM'].includes(error.code));else writeFileSync(file,'next compiler stage');}writeFileSync(${JSON.stringify(path.join(home, "tmp/scratch"))},'test scratch');console.log('candidate input boundary verified');`;
        const result = spawnSync(process.execPath, ["--input-type=module", "-e", program], {
            uid: 10001, gid: 10001, env: { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: home }, encoding: "utf8", timeout: 10000,
        });
        assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    };
    invoke(true);
    await frozen.assertUnchanged();
    preparePortable(workspace, [], options);
    invoke(false);
    console.log("Linux candidate cannot write compiler inputs; scratch and next compiler-stage writes succeed");
} finally { await rm(workspace, { recursive: true, force: true }); }

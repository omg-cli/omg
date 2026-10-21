import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { preparePortable, portableOptions } from "/opt/omg-ci/portable-process.mjs";

assert.equal(process.platform, "linux");
assert.equal(process.getuid(), 0);
const workspace = await mkdtemp("/tmp/omg-portable-fixtures-");
const home = path.join(workspace, "home");
const tracked = ["Cargo.toml", "src/lib.rs"];
try {
    await mkdir(path.join(workspace, "src"));
    for (const file of tracked) await writeFile(path.join(workspace, file), "preserved source");
    const context = preparePortable(workspace, tracked, { home, protectedRoots: ["/opt/omg-ci"] });
    const program = `
        import assert from 'node:assert/strict';
        import {mkdtempSync,writeFileSync,unlinkSync,renameSync,chmodSync,statSync,rmSync} from 'node:fs';
        import path from 'node:path';
        const workspace=process.cwd();
        const fixture=mkdtempSync(path.join(workspace,'.owned-fixture-'));
        writeFileSync(path.join(fixture,'config'),'fixture');
        rmSync(fixture,{recursive:true});
        const denied=operation=>assert.throws(operation,error=>['EACCES','EPERM'].includes(error.code));
        for(const file of ${JSON.stringify(tracked)})denied(()=>writeFileSync(file,'changed'));
        denied(()=>unlinkSync('Cargo.toml'));
        denied(()=>renameSync('Cargo.toml','replacement.toml'));
        denied(()=>renameSync('src','replacement-src'));
        denied(()=>chmodSync(workspace,0o777));
        assert.equal(statSync(workspace).uid,0);
        assert.equal(statSync(workspace).mode&0o7777,0o1777);
    `;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", program], {
        ...portableOptions(workspace, home), encoding: "utf8", timeout: 10000,
    });
    assert.equal(result.status, 0, result.error?.message ?? result.stderr);
    context.assertSource();
    console.log("Candidate-owned relative fixtures work; tracked source cannot be changed or replaced");
} finally {
    await rm(workspace, { recursive: true, force: true });
}

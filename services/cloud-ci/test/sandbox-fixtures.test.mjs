import {expect, test} from "bun:test";
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";

for (const name of ["sandbox-execution-fence", "sandbox-lifecycle"]) {
  test(`${name} retains all seven cases in an isolated module cache`, () => {
    const child=spawnSync(process.execPath,["test",`./test/${name}.fixture.ts`],{
      cwd:fileURLToPath(new URL("../",import.meta.url)),encoding:"utf8",timeout:25000,windowsHide:true,
    });
    const output=(child.stdout??"")+(child.stderr??"");
    expect(child.status,output).toBe(0);
    expect(output).toContain("7 pass");
    expect(output).toContain("0 fail");
    expect(output).toContain("Ran 7 tests across 1 file.");
  },30000);
}

import { expect, test } from "bun:test";
import { mkdtemp, mkdir, readdir, copyFile, symlink, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

test("trusted audit executor imports in source and both exact Docker COPY layouts", async () => {
    const fixture = await mkdtemp(path.join(tmpdir(), "omg-audit-layout-"));
    const sourceRoot = fileURLToPath(new URL("../../../", import.meta.url));
    const runner = path.join(sourceRoot, "services/cloud-ci/runner");
    const image = path.join(fixture, "image/opt/omg-ci");
    try {
        await mkdir(path.join(image, "runner"), { recursive: true });
        for (const name of await readdir(runner)) {
            if (!name.endsWith(".mjs")) continue;
            for (const directory of [image, path.join(image, "runner")])
                await copyFile(path.join(runner, name), path.join(directory, name));
        }
        await copyFile(path.join(sourceRoot, "services/cloud-ci/verifier.mjs"), path.join(image, "verifier.mjs"));
        for (const scripts of [path.join(fixture, "scripts"), path.join(fixture, "image/scripts")]) {
            await mkdir(scripts, { recursive: true });
            await copyFile(path.join(sourceRoot, "scripts/rust-source-policy.mjs"), path.join(scripts, "rust-source-policy.mjs"));
        }
        await symlink(path.join(sourceRoot, "node_modules"), path.join(image, "node_modules"), "junction");
        const flattened = path.join(image, "audit-verifier.mjs");
        const intact = await readFile(flattened, "utf8");
        await writeFile(flattened, intact.replace(/^const verifierRelative = .+;$/m, 'const verifierRelative = "../verifier.mjs";'));
        const fault = spawnSync("node", ["--input-type=module", "-e", `await import(${JSON.stringify(pathToFileURL(flattened).href)})`],
            { encoding: "utf8", timeout: 20000, windowsHide: true });
        expect(fault.status).toBe(1);
        expect(fault.stderr).toContain("ERR_MODULE_NOT_FOUND");
        await writeFile(flattened, intact);
        const modules = [path.join(runner, "audit-verifier.mjs"), path.join(image, "audit-verifier.mjs"), path.join(image, "runner/audit-verifier.mjs")];
        const program = `import assert from 'node:assert/strict'; for(const url of ${JSON.stringify(modules.map((file) => pathToFileURL(file).href))}){const module=await import(url);assert.equal(typeof module.applyTestAudit,'function');assert.equal(typeof module.verifyTestAudit,'function');} console.log('three trusted audit layouts imported');`;
        const result = spawnSync("node", ["--input-type=module", "-e", program], { encoding: "utf8", timeout: 20000, windowsHide: true });
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout.trim()).toBe("three trusted audit layouts imported");
    } finally { await rm(fixture, { recursive: true, force: true }); }
});

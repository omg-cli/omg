import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const linuxRoot = process.platform === "linux" && process.getuid?.() === 0;
const name = "portable timeout diagnostics stay bounded on real Linux candidate execution";

if (linuxRoot)
    test(name, () => {
        const child = spawnSync(
            process.execPath,
            [fileURLToPath(new URL("../runner/portable-timeout-smoke.mjs", import.meta.url))],
            { encoding: "utf8", timeout: 60000 },
        );

        expect(child.status, child.stderr).toBe(0);
    });
else
    test.skip(`${name} (requires Linux root; Dockerfile smoke is the acceptance proof)`, () => {});

import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { portableOptions } from "../runner/portable-process.mjs";

test("portable execution drops identity and does not inherit controller credentials", () => {
    const previous = process.env.GH_TOKEN;
    process.env.GH_TOKEN = "fixture-controller-secret";

    try {
        const options = portableOptions("/workspace", "/tmp/portable-home", {
            GITHUB_RUN_ID: "123",
            GH_TOKEN: "fixture-injected-secret",
            NODE_OPTIONS: "--import=untrusted",
            OMG_NODE_TEST_FIXTURE: "/untrusted/node",
            GIT_CONFIG_COUNT: "1",
            GIT_CONFIG_KEY_0: "safe.directory",
            GIT_CONFIG_VALUE_0: "*",
            PYTHONPATH: "/untrusted/modules",
        });

        expect(options.uid).toBe(10001);
        expect(options.gid).toBe(10001);
        expect(options.detached).toBe(true);
        expect(options.env.HOME).toBe("/tmp/portable-home");
        expect(options.env).toMatchObject({ GITHUB_RUN_ID: "123" });
        expect(Object.hasOwn(options.env, "GH_TOKEN")).toBe(false);
        expect(Object.hasOwn(options.env, "NODE_OPTIONS")).toBe(false);
        expect(options.env.OMG_NODE_TEST_FIXTURE).toBe("/opt/omg-node-test-fixture/node");
        expect(options.env.PYTHONPATH).toBe("/workspace");
        expect(options.env).toMatchObject({
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_CONFIG_COUNT: "3",
            GIT_CONFIG_KEY_0: "maintenance.auto",
            GIT_CONFIG_VALUE_0: "false",
            GIT_CONFIG_KEY_1: "gc.auto",
            GIT_CONFIG_VALUE_1: "0",
            GIT_CONFIG_KEY_2: "safe.directory",
            GIT_CONFIG_VALUE_2: "/workspace",
        });
        expect(Object.hasOwn(options.env, "GIT_DIR")).toBe(false);
        expect(Object.hasOwn(options.env, "GIT_WORK_TREE")).toBe(false);
    } finally {
        if (previous === undefined) delete process.env.GH_TOKEN;
        else process.env.GH_TOKEN = previous;
    }
});

test("preparation enables owned fixtures while preserving protected source and dependency metadata", () => {
    const modulePath = new URL("../runner/portable-process.mjs", import.meta.url).href;

    const child = spawnSync("node", [
        "--eval",
        `
      import fs from "node:fs";
      import path from "node:path";
      import { syncBuiltinESMExports } from "node:module";
      import assert from "node:assert/strict";
      const writes = [];
      const created = [];
      const originalRead = fs.readFileSync;
      const dependency = "/workspace/node_modules/pkg.js";
      const normalize = (file) => String(file).replaceAll(String.fromCharCode(92), "/");
      const fixtures = {
        "pkg.js": { uid: 10001, gid: 10001, mode: 0o100644 },
        "special.js": { uid: 10001, gid: 10001, mode: 0o107644 },
        "owner.js": { uid: 0, gid: 10001, mode: 0o100644 },
        "group.js": { uid: 10001, gid: 0, mode: 0o100644 },
        "link.js": { uid: 0, gid: 0, mode: 0o120777 },
        "tracked.txt": { uid: 0, gid: 0, mode: 0o100444 },
        "deep-audit.tsv": { uid: 0, gid: 0, mode: 0o100444 },
        "tracked-executable.mjs": { uid: 0, gid: 0, mode: 0o100555 },
      };
      const stat = (file) => {
        const name = normalize(file).split("/").at(-1);
        return {
          ...(["/workspace", "/workspace/src", "/workspace/.audit"].includes(normalize(file)) ? { uid: 0, gid: 0, mode: 0o40755 } : fixtures[name] ?? { uid: 10001, gid: 10001, mode: 0o40755 }),
          isDirectory: () => !Object.hasOwn(fixtures, name),
          isSymbolicLink: () => name === "link.js",
          isFile: () => Object.hasOwn(fixtures, name) && name !== "link.js",
        };
      };
      Object.assign(fs, {
        lstatSync: stat,
        readdirSync: (file) => normalize(file) === "/workspace" ? ["node_modules", "src", ".audit"] : normalize(file) === "/workspace/src" ? ["tracked.txt", "tracked-executable.mjs"] : normalize(file) === "/workspace/.audit" ? ["deep-audit.tsv"] : normalize(file) === "/workspace/node_modules" ? Object.keys(fixtures) : [],
        chownSync: (file, uid, gid) => writes.push(["chown", normalize(file), uid, gid]),
        chmodSync: (file, mode) => writes.push(["chmod", normalize(file), mode]),
        mkdirSync: (file) => created.push(normalize(file)),
        readFileSync: (file, ...args) => (normalize(file).endsWith("/target/tracked.txt") || normalize(file).includes("/src/") || normalize(file).includes("/.audit/")) ? Buffer.from("tracked fixture") : originalRead(file, ...args),
      });
      syncBuiltinESMExports();
      Object.defineProperty(process, "platform", { value: "linux" });
      process.getuid = () => 0;
      const { preparePortable } = await import(${JSON.stringify(modulePath)});
      const context = preparePortable(path.normalize("/workspace"), ["src/tracked.txt", "src/tracked-executable.mjs", ".audit/deep-audit.tsv"], { protectedRoots: [] });
      context.assertSource();
      assert.deepEqual(writes.filter(([, file]) => file === "/workspace" || file === "/workspace/src" || file.startsWith("/workspace/src/") || file === "/workspace/.audit" || file.startsWith("/workspace/.audit/")), [["chmod", "/workspace", 0o1777]]);
      assert.deepEqual(writes.filter(([, file]) => file === dependency), []);
      const forFile = (name) => writes.filter(([, file]) => file === "/workspace/node_modules/" + name);
      assert.deepEqual(forFile("special.js"), [["chmod", "/workspace/node_modules/special.js", 0o644]]);
      assert.deepEqual(forFile("owner.js"), [["chown", "/workspace/node_modules/owner.js", 10001, 10001]]);
      assert.deepEqual(forFile("group.js"), [["chown", "/workspace/node_modules/group.js", 10001, 10001]]);
      assert.deepEqual(forFile("link.js"), []);
      assert.ok(!created.includes("/workspace/.audit"));
      assert.ok(created.includes("/workspace/target"));
      assert.ok(writes.some(([operation, file, uid, gid]) => operation === "chown" && file === "/workspace/target" && uid === 10001 && gid === 10001));
      assert.ok(writes.some(([operation, file, mode]) => operation === "chmod" && file === "/workspace/target" && mode === 0o755));
      assert.throws(() => preparePortable(path.normalize("/workspace"), ["target/tracked.txt"], { protectedRoots: [] }), /Build directory overlaps tracked source/);
      assert.throws(() => preparePortable("/workspace", [], { protectedRoots: ["/untrusted-controller"] }), /Controller path is writable by candidate/);
    `,
    ]);

    expect(child.status, new TextDecoder().decode(child.stderr)).toBe(0);
});

import { expect, test } from "bun:test";
import * as fs from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const sdkEntry = fileURLToPath(import.meta.resolve("@opencode/sdk/workerd"));
const utilEntry = Bun.resolveSync("@opencode/util/glob", dirname(sdkEntry));
const require = createRequire(utilEntry);
const { Glob } = await import(pathToFileURL(utilEntry).href);
const { glob } = require("glob");
const mapWorkspaces = createRequire(require.resolve("@npmcli/arborist"))("@npmcli/map-workspaces");
const pacoteRequire = createRequire(require.resolve("pacote"));
const ignoreWalk = createRequire(pacoteRequire.resolve("npm-packlist"))("ignore-walk");
const { rimraf, rimrafSync } = require("rimraf");

test("actual glob and minimatch consumers resolve patched dependency versions", () => {
  const consumers = [
    [utilEntry, ["glob", "minimatch"]],
    ...["@npmcli/map-workspaces", "@npmcli/package-json", "cacache", "rimraf"].map(name => [require.resolve(name), ["glob"]]),
    ...["@npmcli/arborist", "ignore-walk", "@tufjs/models"].map(name => [require.resolve(name), ["minimatch"]]),
  ];
  for (const [entry, dependencies] of consumers) {
    const fromConsumer = createRequire(entry);
    for (const dependency of dependencies) {
      const { version } = fromConsumer(`${dependency}/package.json`);
      const range = dependency === "glob" ? ">=14.0.2 <15" : ">=11.0.1 <12";
      expect(Bun.semver.satisfies(version, range), `${entry} resolved ${dependency}@${version}`).toBe(true);
    }
  }
});

test("installed workspace discovery and ignore rules retain their dependency APIs", async () => {
  const root = await mkdtemp(join(tmpdir(), "omg-workspace-dependencies-"));
  try {
    for (const name of ["one", "two", "skip"]) {
      const directory = join(root, "packages", name);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, "package.json"), JSON.stringify({ name: `fixture-${name}`, version: "1.0.0" }));
    }
    await writeFile(join(root, ".npmignore"), "ignored.txt\ncache/\n");
    await writeFile(join(root, "ignored.txt"), "excluded");
    await writeFile(join(root, "keep.txt"), "kept");
    await mkdir(join(root, "cache"));
    await writeFile(join(root, "cache", "discard.txt"), "excluded");
    const workspaces = await mapWorkspaces({ cwd: root, pkg: { workspaces: ["packages/*", "!packages/skip"] } });
    expect([...workspaces.keys()]).toEqual(["fixture-one", "fixture-two"]);
    const files = await ignoreWalk({ path: root, ignoreFiles: [".npmignore"] });
    expect(files).toContain("keep.txt");
    expect(files).not.toContain("ignored.txt");
    expect(files).not.toContain("cache/discard.txt");
    expect(await Glob.scan("**/*.txt", { cwd: root, ignore: ["cache/**", "ignored.txt"] })).toEqual(["keep.txt"]);
    expect(Glob.match("**/*.txt", ".hidden/keep.txt")).toBe(true);
    expect(Glob.match("**/*.txt", "keep.js")).toBe(false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed rimraf async and sync glob deletion stay inside the private fixture", async () => {
  const root = await mkdtemp(join(tmpdir(), "omg-rimraf-dependencies-"));
  try {
    for (const name of ["async.tmp", "sync.tmp", "keep.txt"]) await writeFile(join(root, name), name);
    expect(await rimraf(join(root, "async.*"), { glob: true })).toBe(true);
    expect(rimrafSync(join(root, "sync.*"), { glob: true })).toBe(true);
    expect(fs.existsSync(join(root, "async.tmp"))).toBe(false);
    expect(fs.existsSync(join(root, "sync.tmp"))).toBe(false);
    expect(await readFile(join(root, "keep.txt"), "utf8")).toBe("keep.txt");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("aborted installed glob traversal stops directory reads", async () => {
  const root = await mkdtemp(join(tmpdir(), "omg-glob-abort-"));
  try {
    for (let index = 0; index < 12; index++) await mkdir(join(root, String(index), "nested"), { recursive: true });
    const controller = new AbortController();
    let reads = 0;
    const filesystem = {
      readdir(path, options, callback) {
        const first = ++reads === 1;
        fs.readdir(path, options, (error, entries) => {
          if (first && !error) controller.abort(new Error("fixture-abort"));
          callback(error, entries);
        });
      },
    };
    await expect(glob("**/*", { cwd: root, fs: filesystem, signal: controller.signal })).rejects.toThrow("fixture-abort");
    const readsAtReject = reads;
    await Bun.sleep(50);
    expect(reads).toBe(readsAtReject);
    expect(reads).toBe(1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed minimatch bounds preprocessing of an amplification pattern", async () => {
  const program = `const {Minimatch}=require(${JSON.stringify(require.resolve("minimatch"))});
const pattern=Array.from({length:15},(_,index)=>'part'+index+'/**/../').join('')+'leaf';
const matcher=new Minimatch(pattern,{optimizationLevel:2});
if(typeof matcher.match('leaf')!=='boolean')throw new Error('Invalid matcher result');
console.log('completed');`;
  const child = Bun.spawn([process.execPath, "--eval", program], {
    stdout: "pipe", stderr: "pipe", timeout: 2000, killSignal: "SIGKILL",
  });
  const [code, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  expect(code, stderr).toBe(0);
  expect(stdout.trim()).toBe("completed");
});

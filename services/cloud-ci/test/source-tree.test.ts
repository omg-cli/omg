import { expect, test } from "bun:test";
import { mkdtemp, mkdir, writeFile, rm, symlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pruneRestoredSource } from "../runner/source-tree.mjs";

test("restored dependency cache cannot resurrect removed source or follow old symlinks", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "omg-ci-source-"));
  const outside = await mkdtemp(path.join(tmpdir(), "omg-ci-outside-"));

  try {
    for (const directory of [
      "src",
      "node_modules/pkg",
      "services/subscriptions/node_modules/pkg",
      "dist",
    ])
      await mkdir(path.join(root, directory), { recursive: true });

    for (const filename of [
      "src/current.mjs",
      "src/deleted.mjs",
      "node_modules/pkg/index.js",
      "services/subscriptions/node_modules/pkg/index.js",
      "dist/stale.js",
    ])
      await writeFile(path.join(root, filename), filename);
    await writeFile(path.join(outside, "retained.txt"), "retain");
    await symlink(
      outside,
      path.join(root, "old-link"),
      process.platform === "win32" ? "junction" : "dir",
    );
    pruneRestoredSource(root, ["src/current.mjs"]);

    for (const filename of [
      "src/current.mjs",
      "node_modules/pkg/index.js",
      "services/subscriptions/node_modules/pkg/index.js",
    ])
      expect(existsSync(path.join(root, filename))).toBe(true);

    for (const filename of ["src/deleted.mjs", "dist", "old-link"])
      expect(existsSync(path.join(root, filename))).toBe(false);
    expect(existsSync(path.join(outside, "retained.txt"))).toBe(true);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

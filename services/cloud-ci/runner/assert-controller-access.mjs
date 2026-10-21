import assert from "node:assert/strict";
import { accessSync, constants, readFileSync, readdirSync } from "node:fs";

const root = "/opt/omg-ci/";

const files = readdirSync(root).filter(
  (name) => name.endsWith(".mjs") || ["package.json", "bun.lock"].includes(name),
);

for (const required of ["prepare-sdk-api.mjs", "package.json", "bun.lock"])
  assert.ok(files.includes(required));

await import("/opt/omg-ci/prepare-sdk-api.mjs");

assert.throws(() => accessSync(root, constants.W_OK), { code: "EACCES" });

for (const name of files) {
  const file = root + name;
  assert.ok(readFileSync(file).length > 0);
  assert.throws(() => accessSync(file, constants.W_OK), { code: "EACCES" });
}

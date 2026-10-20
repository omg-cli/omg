import { expect, test } from "bun:test";
import { backupTransferMode, leafSnapshotOptions } from "../src/backup-policy";
import { cloudCiChecks } from "../runner/plan.mjs";
import { resolveCacheKey } from "../node_modules/@cloudflare/ci/src/ci/cache";

test("only known terminal checks exclude both normal and hidden snapshot entries", () => {
  for (const name of cloudCiChecks.slice(1))
    expect(leafSnapshotOptions(name)).toEqual({ excludes: ["*", ".*"] });

  for (const name of [
    undefined,
    "install",
    "frozen-dependencies",
    "unknown",
    "regression-red-green",
  ])
    expect(leafSnapshotOptions(name)).toEqual({});
});

test("private native credentials produce a distinct dependency cache identity without containing credentials", async () => {
  const native = backupTransferMode({
    R2_ACCESS_KEY_ID: "fixture-access",
    R2_SECRET_ACCESS_KEY: "fixture-secret",
  });

  const binding = backupTransferMode({});

  expect(native).toBe("native-r2-auto");
  expect(binding).toBe("binding-rpc");

  const input = {
    repo: "fixed-repo",
    label: "frozen-dependencies",
    command: "node /opt/omg-ci/run.mjs install",
    paths: ["bun.lock"],
    blobs: [{ path: "bun.lock", sha: "a".repeat(40) }],
  };

  const nativeKey = await resolveCacheKey({ ...input, env: { OMG_CI_BACKUP_MODE: native } });
  const bindingKey = await resolveCacheKey({ ...input, env: { OMG_CI_BACKUP_MODE: binding } });

  expect(nativeKey).not.toBe(bindingKey);
  expect(native).not.toContain("fixture-access");
  expect(native).not.toContain("fixture-secret");
  expect(backupTransferMode({ R2_ACCESS_KEY_ID: "fixture-access" })).toBe("binding-rpc");
  expect(backupTransferMode({ R2_SECRET_ACCESS_KEY: "fixture-secret" })).toBe("binding-rpc");
});

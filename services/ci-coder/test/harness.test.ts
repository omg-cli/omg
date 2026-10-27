import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { z } from "zod";
import { codingRuntimeIdentity, assertRuntimeIdentity } from "../src/runtime";

test("the coding consumer uses the CI worker's exact image and verifier", () => {
  const config = z.object({ vars: z.object({
    CI_IMAGE_DIGEST: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    CI_VERIFIER_REVISION: z.string().regex(/^[a-f0-9]{40}$/),
  }) });
  const [worker, coder] = ["../../cloud-ci/wrangler.jsonc", "../wrangler.jsonc"].map(path =>
    config.parse(Bun.JSONC.parse(readFileSync(new URL(path, import.meta.url), "utf8"))).vars,
  );
  const runtime = codingRuntimeIdentity({ ...coder, CI_API_TOKEN: "x".repeat(32) }, "a".repeat(64));
  expect({ image: runtime.imageDigest, verifier: runtime.verifierRevision }).toEqual({
    image: worker.CI_IMAGE_DIGEST, verifier: worker.CI_VERIFIER_REVISION,
  });
});

test("a durable coding operation cannot silently change verifier or mandatory skills on recovery", () => {
  const configuration = {
    CI_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
    CI_VERIFIER_REVISION: "b".repeat(40),
    CI_API_TOKEN: "x".repeat(32),
  };

  const identity = codingRuntimeIdentity(configuration, "c".repeat(64));
  expect(() => assertRuntimeIdentity(JSON.stringify(identity), identity)).not.toThrow();

  for (const previous of [
    "not-json",
    JSON.stringify({ ...identity, bundleSha256: "d".repeat(64) }),
    JSON.stringify({ ...identity, imageDigest: `sha256:${"d".repeat(64)}` }),
    JSON.stringify({ ...identity, verifierRevision: "d".repeat(40) }),
    JSON.stringify({ ...identity, reasoningEffort: "high" }),
  ])
    expect(() => assertRuntimeIdentity(previous, identity)).toThrow();
  expect(() =>
    codingRuntimeIdentity({ ...configuration, CI_API_TOKEN: "missing" }, "c".repeat(64)),
  ).toThrow();
  expect(() => codingRuntimeIdentity(configuration, "missing-skill-hash")).toThrow();
});

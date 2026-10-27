import { expect, test } from "bun:test";
import { codingRuntimeIdentity, assertRuntimeIdentity } from "../src/runtime";

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

import { expect, mock, test } from "bun:test";
import { createHash } from "node:crypto";
mock.module("cloudflare:workers", () => ({ DurableObject: class {}, WorkerEntrypoint: class {} }));
const { Coder } = await import("../src/harness.ts");
const { codingRuntimeIdentity } = await import("../src/runtime.ts");
const { requiredSkillsManifest } = await import("../src/skills.ts");
const { operationIdentity, parseCodingRequest } = await import("../src/request.ts");

function fixture() {
  const content = "export const value = 1;\n";
  const request = parseCodingRequest({
    repository: "omg-cli/omg", sha: "a".repeat(40), branch: "main", runId: "123", attempt: "1",
    diagnosisTask: true,
    source: { repository: "omg-cli/omg", sha: "a".repeat(40), branch: "main", changedPaths: [],
      auditPaths: ["scripts/fixture.mjs"], diff: "", sourceFiles: [{ path: "scripts/fixture.mjs", content,
        blobSha: createHash("sha1").update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest("hex") }] },
  });
  const id = operationIdentity(request);
  const env = { CI_API_TOKEN: "v".repeat(40), CODER_API_TOKEN: "c".repeat(40),
    CI_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`, CI_VERIFIER_REVISION: "d".repeat(40),
    CI_SERVICE: { fetch() { throw new Error("unexpected verifier request"); } } };
  const calls = [];
  const runtime = codingRuntimeIdentity(env, requiredSkillsManifest.bundleSha256);
  const values = new Map([["request", request], ["runtime-identity", JSON.stringify(runtime)]]);
  const host = Object.assign(Object.create(Coder.prototype), {
    ctx: { id: { name: id }, storage: {
      async get(key) { return values.get(key); },
      async put() { throw new Error("unexpected storage mutation"); },
    } }, env,
    harness: {
      async pending() { return []; },
      async wait(value) { calls.push(`wait:${value}`); return { status: "done", session: "ses_root", text: "incomplete final fragment" }; },
      session(value) { expect(value).toBe("ses_root"); return { async history() {
        calls.push("history"); return [
          { type: "assistant", id: "first", content: [{ type: "text", text: "production edit" }] },
          { type: "assistant", id: "last", content: [{ type: "text", text: `test edit ${env.CODER_API_TOKEN}` }] },
        ];
      } }; },
      async submit() { throw new Error("unexpected model submission"); },
    },
  });
  return { host, calls, id, values };
}

test("actual Coder status reads terminal diagnostic history without model, storage or verifier progression", async () => {
  const { host, calls, id } = fixture();
  const result = await host.status({ diagnosisHistory: true });
  expect(result.status).toBe("done");
  expect(result.diagnosisHistory).toEqual([
    { id: "first", text: ["production edit"] }, { id: "last", text: ["test edit [REDACTED]"] },
  ]);
  expect(calls).toEqual([`wait:${id}`, "history"]);
  expect(result).not.toHaveProperty("diagnosis");
  expect(result).not.toHaveProperty("reason");
});

test("actual Coder history read rejects runtime drift before reading the transcript", async () => {
  const { host, calls, id, values } = fixture();
  const runtime = JSON.parse(values.get("runtime-identity"));
  values.set("runtime-identity", JSON.stringify({ ...runtime, verifierRevision: "e".repeat(40) }));
  await expect(host.status({ diagnosisHistory: true })).rejects.toThrow("runtime identity changed");
  expect(calls).toEqual([`wait:${id}`]);
});

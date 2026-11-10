import { expect, mock, test } from "bun:test";

mock.module("cloudflare:workers", () => ({ DurableObject: class {}, RpcTarget: class {}, WorkerEntrypoint: class {}, tracing: undefined }));
const { handleCapabilityProbe } = await import("../src/ubuntu-pilot");
const token = "capability-probe-fixture-token-0123456789";
const report = {
  accepted: true,
  distro: { ID: "ubuntu", VERSION_ID: "22.04" },
  uid: 0,
  capEff: "0000000000000000",
  checks: { ownedTemporaryDirectory: true, ownershipChange: true, candidateIdentity: true,
    frozenControllerProtected: true, processGroupTermination: true },
  cleanup: true,
  error: null,
};
function fixture(options: { execReject?: boolean; cleanupReject?: boolean; report?: unknown } = {}) {
  const calls: string[] = [];
  const sandbox = {
    async armProbe() { calls.push("arm"); },
    async exec(command: string, executionOptions: object) {
      calls.push("exec");
      if ("signal" in executionOptions) throw new Error("AbortSignal serialization is not enabled.");
      if (options.execReject) throw new Error("execution unavailable");
      return { success: true, exitCode: 0, stdout: JSON.stringify(options.report ?? report), stderr: "",
        command, duration: 1, timestamp: new Date().toISOString() };
    },
    async finishProbe() {
      calls.push("destroy");
      if (options.cleanupReject) throw new Error("destroy unavailable");
      return { destroyed: true };
    },
  };
  const send = (authorization = `Bearer ${token}`, body = '{"kind":"capability-smoke"}') =>
    handleCapabilityProbe(new Request("https://pilot.invalid/probe", { method: "POST", headers: { authorization }, body }), token,
      () => { calls.push("connect"); return sandbox; });
  return { calls, send };
}
test("unauthorized and invalid probe bodies start no sandbox", async () => {
  const state = fixture();
  expect((await state.send("Bearer wrong")).status).toBe(401);
  expect((await state.send(undefined, '{"kind":"shell","command":"id"}')).status).toBe(400);
  expect((await state.send(undefined, "x".repeat(129))).status).toBe(400);
  expect(state.calls).toEqual([]);
});
test("fixed capability probe preserves actual distro and confirms destroy before success", async () => {
  const state = fixture();
  const response = await state.send();
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ accepted: true, destroyed: true, probe: { distro: { VERSION_ID: "22.04" } } });
  expect(state.calls).toEqual(["connect", "arm", "exec", "destroy"]);
});
test("execution and cleanup failures cannot pass and still destroy", async () => {
  for (const options of [{ execReject: true }, { cleanupReject: true }, { report: { ...report, cleanup: false } },
    { report: { ...report, checks: { ...report.checks, frozenControllerProtected: false } } }]) {
    const state = fixture(options);
    const response = await state.send();
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ accepted: false });
    expect(state.calls.at(-1)).toBe("destroy");
  }
});

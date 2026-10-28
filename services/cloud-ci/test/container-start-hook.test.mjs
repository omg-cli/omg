import { expect, mock, test } from "bun:test";

mock.module("cloudflare:workers", () => ({ DurableObject: class {}, RpcTarget: class {}, WorkerEntrypoint: class {}, tracing: undefined }));
const { Container } = await import("@cloudflare/containers");

function host(fenced) {
  let starts = 0;
  const instance = Object.assign(Object.create(Container.prototype), {
    container: {
      running: false,
      start() { starts += 1; },
      monitor() { return new Promise(() => {}); },
      getTcpPort() { return { async fetch() { return new Response(); } }; },
    },
    beforeStart() { if (fenced) throw new Error("fixture teardown fence"); },
    renewActivityTimeout() {},
    async scheduleNextAlarm() {},
    async refreshOutboundInterception() {},
    state: { async setRunning() {} },
  });
  return { instance, starts: () => starts };
}
const wait = { instanceGetTimeoutMS: 20, waitInterval: 10, portToCheck: 33 };

test("installed Container start honors a rejecting lifecycle hook before submission", async () => {
  const state = host(true);
  await expect(state.instance.startContainerIfNotRunning(wait)).rejects.toThrow("fixture teardown fence");
  expect(state.starts()).toBe(0);
});

test("installed Container start still submits once when the hook permits it", async () => {
  const state = host(false);
  expect(await state.instance.startContainerIfNotRunning(wait)).toBe(0);
  expect(state.starts()).toBe(1);
});

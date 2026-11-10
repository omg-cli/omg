import { afterEach, expect, mock, setSystemTime, test } from "bun:test";

const schedules: { when: Date | number; callback: string; payload: unknown; id: number }[] = [];
let destroyFailures = 0;
let destroys = 0;

mock.module("@cloudflare/sandbox", () => ({
  Sandbox: class {
    ctx: ReturnType<typeof context>;
    constructor(ctx: ReturnType<typeof context>) { this.ctx = ctx; }
    beforeStart() {}
    async schedule(when: Date | number, callback: string, payload: unknown) {
      schedules.push({ when, callback, payload, id: schedules.length + 1 });
    }
    async destroy() {
      destroys++;
      if (destroyFailures-- > 0) throw new Error("provider stop unavailable");
      this.ctx.container.running = false;
    }
  },
  getSandbox() { throw new Error("lifecycle test never connects a real sandbox"); },
}));
const { UbuntuPilotSandbox } = await import("../src/ubuntu-pilot");

function context(values = new Map<string, unknown>()) {
  const initializers: Promise<unknown>[] = [];
  return Object.assign(Object.create(null), {
    values, initializers, container: { running: true },
    storage: { async get(key: string) { return values.get(key); }, async put(key: string, value: unknown) { values.set(key, structuredClone(value)); } },
    blockConcurrencyWhile(callback: () => Promise<unknown>) { const work = callback(); initializers.push(work); return work; },
  });
}
async function instance(values?: Map<string, unknown>) {
  const ctx = context(values);
  const sandbox = new UbuntuPilotSandbox(ctx, {});
  await Promise.all(ctx.initializers);
  return { sandbox, ctx, start: () => Reflect.get(sandbox, "beforeStart").call(sandbox) };
}
afterEach(() => { setSystemTime(); schedules.length = 0; destroyFailures = 0; destroys = 0; });

test("probe must arm once before start and persists its absolute expiry across reload", async () => {
  setSystemTime(new Date("2026-11-10T19:00:00Z"));
  const first = await instance();
  expect(first.start).toThrow("late container start");
  await first.sandbox.armProbe();
  expect(first.start).not.toThrow();
  await expect(first.sandbox.armProbe()).rejects.toThrow("already used");
  expect(schedules).toHaveLength(1);
  expect(schedules[0]).toMatchObject({ when: new Date("2026-11-10T19:03:00Z"), callback: "expireProbe", payload: null });
  const restored = await instance(first.ctx.values);
  expect(restored.start).not.toThrow();
  setSystemTime(new Date("2026-11-10T19:03:00Z"));
  expect(restored.start).toThrow("late container start");
});

test("failed deadline callback persists its closed fence and schedules a new bounded cleanup attempt", async () => {
  setSystemTime(new Date("2026-11-10T19:00:00Z"));
  const first = await instance();
  await first.sandbox.armProbe();
  setSystemTime(new Date("2026-11-10T19:03:00Z"));
  destroyFailures = 1;
  await expect(first.sandbox.expireProbe()).rejects.toThrow("provider stop unavailable");
  expect(first.start).toThrow("late container start");
  expect(schedules).toHaveLength(2);
  expect(schedules[1]).toMatchObject({ when: 5, callback: "expireProbe", payload: null });
  expect(schedules[1].id).not.toBe(schedules[0].id);
  const restored = await instance(first.ctx.values);
  expect(restored.start).toThrow("late container start");
  await restored.sandbox.expireProbe();
  expect(restored.ctx.container.running).toBe(false);
  expect(destroys).toBe(2);
});

test("cleanup retry count and retry window are finite when the provider stays unavailable", async () => {
  setSystemTime(new Date("2026-11-10T19:00:00Z"));
  const state = await instance();
  await state.sandbox.armProbe();
  setSystemTime(new Date("2026-11-10T19:03:00Z"));
  destroyFailures = 10;
  for (let attempt = 0; attempt < 3; attempt++) await expect(state.sandbox.expireProbe()).rejects.toThrow();
  expect(schedules).toHaveLength(3);
  expect(destroys).toBe(3);
  setSystemTime(new Date("2026-11-10T19:03:16Z"));
  await expect(state.sandbox.expireProbe()).rejects.toThrow();
  expect(schedules).toHaveLength(3);
  expect(state.start).toThrow("late container start");
});

import { expect, test } from "bun:test";
import { pacedAI, PACING_MODEL } from "../src/model-admission.ts";

test("DeepSeek binding inputs carry the exact routed model and preserve the call options", async () => {
  const calls = [];
  const binding = {async run(...args) {calls.push(args); return {response: "OK"};}};
  const ai = pacedAI(binding, {getByName() {return {async admit() {return {granted: true};}};}});
  const inputs = {messages: [{role: "user", content: "Reply OK"}], max_tokens: 16, reasoning_effort: "none"};
  const options = {signal: new AbortController().signal};
  expect(await ai.run(PACING_MODEL, inputs, options)).toEqual({response: "OK"});
  expect(calls).toEqual([[PACING_MODEL, {...inputs, model: PACING_MODEL}, options]]);
  expect(Object.hasOwn(inputs, "model")).toBe(false);
  await ai.run(PACING_MODEL, {...inputs, model: "wrong-model"}, options);
  expect(calls[1][1].model).toBe(PACING_MODEL);
  await ai.run("other-model", inputs, options);
  expect(calls[2]).toEqual(["other-model", inputs, options]);
});

const model = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";

test("model admission waits before sending the original request and preserves binding ownership", async () => {
  const events = [];
  let admissions = 0;
  const binding = {
    marker: "owner",
    async run(...args) {
      events.push([this.marker, ...args]);
      return "original inference";
    },
    describe() { return this.marker; },
  };
  const namespace = { getByName(name) {
    expect(name).toBe("workers-ai:" + model);
    return { async admit(selected) {
      expect(selected).toBe(model);
      events.push("admit");
      return ++admissions === 1 ? { granted: false, waitMs: 1 } : { granted: true };
    } };
  } };
  const ai = pacedAI(binding, namespace);
  expect(await ai.run(model, { prompt: "fixture" })).toBe("original inference");
  expect(events).toEqual(["admit", "admit", ["owner", model, { prompt: "fixture", model }]]);
  expect(ai.describe()).toBe("owner");
});

test("aborted admission cannot launch inference and provider failure is not retried", async () => {
  const requests = [];
  const failure = new Error("3040: capacity fixture");
  failure.name = "AiError";
  const binding = { async run(...args) { requests.push(args); throw failure; } };
  const controller = new AbortController();
  const denied = pacedAI(binding, { getByName() { return { async admit() {
    controller.abort(new Error("cancelled fixture"));
    return { granted: false, waitMs: 4000 };
  } }; } });
  await expect(denied.run(model, {}, { signal: controller.signal })).rejects.toThrow("cancelled fixture");
  expect(requests).toEqual([]);
  const admitted = pacedAI(binding, { getByName() { return { async admit() { return { granted: true }; } }; } });
  await expect(admitted.run(model, { prompt: "once" }, { signal: AbortSignal.timeout(1000) })).rejects.toBe(failure);
  expect(requests).toEqual([[model, { prompt: "once", model }, expect.any(Object)]]);
});

test("an aborted pending grant cannot turn into a late inference", async () => {
  const controller = new AbortController();
  let release;
  let runs = 0;
  const ai = pacedAI({ async run() { runs++; return "completed"; } }, {
    getByName() { return { admit() { return new Promise(resolve => { release = resolve; }); } }; },
  });
  const result = ai.run(model, {}, { signal: controller.signal });
  controller.abort(new Error("deadline fixture"));
  await expect(result).rejects.toThrow("deadline fixture");
  release({ granted: true });
  await new Promise(resolve => setTimeout(resolve, 1));
  expect(runs).toBe(0);
  const positive = pacedAI({ async run() { return "completed"; } }, {
    getByName() { return { async admit() { return { granted: true }; } }; },
  });
  expect(await positive.run(model, {})).toBe("completed");
});

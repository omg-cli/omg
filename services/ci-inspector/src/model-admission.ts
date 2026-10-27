import type { Ai } from "@cloudflare/workers-types/index.ts";

export const PACING_MODEL = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";
// CodeLoud reserves 15 of the shared account model limit of 20 requests per minute.
export const PACING_INTERVAL_MS = 12000;
const GRANT_LIFETIME_MS = 500;

export type Admission = { granted: true } | { granted: false; waitMs: number };
export type ModelPacerNamespace = {
  getByName(name: string): { admit(model: string): Promise<Admission> };
};
type RunSignal = NonNullable<Parameters<Ai["run"]>[2]>["signal"];

async function withAbort<T>(pending: Promise<T>, signal: RunSignal): Promise<T> {
  signal?.throwIfAborted();
  if (!signal) return pending;
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    pending.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

async function pause(ms: number, signal: RunSignal) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await withAbort(new Promise<void>(resolve => { timer = setTimeout(resolve, ms); }), signal);
  } finally {
    clearTimeout(timer);
  }
}

export function pacedAI(binding: Ai, namespace: ModelPacerNamespace): Ai {
  const pacer = namespace.getByName(`workers-ai:${PACING_MODEL}`);
  return new Proxy(binding, {
    get(target, property) {
      if (property !== "run") {
        let owner: object | null = target;
        while (owner) {
          const descriptor = Object.getOwnPropertyDescriptor(owner, property);
          if (descriptor) {
            const value: unknown = descriptor.get ? descriptor.get.call(target) : descriptor.value;
            return value instanceof Function ? value.bind(target) : value;
          }
          owner = Object.getPrototypeOf(owner);
        }
        return undefined;
      }
      return async (...args: Parameters<Ai["run"]>) => {
        const signal = args[2]?.signal;
        for (;;) {
          signal?.throwIfAborted();
          const startedAt = performance.now();
          const admission = await withAbort(pacer.admit(args[0]), signal);
          signal?.throwIfAborted();
          if (!admission.granted) {
            await pause(admission.waitMs, signal);
          } else if (performance.now() - startedAt < GRANT_LIFETIME_MS) {
            return target.run(...args);
          } else {
            await pause(PACING_INTERVAL_MS, signal);
          }
        }
      };
    },
  });
}

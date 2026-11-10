import { describe, expect, mock, test } from 'bun:test';

mock.module('cloudflare:workers', () => ({
  DurableObject: class {
    constructor(protected ctx: unknown, protected env: unknown) {}
  },
  WorkflowEntrypoint: class {
    constructor(protected ctx: unknown, protected env: unknown) {}
  },
}));

const { NativeRunner, NativeCIWorkflow, parseInput, readOutput, default: worker } = await import('../src/index');
const input = { sourceSha: 'a'.repeat(40), runId: '123', attempt: 1 };
const imageDigest = `sha256:${'b'.repeat(64)}`;
const report = { accepted: true, sourceSha: input.sourceSha, tests: [{ passed: 1 }] };
const stream = (text: string) => new ReadableStream({ start(controller) {
  controller.enqueue(new TextEncoder().encode(text)); controller.close();
} });

function fixture(options: { image?: string; output?: string; destructionFailures?: number } = {}) {
  const data = new Map<string, unknown>();
  const objects = new Map<string, unknown>();
  const calls: { argv: string[]; options: unknown }[] = [];
  let starts = 0, destroys = 0, resets = 0, alarm: number | null = null;
  let releaseFailure = false;
  let initialization = Promise.resolve();
  const container = {
    running: false,
    start() { starts++; this.running = true; },
    async setInactivityTimeout() {},
    async inspect() { return this.running ? { image: options.image ?? `registry/example@${imageDigest}` } : null; },
    async destroy() {
      destroys++;
      if (destroys <= (options.destructionFailures ?? 0)) throw new Error('provider destruction failed');
      this.running = false;
    },
    async exec(argv: string[], execOptions: unknown) {
      calls.push({ argv, options: execOptions });
      return { stdout: stream(options.output ?? `OMG_CI_RESULT=${JSON.stringify(report)}\n`), stderr: stream(''), exitCode: Promise.resolve(0) };
    },
  };
  const storage = {
    async get(key: string) { return data.get(key); },
    async put(key: string | Record<string, unknown>, value?: unknown) {
      if (typeof key === 'string') data.set(key, structuredClone(value));
      else for (const [name, item] of Object.entries(key)) data.set(name, structuredClone(item));
    },
    async delete(key: string) {
      if (key === 'active' && releaseFailure) { releaseFailure = false; throw new Error('reservation release interrupted'); }
      return data.delete(key);
    },
    async setAlarm(value: number) { alarm = value; },
    async deleteAlarm() { alarm = null; },
    async transaction<T>(callback: (transaction: typeof storage) => Promise<T>): Promise<T> {
      const before = new Map(data), previousAlarm = alarm;
      try { return await callback(storage); }
      catch (error) {
        data.clear(); for (const [key, value] of before) data.set(key, value);
        alarm = previousAlarm;
        throw error;
      }
    },
  };
  const ctx = { container, storage, blockConcurrencyWhile<T>(callback: () => Promise<T>) {
    const result = initialization.then(callback);
    initialization = result.then(() => {}, () => { resets++; });
    return result;
  } };
  const env = { CI_IMAGE_DIGEST: imageDigest, CI_TOKEN: 'do-not-forward', CI_BUCKET: {
    async put(key: string, value: unknown) { objects.set(key, structuredClone(value)); },
  } };
  const runner = new NativeRunner(ctx, env);
  return { runner, ctx, env, data, objects, container, calls, ready: () => initialization,
    counts: () => ({ starts, destroys, alarm }), resets: () => resets,
    failRelease: () => { releaseFailure = true; },
    evidence: () => JSON.parse(String([...objects].find(([key]) => key.endsWith('/evidence.json'))?.[1])),
  };
}

describe('native CI boundary', () => {
  test('accepts only immutable exact input', () => {
    expect(parseInput(input)).toEqual(input);
    for (const value of [{ ...input, command: 'anything' }, { ...input, sourceSha: 'main' },
      { ...input, attempt: 0 }, { ...input, runId: '../x' }, null, []]) {
      expect(() => parseInput(value)).toThrow();
    }
  });

  test('rejects unauthenticated traffic before touching bindings', async () => {
    const response = await worker.fetch(new Request('https://ci/runs', { method: 'POST' }), { CI_TOKEN: 'secret' });
    expect(response.status).toBe(401);
  });

  test('caps raw output across both concurrent streams', async () => {
    const stream = (...parts: string[]) => new ReadableStream({ start(controller) {
      for (const part of parts) controller.enqueue(new TextEncoder().encode(part));
      controller.close();
    } });
    expect(await readOutput({ stdout: stream('ab'), stderr: stream('cd') }, 4)).toEqual({
      stdout: new TextEncoder().encode('ab'), stderr: new TextEncoder().encode('cd'),
    });
    await expect(readOutput({ stdout: stream('abc'), stderr: stream('de') }, 4)).rejects.toThrow('output limit');
  });

  test('drains stderr while stdout is waiting rather than serializing pipes', async () => {
    const stderrRead = Promise.withResolvers<void>();
    const stdout = new ReadableStream({ async pull(controller) { await stderrRead.promise; controller.close(); } });
    const stderr = new ReadableStream({ pull(controller) { stderrRead.resolve(); controller.close(); } });
    await expect(readOutput({ stdout, stderr })).resolves.toEqual({ stdout: new Uint8Array(), stderr: new Uint8Array() });
  });
});

describe('native CI lifecycle', () => {
  test('runs fixed root controller, verifies image, destroys before evidence, and never repeats an identity', async () => {
    const f = fixture();
    await f.ready();
    expect(await f.runner.run({ input, mode: 'run' })).toEqual({ key: `run-123-1-${input.sourceSha}/evidence.json`, accepted: true });
    expect(f.calls).toEqual([{ argv: ['/usr/bin/python3', '-I', '/opt/ci/run.py', input.sourceSha], options: { stdout: 'pipe', stderr: 'pipe' } }]);
    expect(f.evidence()).toMatchObject({ accepted: true, input, imageDigest, containerDestroyed: true, report, exitCode: 0 });
    expect(f.counts()).toEqual({ starts: 1, destroys: 1, alarm: null });
    await expect(f.runner.run({ input, mode: 'run' })).rejects.toThrow('already submitted');
    expect(f.counts().starts).toBe(1);
    expect(f.resets()).toBe(0);
  });

  test('image mismatch cannot pass even with a successful trusted report', async () => {
    const f = fixture({ image: 'registry/wrong@sha256:' + 'c'.repeat(64) });
    await f.ready();
    expect((await f.runner.run({ input, mode: 'run' })).accepted).toBe(false);
    expect(f.evidence()).toMatchObject({ accepted: false, containerDestroyed: true, error: 'running image digest mismatch' });
    expect(f.container.running).toBe(false);
  });

  test('output overflow destroys the whole container and fails', async () => {
    const f = fixture({ output: 'x'.repeat(8 * 1024 * 1024 + 1) });
    await f.ready();
    expect((await f.runner.run({ input, mode: 'run' })).accepted).toBe(false);
    expect(f.evidence().error).toContain('output limit');
    expect(f.container.running).toBe(false);
  });

  test('failed destroy leaves no passing evidence and the alarm retries cleanup without exec', async () => {
    const f = fixture({ destructionFailures: 1 });
    await f.ready();
    await expect(f.runner.run({ input, mode: 'run' })).rejects.toThrow('destruction failed');
    expect([...f.objects.keys()]).toEqual([]);
    expect(f.counts().alarm).not.toBeNull();
    await f.runner.alarm();
    expect(f.evidence()).toMatchObject({ accepted: false, containerDestroyed: true });
    expect(f.counts()).toEqual({ starts: 1, destroys: 2, alarm: null });
    expect(f.calls.length).toBe(1);
  });

  for (const output of [undefined, 'missing report']) test(`cleanup alarm preserves the ${output ? 'failed' : 'successful'} result while destruction is delayed`, async () => {
    const f = fixture({ output });
    await f.ready();
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const destroy = f.container.destroy.bind(f.container);
    let calls = 0;
    f.container.destroy = async () => {
      calls++;
      entered.resolve();
      await release.promise;
      await destroy();
    };
    const pending = f.runner.run({ input, mode: 'run' });
    await entered.promise;
    const alarm = f.runner.alarm();
    for (let turn = 0; turn < 10; turn++) await Promise.resolve();
    expect(calls).toBe(1);
    release.resolve();
    expect((await pending).accepted).toBe(output === undefined);
    await alarm;
    expect(f.evidence()).toMatchObject({ accepted: output === undefined, exitCode: 0,
      report: output === undefined ? report : null, error: output === undefined ? null : 'missing final trusted report', containerDestroyed: true });
    expect(f.counts().alarm).toBeNull();
    expect(f.counts().starts).toBe(1);
  });

  test('terminal commit and reservation release roll back together across an interrupted finish', async () => {
    const f = fixture();
    await f.ready();
    f.failRelease();
    await expect(f.runner.run({ input, mode: 'run' })).rejects.toThrow('release interrupted');
    const id = `run-123-1-${input.sourceSha}`;
    expect(f.data.get(id)).toMatchObject({ kind: 'closing' });
    expect(f.data.get('active')).toBe(id);
    const restarted = new NativeRunner(f.ctx, f.env);
    await f.ready();
    expect(f.evidence()).toMatchObject({ accepted: false, error: 'invocation interrupted' });
    expect(f.data.has('active')).toBe(false);
    expect((await restarted.run({ input: { ...input, attempt: 2 }, mode: 'run' })).accepted).toBe(true);
    expect(f.counts().starts).toBe(2);
  });

  test('restart fences an interrupted job, cleans up, and cannot reexecute it', async () => {
    const f = fixture();
    await f.ready();
    const id = `run-123-1-${input.sourceSha}`;
    f.data.set('active', id);
    f.data.set(id, { kind: 'running', job: { input, mode: 'run' }, deadline: Date.now() + 100000 });
    f.container.running = true;
    const restarted = new NativeRunner(f.ctx, f.env);
    await f.ready();
    expect(f.evidence()).toMatchObject({ accepted: false, error: 'invocation interrupted', containerDestroyed: true });
    await expect(restarted.run({ input, mode: 'run' })).rejects.toThrow('already submitted');
    expect(f.calls.length).toBe(0);
  });

  test('cancellation before a queued Workflow starts permanently closes its launch fence', async () => {
    const f = fixture();
    await f.ready();
    await f.runner.cancel(`run-123-1-${input.sourceSha}`);
    await expect(f.runner.run({ input, mode: 'run' })).rejects.toThrow('already submitted');
    expect(f.counts().starts).toBe(0);
  });

  for (const action of ['cancel', 'alarm']) test(`${action} closes active execution and busy capacity never launches twice`, async () => {
    const f = fixture();
    await f.ready();
    const entered = Promise.withResolvers<void>();
    const exit = Promise.withResolvers<number>();
    const stdout = Promise.withResolvers<ReadableStreamDefaultController>();
    const stderr = Promise.withResolvers<ReadableStreamDefaultController>();
    f.container.exec = async () => {
      entered.resolve();
      return {
        stdout: new ReadableStream({ start(controller) { stdout.resolve(controller); } }),
        stderr: new ReadableStream({ start(controller) { stderr.resolve(controller); } }),
        exitCode: exit.promise,
      };
    };
    const destroy = f.container.destroy.bind(f.container);
    f.container.destroy = async () => {
      const wasRunning = f.container.running;
      await destroy();
      if (wasRunning) { (await stdout.promise).close(); (await stderr.promise).close(); exit.resolve(1); }
    };
    const pending = f.runner.run({ input, mode: 'run' });
    await entered.promise;
    await expect(f.runner.run({ input: { ...input, attempt: 2 }, mode: 'run' })).rejects.toThrow('capacity is busy');
    expect(f.resets()).toBe(0);
    if (action === 'cancel') await f.runner.cancel(`run-123-1-${input.sourceSha}`);
    else {
      const id = `run-123-1-${input.sourceSha}`;
      await f.runner.alarm();
      expect(f.container.running).toBe(true);
      expect(f.data.get(id)).toMatchObject({ kind: 'running' });
      f.data.set(id, { kind: 'running', job: { input, mode: 'run' }, deadline: Date.now() - 1 });
      await f.runner.alarm();
    }
    expect((await pending).accepted).toBe(false);
    expect(f.evidence()).toMatchObject({ accepted: false, containerDestroyed: true,
      error: action === 'cancel' ? 'cancelled by caller' : 'absolute deadline exceeded' });
    expect(f.counts().starts).toBe(1);
  });

  test('Workflow has one retry-free step and rejects failed evidence', async () => {
    let seen: unknown;
    const workflow = new NativeCIWorkflow({}, { CI_RUNNER: { getByName() { return { async run() { return { accepted: false, key: 'failure' }; } }; } } });
    await expect(workflow.run({ payload: { input, mode: 'run' } }, {
      async do(name: string, config: unknown, callback: () => Promise<unknown>) { seen = { name, config }; return await callback(); },
    })).rejects.toThrow('native CI failed');
    expect(seen).toEqual({ name: 'native-ci', config: { retries: { limit: 0, delay: '1 second' }, timeout: '45 minutes' } });
  });
});

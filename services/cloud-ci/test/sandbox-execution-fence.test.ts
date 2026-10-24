import { expect, mock, test } from 'bun:test';
import type * as Workers from '@cloudflare/workers-types/index.ts';

declare const ReadableStream: typeof Workers.ReadableStream;
declare const Response: typeof Workers.Response;

type File = { absolutePath: string; type: 'file' | 'symlink'; size: number };
type Listing = { success: true; files: File[] };
type Ctx = {
  id: { toString(): string };
  storage: {
    get<T>(key: string): Promise<T | undefined>;
    put<T>(key: string, value: T): Promise<void>;
    setAlarm(at: number): Promise<void>;
  };
  waitUntil(p: Promise<unknown>): void;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T>;
};
type Env = {
  BACKUP_BUCKET: { get(key: string): Promise<{ text(): Promise<string> } | null>; put(key: string, body: string | Uint8Array, options?: { httpMetadata?: { contentType?: string } }): Promise<unknown> };
  CI_WORKFLOW: { get(owner: string): Promise<{ id: string; status(): Promise<{ status: string }> }> };
  listFiles(path: string): Promise<Listing>;
  readFile(path: string): Promise<Workers.ReadableStream<Uint8Array>>;
};

const id = `cl-123-1-${'a'.repeat(40)}`;
const metadataKey = 'omg:runner-metadata';
const teardownKey = 'omg:runner-teardown';

function file(absolutePath: string, size = 0, type: 'file' | 'symlink' = 'file'): File { return { absolutePath, size, type }; }
function listing(...files: File[]): Listing { return { success: true, files }; }
function stream(bytes: Uint8Array): Workers.ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({ start(c) { c.enqueue(bytes); c.close(); } });
}
type Deferred = { promise: Promise<void>; resolve: () => void };
function deferred(): Deferred {
  let resolve = () => {};
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

class Storage {
  readonly values = new Map<string, unknown>();
  readonly alarms: number[] = [];
  async get<T>(key: string) { return this.values.get(key) as T | undefined; }
  async put<T>(key: string, value: T) { this.values.set(key, value); }
  async setAlarm(at: number) { this.alarms.push(at); }
}

class Context implements Ctx {
  readonly id = { toString: () => 'c'.repeat(64) };
  readonly storage = new Storage();
  private waits: Promise<unknown>[] = [];
  private gate: Promise<unknown> = Promise.resolve();
  waitUntil(p: Promise<unknown>) { this.waits.push(p.then(() => undefined, () => undefined)); }
  blockConcurrencyWhile<T>(fn: () => Promise<T>) { const r = fn(); this.gate = r.then(() => undefined, () => undefined); return r; }
  async settle() { await this.gate; await Promise.allSettled(this.waits); }
}

class Bucket {
  async get(key: string) {
    const stored = this.writes.findLast((write) => write.key === key);
    return stored ? { text: async () => new TextDecoder().decode(stored.content) } : null;
  }
  readonly writes: { key: string; content: Uint8Array; contentType?: string }[] = [];
  async put(key: string, body: string | Uint8Array, options?: { httpMetadata?: { contentType?: string } }) {
    this.writes.push({ key, content: new Uint8Array(await new Response(body).arrayBuffer()), contentType: options?.httpMetadata?.contentType });
    return {};
  }
}
class Workflow {
  status = 'complete';
  async get(owner: string) { return { id: owner, status: async () => ({ status: this.status }) }; }
}
class EnvFixture implements Env {
  readonly bucket = new Bucket();
  readonly workflow = new Workflow();
  readonly BACKUP_BUCKET = this.bucket;
  readonly CI_WORKFLOW = this.workflow;
  running = true;
  listFiles: (path: string) => Promise<Listing> = async () => listing();
  readFile: (path: string) => Promise<Workers.ReadableStream<Uint8Array>> = async () => stream(new Uint8Array());
}

class Fake {
  readonly commands: string[] = [];
  readonly processes: string[] = [];
  readonly destroys: number[] = [];
  readonly delegated: unknown[][] = [];
  readonly starts: unknown[][] = [];
  beforeStartCalls = 0;
  resolveGate?: Deferred;
  resolveStarted?: Deferred;
  constructor(protected ctx: Ctx, protected env: Env) {}
  protected beforeStart() { this.beforeStartCalls += 1; }
  protected assertExecutionAllowed() {}
  configure(...a: unknown[]) { return Promise.resolve(a); }
  private async resolveExecution() {
    this.resolveStarted?.resolve();
    if (this.resolveGate) await this.resolveGate.promise;
    return { sessionId: 'default' };
  }
  async exec(...a: unknown[]) {
    await this.resolveExecution();
    return this.execWithSession(String(a[0]));
  }
  async execWithSessionToken(...a: unknown[]) {
    return this.execWithSession(String(a[0]));
  }
  private async execWithSession(command: string) {
    this.assertExecutionAllowed();
    this.commands.push(command);
    return { exitCode: 0 };
  }
  restoreBackup(...a: unknown[]) { return Promise.resolve(a); }
  createBackup(...a: unknown[]) { return Promise.resolve(a); }
  async startProcess(...a: unknown[]) {
    await this.resolveExecution();
    this.assertExecutionAllowed();
    this.processes.push(String(a[0]));
    this.starts.push(a);
    return { exitCode: 0 };
  }
  streamProcessLogs(...a: unknown[]) { return Promise.resolve(a); }
  readFileStream(...a: unknown[]) { return Promise.resolve(a); }
  listFiles(path: string) { return this.env.listFiles(path); }
  onStop(...a: unknown[]) { return Promise.resolve(a); }
  onActivityExpired() { return Promise.resolve(); }
  alarm(...a: unknown[]) { this.delegated.push(a); return Promise.resolve(); }
  destroy() { this.destroys.push(Date.now()); return Promise.resolve(); }
  readFile(path: string) { return this.env.readFile(path).then((content) => ({ content })); }
}

mock.module('@cloudflare/ci/worker', () => ({ CiSandbox: Fake }));
const { CiSandbox } = await import('../src/sandbox');
type Harness = InstanceType<typeof CiSandbox> & {
  commands: string[];
  processes: string[];
  destroys: number[];
  delegated: unknown[][];
  starts: unknown[][];
  beforeStartCalls: number;
  resolveGate?: Deferred;
  resolveStarted?: Deferred;
};
const make = (ctx: Context, env: EnvFixture): Harness => Reflect.construct(CiSandbox, [ctx, env]);
const alarm = (s: Harness): Promise<void> => Reflect.apply(s.alarm, s, []);

test('fenced running container rejects exec, explicit-session exec, and startProcess at admission', async () => {
  const ctx = new Context();
  const env = new EnvFixture();
  const s = make(ctx, env);
  await ctx.settle();
  await s.destroy();
  const expected = 'Runner teardown refuses container start';
  await expect(s.exec('true')).rejects.toThrow(expected);
  await expect(s.execWithSessionToken('true', 'session-1')).rejects.toThrow(expected);
  await expect(Promise.resolve().then(() => s.startProcess('true', { env: { OMG_CI_LEAF_STEP: 'script-contracts' } }))).rejects.toThrow(expected);
  expect(s.commands).toEqual([]);
  expect(s.processes).toEqual([]);
  expect(s.beforeStartCalls).toBe(0);
  expect(env.running).toBe(true);
});

test('paused exec admitted before the fence is rejected when released', async () => {
  const ctx = new Context();
  const env = new EnvFixture();
  const s = make(ctx, env);
  await ctx.settle();
  const gate = deferred();
  const started = deferred();
  s.resolveGate = gate;
  s.resolveStarted = started;
  const pending = s.exec('sleep 1');
  await started.promise;
  await s.destroy();
  gate.resolve();
  await expect(pending).rejects.toThrow('Runner teardown refuses container start');
  expect(s.commands).toEqual([]);
  expect(s.beforeStartCalls).toBe(0);
});

test('paused startProcess admitted before the fence is rejected when released', async () => {
  const ctx = new Context();
  const env = new EnvFixture();
  const s = make(ctx, env);
  await ctx.settle();
  const gate = deferred();
  const started = deferred();
  s.resolveGate = gate;
  s.resolveStarted = started;
  const pending = s.startProcess('sleep 2', { env: { OMG_CI_LEAF_STEP: 'script-contracts' } });
  await started.promise;
  await s.destroy();
  gate.resolve();
  await expect(pending).rejects.toThrow('Runner teardown refuses container start');
  expect(s.processes).toEqual([]);
  expect(s.beforeStartCalls).toBe(0);
});

test('recreated actor loads the persisted fence and rejects against a still-running container', async () => {
  const ctx = new Context();
  ctx.storage.values.set(teardownKey, true);
  const env = new EnvFixture();
  env.running = true;
  const s = make(ctx, env);
  await ctx.settle();
  const expected = 'Runner teardown refuses container start';
  await expect(s.exec('true')).rejects.toThrow(expected);
  await expect(s.execWithSessionToken('true', 'session-1')).rejects.toThrow(expected);
  await expect(Promise.resolve().then(() => s.startProcess('true', { env: {} }))).rejects.toThrow(expected);
  expect(s.commands).toEqual([]);
  expect(s.processes).toEqual([]);
  expect(s.beforeStartCalls).toBe(0);
  expect(env.running).toBe(true);
});

test('retention reads evidence after the durable fence and then destroys', async () => {
  const ctx = new Context();
  const env = new EnvFixture();
  const s = make(ctx, env);
  await ctx.settle();
  const owner = `${id}-ta-${'b'.repeat(16)}`;
  await ctx.storage.put(metadataKey, { diagnosticRunId: owner, leafStep: 'test-audit-four-state' });
  let sawFence = false;
  env.listFiles = async (path) => {
    sawFence ||= ctx.storage.values.get(teardownKey) === true;
    return path === '/tmp' ? listing(file('/tmp/ci-step.out', 3), file('/tmp/ci-step.err', 3)) : listing();
  };
  env.readFile = async () => stream(new Uint8Array([1, 2, 3]));
  env.workflow.status = 'complete';
  await alarm(s);
  expect(sawFence).toBe(true);
  expect(s.commands).toEqual([]);
  expect(s.processes).toEqual([]);
  expect(s.destroys).toHaveLength(1);
  const keys = env.bucket.writes.map((write) => write.key);
  expect(keys).toContain(`diagnostics/runner-logs/${owner}/test-audit-four-state.stdout`);
  expect(keys).toContain(`diagnostics/runner-logs/${owner}/test-audit-four-state.stderr`);
});

for (const explicitSession of [false, true]) {
  test(`finite leaf metadata is retained before execution, explicit session ${explicitSession}`, async () => {
    const ctx = new Context();
    const env = new EnvFixture();
    const sandbox = make(ctx, env);
    await ctx.settle();
    const options = { env: { OMG_CI_LEAF_STEP: 'rust-portable-tests', OMG_REPORT_RUN_ID: id, OMG_DIAGNOSTIC_RUN_ID: id } };
    if (explicitSession) await sandbox.execWithSessionToken('trusted command', 'session-1', options);
    else await sandbox.exec('trusted command', options);
    expect(ctx.storage.values.get(metadataKey)).toEqual({ reportRunId: id, diagnosticRunId: id, leafStep: 'rust-portable-tests' });
    expect(sandbox.commands).toEqual(['trusted command']);
  });
}

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
  BACKUP_BUCKET: { put(key: string, body: string | Uint8Array, options?: { httpMetadata?: { contentType?: string } }): Promise<unknown> };
  CI_WORKFLOW: { get(owner: string): Promise<{ id: string; status(): Promise<{ status: string }> }> };
  listFiles(path: string): Promise<Listing>;
  readFile(path: string): Promise<Workers.ReadableStream<Uint8Array>>;
};

const report = new TextEncoder().encode('<bad & bytes');
const id = `cl-123-1-${'a'.repeat(40)}`;
const metadataKey = 'omg:runner-metadata';
const teardownKey = 'omg:runner-teardown';

function file(absolutePath: string, size = 0, type: 'file' | 'symlink' = 'file'): File { return { absolutePath, size, type }; }
function listing(...files: File[]): Listing { return { success: true, files }; }
function stream(bytes: Uint8Array): Workers.ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({ start(c) { c.enqueue(bytes); c.close(); } });
}

class Storage {
  readonly values = new Map<string, unknown>();
  readonly alarms: number[] = [];
  private gate?: { key: string; release: () => void; promise: Promise<void> };
  private started?: () => void;
  hold(key: string) {
    let release = () => {};
    const promise = new Promise<void>((resolve) => { release = resolve; });
    this.gate = { key, release, promise };
    return () => { this.gate = undefined; release(); };
  }
  startedPut() { return new Promise<void>((resolve) => { this.started = resolve; }); }
  async get<T>(key: string) { return this.values.get(key) as T | undefined; }
  async put<T>(key: string, value: T) {
    if (this.gate?.key === key) { this.started?.(); await this.gate.promise; }
    this.values.set(key, value);
  }
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
  readonly writes: { key: string; content: Uint8Array; contentType?: string }[] = [];
  async put(key: string, body: string | Uint8Array, options?: { httpMetadata?: { contentType?: string } }) {
    this.writes.push({ key, content: new Uint8Array(await new Response(body).arrayBuffer()), contentType: options?.httpMetadata?.contentType });
    return {};
  }
}
class Workflow {
  status = 'complete';
  beforeStatus?: () => Promise<void>;
  readonly lookups: string[] = [];
  async get(owner: string) {
    this.lookups.push(owner);
    return { id: owner, status: async () => { await this.beforeStatus?.(); return { status: this.status }; } };
  }
}
class EnvFixture implements Env {
  readonly bucket = new Bucket();
  readonly workflow = new Workflow();
  readonly BACKUP_BUCKET = this.bucket;
  readonly CI_WORKFLOW = this.workflow;
  listFiles: (path: string) => Promise<Listing> = async () => listing();
  readFile: (path: string) => Promise<Workers.ReadableStream<Uint8Array>> = async () => stream(new Uint8Array());
}

class Fake {
  readonly starts: unknown[][] = [];
  readonly execs: unknown[][] = [];
  readonly destroys: number[] = [];
  readonly delegated: unknown[][] = [];
  constructor(protected ctx: Ctx, protected env: Env) {}
  protected beforeStart() {}
  configure(...a: unknown[]) { return Promise.resolve(a); }
  exec(...a: unknown[]) { this.beforeStart(); this.execs.push(a); return Promise.resolve({ exitCode: 0 }); }
  execWithSessionToken(...a: unknown[]) { this.beforeStart(); this.execs.push(a); return Promise.resolve({ exitCode: 0 }); }
  restoreBackup(...a: unknown[]) { return Promise.resolve(a); }
  createBackup(...a: unknown[]) { return Promise.resolve(a); }
  startProcess(...a: unknown[]) { this.beforeStart(); this.starts.push(a); return Promise.resolve({ exitCode: 0 }); }
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
type Harness = InstanceType<typeof CiSandbox> & { starts: unknown[][]; execs: unknown[][]; destroys: number[]; delegated: unknown[][] };
const make = (ctx: Context, env: EnvFixture): Harness => Reflect.construct(CiSandbox, [ctx, env]);
const alarm = (s: Harness): Promise<void> => Reflect.apply(s.alarm, s, []);

test('pending metadata write cannot start during destroy', async () => {
  const ctx = new Context(); const env = new EnvFixture(); const s = make(ctx, env); await ctx.settle();
  const release = ctx.storage.hold(metadataKey);
  const started = ctx.storage.startedPut();
  const start = s.startProcess('true', { env: { OMG_CI_LEAF_STEP: 'script-contracts' } });
  await started;
  const destroy = s.destroy();
  release();
  await expect(start).rejects.toThrow('Runner teardown refuses container start');
  await destroy;
  expect(s.starts).toEqual([]);
  expect(ctx.storage.values.get(teardownKey)).toBe(true);
});

test('teardown refuses a replacement start at the container boundary', async () => {
  const ctx = new Context(); const env = new EnvFixture(); const s = make(ctx, env); await ctx.settle();
  await s.destroy();
  await expect(s.exec('true')).rejects.toThrow();
  expect(s.execs).toEqual([]);
  expect(s.destroys).toHaveLength(1);
});

test('retention failure reschedules and keeps the fence', async () => {
  const ctx = new Context(); const env = new EnvFixture(); const s = make(ctx, env); await ctx.settle();
  const owner = `${id}-ta-${'b'.repeat(16)}`;
  await ctx.storage.put(metadataKey, { diagnosticRunId: owner, leafStep: 'test-audit-four-state' });
  env.listFiles = async (path) => path === '/tmp' ? listing(file('/tmp/ci-step.out', 0, 'symlink'), file('/tmp/ci-step.err')) : listing();
  await alarm(s);
  expect(s.destroys).toEqual([]);
  expect(ctx.storage.alarms).toHaveLength(1);
  const delay = ctx.storage.alarms[0]! - Date.now();
  expect(delay).toBeGreaterThan(59_000); expect(delay).toBeLessThanOrEqual(60_000);
  await expect(s.startProcess('true', { env: { OMG_CI_LEAF_STEP: 'script-contracts' } })).rejects.toThrow('Runner teardown refuses container start');
});

test('active owner delegates without fencing', async () => {
  const ctx = new Context(); const env = new EnvFixture(); const s = make(ctx, env); await ctx.settle();
  const owner = `${id}-v-${'b'.repeat(16)}`;
  await ctx.storage.put(metadataKey, { diagnosticRunId: owner, leafStep: 'script-contracts' });
  env.workflow.status = 'running';
  await alarm(s);
  expect(s.delegated).toHaveLength(1); expect(s.destroys).toEqual([]); expect(ctx.storage.alarms).toEqual([]);
  expect(ctx.storage.values.has(teardownKey)).toBe(false);
  await s.startProcess('true', { env: { OMG_CI_LEAF_STEP: 'script-contracts' } });
  expect(s.starts).toHaveLength(1);
});

test('Rust report fallback retains before destroy', async () => {
  const ctx = new Context(); const env = new EnvFixture(); const s = make(ctx, env); await ctx.settle();
  const run = `${id}-ta-${'b'.repeat(16)}`;
  env.listFiles = async (path) => path === '/tmp' ? listing(file('/tmp/ci-step.out'), file('/tmp/ci-step.err')) : path === '/tmp/omg-ci-unit-evidence' ? listing(file('/tmp/omg-ci-unit-evidence/report.xml', report.length)) : listing();
  env.readFile = async (path) => stream(path.endsWith('report.xml') ? report : new Uint8Array());
  await s.startProcess('true', { env: { OMG_CI_LEAF_STEP: 'rust-portable-tests', OMG_DIAGNOSTIC_RUN_ID: run } });
  expect(ctx.storage.values.get(metadataKey)).toEqual({ reportRunId: run, leafStep: 'rust-portable-tests', diagnosticRunId: run });
  await s.destroy();
  expect(env.bucket.writes.map((w) => w.key)).toContain(`reports/${run}/portable-units.xml`);
  expect(s.destroys).toHaveLength(1);
});
import { describe, expect, mock, test } from 'bun:test';
import { Database } from 'bun:sqlite';

mock.module('cloudflare:workers', () => ({ DurableObject: class {
  constructor(protected ctx: unknown, protected env: unknown) {}
} }));
const { default: worker, CacheMintBudget, POLICY, parseSeed } = await import('../src/index');
const account = 'a'.repeat(32), source = 'b'.repeat(40), digest = 'c'.repeat(64);
const seed = {
  schemaVersion: 1, recipeDigest: digest, compilerIdentityDigest: digest,
  target: 'x86_64-unknown-linux-gnu', cwd: '/tmp/omg-r2-read-probe-v1',
  sourceDigest: digest, argumentsDigest: digest, outputDigest: digest, outputBytes: 32,
  producerSourceSha: 'd'.repeat(40), producerRunId: '123', producerAttempt: 1,
};
const keys = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const jwk = { ...await crypto.subtle.exportKey('jwk', keys.publicKey), kid: 'test-key', alg: 'RS256' };
const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
async function jwt(changes: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://token.actions.githubusercontent.com', aud: POLICY.audience,
    iat: now, nbf: now - 1, exp: now + 300, jti: 'fixture-token',
    repository: 'omg-cli/omg', repository_id: '1133413326', repository_owner_id: '329545359',
    repository_visibility: 'public', event_name: 'pull_request', base_ref: 'main',
    ref: 'refs/pull/12/merge', sha: source, run_id: '456', run_attempt: '1',
    workflow_ref: 'omg-cli/omg/.github/workflows/ci.yml@refs/pull/12/merge', workflow_sha: source,
    ...changes };
  const input = `${encode({ alg: 'RS256', typ: 'JWT', kid: 'test-key', ...header })}.${encode(claims)}`;
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keys.privateKey, new TextEncoder().encode(input));
  return `${input}.${Buffer.from(signature).toString('base64url')}`;
}
function fixture(options: { pr?: unknown; upstreamStatus?: number; size?: number } = {}) {
  let issued = 0;
  const reads: string[] = [];
  const env = { R2_ACCOUNT_ID: account, SOURCE_SHA: source, CACHE_SEED: JSON.stringify(seed),
    R2_PARENT_ACCESS_KEY_ID: 'parent-access', R2_PARENT_SECRET_ACCESS_KEY: 'synthetic-secret',
    CACHE_MINTS: { idFromName: (name: string) => name, get: () => ({ issue: async () => {
      issued++; return { kind: 'issued', issuedAt: Math.floor(Date.now() / 1000) };
    } }) },
    DEPENDENCIES: {
      async head(key: string) { reads.push(key); return { size: options.size ?? 5, httpEtag: '"etag"' }; },
      async get(key: string) { reads.push(key); return { size: options.size ?? 5, httpEtag: '"etag"',
        body: new Response('bytes').body }; },
    } };
  const upstream = mock(async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    expect(init?.redirect).toBe('error');
    if (url === POLICY.jwks) {
      expect(new Headers(init?.headers).has('authorization')).toBe(false);
      return Response.json({ keys: [jwk] });
    }
    expect(url).toBe('https://api.github.com/repos/omg-cli/omg/pulls/12');
    expect(new Headers(init?.headers).get('authorization')).toBe('Bearer ghs_ephemeral');
    return Response.json(Object.hasOwn(options, 'pr') ? options.pr : { state: 'open', number: 12, merge_commit_sha: source,
      head: { repo: { id: 1133413326 } }, base: { ref: 'main', repo: { id: 1133413326 } } },
    { status: options.upstreamStatus ?? 200 });
  });
  return { env, reads, upstream, issued: () => issued };
}
async function exchange(token: string, options: Parameters<typeof fixture>[0] = {}) {
  const f = fixture(options);
  const original = globalThis.fetch;
  globalThis.fetch = f.upstream;
  try {
    return { ...f, response: await worker.fetch(new Request('https://artifacts/v1/compiler-cache/credentials', {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'x-github-token': 'ghs_ephemeral' } }), f.env) };
  } finally { globalThis.fetch = original; }
}

describe('closed artifact Worker entrypoint', () => {
  test('valid own PR receives only 45-minute portable GET/HEAD authority', async () => {
    const f = await exchange(await jwt());
    expect(f.response.status).toBe(200);
    expect(f.response.headers.get('cache-control')).toBe('no-store');
    const result = await f.response.json();
    expect(result.mode).toBe('READ_ONLY'); expect(result.prefix).toBe('portable-v1/');
    const r2jwt = Buffer.from(result.sessionToken, 'base64').toString().slice(4);
    const [header, payload, signature] = r2jwt.split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    expect(claims.actions).toEqual(['GetObject', 'HeadObject']);
    expect(claims.paths).toEqual({ prefixPaths: ['portable-v1/'] });
    expect(claims.scope).toBeUndefined(); expect(claims.exp - claims.iat).toBe(2700);
    expect(claims.aud).toBe(`${account}.r2.cloudflarestorage.com`);
    const hmac = await crypto.subtle.importKey('raw', new TextEncoder().encode('synthetic-secret'),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    expect(await crypto.subtle.verify('HMAC', hmac, Buffer.from(signature, 'base64url'),
      new TextEncoder().encode(`${header}.${payload}`))).toBe(true);
    expect(result.secretAccessKey).toBe(require('node:crypto').createHash('sha256').update(r2jwt).digest('hex'));
    expect(result.seed).toEqual(seed); expect(f.issued()).toBe(1);
  });
  test('rejects signature, time, workflow and repository identity failures before issuance', async () => {
    for (const changes of [{ aud: 'other' }, { iss: 'https://evil' }, { repository_id: '1' },
      { repository_owner_id: '1' }, { event_name: 'pull_request_target' }, { base_ref: 'topic' },
      { ref: 'refs/heads/main' }, { workflow_sha: 'f'.repeat(40) }, { workflow_ref: 'other' },
      { exp: 1 }, { iat: Math.floor(Date.now() / 1000) + 600 }, { run_attempt: '0' }]) {
      const f = await exchange(await jwt(changes)); expect(f.response.status).toBeGreaterThanOrEqual(400);
      expect(f.issued()).toBe(0);
    }
    for (const token of [`${await jwt()}broken`, await jwt({}, { alg: 'HS256' }),
      await jwt({}, { jku: 'https://evil' }), 'x'.repeat(17000)]) {
      const f = await exchange(token); expect(f.response.status).toBeGreaterThanOrEqual(400);
      expect(f.issued()).toBe(0);
    }
  });
  test('fork, stale head, closed PR and unavailable public metadata cannot mint', async () => {
    for (const pr of [null, { state: 'closed' }, { state: 'open', merge_commit_sha: source,
      number: 12, head: { repo: { id: 1 } }, base: { ref: 'main', repo: { id: 1133413326 } } },
      { state: 'open', merge_commit_sha: 'f'.repeat(40), number: 12,
        head: { repo: { id: 1133413326 } }, base: { ref: 'main', repo: { id: 1133413326 } } }]) {
      const f = await exchange(await jwt(), { pr }); expect(f.response.status).toBeGreaterThanOrEqual(400);
      expect(f.issued()).toBe(0);
    }
    expect((await exchange(await jwt(), { upstreamStatus: 429 })).response.status).toBe(502);
  });
  test('courier exposes only bounded curated bytes without compiler or listing authority', async () => {
    const f = fixture();
    const root = `https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/`;
    for (const name of ['latest.json', `${digest}.tar`, `${digest}.sigstore.json`]) {
      for (const method of ['GET', 'HEAD']) {
        const response = await worker.fetch(new Request(root + name, { method }), f.env);
        expect(response.status).toBe(200);
        expect(await response.text()).toBe(method === 'HEAD' ? '' : 'bytes');
      }
    }
    for (const path of ['portable-v1/cache', 'dependencies/sqlite-v1/',
      `dependencies/sqlite-v1/x86_64/${digest}/${digest}/unknown.json`,
      `dependencies/sqlite-v1/arm64/${digest}/${digest}/latest.json`]) {
      expect((await worker.fetch(new Request(`https://artifacts/${path}`), f.env)).status).toBe(404);
    }
    expect((await worker.fetch(new Request(root + 'latest.json', { method: 'PUT' }), f.env)).status).toBe(405);
    expect((await worker.fetch(new Request(root + 'latest.json', { headers: { Range: 'bytes=0-1' } }), f.env)).status).toBe(400);
    const large = fixture({ size: 65537 });
    expect((await worker.fetch(new Request(root + 'latest.json'), large.env)).status).toBe(502);
    expect(f.reads.every(key => key.startsWith('dependencies/sqlite-v1/'))).toBe(true);
  });
  test('seed schema refuses extensions and wrong canonical cwd', () => {
    expect(parseSeed(JSON.stringify(seed))).toEqual(seed);
    for (const value of [{ ...seed, secret: 'x' }, { ...seed, cwd: '/foreign' }, { ...seed, outputBytes: 0 }]) {
      expect(() => parseSeed(JSON.stringify(value))).toThrow();
    }
  });
  test('missing metadata credential and body authority are refused before upstream access', async () => {
    const f = fixture();
    const original = globalThis.fetch; globalThis.fetch = f.upstream;
    try {
      const token = await jwt();
      for (const request of [new Request('https://artifacts/v1/compiler-cache/credentials', {
        method: 'POST', headers: { authorization: `Bearer ${token}` } }),
        new Request('https://artifacts/v1/compiler-cache/credentials', { method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'x-github-token': 'ghs_ephemeral' }, body: '{"prefix":"other"}' })]) {
        expect((await worker.fetch(request, f.env)).status).toBe(401);
      }
      expect(f.upstream).not.toHaveBeenCalled(); expect(f.issued()).toBe(0);
    } finally { globalThis.fetch = original; }
  });
  test('an empty streamed POST body has the same authority as a bodyless HTTP POST', async () => {
    const f = fixture(); const original = globalThis.fetch; globalThis.fetch = f.upstream;
    try {
      const response = await worker.fetch(new Request('https://artifacts/v1/compiler-cache/credentials', {
        method: 'POST', headers: { authorization: `Bearer ${await jwt()}`, 'x-github-token': 'ghs_ephemeral' },
        body: new ReadableStream({ start(controller) { controller.close(); } }),
      }), f.env);
      expect(response.status).toBe(200); expect(f.issued()).toBe(1);
    } finally { globalThis.fetch = original; }
  });
  test('upstream malformed/oversized JSON and unknown signing keys fail closed', async () => {
    for (const response of [new Response('not JSON'), new Response('x'.repeat(32769)),
      Response.json({ keys: [{ ...jwk, kid: 'unknown' }] })]) {
      const f = fixture(); const original = globalThis.fetch;
      globalThis.fetch = mock(async () => response);
      try {
        const result = await worker.fetch(new Request('https://artifacts/v1/compiler-cache/credentials', {
          method: 'POST', headers: { authorization: `Bearer ${await jwt()}`, 'x-github-token': 'ghs_ephemeral' } }), f.env);
        expect(result.status).toBeGreaterThanOrEqual(400); expect(f.issued()).toBe(0);
      } finally { globalThis.fetch = original; }
    }
  });
  test('immutable GET miss streams into edge cache and subsequent GET bypasses R2', async () => {
    const f = fixture(), entries = new Map<string, Response>(), pending: Promise<unknown>[] = [];
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const edge = { match: mock(async (key: Request) => entries.get(key.url)?.clone()),
      put: mock(async (key: Request, response: Response) => {
        expect(response.headers.get('content-length')).toBe('5');
        entries.set(key.url, new Response(await response.arrayBuffer(), response));
      }) };
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: edge } });
    const ctx = { waitUntil(promise: Promise<unknown>) { pending.push(promise); } };
    const root = `https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/`;
    try {
      for (const name of [`${digest}.tar`, `${digest}.sigstore.json`]) {
        const first = await worker.fetch(new Request(root + name), f.env, ctx);
        expect(first.headers.get('x-omg-artifact-cache')).toBe('MISS');
        expect(await first.text()).toBe('bytes'); await Promise.all(pending);
        const reads = f.reads.length;
        const second = await worker.fetch(new Request(root + name), f.env, ctx);
        expect(second.headers.get('x-omg-artifact-cache')).toBe('HIT');
        expect(await second.text()).toBe('bytes'); expect(f.reads).toHaveLength(reads);
      }
      const matches = edge.match.mock.calls.length, puts = edge.put.mock.calls.length;
      for (const request of [new Request(root + 'latest.json'), new Request(root + `${digest}.tar`, { method: 'HEAD' }),
        new Request('https://artifacts/v1/compiler-cache/credentials', { method: 'POST' }),
        new Request(root + `${digest}.tar?alternate=1`)]) {
        await worker.fetch(request, f.env, ctx);
      }
      expect(edge.match.mock.calls).toHaveLength(matches); expect(edge.put.mock.calls).toHaveLength(puts);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'caches', previous);
      else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('cache failure or invalid cached metadata falls back to guarded R2 bytes', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    try {
      for (const failure of ['match', 'put', 'size', 'etag', 'type', 'status']) {
        const f = fixture(), pending: Promise<unknown>[] = [];
        const headers = { 'content-length': failure === 'size' ? '167772161' : '5',
          'content-type': failure === 'type' ? 'text/plain' : 'application/x-tar',
          etag: failure === 'etag' ? 'invalid' : '"etag"',
          'cache-control': 'public, max-age=31536000, immutable' };
        const edge = { async match() {
          if (failure === 'match') throw new Error('unavailable');
          return failure === 'put' ? undefined : new Response('cache', { status: failure === 'status' ? 206 : 200, headers });
        }, async put(_key: Request, response: Response) {
          if (failure === 'put') throw new Error('unavailable');
          await response.arrayBuffer();
        } };
        Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: edge } });
        const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
          f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
        expect(await response.text()).toBe('bytes'); expect(f.reads).toHaveLength(1);
        await Promise.all(pending);
      }
    } finally {
      if (previous) Object.defineProperty(globalThis, 'caches', previous);
      else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('a stalled cache put has a bounded lifetime while the R2 response remains usable', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const originalTimer = globalThis.setTimeout;
    const pending: Promise<unknown>[] = [];
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: {
      async match() { return undefined; }, put() { return new Promise(() => {}); },
    } } });
    globalThis.setTimeout = (callback, delay, ...args) => originalTimer(callback, delay === 25000 ? 1 : delay, ...args);
    try {
      const f = fixture();
      const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
        f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
      expect(await response.text()).toBe('bytes');
      const settled = await Promise.race([Promise.all(pending).then(() => true),
        new Promise(resolve => originalTimer(() => resolve(false), 100))]);
      expect(settled).toBe(true);
    } finally {
      globalThis.setTimeout = originalTimer;
      if (previous) Object.defineProperty(globalThis, 'caches', previous);
      else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('cache backlog is dropped while a fast client receives all 129 MiB', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const pending: Promise<unknown>[] = [];
    let resume: (() => void) | undefined, dropped = false, chunks = 0, cacheBytes = 0;
    const paused = new Promise<void>(resolve => { resume = resolve; });
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: {
      async match() { return undefined; },
      async put(_key: Request, response: Response) {
        await paused;
        const reader = response.body?.getReader();
        try {
          for (;;) {
            const item = await reader?.read(); if (!item || item.done) break;
            cacheBytes += item.value.byteLength;
          }
        }
        catch { dropped = true; }
        finally { await reader?.cancel().catch(() => undefined); }
      },
    } } });
    const f = fixture();
    f.env.DEPENDENCIES.get = async () => ({ size: 129 * 1024 * 1024, httpEtag: '"large"',
      body: new ReadableStream({ pull(controller) {
        if (chunks++ < 129) controller.enqueue(new Uint8Array(1024 * 1024));
        else controller.close();
      } }, { highWaterMark: 0 }) });
    try {
      const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
        f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
      const reader = response.body?.getReader(); let bytes = 0;
      for (;;) { const item = await reader?.read(); if (!item || item.done) break; bytes += item.value.byteLength; }
      expect(bytes).toBe(129 * 1024 * 1024);
      resume?.(); await Promise.all(pending);
      expect(dropped).toBe(true);
      expect(cacheBytes).toBeLessThanOrEqual(5 * 1024 * 1024);
    } finally {
      resume?.();
      if (previous) Object.defineProperty(globalThis, 'caches', previous);
      else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('cache cancellation leaves the single R2 reader serving the complete client', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const pending: Promise<unknown>[] = []; let produced = 0, cancelled = 0;
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: {
      async match() { return undefined; }, async put(_key: Request, response: Response) { await response.body?.cancel(); },
    } } });
    const f = fixture();
    f.env.DEPENDENCIES.get = async () => ({ size: 8 * 1024 * 1024, httpEtag: '"large"',
      body: new ReadableStream({ pull(controller) {
        if (produced++ < 8) controller.enqueue(new Uint8Array(1024 * 1024)); else controller.close();
      }, cancel() { cancelled++; } }, { highWaterMark: 0 }) });
    try {
      const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
        f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
      const reader = response.body?.getReader(); let bytes = 0;
      for (;;) { const item = await reader?.read(); if (!item || item.done) break; bytes += item.value.byteLength; }
      await Promise.all(pending);
      expect(bytes).toBe(8 * 1024 * 1024); expect(cancelled).toBe(0);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'caches', previous); else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('client cancellation cancels the one origin reader and stops the cache branch', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const pending: Promise<unknown>[] = []; let cancelled = 0, cacheFailed = false;
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: {
      async match() { return undefined; }, async put(_key: Request, response: Response) {
        try { await response.arrayBuffer(); } catch { cacheFailed = true; throw new Error('cancelled cache'); }
      },
    } } });
    const f = fixture();
    f.env.DEPENDENCIES.get = async () => ({ size: 8 * 1024 * 1024, httpEtag: '"large"',
      body: new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(1024 * 1024)); },
        cancel() { cancelled++; } }, { highWaterMark: 0 }) });
    try {
      const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
        f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
      const reader = response.body?.getReader(); await reader?.read(); await reader?.cancel();
      await Promise.all(pending);
      expect(cancelled).toBe(1); expect(cacheFailed).toBe(true);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'caches', previous); else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('one chunk above cache backlog limit drops cache without truncating that client chunk', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const pending: Promise<unknown>[] = []; let produced = false, cacheFailed = false;
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: {
      async match() { return undefined; }, async put(_key: Request, response: Response) {
        try { await response.arrayBuffer(); } catch { cacheFailed = true; throw new Error('large chunk'); }
      },
    } } });
    const f = fixture();
    f.env.DEPENDENCIES.get = async () => ({ size: 8 * 1024 * 1024, httpEtag: '"large"',
      body: new ReadableStream({ pull(controller) {
        if (!produced) { produced = true; controller.enqueue(new Uint8Array(8 * 1024 * 1024)); }
        else controller.close();
      } }, { highWaterMark: 0 }) });
    try {
      const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
        f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
      const reader = response.body?.getReader(); expect((await reader?.read())?.value.byteLength).toBe(8 * 1024 * 1024);
      expect((await reader?.read())?.done).toBe(true); await Promise.all(pending); expect(cacheFailed).toBe(true);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'caches', previous); else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
  test('cache deadline drops queued bytes while the healthy origin client keeps streaming', async () => {
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'caches');
    const originalTimer = globalThis.setTimeout;
    const pending: Promise<unknown>[] = []; let produced = 0, cancelled = 0, cached: Response | undefined;
    Object.defineProperty(globalThis, 'caches', { configurable: true, value: { default: {
      async match() { return undefined; }, put(_key: Request, response: Response) {
        cached = response; return new Promise(() => {});
      },
    } } });
    globalThis.setTimeout = (callback, delay, ...args) => originalTimer(callback, delay === 25000 ? 5 : delay, ...args);
    const f = fixture();
    f.env.DEPENDENCIES.get = async () => ({ size: 8 * 1024 * 1024, httpEtag: '"large"',
      body: new ReadableStream({ async pull(controller) {
        await new Promise(resolve => originalTimer(resolve, 2));
        if (produced++ < 8) controller.enqueue(new Uint8Array(1024 * 1024)); else controller.close();
      }, cancel() { cancelled++; } }, { highWaterMark: 0 }) });
    try {
      const response = await worker.fetch(new Request(`https://artifacts/dependencies/sqlite-v1/x86_64/${digest}/${digest}/${digest}.tar`),
        f.env, { waitUntil(value: Promise<unknown>) { pending.push(value); } });
      const reader = response.body?.getReader(); let bytes = 0;
      for (;;) { const item = await reader?.read(); if (!item || item.done) break; bytes += item.value.byteLength; }
      await Promise.all(pending);
      expect(bytes).toBe(8 * 1024 * 1024); expect(cancelled).toBe(0);
      const stalled = cached?.body?.getReader(); let cacheBytes = 0, failed = false;
      try { for (;;) { const item = await stalled?.read(); if (!item || item.done) break; cacheBytes += item.value.byteLength; } }
      catch { failed = true; }
      expect(failed).toBe(true); expect(cacheBytes).toBeLessThanOrEqual(1024 * 1024);
    } finally {
      globalThis.setTimeout = originalTimer;
      if (previous) Object.defineProperty(globalThis, 'caches', previous); else Reflect.deleteProperty(globalThis, 'caches');
    }
  });
});

test('persistent mint ledger is bounded, idempotent, expires once and cleans up', async () => {
  const db = new Database(':memory:'); let alarm = 0;
  const storage = { sql: { exec(query: string, ...params: (string | number)[]) {
    const statement = db.query(query);
    if (/^SELECT/.test(query)) return { toArray: () => statement.all(...params) };
    statement.run(...params); return { toArray: () => [] };
  } }, transactionSync<T>(callback: () => T) { return db.transaction(callback)(); },
  async setAlarm(value: number) { alarm = value; }, async deleteAlarm() { alarm = 0; } };
  const budget = new CacheMintBudget({ storage }, {});
  const results = await Promise.all(Array.from({ length: 12 }, (_, n) => budget.issue(n.toString(16).padStart(64, '0'), 1000)));
  expect(results.filter(value => value.kind === 'issued')).toHaveLength(6);
  expect(await budget.issue('0'.repeat(64), 1100)).toEqual({ kind: 'issued', issuedAt: 1000 });
  expect(await budget.issue('0'.repeat(64), 3700)).toEqual({ kind: 'denied' });
  expect(alarm).toBeGreaterThan(1000 * 1000);
  await budget.alarm(); expect(alarm).toBe(0);
  expect(db.query('SELECT * FROM mints').all()).toEqual([]); db.close();
});

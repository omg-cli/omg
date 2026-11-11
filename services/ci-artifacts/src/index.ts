import { DurableObject } from 'cloudflare:workers';

export const POLICY = {
  version: 'portable-read-v1', audience: 'omg-pr-r2-cache-v1',
  issuer: 'https://token.actions.githubusercontent.com',
  jwks: 'https://token.actions.githubusercontent.com/.well-known/jwks',
  repository: 'omg-cli/omg', repositoryId: '1133413326', ownerId: '329545359',
  bucket: 'omg-ci-compiler-cache', prefix: 'portable-v1/', lifetime: 2700,
};
interface Env {
  R2_ACCOUNT_ID: string;
  SOURCE_SHA: string;
  CACHE_SEED?: string;
  R2_PARENT_ACCESS_KEY_ID?: string;
  R2_PARENT_SECRET_ACCESS_KEY?: string;
  CACHE_MINTS: DurableObjectNamespace<CacheMintBudget>;
  DEPENDENCIES: R2Bucket;
}
class Refusal extends Error {
  constructor(readonly status: number) { super('request refused'); }
}
const encoder = new TextEncoder();
const digestPattern = /^[a-f0-9]{64}$/;
const sourcePattern = /^[a-f0-9]{40}$/;
const integerPattern = /^[1-9][0-9]{0,19}$/;
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Refusal(401);
  return Object.fromEntries(Object.entries(value));
}
function text(value: unknown, pattern: RegExp): string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Refusal(401);
  return value;
}
function integer(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Refusal(401);
  return value;
}
export function parseSeed(raw: string) {
  if (raw.length > 8192) throw new Refusal(503);
  const seed = record(JSON.parse(raw));
  const names = ['schemaVersion', 'recipeDigest', 'compilerIdentityDigest', 'target', 'cwd',
    'sourceDigest', 'argumentsDigest', 'outputDigest', 'outputBytes', 'producerSourceSha',
    'producerRunId', 'producerAttempt'];
  if (Object.keys(seed).length !== names.length || names.some(name => !(name in seed))
      || seed.schemaVersion !== 1 || seed.target !== 'x86_64-unknown-linux-gnu'
      || seed.cwd !== '/tmp/omg-r2-read-probe-v1') throw new Refusal(503);
  return { schemaVersion: 1, recipeDigest: text(seed.recipeDigest, digestPattern),
    compilerIdentityDigest: text(seed.compilerIdentityDigest, digestPattern),
    target: seed.target, cwd: seed.cwd, sourceDigest: text(seed.sourceDigest, digestPattern),
    argumentsDigest: text(seed.argumentsDigest, digestPattern), outputDigest: text(seed.outputDigest, digestPattern),
    outputBytes: integer(seed.outputBytes, 1, 1024 * 1024),
    producerSourceSha: text(seed.producerSourceSha, sourcePattern),
    producerRunId: text(seed.producerRunId, integerPattern), producerAttempt: integer(seed.producerAttempt, 1) };
}
function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function decode(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Refusal(401);
  try { return Uint8Array.from(atob(segment.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)); }
  catch { throw new Refusal(401); }
}
function jwtObject(segment: string): Record<string, unknown> {
  try { return record(JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(decode(segment)))); }
  catch { throw new Refusal(401); }
}
async function sha256(value: string): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))),
    value => value.toString(16).padStart(2, '0')).join('');
}
async function boundedJSON(response: Response, limit: number): Promise<unknown> {
  if (!response.ok || !response.body) throw new Refusal(502);
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const item = await reader.read(); if (item.done) break;
      size += item.value.byteLength;
      if (size > limit) throw new Refusal(502);
      chunks.push(item.value);
    }
  } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
}
async function upstream(url: string, limit: number, githubToken?: string): Promise<unknown> {
  try {
    return await boundedJSON(await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { Accept: 'application/json', 'User-Agent': 'omg-ci-artifacts', 'X-GitHub-Api-Version': '2022-11-28',
        ...(githubToken ? { Authorization: `Bearer ${githubToken}` } : {}) } }), limit);
  } catch { throw new Refusal(502); }
}
async function identity(token: string, now: number, githubToken: string) {
  const segments = token.split('.');
  const headerSegment = segments[0], payloadSegment = segments[1], signature = segments[2];
  if (segments.length !== 3 || !headerSegment || !payloadSegment || !signature) throw new Refusal(401);
  const header = jwtObject(headerSegment);
  if (header.alg !== 'RS256' || (header.typ !== undefined && header.typ !== 'JWT')
      || Object.keys(header).some(key => !['alg', 'typ', 'kid'].includes(key))) throw new Refusal(401);
  const kid = text(header.kid, /^[A-Za-z0-9_-]{1,128}$/);
  const jwks = record(await upstream(POLICY.jwks, 32768));
  if (!Array.isArray(jwks.keys) || jwks.keys.length > 10) throw new Refusal(502);
  const candidates = jwks.keys.map(record).filter(key => key.kid === kid);
  const key = candidates[0];
  if (candidates.length !== 1 || !key || key.kty !== 'RSA'
      || (key.alg !== undefined && key.alg !== 'RS256') || (key.use !== undefined && key.use !== 'sig')) throw new Refusal(401);
  const publicKey = await crypto.subtle.importKey('jwk', {
    kty: 'RSA', n: text(key.n, /^[A-Za-z0-9_-]{342,1024}$/), e: text(key.e, /^AQAB$/),
    alg: 'RS256', ext: true,
  }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, decode(signature),
    encoder.encode(`${headerSegment}.${payloadSegment}`))) throw new Refusal(401);
  const claims = jwtObject(payloadSegment);
  const issued = integer(claims.iat), notBefore = integer(claims.nbf), expires = integer(claims.exp);
  if (claims.iss !== POLICY.issuer || claims.aud !== POLICY.audience || issued > now + 60
      || notBefore > now + 60 || expires <= now || expires <= issued || notBefore >= expires
      || expires - issued > 600 || issued < now - 600
      || claims.repository !== POLICY.repository || claims.repository_id !== POLICY.repositoryId
      || claims.repository_owner_id !== POLICY.ownerId || claims.repository_visibility !== 'public'
      || claims.event_name !== 'pull_request' || claims.base_ref !== 'main') throw new Refusal(403);
  const ref = text(claims.ref, /^refs\/pull\/[1-9][0-9]{0,9}\/merge$/);
  const sha = text(claims.sha, sourcePattern), runId = text(claims.run_id, integerPattern);
  const attempt = text(claims.run_attempt, /^[1-9][0-9]{0,5}$/);
  const jti = text(claims.jti, /^[A-Za-z0-9_.:-]{1,256}$/);
  if (claims.workflow_ref !== `${POLICY.repository}/.github/workflows/ci.yml@${ref}`
      || claims.workflow_sha !== sha) throw new Refusal(403);
  const pullRequest = Number(ref.split('/')[2]);
  const pr = record(await upstream(`https://api.github.com/repos/${POLICY.repository}/pulls/${pullRequest}`, 65536, githubToken));
  const head = record(pr.head), base = record(pr.base);
  if (pr.state !== 'open' || pr.number !== pullRequest || pr.merge_commit_sha !== sha
      || record(head.repo).id !== Number(POLICY.repositoryId)
      || record(base.repo).id !== Number(POLICY.repositoryId) || base.ref !== 'main') throw new Refusal(403);
  return { repositoryId: POLICY.repositoryId, runId, runAttempt: Number(attempt), sourceSha: sha,
    pullRequest, tokenHash: await sha256(jti) };
}

type Issuance = { kind: 'issued'; issuedAt: number } | { kind: 'denied' };
export class CacheMintBudget extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS mints (token_hash TEXT PRIMARY KEY, issued_at INTEGER NOT NULL)');
  }
  async issue(tokenHash: string, now: number): Promise<Issuance> {
    if (!digestPattern.test(tokenHash) || !Number.isSafeInteger(now) || now < 0) return { kind: 'denied' };
    const result: Issuance = this.ctx.storage.transactionSync(() => {
      const rows = this.ctx.storage.sql.exec<{ token_hash: string; issued_at: number }>(
        'SELECT token_hash, issued_at FROM mints').toArray();
      const first = rows[0]?.issued_at ?? now;
      if (now >= first + POLICY.lifetime || now < first) return { kind: 'denied' };
      if (!rows.some(row => row.token_hash === tokenHash)) {
        if (rows.length >= 6) return { kind: 'denied' };
        this.ctx.storage.sql.exec('INSERT INTO mints (token_hash, issued_at) VALUES (?, ?)', tokenHash, first);
      }
      return { kind: 'issued', issuedAt: first };
    });
    if (result.kind === 'issued') await this.ctx.storage.setAlarm((result.issuedAt + 86400) * 1000);
    return result;
  }
  async alarm() {
    this.ctx.storage.sql.exec('DELETE FROM mints');
    await this.ctx.storage.deleteAlarm();
  }
}
async function credentials(request: Request, env: Env): Promise<Response> {
  const authorization = request.headers.get('authorization') ?? '';
  if (!authorization.startsWith('Bearer ') || authorization.length > 16384) throw new Refusal(401);
  if (request.body) {
    const reader = request.body.getReader();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const first = await Promise.race([reader.read(), new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Refusal(401)), 1000);
      })]);
      if (!first.done) throw new Refusal(401);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      await reader.cancel();
    }
  }
  const githubToken = request.headers.get('x-github-token') ?? '';
  if (!/^[A-Za-z0-9_.-]{1,4096}$/.test(githubToken)) throw new Refusal(401);
  if (!/^[a-f0-9]{32}$/.test(env.R2_ACCOUNT_ID)
      || !env.R2_PARENT_ACCESS_KEY_ID || !env.R2_PARENT_SECRET_ACCESS_KEY
      || !env.CACHE_SEED || !sourcePattern.test(env.SOURCE_SHA)) throw new Refusal(503);
  const seed = parseSeed(env.CACHE_SEED);
  const now = Math.floor(Date.now() / 1000);
  const admitted = await identity(authorization.slice(7), now, githubToken);
  const id = env.CACHE_MINTS.idFromName([POLICY.version, admitted.runId, admitted.runAttempt, admitted.sourceSha].join('/'));
  const issue = await env.CACHE_MINTS.get(id).issue(admitted.tokenHash, now);
  if (issue.kind !== 'issued') throw new Refusal(429);
  const endpoint = `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
  const claims = { sub: env.R2_ACCOUNT_ID, iss: env.R2_PARENT_ACCESS_KEY_ID,
    aud: new URL(endpoint).host, iat: issue.issuedAt, exp: issue.issuedAt + POLICY.lifetime,
    bucket: POLICY.bucket, actions: ['GetObject', 'HeadObject'], paths: { prefixPaths: [POLICY.prefix] } };
  const unsigned = `${base64url(encoder.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))}.${base64url(encoder.encode(JSON.stringify(claims)))}`;
  const key = await crypto.subtle.importKey('raw', encoder.encode(env.R2_PARENT_SECRET_ACCESS_KEY),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signed = `${unsigned}.${base64url(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(unsigned))))}`;
  return Response.json({ schemaVersion: 1, accessKeyId: env.R2_PARENT_ACCESS_KEY_ID,
    secretAccessKey: await sha256(signed), sessionToken: btoa(`jwt/${signed}`), endpoint,
    bucket: POLICY.bucket, region: 'auto', prefix: POLICY.prefix, mode: 'READ_ONLY',
    expiresAt: claims.exp, policyVersion: POLICY.version,
    admitted: { repositoryId: admitted.repositoryId, runId: admitted.runId, runAttempt: admitted.runAttempt,
      sourceSha: admitted.sourceSha, pullRequest: admitted.pullRequest }, seed },
  { headers: { 'Cache-Control': 'no-store' } });
}
const immutableCacheControl = 'public, max-age=31536000, immutable';
function cacheBranches(body: ReadableStream<Uint8Array>) {
  const reader = body.getReader();
  const queue: Uint8Array[] = [];
  let backlog = 0, cacheActive = true, sourceDone = false, clientClosed = false;
  let cacheController: ReadableStreamDefaultController<Uint8Array> | undefined;
  let wake: (() => void) | undefined;
  const notify = () => { const waiting = wake; wake = undefined; waiting?.(); };
  const dropCache = (error?: Error) => {
    if (!cacheActive) return;
    cacheActive = false;
    queue.length = 0; backlog = 0;
    if (error) cacheController?.error(error);
    notify();
  };
  const cache = new ReadableStream<Uint8Array>({
    start(controller) { cacheController = controller; },
    async pull(controller) {
      while (cacheActive && !sourceDone && queue.length === 0) {
        await new Promise<void>(resolve => { wake = resolve; });
      }
      if (!cacheActive) return;
      const chunk = queue.shift();
      if (chunk) { backlog -= chunk.byteLength; controller.enqueue(chunk); }
      else { cacheActive = false; controller.close(); }
    },
    cancel() { dropCache(); },
  }, { highWaterMark: 0 });
  const client = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const item = await reader.read();
        if (clientClosed) return;
        if (item.done) {
          clientClosed = true; sourceDone = true; notify(); controller.close(); reader.releaseLock();
          return;
        }
        if (cacheActive) {
          if (backlog + item.value.byteLength > 4 * 1024 * 1024) dropCache(new Error('edge cache backlog limit'));
          else { queue.push(item.value); backlog += item.value.byteLength; notify(); }
        }
        controller.enqueue(item.value);
      } catch (error) {
        if (!clientClosed) {
          clientClosed = true; sourceDone = true;
          dropCache(new Error('artifact origin stream failed'));
          controller.error(error); reader.releaseLock();
        }
      }
    },
    async cancel(reason) {
      clientClosed = true; sourceDone = true;
      dropCache(new Error('artifact client disconnected'));
      try { await reader.cancel(reason); }
      finally { reader.releaseLock(); }
    },
  }, { highWaterMark: 0 });
  return { client, cache };
}
function admissibleCached(response: Response, limit: number, contentType: string): boolean {
  const length = response.headers.get('content-length') ?? '';
  return response.status === 200 && response.body !== null && /^[1-9][0-9]{0,8}$/.test(length)
    && Number(length) <= limit && /^"[A-Za-z0-9-]{1,128}"$/.test(response.headers.get('etag') ?? '')
    && response.headers.get('content-type') === contentType
    && response.headers.get('cache-control') === immutableCacheControl
    && !response.headers.has('set-cookie') && !response.headers.has('vary');
}
async function cacheImmutable(cache: Cache, key: Request, response: Response, limit: number): Promise<void> {
  if (!response.body) return;
  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<void>(resolve => {
    timer = setTimeout(() => { abort.abort(); resolve(); }, 25000);
  });
  let bytes = 0;
  try {
    const body = response.body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        bytes += chunk.byteLength;
        if (bytes > limit) throw new Error('cache body limit');
        controller.enqueue(chunk);
      },
      flush() { if (bytes !== limit) throw new Error('cache body length mismatch'); },
    }), { signal: abort.signal });
    await Promise.race([cache.put(key, new Response(body, response)), deadline]);
  }
  catch { abort.abort(); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function dependency(request: Request, env: Env, path: string, ctx?: Pick<ExecutionContext, 'waitUntil'>): Promise<Response> {
  const match = /^\/dependencies\/sqlite-v1\/(x86_64|aarch64)\/([a-f0-9]{64})\/([a-f0-9]{64})\/(latest\.json|[a-f0-9]{64}\.(tar|sigstore\.json))$/.exec(path);
  if (!match) throw new Refusal(404);
  if (request.method !== 'GET' && request.method !== 'HEAD') throw new Refusal(405);
  if (request.headers.has('range')) throw new Refusal(400);
  const latest = match[4] === 'latest.json';
  const archive = match[5] === 'tar';
  const limit = latest ? 65536 : archive ? 160 * 1024 * 1024 : 1024 * 1024;
  const contentType = archive ? 'application/x-tar' : 'application/json';
  const cacheKey = new Request(request.url, { method: 'GET' });
  let edge: Cache | undefined;
  if (!latest && request.method === 'GET' && ctx && typeof caches !== 'undefined') {
    try {
      edge = caches.default;
      const cached = await edge.match(cacheKey);
      if (cached && admissibleCached(cached, limit, contentType)) {
        const hit = new Response(cached.body, cached);
        hit.headers.set('X-OMG-Artifact-Cache', 'HIT');
        return hit;
      }
      if (cached?.body) await cached.body.cancel();
    } catch { edge = undefined; }
  }
  const object = request.method === 'HEAD' ? await env.DEPENDENCIES.head(path.slice(1)) : await env.DEPENDENCIES.get(path.slice(1));
  if (!object) throw new Refusal(404);
  const body = 'body' in object && object.body instanceof ReadableStream ? object.body : null;
  if (!Number.isSafeInteger(object.size) || object.size <= 0 || object.size > limit || !/^"[A-Za-z0-9-]{1,128}"$/.test(object.httpEtag)) {
    if (body) await body.cancel();
    throw new Refusal(502);
  }
  if (request.method === 'GET' && !body) throw new Refusal(502);
  const branches = edge && ctx && body ? cacheBranches(body) : undefined;
  const response = new Response(branches?.client ?? body, { headers: {
    'Content-Type': contentType, 'Content-Length': String(object.size),
    'ETag': object.httpEtag, 'X-Content-Type-Options': 'nosniff',
    'Cache-Control': latest ? 'no-store' : immutableCacheControl,
  } });
  if (edge && ctx && branches) ctx.waitUntil(cacheImmutable(edge, cacheKey, new Response(branches.cache, response), object.size));
  if (!latest && request.method === 'GET') response.headers.set('X-OMG-Artifact-Cache', edge ? 'MISS' : 'BYPASS');
  return response;
}
export default {
  async fetch(request: Request, env: Env, ctx?: Pick<ExecutionContext, 'waitUntil'>): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.search) throw new Refusal(400);
      if (url.pathname === '/v1/compiler-cache/credentials') {
        if (request.method !== 'POST') throw new Refusal(405);
        return await credentials(request, env);
      }
      if (url.pathname === '/health' && request.method === 'GET') {
        return Response.json({ sourceSha: env.SOURCE_SHA, policyVersion: POLICY.version,
          seedRecipeDigest: env.CACHE_SEED ? parseSeed(env.CACHE_SEED).recipeDigest : null },
          { headers: { 'Cache-Control': 'no-store' } });
      }
      return await dependency(request, env, url.pathname, ctx);
    } catch (error) {
      return Response.json({ error: 'artifact request refused' }, { status: error instanceof Refusal ? error.status : 503,
        headers: { 'Cache-Control': 'no-store' } });
    }
  },
};

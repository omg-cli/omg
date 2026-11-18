import { DurableObject, WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';

export type Input = { sourceSha: string; runId: string; attempt: number };
type Mode = 'run' | 'canary';
type Job = { input: Input; mode: Mode };
type Log = { key: string; sha256: string; bytes: number };
type Evidence = {
  schemaVersion: 1; input: Input; mode: Mode; imageDigest: string;
  exitCode: number | null; containerDestroyed: boolean; accepted: boolean;
  report: unknown; logs: { stdout: Log; stderr: Log }; error: string | null;
};
type State =
  | { kind: 'running'; job: Job; deadline: number }
  | { kind: 'closing'; job: Job; deadline: number; error: string | null }
  | { kind: 'terminal'; accepted: boolean };
export interface Env {
  CI_TOKEN: string;
  CI_IMAGE_DIGEST: string;
  CI_BUCKET: R2Bucket;
  CI_RUNNER: DurableObjectNamespace<NativeRunner>;
  CI_WORKFLOW: Workflow<Job>;
}
const LIMIT = 8 * 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function parseInput(value: unknown): Input {
  if (typeof value !== 'object' || value === null || Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== 'attempt,runId,sourceSha' ||
    !('sourceSha' in value) || typeof value.sourceSha !== 'string' || !/^[a-f0-9]{40}$/.test(value.sourceSha) ||
    !('runId' in value) || typeof value.runId !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value.runId) ||
    !('attempt' in value) || typeof value.attempt !== 'number' || !Number.isSafeInteger(value.attempt) || value.attempt < 1) {
    throw new Error('invalid immutable input');
  }
  return { sourceSha: value.sourceSha, runId: value.runId, attempt: value.attempt };
}

function idFor({ input, mode }: Job): string {
  return `${mode}-${input.runId}-${input.attempt}-${input.sourceSha}`;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 1000) : 'native CI failed';
}

function join(parts: Uint8Array[], size: number): Uint8Array {
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
  return result;
}

export async function readOutput(process: Pick<ExecProcess, 'stdout' | 'stderr'>, limit = LIMIT) {
  let used = 0;
  async function drain(stream: ReadableStream | null): Promise<Uint8Array> {
    if (!stream) throw new Error('missing output stream');
    const reader = stream.getReader();
    const parts: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const item = await reader.read();
        if (item.done) return join(parts, size);
        if (!(item.value instanceof Uint8Array)) throw new Error('invalid output chunk');
        used += item.value.byteLength;
        if (used > limit) throw new Error('combined output limit exceeded');
        parts.push(item.value);
        size += item.value.byteLength;
      }
    } finally { reader.releaseLock(); }
  }
  const [stdout, stderr] = await Promise.all([drain(process.stdout), drain(process.stderr)]);
  return { stdout, stderr };
}

async function hash(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('');
}

function parseReport(bytes: Uint8Array): unknown {
  const lines = decoder.decode(bytes).trimEnd().split('\n');
  const line = lines.at(-1);
  if (!line?.startsWith('OMG_CI_RESULT=')) throw new Error('missing final trusted report');
  return JSON.parse(line.slice('OMG_CI_RESULT='.length));
}

function acceptedReport(report: unknown, job: Job): boolean {
  return typeof report === 'object' && report !== null && 'accepted' in report && report.accepted === true &&
    (job.mode === 'canary' || ('sourceSha' in report && report.sourceSha === job.input.sourceSha));
}

const CANARY_SETUP = "import os; os.makedirs('/tmp/omg-ci-owned',exist_ok=False); os.chown('/tmp/omg-ci-owned',10001,10001); open('/tmp/omg-ci-root','w').write('protected'); os.chmod('/tmp/omg-ci-root',0o600)";
const CANARY = `import os,json
assert os.getuid()==10001 and os.getgid()==10001
assert 'VERSION_ID="24.04"' in open('/etc/os-release').read()
assert int(next(line.split()[1] for line in open('/proc/self/status') if line.startswith('CapEff:')),16)==0
open('/tmp/omg-ci-owned/result','w').write('ok')
denied=False
try: open('/tmp/omg-ci-root','w').write('bad')
except PermissionError: denied=True
assert denied
print('OMG_CI_RESULT='+json.dumps({'accepted':True,'ubuntu':'24.04','uid':os.getuid(),'gid':os.getgid(),'rootWriteDenied':denied,'effectiveCapabilities':0}))`;

export class NativeRunner extends DurableObject<Env> {
  private executing = false;
  private destruction: Promise<void> | undefined;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      if (ctx.container?.running) await ctx.container.setInactivityTimeout(60000);
      const id = await ctx.storage.get<string>('active');
      if (id) await this.interrupt(id, 'invocation interrupted');
      else if (ctx.container?.running) await this.destroy();
    });
  }

  private get container(): Container {
    if (!this.ctx.container) throw new Error('container binding unavailable');
    return this.ctx.container;
  }

  private destroy(): Promise<void> {
    if (!this.destruction) this.destruction = (async () => {
      try {
        await this.container.destroy();
        if (this.container.running || await this.container.inspect() !== null) throw new Error('container destruction unconfirmed');
      } finally { this.destruction = undefined; }
    })();
    return this.destruction;
  }

  private async interrupt(id: string, error: string): Promise<void> {
    const state = await this.ctx.storage.get<State>(id);
    if (!state || state.kind === 'terminal') return;
    await this.ctx.storage.setAlarm(Date.now() + 1000);
    await this.ctx.storage.put(id, { ...state, kind: 'closing', error } satisfies State);
    await this.destroy();
    if (!this.executing) await this.finish(id, state.job, null, null, new Uint8Array(), new Uint8Array(), error);
  }

  async cancel(id: string): Promise<void> {
    const active = await this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.get('active') === id) return true;
      if (!await this.ctx.storage.get(id)) await this.ctx.storage.put(id, { kind: 'terminal', accepted: false } satisfies State);
      return false;
    });
    if (active) await this.interrupt(id, 'cancelled by caller');
  }

  async alarm(): Promise<void> {
    const id = await this.ctx.storage.get<string>('active');
    if (!id) {
      if (this.container.running) await this.destroy();
      return;
    }
    const state = await this.ctx.storage.get<State>(id);
    if (state?.kind === 'closing') {
      await this.destroy();
      if (!this.executing) {
        const current = await this.ctx.storage.get<State>(id);
        if (current?.kind === 'closing') await this.finish(id, current.job, null, null, new Uint8Array(), new Uint8Array(), current.error);
      }
    } else if (state?.kind === 'running') {
      if (Date.now() < state.deadline) await this.ctx.storage.setAlarm(state.deadline);
      else await this.interrupt(id, 'absolute deadline exceeded');
    }
  }

  private async assertRunning(id: string): Promise<void> {
    const state = await this.ctx.storage.get<State>(id);
    if (state?.kind !== 'running' || Date.now() >= state.deadline) throw new Error('job launch fence closed');
  }

  private async execute(id: string, job: Job) {
    await this.assertRunning(id);
    this.container.start(job.mode === 'canary' ? { entrypoint: ['sleep', 'infinity'], enableInternet: false } : { enableInternet: false });
    await this.container.setInactivityTimeout(60000);
    if (job.mode === 'canary') {
      await this.assertRunning(id);
      const setup = await this.container.exec(['/usr/bin/python3', '-I', '-c', CANARY_SETUP], { stdout: 'pipe', stderr: 'pipe' });
      await Promise.all([readOutput(setup, 1024), setup.exitCode.then(code => { if (code !== 0) throw new Error('canary setup failed'); })]);
    }
    await this.assertRunning(id);
    const process = await this.container.exec(job.mode === 'canary' ? ['/usr/bin/python3', '-I', '-c', CANARY] : ['/usr/bin/python3', '-I', '/opt/ci/run.py', job.input.sourceSha],
      { stdout: 'pipe', stderr: 'pipe', ...(job.mode === 'canary' ? { user: '10001:10001' } : {}) });
    const [output, exitCode, image] = await Promise.all([readOutput(process), process.exitCode, this.container.inspect()]);
    if (!image || !(image.image === this.env.CI_IMAGE_DIGEST || image.image.endsWith('@' + this.env.CI_IMAGE_DIGEST))) {
      throw new Error('running image digest mismatch');
    }
    return { ...output, exitCode };
  }

  private async finish(id: string, job: Job, exitCode: number | null, report: unknown, stdout: Uint8Array, stderr: Uint8Array, error: string | null) {
    const save = async (name: string, data: Uint8Array): Promise<Log> => {
      const key = `${id}/${name}`;
      await this.env.CI_BUCKET.put(key, data);
      return { key, sha256: await hash(data), bytes: data.byteLength };
    };
    const [out, err] = await Promise.all([save('stdout', stdout), save('stderr', stderr)]);
    const accepted = error === null && exitCode === 0 && acceptedReport(report, job);
    const evidence: Evidence = { schemaVersion: 1, input: job.input, mode: job.mode, imageDigest: this.env.CI_IMAGE_DIGEST,
      exitCode, containerDestroyed: true, accepted, report, logs: { stdout: out, stderr: err }, error };
    const key = `${id}/evidence.json`;
    await this.env.CI_BUCKET.put(key, JSON.stringify(evidence), { httpMetadata: { contentType: 'application/json' } });
    await this.ctx.storage.transaction(async transaction => {
      if (await transaction.get('active') !== id) throw new Error('job reservation changed');
      await transaction.put(id, { kind: 'terminal', accepted } satisfies State);
      await transaction.delete('active');
      await transaction.deleteAlarm();
    });
    return { key, accepted };
  }

  async run(job: Job): Promise<{ key: string; accepted: boolean }> {
    job = { input: parseInput(job.input), mode: job.mode };
    if (job.mode !== 'run' && job.mode !== 'canary') throw new Error('invalid mode');
    if (!/^sha256:[a-f0-9]{64}$/.test(this.env.CI_IMAGE_DIGEST) || /^sha256:0+$/.test(this.env.CI_IMAGE_DIGEST)) throw new Error('image digest is not configured');
    const id = idFor(job);
    const duration = job.mode === 'canary' ? 120000 : 2400000;
    const refused = await this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.get(id)) return 'job was already submitted; use a new attempt';
      if (await this.ctx.storage.get('active')) return 'native CI capacity is busy';
      await this.ctx.storage.put({ [id]: { kind: 'running', job, deadline: Date.now() + duration } satisfies State, active: id });
      await this.ctx.storage.setAlarm(Date.now() + duration);
      this.executing = true;
      return null;
    });
    if (refused) throw new Error(refused);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stdout: Uint8Array = new Uint8Array(), stderr: Uint8Array = new Uint8Array();
    let exitCode: number | null = null, report: unknown = null, error: string | null = null;
    try {
      const result = await Promise.race([this.execute(id, job), new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('absolute deadline exceeded')), duration);
      })]);
      ({ stdout, stderr, exitCode } = result);
      report = parseReport(stdout);
      if (!acceptedReport(report, job)) throw new Error('trusted report rejected job');
    } catch (failure) { error = message(failure); }
    finally { if (timer !== undefined) clearTimeout(timer); }
    const state = await this.ctx.storage.get<State>(id);
    if (state?.kind === 'closing') error = state.error;
    if (state?.kind === 'running' && Date.now() >= state.deadline) error = 'absolute deadline exceeded';
    await this.ctx.storage.put(id, { kind: 'closing', job, deadline: 0, error } satisfies State);
    await this.ctx.storage.setAlarm(Date.now() + 1000);
    try {
      await this.destroy();
      return await this.ctx.blockConcurrencyWhile(async () => {
        const closing = await this.ctx.storage.get<State>(id);
        if (closing?.kind === 'closing' && closing.error) error = closing.error;
        return await this.finish(id, job, exitCode, report, stdout, stderr, error);
      });
    } finally { this.executing = false; }
  }
}

export class NativeCIWorkflow extends WorkflowEntrypoint<Env, Job> {
  async run(event: WorkflowEvent<Job>, step: WorkflowStep) {
    return await step.do('native-ci', { retries: { limit: 0, delay: '1 second' }, timeout: '45 minutes' }, async () => {
      const result = await this.env.CI_RUNNER.getByName('ubuntu').run(event.payload);
      if (!result.accepted) throw new Error('native CI failed; inspect authenticated evidence');
      return result;
    });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.CI_TOKEN || request.headers.get('Authorization') !== `Bearer ${env.CI_TOKEN}`) return Response.json({ error: 'unauthorized' }, { status: 401 });
    const path = new URL(request.url).pathname;
    try {
      if (request.method === 'GET' && path === '/health') return Response.json({ service: 'omg-native-ci', imageDigest: env.CI_IMAGE_DIGEST });
      if (request.method === 'POST' && (path === '/runs' || path === '/canary')) {
        const body = await readOutput({ stdout: request.body, stderr: new ReadableStream({ start(controller) { controller.close(); } }) }, 1024);
        const job: Job = { input: parseInput(JSON.parse(decoder.decode(body.stdout))), mode: path === '/canary' ? 'canary' : 'run' };
        const id = idFor(job);
        await env.CI_WORKFLOW.create({ id, params: job });
        return Response.json({ id, statusUrl: `/runs/${id}`, evidenceUrl: `/runs/${id}/evidence` }, { status: 202 });
      }
      const route = /^\/runs\/((?:run|canary)-[1-9][0-9]{0,19}-[1-9][0-9]*-[a-f0-9]{40})(?:\/(evidence|logs\/stdout|logs\/stderr|cancel))?$/.exec(path);
      const id = route?.[1];
      if (!id) return Response.json({ error: 'not found' }, { status: 404 });
      const action = route?.[2];
      if (request.method === 'POST' && action === 'cancel') {
        await env.CI_RUNNER.getByName('ubuntu').cancel(id);
        return Response.json({ cancelled: true });
      }
      if (request.method !== 'GET') return Response.json({ error: 'method not allowed' }, { status: 405 });
      if (!action) return Response.json(await (await env.CI_WORKFLOW.get(id)).status());
      const key = action === 'evidence' ? `${id}/evidence.json` : `${id}/${action.split('/')[1]}`;
      const object = await env.CI_BUCKET.get(key);
      return object ? new Response(object.body, { headers: { 'Content-Type': action === 'evidence' ? 'application/json' : 'application/octet-stream', 'Cache-Control': 'no-store' } }) : Response.json({ error: 'evidence unavailable' }, { status: 404 });
    } catch (error) { return Response.json({ error: message(error) }, { status: 400 }); }
  },
};

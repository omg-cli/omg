import { Sandbox, getSandbox } from "@cloudflare/sandbox";
import { z } from "zod";
import type * as Workers from "@cloudflare/workers-types/index.ts";

type Request = globalThis.Request | Workers.Request;
declare const Response: typeof Workers.Response;

const hardLimitMs = 180_000;
const stateKey = "capability-probe";
const stateSchema = z.strictObject({ expiresAt: z.number().int().positive(), closed: z.boolean(), cleanupAttempts: z.number().int().nonnegative() });
const reportSchema = z.strictObject({
  accepted: z.boolean(), distro: z.record(z.string(), z.string()), uid: z.number().int().nonnegative(),
  capEff: z.string().regex(/^[a-f0-9]{16}$/),
  checks: z.strictObject({ ownedTemporaryDirectory: z.boolean(), ownershipChange: z.boolean(),
    candidateIdentity: z.boolean(), frozenControllerProtected: z.boolean(), processGroupTermination: z.boolean() }),
  cleanup: z.boolean(), error: z.string().max(1000).nullable(),
});

// SDK 0.x lifecycle and image compatibility: https://developers.cloudflare.com/sandbox/sdk/concepts/sandboxes/
export class UbuntuPilotSandbox extends Sandbox {
  override sleepAfter = "3m";
  override enableInternet = false;
  private probe?: z.infer<typeof stateSchema>;

  constructor(...args: ConstructorParameters<typeof Sandbox>) {
    super(...args);
    const [ctx] = args;
    void ctx.blockConcurrencyWhile(async () => {
      const stored = await ctx.storage.get(stateKey);
      if (stored !== undefined) this.probe = stateSchema.parse(stored);
    });
  }

  protected override beforeStart() {
    if (!this.probe || this.probe.closed || Date.now() >= this.probe.expiresAt)
      throw new Error("Capability probe refuses a late container start");
    super.beforeStart();
  }

  async armProbe() {
    if (this.probe) throw new Error("Capability probe identity already used");
    this.probe = { expiresAt: Date.now() + hardLimitMs, closed: false, cleanupAttempts: 0 };
    await this.ctx.storage.put(stateKey, this.probe);
    // Keep the SDK's lifecycle alarm intact: https://developers.cloudflare.com/containers/api/container-class/#schedule
    await this.schedule(new Date(this.probe.expiresAt), "expireProbe", null);
  }

  async expireProbe() {
    if (!this.probe) throw new Error("Capability probe deadline is missing");
    this.probe.cleanupAttempts++;
    try { await this.finishProbe(); }
    catch (error) {
      if (this.probe.cleanupAttempts < 3 && Date.now() < this.probe.expiresAt + 15_000)
        await this.schedule(5, "expireProbe", null);
      throw error;
    }
  }

  async finishProbe() {
    this.probe = { expiresAt: this.probe?.expiresAt ?? Date.now(), closed: true,
      cleanupAttempts: this.probe?.cleanupAttempts ?? 0 };
    try { await this.ctx.storage.put(stateKey, this.probe); }
    finally { await super.destroy(); }
    if (this.ctx.container?.running) throw new Error("Capability probe container remains running");
    return { destroyed: true };
  }
}

export const capabilityCommand = `env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/bin/python3 - <<'PY'
import json, os, pathlib, shutil, signal, subprocess, sys, tempfile, time
report = {'accepted': False, 'distro': {}, 'uid': os.getuid(), 'capEff': '0000000000000000',
    'checks': dict.fromkeys(['ownedTemporaryDirectory','ownershipChange','candidateIdentity',
        'frozenControllerProtected','processGroupTermination'], False), 'cleanup': False, 'error': None}
work, group, descendant = None, None, None
def deadline(signum, frame):
    raise TimeoutError('fixed capability probe exceeded 30 seconds')
signal.signal(signal.SIGALRM, deadline)
signal.alarm(30)
try:
    report['distro'] = dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    report['distro'] = {key:value.strip('"') for key,value in report['distro'].items()}
    report['capEff'] = next(line.split()[1] for line in pathlib.Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    assert os.getuid() == 0, 'trusted controller is not root'
    work = pathlib.Path(tempfile.mkdtemp(prefix='omg-capability-probe-', dir='/tmp'))
    assert work.parent == pathlib.Path('/tmp') and not work.is_symlink() and work.stat().st_uid == 0
    os.chmod(work, 0o755)
    report['checks']['ownedTemporaryDirectory'] = True
    frozen = work/'frozen'
    frozen.write_text('frozen-controller')
    frozen.chmod(0o444)
    home = work/'candidate'
    home.mkdir(mode=0o700)
    os.chown(home,10001,10001)
    assert (home.stat().st_uid,home.stat().st_gid) == (10001,10001)
    report['checks']['ownershipChange'] = True
    child_code = '''import json,os,pathlib,sys
assert (os.getuid(),os.getgid(),os.getgroups()) == (10001,10001,[])
pathlib.Path(sys.argv[2]).joinpath('candidate-write').write_text('owned')
try:
    pathlib.Path(sys.argv[1]).write_text('escaped')
except PermissionError:
    print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'protected':True}))
else:
    raise AssertionError('candidate overwrote frozen controller')
'''
    child = subprocess.run([sys.executable,'-c',child_code,str(frozen),str(home)],user=10001,group=10001,
        extra_groups=[],capture_output=True,text=True,timeout=5,env={'PATH':'/usr/bin:/bin','HOME':str(home)})
    assert child.returncode == 0, child.stderr
    identity = json.loads(child.stdout)
    assert identity['uid'] == identity['gid'] == 10001
    report['checks']['candidateIdentity'] = True
    assert identity['protected'] is True and frozen.read_text() == 'frozen-controller'
    report['checks']['frozenControllerProtected'] = True
    group_code = '''import signal,subprocess,sys,time
child = subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
def stop(signum,frame):
    child.wait(timeout=3)
    sys.exit(0)
signal.signal(signal.SIGTERM,stop)
print(child.pid,flush=True)
time.sleep(120)
'''
    group = subprocess.Popen([sys.executable,'-c',group_code],start_new_session=True,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={'PATH':'/usr/bin:/bin'})
    descendant = int(group.stdout.readline())
    assert os.getpgid(descendant) == group.pid
    os.killpg(group.pid,signal.SIGTERM)
    assert group.wait(timeout=5) == 0
    assert not pathlib.Path('/proc',str(descendant)).exists(), 'owned descendant survived group termination'
    report['checks']['processGroupTermination'] = True
except Exception as error:
    report['error'] = (type(error).__name__+': '+str(error))[:1000]
finally:
    signal.alarm(0)
    try:
        if group is not None:
            if group.poll() is None:
                os.killpg(group.pid,signal.SIGKILL)
            group.wait(timeout=5)
            if descendant and pathlib.Path('/proc',str(descendant)).exists():
                if os.getpgid(descendant) == group.pid:
                    os.kill(descendant,signal.SIGKILL)
                raise AssertionError('owned descendant required forced cleanup')
        if work is not None:
            assert work.parent == pathlib.Path('/tmp') and work.name.startswith('omg-capability-probe-') and not work.is_symlink()
            shutil.rmtree(work)
            assert not work.exists()
        report['cleanup'] = True
    except Exception as error:
        report['error'] = (report['error'] or '')[:400]+'; cleanup: '+str(error)[:500]
report['accepted'] = report['error'] is None and report['cleanup'] and all(report['checks'].values())
print(json.dumps(report))
sys.exit(0 if report['accepted'] else 1)
PY`;

type ProbeSandbox = Pick<Sandbox, "exec"> & Pick<UbuntuPilotSandbox, "armProbe" | "finishProbe">;
const json = (value: unknown, status: number) =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

async function bounded<T>(operation: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("Capability probe RPC deadline exceeded")), milliseconds);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

export async function handleCapabilityProbe(request: Request, token: string, connect: (id: string) => ProbeSandbox) {
  const hashes = await Promise.all([request.headers.get("Authorization") ?? "", `Bearer ${token}`]
    .map((value) => crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
  const [actual, expected] = hashes.map((hash) => new Uint8Array(hash));
  let difference = 0;
  for (let index = 0; index < actual.length; index++) difference |= actual[index] ^ expected[index];
  if (!/^[^\s]{32,512}$/.test(token) || difference !== 0) return json({ accepted: false, error: "Unauthorized" }, 401);
  if (request.method !== "POST" || new URL(request.url).pathname !== "/probe") return json({ accepted: false, error: "Not found" }, 404);
  try {
    const reader = request.body?.getReader();
    const chunks = [];
    let size = 0;
    if (reader) while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 128) { await reader.cancel(); throw new Error("Probe body too large"); }
      chunks.push(next.value);
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
    z.strictObject({ kind: z.literal("capability-smoke") }).parse(JSON.parse(new TextDecoder().decode(body)));
  } catch {
    return json({ accepted: false, error: "Invalid fixed probe request" }, 400);
  }
  const id = `capability-${crypto.randomUUID()}`;
  const sandbox = connect(id);
  let probe: z.infer<typeof reportSchema> | null = null;
  let error: string | null = null;
  let destroyed = false;
  try {
    await bounded(sandbox.armProbe(), 10_000);
    const result = await bounded(sandbox.exec(capabilityCommand, { timeout: 45_000 }), 120_000);
    if (result.stdout.length > 16_384) throw new Error("Capability report exceeds byte budget");
    probe = reportSchema.parse(JSON.parse(result.stdout));
    if (!result.success || result.exitCode !== 0 || !probe.accepted || !probe.cleanup ||
        probe.uid !== 0 || !Object.values(probe.checks).every(Boolean)) throw new Error("Capability boundary was not established");
  } catch (failure) {
    error = failure instanceof Error ? failure.message.slice(0, 1000) : "Capability probe unavailable";
  } finally {
    // SDK command timeouts leave processes alive: https://developers.cloudflare.com/sandbox/sdk/guides/execute-commands/#timeouts
    try { destroyed = (await bounded(sandbox.finishProbe(), 30_000)).destroyed; }
    catch { error = "Capability probe destruction was not confirmed"; }
  }
  return json({ id, accepted: error === null && destroyed, destroyed, probe, error }, error === null && destroyed ? 200 : 503);
}

type Env = { PILOT_PROBE_TOKEN: string; PILOT_SANDBOX: DurableObjectNamespace<UbuntuPilotSandbox> };
export default {
  fetch(request: Request, env: Env) {
    return handleCapabilityProbe(request, env.PILOT_PROBE_TOKEN, (id) => getSandbox(env.PILOT_SANDBOX,
      id, { sleepAfter: "3m", keepAlive: false, enableDefaultSession: false,
        containerTimeouts: { instanceGetTimeoutMS: 20_000, portReadyTimeoutMS: 40_000 } }));
  },
} satisfies ExportedHandler<Env>;

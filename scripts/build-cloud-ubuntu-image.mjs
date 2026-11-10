import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { authenticate, frozenInputs, frozenAssertion, validateImageIdentity } from '../services/cloud-ci/test/hosted-image-probe.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const registry = 'registry.cloudflare.com';
const dockerfile = 'services/cloud-ci/Dockerfile.ubuntu-pilot';
const hash = value => createHash('sha256').update(value).digest('hex');

export function candidateIdentityMatches(uid, gid, groups) {
    // Node includes the effective GID: https://nodejs.org/api/process.html#processgetgroups
    return uid === 10001 && gid === 10001 && groups.length === 1 && groups[0] === gid;
}

export function pinnedDockerfile(text) {
    const sources = [...text.matchAll(/^[ \t]*FROM[ \t]+(\S+)/gim)];
    if (!sources.length || sources.some(([, image]) => !/^\S+@sha256:[a-f0-9]{64}$/.test(image)))
        throw new Error('Every Ubuntu image FROM requires an exact digest');
}

export function ubuntuFrozenInputs(root, source) {
    const frozen = frozenInputs(root, source);
    for (const name of ['build-comparison.py', 'test-debian-daemon-catalog.py'])
        frozen.files.push({ source: 'scripts/' + name, targets: ['/scripts/' + name],
            sha256: hash(readFileSync(path.join(root, 'scripts', name))) });
    return frozen;
}

export function verifyServerStartup(tag, { run = spawnSync, env = process.env } = {}) {
    const name = 'omg-ubuntu-startup-' + randomUUID();
    const fixedCommand = `env -i PATH=/usr/local/bin:/usr/bin:/bin /bin/sh -eu -c '. /etc/os-release; test "$ID" = ubuntu; test "$VERSION_ID" = 24.04; printf "ubuntu-24.04\\n"'`;
    // SDK 0.12.14 server routes: https://github.com/cloudflare/sandbox-sdk/tree/%40cloudflare%2Fsandbox%400.12.14/packages/sandbox-container/src/handlers
    const probe = `import assert from 'node:assert/strict';
const request = async (route, options = {}, milliseconds = 2000) => {
    const response = await fetch('http://127.0.0.1:3000' + route, { ...options, signal: AbortSignal.timeout(milliseconds) });
    assert.equal(response.status,200,route);
    const reader=response.body.getReader(), chunks=[]; let size=0;
    for (;;) { const next=await reader.read(); if(next.done) break; size+=next.value.byteLength;
        if(size>16384){await reader.cancel();throw new Error('Startup response too large');} chunks.push(next.value); }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};
const deadline=Date.now()+45000;
for (;;) {
    try { const health=await request('/api/health'); assert.equal(health.success,true); assert.equal(health.status,'healthy'); break; }
    catch(error) { if(Date.now()>=deadline) throw new Error('Sandbox health deadline exceeded: '+String(error).slice(0,256)); }
    await new Promise(resolve=>setTimeout(resolve,250));
}
const version=await request('/api/version'); assert.equal(version.success,true); assert.equal(version.version,'0.12.14');
const command=${JSON.stringify(fixedCommand)};
const execution=await request('/api/execute',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({command,timeoutMs:5000})},8000);
assert.equal(execution.success,true); assert.equal(execution.exitCode,0); assert.equal(execution.command,command);
assert.equal(execution.stdout.trim(),'ubuntu-24.04'); assert.equal(execution.stderr,'');
console.log(JSON.stringify({accepted:true,sdkVersion:version.version,distro:'ubuntu',version:'24.04'}));`;
    const execute = (args, timeout = 10_000) => {
        const result = run('docker', args, { env, encoding: 'utf8', timeout, maxBuffer: 1024 * 1024 });
        if (result.error || result.status !== 0)
            throw new Error('Ubuntu default entrypoint ' + args[0] + ' failed: ' + String(result.stderr ?? '').slice(0,4096));
        return result.stdout?.trim() ?? '';
    };
    try {
        execute(['run', '--rm', '--detach', '--network', 'none', '--name', name, tag]);
        const report = JSON.parse(execute(['exec', name, 'node', '--input-type=module', '-e', probe], 60_000));
        if (report.accepted !== true || report.sdkVersion !== '0.12.14' || report.distro !== 'ubuntu' || report.version !== '24.04')
            throw new Error('Ubuntu default entrypoint returned invalid runtime evidence');
        return report;
    } finally {
        run('docker', ['rm', '--force', name], { env, timeout: 10_000, encoding: 'utf8', maxBuffer: 4096 });
        if (execute(['container', 'ls', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']))
            throw new Error('Ubuntu default entrypoint container cleanup was not confirmed');
    }
}

function smokeScript(frozen) {
    const candidateScript = "import assert from 'node:assert/strict';import{writeFileSync}from'node:fs';assert((" +
        candidateIdentityMatches.toString() + ")(process.getuid(),process.getgid(),process.getgroups()),'candidate UID/GID/groups mismatch');writeFileSync(process.argv[2]+'/owned','candidate');assert.throws(()=>writeFileSync(process.argv[1],'escaped'),{code:'EACCES'});";
    return frozenAssertion(frozen).script + `
import { mkdtempSync, writeFileSync, chmodSync, mkdirSync, chownSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const release = Object.fromEntries(readFileSync('/etc/os-release','utf8').split('\\n').filter(line=>line.includes('=')).map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1).replace(/^"|"$/g,'')];}));
assert.equal(release.ID,'ubuntu'); assert.equal(release.VERSION_ID,'24.04');
assert.equal(process.platform,'linux'); assert.equal(process.arch,'x64'); assert.equal(process.getuid(),0);
const work = mkdtempSync('/tmp/omg-image-smoke-');
try {
    chmodSync(work,0o755); const protectedFile=path.join(work,'controller');
    writeFileSync(protectedFile,'frozen'); chmodSync(protectedFile,0o444);
    const home=path.join(work,'candidate'); mkdirSync(home,{mode:0o700}); chownSync(home,10001,10001);
    const child = spawnSync('setpriv',['--reuid=10001','--regid=10001','--clear-groups',process.execPath,'--input-type=module','-e',
        ${JSON.stringify(candidateScript)},
        protectedFile,home],{encoding:'utf8',timeout:10000,env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:home}});
    assert.equal(child.status,0,child.stderr?.slice(0,2048) || 'candidate identity/protected-controller smoke failed');
    assert.equal(readFileSync(protectedFile,'utf8'),'frozen');
} finally { rmSync(work,{recursive:true,force:true}); }
console.log(JSON.stringify({accepted:true,distro:'ubuntu',version:'24.04',architecture:'amd64',candidateUid:10001,frozenFiles:files.length}));`;
}

export async function buildUbuntuImage(output, { root = ROOT, environment = process.env,
    run = spawnSync, login = authenticate } = {}) {
    if (environment.GITHUB_ACTIONS !== 'true' || environment.GITHUB_REPOSITORY !== 'omg-cli/omg' ||
        environment.GITHUB_EVENT_NAME !== 'workflow_dispatch' || environment.RUNNER_OS !== 'Linux' ||
        !/^[a-f0-9]{40}$/.test(environment.GITHUB_SHA ?? ''))
        throw new Error('Ubuntu image builder requires an immutable GitHub Linux manual run');
    const command = (binary, args, options = {}) => {
        const result = run(binary, args, { cwd: root, encoding: 'utf8', timeout: 60_000,
            maxBuffer: 16 * 1024 * 1024, ...options });
        if (result.error || result.status !== 0) {
            const detail = binary === 'docker' && args[0] === 'run' ? String(result.stderr ?? '').slice(0,4096) : '';
            throw new Error(`Ubuntu image ${binary} ${args[0]} failed${detail ? ': ' + detail : ''}`);
        }
        return result.stdout?.trim() ?? '';
    };
    const source = command('git', ['rev-parse', 'HEAD']);
    if (source !== environment.GITHUB_SHA) throw new Error('GitHub source SHA differs from checkout HEAD');
    if (command('git', ['status', '--porcelain=v1', '--untracked-files=normal']))
        throw new Error('Ubuntu image builder requires a clean checkout');
    const account = environment.CLOUDFLARE_ACCOUNT_ID;
    if (!/^[a-f0-9]{32}$/.test(account ?? '') || !environment.CLOUDFLARE_API_TOKEN)
        throw new Error('Ubuntu image builder requires Cloudflare registry credentials');
    const temporary = mkdtempSync(path.join(tmpdir(), 'omg-ubuntu-image-'));
    const context = path.join(temporary, 'context');
    const dockerConfig = path.join(temporary, 'docker-config');
    const dockerEnv = { ...environment, DOCKER_CONFIG: dockerConfig };
    const authenticateRegistry = () => login(account, environment.CLOUDFLARE_API_TOKEN, registry, dockerConfig, {
        fetchImpl: (url, options) => fetch(url, { ...options, signal: AbortSignal.timeout(30_000) }),
        spawn: (binary, args, options) => run(binary, args, { ...options, timeout: 60_000 }),
    });
    try {
        mkdirSync(context, { mode: 0o700 });
        mkdirSync(dockerConfig, { mode: 0o700 });
        const archive = path.join(context, 'source.tar');
        command('git', ['archive', '--format=tar', '--output=' + archive, source]);
        const archiveSha256 = hash(readFileSync(archive));
        command('tar', ['-xf', archive, '-C', context]);
        unlinkSync(archive);
        const recipe = readFileSync(path.join(context, dockerfile), 'utf8');
        pinnedDockerfile(recipe);
        const frozen = ubuntuFrozenInputs(context, source);
        appendFileSync(path.join(context, dockerfile), '\n' + frozenAssertion(frozen).run + '\n');
        const tag = 'omg-cloud-ci-ubuntu-pilot:' + source;
        const registryReference = `${registry}/${account}/omg-cloud-ci-ubuntu-pilot`;
        await authenticateRegistry();
        // Build/push and digest inspection: https://developers.cloudflare.com/containers/guides/image-management/
        command('docker', ['build', '--platform', 'linux/amd64', '-f', dockerfile, '-t', tag, '.'],
            { cwd: context, env: dockerEnv, timeout: 1_800_000, stdio: 'inherit' });
        const smoke = JSON.parse(command('docker', ['run', '--rm', '--network', 'none', '--read-only',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m', '--entrypoint', 'node', tag,
            '--input-type=module', '-e', smokeScript(frozen)], { env: dockerEnv, timeout: 60_000 }).split('\n').at(-1));
        if (smoke.accepted !== true) throw new Error('Ubuntu image smoke did not pass');
        const entrypointSmoke = verifyServerStartup(tag, { run, env: dockerEnv });
        const wrangler = path.join(root, 'services/cloud-ci/node_modules/wrangler/bin/wrangler.js');
        command(process.execPath, [wrangler, 'containers', 'push', tag],
            { cwd: path.join(root, 'services/cloud-ci'), env: dockerEnv, timeout: 600_000, stdio: 'inherit' });
        await authenticateRegistry();
        const image = JSON.parse(command('docker', ['image', 'inspect', '--format', '{{json .}}', tag], { env: dockerEnv }));
        const manifest = JSON.parse(command('docker', ['manifest', 'inspect', '--verbose', registryReference + ':' + source], { env: dockerEnv }));
        const backend = command('docker', ['info', '--format', '{{.Driver}}/{{json .DriverStatus}}'], { env: dockerEnv });
        if (image.Os !== 'linux' || image.Architecture !== 'amd64') throw new Error('Ubuntu image platform mismatch');
        const identity = validateImageIdentity({ localId: image.Id, image, manifest, backend,
            registryReference, repoDigests: image.RepoDigests });
        const proof = { schemaVersion: 1, source, ...identity, registryReference, archiveSha256,
            dockerfileSha256: hash(recipe), builtDockerfileSha256: hash(readFileSync(path.join(context, dockerfile))),
            frozenManifestSha256: hash(JSON.stringify(frozen)), frozen, manifest, image, backend, smoke, entrypointSmoke,
            runId: environment.GITHUB_RUN_ID, attempt: environment.GITHUB_RUN_ATTEMPT };
        const text = JSON.stringify(proof, null, 2) + '\n';
        if (Buffer.byteLength(text) > 1024 * 1024) throw new Error('Ubuntu image proof exceeds byte budget');
        writeFileSync(output, text, { flag: 'wx', mode: 0o600 });
        return proof;
    } finally {
        rmSync(temporary, { recursive: true, force: true });
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    if (process.argv.length !== 3) throw new Error('Usage: node scripts/build-cloud-ubuntu-image.mjs <output.json>');
    await buildUbuntuImage(path.resolve(process.argv[2]));
}

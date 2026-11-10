import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildUbuntuImage, ubuntuFrozenInputs, pinnedDockerfile, candidateIdentityMatches, verifyServerStartup } from '../../../scripts/build-cloud-ubuntu-image.mjs';
import { frozenAssertion } from './hosted-image-probe.mjs';

const sha = 'a'.repeat(40);
const environment = { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'omg-cli/omg',
    GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_SHA: sha, RUNNER_OS: 'Linux',
    CLOUDFLARE_ACCOUNT_ID: 'b'.repeat(32), CLOUDFLARE_API_TOKEN: 'fixture-secret' };

test('default entrypoint must answer the fixed SDK health/version/execute probe before cleanup', () => {
    const calls = [];
    const report = verifyServerStartup('image:fixture', { env: environment,
        run(command, args) {
            calls.push(args);
            if (args[0] === 'run') {
                expect(args).not.toContain('--entrypoint');
                expect(args).not.toContain('-p');
                expect(args).not.toContain('--env');
                expect(args).toContain('none');
                return { status: 0, stdout: 'owned-container-id' };
            }
            if (args[0] === 'exec') {
                expect(args.at(-1)).toContain('/api/health');
                expect(args.at(-1)).toContain('/api/version');
                expect(args.at(-1)).toContain('/api/execute');
                expect(args.at(-1)).not.toContain(environment.CLOUDFLARE_API_TOKEN);
                expect(spawnSync('node', ['--input-type=module', '--check'], { input: args.at(-1) }).status).toBe(0);
                return { status: 0, stdout: JSON.stringify({ accepted: true, sdkVersion: '0.12.14', distro: 'ubuntu', version: '24.04' }) };
            }
            return { status: 0, stdout: '' };
        } });
    expect(report).toMatchObject({ accepted: true, sdkVersion: '0.12.14', distro: 'ubuntu', version: '24.04' });
    expect(calls.map(args => args[0])).toEqual(['run', 'exec', 'rm', 'container']);
});

test('unhealthy server and wrong runtime evidence still retire the owned container and cannot pass', () => {
    for (const mode of ['failed', 'wrong-version', 'cleanup-failed']) {
        const calls = [];
        expect(() => verifyServerStartup('image:fixture', { env: environment, run(command, args) {
            calls.push(args[0]);
            if (args[0] === 'run') return { status: 0, stdout: 'owned-container-id' };
            if (args[0] === 'exec') return mode === 'failed' ? { status: 1, stderr: 'controlled startup failure' } :
                { status: 0, stdout: JSON.stringify({ accepted: true, sdkVersion: mode === 'wrong-version' ? '1.0' : '0.12.14', distro: 'ubuntu', version: '24.04' }) };
            return { status: 0, stdout: args[0] === 'container' && mode === 'cleanup-failed' ? 'still-owned' : '' };
        } })).toThrow();
        expect(calls).toEqual(['run', 'exec', 'rm', 'container']);
    }
});

test('invalid CI identity and stale source fail before any Docker or registry operation', async () => {
    for (const change of [{ GITHUB_ACTIONS: '' }, { GITHUB_REPOSITORY: 'other/repo' },
        { GITHUB_EVENT_NAME: 'pull_request' }, { RUNNER_OS: 'Windows' }, { GITHUB_SHA: 'c'.repeat(40) }]) {
        const calls = [];
        await expect(buildUbuntuImage('unused.json', { environment: { ...environment, ...change },
            run(command, args) { calls.push(command); return { status: 0, stdout: args[0] === 'rev-parse' ? sha : '' }; },
            login() { throw new Error('registry must not be called'); } })).rejects.toThrow();
        expect(calls.every(command => command === 'git')).toBe(true);
    }
});

test('dirty source refuses to create an image', async () => {
    const calls = [];
    await expect(buildUbuntuImage('unused.json', { environment,
        run(command, args) { calls.push(command); return { status: 0, stdout: args[0] === 'rev-parse' ? sha : ' M source.rs' }; },
        login() { throw new Error('registry must not be called'); } })).rejects.toThrow('clean');
    expect(calls).toEqual(['git', 'git']);
});

test('every Dockerfile source stage must be immutable', () => {
    expect(() => pinnedDockerfile(`FROM ubuntu:24.04@sha256:${'a'.repeat(64)}\n`)).not.toThrow();
    for (const dockerfile of ['', 'FROM ubuntu:24.04\n',
        `FROM ubuntu@sha256:${'a'.repeat(64)} AS base\n  FROM node:latest\n`,
        `FROM ubuntu@sha256:${'a'.repeat(64)} AS base\nFROM node:latest\n`])
        expect(() => pinnedDockerfile(dockerfile)).toThrow('digest');
});

test('Node candidate identity allows its effective group only and refuses privilege leaks', () => {
    expect(candidateIdentityMatches(10001, 10001, [10001])).toBe(true);
    for (const [uid, gid, groups] of [[0, 10001, [10001]], [10001, 0, [0]],
        [10001, 10001, []], [10001, 10001, [0, 10001]], [10001, 10001, [10001, 10002]]])
        expect(candidateIdentityMatches(uid, gid, groups)).toBe(false);
});

for (const failedPhase of ['build', 'run']) test(`failed ${failedPhase} removes context and credentials without publishing`, async () => {
    let context, dockerConfig;
    const dockerCalls = [];
    let failure;
    try { await buildUbuntuImage('unused.json', { environment,
        async login(account, token, host, config) { dockerConfig = config; writeFileSync(path.join(config, 'config.json'), 'private fixture credentials'); },
        run(command, args, options) {
            if (command === 'git' && args[0] === 'rev-parse') return { status: 0, stdout: sha };
            if (command === 'git' && args[0] === 'status') return { status: 0, stdout: '' };
            if (command === 'git' && args[0] === 'archive') {
                writeFileSync(args.find(arg => arg.startsWith('--output=')).slice(9), 'committed archive fixture');
                return { status: 0, stdout: '' };
            }
            if (command === 'tar') {
                context = args.at(-1);
                for (const name of ['services/cloud-ci/runner/run.mjs', 'services/cloud-ci/verifier.mjs',
                    'scripts/rust-source-policy.mjs', 'scripts/prepare-node-test-fixture.py',
                    'scripts/build-comparison.py', 'scripts/test-debian-daemon-catalog.py']) {
                    mkdirSync(path.dirname(path.join(context, name)), { recursive: true });
                    writeFileSync(path.join(context, name), 'frozen fixture');
                }
                writeFileSync(path.join(context, 'services/cloud-ci/Dockerfile.ubuntu-pilot'), `FROM ubuntu@sha256:${'a'.repeat(64)}\n`);
                return { status: 0, stdout: '' };
            }
            if (command === 'docker') {
                dockerCalls.push(args[0]);
                expect(options.env.DOCKER_CONFIG).toBe(dockerConfig);
                expect(readFileSync(path.join(context, 'services/cloud-ci/Dockerfile.ubuntu-pilot'), 'utf8')).toContain('RUN --network=none');
                if (args[0] === 'run') {
                    const syntax = spawnSync('node', ['--input-type=module', '--check'], { input: args.at(-1), encoding: 'utf8' });
                    expect(syntax.status, syntax.stderr).toBe(0);
                }
                if (args[0] !== failedPhase) return { status: 0, stdout: '' };
                return { status: 1, stdout: '', stderr: 'controlled smoke failure\n' + 'x'.repeat(10_000) };
            }
            throw new Error('unexpected build operation');
        },
    }); } catch (error) { failure = error; }
    expect(failure?.message).toContain(`docker ${failedPhase} failed`);
    if (failedPhase === 'run') expect(failure?.message).toContain('controlled smoke failure');
    else expect(failure?.message).not.toContain('controlled smoke failure');
    expect(failure?.message.length).toBeLessThan(5000);
    expect(failure?.message).not.toContain(environment.CLOUDFLARE_API_TOKEN);
    expect(dockerCalls).toEqual(failedPhase === 'build' ? ['build'] : ['build', 'run']);
    expect(existsSync(context)).toBe(false);
    expect(existsSync(dockerConfig)).toBe(false);
});

test('both runner targets, verifier and native oracle scripts are frozen and actually checked', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'ubuntu-image-inputs-'));
    const installed = mkdtempSync(path.join(tmpdir(), 'ubuntu-image-installed-'));
    const sources = ['services/cloud-ci/runner/run.mjs', 'services/cloud-ci/verifier.mjs',
        'scripts/rust-source-policy.mjs', 'scripts/prepare-node-test-fixture.py',
        'scripts/build-comparison.py', 'scripts/test-debian-daemon-catalog.py'];
    try {
        for (const source of sources) {
            mkdirSync(path.dirname(path.join(root, source)), { recursive: true });
            writeFileSync(path.join(root, source), `fixture ${source}\n`);
        }
        const frozen = ubuntuFrozenInputs(root, sha);
        expect(frozen.files.map(file => file.source).sort()).toEqual(sources.sort());
        expect(frozen.files.find(file => file.source.endsWith('runner/run.mjs')).targets)
            .toEqual(['/opt/omg-ci/run.mjs', '/opt/omg-ci/runner/run.mjs']);
        for (const file of frozen.files) for (const target of file.targets) {
            mkdirSync(path.dirname(path.join(installed, target)), { recursive: true });
            writeFileSync(path.join(installed, target), readFileSync(path.join(root, file.source)));
        }
        const assertion = frozenAssertion(frozen, installed).script;
        expect(spawnSync(process.execPath, ['--input-type=module', '-e', assertion]).status).toBe(0);
        for (const source of sources) {
            const file = frozen.files.find(file => file.source === source);
            for (const target of file.targets) {
                writeFileSync(path.join(installed, target), 'controlled corruption');
                expect(spawnSync(process.execPath, ['--input-type=module', '-e', assertion], { stdio: 'pipe' }).status).toBe(1);
                writeFileSync(path.join(installed, target), readFileSync(path.join(root, source)));
            }
        }
    } finally {
        rmSync(root, { recursive: true, force: true });
        rmSync(installed, { recursive: true, force: true });
    }
});

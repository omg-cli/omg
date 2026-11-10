import { expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildUbuntuImage, ubuntuFrozenInputs, pinnedDockerfile } from '../../../scripts/build-cloud-ubuntu-image.mjs';
import { frozenAssertion } from './hosted-image-probe.mjs';

const sha = 'a'.repeat(40);
const environment = { GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'omg-cli/omg',
    GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_SHA: sha, RUNNER_OS: 'Linux',
    CLOUDFLARE_ACCOUNT_ID: 'b'.repeat(32), CLOUDFLARE_API_TOKEN: 'fixture-secret' };

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

test('a failed build removes archived context and isolated Docker credentials without publishing', async () => {
    let context, dockerConfig;
    const dockerCalls = [];
    await expect(buildUbuntuImage('unused.json', { environment,
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
                return { status: 1, stdout: '' };
            }
            throw new Error('unexpected build operation');
        },
    })).rejects.toThrow('docker build failed');
    expect(dockerCalls).toEqual(['build']);
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

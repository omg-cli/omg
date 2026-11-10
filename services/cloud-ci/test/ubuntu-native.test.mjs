import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runUbuntuNative, prepareUbuntuNative, validateUbuntuReport, ubuntuNativeTests } from '../runner/ubuntu-native.mjs';

const sha = 'a'.repeat(40);
const hash = 'b'.repeat(64);
function fixture() {
    const daemon = JSON.stringify({ accepted: true, source_sha: sha, native_candidate_count: 30000,
        native_candidate_sha256: hash, omg_sha256: hash, omgd_sha256: hash, info_requests_delta: 2,
        shutdown_returncode: 0, socket_absent_after_shutdown: true,
        native_state_unchanged: { '/var/lib/dpkg/status': hash },
        native_state_after_shutdown: { '/var/lib/dpkg/status': hash } });
    return { daemon, summary: { schemaVersion: 1, accepted: true, sourceSha: sha,
        platform: { id: 'ubuntu', version: '24.04', architecture: 'x86_64', uid: 10001, gid: 10001,
            pythonVersion: '3.12.3', aptPkgModule: '/usr/lib/python3/dist-packages/apt_pkg.so', nativeCandidateCount: 30000,
            compiler: 'rustc 1.95.0 (fixture)\nhost: x86_64-unknown-linux-gnu' },
        build: { profile: 'release', features: 'debian,pgp,license',
            argv: ['cargo', 'build', '--bins', '--release', '--no-default-features', '--features',
                'debian,pgp,license', '--locked', '--offline', '--message-format=json'],
            releaseProfile: { lto: 'fat', 'codegen-units': 1, 'opt-level': 3, panic: 'unwind', strip: true, incremental: false },
            environment: { CARGO_BUILD_JOBS: '4', CARGO_INCREMENTAL: '0', RUSTFLAGS: '', OMG_DISABLE_TELEMETRY: '1' },
            binaryHashes: { omg: hash, omgd: hash } },
        tests: ubuntuNativeTests.map(name => ({ name, passed: 1, failed: 0, ignored: 0 })),
        inventory: { nativeExplicitCount: 100, completeNamesEqual: true, nativeStateUnchanged: true,
            beforeSha256: hash, afterSha256: hash },
        daemonReceiptSha256: createHash('sha256').update(daemon).digest('hex') } };
}

test('Ubuntu receipt requires native identity, full inventory, real tests, and daemon behavior', () => {
    const { summary, daemon } = fixture();
    assert.equal(validateUbuntuReport(summary, daemon, sha), summary);
    for (const mutate of [s => s.platform.version = '22.04', s => s.platform.uid = 0,
        s => s.platform.nativeCandidateCount = 24999, s => s.tests[0].passed = 0,
        s => s.tests[0].name = 'other::test', s => s.inventory.afterSha256 = 'c'.repeat(64),
        s => s.build.profile = 'dev', s => s.build.environment.CARGO_PROFILE_RELEASE_LTO = 'off',
        s => s.build.binaryHashes.omgd = 'c'.repeat(64), s => s.sourceSha = 'c'.repeat(40)]) {
        const changed = structuredClone(summary);
        mutate(changed);
        assert.throws(() => validateUbuntuReport(changed, daemon, sha));
    }
});

test('daemon rejection, missing metrics, and failed shutdown cannot pass native admission', () => {
    for (const patch of [{ accepted: false }, { info_requests_delta: 0 }, { shutdown_returncode: 1 },
        { socket_absent_after_shutdown: false }, { native_state_after_shutdown: {} }]) {
        const { summary, daemon } = fixture();
        const changed = JSON.stringify({ ...JSON.parse(daemon), ...patch });
        summary.daemonReceiptSha256 = createHash('sha256').update(changed).digest('hex');
        assert.throws(() => validateUbuntuReport(summary, changed, sha));
    }
});

test('native execution uses the candidate boundary and rejects a successful zero-test command', async () => {
    for (const zeroTests of [false, true]) {
        const workspace = mkdtempSync(path.join(os.tmpdir(), 'omg-ubuntu-native-'));
        const context = { workspace };
        const reports = new Map();
        const { summary, daemon } = fixture();
        mkdirSync(path.join(workspace, 'target'));
        let daemonRan = false;
        const execute = async (portable, command, argv, env, options) => {
            assert.equal(portable, context);
            assert.equal(command, '/usr/bin/env');
            assert.deepEqual(argv.slice(0, 5), ['-u', 'CARGO_PROFILE_DEV_DEBUG', '-u', 'CARGO_PROFILE_TEST_DEBUG', 'OMG_DISABLE_TELEMETRY=1']);
            assert.ok(options.timeoutMs > 0);
            assert.equal(options.maxOutput, 8 * 1024 * 1024);
            const [child, ...args] = argv.slice(5);
            let stdout = '';
            if (child === '/usr/bin/mkdir') mkdirSync(args.at(-1));
            else if (child === '/usr/bin/python3' && args.includes('/scripts/test-debian-daemon-catalog.py')) {
                assert.equal(env.OMG_CONTRACT_SOURCE_SHA, sha);
                assert.equal(args[0], '-I');
                daemonRan = true;
                const directory = args[args.indexOf('--evidence-dir') + 1];
                mkdirSync(directory);
                const actual = { ...JSON.parse(daemon) };
                for (const name of ['omg', 'omgd']) actual[name + '_sha256'] = createHash('sha256').update(name).digest('hex');
                writeFileSync(path.join(directory, 'receipt.json'), JSON.stringify(actual));
            } else if (child === '/usr/bin/python3') {
                assert.equal(args[0], '-I');
                stdout = args.at(-1).includes('configuration=') ? JSON.stringify({ platform: summary.platform,
                    releaseProfile: summary.build.releaseProfile, environment: summary.build.environment, version: '0.1.2' }) :
                    JSON.stringify({ rows: ['bash\t1\tinstalled'], names: ['bash'], state: { '/var/lib/dpkg/status': hash } });
            } else if (child === 'cargo' && args[0] === 'build') {
                const directory = path.join(workspace, 'target/release');
                mkdirSync(directory);
                const records = ['omg', 'omgd'].map(name => {
                    writeFileSync(path.join(directory, name), name);
                    return { reason: 'compiler-artifact', target: { name }, executable: path.join(directory, name) };
                });
                stdout = [...records, { reason: 'build-finished', success: true }].map(JSON.stringify).join('\n');
            } else if (child === 'cargo' && args[0] === 'test') {
                assert.ok(args.includes('--release') && args.includes('--offline') && args.includes('--exact'));
                const name = args.find(value => ubuntuNativeTests.includes(value));
                stdout = zeroTests ? 'test result: ok. 0 passed; 0 failed; 0 ignored;' :
                    `test ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;`;
            } else if (args[0] === '--version') stdout = path.basename(child) + ' 0.1.2';
            else if (args[0] === '--help') stdout = 'Usage: ' + path.basename(child);
            else if (args[0] === '--json') stdout = JSON.stringify({ packages: ['bash'], count: 1 });
            return { stdout, stderr: '', exitCode: 0 };
        };
        try {
            await prepareUbuntuNative({ portable: context }, execute);
            const operation = runUbuntuNative({ sha, portable: context,
                report: (name, file) => reports.set(name, JSON.parse(readFileSync(file, 'utf8'))) }, execute);
            if (zeroTests) await assert.rejects(operation, /named test did not execute/);
            else assert.equal((await operation).accepted, true);
            assert.equal(reports.get('ubuntu-native.json').accepted, !zeroTests);
            assert.equal(daemonRan, !zeroTests);
            assert.equal(reports.has('ubuntu-daemon.json'), !zeroTests);
        } finally {
            rmSync(workspace, { recursive: true, force: true });
        }
    }
});

test('Ubuntu image preserves genuine native packages, frozen oracles, and existing toolchain pins', () => {
    const image = readFileSync(new URL('../Dockerfile.ubuntu-pilot', import.meta.url), 'utf8');
    assert.match(image, /FROM ubuntu:24\.04@sha256:[a-f0-9]{64}/);
    assert.match(image, /COPY --from=sandbox-runtime \/container-server\/sandbox \/container-server\/sandbox/);
    assert.match(image, /cloudflare\/sandbox:0\.12\.14@sha256:b8175e89/);
    assert.match(image, /node:24\.22\.1-bookworm-slim@sha256:/);
    assert.match(image, /rust:1\.95\.0-slim-bookworm@sha256:/);
    assert.match(image, /python3-apt/);
    assert.match(image, /libapt-pkg-dev/);
    assert.match(image, />= 25000/);
    assert.doesNotMatch(image, /rm[^\n]*\/var\/lib\/apt\/lists/);
    for (const file of ['build-comparison.py', 'test-debian-daemon-catalog.py'])
        assert.ok(image.includes(`COPY scripts/${file} /scripts/${file}`));
    assert.match(image, /ENTRYPOINT \["\/container-server\/sandbox"\]/);
});

test('Ubuntu image includes the pinned SDK server startup and backup runtime', () => {
    const image = readFileSync(new URL('../Dockerfile.ubuntu-pilot', import.meta.url), 'utf8');
    assert.match(image, /^EXPOSE 3000$/m);
    assert.match(image, /^ENV SANDBOX_VERSION=0\.12\.14$/m);
    for (const [name, count] of [['PYTHON', 0], ['JAVASCRIPT', 3], ['TYPESCRIPT', 3]])
        assert.ok(image.includes(`ENV ${name}_POOL_MIN_SIZE=${count}`));
    assert.match(image, /^WORKDIR \/container-server$/m);
    assert.match(image, /COPY --from=sandbox-runtime \/container-server\/dist\/runtime\/executors\/javascript\/node_executor\.js \/container-server\/dist\/runtime\/executors\/javascript\/node_executor\.js/);
    assert.match(image, /COPY --from=sandbox-runtime \/container-server\/dist\/index\.js \/container-server\/dist\/index\.js/);
    assert.match(image, /COPY --from=sandbox-runtime \/usr\/bin\/fuse-overlayfs \/usr\/bin\/fuse-overlayfs/);
    for (const command of ['s3fs', 'fuse3', 'squashfuse', 'squashfs-tools'])
        assert.match(image, new RegExp(`apt-get install[^\n]*\\b${command}\\b`));
    assert.ok(image.includes('ln -sf /proc/mounts /etc/mtab'));
    assert.ok(image.includes("sed -i 's/#user_allow_other/user_allow_other/' /etc/fuse.conf"));
});

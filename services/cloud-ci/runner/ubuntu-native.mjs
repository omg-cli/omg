import { createHash, randomUUID } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { runPortable } from './portable-process.mjs';
import { rustTimeouts } from './plan.mjs';

export const ubuntuNativeTests = [
    'package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages',
    'package_managers::debian_db::db::tests::installed_status_accepts_held_packages_but_not_partial_states',
];
const features = 'debian,pgp,license';
const flags = ['--release', '--no-default-features', '--features', features, '--locked', '--offline'];
const buildArgv = ['cargo', 'build', '--bins', ...flags, '--message-format=json'];
const hash = value => createHash('sha256').update(value).digest('hex');
const validHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const require = (condition, message) => { if (!condition) throw new Error(message); };
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

export function validateUbuntuReport(summary, daemonText, expectedSha) {
    const daemon = JSON.parse(daemonText);
    require(summary?.schemaVersion === 1 && summary.accepted === true &&
        /^[a-f0-9]{40}$/.test(expectedSha) && summary.sourceSha === expectedSha, 'Native source identity mismatch');
    const platform = summary.platform;
    require(platform?.id === 'ubuntu' && platform.version === '24.04' && platform.architecture === 'x86_64' &&
        platform.uid === 10001 && platform.gid === 10001 && /^3\.12\./.test(platform.pythonVersion) &&
        platform.aptPkgModule?.startsWith('/usr/lib/python3/dist-packages/') &&
        Number.isInteger(platform.nativeCandidateCount) && platform.nativeCandidateCount >= 25000 &&
        platform.compiler?.startsWith('rustc 1.95.0 ') && platform.compiler.includes('host: x86_64-unknown-linux-gnu'),
        'Native Ubuntu platform mismatch');
    const build = summary.build;
    require(build?.profile === 'release' && build.features === features && same(build.argv, buildArgv), 'Native release recipe mismatch');
    const release = build.releaseProfile;
    require(release?.lto === 'fat' && release['codegen-units'] === 1 && release['opt-level'] === 3 &&
        release.panic === 'unwind' && release.strip === true && release.incremental === false, 'Native release profile changed');
    require(build.environment?.CARGO_BUILD_JOBS === '4' && build.environment.CARGO_INCREMENTAL === '0' &&
        build.environment.RUSTFLAGS === '' && build.environment.OMG_DISABLE_TELEMETRY === '1' &&
        !Object.keys(build.environment).some(name => name.startsWith('CARGO_PROFILE_') ||
            ['OMG_TEST_MODE', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS'].includes(name)),
        'Native compiler environment changed');
    require(Object.keys(build.binaryHashes ?? {}).sort().join(',') === 'omg,omgd' &&
        Object.values(build.binaryHashes).every(validHash), 'Native binary hashes missing');
    require(summary.tests?.length === 2 && ubuntuNativeTests.every(name => summary.tests.filter(test =>
        test.name === name && test.passed === 1 && test.failed === 0 && test.ignored === 0).length === 1),
        'Native named tests did not execute');
    const inventory = summary.inventory;
    require(Number.isInteger(inventory?.nativeExplicitCount) && inventory.nativeExplicitCount > 0 &&
        inventory.completeNamesEqual === true && inventory.nativeStateUnchanged === true &&
        validHash(inventory.beforeSha256) && inventory.beforeSha256 === inventory.afterSha256, 'Native package state changed');
    require(summary.daemonReceiptSha256 === hash(daemonText) && daemon.accepted === true &&
        daemon.source_sha === expectedSha && daemon.native_candidate_count === platform.nativeCandidateCount &&
        validHash(daemon.native_candidate_sha256) && daemon.omg_sha256 === build.binaryHashes.omg &&
        daemon.omgd_sha256 === build.binaryHashes.omgd && daemon.info_requests_delta === 2 &&
        daemon.shutdown_returncode === 0 && daemon.socket_absent_after_shutdown === true &&
        validHash(daemon.native_state_unchanged?.['/var/lib/dpkg/status']) &&
        same(daemon.native_state_unchanged, daemon.native_state_after_shutdown), 'Native daemon proof failed');
    return summary;
}

function safeFile(file, workspace, maximum = 20_000_000) {
    const relative = path.relative(workspace, file);
    require(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'Native artifact escapes workspace');
    let current = workspace;
    require(lstatSync(current).isDirectory() && !lstatSync(current).isSymbolicLink(), 'Native workspace is not a directory');
    const parts = relative.split(path.sep);
    for (const [index, part] of parts.entries()) {
        current = path.join(current, part);
        const info = lstatSync(current);
        require(!info.isSymbolicLink() && (index === parts.length - 1 ? info.isFile() && info.size <= maximum : info.isDirectory()),
            'Native artifact is not a bounded regular file');
    }
    return readFileSync(file);
}

function safeDirectory(directory, workspace) {
    const relative = path.relative(workspace, directory);
    require(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'Native directory escapes workspace');
    let current = workspace;
    for (const part of [null, ...relative.split(path.sep)]) {
        if (part !== null) current = path.join(current, part);
        const info = lstatSync(current);
        require(info.isDirectory() && !info.isSymbolicLink(), 'Native evidence parent is not a real directory');
    }
}

function nativeRun(portable, onOutput, execute) {
    return (command, args, env = {}) => execute(portable, '/usr/bin/env', [
        '-u', 'CARGO_PROFILE_DEV_DEBUG', '-u', 'CARGO_PROFILE_TEST_DEBUG',
        'OMG_DISABLE_TELEMETRY=1', command, ...args,
    ], env, { timeoutMs: rustTimeouts.child, maxOutput: 8 * 1024 * 1024, onOutput });
}

export async function prepareUbuntuNative({ portable, onOutput = () => {} }, execute = runPortable) {
    return nativeRun(portable, onOutput, execute)('cargo', ['fetch', '--locked', '--target', 'x86_64-unknown-linux-gnu']);
}

const inventoryProgram = `import json,os,runpy
oracle=runpy.run_path('/scripts/build-comparison.py')
rows,names=oracle['native_inventory']('/workspace',os.environ)
state=runpy.run_path('/scripts/test-debian-daemon-catalog.py')['native_state']()
print(json.dumps({'rows':rows,'names':sorted(names),'state':state},sort_keys=True))`;

const platformProgram = `import apt_pkg,json,os,platform,subprocess,sys,tomllib
release=dict(line.rstrip().split('=',1) for line in open('/etc/os-release') if '=' in line)
apt_pkg.init()
cache=apt_pkg.Cache(None)
deps=apt_pkg.DepCache(cache)
count=sum(1 for package in cache.packages if deps.get_candidate_ver(package) or package.current_ver)
configuration=tomllib.load(open('Cargo.toml','rb'))
environment={name:value for name,value in os.environ.items() if name.startswith(('CARGO_PROFILE_','RUSTC')) or name in ('CARGO_BUILD_JOBS','CARGO_INCREMENTAL','OMG_TEST_MODE','OMG_DISABLE_TELEMETRY','CARGO_ENCODED_RUSTFLAGS')}
environment['RUSTFLAGS']=os.environ.get('RUSTFLAGS','')
print(json.dumps({'platform':{'id':release.get('ID','').strip('"'),'version':release.get('VERSION_ID','').strip('"'),'architecture':platform.machine(),'uid':os.getuid(),'gid':os.getgid(),'pythonVersion':platform.python_version(),'aptPkgModule':apt_pkg.__file__,'nativeCandidateCount':count,'compiler':subprocess.check_output(['rustc','-vV'],text=True)},'releaseProfile':configuration['profile']['release'],'environment':environment,'version':configuration['package']['version']}))`;

export async function runUbuntuNative({ sha, portable, report, onOutput = () => {} }, execute = runPortable) {
    require(/^[a-f0-9]{40}$/.test(sha), 'Invalid native source SHA');
    const run = nativeRun(portable, onOutput, execute);
    const directory = path.join(portable.workspace, 'target', 'cloud-ubuntu-native-' + randomUUID());
    await run('/usr/bin/mkdir', ['-m', '700', directory]);
    const daemonDirectory = path.join(directory, 'daemon');
    const summary = { schemaVersion: 1, accepted: false, sourceSha: sha, tests: [] };
    let daemonText;
    try {
        const observed = JSON.parse((await run('/usr/bin/python3', ['-I', '-c', platformProgram])).stdout);
        summary.platform = observed.platform;
        summary.build = { argv: buildArgv, profile: 'release', features, releaseProfile: observed.releaseProfile,
            environment: observed.environment };
        require(summary.platform.id === 'ubuntu' && summary.platform.version === '24.04' &&
            summary.platform.uid === 10001 && summary.platform.gid === 10001 &&
            summary.platform.nativeCandidateCount >= 25000, 'Native Ubuntu prerequisites failed');
        const before = JSON.parse((await run('/usr/bin/python3', ['-I', '-c', inventoryProgram])).stdout);
        const built = await run('cargo', buildArgv.slice(1));
        const records = built.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
        require(records.at(-1)?.reason === 'build-finished' && records.at(-1)?.success === true, 'Native build did not finish');
        const artifacts = new Map(records.filter(row => row.reason === 'compiler-artifact' && row.executable &&
            ['omg', 'omgd'].includes(row.target.name)).map(row => [row.target.name, row]));
        summary.build.binaryHashes = {};
        for (const name of ['omg', 'omgd']) {
            const file = path.join(portable.workspace, 'target', 'release', name);
            require(artifacts.get(name)?.executable === file, 'Native release binary missing');
            summary.build.binaryHashes[name] = hash(safeFile(file, portable.workspace, 256 * 1024 * 1024));
            require((await run(file, ['--version'])).stdout.trim() === name + ' ' + observed.version, 'Native binary version mismatch');
            require((await run(file, ['--help'])).stdout.includes('Usage:'), 'Native binary help failed');
        }
        for (const name of ubuntuNativeTests) {
            const result = await run('cargo', ['test', '--lib', ...flags, name, '--', '--exact', '--nocapture', '--test-threads=1']);
            require(result.stdout.split('\n').some(line => line.trim() === 'test ' + name + ' ... ok') &&
                /^test result: ok\. 1 passed; 0 failed; 0 ignored;/m.test(result.stdout), 'Native named test did not execute');
            summary.tests.push({ name, passed: 1, failed: 0, ignored: 0 });
        }
        const inventory = JSON.parse((await run(path.join(portable.workspace, 'target/release/omg'), ['--json', 'explicit'])).stdout);
        require(Array.isArray(inventory.packages) && before.names.length > 0 &&
            inventory.count === inventory.packages.length && new Set(inventory.packages).size === inventory.count &&
            same([...inventory.packages].sort(), before.names), 'Complete native inventory differs');
        try {
            await run('/usr/bin/python3', ['-I', '/scripts/test-debian-daemon-catalog.py',
                '--omg-binary', path.join(portable.workspace, 'target/release/omg'),
                '--omgd-binary', path.join(portable.workspace, 'target/release/omgd'), '--evidence-dir', daemonDirectory],
                { OMG_CONTRACT_SOURCE_SHA: sha });
        } finally {
            const daemonFile = path.join(daemonDirectory, 'receipt.json');
            if (existsSync(daemonFile)) {
                daemonText = safeFile(daemonFile, portable.workspace).toString('utf8');
                report('ubuntu-daemon.json', daemonFile);
            }
            const log = path.join(daemonDirectory, 'daemon.log');
            if (existsSync(log)) onOutput('stderr', Buffer.from('OMG_UBUNTU_DAEMON_LOG=' +
                JSON.stringify(safeFile(log, portable.workspace).subarray(-65536).toString('utf8')) + '\n'));
        }
        const after = JSON.parse((await run('/usr/bin/python3', ['-I', '-c', inventoryProgram])).stdout);
        require(same(before, after), 'Native package state changed');
        summary.inventory = { nativeExplicitCount: before.names.length, completeNamesEqual: true,
            nativeStateUnchanged: true, beforeSha256: hash(JSON.stringify(before)), afterSha256: hash(JSON.stringify(after)) };
        summary.daemonReceiptSha256 = hash(daemonText ?? '');
        summary.accepted = true;
        validateUbuntuReport(summary, daemonText, sha);
    } catch (error) {
        summary.accepted = false;
        summary.error = String(error).slice(0, 2000);
        throw error;
    } finally {
        safeDirectory(directory, portable.workspace);
        const file = path.join(directory, 'receipt.json');
        writeFileSync(file, JSON.stringify(summary) + '\n', { flag: 'wx', mode: 0o444 });
        report('ubuntu-native.json', file);
    }
    return summary;
}

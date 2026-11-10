#!/usr/bin/env python3
"""Measure one compilation-cold and three unchanged warm Ubuntu Rust workloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import statistics
import subprocess
import sys
import tarfile
import time
import tomllib

FEATURES = 'debian,pgp,license'
TESTS = (
    'package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages',
    'package_managers::debian_db::db::tests::installed_status_accepts_held_packages_but_not_partial_states',
)
FLAGS = ['--release', '--no-default-features', '--features', FEATURES, '--locked', '--offline']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def manifest(source):
    files = {}
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source)
        if relative.parts[0] == 'target':
            continue
        require(not path.is_symlink(), 'source contains a symlink')
        if path.is_file():
            files[relative.as_posix()] = digest(path)
    return files


def manifest_digest(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def prepare(archive, source, evidence, source_sha):
    require(re.fullmatch('[a-f0-9]{40}', source_sha), 'source SHA must be a full commit ID')
    require(not source.exists() and not source.is_symlink(), 'source destination already exists')
    evidence.mkdir(parents=True, exist_ok=False)
    source.mkdir()
    with tarfile.open(archive, 'r:*') as incoming:
        members = incoming.getmembers()
        require(len(members) <= 100000 and sum(m.size for m in members) <= 1024**3, 'oversized source archive')
        seen = set()
        for member in members:
            name = PurePosixPath(member.name)
            require(name.parts and not name.is_absolute() and '..' not in name.parts and
                    '.git' not in name.parts and name.parts[0] != 'target' and '\\' not in member.name and
                    member.name not in seen and (member.isdir() or member.isfile()), 'unsafe source archive entry')
            seen.add(member.name)
            target = source.joinpath(*name.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with incoming.extractfile(member) as stream, target.open('xb') as output:
                    while block := stream.read(1024 * 1024):
                        output.write(block)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
    files = manifest(source)
    require(all(name in files for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml')),
            'archive lacks required Rust inputs')
    identity = {'sourceSha': source_sha, 'archiveSha256': digest(archive), 'files': files,
                'sourceManifestSha256': manifest_digest(files)}
    write_json(evidence / 'prepared.json', identity)
    write_json(evidence / 'receipt.json', {'status': 'prepared', 'sourceSha': source_sha})
    return identity


def build_environment(original):
    environment = {key: value for key, value in original.items()
        if not (key.startswith(('CARGO_', 'RUSTC', 'SCCACHE_', 'CMAKE_', 'OPENSSL_')) or
                key in ('RUSTFLAGS', 'RUSTDOCFLAGS', 'CC', 'CXX', 'AR', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'OMG_TEST_MODE'))}
    if original.get('CARGO_HOME'):
        environment['CARGO_HOME'] = original['CARGO_HOME']
    environment.update(CARGO_BUILD_JOBS='4', CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true',
                       CARGO_TERM_COLOR='never', RUSTFLAGS='', RUSTUP_TOOLCHAIN='1.95.0', NO_COLOR='1')
    return environment


def system_information(source, evidence, environment):
    require(sys.platform == 'linux' and hasattr(os, 'wait4'), 'measurement requires Linux wait4')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04',
            'measurement requires Ubuntu 24.04')
    cargo_home = Path(environment.get('CARGO_HOME', str(Path.home() / '.cargo')))
    require(not any((cargo_home / name).exists() for name in ('config', 'config.toml')), 'foreign Cargo home configuration')
    def output(argv):
        return subprocess.check_output(argv, cwd=source, env=environment, text=True, timeout=60).strip()
    compiler = output(['rustc', '-vV'])
    require(compiler.startswith('rustc 1.95.0 ') and 'host: x86_64-unknown-linux-gnu' in compiler.splitlines(),
            'unexpected Rust compiler')
    packages = output(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
    (evidence / 'packages.txt').write_text(packages + '\n', encoding='utf-8')
    cpu = Path('/proc/cpuinfo').read_text()
    (evidence / 'cpuinfo.txt').write_text(cpu, encoding='utf-8')
    return {'osRelease': release, 'kernel': output(['uname', '-a']), 'compiler': compiler,
            'cargo': output(['cargo', '--version']), 'gcc': output(['gcc', '--version']),
            'cpuCount': os.cpu_count(), 'memoryBefore': Path('/proc/meminfo').read_text(),
            'packageInventorySha256': digest(evidence / 'packages.txt'),
            'environment': {name: environment[name] for name in
                ('CARGO_BUILD_JOBS', 'CARGO_INCREMENTAL', 'CARGO_NET_OFFLINE', 'RUSTFLAGS', 'RUSTUP_TOOLCHAIN')}}


def memory_snapshot():
    return {name: Path('/proc/' + name).read_text() for name in ('meminfo', 'vmstat', 'pressure/memory')
            if Path('/proc/' + name).is_file()}


def measure(argv, source, evidence, label, environment, timeout=5400):
    stdout, stderr = evidence / (label + '.stdout'), evidence / (label + '.stderr')
    before = memory_snapshot()
    started, timed_out = time.monotonic(), False
    with stdout.open('wb') as out, stderr.open('wb') as err:
        process = subprocess.Popen(argv, cwd=source, env=environment, stdout=out, stderr=err, start_new_session=True)
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic() - started >= timeout:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(0.05)
        finally:
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                _, status, _ = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
    return {'label': label, 'argv': argv, 'wallSeconds': time.monotonic() - started,
            'userSeconds': usage.ru_utime, 'systemSeconds': usage.ru_stime,
            'maximumProcessRssKiB': usage.ru_maxrss, 'exitCode': process.returncode, 'timedOut': timed_out,
            'stdoutSha256': digest(stdout), 'stderrSha256': digest(stderr),
            'memoryBefore': before, 'memoryAfter': memory_snapshot()}


def verify_test(text, name):
    require(re.search(r'(?m)^test ' + re.escape(name) + r' \.\.\. ok\s*$', text) and
            re.search(r'(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored;', text),
            'named test did not execute exactly once: ' + name)


def verify_build(text, source, cold):
    messages = [json.loads(line) for line in text.splitlines() if line.strip()]
    require(messages and messages[-1].get('reason') == 'build-finished' and
            messages[-1].get('success') is True, 'Cargo did not finish successfully')
    artifacts = {row['target']['name']: row for row in messages if row.get('reason') == 'compiler-artifact'
                 and row.get('executable') and row['target']['name'] in ('omg', 'omgd')}
    require(set(artifacts) == {'omg', 'omgd'}, 'both release binaries must be built')
    for name, item in artifacts.items():
        binary = source / 'target/release' / name
        require(binary.is_file() and not binary.is_symlink() and item['executable'] == str(binary) and
                (not cold or item.get('fresh') is False), 'missing or stale cold binary: ' + name)
    return {name: digest(source / 'target/release' / name) for name in artifacts}


def native_inventory(source, environment):
    def output(argv):
        return subprocess.check_output(argv, cwd=source, env=environment, text=True, timeout=90)
    rows = sorted(output(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${db:Status-Status}\n']).splitlines())
    installed = {row.split('\t')[0] for row in rows if row.endswith('\tinstalled')}
    manual = set(output(['apt-mark', 'showmanual']).splitlines())
    return rows, installed & manual


def run_wave(source, evidence, source_sha):
    receipt_path = evidence / 'receipt.json'
    previous = json.loads(receipt_path.read_text(encoding='utf-8')) if receipt_path.is_file() else {}
    receipt = {'schemaVersion': 1, 'status': 'running', 'sourceSha': source_sha, 'samples': [],
               'profile': 'release', 'features': FEATURES, 'jobs': 4, 'scriptSha256': digest(__file__),
               'rssMeaning': 'wait4 maximum process RSS in KiB; not simultaneous whole-build memory',
               'coldMeaning': 'empty target with prefetched dependencies; OS page cache retained',
               'warmMeaning': 'unchanged source and target; Cargo builds can be near no-ops'}
    write_json(receipt_path, receipt)
    try:
        require(previous.get('status') == 'prepared', 'comparison must start from a fresh prepared source')
        identity = json.loads((evidence / 'prepared.json').read_text(encoding='utf-8'))
        require(identity['sourceSha'] == source_sha and manifest(source) == identity['files'], 'source identity mismatch')
        require(not (source / 'target').exists(), 'cold sample already has compiled artifacts')
        receipt.update({key: identity[key] for key in ('archiveSha256', 'sourceManifestSha256')})
        configuration = tomllib.loads((source / 'Cargo.toml').read_text(encoding='utf-8'))
        receipt['releaseProfile'] = configuration['profile']['release']
        receipt['cargoConfiguration'] = (source / '.cargo/config.toml').read_text(encoding='utf-8')
        environment = build_environment(os.environ)
        receipt['system'] = system_information(source, evidence, environment)
        write_json(receipt_path, receipt)
        def phase(argv, label, kind, sample):
            row = measure(argv, source, evidence, label, environment)
            row.update(kind=kind, sample=sample, cacheState='cold' if sample == 0 else 'warm')
            receipt['samples'].append(row)
            write_json(receipt_path, receipt)
            require(row['exitCode'] == 0 and not row['timedOut'], label + ' failed')
            return (evidence / (label + '.stdout')).read_text(encoding='utf-8')
        binary_hashes = None
        for sample in range(4):
            label = 'build-' + str(sample)
            text = phase(['cargo', 'build', '--bins', '--timings', *FLAGS, '--message-format=json'], label, 'build', sample)
            hashes = verify_build(text, source, sample == 0)
            require(binary_hashes is None or binary_hashes == hashes, 'unchanged warm build changed binaries')
            binary_hashes = hashes
            timing = source / 'target/cargo-timings/cargo-timing.html'
            if timing.is_file():
                (evidence / (label + '-timing.html')).write_bytes(timing.read_bytes())
        receipt['binaryHashes'] = binary_hashes
        receipt['tests'] = []
        for sample in range(4):
            for index, name in enumerate(TESTS):
                label = 'test-' + str(sample) + '-' + str(index)
                text = phase(['cargo', 'test', '--lib', *FLAGS, name, '--', '--exact', '--nocapture', '--test-threads=1'],
                             label, 'test-' + str(index), sample)
                verify_test(text, name)
                receipt['tests'].append({'name': name, 'sample': sample, 'passed': 1, 'failed': 0, 'ignored': 0})
        receipt['binaryExecution'] = []
        version = configuration['package']['version']
        for name in ('omg', 'omgd'):
            binary = source / 'target/release' / name
            for option in ('--version', '--help'):
                text = phase([str(binary), option], name + option, 'correctness', 0)
                require(text.strip() == name + ' ' + version if option == '--version' else
                        'Usage:' in text and name in text, 'binary CLI correctness failed')
            receipt['binaryExecution'].append({'binary': name, 'version': name + ' ' + version,
                                               'versionExit': 0, 'helpExit': 0})
        before, expected = native_inventory(source, environment)
        text = phase([str(source / 'target/release/omg'), '--json', 'explicit'], 'native-inventory', 'correctness', 0)
        inventory = json.loads(text)
        names = inventory.get('packages')
        require(expected and isinstance(names, list) and all(isinstance(name, str) and name for name in names) and
                len(names) == len(set(names)) == inventory.get('count') and set(names) == expected,
                'native explicit package inventory differs')
        after, expected_after = native_inventory(source, environment)
        require(before == after and expected == expected_after, 'native installed package state changed')
        receipt['inventoryProof'] = {'nativeExplicitCount': len(expected), 'completeNamesEqual': True,
            'nativeStateUnchanged': True, 'installedInventorySha256': hashlib.sha256('\n'.join(after).encode()).hexdigest()}
        require(manifest(source) == identity['files'], 'source changed during measurement')
        receipt['summary'] = {}
        for kind in ('build', 'test-0', 'test-1'):
            rows = [row for row in receipt['samples'] if row['kind'] == kind]
            warm = [row['wallSeconds'] for row in rows if row['sample'] > 0]
            receipt['summary'][kind] = {'coldSeconds': rows[0]['wallSeconds'], 'coldN': 1,
                'warmMedianSeconds': statistics.median(warm), 'warmN': len(warm), 'warmSeconds': warm}
        receipt['testColdMeaning'] = 'first libtest compile after release builds; second named test reuses it'
        receipt['status'] = 'complete'
    except Exception as error:
        receipt.update(status='failed', error=str(error))
        raise
    finally:
        write_json(receipt_path, receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'run'))
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            require(args.archive is not None, 'prepare requires an archive')
            prepare(args.archive.resolve(), args.source.resolve(), args.evidence.resolve(), args.source_sha)
        else:
            run_wave(args.source.resolve(), args.evidence.resolve(), args.source_sha)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Comparison failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

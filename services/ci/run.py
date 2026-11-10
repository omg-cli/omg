#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import selectors
import signal
import stat
import subprocess
import sys
import time
import tomllib

WORK = Path('/work')
SOURCE = WORK / 'source'
REPORTS = WORK / 'reports'
ORACLE = Path('/opt/ci/build-comparison.py')
DAEMON = Path('/opt/ci/test-debian-daemon-catalog.py')
ARTIFACTS = Path('/opt/ci/artifacts')
CARGO = Path('/opt/ci/Cargo.toml')
LIMIT = 8 * 1024 * 1024
BINARY_LIMIT = 256 * 1024 * 1024
FEATURES = 'debian,pgp,license'
FLAGS = ['--release', '--no-default-features', '--features', FEATURES, '--locked', '--offline']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def candidate_environment():
    return dict(PATH='/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin', HOME='/work/home',
        TMPDIR='/work/home/tmp', CARGO_HOME='/work/cargo', CARGO_TARGET_DIR='/work/target',
        RUSTUP_HOME='/usr/local/rustup', CARGO_BUILD_JOBS='4', CARGO_INCREMENTAL='0', RUSTFLAGS='',
        NO_COLOR='1', CARGO_TERM_COLOR='never', OMG_DISABLE_TELEMETRY='1', PYTHONDONTWRITEBYTECODE='1',
        GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
        GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='safe.directory', GIT_CONFIG_VALUE_0='/work/source')


def verify_selected_test(stdout, name, exit_code):
    require(exit_code == 0, 'selected test command failed')
    runpy.run_path(str(ORACLE))['verify_test'](stdout, name)


def selected_tests(command, names, libtest=None):
    rows = []
    for index, name in enumerate(names):
        argv = ([str(libtest), name] if libtest is not None else
                ['cargo', 'test', '--lib', *FLAGS, name, '--'])
        text = command([*argv, '--exact', '--nocapture', '--test-threads=1'], f'test-{index}')
        verify_selected_test(text, name, 0)
        rows.append({'name': name, 'passed': 1, 'failed': 0, 'ignored': 0, 'stdout': text})
    return rows


def select_libtest(text):
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    require([row.get('success') for row in rows if row.get('reason') == 'build-finished'] == [True],
            'libtest compilation did not finish successfully')
    selected = [row for row in rows if row.get('reason') == 'compiler-artifact'
                and row.get('target', {}).get('name') == 'omg_lib' and row.get('executable')]
    require(len(selected) == 1, 'expected exactly one owning libtest executable')
    row = selected[0]
    path = Path(row['executable'])
    require(row.get('manifest_path') == str(SOURCE / 'Cargo.toml') and
            row.get('target', {}).get('kind') == ['lib'] and row.get('profile', {}).get('test') is True and
            row.get('profile', {}).get('opt_level') == '3' and
            set(FEATURES.split(',')) <= set(row.get('features', [])) and
            not {'arch', 'fedora', 'macos', 'debian-pure'} & set(row.get('features', [])) and
            path.parent == WORK / 'target/release/deps' and path.name.startswith('omg_lib-'),
            'foreign libtest source, recipe or path')
    return path


def validate_baked(sha, cargo, manifest, build_receipt, files, manifest_bytes):
    document = tomllib.loads(cargo.decode('utf-8'))
    require(manifest.get('schemaVersion') == 1 and manifest.get('sourceSha') == sha and
            manifest.get('features') == FEATURES and manifest.get('profile') == 'release' and
            manifest.get('version') == document['package']['version'] and
            manifest.get('releaseProfile') == document['profile']['release'] and
            manifest.get('cargoTomlSha256') == digest(cargo), 'baked source or release recipe mismatch')
    compiler = manifest.get('compiler')
    require(isinstance(compiler, str) and compiler.startswith('rustc 1.95.0 ') and
            'host: x86_64-unknown-linux-gnu' in compiler.splitlines(), 'baked compiler identity mismatch')
    require(set(files) == set(manifest.get('files', {})) == {'omg', 'omgd', 'libtest'},
            'baked executable set mismatch')
    for name, content in files.items():
        expected = manifest['files'][name]
        require(type(expected.get('bytes')) is int and 0 < expected['bytes'] == len(content) <= BINARY_LIMIT and
                expected.get('sha256') == digest(content), 'baked executable digest mismatch: ' + name)
    require(build_receipt.get('accepted') is True and build_receipt.get('candidateProcessesStopped') is True and
            build_receipt.get('sourceSha') == sha and build_receipt.get('runtimeOnly') is False and
            build_receipt.get('buildExecutor') == 'github-actions-image-build' and
            build_receipt.get('artifactManifestSha256') == digest(manifest_bytes) and
            build_receipt.get('libtestSha256') == manifest['files']['libtest']['sha256'] and
            build_receipt.get('binaryHashes') == {name: manifest['files'][name]['sha256'] for name in ('omg', 'omgd')},
            'baked build did not complete with matching artifacts and cleanup')
    return manifest


def immutable_bytes(file, limit=LIMIT):
    require(file.is_relative_to(CARGO.parent), 'baked input escapes controller directory')
    for item in [file, *list(file.parents)[:len(file.relative_to(CARGO.parent).parts)]]:
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'baked input is redirected or candidate-writable')
    info = file.stat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o222 and 0 < info.st_size <= limit,
            'baked input is not an immutable bounded regular file')
    if file.name in ('omg', 'omgd', 'libtest'):
        require(info.st_mode & 0o111, 'baked executable is not executable')
    return file.read_bytes()


def load_baked(sha):
    manifest_bytes = immutable_bytes(ARTIFACTS / 'manifest.json')
    receipt_bytes = immutable_bytes(ARTIFACTS / 'build-receipt.json')
    manifest = validate_baked(sha, immutable_bytes(CARGO), json.loads(manifest_bytes), json.loads(receipt_bytes),
        {name: immutable_bytes(ARTIFACTS / name, BINARY_LIMIT) for name in ('omg', 'omgd', 'libtest')}, manifest_bytes)
    return manifest, digest(manifest_bytes), digest(receipt_bytes)


def publish_artifacts(receipt, libtest, cargo):
    require(receipt.get('accepted') is True and receipt.get('candidateProcessesStopped') is True,
            'cannot publish an unsuccessful or unclean build')
    manifest = {key: receipt[key] for key in ('sourceSha', 'features', 'profile', 'version', 'compiler', 'releaseProfile')}
    manifest.update(schemaVersion=1, cargoTomlSha256=digest(cargo), files={})
    contents = {name: artifact(WORK / 'target/release' / name, BINARY_LIMIT) for name in ('omg', 'omgd')}
    contents['libtest'] = artifact(libtest, BINARY_LIMIT)
    for name, content in contents.items():
        require(content and (name == 'libtest' or digest(content) == receipt['binaryHashes'][name]),
                'completed build executable changed')
        manifest['files'][name] = {'sha256': digest(content), 'bytes': len(content)}
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    receipt.update(artifactManifestSha256=digest(manifest_bytes), libtestSha256=digest(contents['libtest']))
    validate_baked(receipt['sourceSha'], cargo, manifest, receipt, contents, manifest_bytes)
    ARTIFACTS.mkdir(mode=0o755, exist_ok=False)
    for name, content in dict(contents, **{'manifest.json': manifest_bytes,
            'build-receipt.json': json.dumps(receipt).encode()}).items():
        path = ARTIFACTS / name
        with path.open('xb') as output:
            output.write(content)
        path.chmod(0o555 if name in contents else 0o444)
    ARTIFACTS.chmod(0o555)


def candidate_pids():
    pids = []
    for status in Path('/proc').glob('[0-9]*/status'):
        try:
            text = status.read_text()
            if re.search(r'^Uid:\s+10001\s', text, re.M) and not re.search(r'^State:\s+Z', text, re.M):
                pids.append(int(status.parent.name))
        except ProcessLookupError:
            continue
        except FileNotFoundError:
            continue
    return pids


def kill_candidates():
    for pid in candidate_pids():
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
    deadline = time.monotonic() + 5
    while candidate_pids() and time.monotonic() < deadline:
        time.sleep(0.05)
    require(not candidate_pids(), 'candidate processes did not stop')


def artifact(file, limit=LIMIT):
    require(file.is_relative_to(WORK), 'artifact escapes owned work')
    for item in [file, *list(file.parents)[:len(file.relative_to(WORK).parts)]]:
        require(not item.is_symlink(), 'artifact contains a symlink')
    require(file.is_file() and file.stat().st_size <= limit, 'artifact is not a bounded regular file')
    return file.read_bytes()


def main(sha, build=False):
    receipt = {'schemaVersion': 1, 'accepted': False, 'sourceSha': sha, 'commands': [], 'tests': [],
        'runtimeOnly': not build, 'buildExecutor': 'github-actions-image-build', 'buildSourceSha': sha}
    libtest = None
    environment, child, ready = candidate_environment(), None, False
    deadline = time.monotonic() + 2390
    def interrupt(number, frame):
        raise TimeoutError('job deadline or termination signal')
    def command(argv, label, candidate=True):
        nonlocal child
        remaining = min(1200, deadline - time.monotonic())
        require(remaining > 0, 'job deadline exceeded')
        wrapped = ['/usr/bin/setpriv', '--reuid=10001', '--regid=10001', '--clear-groups',
            '--no-new-privs', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all', '--', *argv] if candidate else argv
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        started = time.monotonic()
        print(json.dumps({'event': 'phase-start', 'phase': label}), flush=True)
        child = subprocess.Popen(wrapped, cwd=SOURCE, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            with selectors.DefaultSelector() as streams:
                for name in output:
                    streams.register(getattr(child, name), selectors.EVENT_READ, name)
                while streams.get_map():
                    require(time.monotonic() - started < remaining, label + ' timed out')
                    for key, _ in streams.select(0.1):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            streams.unregister(key.fileobj)
                        else:
                            require(sum(map(len, output.values())) + len(block) <= LIMIT, label + ' exceeded output budget')
                            output[key.data].extend(block)
            code = child.wait(timeout=max(0.1, remaining - (time.monotonic() - started)))
        finally:
            original_error, cleanup_error = sys.exc_info()[1], None
            try:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                kill_candidates()
                child.wait(timeout=5)
            except Exception as error:
                cleanup_error = error
                receipt['cleanupError'] = str(error)[:500]
            for name in output:
                getattr(child, name).close()
            row = {'label': label, 'argv': argv, 'exitCode': child.returncode, 'seconds': time.monotonic() - started}
            for name, content in output.items():
                (REPORTS / f'{label}.{name}').write_bytes(content)
                row[name + 'Sha256'] = digest(content)
                print(json.dumps({'event': 'phase-log', 'phase': label, 'stream': name,
                    'content': content.decode('utf-8', errors='replace')}), flush=True)
            receipt['commands'].append(row)
            print(json.dumps({'event': 'phase-end', **row}), flush=True)
            child = None
            if cleanup_error is not None:
                if original_error is not None:
                    original_error.add_note('Candidate cleanup also failed: ' + str(cleanup_error)[:500])
                else:
                    raise cleanup_error
        require(code == 0, label + ' exited ' + str(code))
        return output['stdout'].decode('utf-8')
    try:
        require(sys.platform == 'linux' and os.getuid() == 0, 'controller requires Linux root')
        require(re.fullmatch('[a-f0-9]{40}', sha), 'source must be a full commit SHA')
        WORK.mkdir(exist_ok=False)
        REPORTS.mkdir(mode=0o700)
        ready = True
        SOURCE.mkdir()
        for name in (('home', 'home/tmp', 'cargo', 'target') if build else ('home', 'home/tmp')):
            directory = WORK / name
            directory.mkdir(exist_ok=True)
            os.chown(directory, 10001, 10001)
            directory.chmod(0o700)
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            signal.signal(number, interrupt)
        signal.setitimer(signal.ITIMER_REAL, 2390)
        if build:
            command(['git', 'init', '-q'], 'git-init', False)
            command(['git', 'fetch', '--depth=1', 'https://github.com/omg-cli/omg.git', sha], 'git-fetch', False)
            command(['git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--detach', 'FETCH_HEAD'], 'git-checkout', False)
            require(command(['git', 'rev-parse', 'HEAD'], 'source-identity', False).strip() == sha, 'checkout identity mismatch')
            require((SOURCE / 'Cargo.toml').read_bytes() == CARGO.read_bytes(), 'frozen Cargo manifest differs from source')
            for root, directories, files in os.walk(SOURCE, followlinks=False):
                for name in files:
                    file = Path(root) / name
                    if not file.is_symlink():
                        file.chmod(0o555 if file.stat().st_mode & 0o111 else 0o444)
                Path(root).chmod(0o555)
        boundary = json.loads(command(['/usr/bin/python3', '-I', '-c',
            "import json,os,pathlib; print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'status':pathlib.Path('/proc/self/status').read_text(),'controllerWritable':os.access('/opt/ci/run.py',os.W_OK)}))"], 'candidate-boundary'))
        require(boundary['uid'] == boundary['gid'] == 10001 and not boundary['controllerWritable'] and
            re.search(r'^CapEff:\s+0+$', boundary['status'], re.M) and
            re.search(r'^NoNewPrivs:\s+1$', boundary['status'], re.M), 'candidate privilege boundary failed')
        receipt['candidate'] = {'uid': 10001, 'gid': 10001, 'capabilities': '0', 'noNewPrivileges': True, 'controllerWritable': False}
        receipt['platform'] = {key: value.strip('"') for key, value in
            (line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)}
        receipt['platform']['architecture'] = os.uname().machine
        require(receipt['platform'].get('ID') == 'ubuntu' and receipt['platform'].get('VERSION_ID') == '24.04' and
            receipt['platform']['architecture'] == 'x86_64', 'wrong native distro')
        cargo = (SOURCE / 'Cargo.toml').read_bytes() if build else immutable_bytes(CARGO)
        document = tomllib.loads(cargo.decode('utf-8'))
        if build:
            receipt['compiler'] = command(['rustc', '-vV'], 'compiler')
            require(receipt['compiler'].startswith('rustc 1.95.0 ') and 'host: x86_64-unknown-linux-gnu' in receipt['compiler'], 'wrong Rust compiler')
        else:
            manifest, manifest_digest, build_receipt_digest = load_baked(sha)
            receipt.update(compiler=manifest['compiler'], artifactManifestSha256=manifest_digest,
                libtestSha256=manifest['files']['libtest']['sha256'],
                buildMetadata={'manifest': manifest, 'buildReceiptSha256': build_receipt_digest})
        receipt.update(profile='release', features=FEATURES, environment=environment,
            releaseProfile=document['profile']['release'], version=document['package']['version'],
            oracleHashes={file.name: digest(file.read_bytes()) for file in (Path(__file__), ORACLE, DAEMON)})
        inventory_command = ['/usr/bin/python3', '-I', '-c',
            "import json,os,runpy; rows,names=runpy.run_path('/opt/ci/build-comparison.py')['native_inventory']('/work/source',os.environ); print(json.dumps({'rows':rows,'names':sorted(names)}))"]
        before = json.loads(command(inventory_command, 'inventory-before'))
        oracle = runpy.run_path(str(ORACLE))
        if build:
            command(['cargo', 'fetch', '--locked', '--target', 'x86_64-unknown-linux-gnu'], 'dependencies')
            built = command(['cargo', 'build', '--bins', *FLAGS, '--message-format=json'], 'release-build')
            require((WORK / 'target/release').is_dir() and not (WORK / 'target/release').is_symlink(), 'release directory is invalid')
            receipt['binaryHashes'] = oracle['verify_build'](built, WORK, True)
        else:
            receipt['binaryHashes'] = {name: manifest['files'][name]['sha256'] for name in ('omg', 'omgd')}
        binaries = {name: (WORK / 'target/release' if build else ARTIFACTS) / name for name in ('omg', 'omgd')}
        version = document['package']['version']
        for name in ('omg', 'omgd'):
            binary = str(binaries[name])
            require(command([binary, '--version'], name + '-version').strip() == name + ' ' + version, 'binary version mismatch')
            require('Usage:' in command([binary, '--help'], name + '-help'), 'binary help failed')
        receipt['tests'] = selected_tests(command, oracle['TESTS'], None if build else ARTIFACTS / 'libtest')
        actual = json.loads(command([str(binaries['omg']), '--json', 'explicit'], 'native-inventory'))
        names = actual.get('packages')
        require(before['names'] and isinstance(names, list) and all(isinstance(name, str) for name in names) and
            len(names) == len(set(names)) == actual.get('count') and sorted(names) == before['names'], 'complete native inventory mismatch')
        environment['OMG_CONTRACT_SOURCE_SHA'] = sha
        command(['/usr/bin/python3', '-I', str(DAEMON), '--omg-binary', str(binaries['omg']),
            '--omgd-binary', str(binaries['omgd']), '--evidence-dir', '/work/home/daemon'], 'daemon-catalogue')
        daemon = json.loads(artifact(WORK / 'home/daemon/receipt.json'))
        require(daemon.get('accepted') is True and daemon.get('source_sha') == sha and daemon.get('native_candidate_count', 0) >= 25000 and
            daemon.get('info_requests_delta') == 2 and daemon.get('shutdown_returncode') == 0 and daemon.get('socket_absent_after_shutdown') is True and
            all(daemon.get(name + '_sha256') == value for name, value in receipt['binaryHashes'].items()) and
            daemon.get('native_state_unchanged') == daemon.get('native_state_after_shutdown'), 'native daemon proof failed')
        after = json.loads(command(inventory_command, 'inventory-after'))
        require(before == after, 'native package state changed')
        if build:
            libtest = select_libtest(command(['cargo', 'test', '--lib', *FLAGS, '--no-run', '--message-format=json'], 'libtest-artifact'))
        receipt.update(daemon=daemon, inventory={'nativeExplicitCount': len(names), 'completeNamesEqual': True,
            'nativeStateUnchanged': True, 'beforeSha256': digest(json.dumps(before).encode()), 'afterSha256': digest(json.dumps(after).encode())}, accepted=True)
    except Exception as error:
        receipt.update(accepted=False, error=str(error)[:2000], errorType=type(error).__name__)
    finally:
        if ready:
            signal.setitimer(signal.ITIMER_REAL, 0)
            try:
                kill_candidates()
                receipt['candidateProcessesStopped'] = True
            except Exception as error:
                receipt.update(accepted=False, candidateProcessesStopped=False, cleanupError=str(error)[:500])
            daemon_file = WORK / 'home/daemon/receipt.json'
            if daemon_file.exists() and not daemon_file.is_symlink():
                try:
                    receipt['daemon'] = json.loads(artifact(daemon_file))
                except (OSError, ValueError) as error:
                    receipt.update(accepted=False, artifactError=str(error)[:500])
            daemon_log = WORK / 'home/daemon/daemon.log'
            if daemon_log.exists() and not daemon_log.is_symlink():
                try:
                    content = artifact(daemon_log)
                    (REPORTS / 'daemon.log').write_bytes(content)
                    receipt['daemonLogSha256'] = digest(content)
                except (OSError, ValueError) as error:
                    receipt.update(accepted=False, artifactError=str(error)[:500])
            if build and receipt['accepted']:
                try:
                    publish_artifacts(receipt, libtest, cargo)
                except Exception as error:
                    receipt.update(accepted=False, artifactError=str(error)[:500])
            (REPORTS / 'receipt.json').write_text(json.dumps(receipt) + '\n')
        print('OMG_CI_RESULT=' + json.dumps(receipt), flush=True)
    return 0 if receipt['accepted'] else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'build':
        raise SystemExit(main(sys.argv[2], build=True))
    raise SystemExit(main(sys.argv[1] if len(sys.argv) == 2 else ''))

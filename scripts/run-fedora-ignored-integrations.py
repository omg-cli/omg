#!/usr/bin/env python3
"""Run two existing ignored methods against native Fedora fixtures in CI."""
import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib


SELECTORS = (
    'package_managers::dnf::tests::native_removal_simulation_preserves_installed_inventory',
    'package_managers::dnf_advisory::tests::native_advisory_scope_includes_excluded_installed_packages',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def feature_closure(manifest, requested):
    features = manifest['features']
    dependencies = manifest['dependencies']
    suppressed = {edge[4:] for edges in features.values() for edge in edges if edge.startswith('dep:')}
    implicit = {name for name, value in dependencies.items()
                if isinstance(value, dict) and value.get('optional') and name not in suppressed}
    selected = set()
    pending = list(requested)
    while pending:
        name = pending.pop()
        require(name in features or name in implicit, 'Unknown requested Cargo feature: ' + name)
        if name in selected:
            continue
        selected.add(name)
        pending.extend(edge for edge in features.get(name, []) if ':' not in edge and '/' not in edge)
    return selected


def select_libtest(text, manifest_path, features):
    artifacts = []
    finished = []
    for line in text.splitlines():
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get('reason') == 'build-finished':
            finished.append(row.get('success'))
        if (row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'omg_lib'
                and row.get('profile', {}).get('test') and row.get('executable')):
            require(Path(row['manifest_path']) == manifest_path, 'Foreign libtest manifest')
            require(set(row['features']) == features, 'Unexpected Cargo feature closure')
            artifacts.append(row)
    require(finished == [True], 'Missing or failed Cargo build completion')
    require(len(artifacts) == 1, 'Expected one existing omg_lib executable')
    return artifacts[0]


def require_exact_pass(selector, stdout, exit_code):
    named = re.findall(r'^test (\S+) \.\.\. (\S+)$', stdout, re.M)
    summaries = re.findall(r'^test result: ([^\n]+)$', stdout, re.M)
    require(exit_code == 0 and named == [(selector, 'ok')], 'Missing exact named method PASS')
    require(len(summaries) == 1 and re.fullmatch(
        r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [^\n]+',
        summaries[0]), 'Expected exactly one PASS and zero failed/ignored')
    return summaries[0]


def fixture_config(root):
    config = configparser.ConfigParser(interpolation=None)
    config['main'] = dict(reposdir=(root/'repos').as_posix(), cachedir=(root/'cache').as_posix(),
                          system_cachedir=(root/'cache').as_posix(), persistdir=(root/'persist').as_posix(),
                          logdir=(root/'logs').as_posix(), plugins='0', gpgcheck='1',
                          repo_gpgcheck='1', localpkg_gpgcheck='1')
    return config


def explicit_inventory_args():
    return ['dnf', '--cacheonly', '--disable-repo=*', '--setopt=disable_excludes=*',
            'repoquery', '--userinstalled', '--qf', r'%{name}\n']


def tree_dependents_args():
    return ['dnf', '--cacheonly', '--disable-repo=*', 'repoquery', '--installed',
            '--whatrequires', 'tree', '--qf', r'%{name}\n']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--features', required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    require(os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'Requires disposable native CI container')
    require(os.uname().machine == 'x86_64', 'Existing removal assertion requires x86_64')
    require('ID=fedora' in Path('/etc/os-release').read_text().splitlines(), 'Requires Fedora')
    require('OMG_ISOLATED_FIXTURE_TEST' not in os.environ, 'Unexpected inherited isolated-test marker')
    manifest = project/'Cargo.toml'
    features = feature_closure(tomllib.loads(manifest.read_text()), args.features.split(','))
    require({'fedora', 'pgp', 'license', 'rusqlite', 'sequoia-openpgp'} == features,
            'Expected native Fedora CI feature closure')
    artifact = select_libtest(args.artifacts.read_text(), manifest, features)
    binary = Path(artifact['executable'])
    target = Path(os.environ.get('CARGO_TARGET_DIR', project/'target')).resolve()
    require(binary.is_file() and not binary.is_symlink()
            and binary.resolve().is_relative_to(target/'debug/deps'), 'Unsafe libtest location')
    with binary.open('rb') as stream:
        require(stream.read(4) == b'\x7fELF', 'Expected native ELF')
    before_hash = digest(binary)
    out = args.evidence_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = dict(accepted=False, source_sha=os.environ.get('GITHUB_SHA'),
                   binary=str(binary), binary_sha256_before=before_hash,
                   features=sorted(features), commands=[], methods=[],
                   scope='Native Fedora container, two exact ignored fixture methods, no host package writes')
    require(re.fullmatch(r'[0-9a-f]{40}', receipt['source_sha'] or ''), 'Missing CI source identity')
    source_paths = ['Cargo.toml', 'Cargo.lock', 'src/package_managers/dnf.rs',
                    'src/package_managers/dnf_advisory.rs', 'scripts/qemu-fedora-advisory-oracle.py',
                    'scripts/run-fedora-ignored-integrations.py', '.github/workflows/ci.yml']
    receipt['source_sha256'] = {name: digest(project/name) for name in source_paths}
    receipt['cargo_artifacts_sha256'] = digest(args.artifacts)
    started = time.monotonic()
    deadline = started + 120
    env = {key: value for key, value in os.environ.items()
           if key not in ('OMG_TEST_DISTRO', 'OMG_TEST_BACKEND', 'GNUPGHOME')}
    env.update(LC_ALL='C', NO_COLOR='1', CARGO_TERM_COLOR='never', OMG_DISABLE_DAEMON='1',
               PATH='/usr/sbin:/usr/bin:/sbin:/bin')

    def command(label, argv, extra_env=None, expected=0, cleanup=False):
        remaining = 5 if cleanup else min(60, deadline - time.monotonic())
        require(remaining > 0, 'Fixture phase deadline expired')
        call_env = dict(env, **(extra_env or {}))
        start = time.monotonic()
        with (out/(label+'.stdout')).open('wb') as stdout, (out/(label+'.stderr')).open('wb') as stderr:
            child = subprocess.Popen([str(value) for value in argv], env=call_env, cwd=project,
                                     stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
            timed_out = False
            try:
                child.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
            finally:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        require(child.poll() is not None, 'Owned fixture command disappeared without exit')
                    child.wait(timeout=5)
                receipt['commands'].append(dict(label=label, argv=[str(value) for value in argv],
                    pid=child.pid, exit_code=child.returncode, timed_out=timed_out,
                    elapsed_seconds=time.monotonic()-start))
                (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        require(not timed_out and child.returncode == expected, 'Native fixture command failed: ' + label)
        return (out/(label+'.stdout')).read_text()

    def state(label, cleanup=False):
        installed = command(label+'-rpm', ['rpm', '-qa', '--qf',
                            '%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'], cleanup=cleanup)
        explicit = command(label+'-explicit', explicit_inventory_args(), cleanup=cleanup)
        reason = Path('/usr/lib/sysimage/libdnf5')
        files = sorted(reason.rglob('*.toml'))
        require(any(path.name == 'packages.toml' for path in files), 'Missing DNF5 reason state')
        require(all(path.is_file() and not path.is_symlink() for path in files), 'Invalid DNF5 reason files')
        return dict(installed=sorted(installed.splitlines()), explicit=sorted(explicit.splitlines()),
                    reasons={str(path.relative_to(reason)): digest(path) for path in files},
                    dnf_config_sha256=digest(Path('/etc/dnf/dnf.conf')))

    def interrupted(signum, frame):
        raise RuntimeError('Fixture interrupted by signal ' + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    before = None
    completed = False
    try:
        receipt['providers'] = {}
        for name in ('rpm', 'dnf', 'createrepo_c', 'modifyrepo_c', 'gpg', 'gpgconf'):
            resolved = shutil.which(name, path=env['PATH'])
            require(resolved is not None, 'Missing native provider: ' + name)
            path = Path(resolved).resolve(strict=True)
            require(path.is_file() and all(parent.stat().st_uid == 0 and parent.stat().st_mode & 0o022 == 0
                    for parent in (path, *path.parents)), 'Provider is not root-controlled: ' + name)
            receipt['providers'][name] = dict(path=str(path), sha256=digest(path))
        for name in ('rpm', 'dnf'):
            receipt['providers'][name]['version'] = command(name+'-version', [name, '--version'])
        require('dnf5' in receipt['providers']['dnf']['version'].lower(), 'Requires DNF5 provider')
        tree = command('tree-installed', ['rpm', '-q', '--qf', '%{NAME}.%{ARCH}\n', 'tree'])
        require(tree == 'tree.x86_64\n', 'Installed tree.x86_64 fixture required')
        dependents = command('tree-dependents', tree_dependents_args())
        require(not dependents.strip(), 'Installed tree fixture must be a leaf')
        before = state('before')
        receipt['native_state_before'] = before
        stdout = command('ignored-removal', [binary, SELECTORS[0], '--exact', '--ignored',
                                             '--nocapture', '--test-threads=1'])
        receipt['methods'].append(dict(selector=SELECTORS[0], summary=require_exact_pass(SELECTORS[0], stdout, 0)))
        require(state('after-removal') == before, 'Removal simulation changed native state')
        with tempfile.TemporaryDirectory(prefix='omg-fedora-ignored-', dir='/var/tmp') as directory:
            root = Path(directory)
            for name in ('repo', 'repos', 'cache', 'persist', 'logs', 'keys'):
                (root/name).mkdir(mode=0o700)
            native = command('glibc-installed', ['rpm', '-q', '--qf',
                             '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n', 'glibc'])
            rows = [dict(zip(('name', 'epoch', 'version', 'release', 'arch'), line.split('\t')))
                    for line in native.splitlines()]
            require(len(rows) == 1 and rows[0]['arch'] == 'x86_64', 'Requires one native installed glibc')
            identity = rows[0]
            spec = importlib.util.spec_from_file_location('fedora_advisory', project/'scripts/qemu-fedora-advisory-oracle.py')
            oracle = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(oracle)
            xml = oracle.updateinfo(identity)
            (root/'updateinfo.xml').write_text(xml)
            (out/'updateinfo.xml').write_text(xml)
            old = identity['epoch']+':'+identity['version']+'-'+identity['release']
            comparison = command('native-rpm-comparison', ['rpm', '--eval',
                '%{lua:print(rpm.vercmp(os.getenv("OMG_LEFT_EVR"), os.getenv("OMG_RIGHT_EVR")))}'],
                dict(OMG_LEFT_EVR=old, OMG_RIGHT_EVR=old+'.omgqemu616'))
            require(comparison.strip() == '-1', 'Synthetic advisory must be newer under native RPM')
            keys = ['gpg', '--homedir', root/'keys', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
            try:
                command('keygen', keys+['--quick-generate-key', 'OMG CI advisory fixture <fixture@example.invalid>', 'rsa2048', 'sign', '1d'])
                keylist = command('keylist', keys+['--with-colons', '--list-keys'])
                fingerprint = next(line.split(':')[9] for line in keylist.splitlines() if line.startswith('fpr:'))
                public = command('keyexport', keys+['--armor', '--export', fingerprint])
                (root/'fixture-key.asc').write_text(public)
                command('createrepo', ['createrepo_c', root/'repo'])
                command('modifyrepo', ['modifyrepo_c', '--compress-type', 'gz', '--mdtype', 'updateinfo', root/'updateinfo.xml', root/'repo/repodata'])
                metadata = root/'repo/repodata/repomd.xml'
                command('sign', keys+['--armor', '--detach-sign', '--output', str(metadata)+'.asc', metadata])
                command('verify', keys+['--verify', str(metadata)+'.asc', metadata])
                config = fixture_config(root)
                with (root/'dnf.conf').open('w') as stream:
                    config.write(stream)
                repo = ('[omg-qemu-616]\nname=Signed local advisory fixture\nbaseurl='+ (root/'repo').as_uri()
                        +'\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nlocalpkg_gpgcheck=1\ngpgkey='
                        +(root/'fixture-key.asc').as_uri()+'\nskip_if_unavailable=false\n')
                (root/'repos/fixture.repo').write_text(repo)
                common = ['dnf', '--config='+str(root/'dnf.conf'), '--disable-plugin=*', '--setopt=*.skip_if_unavailable=false']
                command('key-admission', common+['--refresh', '-y', 'makecache'])
                selected = command('native-excluded-default-list', common+['--cacheonly', '--setopt=excludepkgs=glibc*', 'advisory', 'list', '--available', '--security', '--json'])
                require(json.loads(selected) == [], 'Native exclusion must hide the advisory control')
                for operation in ('list', 'info'):
                    data = json.loads(command('native-excluded-override-'+operation, common+['--cacheonly', '--setopt=excludepkgs=glibc*', '--setopt=disable_excludes=*', 'advisory', operation, '--available', '--security', '--json']))
                    name, severity = ('name', 'severity') if operation == 'list' else ('Name', 'Severity')
                    require(len(data) == 1 and (data[0][name], data[0][severity]) == ('OMG-QEMU-FEDORA-616', 'Important'), 'Unexpected native advisory applicability')
                stdout = command('ignored-advisory', [binary, SELECTORS[1], '--exact', '--ignored', '--nocapture', '--test-threads=1'],
                                 dict(OMG_DNF_ADVISORY_FIXTURE_CONFIG=str(root/'dnf.conf')))
                receipt['methods'].append(dict(selector=SELECTORS[1], summary=require_exact_pass(SELECTORS[1], stdout, 0)))
                shutil.copytree(root/'repo/repodata', out/'repodata')
                for label, path in [('fixture.repo', root/'repos/fixture.repo'), ('private-dnf.conf', root/'dnf.conf'),
                                    ('fixture-key.asc', root/'fixture-key.asc'), ('repomd.xml', metadata),
                                    ('repomd.xml.asc', Path(str(metadata)+'.asc'))]:
                    (out/label).write_bytes(path.read_bytes())
            finally:
                command('key-agent-cleanup', ['gpgconf', '--homedir', root/'keys', '--kill', 'gpg-agent'], cleanup=True)
        require([row['selector'] for row in receipt['methods']] == list(SELECTORS), 'Missing selected method')
        completed = True
    except Exception as error:
        receipt['failure'] = str(error)
        raise
    finally:
        if before is not None:
            try:
                receipt['native_state_after'] = state('terminal', cleanup=True)
                receipt['native_state_unchanged'] = receipt['native_state_after'] == before
            except Exception as error:
                receipt['terminal_state_error'] = str(error)
                receipt['native_state_unchanged'] = False
        receipt['elapsed_seconds'] = time.monotonic()-started
        receipt['binary_sha256_after'] = digest(binary)
        receipt['identity_unchanged'] = (receipt['binary_sha256_after'] == before_hash and all(
            digest(project/name) == expected for name, expected in receipt['source_sha256'].items()))
        receipt['accepted'] = completed and receipt['identity_unchanged'] and receipt.get('native_state_unchanged', False)
        (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
        require(receipt['identity_unchanged'], 'ELF or source changed during fixture execution')
        require(before is None or receipt['native_state_unchanged'], 'Native state changed or terminal observation failed')


if __name__ == '__main__':
    main()

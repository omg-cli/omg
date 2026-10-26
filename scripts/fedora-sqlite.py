#!/usr/bin/env python3
"""Build and admit reviewed Fedora SQLite bundles from the current trusted CI run."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

DEFAULT_POLICY = Path(__file__).resolve().parents[1]/'tests/qemu-image-provenance/fedora-sqlite.json'
MAX_FILE_BYTES = 160 * 1024 * 1024


def digest(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_FILE_BYTES:
        raise ValueError('missing, linked or oversized bundle file: '+path.name)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('duplicate JSON field')
    return result


def document(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('invalid manifest or policy')
    result = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError('manifest or policy must be an object')
    return result


def package_names(policy, arch):
    if arch not in ('x86_64', 'aarch64'):
        raise ValueError('unsupported native architecture')
    evr = policy['version']+'-'+policy['release']
    return [f'sqlite-{evr}.{arch}.rpm', f'sqlite-libs-{evr}.{arch}.rpm', f'sqlite-{evr}.src.rpm']


def select_bundle(root, arch, attempt):
    pattern = re.compile(r'fedora-sqlite-'+re.escape(arch)+r'-([1-9][0-9]*)')
    candidates = []
    for path in root.iterdir():
        match = pattern.fullmatch(path.name)
        if match and int(match[1]) <= attempt and path.is_dir() and not path.is_symlink():
            candidates.append((int(match[1]), path))
    if not candidates:
        raise ValueError('no current-run SQLite supply artifact')
    return max(candidates)[1]


def verify_bundle(directory, policy, arch, revision):
    manifest = document(directory/'manifest.json')
    expected = {'schema_version': 1, 'architecture': arch, 'source_sha': revision,
                'rpmbuild_exit': 0, 'nofile_soft': policy['nofile_soft']}
    expected.update({key: policy[key] for key in ('base_image', 'source_sha256', 'patch_sha256',
                                                'fingerprint', 'version', 'release')})
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or any(type(manifest.get(k)) is not type(v) or manifest.get(k) != v for k, v in expected.items()):
        raise ValueError('SQLite build source, identity, limits or result differs from policy')
    if not re.fullmatch(r'[0-9a-f]{64}', manifest.get('library_sha256', '')):
        raise ValueError('missing installed-library digest')
    required = set(package_names(policy, arch)) | {'rpmbuild.log', 'test-details.txt', 'packages.tsv', 'source-signature.txt'}
    files = manifest.get('files', {})
    if not isinstance(files, dict) or set(files) != required:
        raise ValueError('SQLite supply must contain exactly the reviewed proof and package set')
    if directory.is_symlink() or {p.name for p in directory.iterdir()} != required | {'manifest.json'}:
        raise ValueError('extra or linked SQLite bundle content refused')
    for name, expected_digest in files.items():
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name) or digest(directory/name) != expected_digest:
            raise ValueError('SQLite bundle digest or path rejected: '+name)
    log = (directory/'rpmbuild.log').read_text(encoding='utf-8')
    summary = re.findall(r'^([0-9]+) errors out of ([0-9]+) tests on +Linux 64-bit$', log, re.M)
    fuzz = re.findall(r'^fuzzcheck: ([0-9]+) errors out of ([0-9]+) tests', log, re.M)
    if (f"SQLITE_NOFILE_SOFT={policy['nofile_soft']}\n" not in log
            or 'Executing(%check)' not in log or len(summary) != 1 or summary[0][0] != '0'
            or int(summary[0][1]) <= 0 or not fuzz or any(int(e) or int(n) <= 0 for e, n in fuzz)):
        raise ValueError('complete unchanged RPM checks did not pass')
    names = sorted(re.findall(r'^Time: (\S+) [0-9]+ ms$', log, re.M))
    inventory = policy['test_files'][arch]
    if len(names) != inventory['count'] or hashlib.sha256(('\n'.join(names)+'\n').encode()).hexdigest() != inventory['sha256']:
        raise ValueError('complete original test-file inventory plus WAL regression is required')
    details = (directory/'test-details.txt').read_text(encoding='utf-8')
    passed = Counter(re.findall(r'^(\S+)\.\.\. Ok$', details, re.M))
    if any(passed[name] != count for name, count in policy['required_assertions'].items()):
        raise ValueError('required FD-exhaustion or WAL assertions did not execute and pass')
    signature = (directory/'source-signature.txt').read_text(encoding='utf-8')
    if not re.search(r'RSA.*6d9f90a6.*OK', signature, re.I):
        raise ValueError('signed Fedora source verification is missing')
    return manifest


def validate_installed(record, manifest):
    expected = {'name': 'sqlite-libs', 'version': manifest['version'], 'release': manifest['release'],
                'architecture': manifest['architecture'], 'library_sha256': manifest['library_sha256']}
    if any(record.get(key) != value for key, value in expected.items()):
        raise ValueError('installed Fedora SQLite baseline is unpatched or differs from admitted native bytes')



def verify_guest_evidence(directory, bundle, manifest):
    for name in ('before', 'after'):
        record = document(directory/('fedora-sqlite-'+name+'.json'))
        expected = {'schema_version': 1, 'source_sha': manifest['source_sha'],
                    'manifest_sha256': digest(bundle/'manifest.json'), 'native_package_verification': True}
        if any(type(record.get(k)) is not type(v) or record.get(k) != v for k, v in expected.items()):
            raise ValueError('native SQLite evidence identity or verification rejected')
        validate_installed(record.get('installed', {}), manifest)
        if record.get('package_sha256') != {n: manifest['files'][n] for n in package_names(manifest, manifest['architecture'])}:
            raise ValueError('native SQLite evidence differs from supplied RPM bytes')
        if name == 'before':
            if record.get('before_admitted') is not False:
                raise ValueError('fresh Fedora baseline did not reject the unpatched library')
            previous = record.get('before', {})
            if previous.get('version') != '3.51.2' or previous.get('release') not in ('1.fc44', '2.fc44'):
                raise ValueError('unexpected original Fedora baseline')


def run(arguments, **kwargs):
    return subprocess.run([str(arg) for arg in arguments], check=True, timeout=kwargs.pop('timeout', 60),
                          stdin=subprocess.DEVNULL, **kwargs)


def installed_record():
    identity = subprocess.check_output(['rpm', '-q', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', 'sqlite-libs'], text=True, timeout=10).split('\t')
    if len(identity) != 4:
        raise ValueError('installed SQLite identity is ambiguous')
    library = Path('/usr/lib64/libsqlite3.so.0').resolve(strict=True)
    metadata = library.stat()
    if library.parent != Path('/usr/lib64') or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError('installed SQLite library ownership or path rejected')
    return dict(zip(('name', 'version', 'release', 'architecture'), identity), library_sha256=digest(library))


def install_bundle(directory, output, policy, arch, revision, install):
    if platform.system() != 'Linux' or os.geteuid() != 0:
        raise ValueError('native Fedora installation/evidence requires root')
    os_release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID="?fedora"?$', os_release, re.M) or not re.search(r'^VERSION_ID="?44"?$', os_release, re.M):
        raise ValueError('SQLite supply is reviewed only for Fedora 44')
    if platform.machine() != arch:
        raise ValueError('SQLite package and native guest architecture differ')
    manifest = verify_bundle(directory, policy, arch, revision)
    before = installed_record()
    try:
        validate_installed(before, manifest)
        before_admitted = True
    except ValueError:
        before_admitted = False
    if install and not before_admitted:
        packages = [directory/name for name in package_names(policy, arch)[:2]]
        query = '[%{FILENAMES}\t%{FILEDIGESTS}\n]'
        dump = subprocess.check_output(['rpm', '-qp', '--qf', query, str(packages[1])], text=True, timeout=20)
        library_row = '/usr/lib64/libsqlite3.so.'+policy['version']+'\t'+manifest['library_sha256']
        if library_row not in dump.splitlines():
            raise ValueError('native RPM file digest differs from supplied library digest')
        for path, name in zip(packages, ('sqlite', 'sqlite-libs')):
            observed = subprocess.check_output(['rpm', '-qp', '--qf', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', str(path)], text=True, timeout=10)
            if observed != '\t'.join((name, policy['version'], policy['release'], arch)):
                raise ValueError('native RPM package identity rejected')
        run(['rpm', '-Uvh', *packages], timeout=90)
    record = installed_record()
    validate_installed(record, manifest)
    run(['rpm', '-V', 'sqlite', 'sqlite-libs'], timeout=20)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({'schema_version': 1, 'source_sha': revision,
        'installed': record, 'before': before, 'before_admitted': before_admitted, 'manifest_sha256': digest(directory/'manifest.json'),
        'package_sha256': {name: manifest['files'][name] for name in package_names(policy, arch)},
        'native_package_verification': True}, indent=2)+'\n')
    print('Installed native Fedora SQLite baseline admitted')


def build_bundle(destination, policy_path, policy, revision):
    if platform.system() != 'Linux' or os.geteuid() != 0 or platform.machine() not in policy['test_files']:
        raise ValueError('source build requires a native supported Fedora builder')
    arch = platform.machine()
    if destination.exists():
        raise ValueError('refusing to overwrite a previous supply build')
    os_release = Path('/etc/os-release').read_text()
    if not re.search(r'^ID="?fedora"?$', os_release, re.M) or not re.search(r'^VERSION_ID="?44"?$', os_release, re.M):
        raise ValueError('source builder must be Fedora 44')
    actual_revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True, timeout=10).strip()
    if actual_revision != revision:
        raise ValueError('builder checkout differs from requested source revision')
    destination.mkdir(parents=True)
    material = policy_path.parent
    if digest(material/policy['patch']) != policy['patch_sha256'] or digest(material/policy['keyring']) != policy['keyring_sha256']:
        raise ValueError('reviewed source patch or Fedora keyring changed')
    run(['dnf', '--releasever=44', '--disablerepo=*', '--enablerepo=fedora', '--enablerepo=updates',
         '--setopt=gpgcheck=1', '--setopt=localpkg_gpgcheck=1', '-y', 'install',
         'rpm-build', 'rpmdevtools', 'curl-minimal', 'gcc', 'gcc-c++', 'make', 'ncurses-devel', 'readline-devel',
         'glibc-devel', 'autoconf', 'tcl', 'tcl-devel', 'zlib-ng-compat-devel', 'chrpath',
         'patch', 'cpio', 'gnupg2', 'shadow-utils'], timeout=600)
    with tempfile.TemporaryDirectory(prefix='omg-sqlite-source-') as temporary:
        work = Path(temporary)
        source = work/'sqlite.src.rpm'
        run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
             '--proto-redir', '=https', '--connect-timeout', '20', '--max-time', '120',
             '--max-filesize', '40000000', '--output', source, policy['source_url']], timeout=130)
        if digest(source) != policy['source_sha256']:
            raise ValueError('authenticated Fedora source RPM digest rejected')
        home = work/'gpg'
        home.mkdir(mode=0o700)
        common = ['gpg', '--no-options', '--homedir', home, '--batch', '--no-tty']
        run([*common, '--import', material/policy['keyring']], capture_output=True)
        fingerprints = subprocess.check_output([str(x) for x in [*common, '--with-colons', '--fingerprint', policy['fingerprint']]], text=True, timeout=10)
        if 'fpr:::::::::'+policy['fingerprint']+':' not in fingerprints:
            raise ValueError('Fedora 44 publisher fingerprint rejected')
        public = work/'fedora44.asc'
        with public.open('wb') as stream:
            run([*common, '--armor', '--export', policy['fingerprint']], stdout=stream)
        run(['rpmkeys', '--import', public])
        with (destination/'source-signature.txt').open('wb') as stream:
            run(['rpmkeys', '--checksig', '--verbose', source], stdout=stream, stderr=subprocess.STDOUT)
        signature = (destination/'source-signature.txt').read_text()
        if not re.search(r'RSA.*6d9f90a6.*OK', signature, re.I):
            raise ValueError('Fedora source signature rejected')
        packages = subprocess.check_output(['rpm', '-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIGPGP:pgpsig}\n'], text=True, timeout=20)
        if re.search(r'\.fc(?:4[5-9]|[5-9][0-9])\b', packages):
            raise ValueError('non-Fedora44 build dependency refused')
        (destination/'packages.tsv').write_text('\n'.join(sorted(packages.splitlines()))+'\n')
        run(['useradd', '--create-home', '--uid', '1000', 'sqlitebuilder'])
        top = Path('/build/fedora-sqlite')
        if top.exists():
            raise ValueError('refusing a previous RPM build directory')
        top.mkdir(parents=True)
        run(['rpm', '-i', '--define', '_topdir '+str(top), source])
        shutil.copyfile(material/policy['patch'], top/'SOURCES'/policy['patch'])
        spec = top/'SPECS/sqlite.spec'
        text = spec.read_text()
        replacements = [('Release: 2%{?dist}', 'Release: '+policy['release'].removesuffix('.fc44')+'%{?dist}'),
            ('Patch3: sqlite-3.51.2-CVE-2026-11822-CVE-2026-11824.patch',
             'Patch3: sqlite-3.51.2-CVE-2026-11822-CVE-2026-11824.patch\nPatch4: '+policy['patch']),
            ('%patch -P 3 -p1', '%patch -P 3 -p1\n%patch -P 4 -p1'),
            ('make test\n', 'make test\ncp test-out.txt %{_topdir}/test-details.txt\n')]
        for old, new in replacements:
            if text.count(old) != 1:
                raise ValueError('official Fedora spec differs from reviewed source')
            text = text.replace(old, new)
        spec.write_text(text)
        run(['chown', '-R', 'sqlitebuilder:sqlitebuilder', top])
        command = ['runuser', '-u', 'sqlitebuilder', '--', 'env', '-i', 'HOME=/home/sqlitebuilder',
                   'PATH=/usr/bin:/usr/sbin:/bin:/sbin', 'LANG=C.UTF-8', 'bash', '-c',
                   'set -euo pipefail; ulimit -Sn "$1"; shift; printf "SQLITE_NOFILE_SOFT=%s\n" "$(ulimit -Sn)"; exec "$@"',
                   '_', str(policy['nofile_soft']), 'rpmbuild', '-ba',
                   '--define', '_topdir '+str(top), '--define', '_smp_mflags -j2', spec]
        with (destination/'rpmbuild.log').open('wb') as stream:
            run(['timeout', '--kill-after=10s', '1800s', *command],
                stdout=stream, stderr=subprocess.STDOUT, timeout=1820)
        shutil.copyfile(top/'test-details.txt', destination/'test-details.txt')
        for name in package_names(policy, arch):
            source_path = top/('SRPMS' if name.endswith('.src.rpm') else 'RPMS/'+arch)/name
            shutil.copyfile(source_path, destination/name)
        native = destination/package_names(policy, arch)[1]
        rows = subprocess.check_output(['rpm', '-qp', '--qf', '[%{FILENAMES}\t%{FILEDIGESTS}\n]', str(native)], text=True, timeout=20)
        library = '/usr/lib64/libsqlite3.so.'+policy['version']
        hashes = [row.split('\t')[1] for row in rows.splitlines() if row.split('\t')[0] == library]
        if len(hashes) != 1 or not re.fullmatch(r'[0-9a-f]{64}', hashes[0]):
            raise ValueError('native RPM library digest is missing or ambiguous')
        manifest = {'schema_version': 1, 'source_sha': revision, 'architecture': arch,
                    'rpmbuild_exit': 0, 'nofile_soft': policy['nofile_soft'], 'library_sha256': hashes[0]}
        manifest.update({k: policy[k] for k in ('base_image', 'source_sha256', 'patch_sha256', 'fingerprint', 'version', 'release')})
        manifest['files'] = {p.name: digest(p) for p in destination.iterdir()}
        (destination/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        verify_bundle(destination, policy, arch, revision)
        print('Complete Fedora SQLite source build and baseline bundle admitted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'verify', 'select', 'install', 'installed'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    parser.add_argument('--arch', choices=['x86_64', 'aarch64'], default={'AMD64': 'x86_64', 'ARM64': 'aarch64'}.get(platform.machine(), platform.machine()))
    parser.add_argument('--revision', required=True)
    parser.add_argument('--attempt', type=int)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--evidence-dir', type=Path)
    args = parser.parse_args()
    try:
        policy = document(args.policy)
        if args.action == 'build':
            build_bundle(args.directory, args.policy, policy, args.revision)
        elif args.action == 'select':
            selected = select_bundle(args.directory, args.arch, args.attempt)
            verify_bundle(selected, policy, args.arch, args.revision)
            print(selected.resolve())
        elif args.action == 'verify':
            manifest = verify_bundle(args.directory, policy, args.arch, args.revision)
            if args.evidence_dir is not None:
                verify_guest_evidence(args.evidence_dir, args.directory, manifest)
            print('Complete Fedora SQLite bundle admitted')
        else:
            if args.output is None:
                raise ValueError('installed evidence output is required')
            install_bundle(args.directory, args.output, policy, args.arch, args.revision, args.action == 'install')
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Fedora SQLite admission refused: '+str(error)+'\n')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run the same exact Arch CLI coverage cases in disposable Docker or QEMU guests."""

import argparse
import base64
import gzip
import io
import time
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tarfile
from typing import NamedTuple
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fixture_command(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, timeout=40, **kwargs)


def fixture_member(archive, name, value):
    data = value.encode() if isinstance(value, str) else value
    info = tarfile.TarInfo(name)
    info.uid = info.gid = 0
    info.mode = 0o644
    info.mtime = 1
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def fixture_package(directory, name, version, payload_path, payload, depends=()):
    path = directory / f'{name}-{version}-any.pkg.tar.gz'
    info = (f'pkgname = {name}\npkgbase = {name}\npkgver = {version}\n'
            'pkgdesc = inert coverage fixture\nbuilddate = 1\npackager = Native Fixture <coverage@example.invalid>\n'
            f'size = {len(payload)}\narch = any\nlicense = MIT\n'
            + ''.join(f'depend = {dep}\n' for dep in depends)).encode()
    build = (f'format = 2\npkgname = {name}\npkgbase = {name}\npkgver = {version}\n'
             'pkgarch = any\nbuilddate = 1\npackager = Native Fixture <coverage@example.invalid>\n').encode()
    contents = [('.PKGINFO', info), ('.BUILDINFO', build), (payload_path, payload)]
    mtree = '#mtree\n/set uid=0 gid=0 type=file\n' + ''.join(
        f'./{p} mode=644 size={len(b)} time=1.0 sha256digest={hashlib.sha256(b).hexdigest()}\n'
        for p, b in contents)
    with tarfile.open(path, 'w:gz', format=tarfile.GNU_FORMAT) as archive:
        fixture_member(archive, '.PKGINFO', info)
        fixture_member(archive, '.BUILDINFO', build)
        fixture_member(archive, '.MTREE', gzip.compress(mtree.encode(), mtime=0))
        fixture_member(archive, payload_path, payload)
    return path


def fixture_local_package(root, database, name, version, payload_path, payload, reason, depends=()):
    location = database / 'local' / f'{name}-{version}'
    location.mkdir()
    fields = {'NAME': name, 'BASE': name, 'VERSION': version, 'DESC': 'inert coverage fixture',
              'ARCH': 'any', 'BUILDDATE': '1', 'INSTALLDATE': '1',
              'SIZE': str(len(payload)), 'REASON': str(reason), 'LICENSE': 'MIT', 'VALIDATION': 'pgp', 'PACKAGER': 'Native Fixture <coverage@example.invalid>'}
    if depends:
        fields['DEPENDS'] = '\n'.join(depends)
    (location / 'desc').write_text(''.join(f'%{k}%\n{v}\n\n' for k, v in fields.items()))
    (location / 'files').write_text(f'%FILES%\n{payload_path}\n\n')
    target = root / payload_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)


def create_signed_fixture(owner):
    if os.geteuid() != 0:
        raise RuntimeError('Guest root setup required')
    for kind in ('mnt', 'net'):
        if os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind):
            raise RuntimeError('Private guest namespaces required before fixture setup')
    if fixture_command(['systemd-detect-virt', '--vm'], text=True).stdout.strip() not in ('qemu', 'kvm'):
        raise RuntimeError('Disposable QEMU guest required')
    if owner.parent != Path('/opt') or not owner.name.startswith('omg-coverage-') or owner.exists():
        raise RuntimeError('New exact /opt/omg-coverage-* fixture owner required')
    owner.mkdir(mode=0o755)
    for path in ('root', 'db/local', 'db/sync', 'cache', 'repos/core', 'repos/omarchy', 'signing', 'gnupg'):
        (owner / path).mkdir(parents=True, exist_ok=True)
    for path in ('signing', 'gnupg'):
        (owner / path).chmod(0o700)
    (owner / 'db/local/ALPM_DB_VERSION').write_text('9\n')
    signing = ['gpg', '--batch', '--homedir', str(owner / 'signing'), '--pinentry-mode', 'loopback', '--passphrase', '']
    fixture_command(signing + ['--quick-generate-key', 'OMG coverage fixture <coverage@example.invalid>', 'ed25519', 'cert,sign', '1d'])
    listing = fixture_command(signing + ['--with-colons', '--fingerprint', '--list-keys'], text=True).stdout
    fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    if len(fingerprints) != 1 or len(fingerprints[0]) != 40:
        raise RuntimeError('One exact private fixture signing fingerprint required')
    fingerprint = fingerprints[0]
    before_public = fixture_command(signing + ['--export', fingerprint]).stdout
    public_path = owner / 'fixture-public.gpg'
    public_path.write_bytes(before_public)
    ring = ['gpg', '--batch', '--homedir', str(owner / 'gnupg'), '--no-default-keyring', '--keyring', str(owner / 'gnupg/pubring.gpg')]
    fixture_command(ring + ['--import', str(public_path)])
    fixture_command(ring + ['--import-ownertrust'], input=(fingerprint + ':6:\n').encode())
    fixture_command(ring + ['--check-trustdb'])
    if not (owner / 'gnupg/pubring.gpg').is_file():
        raise RuntimeError('Initialized pacman-compatible public keyring required')
    fixture_command(signing + ['--quick-add-uid', fingerprint, 'Updated coverage fixture <updated19@example.invalid>'])
    updated_public = fixture_command(signing + ['--export', fingerprint]).stdout
    if before_public == updated_public:
        raise RuntimeError('Updated public bundle must differ from initial bundle')
    initial = {}
    repositories = {'core': [], 'omarchy': []}
    for name, repository, reason, depends in (
        ('archlinux-keyring', 'core', 0, ()), ('omarchy-keyring', 'omarchy', 0, ()),
        ('omg-coverage-app', 'core', 0, ('omg-coverage-dep>=1-1',)),
        ('omg-coverage-dep', 'core', 1, ()), ('omg-coverage-desktop', 'omarchy', 0, ())):
        keyring = name.endswith('-keyring')
        payload_path = ('usr/share/pacman/keyrings/' + name.removesuffix('-keyring') + '.gpg'
                        if keyring else 'usr/share/omg-coverage/' + name + '.txt')
        old_payload = before_public if keyring else (name + ': installed1\n').encode()
        new_payload = updated_public if keyring else (name + ': upgraded3\n').encode()
        fixture_local_package(owner / 'root', owner / 'db', name, '1-1', payload_path, old_payload, reason, depends)
        archive = fixture_package(owner / 'repos' / repository, name, '3-1', payload_path, new_payload, depends)
        fixture_command(signing + ['--local-user', fingerprint, '--detach-sign', '--output', str(archive) + '.sig', str(archive)])
        repositories[repository].append((name, archive, payload_path, new_payload, depends))
        initial[name] = {'version': '1-1', 'reason': reason, 'payload_path': payload_path,
                         'before_sha256': hashlib.sha256(old_payload).hexdigest(),
                         'after_sha256': hashlib.sha256(new_payload).hexdigest()}
    for name, reason in (('omg-coverage-dead-dep', 1),):
        fixture_local_package(owner / 'root', owner / 'db', name, '1-1', 'usr/share/omg-coverage/' + name + '.txt', b'retain unless actual orphan\n', reason)
    for repository, records in repositories.items():
        database = owner / 'repos' / repository / (repository + '.db')
        with tarfile.open(database, 'w:gz') as archive:
            for name, file, payload_path, payload, depends in records:
                fields = {'NAME': name, 'BASE': name, 'VERSION': '3-1', 'FILENAME': file.name,
                          'DESC': 'inert signed coverage fixture', 'ARCH': 'any', 'PACKAGER': 'Native Fixture <coverage@example.invalid>',
                          'CSIZE': str(file.stat().st_size), 'ISIZE': str(len(payload)),
                          'SHA256SUM': sha(file), 'PGPSIG': base64.b64encode(Path(str(file) + '.sig').read_bytes()).decode(), 'LICENSE': 'MIT'}
                if depends:
                    fields['DEPENDS'] = '\n'.join(depends)
                fixture_member(archive, name + '-3-1/desc', ''.join(f'%{k}%\n{v}\n\n' for k, v in fields.items()))
        fixture_command(signing + ['--local-user', fingerprint, '--detach-sign', '--output', str(database) + '.sig', str(database)])
    for version in ('0-1', '1-1', '2-1'):
        file = fixture_package(owner / 'cache', 'omg-coverage-app', version, 'usr/share/omg-coverage/omg-coverage-app.txt', b'cached fixture\n', ('omg-coverage-dep>=1-1',))
        fixture_command(signing + ['--local-user', fingerprint, '--detach-sign', '--output', str(file) + '.sig', str(file)])
    (owner / 'cache/unrelated.txt').write_text('must survive pruning\n')
    (owner / 'outside-cache.txt').write_text('must survive symlink escape\n')
    (owner / 'cache/escape.pkg.tar.gz').symlink_to(owner / 'outside-cache.txt')
    configuration = ('[options]\nRootDir = ' + str(owner / 'root') + '\nDBPath = ' + str(owner / 'db')
                     + '\nCacheDir = ' + str(owner / 'cache') + '\nGPGDir = ' + str(owner / 'gnupg')
                     + '\nLogFile = ' + str(owner / 'pacman.log')
                     + '\nArchitecture = auto\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    for repository in repositories:
        configuration += '[' + repository + ']\nSigLevel = Required TrustedOnly\nServer = file://' + str(owner / 'repos' / repository) + '\n'
    (owner / 'pacman.conf').write_text(configuration)
    receipt = {'status': 'PREPARED_DATA_ONLY_NOT_RUNTIME_PROOF', 'owner': str(owner), 'created_unix': time.time(),
               'fixture_signer_fingerprint': fingerprint, 'signer_is_authored_throwaway_key': True,
               'host_or_publisher_secret_material_used': False, 'siglevel_weakened': False,
               'initial_packages': initial, 'config_sha256': sha(owner / 'pacman.conf'),
               'public_before_sha256': hashlib.sha256(before_public).hexdigest(),
               'public_updated_sha256': hashlib.sha256(updated_public).hexdigest(),
               'archive_sha256': {str(p.relative_to(owner)): sha(p) for p in sorted((owner / 'repos').rglob('*')) if p.is_file()}}
    (owner / 'data-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt



def verify_signed_fixture(owner):
    receipt = json.loads((owner / 'data-receipt.json').read_text())
    for name, expected in receipt['initial_packages'].items():
        installed = owner / 'db/local' / (name + '-3-1')
        require(installed.is_dir() and not (owner / 'db/local' / (name + '-1-1')).exists(),
                'Native transaction did not upgrade ' + name)
        fields = dict(re.findall(r'%([A-Z]+)%\n(.*?)\n\n', (installed / 'desc').read_text(), re.S))
        require(fields['NAME'] == name and fields['VERSION'] == '3-1'
                and int(fields.get('REASON', '0')) == expected['reason'],
                'Native transaction changed package identity or install intent')
        require(sha(owner / 'root' / expected['payload_path']) == expected['after_sha256'],
                'Native transaction payload differs for ' + name)
    require(not (owner / 'db/local/omg-coverage-dead-dep-1-1').exists(), 'Native orphan was retained')
    require((owner / 'cache/unrelated.txt').read_text() == 'must survive pruning\n'
            and (owner / 'outside-cache.txt').read_text() == 'must survive symlink escape\n'
            and (owner / 'cache/escape.pkg.tar.gz').is_symlink(), 'Cache pruning escaped its package scope')
    require(not (owner / 'cache/omg-coverage-app-0-1-any.pkg.tar.gz').exists(), 'Native cache pruning did not run')
    require(not (owner / 'db/db.lck').exists(), 'Native transaction leaked its database lock')
    return dict(status='PASS_SIGNED_NATIVE_STATE', packages=receipt['initial_packages'])


def unpack_evidence(archive, directory):
    metadata = archive.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 1024 ** 3,
            'Returned archive must be a bounded regular file')
    owner = directory.parent.stat()
    directory.mkdir(mode=0o700)
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:') as bundle:
        for index, member in enumerate(bundle):
            require(index < 8192, 'Returned archive has too many members')
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts
                    and not any(ord(character) < 32 or character == '\\' for character in member.name),
                    'Unsafe returned archive path')
            require(member.isdir() or member.isreg(), 'Returned archive contains a non-regular entry')
            if name == PurePosixPath('.'):
                require(member.isdir(), 'Archive root must be a directory')
                continue
            require(name not in seen, 'Duplicate returned archive path')
            seen.add(name)
            target = directory.joinpath(*name.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(mode=0o700, exist_ok=True)
                continue
            total += member.size
            require(0 <= member.size <= 64 * 1024 ** 2 and total <= 512 * 1024 ** 2,
                    'Returned archive exceeds its extraction budget')
            with bundle.extractfile(member) as source, target.open('xb') as output:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    require(chunk, 'Truncated returned archive member')
                    output.write(chunk)
                    remaining -= len(chunk)
            target.chmod(0o600)
    # The controller may run as root; ownership follows the caller's work directory.
    for path in (directory, *directory.rglob('*')):
        if (path.stat().st_uid, path.stat().st_gid) != (owner.st_uid, owner.st_gid):
            os.chown(path, owner.st_uid, owner.st_gid)


def controller_bind_path(path, mounts):
    def absolute(value):
        require(isinstance(value, str) and value and not value.startswith('//')
                and not any(ord(character) < 32 or character == ',' for character in value),
                'Unsafe controller mount path')
        parsed = PurePosixPath(value)
        require(parsed.is_absolute() and '..' not in parsed.parts, 'Controller mount path must be absolute without parent traversal')
        return parsed

    requested = absolute(path)
    require(isinstance(mounts, list), 'Docker mounts must be an array')
    candidates = []
    for mount in mounts:
        require(isinstance(mount, dict), 'Invalid Docker mount record')
        if mount.get('Type') != 'bind':
            continue
        destination = absolute(mount.get('Destination'))
        if requested.is_relative_to(destination):
            candidates.append((destination, mount))
    require(candidates, 'No bind mount maps the requested controller directory')
    depth = max(len(destination.parts) for destination, _ in candidates)
    closest = [(destination, mount) for destination, mount in candidates if len(destination.parts) == depth]
    require(len(closest) == 1, 'Ambiguous controller mount mapping')
    destination, mount = closest[0]
    require(mount.get('RW') is True, 'Controller workspace bind must be writable')
    source = absolute(mount.get('Source'))
    return str(source / requested.relative_to(destination))


TESTS = {
    'coverage14': (
        'why_contracts::uninstalled_package_fails_naming_cause_and_remedy',
        'why_contracts::explicit_package_reports_reason_dependencies_and_safety',
        'why_contracts::orphan_dependency_is_flagged_safe_to_remove',
        'why_contracts::required_by_card_shows_dependent_and_dependency_path',
        'why_contracts::reverse_lists_dependents_with_safety_warning',
        'why_contracts::reverse_without_dependents_is_safe',
    ),
    'arch-contracts': (
        'dependency_reports_bound_large_reverse_dependency_lists',
        'native_size_tree_includes_installed_virtual_provider',
        'native_size_tree_counts_one_provider_for_multiple_virtual_requirements',
        'native_size_tree_respects_virtual_provider_version_constraints',
        'native_size_tree_preserves_exact_name_dependency_totals',
        'native_size_tree_refuses_absent_root_without_changing_private_data',
    ),
    'comprehensive': ('behavior_inventory_runs_in_hermetic_state',),
    'cli-unit': ('fast_path_tests::private_install_plan_rejects_missing_or_invalid_descriptors',),
}
ROLES = ('cli', 'daemon', *TESTS)
CASES = tuple((f'test-{index:02}', role, name)
              for index, (role, name) in enumerate(
                  ((role, name) for role, names in TESTS.items() for name in names), 1))
OMARCHY_PREFIX = (
    'omarchy-update-requires-free-space', 'omarchy-snapshot\tcreate',
    'omarchy-update-stay-awake\tstart', 'omarchy-update-dev')
OMARCHY_SUFFIX = (
    'omarchy-migrate\t--pending', 'omarchy-restart-shell', 'omarchy-migrate',
    'omarchy-update-analyze-logs',
    'omarchy-shell\t-q\tomarchy.system-update\tclear',
    'omarchy-update-restart\t--services-only', 'omarchy-hook\tpost-update',
    'omarchy-update-mise', 'omarchy-update-boot', 'omarchy-update-stay-awake\tstop')


class OmarchyCase(NamedTuple):
    exit_status: int
    helpers: tuple[str, ...]
    scene: str = 'none'
    absent_helper: str | None = None
    native_committed: bool = False
    reboot_answer: str | None = None
    authorization: str | None = None


OMARCHY_CASES = {
    'omarchy-success': OmarchyCase(0, OMARCHY_PREFIX + OMARCHY_SUFFIX, native_committed=True),
    'omarchy-vendor-failure': OmarchyCase(1, OMARCHY_PREFIX + ('omarchy-update-stay-awake\tstop',)),
    'omarchy-declined': OmarchyCase(0, ('omarchy-update-requires-free-space', 'omarchy-update-confirm')),
    'omarchy-optional-failures': OmarchyCase(0, tuple(
        item for item in OMARCHY_PREFIX + OMARCHY_SUFFIX
        if item.split('\t')[0] not in ('omarchy-snapshot', 'omarchy-restart-shell', 'omarchy-update-mise')),
        native_committed=True),
    'omarchy-migration-refusal': OmarchyCase(1, ()),
    'omarchy-unsupported-mode': OmarchyCase(1, ()),
    'omarchy-invalid-transport': OmarchyCase(1, ()),
    'omarchy-snapshot-missing': OmarchyCase(0, tuple(
        item for item in OMARCHY_PREFIX + OMARCHY_SUFFIX
        if item != 'omarchy-snapshot\tcreate'), absent_helper='omarchy-snapshot', native_committed=True),
    'omarchy-snapshot-unsupported': OmarchyCase(0, OMARCHY_PREFIX + OMARCHY_SUFFIX,
        scene='snapshot-unsupported', native_committed=True),
    'omarchy-required-helper-missing': OmarchyCase(1, OMARCHY_PREFIX[:3] +
        ('omarchy-update-stay-awake\tstop',), absent_helper='omarchy-update-dev'),
    'omarchy-reboot-decline': OmarchyCase(0, OMARCHY_PREFIX[:1] +
        ('omarchy-update-confirm',) + OMARCHY_PREFIX[1:] + OMARCHY_SUFFIX,
        native_committed=True, reboot_answer='n'),
    'omarchy-reboot-accept': OmarchyCase(0, OMARCHY_PREFIX[:1] +
        ('omarchy-update-confirm',) + OMARCHY_PREFIX[1:] + OMARCHY_SUFFIX + ('omarchy-system\treboot',),
        native_committed=True, reboot_answer='y'),
    'omarchy-reboot-failure': OmarchyCase(1, OMARCHY_PREFIX[:1] +
        ('omarchy-update-confirm',) + OMARCHY_PREFIX[1:] + OMARCHY_SUFFIX + ('omarchy-system\treboot',),
        scene='reboot-failure', native_committed=True, reboot_answer='y'),
    'omarchy-authorization-refresh': OmarchyCase(0, OMARCHY_PREFIX + OMARCHY_SUFFIX,
        scene='authorization-hold', native_committed=True, authorization='refresh'),
    'omarchy-authorization-denied': OmarchyCase(0, OMARCHY_PREFIX + OMARCHY_SUFFIX,
        scene='authorization-hold', native_committed=True, authorization='denied'),
}

PROCESS_STAGES = ('cli-q', 'cli-v', 'cli-vv', 'cli-vvv', 'daemon', *OMARCHY_CASES)
STAGES = tuple('registry-' + role for role in TESTS) + tuple(row[0] for row in CASES) + PROCESS_STAGES
PROFILE = re.compile(r'omg-extra-(' + '|'.join(map(re.escape, STAGES)) + r')-([0-9]+)-([0-9]+_[0-9]+)\.profraw')


def authorization_audit(text):
    records = [record for record in re.split(
        r'(?m)(?=^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+:)', text)
        if re.search(r'(?:^|[;\n])\s*COMMAND=/usr/bin/true\s*(?:\n|$)', record)]
    require(len(records) == 2, 'One initial authorization and one timed refresh are required')
    timestamps = []
    for record in records:
        stamp = re.match(r'^[A-Za-z]{3}\s+\d{1,2}\s+(\d{2}):(\d{2}):(\d{2})\s+:', record)
        require(stamp is not None and ': nobody :' in record and 'USER=root' in record,
                'Authorization audit has an unexpected actor, target or timestamp')
        hour, minute, second = map(int, stamp.groups())
        require(hour < 24 and minute < 60 and second < 60, 'Invalid authorization audit time')
        timestamps.append(hour * 3600 + minute * 60 + second)
    require('command not allowed' not in records[0], 'Initial authorization was refused')
    elapsed = (timestamps[1] - timestamps[0]) % (24 * 3600)
    require(59 <= elapsed <= 95, 'Authorization refresh did not follow the real interval')
    return dict(initial_authorizations=1, refresh_count=1, refresh_after_seconds=elapsed,
                denied='command not allowed' in records[1])


def omarchy_guest_script():
    script = r'''unshare --mount --net --fork bash -s <<'OMG_OMARCHY_NAMESPACE'
set -euo pipefail
mount --make-rprivate /
for tool in script flock tar mount mountpoint readlink runuser; do
  command -v "$tool" > /dev/null || { printf 'Missing Omarchy fixture command: %s\n' "$tool" >&2; exit 1; }
done
fixture=/opt/omg-omarchy-coverage
test ! -e "$fixture" && test ! -L "$fixture"
install -d -m 755 "$fixture"
printf 'ID=omarchy\nID_LIKE=arch\n' > "$fixture/release"
mount --bind "$fixture/release" /etc/os-release
mount -t tmpfs -o nosuid,nodev,mode=1777 tmpfs /tmp
install -d -m 755 "$fixture/runtime" "$fixture/runtime/migrations" /usr/share/omarchy
mount --bind "$fixture/runtime" /usr/share/omarchy
test "$(stat -c '%u:%a' /usr/share/omarchy)" = 0:755
test "$(stat -c '%u:%a' /usr/share/omarchy/migrations)" = 0:755
cat > "$fixture/stage" <<'OMG_INERT_OMARCHY_STAGE'
#!/bin/bash
set -euo pipefail
name=${0##*/}
omarchy_security_require_source_root() {
  local command_source command_name=${1##*/}
  command_source=$(/usr/bin/readlink -e -- "$1") || return 1

  # A runtime root selects the code used by this invocation. Accept the
  # canonical checkout containing the entrypoint or the package's bin links.
  if [[ ${OMARCHY_PATH:-} != /* || $(/usr/bin/realpath -e -- "$OMARCHY_PATH") != "$OMARCHY_PATH" ]] ||
    ! { [[ $command_source == "$OMARCHY_PATH/bin/$command_name" ]] ||
      [[ $OMARCHY_PATH == "/usr/share/omarchy" && $command_source == "/usr/bin/$command_name" ]]; }; then
    echo "OMARCHY_PATH does not match this Omarchy command." >&2
    return 1
  fi
}
case "$name" in omarchy-*) omarchy_security_require_source_root "$0" ;; esac
{ printf '%s' "$name"; if test "$#" -gt 0; then printf '\t%s' "$@"; fi; printf '\n'; } >> "$OMARCHY_HELPER_TRACE"
case "$name:${OMARCHY_FIXTURE_SCENE:-none}" in
  omarchy-snapshot:snapshot-unsupported) exit 127 ;;
  omarchy-system:reboot-failure) exit 7 ;;
  omarchy-update-dev:authorization-hold) sleep 65 ;;
esac
case "$name" in
  omarchy-update-pkg-prune|omarchy-update-keyring|omarchy-update-system-pkgs|omarchy-update-orphan-pkgs|pacman|pacman-key|paccache|yay|aura|paru)
    printf 'external package helper must never run in the native fixture\n' >&2; exit 99 ;;
  omarchy-update-confirm) test "$OMARCHY_FIXTURE_CASE" != omarchy-declined ;;
  omarchy-snapshot|omarchy-update-mise) test "$OMARCHY_FIXTURE_CASE" != omarchy-optional-failures ;;
  *) exit 0 ;;
esac
OMG_INERT_OMARCHY_STAGE
cat > "$fixture/foreign-stage-prefix" <<'OMG_FOREIGN_OMARCHY_STAGE_PREFIX'
#!/bin/bash
set -euo pipefail
printf 'foreign helper executed: %s\n' "$0" >> "$OMARCHY_HELPER_TRACE.unexpected"
OMG_FOREIGN_OMARCHY_STAGE_PREFIX
install -d -m 755 "$fixture/foreign" "$fixture/foreign/bin" "$fixture/saved"
for name in omarchy-snapshot omarchy-restart-shell omarchy-update-mise omarchy-update-confirm; do
  cat "$fixture/foreign-stage-prefix" > "$fixture/foreign/bin/$name"
  tail -n +2 "$fixture/stage" >> "$fixture/foreign/bin/$name"
  chmod 755 "$fixture/foreign/bin/$name"
done
chmod 755 "$fixture/stage"
cat > "$fixture/attended.py" <<'OMG_ATTENDED_OMARCHY_DRIVER'
import errno, fcntl, json, os, pty, select, signal, struct, sys, termios, time
from pathlib import Path

answer = sys.argv[1]
assert answer in ('y', 'n')
child, terminal = pty.fork()
if child == 0:
    os.execv('/omg-extra-bin/cli', ['/omg-extra-bin/cli', 'update'])
status = None
responded = False
output = bytearray()
deadline = time.monotonic() + 30
try:
    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    while time.monotonic() < deadline:
        if select.select([terminal], [], [], 0.1)[0]:
            try:
                chunk = os.read(terminal, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b''
            if chunk:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                output.extend(chunk)
                assert len(output) <= 1024 * 1024, 'Attended transcript budget exceeded'
                if not responded and b'Reboot now?' in output:
                    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 100, 0, 0))
                    os.kill(child, signal.SIGWINCH)
                    os.write(terminal, (answer + '\n').encode())
                    responded = True
        observed, value = os.waitpid(child, os.WNOHANG)
        if observed:
            status = value
            break
    assert status is not None, 'Attended CLI deadline exceeded'
    assert responded, 'Genuine reboot prompt was not observed'
    while select.select([terminal], [], [], 0)[0]:
        try:
            chunk = os.read(terminal, 4096)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        output.extend(chunk)
        assert len(output) <= 1024 * 1024, 'Attended transcript budget exceeded'
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
finally:
    if status is None:
        os.kill(child, signal.SIGTERM)
        for _ in range(30):
            observed, status = os.waitpid(child, os.WNOHANG)
            if observed:
                break
            status = None
            time.sleep(0.1)
        if status is None:
            os.kill(child, signal.SIGKILL)
            _, status = os.waitpid(child, 0)
    os.close(terminal)
code = os.waitstatus_to_exitcode(status)
receipt = dict(prompt_observed=responded, answer=answer, resize_sent=1, cli_exit_code=code)
Path(os.environ['OMARCHY_HELPER_TRACE']).with_name('interaction.json').write_text(json.dumps(receipt)+'\n')
sys.exit(code)
OMG_ATTENDED_OMARCHY_DRIVER
test -u /usr/bin/sudo
runuser -u nobody -- sudo -n /usr/bin/true
for name in pacman pacman-key paccache; do
  if test -e "/usr/bin/$name"; then
    mount --bind "$fixture/stage" "$(readlink -e "/usr/bin/$name")"
  else
    install -m 755 "$fixture/stage" "/usr/bin/$name"
  fi
done
install -d -m 700 /profiles/native-root
printf 'Defaults env_file="/etc/omg-native-coverage.env"\nnobody ALL=(root) NOPASSWD: /usr/bin/true, /usr/bin/systemd-run --scope --quiet --collect -- /omg-extra-bin/cli *\n' > /etc/sudoers.d/omg-native-coverage
chmod 440 /etc/sudoers.d/omg-native-coverage
visudo -cf /etc/sudoers.d/omg-native-coverage
created=()
trap 'for path in "${created[@]}"; do rm -f -- "$path"; done; rm -rf -- "$fixture"' EXIT
for name in omarchy-update-requires-free-space omarchy-update-confirm omarchy-update-pkg-prune \
  omarchy-snapshot omarchy-update-stay-awake omarchy-update-dev omarchy-update-keyring \
  omarchy-update-system-pkgs omarchy-migrate omarchy-restart-shell omarchy-update-orphan-pkgs \
  omarchy-update-analyze-logs omarchy-shell omarchy-update-restart omarchy-hook \
  omarchy-update-mise omarchy-update-boot omarchy-system yay aura paru; do
  test ! -e "/usr/bin/$name" && test ! -L "/usr/bin/$name"
  install -m 755 "$fixture/stage" "/usr/bin/$name"
  created+=("/usr/bin/$name")
done
case_root=/var/tmp/omg-extra-nobody/omarchy
install -d -m 700 -o nobody -g nobody "$case_root"
ip link set lo up
python3 -m http.server 18080 --bind 127.0.0.1 --directory /opt > "$fixture/repository-server.log" 2>&1 &
repository_server=$!
trap 'kill "$repository_server"; wait "$repository_server" || true; for path in "${created[@]}"; do rm -f -- "$path"; done; rm -rf -- "$fixture"' EXIT
for ((attempt=0; attempt<50; attempt++)); do
  if python3 -c 'import socket; socket.create_connection(("127.0.0.1", 18080), 1).close()' 2>/dev/null; then break; fi
  kill -0 "$repository_server"
  sleep 0.1
done
for stage in OMARCHY_STAGE_NAMES; do
  case_dir="$case_root/$stage"
  install -d -m 700 -o nobody -g nobody "$case_dir" "$case_dir/config" "$case_dir/run" \
    "$case_dir/db" "$case_dir/db/local" "$case_dir/db/sync" "$case_dir/migrations" \
    "$case_dir/checkout/bin" "$case_dir/checkout/migrations"
  printf 'telemetry_enabled = false\n[aur]\nsecurity_profile = "standard"\n' > "$case_dir/config/config.toml"
  signed_owner="/opt/omg-coverage-$stage"
  python3 /native-cli-coverage.py signed-fixture --owner "$signed_owner"
  sed -i "s|file://$signed_owner/repos/|http://127.0.0.1:18080/${signed_owner##*/}/repos/|g" "$signed_owner/pacman.conf"
  cp "$signed_owner/pacman.conf" "$case_dir/pacman.conf"
  mount --bind "$signed_owner/pacman.conf" /etc/pacman.conf
  if test "$stage" = omarchy-vendor-failure; then
    printf 'invalid database signature\n' > "$signed_owner/repos/core/core.db.sig"
  fi
  printf 'LLVM_PROFILE_FILE=/profiles/native-root/omg-extra-%s-%%p-%%m.profraw\n' "$stage" > /etc/omg-native-coverage.env
  chmod 600 /etc/omg-native-coverage.env
  : > "$case_dir/helpers.tsv"
  printf '#!/bin/bash\nexit 88\n' > "$case_dir/checkout/bin/omarchy-migrate"
  chmod 755 "$case_dir/checkout/bin/omarchy-migrate"
  chown -R nobody:nobody "$case_dir"
  rm -f "$fixture/runtime/migrations/1.sh"
  case "$stage" in
    omarchy-success)
      printf 'omarchy-pkg-aur-add forbidden-home-fixture\n' > "$case_dir/checkout/migrations/1.sh"
      ;;
    omarchy-migration-refusal)
      printf 'omarchy-pkg-aur-add forbidden-installed-fixture\n' > "$fixture/runtime/migrations/1.sh"
      ;;
  esac
  args=(--yes)
  extra=()
  case "$stage" in
    omarchy-declined) args=() ;;
    omarchy-unsupported-mode) args=(--fast) ;;
    omarchy-invalid-transport) extra=(OMG_OMARCHY_LOCK_FD=999999) ;;
  esac
  if test "$stage" = omarchy-optional-failures; then
    for name in omarchy-snapshot omarchy-restart-shell omarchy-update-mise omarchy-update-confirm; do
      test -f "/usr/bin/$name" && test ! -L "/usr/bin/$name"
      if mountpoint -q "/usr/bin/$name"; then
        printf 'Refusing mounted optional fixture helper: %s\n' "$name" >&2
        exit 1
      fi
      mv "/usr/bin/$name" "$fixture/saved/$name"
      ln -s "$fixture/foreign/bin/$name" "/usr/bin/$name"
      test "$(readlink -e "/usr/bin/$name")" = "$fixture/foreign/bin/$name"
      test "$(stat -c '%u:%a' "$fixture/foreign/bin/$name")" = 0:755
    done
  fi
  scene=none
  authorization=
  stage_timeout=40
  authorization_job=
  reboot_answer=
  absent_helper=
  case "$stage" in
OMARCHY_CASE_SETUP
  esac
  if test -n "$absent_helper"; then
    test -f "/usr/bin/$absent_helper" && test ! -L "/usr/bin/$absent_helper"
    test ! -e "$fixture/saved/$absent_helper"
    mv "/usr/bin/$absent_helper" "$fixture/saved/$absent_helper"
  fi
  launch=(bash -c 'test "$(id -u)" -ne 0; test -z "${OMG_TEST_MODE+x}"; test -z "${CARGO_PRIMARY_PACKAGE+x}"; exec /omg-extra-bin/cli update "$@"' bash "${args[@]}")
  if test -n "$reboot_answer"; then
    install -d -m 700 -o nobody -g nobody "$case_dir/.local/state/omarchy"
    touch "$case_dir/.local/state/omarchy/reboot-required"
    chown nobody:nobody "$case_dir/.local/state/omarchy/reboot-required"
    launch=(python3 "$fixture/attended.py" "$reboot_answer")
  fi
  if test -n "$authorization"; then
    printf 'Defaults logfile="/evidence/cli/%s-authorization.log"\nDefaults log_denied\n' "$stage" > /etc/sudoers.d/zz-omg-authorization-log
    chmod 440 /etc/sudoers.d/zz-omg-authorization-log
    visudo -cf /etc/sudoers.d/zz-omg-authorization-log
    if test "$authorization" = denied; then
      (
        sleep 5
        printf 'nobody ALL=(root) NOPASSWD: !/usr/bin/true\n' > /etc/sudoers.d/zzzz-omg-authorization-denied
        chmod 440 /etc/sudoers.d/zzzz-omg-authorization-denied
        visudo -cf /etc/sudoers.d/zzzz-omg-authorization-denied
      ) &
      authorization_job=$!
    fi
  fi
  result=0
  timeout --signal=TERM --kill-after=3 "$stage_timeout" runuser -u nobody -- env -i \
    PATH=/usr/bin:/bin LANG=C.UTF-8 HOME="$case_dir" TMPDIR="$case_dir" \
    XDG_RUNTIME_DIR="$case_dir/run" XDG_CONFIG_HOME="$case_dir/config" \
    XDG_CACHE_HOME="$case_dir/cache" XDG_DATA_HOME="$case_dir/data" XDG_STATE_HOME="$case_dir/state" \
    OMG_CONFIG_DIR="$case_dir/config" OMG_CACHE_DIR="$case_dir/cache" OMG_DATA_DIR="$case_dir/data" \
    OMG_DAEMON_DATA_DIR="$case_dir/daemon" OMG_DISABLE_DAEMON=1 OMG_DISABLE_TELEMETRY=1 \
    OMG_PACMAN_CONF="$case_dir/pacman.conf" OMG_PACMAN_DB_DIR="$signed_owner/db" \
    OMARCHY_PATH="$case_dir/checkout" OMARCHY_MIGRATION_STATE="$case_dir/migrations" \
    OMARCHY_FIXTURE_CASE="$stage" OMARCHY_FIXTURE_SCENE="$scene" OMARCHY_HELPER_TRACE="$case_dir/helpers.tsv" \
    LLVM_PROFILE_FILE="/profiles/omg-extra-$stage-%p-%m.profraw" "${extra[@]}" \
    "${launch[@]}" < /dev/null > "/evidence/cli/$stage.log" 2>&1 || result=$?
  if test -n "$authorization"; then
    if test -n "$authorization_job"; then wait "$authorization_job"; fi
    rm -f /etc/sudoers.d/zzzz-omg-authorization-denied /etc/sudoers.d/zz-omg-authorization-log
    python3 - "$stage" "$authorization" <<'OMG_AUTHORIZATION_RECEIPT'
import hashlib, json, runpy, stat, sys
from pathlib import Path
stage, expected = sys.argv[1:]
path = Path('/evidence/cli') / (stage + '-authorization.log')
metadata = path.lstat()
assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
producer = runpy.run_path('/native-cli-coverage.py', run_name='authorization_fixture')
receipt = producer['authorization_audit'](path.read_text())
assert receipt['denied'] == (expected == 'denied'), 'Real sudo refusal differs from the selected control'
receipt.update(log_uid=metadata.st_uid, log_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
path.with_suffix('.json').write_text(json.dumps(receipt)+'\n')
OMG_AUTHORIZATION_RECEIPT
  fi
  for profile in /profiles/native-root/omg-extra-*.profraw; do
    test -f "$profile" || continue
    test "$(stat -c %u "$profile")" = 0
    mv "$profile" /profiles/
  done
  if test -n "$absent_helper"; then
    test ! -e "/usr/bin/$absent_helper" && test ! -L "/usr/bin/$absent_helper"
    mv "$fixture/saved/$absent_helper" "/usr/bin/$absent_helper"
    cmp "$fixture/stage" "/usr/bin/$absent_helper"
    printf 'absent helper restored after genuine CLI execution\n' > "/evidence/cli/$stage-layout.txt"
  fi
  case "$stage" in
    OMARCHY_COMMITTED_CASES)
    python3 /native-cli-coverage.py verify-signed-fixture --owner "$signed_owner" \
      > "/evidence/cli/$stage-native-state.json" ;;
  esac
  if test "$stage" = omarchy-optional-failures; then
    for name in omarchy-snapshot omarchy-restart-shell omarchy-update-mise omarchy-update-confirm; do
      test -L "/usr/bin/$name"
      test "$(readlink -e "/usr/bin/$name")" = "$fixture/foreign/bin/$name"
      rm -- "/usr/bin/$name"
      mv "$fixture/saved/$name" "/usr/bin/$name"
      test -f "/usr/bin/$name" && test ! -L "/usr/bin/$name"
      cmp "$fixture/stage" "/usr/bin/$name"
    done
    test ! -e "$case_dir/helpers.tsv.unexpected"
    printf 'foreign optional helpers never executed; original helpers restored\n' > "/evidence/cli/$stage-layout.txt"
  fi
  if test -n "$reboot_answer"; then
    cp "$case_dir/interaction.json" "/evidence/cli/$stage-interaction.json"
  fi
  printf '%s\n' "$result" > "/evidence/cli/$stage-exit.txt"
  cp "$case_dir/helpers.tsv" "/evidence/cli/$stage-helpers.tsv"
  if test -f "$case_dir/run/omarchy-update.lock"; then
    flock --nonblock "$case_dir/run/omarchy-update.lock" true
    test "$(stat -c '%u:%a' "$case_dir/run/omarchy-update.lock")" = "$(id -u nobody):600"
    test "$(stat -c '%u:%a' /tmp/omarchy-update.log)" = "$(id -u nobody):600"
    test -s /tmp/omarchy-update.log
    cp /tmp/omarchy-update.log "/evidence/cli/$stage-transcript.log"
    printf 'released private lock; owned transcript mode=600\n' > "/evidence/cli/$stage-coordination.txt"
  fi
  printf '%s\t0\n' "$stage" >> /evidence/cli/process-checks.tsv
done
OMG_OMARCHY_NAMESPACE
'''
    setup = '\n'.join(
        f'    {shlex.quote(stage)}) scene={shlex.quote(case.scene)}; '
        f'absent_helper={shlex.quote(case.absent_helper or "")}; '
        f'reboot_answer={shlex.quote(case.reboot_answer or "")}; '
        f'authorization={shlex.quote(case.authorization or "")}; '
        f'stage_timeout={95 if case.authorization else 40} ;;'
        for stage, case in OMARCHY_CASES.items())
    return (script.replace('OMARCHY_STAGE_NAMES', ' '.join(map(shlex.quote, OMARCHY_CASES)))
            .replace('OMARCHY_CASE_SETUP', setup)
            .replace('OMARCHY_COMMITTED_CASES', '|'.join(shlex.quote(stage)
                     for stage, case in OMARCHY_CASES.items() if case.native_committed)))


def guest_script(artifacts, compiled_cli):
    quote = shlex.quote
    receipt = json.dumps(dict(original=compiled_cli, copy='/omg-extra-bin/cli', sha256=artifacts['cli']['sha256']))
    artifact_lines = '\n'.join(f"{item['sha256']}  /omg-extra-bin/{role}" for role, item in artifacts.items()) + '\n'
    selection = '\n'.join('\t'.join(row) for row in CASES) + '\n'
    script = r'''set -euo pipefail
test "$(id -u)" = 0
test -f /etc/arch-release
. /etc/os-release
test "$ID" = arch
test "$(uname -m)" = x86_64
test "$(id -u nobody)" -ne 0
test "$(stat -c '%u:%a' /omg-extra-bin)" = 0:755
install -d -m 755 /evidence/cli
test "$(stat -c '%u:%a' /profiles)" = 0:1777
! compgen -G '/profiles/omg-extra-*.profraw'
install -d -m 755 -o nobody -g nobody /evidence/cli/inventory
install -d -m 700 -o nobody -g nobody /var/tmp/omg-extra-nobody
install -d -m 700 /var/tmp/omg-extra-root /var/tmp/omg-extra-root/data
printf '%s' RECEIPT > /omg-extra-bin/cli-receipt.json
chmod 644 /omg-extra-bin/cli-receipt.json
test "$(stat -c '%u:%a' /omg-extra-bin)" = 0:755
printf '%s' ARTIFACTS > /evidence/cli/artifacts.sha256
sha256sum -c /evidence/cli/artifacts.sha256 > /evidence/cli/artifact-check.txt
printf '%s' SELECTION > /evidence/cli/expected-tests.tsv
for role in cli daemon coverage14 arch-contracts comprehensive cli-unit; do
  test "$(stat -c '%u:%a' "/omg-extra-bin/$role")" = 0:755
  ldd "/omg-extra-bin/$role" > "/evidence/cli/abi-$role.txt" 2>&1
  ! grep -F 'not found' "/evidence/cli/abi-$role.txt"
done
getconf GNU_LIBC_VERSION > /evidence/cli/libc.txt
pacman -Q pacman libarchive > /evidence/cli/native-library-versions.txt
ln /omg-extra-bin/cli /omg-extra-bin/omg
ln /omg-extra-bin/daemon /omg-extra-bin/omgd
test "$(stat -c '%d:%i' /omg-extra-bin/cli)" = "$(stat -c '%d:%i' /omg-extra-bin/omg)"
test "$(stat -c '%d:%i' /omg-extra-bin/daemon)" = "$(stat -c '%d:%i' /omg-extra-bin/omgd)"
uname -a > /evidence/cli/kernel.txt
cat /proc/sys/kernel/random/boot_id > /evidence/cli/boot-id.txt
printf 'actual_id=%s ordinary_uid=%s root_uid=%s\n' "$ID" "$(id -u nobody)" "$(id -u)" > /evidence/cli/identity.txt
fingerprint_db() {
  printf 'scope=/var/lib/pacman exclusions=atime-only\n'
  find /var/lib/pacman -xdev -printf '%P\t%y\t%m\t%U\t%G\t%s\t%T@\t%C@\t%l\n' | LC_ALL=C sort
  find /var/lib/pacman -xdev -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
}
fingerprint_db > /evidence/cli/db-before.txt
trap 'fingerprint_db > /evidence/cli/db-after.txt' EXIT
unshare --mount --net --fork bash -s <<'OMG_EXTRA_NAMESPACE'
set -euo pipefail
mount --make-rprivate /
ip link set lo up
test "$(ip -o link show | wc -l)" = 1
ip -o link show | grep -E '^[0-9]+: lo:' > /evidence/cli/network.txt
mount -t tmpfs -o nosuid,nodev,noexec,mode=755 tmpfs /var/log
ordinary() {
  runuser -u nobody -- env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
    HOME=/var/tmp/omg-extra-nobody TMPDIR=/var/tmp/omg-extra-nobody \
    XDG_CONFIG_HOME=/var/tmp/omg-extra-nobody/config XDG_CACHE_HOME=/var/tmp/omg-extra-nobody/cache \
    XDG_DATA_HOME=/var/tmp/omg-extra-nobody/data XDG_STATE_HOME=/var/tmp/omg-extra-nobody/state \
    XDG_RUNTIME_DIR=/var/tmp/omg-extra-nobody/run \
    OMG_CONFIG_DIR=/var/tmp/omg-extra-nobody/config/omg OMG_CACHE_DIR=/var/tmp/omg-extra-nobody/cache/omg \
    OMG_DATA_DIR=/var/tmp/omg-extra-nobody/data/omg OMG_DAEMON_DATA_DIR=/var/tmp/omg-extra-nobody/daemon \
    OMG_DISABLE_TELEMETRY=1 OMG_DISABLE_DAEMON=1 \
    OMG_CONTRACT_REQUIRE_NATIVE_ARCH=1 OMG_CONTRACT_EXPECTED_CLI=COMPILED_CLI \
    OMG_CONTRACT_CLI_ROOT_FIXTURE=/omg-extra-bin/cli-receipt.json \
    OMG_CLI_BEHAVIOR_EVIDENCE_DIR=/evidence/cli/inventory "$@"
}
ordinary bash -c 'test "$(id -u)" -ne 0; umask 077; mkdir -p "$HOME/work" "$XDG_RUNTIME_DIR" "$OMG_CONFIG_DIR"; printf "telemetry_enabled = false\n" > "$OMG_CONFIG_DIR/config.toml"'
ordinary bash -c 'missing=0; for tool in git make jq cmp; do if ! command -v "$tool"; then printf "Missing native fixture command: %s\n" "$tool" >&2; missing=1; fi; done; exit "$missing"' > /evidence/cli/prerequisites.txt
for role in coverage14 arch-contracts comprehensive cli-unit; do
  LLVM_PROFILE_FILE="/profiles/omg-extra-registry-$role-%p-%m.profraw" \
    /omg-extra-bin/"$role" --list --format terse > /evidence/cli/registry-"$role".txt 2>&1
done
while IFS=$'\t' read -r stage role name; do
  registry=/evidence/cli/registry-$role.txt
  test "$(grep -Fxc "$name: test" "$registry")" = 1
  log=/evidence/cli/$stage.log
  if test "$role" = cli-unit; then
    timeout --signal=TERM --kill-after=3 45 env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
      HOME=/var/tmp/omg-extra-root OMG_DATA_DIR=/var/tmp/omg-extra-root/data OMG_NATIVE_TEST_DATA_DIR=1 \
      OMG_DISABLE_TELEMETRY=1 LLVM_PROFILE_FILE="/profiles/omg-extra-$stage-%p-%m.profraw" \
      bash -c 'cd "$HOME"; test "$(id -u)" = 0; printf "[extra-root-test] uid=%s\n" "$(id -u)"; exec "$@"' \
      bash /omg-extra-bin/"$role" "$name" --exact --nocapture --test-threads=1 < /dev/null > "$log" 2>&1
  else
    limit=45
    if test "$role" = comprehensive; then limit=360; fi
    timeout --signal=TERM --kill-after=3 "$limit" \
      bash -c 'ordinary env LLVM_PROFILE_FILE="$1" bash -c '\''cd "$HOME/work"; test "$(id -u)" -ne 0; exec "$@"'\'' bash "$2" "$3" --exact --nocapture --test-threads=1' \
      bash "/profiles/omg-extra-$stage-%p-%m.profraw" "/omg-extra-bin/$role" "$name" < /dev/null > "$log" 2>&1
  fi
  grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$log"
  ! grep -E '\[omg-skip\]|\[native-arch-fixture-skip\]|\[native-inventory-unavailable\]|LLVM Profile (Error|Warning)' "$log"
  if test "$role" != cli-unit; then
    grep -Eq '\[native-arch-fixture\] uid=[1-9][0-9]* actual_id=arch' "$log"
  fi
  printf '%s\t%s\t%s\tPASS\n' "$stage" "$role" "$name" >> /evidence/cli/passed.tsv
done < /evidence/cli/expected-tests.tsv
for flags in q v vv vvv; do
  ordinary env LLVM_PROFILE_FILE="/profiles/omg-extra-cli-$flags-%p-%m.profraw" \
    bash -c 'cd "$HOME/work"; test -z "${RUST_LOG+x}"; exec /omg-extra-bin/cli "-$1" config' bash "$flags" \
    > /evidence/cli/cli-"$flags".log 2>&1
  printf 'cli-%s\t0\n' "$flags" >> /evidence/cli/process-checks.tsv
done
ordinary env LLVM_PROFILE_FILE='/profiles/omg-extra-daemon-%p-%m.profraw' RUST_LOG='[' \
  timeout --signal=TERM --kill-after=3 40 bash -c '
    set -euo pipefail
    test "$(id -u)" -ne 0
    cd "$HOME/work"
    socket="$XDG_RUNTIME_DIR/extra.sock"
    /omg-extra-bin/daemon --socket "$socket" &
    child=$!
    trap '\''kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true'\'' EXIT
    ready=0
    for ((i=0;i<100;i++)); do
      kill -0 "$child"
      if test -S "$socket"; then ready=1; break; fi
      sleep 0.1
    done
    test "$ready" = 1
    test "$(stat -c %u "$socket")" = "$(id -u)"
    printf "[extra-daemon] startup_socket=ready uid=%s\n" "$(id -u)"
    kill -TERM "$child"
    wait "$child"
    test ! -e "$socket"
    trap - EXIT
    printf "[extra-daemon] sigterm_exit=0 socket_removed=yes\n"
  ' > /evidence/cli/daemon.log 2>&1
printf 'daemon\t0\n' >> /evidence/cli/process-checks.tsv
OMARCHY_CASE_BODY
OMG_EXTRA_NAMESPACE
fingerprint_db > /evidence/cli/db-after.txt
cmp /evidence/cli/db-before.txt /evidence/cli/db-after.txt
trap - EXIT
printf 'PASS\n' > /evidence/cli/all-stages-pass.txt
'''
    script = script.replace('RECEIPT', quote(receipt)).replace('ARTIFACTS', quote(artifact_lines))
    script = script.replace('SELECTION', quote(selection)).replace('COMPILED_CLI', quote(compiled_cli))
    script = script.replace('OMARCHY_CASE_BODY', omarchy_guest_script())
    # The timeout shell inherits this function, never a caller-supplied environment.
    script = script.replace('ordinary bash -c', 'export -f ordinary\nordinary bash -c', 1)
    return script


def validate_evidence(evidence, profiles, artifacts, commit):
    require(evidence.is_dir() and not evidence.is_symlink(), 'Unsafe supplemental evidence directory')
    evidence_files = list(evidence.rglob('*'))
    require(len(evidence_files) <= 8192, 'Supplemental evidence has too many files')
    for path in evidence_files:
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), 'Unsafe evidence member')
        require(not path.is_file() or path.stat().st_size <= 16 * 1024 ** 2,
                'Supplemental evidence member exceeds 16 MiB')
    require((evidence / 'all-stages-pass.txt').read_text() == 'PASS\n', 'Guest did not complete every stage')
    expected = ['\t'.join(row) for row in CASES]
    require((evidence / 'expected-tests.tsv').read_text().splitlines() == expected, 'Guest selection mismatch')
    require((evidence / 'passed.tsv').read_text().splitlines() == [row + '\tPASS' for row in expected], 'Incomplete/reordered tests')
    require((evidence / 'process-checks.tsv').read_text().splitlines() == [s + '\t0' for s in PROCESS_STAGES], 'Process checks incomplete')
    require((evidence / 'db-before.txt').read_bytes() == (evidence / 'db-after.txt').read_bytes(), 'Real guest package DB changed')
    require(re.fullmatch(r'actual_id=arch ordinary_uid=[1-9][0-9]* root_uid=0\n', (evidence / 'identity.txt').read_text()), 'Guest UID/distro identity differs')
    require((evidence / 'artifacts.sha256').read_text().splitlines() == [f"{a['sha256']}  /omg-extra-bin/{r}" for r, a in artifacts.items()], 'Guest artifact hash receipt mismatch')
    for role in ROLES:
        require('not found' not in (evidence / f'abi-{role}.txt').read_text(), 'Missing ABI dependency')
    grouped = {stage: [] for stage in STAGES}
    selected_profiles = list(profiles.glob('omg-extra-*.profraw'))
    require(len(selected_profiles) <= 8192, 'Supplemental profiles have too many files')
    for path in selected_profiles:
        match = PROFILE.fullmatch(path.name)
        require(match and path.is_file() and not path.is_symlink()
                and 0 < path.stat().st_size <= 64 * 1024 ** 2, 'Unsafe or empty raw profile')
        with path.open('rb') as raw:
            require(raw.read(8) == bytes.fromhex('8172666f72706cff'), 'Not an x86_64 LLVM raw profile')
        grouped[match[1]].append(path)
    require(all(grouped.values()), 'One or more stages have no raw profiles')
    require(sum(p.stat().st_size for rows in grouped.values() for p in rows) <= 512 * 1024 ** 2,
            'Supplemental profiles exceed the 512 MiB return budget')
    cli_modules = {PROFILE.fullmatch(p.name)[3] for p in grouped['cli-q']}
    require(len(cli_modules) == 1, 'Safe CLI identity must produce one module signature')
    suite = ET.Element('testsuite', name='extra-native-coverage', tests=str(len(CASES)))
    tests = []
    for stage, role, name in CASES:
        require((evidence / f'registry-{role}.txt').read_text().splitlines().count(name + ': test') == 1, 'Test registry mismatch')
        log = (evidence / f'{stage}.log').read_text()
        require(len(re.findall(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', log, re.M)) == 1, 'Test not exactly one PASS')
        require(len(re.findall(r'^test ' + re.escape(name) + r' \.\.\.', log, re.M)) == 1, 'Selected test execution missing/duplicated')
        require(not re.search(r'\[omg-skip\]|\[native-arch-fixture-skip\]|\[native-inventory-unavailable\]|LLVM Profile (Error|Warning)', log), 'Skip/LLVM diagnostic')
        modules = {PROFILE.fullmatch(p.name)[3] for p in grouped[stage]}
        if role != 'cli-unit':
            require(re.search(r'\[native-arch-fixture\] uid=[1-9][0-9]* actual_id=arch', log), 'Missing native ordinary admission')
            require(cli_modules <= modules and len(modules) >= 2, 'Missing matching child CLI/harness raw profiles')
        else:
            require('[extra-root-test] uid=0' in log, 'Root receiver branch not admitted')
        ET.SubElement(suite, 'testcase', name=name, classname=role)
        tests.append(dict(stage=stage, role=role, name=name, result='PASS'))
    inventory = (evidence / 'test-13.log').read_text()
    require('[native-inventory-coverage] unavailable_rows=0;' in inventory, 'Inventory native rows unavailable')
    rows = (evidence / 'inventory/index.tsv').read_text().splitlines()
    for name in ('why', 'why-reverse', 'size', 'size-tree', 'blame'):
        matches = [line.split('\t') for line in rows[1:] if line.split('\t')[0] == name]
        require(len(matches) == 1 and matches[0][3] == matches[0][4] and matches[0][-2] == 'none'
                and matches[0][-1] != 'unavailable', 'Missing/failed native inventory row: ' + name)
    daemon = (evidence / 'daemon.log').read_text()
    require('[extra-daemon] startup_socket=ready uid=' in daemon and '[extra-daemon] sigterm_exit=0 socket_removed=yes' in daemon, 'Daemon lifecycle incomplete')
    for stage, case in OMARCHY_CASES.items():
        status, helpers = case.exit_status, case.helpers
        require((evidence / f'{stage}-exit.txt').read_text() == f'{status}\n',
                'Omarchy CLI exit status differs: ' + stage)
        require((evidence / f'{stage}-helpers.tsv').read_text().splitlines() == list(helpers),
                'Omarchy helper execution differs: ' + stage)
        modules = {PROFILE.fullmatch(p.name)[3] for p in grouped[stage]}
        require(modules == cli_modules, 'Omarchy profiles do not match the actual CLI: ' + stage)
        log = (evidence / f'{stage}.log').read_text()
        if helpers:
            require((evidence / f'{stage}-coordination.txt').read_text()
                    == 'released private lock; owned transcript mode=600\n',
                    'Omarchy coordination cleanup differs: ' + stage)
            transcript = (evidence / f'{stage}-transcript.log').read_text()
            require(transcript.startswith('OMG Omarchy update started\n')
                    and '\nOMG Omarchy update finished: ' in transcript,
                    'Omarchy has no complete genuine PTY transcript: ' + stage)
        if case.native_committed:
            require(json.loads((evidence / f'{stage}-native-state.json').read_text())['status']
                    == 'PASS_SIGNED_NATIVE_STATE', 'Missing committed native package state')
            require('up to date' in log.lower(),
                    'Native OMG AUR did not complete: ' + stage)
        if case.authorization:
            observation = authorization_audit((evidence / f'{stage}-authorization.log').read_text())
            require(observation['denied'] == (case.authorization == 'denied'),
                    'Real sudo refresh result differs: ' + stage)
            observation.update(log_uid=0, log_sha256=sha(evidence / f'{stage}-authorization.log'))
            refresh = json.loads((evidence / f'{stage}-authorization.json').read_text())
            require(refresh == observation, 'Real authorization audit differs: ' + stage)
            if case.authorization == 'denied':
                require('Omarchy update authorization refresh stopped' in log,
                        'Authorization refusal was not visible')
        if case.reboot_answer:
            interaction = json.loads((evidence / f'{stage}-interaction.json').read_text())
            require(interaction == dict(prompt_observed=True, answer=case.reboot_answer,
                                        resize_sent=1, cli_exit_code=case.exit_status),
                    'Attended reboot interaction differs: ' + stage)
            require('Reboot now?' in log, 'Attended CLI did not show its reboot prompt')
            if case.scene == 'reboot-failure':
                require('Omarchy reboot failed' in log, 'Reboot helper failure was hidden')
        if case.absent_helper:
            require((evidence / f'{stage}-layout.txt').read_text()
                    == 'absent helper restored after genuine CLI execution\n',
                    'Missing helper was not restored: ' + stage)
        if stage == 'omarchy-required-helper-missing':
            require('omarchy-update-dev' in log and 'Omarchy update did not complete' in log,
                    'Missing required helper was not reported')
        if stage == 'omarchy-optional-failures':
            require((evidence / f'{stage}-layout.txt').read_text()
                    == 'foreign optional helpers never executed; original helpers restored\n',
                    'Optional Omarchy helper layout exclusion differs')
            require('snapshot' in log.lower() and 'mise' in log.lower(),
                    'Optional Omarchy update failures were not visible: ' + stage)
        elif stage == 'omarchy-vendor-failure':
            require('Omarchy update did not complete' in log, 'Missing vendor failure diagnostic')
        elif stage == 'omarchy-migration-refusal':
            require('external package helper' in log, 'Missing native package migration refusal')
        elif stage == 'omarchy-unsupported-mode':
            require('complete update lifecycle' in log, 'Unsupported Omarchy scope accepted')
        elif stage == 'omarchy-invalid-transport':
            require('Incomplete Omarchy update transport' in log, 'Incomplete transport accepted')
    for path in evidence.rglob('*'):
        if path.is_file():
            require(not re.search(rb'LLVM Profile (Error|Warning)', path.read_bytes()), 'LLVM runtime diagnostic in evidence')
    ET.ElementTree(suite).write(evidence / 'tests.xml', encoding='unicode', xml_declaration=True)
    selected = sorted(path for paths in grouped.values() for path in paths)
    (evidence / 'verification.json').write_text(json.dumps(dict(source_commit=commit, tests=tests,
        process_checks=list(PROCESS_STAGES), artifacts=artifacts,
        profiles=[dict(name=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in selected]), indent=2) + '\n')
    return selected


def prepare(target, commit):
    require(re.fullmatch(r'[0-9a-f]{40}', commit), 'Expected a full source commit')
    target = target.resolve(strict=True)
    require(target.is_dir(), 'Coverage target is absent')
    paths = {'cli': target / 'debug/omg', 'daemon': target / 'debug/omgd'}
    for role, prefix in (('coverage14', 'coverage_14'), ('arch-contracts', 'arch_cli_contracts'),
                         ('comprehensive', 'cli_comprehensive'), ('cli-unit', 'omg')):
        matches = [path for path in (target / 'debug/deps').glob(prefix + '-*')
                   if re.fullmatch(re.escape(prefix) + r'-[0-9a-f]{16}', path.name)
                   and path.is_file() and not path.is_symlink() and os.access(path, os.X_OK)
                   and not path.samefile(paths['cli'])]
        require(len(matches) == 1, 'Expected exactly one instrumented harness for ' + role)
        paths[role] = matches[0]
    require(len({(path.stat().st_dev, path.stat().st_ino) for path in paths.values()}) == len(ROLES),
            'Supplemental artifact roles must be distinct')
    artifacts = {}
    for role, path in paths.items():
        require(path.resolve(strict=True) == path and path.is_relative_to(target),
                'Artifact source escapes the canonical coverage target: ' + role)
        require(path.is_file() and not path.is_symlink() and os.access(path, os.X_OK),
                'Unsafe or absent artifact: ' + role)
        require(0 < path.stat().st_size <= 512 * 1024 ** 2, 'Artifact size exceeds bound: ' + role)
        sections = subprocess.run(['readelf', '--wide', '--section-headers', str(path)],
                                  check=True, capture_output=True, text=True, timeout=30).stdout
        require('__llvm_covmap' in sections and '__llvm_prf' in sections,
                'Artifact lacks LLVM instrumentation: ' + role)
        artifacts[role] = dict(path=str(path), sha256=sha(path), bytes=path.stat().st_size)
    return dict(source_commit=commit, producer_sha256=sha(Path(__file__)), artifacts=artifacts)


def read_manifest(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
            'Unsafe or oversized supplemental manifest')
    value = json.loads(path.read_text())
    require(set(value) == {'source_commit', 'producer_sha256', 'artifacts'}, 'Unknown manifest schema')
    require(re.fullmatch(r'[0-9a-f]{40}', value['source_commit']), 'Invalid source identity')
    require(value['producer_sha256'] == sha(Path(__file__)), 'Producer source changed after admission')
    require(set(value['artifacts']) == set(ROLES), 'Supplemental artifacts are incomplete')
    for role, artifact in value['artifacts'].items():
        require(set(artifact) == {'path', 'sha256', 'bytes'}, 'Unknown artifact schema: ' + role)
        require(Path(artifact['path']).is_absolute(), 'Artifact source path must be absolute')
        require(re.fullmatch(r'[0-9a-f]{64}', artifact['sha256']), 'Invalid artifact digest')
        require(type(artifact['bytes']) is int and 0 < artifact['bytes'] <= 512 * 1024 ** 2,
                'Invalid artifact byte bound')
    return value


def validate_artifact_copies(directory, artifacts):
    for role, artifact in artifacts.items():
        path = directory / role
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == artifact['bytes']
                and os.access(path, os.X_OK) and sha(path) == artifact['sha256'],
                'Copied artifact identity differs: ' + role)


def run_guest(manifest):
    require(os.geteuid() == 0, 'Supplemental execution requires a disposable root guest')
    directory = Path('/omg-extra-bin')
    paths = [directory, Path(__file__), Path('/native-cli-manifest.json')]
    paths += [directory / role for role in ROLES]
    for path in paths:
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
                'Supplemental input is writable or not root-owned: ' + str(path))
    validate_artifact_copies(directory, manifest['artifacts'])
    script = guest_script(manifest['artifacts'], manifest['artifacts']['cli']['path'])
    subprocess.run(['bash', '-euo', 'pipefail', '-c', script], check=True, timeout=660)
    for role, artifact in manifest['artifacts'].items():
        require(sha(directory / role) == artifact['sha256'], 'Artifact changed during execution: ' + role)
    validate_evidence(Path('/evidence/cli'), Path('/profiles'), manifest['artifacts'], manifest['source_commit'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    admission = commands.add_parser('prepare')
    admission.add_argument('--target', required=True, type=Path)
    admission.add_argument('--source-commit', required=True)
    admission.add_argument('--output', required=True, type=Path)
    commands.add_parser('run')
    signed = commands.add_parser('signed-fixture')
    signed.add_argument('--owner', required=True, type=Path)
    signed_check = commands.add_parser('verify-signed-fixture')
    signed_check.add_argument('--owner', required=True, type=Path)
    extraction = commands.add_parser('unpack')
    extraction.add_argument('--archive', required=True, type=Path)
    extraction.add_argument('--directory', required=True, type=Path)
    mapping = commands.add_parser('controller-path')
    mapping.add_argument('--path', required=True)
    verification = commands.add_parser('verify')
    verification.add_argument('--manifest', required=True, type=Path)
    verification.add_argument('--evidence', required=True, type=Path)
    verification.add_argument('--profiles', required=True, type=Path)
    args = parser.parse_args()
    if args.operation == 'prepare':
        value = prepare(args.target, args.source_commit)
        with args.output.open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.write('\n')
    elif args.operation == 'signed-fixture':
        create_signed_fixture(args.owner)
    elif args.operation == 'verify-signed-fixture':
        print(json.dumps(verify_signed_fixture(args.owner)))
    elif args.operation == 'unpack':
        unpack_evidence(args.archive, args.directory)
    elif args.operation == 'controller-path':
        metadata = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(metadata) <= 1024 * 1024, 'Docker mount metadata exceeds its bound')
        print(controller_bind_path(args.path, json.loads(metadata)))
    elif args.operation == 'run':
        run_guest(read_manifest(Path('/native-cli-manifest.json')))
    else:
        manifest = read_manifest(args.manifest)
        validate_evidence(args.evidence, args.profiles, manifest['artifacts'], manifest['source_commit'])


if __name__ == '__main__':
    main()

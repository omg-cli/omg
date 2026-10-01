#!/usr/bin/env python3
"""Install a pinned macOS nextest with a separate, authenticated source route.

Release checksum: https://github.com/nextest-rs/nextest/releases/tag/cargo-nextest-0.9.143
The same archive hash is in install-action's nextest.json at e67fa11c4b9316fa714ddf0abed07a0c3143b95b.
Registry source checksum: https://crates.io/api/v1/crates/cargo-nextest/0.9.143
The packaged source VCS commit differs from the release tag; equivalence is not
claimed. Its own exact archive, manifest and lockfile are the source contract.
Cargo --locked behavior: https://doc.rust-lang.org/cargo/commands/cargo-install.html
Curl transfer codes: https://curl.se/libcurl/c/libcurl-errors.html
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import subprocess
import tarfile
import time

VERSION = '0.9.143'
RELEASE_URL = ('https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.143/'
               'cargo-nextest-0.9.143-universal-apple-darwin.tar.gz')
RELEASE_SHA = '4830d430411148d17602a75cc880bfb4dc8dac153dea59a48a2ef4cc93577f07'
RELEASE_BINARY_SHA = '0834e83a817f56160c002f739fa81e3f06e6ac58d02f80ed5d6503468d846b0c'
REGISTRY_URL = 'https://static.crates.io/crates/cargo-nextest/cargo-nextest-0.9.143.crate'
REGISTRY_SHA = '82c78e1bf2be79fd08f8665d9760dd9f954e4c62ae5d8d08f70a1741347a295b'
LOCK_SHA = 'b2962afcfaab0420b0c000f37cbe705cefe33dba34def74139f68fd5114d1cc5'
MANIFEST_SHA = '13ae6384cdafc867d7ab694db14d4bcb87189f19f135f488e413dba4baaed4dc'
SOURCE_COMMIT = 'b5c26d09f5a0b1760f0c323a91102375d3f82e3b'
RELEASE_TAG_COMMIT = '60fa45f638ffc3f35e74afa65737f45fcd32db2a'


class AdmissionError(RuntimeError):
    """A failed trust, version, process or source contract is always fatal."""


class TransferFailure(RuntimeError):
    """Only a defined unsuccessful release transfer can enter the source route."""


def require(condition, message):
    if not condition:
        raise AdmissionError(message)


def digest(path):
    checksum = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(8192):
            checksum.update(chunk)
    return checksum.hexdigest()


def admit(path, expected, maximum):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            and metadata.st_uid == os.geteuid(), f'unsafe installer artifact: {path}')
    require(0 < metadata.st_size <= maximum and digest(path) == expected,
            f'installer artifact checksum or size mismatch: {path}')


def group_exists(group):
    try:
        os.killpg(group, 0)
        return True
    except ProcessLookupError:
        return False


def finish_group(process, row):
    """Reap the leader and terminate all remaining members of its own session."""
    process.poll()
    remaining = group_exists(process.pid)
    row['group_remaining_at_cleanup'] = remaining
    for label, action in [('term', signal.SIGTERM), ('kill', signal.SIGKILL)]:
        if not group_exists(process.pid):
            break
        try:
            os.killpg(process.pid, action)
            row['group_' + label + '_sent'] = True
        except ProcessLookupError:
            row['group_exited_before_' + label] = True
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            process.poll()
            if not group_exists(process.pid):
                break
            time.sleep(0.05)
    process.poll()
    row['group_gone_after_cleanup'] = not group_exists(process.pid)
    require(row['group_gone_after_cleanup'], 'owned command group did not terminate')
    return remaining


class Commands:
    def __init__(self, receipts):
        self.receipts = receipts
        receipts.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.rows = []
        self.deadline = time.monotonic() + 660

    def run(self, label, argv, seconds, cwd, env=None, bounded_file=None):
        started = time.monotonic()
        seconds = min(seconds, self.deadline - started)
        require(seconds > 0, 'installer exhausted its total elapsed budget')
        row = {'label': label, 'argv': list(map(str, argv)), 'deadline_seconds': seconds,
               'started_unix': time.time()}
        output = self.receipts / (label + '.stdout')
        error = self.receipts / (label + '.stderr')
        failure = None
        with output.open('xb') as stdout, error.open('xb') as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            row['leader_pid'] = row['process_group'] = process.pid
            while process.poll() is None:
                if time.monotonic() - started >= seconds:
                    failure = 'command exceeded its elapsed deadline'
                if bounded_file and bounded_file[0].exists():
                    if bounded_file[0].stat().st_size > bounded_file[1]:
                        failure = 'command output exceeded its byte bound'
                if failure:
                    break
                time.sleep(0.05)
            try:
                remaining = finish_group(process, row)
                if remaining and failure is None:
                    failure = 'command leader finished with unfinished descendants'
            except AdmissionError as cleanup_error:
                failure = str(cleanup_error) if failure is None else failure + '; ' + str(cleanup_error)
            if process.poll() is None:
                failure = 'owned command leader did not terminate after group cleanup; ' + str(failure)
            row.update(exit=process.poll(), seconds=time.monotonic() - started,
                       controller_failure=failure)
        self.rows.append(row)
        (self.receipts / 'commands.json').write_text(json.dumps(self.rows, indent=2) + '\n')
        require(failure is None, failure)
        return row['exit'], output, error


def download(commands, label, url, destination):
    code, _, error = commands.run(label, [
        'curl', '--proto', '=https', '--tlsv1.2', '--fail', '--location',
        '--silent', '--show-error', '--connect-timeout', '15', '--max-time', '60',
        '--max-filesize', str(32 * 1024 * 1024), '--output', str(destination), url,
    ], 75, destination.parent, bounded_file=(destination, 32 * 1024 * 1024))
    if code == 0:
        return
    diagnostic = error.read_text(errors='replace')
    recoverable = code in {6, 7, 18, 28, 52, 56}
    recoverable |= code == 22 and bool(re.search(r'\b(?:429|500|502|503|504)\b', diagnostic))
    if recoverable:
        raise TransferFailure(f'{label} transfer failed with curl exit {code}; retained {error}')
    raise AdmissionError(f'{label} failed with curl exit {code}; retained {error}')


def release_binary(archive, destination):
    admit(archive, RELEASE_SHA, 32 * 1024 * 1024)
    with tarfile.open(archive, 'r:gz') as compressed:
        members = list(compressed)
        require(len(members) == 1 and members[0].name == 'cargo-nextest'
                and members[0].isfile() and members[0].size == 41_866_736,
                'invalid pinned macOS release member')
        source = compressed.extractfile(members[0])
        require(source is not None, 'macOS release member is unavailable')
        with source, destination.open('xb') as output:
            while chunk := source.read(8192):
                output.write(chunk)
    admit(destination, RELEASE_BINARY_SHA, 41_866_736)
    destination.chmod(0o555)


def source_tree(archive, destination):
    admit(archive, REGISTRY_SHA, 32 * 1024 * 1024)
    destination.mkdir(mode=0o700)
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as compressed:
        for count, member in enumerate(compressed, start=1):
            name = PurePosixPath(member.name)
            require(count <= 5000 and not name.is_absolute()
                    and '..' not in name.parts and '\\' not in member.name
                    and name.parts[0] == 'cargo-nextest-0.9.143', 'unsafe registry member path')
            relative = Path(*name.parts[1:])
            require(str(relative) not in seen, 'duplicate registry member')
            seen.add(str(relative))
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                require(member.isfile() and 0 <= member.size <= 8 * 1024 * 1024,
                        'registry archive contains a link or oversized member')
                total += member.size
                require(total <= 32 * 1024 * 1024, 'registry source exceeds its byte bound')
                target.parent.mkdir(parents=True, exist_ok=True)
                source = compressed.extractfile(member)
                require(source is not None, 'registry source member cannot be read')
                with source, target.open('xb') as output:
                    while chunk := source.read(8192):
                        output.write(chunk)
    require(digest(destination / 'Cargo.toml') == MANIFEST_SHA, 'packaged manifest mismatch')
    require(digest(destination / 'Cargo.lock') == LOCK_SHA, 'packaged lock mismatch')
    vcs = json.loads((destination / '.cargo_vcs_info.json').read_text())
    require(vcs['git']['sha1'] == SOURCE_COMMIT, 'packaged source identity mismatch')
    return {'archive_sha256': REGISTRY_SHA, 'packaged_lock_sha256': LOCK_SHA,
            'packaged_manifest_sha256': MANIFEST_SHA, 'minimum_rust_version': '1.91',
            'packaged_source_commit': SOURCE_COMMIT, 'release_tag_commit': RELEASE_TAG_COMMIT,
            'source_matches_release_tag': False}


def select_route(release, source):
    try:
        return release(), None
    except TransferFailure as failure:
        return source(), str(failure)


def install(destination, receipts, source_only=False):
    require(platform.system() == 'Darwin' and platform.machine() in {'arm64', 'x86_64'},
            'this installer requires native macOS ARM64 or x86_64')
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    commands = Commands(receipts)
    binary = destination / 'bin' / 'cargo-nextest'
    binary.parent.mkdir(mode=0o700)
    source_receipt = None

    def from_release():
        archive = destination / 'release.tar.gz'
        download(commands, 'release-transfer', RELEASE_URL, archive)
        release_binary(archive, binary)
        return 'official-release'

    def from_source():
        nonlocal source_receipt
        archive = destination / 'registry.crate'
        download(commands, 'registry-transfer', REGISTRY_URL, archive)
        source = destination / 'registry-source'
        source_receipt = source_tree(archive, source)
        code, output, _ = commands.run('rust-version', ['rustc', '--version'], 15, destination)
        require(code == 0 and output.stat().st_size <= 4096
                and output.read_text().startswith('rustc 1.95.0 '), 'expected pinned Rust 1.95.0')
        code, _, _ = commands.run('registry-build', [
            'cargo', 'install', '--path', str(source), '--locked', '--bin', 'cargo-nextest',
            '--root', str(destination), '--target-dir', str(destination / 'build'),
        ], 480, source)
        require(code == 0, 'locked registry nextest build failed')
        require(digest(source / 'Cargo.lock') == LOCK_SHA, 'build changed its packaged lock')
        metadata = binary.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_uid == os.geteuid() and metadata.st_mode & 0o022 == 0,
                'unsafe compiled nextest executable')
        binary.chmod(0o555)
        return 'official-locked-registry-source'

    if source_only:
        route, primary_failure = from_source(), None
    else:
        route, primary_failure = select_route(from_release, from_source)
    before = digest(binary)
    code, output, _ = commands.run('installed-version', [str(binary), '--version'], 15, destination)
    require(code == 0 and output.stat().st_size <= 4096, 'installed nextest version probe failed')
    version = output.read_text().strip()
    require(version.split()[:2] == ['cargo-nextest', VERSION], 'installed nextest version mismatch')
    require(digest(binary) == before, 'version probe changed the admitted executable')
    require(time.monotonic() <= commands.deadline, 'installer exceeded its total elapsed budget')
    receipt = {'version': version, 'route': route, 'primary_transfer_failure': primary_failure,
               'source_only_requested': source_only, 'source_contract': source_receipt,
               'binary_sha256': before, 'release_archive_sha256': RELEASE_SHA,
               'native_platform': platform.platform(), 'effective_uid': os.geteuid(),
               'total_elapsed_budget_seconds': 660,
               'installer_sha256': digest(Path(__file__)),
               'workflow_source_sha': os.environ.get('GITHUB_SHA'),
               'commands': commands.rows}
    (receipts / 'admission.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--source-only', action='store_true',
                        help='explicitly validate the independent registry build on native macOS')
    arguments = parser.parse_args()
    binary = install(arguments.destination.absolute(), arguments.receipts.absolute(), arguments.source_only)
    path_file = os.environ.get('GITHUB_PATH')
    if path_file:
        require('\n' not in str(binary.parent) and '\r' not in str(binary.parent),
                'installed nextest path must fit on one line')
        with Path(path_file).open('a') as output:
            output.write(str(binary.parent) + '\n')
    print(binary)


if __name__ == '__main__':
    main()

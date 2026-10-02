#!/usr/bin/env python3
"""Prove the real inventory mutation gate without running package commands."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

CASES = ('release-package-search-tree', 'release-package-install-tree', 'release-package-remove-tree')
SNAPSHOTS = {
    'arch': "pacman -Q; printf '\\ninstall reasons\\n'; pacman -Qqe",
    'debian': "dpkg-query -W '-f=${Package}\\t${Version}\\t${Status}\\t${Architecture}\\n'; printf '\\ninstall reasons\\n'; apt-mark showmanual",
    'ubuntu': "dpkg-query -W '-f=${Package}\\t${Version}\\t${Status}\\t${Architecture}\\n'; printf '\\ninstall reasons\\n'; apt-mark showmanual",
    'fedora': "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n'; printf '\\ninstall reasons\\n'; dnf --cacheonly --disable-repo='*' repoquery --installed --queryformat '%{name} %{arch} %{reason}\\n'",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def subset(path):
    data = path.read_bytes()
    if not data or len(data) > 1024 * 1024:
        raise ValueError('source inventory is missing or oversized')
    lines = data.splitlines(keepends=True)
    selected = [line for line in lines[1:] if line.split(b'\t', 1)[0].decode() in CASES]
    if len(selected) != 3 or [line.split(b'\t', 1)[0].decode() for line in selected] != list(CASES):
        raise ValueError('source inventory must contain each refusal row exactly once')
    for line, operation, safety in zip(selected, ('search', 'install', 'remove'), ('read', 'package-mutation', 'package-mutation')):
        cells = line.decode().rstrip('\r\n').split('\t')
        argv = [operation, 'tree'] if operation == 'search' else [operation, '--yes', 'tree']
        if len(cells) != 10 or json.loads(cells[1]) != argv or cells[2] != safety:
            raise ValueError('refusal rows must preserve reviewed tree package mutations')
    return data, lines[0] + b''.join(selected)


def verify(receipt, args):
    source, selection = subset(args.tsv)
    if not isinstance(receipt, dict) or receipt.get('schema_version') != 1 or receipt.get('kind') != 'mutation-refusal' or receipt.get('complete') is not True:
        raise ValueError('refusal proof is incomplete')
    if receipt.get('distro') != args.distro or receipt.get('source_sha256') != digest(source) or receipt.get('subset_sha256') != digest(selection):
        raise ValueError('refusal inventory identity mismatch')
    before, after = receipt.get('state_before_sha256'), receipt.get('state_after_sha256')
    if not isinstance(before, str) or len(before) != 64 or any(c not in '0123456789abcdef' for c in before) or before != after:
        raise ValueError('native package/version/reason state changed or is missing')
    metadata = receipt.get('metadata', {})
    if not isinstance(metadata, dict) or metadata.get('allow_mutations') is not False or metadata.get('allow_credentialed') is not False or metadata.get('distro') != args.distro or metadata.get('binary') != args.binary or metadata.get('release') != args.tag or metadata.get('tiers') != 'container':
        raise ValueError('executor opt-in or guest identity is invalid')
    rows = receipt.get('results', [])
    if not isinstance(rows, list) or len(rows) != 3 or any(not isinstance(row, dict) for row in rows) or [row.get('case_id') for row in rows] != ['qemu-' + args.distro + '-' + case for case in CASES]:
        raise ValueError('refusal rows are missing, duplicated or unexpected')
    control = rows[0]
    if control.get('result') != 'PASS' or control.get('exit_code') != 0 or control.get('artifact_source') != 'inventory' or control.get('distro') != args.distro:
        raise ValueError('read-only positive control did not execute successfully')
    if any(row.get('result') != 'SKIPPED' or row.get('exit_code') != -1 or row.get('elapsed_seconds') != 0 or row.get('artifact_source') != 'inventory' or row.get('distro') != args.distro for row in rows[1:]):
        raise ValueError('a mutation row executed or failed instead of being refused')
    summary = receipt.get('summary', {})
    if not isinstance(summary, dict) or summary.get('complete') is not True:
        raise ValueError('executor did not complete the refusal selection')
    for field, name in (('oracle_sha256', 'qemu-mutation-refusal.py'), ('executor_sha256', 'qemu-inventory.sh')):
        if receipt.get(field) != digest(Path(__file__).with_name(name).read_bytes()):
            raise ValueError('refusal driver identity mismatch')


def native_state(args):
    guest = args.work / 'guest'
    result = subprocess.run(['ssh', '-n', '-i', str(guest / 'client-key'), '-p', '2222',
                             '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                             '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3',
                             '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(guest / 'known_hosts'),
                             'bench@127.0.0.1', 'bash -eu -c ' + shlex.quote(SNAPSHOTS[args.distro])],
                            capture_output=True, timeout=20, check=True)
    if not result.stdout.strip() or len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError('native snapshot is empty or oversized')
    sections = result.stdout.split(b'\ninstall reasons\n')
    if len(sections) != 2 or not sections[0].strip():
        raise ValueError('native snapshot lacks installed/reason identity')
    return digest(json.dumps([sorted(section.decode().splitlines()) for section in sections]).encode())


def collect(args):
    receipt = {'schema_version': 1, 'kind': 'mutation-refusal', 'distro': args.distro, 'complete': False}
    try:
        source, selection = subset(args.tsv)
        receipt.update(source_sha256=digest(source), subset_sha256=digest(selection),
                       oracle_sha256=digest(Path(__file__).read_bytes()),
                       executor_sha256=digest(Path(__file__).with_name('qemu-inventory.sh').read_bytes()))
        private = args.work / 'mutation-refusal'
        private.mkdir(mode=0o700)
        (private / 'guest').mkdir(mode=0o700)
        for name in ('client-key', 'known_hosts'):
            origin = args.work / 'guest' / name
            if origin.is_symlink() or not origin.is_file():
                raise ValueError('strict SSH identity is missing or linked')
            shutil.copyfile(origin, private / 'guest' / name)
            (private / 'guest' / name).chmod(0o600)
        inventory = private / 'cases.tsv'
        inventory.write_bytes(selection)
        receipt['state_before_sha256'] = native_state(args)
        try:
            result = subprocess.run(['bash', str(Path(__file__).with_name('qemu-inventory.sh')),
                                     '--work', str(private), '--distro', args.distro, '--tag', args.tag,
                                     '--binary', args.binary, '--tiers', 'container', '--tsv', str(inventory)],
                                    capture_output=True, timeout=60)
            (private / 'executor.log').write_bytes(result.stdout + result.stderr)
        finally:
            receipt['state_after_sha256'] = native_state(args)
        for field, name in (('metadata', 'metadata.json'), ('results', 'results.json'), ('summary', 'summary.json')):
            path = private / 'inventory' / name
            if path.stat().st_size > 1024 * 1024:
                raise ValueError('executor receipt is oversized')
            receipt[field] = json.loads(path.read_text())
        if result.returncode != 0:
            raise ValueError('refusal executor failed with exit ' + str(result.returncode))
        receipt['complete'] = True
        verify(receipt, args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt['complete'] = False
        receipt['error'] = str(error)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('collect', 'verify'))
    parser.add_argument('--work', type=Path)
    parser.add_argument('--receipt', required=True)
    parser.add_argument('--tsv', required=True, type=Path)
    parser.add_argument('--distro', required=True, choices=tuple(SNAPSHOTS))
    parser.add_argument('--tag', required=True)
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    if args.mode == 'collect':
        if args.work is None:
            parser.error('collect requires --work')
        receipt = collect(args)
        encoded = json.dumps(receipt, indent=2) + '\n'
        if args.receipt == '-':
            sys.stdout.write(encoded)
        else:
            Path(args.receipt).write_text(encoded)
        if not receipt['complete']:
            print(receipt['error'], file=sys.stderr)
            return 120
        return 0
    try:
        path = Path(args.receipt)
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError('refusal receipt is linked or oversized')
        verify(json.loads(path.read_text()), args)
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 120
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

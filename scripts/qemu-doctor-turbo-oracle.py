#!/usr/bin/env python3
"""Check removal of file capabilities on a private exact-copy Doctor executable."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

LIMIT = 128 * 1024 * 1024


def digest(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= LIMIT:
            raise ValueError('invalid bounded regular executable')
        result = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > LIMIT:
                raise ValueError('executable grew beyond bound')
            result.update(chunk)
    return result.hexdigest()


def capability(path):
    try:
        return os.getxattr(path, 'security.capability', follow_symlinks=False).hex()
    except OSError as error:
        if error.errno == errno.ENODATA:
            return None
        raise


def state(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('executable must be a regular nonlinked file')
    return dict(sha256=digest(path), mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid, capability=capability(path))


def trusted_setcap():
    for candidate in ('/usr/sbin/setcap', '/sbin/setcap', '/usr/bin/setcap', '/bin/setcap'):
        path = Path(candidate).resolve()
        if not path.is_file():
            continue
        if all(p.stat().st_uid == 0 and not p.stat().st_mode & 0o022
               for p in (path, *path.parents)) and os.access(path, os.X_OK):
            return str(path)
    raise ValueError('missing root-controlled setcap dependency')


def owned_directory(root):
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('oracle root must be a private owned directory')
    private = root / 'doctor-turbo-private'
    if private.exists() or private.is_symlink():
        info = private.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError('private executable directory is not owned and regular')
    return private


def prepare(source, root):
    private = owned_directory(root)
    private.mkdir(mode=0o700)
    target = private / 'omg'
    before = state(source)
    try:
        shutil.copyfile(source, target, follow_symlinks=False)
        target.chmod(0o700)
        if digest(target) != before['sha256'] or state(source) != before:
            raise ValueError('private copy differs or source changed')
        subprocess.run(['/usr/bin/sudo', '-n', '--', trusted_setcap(),
                        'cap_net_bind_service=ep', str(target)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10, check=True)
        seeded = capability(target)
        if seeded is None:
            raise ValueError('test capability was not established')
        subprocess.run([trusted_setcap(), '-v', 'cap_net_bind_service=ep', str(target)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10, check=True)
        receipt = dict(source=str(source), original=before, seeded_capability=seeded)
        with (private / 'before.json').open('x') as stream:
            json.dump(receipt, stream)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def verify(source, root, output):
    private = owned_directory(root)
    target = private / 'omg'
    receipt_path = private / 'before.json'
    if receipt_path.is_symlink() or receipt_path.stat().st_size > 4096:
        raise ValueError('invalid preparation receipt')
    receipt = json.loads(receipt_path.read_text())
    if receipt['source'] != str(source) or state(source) != receipt['original']:
        raise ValueError('original executable state changed')
    actual = state(target)
    if actual['sha256'] != receipt['original']['sha256'] or actual['mode'] != 0o700:
        raise ValueError('private executable bytes or mode changed')
    if actual['capability'] is not None:
        raise ValueError('Doctor retained a capability xattr, including an empty set')
    if output.is_symlink() or output.stat().st_size > 65536:
        raise ValueError('invalid bounded Doctor output')
    text = output.read_text()
    if ('No permanent privileges granted to any binary' not in text
            or 'No file capabilities remain (or none were set)' not in text):
        raise ValueError('Doctor lacks matching capability-cleanup result')
    print(json.dumps(dict(schema_version=1, complete=True, original_unchanged=True,
                          capabilities_removed=True, copy_sha256=actual['sha256'],
                          seeded_capability='cap_net_bind_service=ep')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'verify', 'cleanup'))
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'prepare':
            prepare(args.source, args.root)
        elif args.operation == 'verify':
            if args.output is None:
                raise ValueError('Doctor output is required')
            verify(args.source, args.root, args.output)
        else:
            (owned_directory(args.root) / 'omg').unlink(missing_ok=True)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'Doctor capability oracle failed: {error}', file=sys.stderr)
        return 2 if args.operation == 'prepare' else 1


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Seed and check the private legacy audit-log severity/limit export fixture."""
import hashlib
import json
import stat
import sys
from pathlib import Path


def entries():
    result = []
    previous = 'genesis'
    for number, severity in enumerate(('error', 'info', 'critical', 'warning', 'error', 'critical')):
        row = dict(id=f'fixture-{number}', timestamp=f'2025-01-01T00:00:0{number}Z',
                   event_type='policy_violation', severity=severity, user='fixture',
                   resource=f'package-{number}', description=f'audit fixture {number}',
                   prev_hash=previous)
        # Original PR691 AuditEntry::compute_hash uses Debug names and concatenation.
        preimage = ''.join((row['id'], row['timestamp'], 'PolicyViolation',
                            severity.capitalize(), row['user'], row['resource'],
                            row['description'], previous))
        row['hash'] = hashlib.sha256(preimage.encode()).hexdigest()
        previous = row['hash']
        result.append(row)
    return result


def source_bytes():
    return ''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in entries()).encode()


def private_file(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o600:
        raise ValueError('audit fixture/export must be a private regular file')
    if path.stat().st_size > 32768:
        raise ValueError('audit fixture/export exceeds byte bound')
    return path.read_bytes()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate export key')
        result[key] = value
    return result


def main():
    mode, root_arg = sys.argv[1:]
    root = Path(root_arg)
    data = root / 'audit-log-data'
    store = data / 'audit' / 'audit.jsonl'
    export = root / 'audit-log-export.json'
    if mode == 'prepare':
        if data.exists() or data.is_symlink() or export.exists() or export.is_symlink():
            raise ValueError('fixture must start absent')
        store.parent.mkdir(parents=True, mode=0o700)
        store.write_bytes(source_bytes())
        store.chmod(0o600)
    elif mode == 'check':
        if data.is_symlink() or store.parent.is_symlink():
            raise ValueError('fixture directory is a symlink')
        if private_file(store) != source_bytes():
            raise ValueError('source audit log changed')
        actual = json.loads(private_file(export), object_pairs_hook=unique_object)
        # Legacy input omits the marker; AuditEntry defaults it to zero on
        # deserialization and includes that explicit version in JSON exports.
        expected = [dict(entries()[index], hash_version=0) for index in (5, 4, 2)]
        if actual != expected:
            raise ValueError('export is not newest three error-or-critical records')
    else:
        raise ValueError('unknown oracle mode')


if __name__ == '__main__':
    main()

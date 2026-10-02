"""Exercise real Doctor index reads inside a disposable guest mount namespace.

unshare(1) private propagation isolates bind mounts. apt-get(8) describes the
native lists; the product's bounded validators must read these actual files.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


CASES = ('empty', 'corrupt-gzip', 'unreadable', 'corrupt-status')
STATUS = 'Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2-1\n\n'
PATHS = ('/var/lib/dpkg/status', '/var/lib/apt/lists')


def validate_receipt(value, distro):
    if (not isinstance(value, dict) or value.get('schema_version') != 1
            or value.get('distro') != distro or value.get('complete') is not True):
        raise ValueError('incomplete or mismatched Doctor index evidence')
    before, after = value.get('db_before'), value.get('db_after')
    if not isinstance(before, str) or not re.fullmatch('[0-9a-f]{64}', before) or before != after:
        raise ValueError('native database changed or snapshots missing')
    baseline = value.get('baseline_issues')
    cases = value.get('cases')
    if type(baseline) is not int or baseline < 0 or not isinstance(cases, dict) or set(cases) != set(CASES):
        raise ValueError('missing baseline or negative cases')
    for name in CASES:
        case = cases[name]
        expected = baseline + (name != 'empty')
        if (not isinstance(case, dict) or type(case.get('issues')) is not int
                or case['issues'] != expected or type(case.get('exit')) is not int
                or case['exit'] != (1 if expected else 0) or case.get('diagnostic') is not True):
            raise ValueError(f'{name} did not establish counted native index health')


def snapshot():
    digest = hashlib.sha256()
    for name in PATHS:
        root = Path(name)
        paths = [root, *sorted(root.rglob('*'))] if root.is_dir() else [root]
        for path in paths:
            digest.update(str(path).encode())
            if path.is_symlink():
                digest.update(os.readlink(path).encode())
            elif path.is_file():
                with path.open('rb') as stream:
                    for data in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(data)
    return digest.hexdigest()


def run(binary_name, distro):
    import pwd
    virt = subprocess.run(['systemd-detect-virt', '--vm'], capture_output=True, text=True, timeout=10)
    if (os.geteuid() != 0 or virt.returncode != 0 or virt.stdout.strip() not in ('qemu', 'kvm')
            or os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt')):
        raise RuntimeError('requires a disposable QEMU guest and a private root mount namespace')
    release = Path('/etc/os-release').read_text().splitlines()
    if not any(line in (f'ID={distro}', f'ID="{distro}"') for line in release):
        raise RuntimeError('native guest distribution mismatch')
    account = pwd.getpwnam('bench')
    binary = Path(binary_name).resolve(strict=True)
    if not binary.is_relative_to(Path(account.pw_dir)) or binary.name != 'omg' or not os.access(binary, os.X_OK):
        raise RuntimeError('expected admitted bench release binary')
    receipt = {'schema_version': 1, 'distro': distro, 'complete': False,
               'db_before': snapshot(), 'cases': {}}
    with tempfile.TemporaryDirectory(prefix='omg-doctor-index-', dir=account.pw_dir) as directory:
        root = Path(directory)
        root.chmod(0o755)
        lists = root / 'lists'
        lists.mkdir()
        status = root / 'status'
        status.write_text(STATUS)
        with ExitStack() as mounts:
            for source, target in ((status, PATHS[0]), (lists, PATHS[1])):
                subprocess.run(['mount', '--bind', str(source), target], check=True, timeout=10, capture_output=True)
                mounts.callback(subprocess.run, ['umount', target], check=True, timeout=10, capture_output=True)
            env = {'PATH': f'{binary.parent}:/usr/bin:/bin', 'HOME': account.pw_dir,
                   'OMG_TEST_MODE': '0', 'OMG_DISABLE_DAEMON': '1', 'OMG_NO_UPDATE_CHECK': '1',
                   'NO_COLOR': '1', 'HTTPS_PROXY': 'http://127.0.0.1:1',
                   'HTTP_PROXY': 'http://127.0.0.1:1', 'ALL_PROXY': 'http://127.0.0.1:1',
                   'NO_PROXY': '', 'OMG_CONFIG_DIR': str(root / 'config'),
                   'OMG_DATA_DIR': str(root / 'data'), 'OMG_CACHE_DIR': str(root / 'cache')}
            for name in CASES:
                for old in lists.iterdir():
                    old.unlink()
                status.write_text(STATUS if name != 'corrupt-status' else 'not a dpkg paragraph\n')
                index = lists / ('fixture_Packages.gz' if name == 'corrupt-gzip' else 'fixture_Packages')
                index.write_bytes(b'not gzip' if name == 'corrupt-gzip' else b'')
                index.chmod(0 if name == 'unreadable' else 0o644)
                result = subprocess.run(['setpriv', f'--reuid={account.pw_uid}',
                    f'--regid={account.pw_gid}', '--clear-groups', '--no-new-privs',
                    '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                    str(binary), 'doctor'], env=env, capture_output=True, text=True, timeout=20)
                if len(result.stdout) + len(result.stderr) > 8192:
                    raise RuntimeError('unbounded Doctor output')
                match = re.search(r'^Error: doctor found (\d+) health issue\(s\)$', result.stderr, re.MULTILINE)
                issues = int(match[1]) if match else (0 if result.returncode == 0 else -1)
                label = 'dpkg package database' if name == 'corrupt-status' else 'APT package indexes'
                diagnostic = (f'{label} (' in result.stdout if name == 'empty'
                              else f'✗ {label}:' in result.stdout and f'{label} (' not in result.stdout)
                receipt['cases'][name] = {'exit': result.returncode, 'issues': issues,
                    'diagnostic': diagnostic, 'stdout': result.stdout, 'stderr': result.stderr}
                if name == 'empty':
                    receipt['baseline_issues'] = issues
    receipt['db_after'] = snapshot()
    receipt['complete'] = True
    return receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--distro', required=True, choices=('debian', 'ubuntu'))
    parser.add_argument('--binary')
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.receipt:
            if not args.receipt.is_file() or args.receipt.stat().st_size > 65536:
                raise ValueError('missing or oversized Doctor index evidence')
            validate_receipt(json.loads(args.receipt.read_text()), args.distro)
        elif args.binary:
            value = run(args.binary, args.distro)
            print(json.dumps(value, sort_keys=True), flush=True)
            validate_receipt(value, args.distro)
        else:
            parser.error('--binary or --receipt is required')
        return 0
    except ValueError as error:
        print(f'PRODUCT_FAIL: {error}', file=sys.stderr)
        return 1
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'HARNESS_ERROR: {error}', file=sys.stderr)
        return 120


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Exercise real package installation with explicit Unknown-only terminal review."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native_state():
    database = Path('/var/lib/pacman/local')
    entries = []
    for path in sorted(database.rglob('*')):
        require(not path.is_symlink(), 'Unexpected symlink in native package database')
        entries.append((str(path.relative_to(database)), 'directory' if path.is_dir()
                        else hashlib.sha256(path.read_bytes()).hexdigest()))
    return subprocess.check_output(['pacman', '-Q'], timeout=10), entries


def deny_unattended(command, before):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            start_new_session=True, timeout=90)
    plain = re.sub(rb'\x1b\[[0-?]*[ -/]*[@-~]', b'', result.stdout + result.stderr)
    print(plain.decode(errors='replace'), flush=True)
    require(result.returncode != 0, 'Unattended installation unexpectedly succeeded')
    if '-y' in command:
        require(b'SECURITY WARNING: advisory coverage for the selected transaction is unknown.' in plain
                and b'Security review requires an attended controlling terminal' in plain
                and b'--yes cannot accept advisory risk or unknown coverage' in plain,
                'Unattended installation failed without proving missing security consent')
    else:
        require(b'Use --yes for non-interactive package installation' in plain,
                'Unattended installation failed without proving missing mutation consent')
    require(native_state() == before, 'Denied installation changed the native package database')
    require(not Path('/var/lib/pacman/db.lck').exists(), 'Denied installation left the package database locked')


def main():
    require(len(sys.argv) == 5, 'Expected Unknown helper source, package, executable and removal mode')
    helper_source, package, executable, removal = sys.argv[1:]
    require((package, executable) in (('ripgrep', 'rg'), ('tree', 'tree')) and removal in ('keep', 'remove'),
            'Unsupported disposable Docker install fixture case')
    require(os.getuid() != 0, 'Docker install fixture must begin as the ordinary test user')
    absent = subprocess.run(['pacman', '-Qq', package], capture_output=True, timeout=10)
    require(absent.returncode == 1, 'Install fixture package must initially be absent')
    before = native_state()
    cli = ['sudo', '-n', '/usr/local/bin/omg']
    deny_unattended(cli + ['install', package], before)
    deny_unattended(cli + ['install', '-y', package], before)
    helper = types.ModuleType('attend_unknown_fixture')
    exec(compile(helper_source, 'attend-unknown-fixture.py', 'exec'), helper.__dict__)
    with tempfile.TemporaryDirectory(prefix='omg-docker-install-') as directory:
        receipt = Path(directory) / 'security-review.json'
        code = helper.attend(cli + ['install', '-y', package], receipt, 120)
        require(code == 0, 'Foreground installation failed after explicit Unknown-only review')
        review = json.loads(receipt.read_text())
        require(review.get('cli_exit_code') == 0 and type(review.get('reviews')) is list
                and 0 < len(review['reviews']) <= 64
                and all(type(digest) is str and re.fullmatch('[a-f0-9]{64}', digest) for digest in review['reviews']),
                'Successful install lacks exact explicit security-review receipts')
        subprocess.run(['pacman', '-Qi', package], check=True, timeout=10)
        subprocess.run(['which', executable], check=True, timeout=10)
        require(native_state() != before, 'Successful installation did not change the native package database')
        if removal == 'remove':
            subprocess.run(cli + ['remove', '-y', package], check=True, timeout=90)
            require(subprocess.run(['which', executable], capture_output=True, timeout=10).returncode == 1,
                    'Removed package executable remains installed')
            require(subprocess.run(['pacman', '-Qq', package], capture_output=True, timeout=10).returncode == 1,
                    'Removed package remains in the native package database')
        print(json.dumps({'security_review': review, 'package': package, 'removed': removal == 'remove'}), flush=True)
    print(f'INSTALL_FIXTURE_PASS package={package} no_tty=1 yes_denied=1 native_state_unchanged=1 '
          f'explicit_unknown_review=1 removed={int(removal == "remove")}', flush=True)


if __name__ == '__main__':
    main()

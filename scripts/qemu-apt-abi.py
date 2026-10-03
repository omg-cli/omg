#!/usr/bin/env python3
"""Record APT 7 resolution using the trusted loader inside a Trixie guest.

The loader's --list resolves dependencies without running the product entrypoint.
See https://man7.org/linux/man-pages/man8/ld.so.8.html. This is guest evidence;
the host must independently bind it to the native archive and trusted source.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import subprocess
import sys

LOG_LIMIT = 65536
FILE_LIMIT = 128 * 1024 * 1024
LOADER = Path('/lib64/ld-linux-x86-64.so.2')


def release_values(content):
    result = {}
    for line in content.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, separator, value = line.partition('=')
        fields = shlex.split(value)
        if not separator or not re.fullmatch('[A-Z][A-Z0-9_]*', key) or key in result or len(fields) != 1:
            raise ValueError('invalid or duplicate os-release identity')
        result[key] = fields[0]
    return result


def validate_guest(distro, arch, release):
    if (distro != 'debian-trixie' or arch != 'x86_64'
            or release.get('ID') != 'debian' or release.get('VERSION_ID') != '13'):
        raise ValueError('APT 7 probe requires the Debian 13 x86-64 guest')


def resolved_apt_library(report):
    if len(report.encode('utf-8')) > LOG_LIMIT or 'not found' in report:
        raise ValueError('missing or oversized loader dependency evidence')
    rows = [line.strip() for line in report.splitlines() if line.lstrip().startswith('libapt-pkg.so.')]
    if len(rows) != 1:
        raise ValueError('expected exactly one APT dependency')
    match = re.fullmatch(r'libapt-pkg\.so\.7\.0 => ((?:/usr)?/lib/x86_64-linux-gnu/libapt-pkg\.so\.7\.0) \(0x[0-9a-fA-F]+\)', rows[0])
    if match is None:
        raise ValueError('APT 7 did not resolve to the native system library')
    return match[1]


def digest_file(path):
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= FILE_LIMIT:
        raise ValueError('identity requires a bounded regular file')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    after = path.stat()
    if (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('file changed during identity capture')
    return digest.hexdigest()


def probe(distro, arch, binaries, output):
    import resource
    if os.geteuid() == 0 or platform.machine() != arch:
        raise ValueError('probe requires an ordinary user in the selected guest')
    release = Path('/etc/os-release').read_bytes()
    if len(release) > 4096:
        raise ValueError('oversized guest identity')
    validate_guest(distro, arch, release_values(release.decode('utf-8')))
    if set(binaries) != {'omg', 'omgd'}:
        raise ValueError('both product binaries are required')
    output.mkdir(mode=0o700, exist_ok=False)
    (output / 'os-release').write_bytes(release)
    loader_hash = digest_file(LOADER)
    helper_hash = digest_file(Path(__file__))
    environment = {key: value for key, value in os.environ.items() if not key.startswith('LD_')}
    environment['LC_ALL'] = 'C'
    entries = {}
    for name, binary in sorted(binaries.items()):
        if binary.is_symlink() or not os.access(binary, os.X_OK):
            raise ValueError('product must be a regular executable')
        binary_hash = digest_file(binary)
        log = output / (name + '-loader.log')
        with log.open('xb') as stream:
            completed = subprocess.run([str(LOADER), '--list', str(binary)],
                stdout=stream, stderr=subprocess.STDOUT, env=environment, timeout=15,
                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT)))
        if completed.returncode != 0:
            raise ValueError('trusted loader refused the product dependencies')
        raw = log.read_bytes()
        library = Path(resolved_apt_library(raw.decode('utf-8')))
        if binary_hash != digest_file(binary):
            raise ValueError('product changed during dependency resolution')
        entries[name] = dict(binary_sha256=binary_hash, library_path=str(library),
            library_sha256=digest_file(library), log_sha256=hashlib.sha256(raw).hexdigest())
    if loader_hash != digest_file(LOADER) or helper_hash != digest_file(Path(__file__)):
        raise ValueError('trusted probe inputs changed')
    if len({entry['library_sha256'] for entry in entries.values()}) != 1:
        raise ValueError('APT library differs between product binaries')
    receipt = dict(schema_version=1, kind='trixie-apt-abi', complete=True, distro=distro,
        arch=arch, ordinary_user_uid=os.geteuid(), os_id='debian', version_id='13',
        os_release_sha256=hashlib.sha256(release).hexdigest(), loader_sha256=loader_hash,
        probe_sha256=helper_hash, binaries=entries)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distro', required=True)
    parser.add_argument('--arch', required=True)
    parser.add_argument('--omg', type=Path, required=True)
    parser.add_argument('--omgd', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        probe(args.distro, args.arch, {'omg': args.omg, 'omgd': args.omgd}, args.output)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f'HARNESS_ERROR: APT ABI probe: {error}', file=sys.stderr)
        return 120


if __name__ == '__main__':
    sys.exit(main())

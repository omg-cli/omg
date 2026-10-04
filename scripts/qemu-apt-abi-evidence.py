#!/usr/bin/env python3
"""Independently bind Trixie loader evidence to the selected native archive.

This checks guest dependency resolution, not product runtime behavior. The
caller must also admit the source, publisher image, and ordinary guest owner.
Loader --list semantics: https://man7.org/linux/man-pages/man8/ld.so.8.html.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

spec = importlib.util.spec_from_file_location('apt_abi_probe', Path(__file__).with_name('qemu-apt-abi.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
HASH = re.compile(r'[0-9a-f]{64}\Z')
FILES = {'receipt.json': 65536, 'os-release': 4096,
         'omg-loader.log': 65536, 'omgd-loader.log': 65536}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate ABI receipt key')
        result[key] = value
    return result


def read_regular(path, limit):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
        raise ValueError('ABI input requires a bounded regular file')
    with path.open('rb') as stream:
        value = stream.read(limit + 1)
    after = path.lstat()
    identity = lambda details: (details.st_dev, details.st_ino, details.st_size, details.st_mtime_ns)
    if len(value) != before.st_size or identity(before) != identity(after):
        raise ValueError('ABI input changed during capture')
    return value


def archive_binary_hashes(archive):
    hashes = {}
    parents = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as source:
        for count, member in enumerate(source, 1):
            total += member.size
            if count > 64 or total > 512 * 1024 * 1024:
                raise ValueError('native archive exceeds ABI replay budget')
            parts = PurePosixPath(member.name).parts
            if not parts or parts[-1] not in {'omg', 'omgd'}:
                continue
            if (len(parts) != 2 or not re.fullmatch(r'omg-v[0-9]+\.[0-9]+\.[0-9]+-x86_64-linux-debian-trixie', parts[0])
                    or not member.isfile() or not 0 < member.size <= probe.FILE_LIMIT
                    or not member.mode & 0o111 or parts[-1] in hashes):
                raise ValueError('invalid Trixie native binary pair')
            parents.add(parts[0])
            digest = hashlib.sha256()
            with source.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            hashes[parts[-1]] = digest.hexdigest()
    if set(hashes) != {'omg', 'omgd'} or len(parents) != 1:
        raise ValueError('missing or mixed Trixie native binary pair')
    return hashes


def validate_evidence(directory, archive, probe_file):
    try:
        if directory.is_symlink() or {path.name for path in directory.iterdir()} != set(FILES):
            raise ValueError('incomplete or unexpected ABI evidence files')
        raw = {name: read_regular(directory / name, limit) for name, limit in FILES.items()}
        receipt = json.loads(raw['receipt.json'], object_pairs_hook=unique_object)
        keys = {'schema_version', 'kind', 'complete', 'distro', 'arch', 'ordinary_user_uid',
                'os_id', 'version_id', 'os_release_sha256', 'loader_sha256', 'probe_sha256', 'binaries'}
        if (not isinstance(receipt, dict) or set(receipt) != keys
                or type(receipt['schema_version']) is not int or receipt['schema_version'] != 1
                or receipt['kind'] != 'trixie-apt-abi' or receipt['complete'] is not True
                or type(receipt['ordinary_user_uid']) is not int
                or not 0 < receipt['ordinary_user_uid'] < 2**32
                or receipt['os_id'] != 'debian' or receipt['version_id'] != '13'):
            raise ValueError('incomplete ABI receipt identity')
        probe.validate_guest(receipt['distro'], receipt['arch'],
                             probe.release_values(raw['os-release'].decode('utf-8')))
        for key in ('os_release_sha256', 'loader_sha256', 'probe_sha256'):
            if not isinstance(receipt[key], str) or not HASH.fullmatch(receipt[key]):
                raise ValueError('invalid ABI identity hash')
        if receipt['os_release_sha256'] != hashlib.sha256(raw['os-release']).hexdigest():
            raise ValueError('raw guest identity differs')
        expected_probe = read_regular(probe_file, 1024 * 1024)
        if receipt['probe_sha256'] != hashlib.sha256(expected_probe).hexdigest():
            raise ValueError('guest probe differs from selected source')
        details = archive.lstat()
        if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= probe.FILE_LIMIT:
            raise ValueError('native archive must be a bounded regular file')
        archive_hash = probe.digest_file(archive)
        hashes = archive_binary_hashes(archive)
        entries = receipt['binaries']
        if not isinstance(entries, dict) or set(entries) != {'omg', 'omgd'}:
            raise ValueError('both binary ABI receipts are required')
        for name, entry in entries.items():
            if not isinstance(entry, dict) or set(entry) != {'binary_sha256', 'library_path', 'library_sha256', 'log_sha256'}:
                raise ValueError('incomplete binary ABI fields')
            for key in ('binary_sha256', 'library_sha256', 'log_sha256'):
                if not isinstance(entry[key], str) or not HASH.fullmatch(entry[key]):
                    raise ValueError('invalid binary ABI hash')
            log = raw[name + '-loader.log']
            if (entry['binary_sha256'] != hashes[name]
                    or entry['log_sha256'] != hashlib.sha256(log).hexdigest()
                    or entry['library_path'] != probe.resolved_apt_library(log.decode('utf-8'))):
                raise ValueError('binary or raw loader evidence differs')
        if len({entry['library_sha256'] for entry in entries.values()}) != 1:
            raise ValueError('native APT library differs between binaries')
        if archive_hash != probe.digest_file(archive) or expected_probe != read_regular(probe_file, 1024 * 1024):
            raise ValueError('native ABI replay inputs changed')
        return dict(receipt, native_archive_sha256=archive_hash)
    except (OSError, UnicodeError, KeyError, TypeError, tarfile.TarError) as error:
        raise ValueError('APT ABI evidence rejected: ' + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--probe', type=Path, default=Path(__file__).with_name('qemu-apt-abi.py'))
    args = parser.parse_args()
    try:
        validate_evidence(args.evidence_dir, args.archive, args.probe)
        print('PASS: archive-bound Trixie APT ABI evidence')
        return 0
    except ValueError as error:
        print('HARNESS_ERROR: ' + str(error))
        return 120


if __name__ == '__main__':
    raise SystemExit(main())

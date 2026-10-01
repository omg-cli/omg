#!/usr/bin/env python3
"""Prepare the genuine Node 20.10.0 executable for offline activation tests.

Official release: https://nodejs.org/en/blog/release/v20.10.0
The exact SHASUMS256.txt.asc below was independently verified with signer
8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 and the official release-keys keyring
at commit 481637f813e912c4aa3622d7964ab426c97b8e8d:
https://github.com/nodejs/release-keys/tree/481637f813e912c4aa3622d7964ab426c97b8e8d
The pinned signed bytes bind the archive checksum. The ELF checksum additionally
binds the exact regular member copied by the tests. This fixture proves installed
version selection and activation; it does not certify OMG's download transport.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request

VERSION = '20.10.0'
MANIFEST = 'SHASUMS256.txt.asc'
MANIFEST_SHA256 = 'b015e943f56e593eefdb0f718410444a895ef1843e5796744365d59f6d95850b'
ARCHIVE = 'node-v20.10.0-linux-x64.tar.xz'
ARCHIVE_SHA256 = '3fe4ec5d70c8b4ffc1461dec83ab23fc70124e137c4cbbe1ccc9d6ae6ec04a7d'
NODE_SHA256 = 'd9cbc20cbf39eba838b077d3358d3203d549ae1f71e8085c6451d3bd712610ae'
NODE_BYTES = 96_227_728
SOURCE = 'https://nodejs.org/dist/v20.10.0/'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def sealed_file(path, checksum, limit):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            f'fixture must be a single regular file: {path}')
    require(metadata.st_uid == os.geteuid() and metadata.st_mode & 0o222 == 0,
            f'fixture must be owned by this user and read-only: {path}')
    require(0 < metadata.st_size <= limit and digest(path) == checksum,
            f'fixture checksum or size mismatch: {path}')


def acquire(name, checksum, limit, destination, artifacts):
    path = destination / name
    if artifacts is not None:
        source = (artifacts / name).open('rb')
    else:
        source = urllib.request.urlopen(SOURCE + name, timeout=60)
        require(source.geturl() == SOURCE + name, 'unexpected fixture download redirect')
    count = 0
    with source, path.open('xb') as output:
        while chunk := source.read(min(8192, limit + 1 - count)):
            count += len(chunk)
            require(count <= limit, f'fixture download exceeds its bound: {name}')
            output.write(chunk)
    require(digest(path) == checksum, f'official fixture checksum mismatch: {name}')
    path.chmod(0o444)
    sealed_file(path, checksum, limit)
    return path


def verify(destination):
    metadata = destination.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and metadata.st_mode & 0o077 == 0, 'fixture directory must be private and owned')
    sealed_file(destination / MANIFEST, MANIFEST_SHA256, 64 * 1024)
    sealed_file(destination / ARCHIVE, ARCHIVE_SHA256, 64 * 1024 * 1024)
    sealed_file(destination / 'node', NODE_SHA256, NODE_BYTES)
    require((destination / 'node').stat().st_size == NODE_BYTES,
            'official Node executable length mismatch')
    require((destination / 'node').stat().st_mode & 0o111 == 0o111,
            'official Node fixture must be executable')
    require(set(item.name for item in destination.iterdir()) == {MANIFEST, ARCHIVE, 'node'},
            'unexpected fixture directory entries')


def prepare(destination, artifacts=None):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64',
            'the admitted Node fixture requires Linux x86_64')
    if destination.exists() or destination.is_symlink():
        verify(destination)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.node-fixture-', dir=destination.parent) as staging:
        directory = Path(staging)
        manifest = acquire(MANIFEST, MANIFEST_SHA256, 64 * 1024, directory, artifacts)
        require(f'{ARCHIVE_SHA256}  {ARCHIVE}' in manifest.read_text().splitlines(),
                'admitted signed manifest does not bind the archive')
        archive = acquire(ARCHIVE, ARCHIVE_SHA256, 64 * 1024 * 1024, directory, artifacts)
        member_name = 'node-v20.10.0-linux-x64/bin/node'
        with tarfile.open(archive, 'r:xz') as compressed:
            matches = []
            for count, member in enumerate(compressed, start=1):
                require(count <= 20_000, 'fixture archive has too many members')
                if member.name == member_name:
                    matches.append(member)
            require(len(matches) == 1 and matches[0].isfile()
                    and matches[0].size == NODE_BYTES, 'invalid official Node archive member')
            source = compressed.extractfile(matches[0])
            require(source is not None, 'official Node member cannot be read')
            with source, (directory / 'node').open('xb') as output:
                shutil.copyfileobj(source, output, length=8192)
        (directory / 'node').chmod(0o555)
        verify(directory)
        directory.rename(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--artifact-directory', type=Path,
                        help='verify already downloaded official artifacts without networking')
    arguments = parser.parse_args()
    destination = arguments.destination.absolute()
    prepare(destination, arguments.artifact_directory)
    receipt = {'version': VERSION, 'manifest_url': SOURCE + MANIFEST,
               'manifest_sha256': MANIFEST_SHA256, 'archive_url': SOURCE + ARCHIVE,
               'archive_sha256': ARCHIVE_SHA256, 'node_sha256': NODE_SHA256,
               'node': str(destination / 'node'), 'bytes': NODE_BYTES}
    print(json.dumps(receipt, sort_keys=True))
    environment_file = os.environ.get('GITHUB_ENV')
    if environment_file is not None:
        require('\n' not in str(destination) and '\r' not in str(destination),
                'fixture environment path must fit on one line')
        with Path(environment_file).open('a') as environment:
            environment.write(f'OMG_NODE_TEST_FIXTURE={destination / "node"}\n')


if __name__ == '__main__':
    main()

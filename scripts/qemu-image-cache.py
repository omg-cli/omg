#!/usr/bin/env python3
"""Copy pinned image bytes through an untrusted cache; never cache guest state."""
import argparse
import hashlib
import fcntl
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile


def verified_copy(source, destination, algorithm, digest):
    """Publish a regular-file copy only after its full digest matches the pin."""
    if algorithm not in ('sha256', 'sha512') or not re.fullmatch(
        '[0-9a-f]{' + str(hashlib.new(algorithm).digest_size * 2) + '}', digest
    ):
        raise ValueError('invalid image digest')
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode):
        raise ValueError('image must be a regular file, not a link')
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    temporary = None
    try:
        with os.fdopen(fd, 'rb') as incoming:
            if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                raise ValueError('image must be a regular file')
            with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as outgoing:
                temporary = Path(outgoing.name)
                checksum = hashlib.new(algorithm)
                for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                    checksum.update(chunk)
                    outgoing.write(chunk)
                if checksum.hexdigest() != digest:
                    raise ValueError('image digest mismatch')
                outgoing.flush()
                os.fsync(outgoing.fileno())
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


DEFAULT_CACHE_BUDGET_BYTES = 4 * 1024 * 1024 * 1024
LOCK_NAME = '.image-cache.lock'


class CacheQuotaExceeded(Exception):
    """The optional write cannot fit without exceeding the cache's peak budget."""


def cache_bytes(directory_fd, lock_stat):
    """Account all flat-cache file bytes, including unknown files and leftovers."""
    total = 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError('cache entries must be regular files, not links or directories')
            if entry.name == LOCK_NAME:
                if (metadata.st_dev, metadata.st_ino) != (lock_stat.st_dev, lock_stat.st_ino):
                    raise ValueError('cache writer lock changed')
            else:
                total += metadata.st_size
    return total


def source_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def publish_cache(source, destination, algorithm, digest,
                  budget_bytes=DEFAULT_CACHE_BUDGET_BYTES):
    """Serialize verified cache writes within a cumulative peak file-byte limit.

    The budget includes the old destination and a complete temporary copy.
    Unknown files count but are never removed. Only cooperating writers are
    serialized; filesystem metadata is outside this image-content byte budget.
    """
    if algorithm not in ('sha256', 'sha512') or not re.fullmatch(
        '[0-9a-f]{' + str(hashlib.new(algorithm).digest_size * 2) + '}', digest
    ):
        raise ValueError('invalid image digest')
    if not isinstance(budget_bytes, int) or isinstance(budget_bytes, bool) or budget_bytes < 0:
        raise ValueError('cache budget must be a nonnegative integer')
    source, destination = Path(source), Path(destination)
    if destination.name != f'{algorithm}-{digest}.qcow2':
        raise ValueError('cache destination must match the pinned image filename')
    if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode):
        raise ValueError('image must be a regular file, not a link')
    source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(source_fd, 'rb') as incoming:
        original = os.fstat(incoming.fileno())
        if not stat.S_ISREG(original.st_mode):
            raise ValueError('image must be a regular file')
        checksum = hashlib.new(algorithm)
        size = 0
        for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
            checksum.update(chunk)
            size += len(chunk)
        if checksum.hexdigest() != digest:
            raise ValueError('image digest mismatch')
        if size != original.st_size or source_identity(os.fstat(incoming.fileno())) != source_identity(original):
            raise ValueError('image changed during digest verification')
        # Reject symlink ancestry rather than following a caller's redirected cache.
        for parent in (destination.parent.absolute(), *destination.parent.absolute().parents):
            if parent.is_symlink():
                raise ValueError('cache directory must not contain symlinks')
        destination.parent.mkdir(parents=True, exist_ok=True)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            lock_fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                              0o600, dir_fd=directory_fd)
            try:
                lock_stat = os.fstat(lock_fd)
                if not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1 or lock_stat.st_size != 0:
                    raise ValueError('cache writer lock must be an empty regular file, not a link')
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                if source_identity(os.fstat(incoming.fileno())) != source_identity(original):
                    raise ValueError('image changed while waiting for cache writer lock')
                used = cache_bytes(directory_fd, lock_stat)
                if used + size > budget_bytes:
                    raise CacheQuotaExceeded(f'{used} existing + {size} temporary bytes exceeds {budget_bytes}')
                temporary = '.image-cache-tmp-' + secrets.token_hex(16)
                outgoing_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      0o600, dir_fd=directory_fd)
                try:
                    incoming.seek(0)
                    checksum = hashlib.new(algorithm)
                    copied = 0
                    with os.fdopen(outgoing_fd, 'wb') as outgoing:
                        for chunk in iter(lambda: incoming.read(1024 * 1024), b''):
                            copied += len(chunk)
                            if copied > size:
                                raise ValueError('image changed during copy')
                            checksum.update(chunk)
                            outgoing.write(chunk)
                        if copied != size or checksum.hexdigest() != digest or source_identity(
                            os.fstat(incoming.fileno())
                        ) != source_identity(original):
                            raise ValueError('image changed during copy')
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                    os.replace(temporary, destination.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    temporary = None
                finally:
                    if temporary is not None:
                        os.unlink(temporary, dir_fd=directory_fd)
            finally:
                os.close(lock_fd)
        finally:
            os.close(directory_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--algorithm', choices=('sha256', 'sha512'), required=True)
    parser.add_argument('--digest', required=True)
    parser.add_argument('--cache-write', action='store_true',
                        help='publish to the bounded optional flat image cache')
    parser.add_argument('--cache-budget-bytes', type=int, default=DEFAULT_CACHE_BUDGET_BYTES,
                        help='maximum cumulative cache file bytes including the temporary copy (default: 4 GiB)')
    args = parser.parse_args()
    if args.cache_budget_bytes < 0:
        parser.error('--cache-budget-bytes must be nonnegative')
    try:
        if args.cache_write:
            publish_cache(args.source, args.destination, args.algorithm, args.digest, args.cache_budget_bytes)
        else:
            verified_copy(args.source, args.destination, args.algorithm, args.digest)
    except CacheQuotaExceeded as error:
        parser.exit(4, f'Image cache quota exceeded: {error}\n')
    except (OSError, ValueError) as error:
        parser.exit(1, f'Image cache rejected: {error}\n')


if __name__ == '__main__':
    main()

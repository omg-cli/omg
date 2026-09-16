#!/usr/bin/env python3
"""Copy pinned image bytes through an untrusted cache; never cache guest state."""
import argparse
import hashlib
import os
from pathlib import Path
import re
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--algorithm', choices=('sha256', 'sha512'), required=True)
    parser.add_argument('--digest', required=True)
    args = parser.parse_args()
    try:
        verified_copy(args.source, args.destination, args.algorithm, args.digest)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Image cache rejected: {error}\n')


if __name__ == '__main__':
    main()

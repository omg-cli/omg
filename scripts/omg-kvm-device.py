#!/usr/bin/env python3
"""Provision and verify the Ubuntu WSL runner's private KVM device node.

WSL distros share /dev/kvm, whose group and ACL can change when another distro
starts. The runner's ext4 filesystem has a separate inode with stable ownership.
"""

import argparse
import fcntl
import grp
import os
from pathlib import Path
import stat
import sys


SOURCE = Path("/dev/kvm")
PARENT = Path("/var/lib/omg-runner")
ALIAS = PARENT / "kvm"
GROUP = "omgci"
KVM_GET_API_VERSION = 0xAE00


class KvmDeviceError(Exception):
    pass


def reject_extended_acl(path: Path) -> None:
    # A default ACL on the parent can grant a named user access to a new node
    # even when stat reports 0660: the group bits then represent the ACL mask.
    attributes = os.listxattr(path, follow_symlinks=False)
    if any(name in ("system.posix_acl_access", "system.posix_acl_default") for name in attributes):
        raise KvmDeviceError(f"{path} has an extended POSIX ACL")


def character_device(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise KvmDeviceError(f"{path} is missing") from exc
    if not stat.S_ISCHR(info.st_mode):
        raise KvmDeviceError(f"{path} is not a character device")
    return info


def private_parent(path: Path, create: bool) -> None:
    if create:
        try:
            path.mkdir(mode=0o755)
        except FileExistsError:
            pass
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise KvmDeviceError(f"{path} is missing") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise KvmDeviceError(f"{path} must be a real directory, not a symlink")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise KvmDeviceError(f"{path} must be a root-owned, non-writable directory")
    if info.st_mode & 0o111 != 0o111:
        raise KvmDeviceError(f"{path} must be traversable by the runner")
    reject_extended_acl(path)
    # Character nodes on nodev mounts exist but cannot be opened.
    if os.statvfs(path).f_flag & getattr(os, "ST_NODEV", 4):
        raise KvmDeviceError(f"{path} is on a nodev filesystem")


def probe(path: Path, expected_device: int | None = None) -> None:
    before = character_device(path)
    if expected_device is not None and before.st_rdev != expected_device:
        raise KvmDeviceError(f"{path} major/minor differs from {SOURCE}")
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise KvmDeviceError(f"cannot open {path} read/write: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISCHR(opened.st_mode) or opened.st_rdev != before.st_rdev:
            raise KvmDeviceError(f"{path} changed during verification")
        api = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
        if api != 12:
            raise KvmDeviceError(f"{path} returned unexpected KVM API version {api}")
    except OSError as exc:
        raise KvmDeviceError(f"KVM ioctl failed on {path}: {exc}") from exc
    finally:
        os.close(fd)


def verify_alias(source: Path = SOURCE, alias: Path = ALIAS, group: str = GROUP) -> None:
    source_info = character_device(source)
    private_parent(alias.parent, create=False)
    alias_info = character_device(alias)
    reject_extended_acl(alias)
    expected_gid = grp.getgrnam(group).gr_gid
    if (alias_info.st_uid, alias_info.st_gid, stat.S_IMODE(alias_info.st_mode)) != (0, expected_gid, 0o660):
        raise KvmDeviceError(f"{alias} must be root:{group} mode 0660")
    probe(alias, source_info.st_rdev)


def setup_alias(source: Path = SOURCE, alias: Path = ALIAS, group: str = GROUP) -> None:
    if os.geteuid() != 0:
        raise KvmDeviceError("setup requires root")
    source_info = character_device(source)
    probe(source, source_info.st_rdev)
    private_parent(alias.parent, create=True)
    expected_gid = grp.getgrnam(group).gr_gid
    try:
        alias.lstat()
    except FileNotFoundError:
        os.mknod(alias, stat.S_IFCHR | 0o600, source_info.st_rdev)
        os.chown(alias, 0, expected_gid, follow_symlinks=False)
        os.chmod(alias, 0o660, follow_symlinks=False)
    # An existing wrong node is an error, never silently replaced or chmodded.
    verify_alias(source, alias, group)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup", "check", "probe-hosted"))
    args = parser.parse_args()
    try:
        if args.command == "setup":
            setup_alias()
        elif args.command == "check":
            verify_alias()
        else:
            probe(SOURCE)
    except (KvmDeviceError, OSError, KeyError) as exc:
        print(f"KVM device check failed: {exc}", file=sys.stderr)
        return 1
    print(f"KVM API 12 available via {ALIAS if args.command != 'probe-hosted' else SOURCE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

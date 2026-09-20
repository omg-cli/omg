#!/usr/bin/env python3
"""Export bounded, allowlisted QEMU diagnostics without following filesystem links.

Linux CI invokes this with sudo to read controller-owned diagnostics. Raw guest
state is never traversed. The fresh destination contains runner-owned regular
files, preserving report paths for the nightly recursive results collector.
"""
import argparse
import json
import os
from pathlib import PurePosixPath
import re
import stat


MAX_ENTRIES = 20000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
NAME = r"[a-zA-Z0-9][a-zA-Z0-9_.-]*"
RUN = r"run-[a-zA-Z0-9-]+"
HOST_FILES = {
    "results.json", "sentry-results.json", "metadata.txt", "host-metadata.txt",
    "cleanup.log", "reporting.log", "reporting-status.json", "kvm-probe.log", "engine-preflight.log",
    "controller-setup.log", "controller-security.log", "controller-pull.log", "image-setup.log", "boot.log", "guest-check.log",
    "evidence-copy.log", "benchmark-validation.log", "transactions.log",
    "transaction-validation.log", "inventory.log",
    "guest-health.json", "controller-health.json", "controller-final-state.json", "health-validation.log",
    "inventory-admission.json",
    "storage-faults.json", "storage-faults.log",
    "egress-policy.json", "egress-policy.log",
    "image-provenance.json", "image-cache.log",
    "benchmark-driver-sha256.txt", "cases.tsv", "controller-id.txt", "release-checksum.txt",
}
GUEST_FILES = {
    "qemu-startup.log", "daemon-lifecycle.json",
    "daemon-direct.log", "daemon-foreground.log",
    "daemon-direct-status.txt", "daemon-foreground-status.txt",
    "daemon-direct-duplicate.txt", "daemon-foreground-duplicate.txt",
    "daemon-direct-launcher.txt", "daemon-foreground-launcher.txt",
    "exit-code", "audit-directory-after.txt", "audit-directory-metadata.txt",
    "index-update.txt", "search.txt", "omg-info.txt", "native-info.txt",
    "local-package.sha256", "local-consent.txt", "system-audit-verify.txt",
    "installed-after.txt", "repository-hashes.txt", "guest-metadata.txt",
    "inventory-setup.txt", "container-engine.txt", "rust-toolchain.txt",
}
BENCH_FILES = {
    "summary.json", "preflight.json", "os-release", "boot-id.txt", "cpuinfo.txt",
    "meminfo.txt", "kernel.txt", "binary-sha256.txt", "hyperfine-version.txt",
    "native-version.txt", "omg-version.txt", "extra-version.txt",
    "proc-stat-before.txt", "proc-stat-after.txt", "foreign-architectures.txt",
    "installed.names", "uninstalled-manual.names", "installed-before.tsv",
    "installed-after.tsv", "installed-expected.tsv", "manual-before.names",
    "manual-after.names", "manual-expected.names", "cache-before.sha256",
    "cache-after.sha256", "started-at.txt",
}
# Additional files emitted by benchmark-hyperfine.sh --guest-transaction.
# Admit these only at the transaction-trial root, never in cache/data/config.
TRANSACTION_FILES = {
    "command.json", "expected-identity.tsv",
    "omg-info-before.stdout", "omg-info-before.stderr",
    "native-info-before.stdout", "native-info-before.stderr",
    "omg-identity-before.tsv", "native-identity-before.tsv",
    "manual-before.stdout", "manual-before.stderr", "manual-after.stdout", "manual-after.stderr",
    "cache-before-paths.txt", "cache-after-paths.txt",
}


def benchmark_file(name):
    return name in BENCH_FILES or re.fullmatch(
        r"(?:info|search|explicit|status|install|remove|update)(?:\.commands)?\.(?:json|md)"
        r"|(?:omg|native|extra)-(?:info|identity)(?:-after)?\.(?:stdout|stderr|tsv)"
        r"|(?:search|explicit|count)-(?:omg|native|extra)-(?:before|after)\.(?:stdout|stderr|names)"
        r"|native-cache-prepare\.(?:stdout|stderr)", name
    ) is not None


def allowed_directory(parts):
    if not parts:
        return True
    if not re.fullmatch(RUN, parts[0]):
        return False
    rest = parts[1:]
    return rest in ((), ("guest",), ("guest", "evidence"),
                    ("guest", "evidence", "benchmarks"), ("inventory",),
                    ("inventory", "rows"), ("transactions",), ("transactions", "trials")) or (
        len(rest) in (3, 4) and rest[:2] == ("transactions", "trials")
        and re.fullmatch(NAME, rest[2]) is not None
        and (len(rest) == 3 or rest[3] == "transaction-trial")
    )


def allowed_file(parts):
    if parts == ("provenance.json",):
        return True
    if len(parts) < 2 or not allowed_directory(parts[:-1]):
        return False
    parent, name = parts[1:-1], parts[-1]
    if parent == ():
        return name in HOST_FILES
    if parent == ("guest",):
        return name == "serial.log"
    if parent == ("guest", "evidence"):
        return name in GUEST_FILES
    if parent == ("inventory",):
        return name in {"results.json", "summary.json", "metadata.json", "input-sha256.txt"}
    if parent == ("inventory", "rows"):
        return re.fullmatch(r"[a-z0-9][a-z0-9-]*(?:\.stdout|\.stderr)?\.log", name) is not None
    if parent == ("transactions",):
        return name in {"results.json", "summary.json", "bases.json", "boot-ids.txt",
                        "expected-version.txt", "automatic-updates.log", "resume-disk.log",
                        "resume-serial.log", "resume-boot.log"} or re.fullmatch(
            r"(?:install|remove)-(?:base-check\.log|base-unchanged\.log|firmware\.sha256|"
            r"repository-state\.(?:log|sha256)|before\.tsv|manual-before\.names)"
            r"|(?:prepare|stop-prepared)-(?:install|remove)(?:-serial|-boot)?\.log", name
        ) is not None
    if len(parent) == 3 and parent[:2] == ("transactions", "trials"):
        return name in {"disk-create.log", "serial.log", "boot.log", "guest.log", "copy.log",
                        "validation.log", "stop.log", "health.json", "health.log"}
    return benchmark_file(name) or (
        len(parent) == 4 and parent[:2] == ("transactions", "trials")
        and parent[3] == "transaction-trial" and name in TRANSACTION_FILES
    )


def open_directory(path):
    """Open every absolute path component without resolving any symlink."""
    parts = PurePosixPath(path).parts
    if not parts or parts[0] != "/" or ".." in parts:
        raise ValueError("an absolute path without parent traversal is required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for component in parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def export(source, destination, uid, gid, max_file=MAX_FILE_BYTES, max_total=MAX_TOTAL_BYTES,
           max_entries=MAX_ENTRIES):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("descriptor-safe export requires POSIX directory descriptors")
    destination = PurePosixPath(destination)
    parent = open_directory(str(destination.parent))
    try:
        # Never reuse or clean a pre-existing destination, even an empty one.
        os.mkdir(destination.name, 0o700, dir_fd=parent)
        target = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=parent)
        os.fchown(target, uid, gid)
    finally:
        os.close(parent)
    report = {"copied": [], "skipped": [], "errors": [], "bytes": 0}
    entries = 0

    def write_file(directory, name, data):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=directory)
        try:
            os.fchown(fd, uid, gid)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
        finally:
            os.close(fd)

    def walk(source_fd, target_fd, parts):
        nonlocal entries
        with os.scandir(source_fd) as iterator:
            for entry in iterator:
                entries += 1
                if entries > max_entries:
                    raise ValueError("entry budget exceeded")
                child = (*parts, entry.name)
                relative = "/".join(child)
                if not allowed_directory(child) and not allowed_file(child):
                    report["skipped"].append(relative)
                    continue
                fd = None
                try:
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                    if allowed_directory(child):
                        flags |= os.O_DIRECTORY
                    fd = os.open(entry.name, flags, dir_fd=source_fd)
                    before = os.fstat(fd)
                    if allowed_directory(child):
                        os.mkdir(entry.name, 0o700, dir_fd=target_fd)
                        out = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=target_fd)
                        try:
                            os.fchown(out, uid, gid)
                            walk(fd, out, child)
                        finally:
                            os.close(out)
                    else:
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                            raise ValueError("not a single-link regular file")
                        if before.st_size > max_file or report["bytes"] + before.st_size > max_total:
                            raise ValueError("file or total byte budget exceeded")
                        with os.fdopen(fd, "rb", closefd=False) as stream:
                            data = stream.read(max_file + 1)
                        after = os.fstat(fd)
                        if (len(data) != before.st_size or after.st_size != before.st_size
                                or after.st_mtime_ns != before.st_mtime_ns or after.st_nlink != 1):
                            raise ValueError("file changed during export")
                        write_file(target_fd, entry.name, data)
                        report["bytes"] += len(data)
                        report["copied"].append(relative)
                except (OSError, ValueError) as error:
                    report["errors"].append({"path": relative, "error": str(error)})
                finally:
                    if fd is not None:
                        os.close(fd)

    try:
        try:
            source_fd = open_directory(source)
            try:
                walk(source_fd, target, ())
            finally:
                os.close(source_fd)
        except (OSError, ValueError) as error:
            report["errors"].append({"path": ".", "error": str(error)})
        write_file(target, "export-report.json", (json.dumps(report, indent=2) + "\n").encode())
        os.fchown(target, uid, gid)
    finally:
        os.close(target)
    print(f"Exported {len(report['copied'])} files ({report['bytes']} bytes); "
          f"skipped {len(report['skipped'])} paths; {len(report['errors'])} errors")
    return 1 if report["errors"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    args = parser.parse_args()
    return export(args.source, args.destination, args.uid, args.gid)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Prove a distro release binary refuses a different live package backend.

Run only in a disposable QEMU guest, as root inside a private mount namespace.
Exit 1 is a product failure; exit 120 is an incomplete fixture or oracle.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tempfile


class ProductFailure(Exception):
    """The binary completed but violated the backend isolation contract."""


DATABASE_PATHS = {
    "arch": ("/var/lib/pacman/local",),
    "debian": ("/var/lib/dpkg/status", "/var/lib/apt/extended_states"),
    "ubuntu": ("/var/lib/dpkg/status", "/var/lib/apt/extended_states"),
    "fedora": ("/usr/lib/sysimage/rpm", "/var/lib/rpm"),
}
FAKE_ID = {"arch": "fedora", "debian": "fedora", "ubuntu": "fedora", "fedora": "debian"}
NATIVE_EXECUTABLES = {
    "arch": ("pacman", "pacman-conf"),
    "debian": ("apt", "apt-get", "apt-cache", "dpkg", "dpkg-query"),
    "ubuntu": ("apt", "apt-get", "apt-cache", "dpkg", "dpkg-query"),
    "fedora": ("dnf", "dnf5", "rpm", "rpmdb"),
}
PROBES = (
    ("doctor", ("doctor",)),
    ("info", ("info", "bash")),
    ("search", ("search", "bash")),
    ("status", ("status",)),
    ("explicit_count", ("ec",)),
    ("install_dry_run", ("install", "--dry-run", "bash")),
    ("remove_dry_run", ("remove", "--dry-run", "bash")),
    ("update_check", ("update", "--check")),
    ("clean_dry_run", ("clean", "--cache", "--dry-run")),
    ("dash", ("dash",)),
    ("omgd", ()),
)


def database_snapshot(distro):
    digest = hashlib.sha256()
    found = False
    for root_name in DATABASE_PATHS[distro]:
        root = Path(root_name)
        if not root.exists():
            continue
        found = True
        paths = [root, *sorted(root.rglob("*"))] if root.is_dir() else [root]
        for path in paths:
            metadata = path.lstat()
            digest.update(f"{path}:{metadata.st_mode}:{metadata.st_uid}:"
                          f"{metadata.st_gid}:{metadata.st_size}:"
                          f"{metadata.st_mtime_ns}".encode())
            if path.is_symlink():
                digest.update(os.readlink(path).encode())
            if path.is_file():
                with path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
    if not found:
        raise RuntimeError("native package database fixture is missing")
    return digest.hexdigest()


def native_db_access(trace_text, distro):
    return (any(f'"{path}' in trace_text for path in DATABASE_PATHS[distro])
            or any(re.search(rf'execve\("[^"]*/{tool}"', trace_text)
                   for tool in NATIVE_EXECUTABLES[distro]))


def validate_receipt(receipt, distro):
    if not isinstance(receipt, dict) or receipt.get("schema_version") != 1:
        raise ValueError("invalid backend mismatch receipt")
    if receipt.get("distro") != distro or receipt.get("fixture_distro") != FAKE_ID[distro]:
        raise ValueError("backend mismatch receipt identifies the wrong guest or fixture")
    if receipt.get("complete") is not True or receipt.get("failure_kind") != "none":
        raise ValueError("backend mismatch probe did not pass")
    if not all(isinstance(receipt.get(key), str) and
               re.fullmatch(r"[0-9a-f]{64}", receipt[key])
               for key in ("db_before", "db_after")):
        raise ValueError("native package database snapshots are missing")
    if receipt.get("db_before") != receipt.get("db_after"):
        raise ValueError("native package database changed")
    for name, _ in PROBES:
        if receipt.get(f"{name}_exit") != 1 or receipt.get(f"{name}_mismatch") is not True:
            raise ValueError(f"{name} did not fail with an actionable mismatch")
        if receipt.get(f"{name}_native_db_access") is not False:
            raise ValueError(f"{name} accessed the native package database")
    if receipt.get("omgd_state_created") is not False:
        raise ValueError("omgd created runtime or cache state")


def run(binary_name, distro):
    if os.geteuid() != 0:
        raise RuntimeError("backend mismatch fixture requires root in a private mount namespace")
    virt = subprocess.run(["systemd-detect-virt", "--vm"], capture_output=True, text=True,
                          timeout=10, check=False)
    if virt.returncode != 0 or virt.stdout.strip() not in ("kvm", "qemu"):
        raise RuntimeError("backend mismatch fixture requires a disposable QEMU guest")
    account = pwd.getpwnam("bench")
    binary = Path(binary_name).resolve(strict=True)
    daemon = binary.with_name("omgd")
    if (binary.name != "omg" or not binary.is_relative_to(Path(account.pw_dir))
            or not os.access(binary, os.X_OK) or not os.access(daemon, os.X_OK)):
        raise RuntimeError("expected installed omg and omgd release binaries")
    if distro not in DATABASE_PATHS:
        raise RuntimeError("unsupported guest distribution")
    source_id = Path("/etc/os-release").read_text().splitlines()
    if not any(line == f"ID={distro}" or line == f'ID="{distro}"' for line in source_id):
        raise RuntimeError("guest /etc/os-release does not match requested distribution")
    if not shutil.which("strace") or not shutil.which("mount") or not shutil.which("setpriv"):
        raise RuntimeError("backend mismatch fixture requires strace, mount, and setpriv")

    root = Path(tempfile.mkdtemp(prefix="omg-backend-mismatch-", dir=account.pw_dir))
    os.chown(root, account.pw_uid, account.pw_gid)
    fixture = root / "os-release"
    fixture.write_text(f"ID={FAKE_ID[distro]}\nNAME=OMG-QEMU-backend-mismatch\n")
    trace_probe_path = root / "preflight.trace"
    receipt = {"schema_version": 1, "distro": distro, "fixture_distro": FAKE_ID[distro],
               "complete": False, "failure_kind": "harness"}
    try:
        receipt["db_before"] = database_snapshot(distro)
        mount = subprocess.run(["mount", "--bind", str(fixture), "/etc/os-release"],
                               capture_output=True, text=True, timeout=10, check=False)
        if mount.returncode != 0:
            raise RuntimeError(f"private os-release bind mount failed: {mount.stderr.strip()}")
        if f"ID={FAKE_ID[distro]}" not in Path("/etc/os-release").read_text().splitlines():
            raise RuntimeError("private os-release bind mount did not take effect")

        env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "USER": "bench", "LOGNAME": "bench",
               "OMG_CONFIG_DIR": str(root / "config"), "OMG_CACHE_DIR": str(root / "cache"),
               "OMG_DATA_DIR": str(root / "data"), "OMG_TEST_MODE": "0",
               "OMG_DISABLE_DAEMON": "1", "OMG_NO_UPDATE_CHECK": "1", "NO_COLOR": "1"}
        prefix = ["setpriv", f"--reuid={account.pw_uid}", f"--regid={account.pw_gid}",
                  "--clear-groups", "--no-new-privs", "--bounding-set=-all",
                  "--inh-caps=-all", "--ambient-caps=-all"]
        trace_probe = subprocess.run(
            ["strace", "--kill-on-exit", "-f", "-qq", "-e", "trace=execve,%file", "-o", str(trace_probe_path)]
            + prefix + ["/usr/bin/true"], env=env, cwd=root, capture_output=True,
            text=True, timeout=10, check=False)
        if (trace_probe.returncode != 0 or not trace_probe_path.is_file()
                or 'execve("/usr/bin/true"' not in trace_probe_path.read_text()):
            raise RuntimeError("strace fixture cannot trace a privilege-dropped command")
        expected_feature = FAKE_ID[distro]
        for name, args in PROBES:
            command = [str(daemon if name == "omgd" else binary), *args]
            trace = root / f"{name}.trace"
            argv = ["strace", "--kill-on-exit", "-f", "-qq", "-e", "trace=execve,%file", "-o", str(trace)]
            argv += prefix + command
            command_env = env.copy()
            if name == "omgd":
                command_env["HOME"] = str(root / "daemon-home")
                command_env["OMG_CONFIG_DIR"] = str(root / "daemon-config")
                command_env["OMG_CACHE_DIR"] = str(root / "daemon-cache")
                command_env["OMG_DATA_DIR"] = str(root / "daemon-cli-data")
                command_env["OMG_DAEMON_DATA_DIR"] = str(root / "daemon-data")
                command_env["XDG_RUNTIME_DIR"] = str(root / "daemon-runtime")
                command_env["OMG_SOCKET_PATH"] = str(root / "daemon-runtime/omg.sock")
            result = subprocess.run(argv, env=command_env, cwd=root, capture_output=True, text=True,
                                    timeout=45, check=False)
            output = result.stdout + result.stderr
            receipt[f"{name}_exit"] = result.returncode
            receipt[f"{name}_mismatch"] = ("package backend" in output.lower()
                and f"--features {expected_feature}," in output)
            receipt[f"{name}_output"] = output[-4096:]
            if not trace.is_file():
                raise RuntimeError(f"{name} syscall trace is missing")
            trace_text = trace.read_text()
            if f'execve("{command[0]}"' not in trace_text:
                raise RuntimeError(f"{name} syscall trace did not execute the submitted binary")
            receipt[f"{name}_native_db_access"] = native_db_access(trace_text, distro)
            if receipt[f"{name}_native_db_access"]:
                raise ProductFailure(f"{name} accessed the native package database before refusing")
            if result.returncode != 1 or not receipt[f"{name}_mismatch"]:
                raise ProductFailure(f"{name} did not refuse the wrong backend with build guidance")
            if name == "omgd":
                receipt["omgd_state_created"] = any((root / leaf).exists() for leaf in
                    ("daemon-home", "daemon-config", "daemon-cache", "daemon-cli-data",
                     "daemon-data", "daemon-runtime"))
                if receipt["omgd_state_created"]:
                    raise ProductFailure("omgd created socket, runtime, or cache state before rejecting the backend")
        try:
            receipt["db_after"] = database_snapshot(distro)
        except (OSError, RuntimeError) as error:
            raise ProductFailure(f"native package database became unreadable: {error}") from error
        if receipt["db_before"] != receipt["db_after"]:
            raise ProductFailure("native package database changed during wrong-backend probes")
        receipt["complete"] = True
        receipt["failure_kind"] = "none"
        validate_receipt(receipt, distro)
        return receipt, 0
    except ProductFailure as error:
        receipt["failure_kind"] = "product"
        receipt["error"] = str(error)
        if "db_before" in receipt and "db_after" not in receipt:
            try:
                receipt["db_after"] = database_snapshot(distro)
            except (OSError, RuntimeError) as snapshot_error:
                receipt["db_after_error"] = str(snapshot_error)
        print(f"PRODUCT_FAIL: {error}", file=sys.stderr)
        return receipt, 1
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        receipt["failure_kind"] = "harness"
        receipt["error"] = str(error)
        print(f"HARNESS_ERROR: {error}", file=sys.stderr)
        return receipt, 120
    finally:
        shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary")
    parser.add_argument("--distro", choices=sorted(DATABASE_PATHS))
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    if args.receipt:
        validate_receipt(json.loads(args.receipt.read_text()), args.distro)
        return 0
    if not args.binary or not args.distro:
        parser.error("--binary and --distro are required in probe mode")
    try:
        receipt, status = run(args.binary, args.distro)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        receipt = {"schema_version": 1, "distro": args.distro,
                   "fixture_distro": FAKE_ID[args.distro], "complete": False,
                   "failure_kind": "harness", "error": str(error)}
        status = 120
    print(json.dumps(receipt, sort_keys=True))
    return status


if __name__ == "__main__":
    sys.exit(main())

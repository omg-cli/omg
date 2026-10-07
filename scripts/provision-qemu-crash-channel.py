#!/usr/bin/env python3
"""Activate the real vendor crash collector in a disposable QEMU guest."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SPEC = importlib.util.spec_from_file_location(
    "qemu_health", Path(__file__).with_name("check-qemu-health.py"))
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)
DESTINATION = Path("/etc/sysctl.d/99-omg-qemu-coredump.conf")


def vendor_settings(text):
    settings = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key not in ("kernel.core_pattern", "kernel.core_pipe_limit"):
            continue
        if not separator or key in settings:
            raise ValueError("ambiguous vendor crash settings")
        settings[key] = value
    pattern = settings.get("kernel.core_pattern", "")
    match = HEALTH.CORE_PATTERN.fullmatch(pattern)
    limit = settings.get("kernel.core_pipe_limit", "")
    if not match or not re.fullmatch(r"[1-9][0-9]?", limit) or int(limit) > 64:
        raise ValueError("unsupported vendor crash settings")
    return pattern, limit, match[1]


def provision():
    if os.geteuid() != 0:
        raise ValueError("crash provisioning requires guest root")
    if HEALTH.query(["systemd-detect-virt", "--vm"]).strip() not in ("qemu", "kvm"):
        raise ValueError("crash provisioning requires a QEMU/KVM guest")
    vendor = Path("/usr/lib/sysctl.d/50-coredump.conf")
    if not vendor.exists():
        vendor = Path("/lib/sysctl.d/50-coredump.conf")
    info = vendor.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("vendor crash settings are not root protected")
    pattern, limit, handler = vendor_settings(HEALTH.bounded_file(vendor))
    HEALTH.query(["test", "-x", handler])
    content = ("# Disposable OMG QEMU guest: vendor crash collector settings only.\n"
               f"kernel.core_pattern={pattern}\nkernel.core_pipe_limit={limit}\n")
    if DESTINATION.is_symlink():
        raise ValueError("guest crash settings destination is a symlink")
    if DESTINATION.exists():
        info = DESTINATION.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or HEALTH.bounded_file(DESTINATION) != content:
            raise ValueError("guest crash settings already differ")
    else:
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=DESTINATION.parent,
                                             prefix=".omg-coredump-", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content)
                os.fchmod(stream.fileno(), 0o644)
            temporary.replace(DESTINATION)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    sysctl = Path("/usr/lib/systemd/systemd-sysctl")
    if not sysctl.exists():
        sysctl = Path("/lib/systemd/systemd-sysctl")
    HEALTH.query(["systemctl", "daemon-reload"])
    HEALTH.query(["systemctl", "start", "systemd-coredump.socket"])
    HEALTH.query([str(sysctl), str(DESTINATION)])
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not HEALTH.BOOT_ID.fullmatch(boot):
        raise ValueError("invalid guest boot identity")
    channel = HEALTH.crash_channel_capability(boot)
    if channel["core_pattern"] != pattern:
        raise ValueError("guest crash handler differs from vendor")
    if HEALTH.query(["cat", "/proc/sys/kernel/core_pipe_limit"]).strip() != limit:
        raise ValueError("guest crash processing does not wait for collector")
    return {"schema_version": 1, "vendor_config": str(vendor),
            "guest_config": str(DESTINATION), "core_pipe_limit": int(limit),
            "crash_channel": channel}


def main():
    try:
        print(json.dumps(provision()))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"QEMU crash channel provisioning failed: {error}", file=sys.stderr)
        return 120


if __name__ == "__main__":
    raise SystemExit(main())

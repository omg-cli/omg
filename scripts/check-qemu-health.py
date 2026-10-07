#!/usr/bin/env python3
"""Collect bounded guest health and reject crash evidence before QEMU admission.

Only kernel messages and selected coredump identity fields are queried. Never
collect core files, process environments, command lines or arbitrary journals.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

LIMIT = 1024 * 1024
FATAL = re.compile(
    r"(?:Kernel panic - not syncing:|BUG: (?:unable to handle|kernel NULL|soft lockup)|"
    r"Oops:|watchdog: BUG: soft lockup|NMI watchdog: Watchdog detected hard LOCKUP|"
    r"Out of memory: Killed process|Memory cgroup out of memory: Killed process|"
    r"(?:omg|omgd)\[[0-9]+\]: (?:segfault|general protection fault)|"
    # Linux x86 show_signal emits comm[pid] trap description without a colon.
    # Require the known identity and IP field; publish no addresses or VMA path.
    r"(?<![\w.-])(?:omg|omgd)\[[0-9]+\] trap (?:invalid opcode|divide error)(?= ip:[0-9a-f]))"
)
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
CORE_PATTERN = re.compile(
    r"\|(/(?:usr/)?lib(?:64)?/systemd/systemd-coredump)"
    # Debian's vendor configuration replaces %c with this exact RLIMIT value.
    # Preserve the same handler and positional ABI; arbitrary literals refuse.
    r" %P %u %g %s %t (?:%c|9223372036854775808) %h(?: %d(?: %F(?: %I)?)?)?"
)
CAPABILITY_PROPERTIES = "Id,LoadState,ActiveState,SubState,Result,UnitFileState"


def validate_crash_channel(channel, boot_id):
    if (not isinstance(channel, dict)
            or channel.get("kind") != "systemd-coredump-pipe"
            or channel.get("boot_id") != boot_id
            or not isinstance(channel.get("core_pattern"), str)
            or not CORE_PATTERN.fullmatch(channel["core_pattern"])
            or channel.get("handler_executable") is not True):
        raise ValueError("missing or unsupported crash channel capability")
    for name, identity, active, substate in (
        ("socket", "systemd-coredump.socket", "active", "listening"),
        ("processor", "systemd-coredump@omg-health.service", "inactive", "dead"),
    ):
        fields = channel.get(name)
        if (not isinstance(fields, dict)
                or set(fields) != set(CAPABILITY_PROPERTIES.split(","))
                or fields["Id"] != identity or fields["LoadState"] != "loaded"
                or fields["ActiveState"] != active or fields["SubState"] != substate
                or fields["Result"] != "success"
                or fields["UnitFileState"] not in ("static", "enabled", "enabled-runtime")):
            raise ValueError("crash channel is absent, disabled, pending or failed")


def crash_channel_capability(boot_id):
    pattern = query(["cat", "/proc/sys/kernel/core_pattern"]).strip()
    match = CORE_PATTERN.fullmatch(pattern)
    if not match:
        raise ValueError("unsupported kernel crash handler")
    # Check executable availability without invoking the handler or reading cores.
    query(["test", "-x", match[1]])
    channel = {"kind": "systemd-coredump-pipe", "boot_id": boot_id,
               "core_pattern": pattern, "handler_executable": True}
    for name, unit in (("socket", "systemd-coredump.socket"),
                       ("processor", "systemd-coredump@omg-health.service")):
        # An inert instance loads the template without starting a processor.
        evidence = query(["systemctl", "show", "--all",
                          "--property=" + CAPABILITY_PROPERTIES, unit])
        fields = {}
        for line in evidence.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in CAPABILITY_PROPERTIES.split(",") or key in fields:
                raise ValueError("invalid crash channel capability evidence")
            fields[key] = value
        channel[name] = fields
    validate_crash_channel(channel, boot_id)
    return channel


def bounded_file(path, errors="strict"):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError("invalid or oversized health evidence")
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("health evidence grew beyond limit")
    return data.decode("utf-8", errors=errors)


def query(argv):
    # File-backed capture bounds Python memory even if a guest is very noisy.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        completed = subprocess.run(argv, stdout=output, stderr=errors,
                                   timeout=15, check=False)
        if completed.returncode != 0 or output.tell() > LIMIT:
            errors.seek(0)
            detail = errors.read(4096).decode("utf-8", errors="replace")
            detail = re.sub(r"[^a-zA-Z0-9 ._:/=()\n-]", "?", detail)
            kind = "kernel" if "--dmesg" in argv else "crash"
            raise ValueError(f"{kind} health query failed: exit={completed.returncode}, bytes={output.tell()}: {detail}")
        output.seek(0)
        return output.read(LIMIT + 1).decode("utf-8", errors="strict")


def crash_signatures(text):
    # Publish only the matched signature, never adjacent potentially sensitive text.
    return sorted(set(match.group(0) for match in FATAL.finditer(text)))


def refuse_pending_crash_processing():
    properties = {"Id", "ActiveState", "SubState", "Result"}
    evidence = query(["systemctl", "show", "--all",
                      "--property=Id,ActiveState,SubState,Result", "systemd-coredump@*.service"])
    for block in evidence.strip().split("\n\n"):
        if not block:
            continue
        fields = {}
        for line in block.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key not in properties or key in fields:
                raise ValueError("invalid coredump processing evidence")
            fields[key] = value
        if (set(fields) != properties
                or not fields["Id"].startswith("systemd-coredump@")
                or not fields["Id"].endswith(".service")
                or not fields["SubState"]):
            raise ValueError("invalid coredump processing evidence")
        if fields["ActiveState"] != "inactive" or fields["Result"] != "success":
            raise ValueError("coredump processor is active or failed")


def collect():
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not BOOT_ID.fullmatch(boot_id):
        raise ValueError("invalid guest boot identity")
    # /proc uses UUID hyphens; journalctl's boot descriptor requires 32 hex digits.
    journal_boot = boot_id.replace("-", "")
    channel = crash_channel_capability(boot_id)
    refuse_pending_crash_processing()
    kernel = query(["journalctl", "--boot=" + journal_boot, "--dmesg", "--quiet", "--no-pager", "--output=cat"])
    if not kernel.strip() or kernel.strip() == "-- No entries --":
        raise ValueError("missing boot kernel evidence")
    cores = query(["journalctl", "--boot=" + journal_boot, "--quiet", "--no-pager", "--output=json",
                   "--output-fields=COREDUMP_COMM,COREDUMP_EXE,COREDUMP_SIGNAL",
                   "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1"])
    crashes = []
    for line in cores.splitlines():
        row = json.loads(line)
        executable = row.get("COREDUMP_EXE", "")
        process = Path(executable).name if isinstance(executable, str) else ""
        if process not in ("omg", "omgd"):
            process = row.get("COREDUMP_COMM")
        if process in ("omg", "omgd"):
            signal = row.get("COREDUMP_SIGNAL")
            if not isinstance(signal, str) or not re.fullmatch(r"[0-9]{1,3}", signal):
                raise ValueError("invalid crash signal")
            crashes.append({"process": process, "signal": int(signal)})
    refuse_pending_crash_processing()
    if (crash_channel_capability(boot_id) != channel
            or Path("/proc/sys/kernel/random/boot_id").read_text().strip() != boot_id):
        raise ValueError("crash channel or guest boot changed during collection")
    return {"schema_version": 2, "complete": True, "boot_id": boot_id,
            "crash_channel": channel,
            "kernel_bytes": len(kernel.encode()), "fatal_signatures": crash_signatures(kernel),
            "product_crashes": crashes}


def verify_guest(guest, serial, boot_id=None):
    payload = json.loads(bounded_file(guest))
    if (not isinstance(payload, dict) or payload.get("schema_version") != 2
            or payload.get("complete") is not True
            or not isinstance(payload.get("boot_id"), str)
            or not BOOT_ID.fullmatch(payload["boot_id"])
            or type(payload.get("kernel_bytes")) is not int
            or not 0 < payload["kernel_bytes"] <= LIMIT
            or payload.get("fatal_signatures") != []
            or payload.get("product_crashes") != []):
        raise ValueError("guest crash or incomplete health evidence")
    validate_crash_channel(payload.get("crash_channel"), payload["boot_id"])
    # Serial consoles are byte streams, not a UTF-8 protocol. A torn terminal
    # glyph must not invalidate otherwise complete health evidence. Preserve
    # invalid bytes as escapes; never discard surrounding crash signatures.
    serial_text = bounded_file(serial, errors="backslashreplace")
    if not serial_text.strip() or crash_signatures(serial_text):
        raise ValueError("missing serial evidence or fatal guest signature")
    if boot_id is not None and payload["boot_id"] != boot_id:
        raise ValueError("health evidence belongs to a different trial boot")
    return 0


def verify(guest, serial, controller, boot_id=None):
    verify_guest(guest, serial, boot_id)
    state = json.loads(bounded_file(controller))
    if (not isinstance(state, dict) or state.get("Running") is not True
            or state.get("OOMKilled") is not False
            or type(state.get("ExitCode")) is not int or state["ExitCode"] != 0):
        raise ValueError("controller stopped or was OOM killed")
    return 0


def verify_preparations(root):
    boots = set()
    for operation in ("remove", "install"):
        prefix = root / "transactions" / f"prepare-{operation}"
        boot_id = bounded_file(Path(str(prefix) + "-boot-id.txt")).strip()
        if not BOOT_ID.fullmatch(boot_id) or boot_id in boots:
            raise ValueError("invalid or repeated preparation boot identity")
        boots.add(boot_id)
        serial = (root / "guest" / "serial.log" if operation == "remove"
                  else Path(str(prefix) + "-serial.log"))
        verify_guest(Path(str(prefix) + "-health.json"), serial, boot_id)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("collect")
    preparations = commands.add_parser("verify-preparations")
    preparations.add_argument("--root", type=Path, required=True)
    trial = commands.add_parser("verify-trial")
    trial.add_argument("--guest", type=Path, required=True)
    trial.add_argument("--serial", type=Path, required=True)
    trial.add_argument("--boot-id", required=True)
    admission = commands.add_parser("verify")
    admission.add_argument("--boot-id", required=True)
    for name in ("guest", "serial", "controller"):
        admission.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "collect":
            print(json.dumps(collect()))
            return 0
        if args.command == "verify-trial":
            return verify_guest(args.guest, args.serial, args.boot_id)
        if args.command == "verify-preparations":
            return verify_preparations(args.root)
        return verify(args.guest, args.serial, args.controller, args.boot_id)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"QEMU health evidence failed admission: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

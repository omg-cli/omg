#!/usr/bin/env python3
"""Stream scoped Linux runner evidence around the unchanged mutation command.

Memory/VM counters: https://docs.kernel.org/filesystems/proc.html
Cgroup scope: https://docs.kernel.org/admin-guide/cgroup-v2.html
"""
import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

PREFIX = "OMG_MUTATION_HEALTH "
MAX_REPORT_BYTES = 1024 * 1024


def interval_seconds(value):
    number = float(value)
    if not math.isfinite(number) or not 0 < number <= 60:
        raise argparse.ArgumentTypeError("interval must be finite and between 0 and 60 seconds")
    return number


def snapshot():
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in {"MemTotal", "MemAvailable", "SwapFree"}:
            fields = value.split()
            if len(fields) != 2 or fields[1] != "kB" or key in memory:
                raise ValueError("invalid required memory metric")
            memory[key] = int(fields[0])
    if set(memory) != {"MemTotal", "MemAvailable", "SwapFree"} or any(value < 0 for value in memory.values()):
        raise ValueError("missing or negative required memory metric")
    vm = dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())
    oom = int(vm["oom_kill"])
    if oom < 0:
        raise ValueError("negative kernel OOM-kill counter")
    group = {"scope": None, "events": None, "availability": "no-unified-cgroup"}
    unified = [line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines() if line.startswith("0::")]
    if len(unified) > 1:
        raise ValueError("multiple unified cgroups")
    if unified:
        relative = Path(unified[0].lstrip("/"))
        if ".." in relative.parts:
            raise ValueError("invalid cgroup path")
        group["scope"] = unified[0]
        events = Path("/sys/fs/cgroup") / relative / "memory.events"
        if events.is_file():
            group["events"] = {key: int(value) for key, value in (line.split() for line in events.read_text().splitlines())}
            group["availability"] = "observed"
        else:
            group["availability"] = "memory-controller-unavailable"
    disk = shutil.disk_usage(Path.cwd())
    filesystem = os.statvfs(Path.cwd())
    return {"utc": datetime.now(timezone.utc).isoformat(),
            "memory_total_kib": memory["MemTotal"],
            "memory_available_kib": memory["MemAvailable"],
            "swap_free_kib": memory["SwapFree"],
            "kernel_oom_kills": oom, "cgroup_memory": group,
            "workspace_free_bytes": disk.free,
            "workspace_free_inodes": filesystem.f_favail,
            "load_average": list(os.getloadavg())}


def observe(command, report, interval):
    started = time.monotonic()
    cancellation = {"signal": None, "group_signal_error": None}
    child = None
    previous = {}
    written = 0
    with report.open("xb") as output:
        def emit(phase, returncode=None):
            nonlocal written
            row = {**snapshot(), "schema_version": 1, "phase": phase,
                   "elapsed_seconds": time.monotonic() - started,
                   "child_pid": child.pid if child else None,
                   "child_returncode": returncode,
                   "cancellation_signal": cancellation["signal"],
                   "group_signal_error": cancellation["group_signal_error"]}
            raw = (json.dumps(row, sort_keys=True) + "\n").encode()
            if written + len(raw) > MAX_REPORT_BYTES:
                raise ValueError("runner health report exceeds its byte bound")
            output.write(raw)
            output.flush()
            written += len(raw)
            print(PREFIX + raw.decode().rstrip("\n"), flush=True)

        def cancel(signum, _frame):
            cancellation["signal"] = signum
            if child is not None and child.poll() is None:
                try:
                    os.killpg(child.pid, signum)
                except ProcessLookupError as error:
                    cancellation["group_signal_error"] = str(error)

        emit("start")
        try:
            child = subprocess.Popen(command, start_new_session=True)
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, cancel)
            emit("spawn")
            while True:
                try:
                    result = child.wait(timeout=interval)
                except subprocess.TimeoutExpired:
                    emit("sample")
                else:
                    emit("finish", result)
                    if cancellation["signal"] is not None:
                        return 128 + cancellation["signal"]
                    return result if result >= 0 else 128 - result
        finally:
            if child is not None and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--interval", type=interval_seconds, default=30)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if os.name != "posix" or not command:
        parser.error("a Linux runner and command after -- are required")
    try:
        return observe(command, args.report, args.interval)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Runner health observation failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())

"""Optional Linux wait4 collector; no product workload or sampling policy.

CPU includes descendants the child itself waited for. Maximum RSS is a
high-water value in KiB, not simultaneous aggregate process-tree memory.
RSS covers the child's raw process lifetime, including its pre-exec image:
a loaded caller can impose a floor even on a small executable. Exec does not
reset resource usage. Use a fresh lightweight collector for comparisons;
no caller-floor or cumulative-RSS subtraction is performed.
Detached/unwaited descendants and persistent daemons are outside this scope.
Use only trusted bounded commands that do not escape their process group.
"""

import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import time


def output_identity(stream):
    stream.seek(0)
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(65536):
        digest.update(chunk)
        size += len(chunk)
    return size, digest.hexdigest()


def collect(command, timeout, scratch_dir):
    """Reap exactly one owned child with wait4, never cumulative RSS deltas."""
    if sys.platform != "linux":
        raise RuntimeError("collector requires Linux wait4 RSS units")
    if not command or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("command and finite timeout in (0, 60] required")
    with tempfile.TemporaryFile(dir=scratch_dir) as stdout, tempfile.TemporaryFile(dir=scratch_dir) as stderr:
        start = time.monotonic()
        process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            while True:
                waited_pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if waited_pid:
                    break
                if time.monotonic() - start >= timeout:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    waited_pid, status, usage = os.wait4(process.pid, 0)
                    break
                time.sleep(0.001)
            process.returncode = os.waitstatus_to_exitcode(status)
        finally:
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                _, status, _ = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
        elapsed = time.monotonic() - start
        stdout_size, stdout_hash = output_identity(stdout)
        stderr_size, stderr_hash = output_identity(stderr)
    return {
        "schema_version": 1, "command": command, "pid": waited_pid,
        "exit_code": process.returncode, "timed_out": timed_out,
        "elapsed_seconds": elapsed, "elapsed_clock": "monotonic",
        "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
        "max_rss_kib": usage.ru_maxrss,
        "resource_scope": "wait4 child and waited descendants; raw process-lifetime RSS includes pre-exec floor; RSS is not aggregate tree usage",
        "stdout_bytes": stdout_size, "stdout_sha256": stdout_hash,
        "stderr_bytes": stderr_size, "stderr_sha256": stderr_hash,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--scratch-dir", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    result = collect(command, args.timeout, args.scratch_dir)
    print(json.dumps(result, sort_keys=True))
    return 124 if result["timed_out"] else (result["exit_code"] if result["exit_code"] >= 0 else 128 - result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())

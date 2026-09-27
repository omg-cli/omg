#!/usr/bin/env python3
"""Prove that `omg run --watch smoke` reruns after one source edit in a PTY."""

import argparse
import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import sys
import time


READY = b"Watching for changes..."
RERUN = b"File changed, re-running"
TASK_OUTPUT = b"smoke-task-ok"
MARKER_LINE = "omg-qemu-watch-run"
MAX_OUTPUT = 65536


class WatchFailure(Exception):
    pass


def marker_count(path):
    if not path.exists() or path.is_symlink():
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    if any(line != MARKER_LINE for line in lines):
        raise WatchFailure("watch task marker contains unexpected data")
    return len(lines)


def run(binary, fixture, phase_timeout=20.0, quiet_seconds=1.5,
        shutdown_timeout=5.0):
    fixture = fixture.resolve(strict=True)
    trigger = fixture / "src" / "watch-trigger.txt"
    marker = fixture / "watch-runs.marker"
    receipt = fixture / "watch-evidence.json"
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise WatchFailure("watch binary is unavailable")
    if not trigger.is_file() or trigger.is_symlink() or marker.exists() or receipt.exists():
        raise WatchFailure("watch fixture is not clean")

    child, master = pty.fork()
    if child == 0:
        os.chdir(fixture)
        os.execv(str(binary), [str(binary), "run", "--watch", "smoke"])

    output = bytearray()
    status = None

    def poll():
        nonlocal status
        if status is None:
            pid, observed = os.waitpid(child, os.WNOHANG)
            if pid:
                status = observed
        if len(output) >= MAX_OUTPUT:
            raise WatchFailure("watch output exceeded limit")
        readable, _, _ = select.select([master], [], [], 0.05)
        if readable:
            try:
                chunk = os.read(master, min(4096, MAX_OUTPUT - len(output)))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            output.extend(chunk)
        return bytes(output)

    def wait_until(label, predicate, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            content = poll()
            count = marker_count(marker)
            if count > (1 if label == "initial run" else 2):
                raise WatchFailure("watch task ran too many times")
            if predicate(content, count):
                return
            if status is not None:
                raise WatchFailure(f"watch process exited before {label}")
        raise WatchFailure(f"watch process timed out waiting for {label}")

    def quiet(label, expected_count):
        deadline = time.monotonic() + quiet_seconds
        while time.monotonic() < deadline:
            content = poll()
            if status is not None or marker_count(marker) != expected_count:
                raise WatchFailure(f"watch process changed during {label}")
            if content.count(RERUN) > (0 if expected_count == 1 else 1):
                raise WatchFailure(f"watch process reran during {label}")

    try:
        wait_until("initial run", lambda content, count:
                   READY in content and content.count(TASK_OUTPUT) == 1 and count == 1,
                   phase_timeout)
        quiet("pre-edit quiet interval", 1)
        trigger.write_text("changed once\n", encoding="utf-8")
        wait_until("source-edit rerun", lambda content, count:
                   RERUN in content and content.count(TASK_OUTPUT) == 2 and count == 2,
                   phase_timeout)
        quiet("post-edit quiet interval", 2)
        os.write(master, b"\x03")
        deadline = time.monotonic() + shutdown_timeout
        while status is None and time.monotonic() < deadline:
            poll()
        if status is None or not (
            os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGINT
            or os.WIFEXITED(status) and os.WEXITSTATUS(status) == 130
        ):
            raise WatchFailure("watch process did not stop after Ctrl+C")
        if marker_count(marker) != 2:
            raise WatchFailure("watch task changed during shutdown")
        receipt.write_text(json.dumps({
            "schema_version": 1,
            "initial_runs": 1,
            "runs_after_edit": 2,
            "readiness_seen": True,
            "rerun_seen": True,
            "ctrl_c_stopped": True,
        }, sort_keys=True) + "\n", encoding="utf-8")
        sys.stdout.buffer.write(output)
        return 0
    except WatchFailure:
        sys.stderr.buffer.write(output[-8192:])
        raise
    finally:
        if status is None:
            try:
                os.killpg(child, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                pid, observed = os.waitpid(child, os.WNOHANG)
                if pid:
                    status = observed
                    break
                time.sleep(0.05)
            if status is None:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)
        os.close(master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--phase-timeout", type=float, default=20.0)
    parser.add_argument("--quiet-seconds", type=float, default=1.5)
    parser.add_argument("--shutdown-timeout", type=float, default=5.0)
    args = parser.parse_args()
    if min(args.phase_timeout, args.quiet_seconds, args.shutdown_timeout) <= 0:
        parser.error("timeouts must be positive")
    try:
        return run(args.binary, args.fixture, args.phase_timeout,
                   args.quiet_seconds, args.shutdown_timeout)
    except (WatchFailure, OSError, UnicodeError) as error:
        print(f"assertion failed: run --watch: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

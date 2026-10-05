"""Real controlling-PTY task checks; not a physical terminal or guest receipt."""

import errno
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import sys
import tempfile
import termios
import time


def live(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0]
        return state not in "ZX"
    except FileNotFoundError:
        return False


def check(binary, script, input_bytes, expected_success, expected_output):
    with tempfile.TemporaryDirectory() as directory:
        master, slave = pty.openpty()
        runner = os.fork()
        if runner == 0:
            os.close(master)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            for descriptor in (0, 1, 2):
                os.dup2(slave, descriptor)
            if slave > 2:
                os.close(slave)
            os.chdir(directory)
            os.execve(binary, [binary, "run", "sh", "--", "-c", script], {
                "HOME": directory,
                "PATH": "/usr/bin:/bin",
                "OMG_DISABLE_TELEMETRY": "1",
            })
        os.close(slave)
        task = None
        descendant = None
        reaped = False
        output = bytearray()
        try:
            deadline = time.monotonic() + 10
            ready = Path(directory, "pids")
            while True:
                if ready.exists():
                    fields = ready.read_text().split()
                    if len(fields) == 2:
                        task, descendant = map(int, fields)
                        break
                assert time.monotonic() < deadline, "task failed to become ready"
                time.sleep(0.02)
            assert os.getpgid(task) == task, "task must own its group"
            while os.tcgetpgrp(master) != task:
                assert time.monotonic() < deadline, "task must own terminal input"
                time.sleep(0.02)
            assert live(descendant), "control must be alive before input"
            os.write(master, input_bytes)
            deadline = time.monotonic() + 8
            status = None
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.02)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                exited, status = os.waitpid(runner, os.WNOHANG)
                if exited:
                    reaped = True
                    break
            assert reaped, f"CLI did not exit: {output!r}"
            success = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            assert success == expected_success, (status, output)
            assert expected_output in output, output
            assert not live(descendant), "live descendant survived terminal cancellation"
            print(f"PASS controlling PTY: {expected_output.decode()} status={status}")
        finally:
            # Groups are restricted to this newly created session. The runner
            # has not been reaped on failures, so its PID cannot be reused.
            for pid in (task, runner):
                if pid is not None:
                    try:
                        if os.getsid(pid) == runner:
                            os.killpg(os.getpgid(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        continue  # An absent fixture process needs no further cleanup.
            if not reaped:
                os.waitpid(runner, 0)
            os.close(master)


if __name__ == "__main__":
    executable = str(Path(sys.argv[1]).resolve(strict=True))
    check(executable,
          "printf '%s %s\\n' $$ $$ > pids; read line; printf 'GOT:%s\\n' \"$line\"",
          b"terminal-input\n", True, b"GOT:terminal-input")
    check(executable,
          "sleep 40 & printf '%s %s\\n' $$ $! > pids; wait",
          b"\x03", False, b"Task cancelled by SIGINT")

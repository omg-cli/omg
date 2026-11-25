import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import sys
import termios
import time


binary = sys.argv[1]
mode = sys.argv[2] if len(sys.argv) > 2 else "history"
data = Path(os.environ["OMG_DATA_DIR"])
package = "omg-history-lock-fixture"
if mode == "history":
    (data / "history.json").write_text(json.dumps([{
        "id": "history-lock-fixture",
        "timestamp": "2026-01-01T00:00:00Z",
        "transaction_type": "Install",
        "success": True,
        "changes": [{"name": package, "new_version": "1", "source": "local"}],
    }]), encoding="utf-8")

with (data / "history.lock").open("wb") as lock:
    if mode == "history":
        fcntl.flock(lock, fcntl.LOCK_EX)
    pid, terminal = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 45, 160, 0, 0))
        os.execv(binary, [binary, "dash"])

    transcript = bytearray()
    cursor_replies = 0
    deadline = time.monotonic() + 10

    def read_output(timeout):
        global cursor_replies
        if not select.select([terminal], [], [], timeout)[0]:
            return False
        try:
            text = os.read(terminal, 8192)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            return None
        if not text:
            return None
        transcript.extend(text)
        assert len(transcript) <= 256 * 1024, "dashboard exceeded the output bound"
        while cursor_replies < transcript.count(b"\x1b[6n"):
            os.write(terminal, b"\x1b[1;1R")
            cursor_replies += 1
        return True

    def read_until(expected, start=0):
        while transcript.find(expected, start) == -1 and time.monotonic() < deadline:
            if read_output(0.1) is None:
                break
        assert transcript.find(expected, start) != -1, (expected, bytes(transcript[-2048:]))

    reaped = False
    try:
        if mode == "history":
            read_until(b"Package history unavailable")
            time.sleep(0.25)
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.write(terminal, b"5")
            read_until(package.encode())

            fcntl.flock(lock, fcntl.LOCK_EX)
            os.write(terminal, b"r")
            time.sleep(0.25)
        else:
            assert mode == "action"
            read_until(b"Updates unknown")
            os.write(terminal, b"2")
            read_until(b"Type / to search packages")
            os.write(terminal, b"/git\r")
            read_until(b"Version control")
            os.write(terminal, b"\r")
            read_until(b"Install git?")
            action_started = len(transcript)
            os.write(terminal, b"\r")
            alternate_screen = b"\x1b[?1049h"
            read_until(alternate_screen, action_started)
            resumed_at = transcript.index(alternate_screen, action_started)
            read_until(b"Version control", resumed_at)
            state = data / "mock_state_apt.json"
            assert json.loads(state.read_text(encoding="utf-8"))["installed"]["git"] == "2.39.2"
            state.write_text("invalid mock state", encoding="utf-8")
            os.write(terminal, b"/git\r")
            read_until(b"failed to parse mock state", action_started)
            assert b"\x1b[6n" not in transcript[resumed_at:], "dashboard queried the cursor when resuming"

        quit_started = len(transcript)
        os.write(terminal, b"q")
        restored = b"\x1b[?1049l"
        read_until(restored, quit_started)
        while time.monotonic() < deadline:
            read_output(0.05)
            child, status = os.waitpid(pid, os.WNOHANG)
            if child:
                reaped = True
                while read_output(0):
                    pass
                exit_code = os.waitstatus_to_exitcode(status)
                assert exit_code == 0, (exit_code, bytes(transcript[-1024:]))
                break
        assert reaped, f"dashboard did not exit in {mode} scenario"
        shell_output = transcript[transcript.index(restored, quit_started) + len(restored):]
        assert b"\x1b[6n" not in shell_output, "dashboard queried the restored shell cursor"
        assert b"\x1b[2J" not in shell_output, "dashboard cleared the restored shell screen"
    finally:
        if not reaped:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)

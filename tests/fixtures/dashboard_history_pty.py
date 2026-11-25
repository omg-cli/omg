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
data = Path(os.environ["OMG_DATA_DIR"])
package = "omg-history-lock-fixture"
(data / "history.json").write_text(json.dumps([{
    "id": "history-lock-fixture",
    "timestamp": "2026-01-01T00:00:00Z",
    "transaction_type": "Install",
    "success": True,
    "changes": [{"name": package, "new_version": "1", "source": "local"}],
}]), encoding="utf-8")

with (data / "history.lock").open("wb") as lock:
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
        assert len(transcript) <= 128 * 1024, "dashboard exceeded the output bound"
        while cursor_replies < transcript.count(b"\x1b[6n"):
            os.write(terminal, b"\x1b[1;1R")
            cursor_replies += 1
        return True

    def read_until(expected):
        while expected not in transcript and time.monotonic() < deadline:
            if read_output(0.1) is None:
                break
        assert expected in transcript, (expected, bytes(transcript[-1024:]))

    reaped = False
    try:
        read_until(b"Package history unavailable")
        time.sleep(0.25)
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.write(terminal, b"5")
        read_until(package.encode())

        fcntl.flock(lock, fcntl.LOCK_EX)
        os.write(terminal, b"r")
        time.sleep(0.25)
        os.write(terminal, b"q")
        restored = b"\x1b[?1049l"
        read_until(restored)
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
        assert reaped, "dashboard could not exit during a history write"
        shell_output = transcript.split(restored, 1)[1]
        assert b"\x1b[6n" not in shell_output, "dashboard queried the restored shell cursor"
        assert b"\x1b[2J" not in shell_output, "dashboard cleared the restored shell screen"
    finally:
        if not reaped:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)

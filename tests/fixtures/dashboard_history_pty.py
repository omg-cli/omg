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

    def read_until(expected):
        global cursor_replies
        while expected not in transcript and time.monotonic() < deadline:
            if not select.select([terminal], [], [], 0.1)[0]:
                continue
            try:
                text = os.read(terminal, 8192)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
            if not text:
                break
            transcript.extend(text)
            assert len(transcript) <= 128 * 1024, "dashboard exceeded the output bound"
            while cursor_replies < transcript.count(b"\x1b[6n"):
                os.write(terminal, b"\x1b[1;1R")
                cursor_replies += 1
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
        read_until(b"\x1b[?1049l")
        while time.monotonic() < deadline:
            child, status = os.waitpid(pid, os.WNOHANG)
            if child:
                reaped = True
                assert os.waitstatus_to_exitcode(status) == 0
                break
            time.sleep(0.01)
        assert reaped, "dashboard could not exit during a history write"
    finally:
        if not reaped:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)

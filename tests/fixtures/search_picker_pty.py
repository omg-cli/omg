"""Select the first row in a real OMG search terminal."""

import contextlib
import errno
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

binary, expected = sys.argv[1:]
pid, terminal = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 140, 0, 0))
    os.execv(binary, [binary, "search", "omg-native-picker", "--no-aur"])

output = bytearray()
selected = False
cursor_answers = 0
reaped = False
try:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and len(output) < 1024 * 1024:
        if not select.select([terminal], [], [], 0.2)[0]:
            continue
        try:
            chunk = os.read(terminal, 65536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        output.extend(chunk)
        while cursor_answers < output.count(b"\x1b[6n"):
            os.write(terminal, b"\x1b[1;1R")
            cursor_answers += 1
        if not selected and b"Select a package for details" in output:
            os.write(terminal, b"\r")
            selected = True

    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            reaped = True
            break
        time.sleep(0.02)
    transcript = output.decode(errors="replace")
    assert reaped and os.waitstatus_to_exitcode(status) == 0, transcript
    assert selected and expected in transcript, transcript
    assert transcript.count("omg-native-picker") == 1, transcript
finally:
    if not reaped:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    os.close(terminal)

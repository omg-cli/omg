#!/usr/bin/env python3
"""Explicitly acknowledge only Unknown coverage in disposable native fixtures."""

import argparse
import errno
import json
import os
from pathlib import Path
import re
import signal
import sys
import time


def review_answers(output, offset):
    answers = []
    start = offset
    pattern = rb'Type accept ([0-9a-f]{64}) within 60 seconds to continue \(default: cancel\): '
    for prompt in re.finditer(pattern, output[offset:]):
        end = offset + prompt.end()
        details = output[start:end]
        if (b'SECURITY WARNING: advisory coverage for the selected transaction is unknown.' not in details
                or b'disclosed advisory findings' in details):
            raise ValueError('Fixture may acknowledge only an identified Unknown-only review')
        answers.append(b'accept ' + prompt[1] + b'\n')
        start = end
    if answers:
        offset = end
    return offset, answers


def attend(command, receipt, timeout):
    import pty
    import select

    if not command or not 0 < timeout <= 120:
        raise ValueError('Fixture requires a command and a bounded deadline')
    child, terminal = pty.fork()
    if child == 0:
        os.execvp(command[0], command)
    status = None
    output = bytearray()
    offset = 0
    reviews = []
    deadline = time.monotonic() + timeout

    def capture():
        nonlocal offset
        try:
            chunk = os.read(terminal, 8192)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            return False
        if not chunk:
            return False
        output.extend(chunk)
        if len(output) > 1024 * 1024:
            raise ValueError('Unknown fixture terminal exceeded its capture bound')
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        offset, answers = review_answers(output, offset)
        if len(reviews) + len(answers) > 64:
            raise ValueError('Unknown fixture exceeded its review count bound')
        for answer in answers:
            os.write(terminal, answer)
            reviews.append(answer[7:-1].decode('ascii'))
        return True

    try:
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.05)[0]:
                capture()
            observed, value = os.waitpid(child, os.WNOHANG)
            if observed:
                status = value
                while select.select([terminal], [], [], 0)[0] and capture():
                    pass
                break
        if status is None:
            raise TimeoutError('Unknown fixture terminal exceeded its owned deadline')
        code = os.waitstatus_to_exitcode(status)
        receipt.write_text(json.dumps(dict(reviews=reviews, cli_exit_code=code)) + '\n')
        return code
    finally:
        if status is None:
            os.killpg(child, signal.SIGKILL)
            os.waitpid(child, 0)
        os.close(terminal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    sys.exit(attend(command, args.receipt, args.timeout))


if __name__ == '__main__':
    main()

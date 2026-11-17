#!/usr/bin/env python3
"""Exercise real runtime risk consent in the disposable QEMU guest."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

MAX_TRANSCRIPT = 2 * 1024 * 1024
PROMPT = re.compile(rb"(?:^|\r?\n)Type accept ([0-9a-f]{64}) within 60 seconds to continue \(default: cancel\): ")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def stop(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        return


def checked_warning(transcript, runtime, version):
    require(b'SECURITY WARNING:' in transcript, 'missing explicit security warning before acceptance')
    require(f'Package: ["{runtime}","{version}"'.encode() in transcript, 'warning identity does not match the selected runtime')
    require(re.search(rb'https://[A-Za-z0-9.-]+/[^\s"<>]+', transcript), 'warning has no public HTTPS source URL')
    if b'disclosed advisory findings' in transcript:
        require(re.search(rb'(?:CVE-\d{4}-\d{4,19}|GHSA-[a-z0-9-]+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+|PSF-\d{4}-\d+|NODE-CORE-\d+)', transcript), 'warning has no disclosed advisory identifier')
    else:
        require(b'coverage' in transcript and (b'Coverage gap:' in transcript or b'Coverage: unknown' in transcript), 'warning does not explain unknown coverage')


def run_install(command, runtime, version, timeout, root):
    deadline = time.monotonic() + timeout
    current = Path(os.environ.get('OMG_DATA_DIR', Path(root) / 'runtime-data')) / 'versions' / runtime / 'current'
    previous_current = os.readlink(current) if current.is_symlink() else None
    with tempfile.TemporaryFile() as capture:
        denied = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=capture, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            while denied.poll() is None:
                require(time.monotonic() < deadline, 'runtime denial control exceeded the row deadline')
                require(os.fstat(capture.fileno()).st_size <= MAX_TRANSCRIPT, 'runtime denial capture exceeded its bound')
                time.sleep(0.02)
            capture.seek(0); denial = capture.read(MAX_TRANSCRIPT + 1)
            require(len(denial) <= MAX_TRANSCRIPT, 'runtime denial capture exceeded its bound')
        finally:
            if denied.poll() is None: stop(denied.pid)
            denied.wait(timeout=5)
    require(denied.returncode != 0 and b'Security review requires an attended controlling terminal' in denial, 'runtime installed without the required attended security decision')
    checked_warning(denial, runtime, version)
    require((os.readlink(current) if current.is_symlink() else None) == previous_current, 'denied runtime changed the active selection')
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(command[0], command)
    transcript = bytearray()
    status = None
    accepted = None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(descriptor, 8192)
                except OSError as error:
                    if error.errno == errno.EIO: break
                    raise
                if not chunk: break
                transcript.extend(chunk)
                require(len(transcript) <= MAX_TRANSCRIPT, 'runtime terminal capture exceeded its bound')
                prompt = PROMPT.search(transcript)
                if prompt and accepted is None:
                    checked_warning(transcript[:prompt.start()], runtime, version)
                    accepted = prompt[1].decode('ascii')
                    os.write(descriptor, b'accept ' + prompt[1] + b'\n')
        while status is None and time.monotonic() < deadline:
            child, completed = os.waitpid(pid, os.WNOHANG)
            if child: status = completed; break
            time.sleep(0.01)
        require(status is not None, 'runtime terminal command exceeded the row deadline')
        require(accepted is not None, 'runtime did not request an exact review digest')
        code = os.waitstatus_to_exitcode(status)
        receipt = {'schema_version': 1, 'runtime': runtime, 'version': version,
                   'denied_exit_code': denied.returncode, 'denied_current_unchanged': True,
                   'accepted_review': accepted, 'accepted_exit_code': code,
                   'transcript_sha256': hashlib.sha256(transcript).hexdigest()}
        return code, bytes(transcript), receipt
    finally:
        if status is None:
            stop(pid)
            os.waitpid(pid, 0)
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', choices=('node', 'python', 'go', 'rust'), required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--timeout', type=int, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    require(command and 1 <= args.timeout <= 1500, 'invalid bounded runtime command')
    command[0] = str(Path(command[0]).resolve(strict=True))
    def interrupted(signum, _frame): raise RuntimeError(f'runtime consent interrupted by signal {signum}')
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(signum, interrupted)
    code, transcript, receipt = run_install(command, args.runtime, args.version, args.timeout, Path.cwd())
    sys.stdout.buffer.write(transcript)
    print('\nOMG_QEMU_RUNTIME_CONSENT=' + json.dumps(receipt, sort_keys=True))
    return code


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f'assertion failed: runtime advisory consent: {error}')

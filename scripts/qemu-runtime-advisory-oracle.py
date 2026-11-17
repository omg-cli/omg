#!/usr/bin/env python3
"""Exercise real runtime or native-package risk consent in disposable QEMU."""
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
    if runtime == 'native':
        subjects = []
        for value in re.findall(rb'(?:^|\r?\n)Package: ([^\r\n]+)', transcript):
            identity = json.loads(value)
            require(isinstance(identity, list) and 2 <= len(identity) <= 8
                    and all(isinstance(part, str) and 0 < len(part) <= 4096 for part in identity[:2]),
                    'native warning has no exact package/version identity')
            subjects.append(identity[:2])
        require(subjects, 'native warning has no exact package/version identity')
    else:
        require(f'Package: ["{runtime}","{version}"'.encode() in transcript, 'warning identity does not match the selected runtime')
    require(re.search(rb'https://[A-Za-z0-9.-]+/[^\s"<>]*', transcript), 'warning has no public HTTPS source URL')
    if b'disclosed advisory findings' in transcript:
        require(re.search(rb'(?:CVE-\d{4}-\d{4,19}|GHSA-[a-z0-9-]+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+|PSF-\d{4}-\d+|NODE-CORE-\d+|AVG-\d+|(?:RHSA|FEDORA|DSA|USN|ALAS)[-:][A-Za-z0-9:.-]+)', transcript), 'warning has no disclosed advisory identifier')
    else:
        require(b'coverage' in transcript and (b'Coverage gap:' in transcript or b'Coverage: unknown' in transcript), 'warning does not explain unknown coverage')


def run_denial(command, runtime, version, deadline):
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
    require(denied.returncode != 0 and b'Security review requires an attended controlling terminal' in denial, 'command did not refuse its missing attended security decision')
    checked_warning(denial, runtime, version)
    return denied.returncode, denial


def run_install(command, runtime, version, timeout, root):
    deadline = time.monotonic() + timeout
    current = Path(os.environ.get('OMG_DATA_DIR', Path(root) / 'runtime-data')) / 'versions' / runtime / 'current'
    previous_current = os.readlink(current) if current.is_symlink() else None
    denied_code, _ = run_denial(command, runtime, version, deadline)
    require((os.readlink(current) if current.is_symlink() else None) == previous_current, 'denied runtime changed the active selection')
    return run_terminal(command, runtime, version, deadline, denied_code)


def run_terminal(command, runtime, version, deadline, denied_exit_code=None, require_review=True):
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execv(command[0], command)
    transcript = bytearray()
    status = None
    accepted = []
    consumed = 0
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
                prompt = PROMPT.search(transcript, consumed)
                if prompt:
                    checked_warning(transcript[consumed:prompt.start()], runtime, version)
                    require(len(accepted) < 16, 'command exceeded its bounded review count')
                    accepted.append(prompt[1].decode('ascii'))
                    os.write(descriptor, b'accept ' + prompt[1] + b'\n')
                    consumed = prompt.end()
        while status is None and time.monotonic() < deadline:
            child, completed = os.waitpid(pid, os.WNOHANG)
            if child: status = completed; break
            time.sleep(0.01)
        require(status is not None, 'runtime terminal command exceeded the row deadline')
        require(accepted or not require_review, 'command did not request an exact review digest')
        if not accepted:
            require(b'SECURITY WARNING:' not in transcript, 'security warning was not followed by an exact review decision')
        code = os.waitstatus_to_exitcode(status)
        receipt = {'schema_version': 1, 'runtime': runtime, 'version': version,
                   'denied_exit_code': denied_exit_code,
                   'denied_current_unchanged': True if denied_exit_code is not None else None,
                   'accepted_review': accepted[-1] if accepted else None,
                   'accepted_reviews': accepted, 'accepted_exit_code': code,
                   'transcript_sha256': hashlib.sha256(transcript).hexdigest()}
        return code, bytes(transcript), receipt
    finally:
        if status is None:
            stop(pid)
            os.waitpid(pid, 0)
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--runtime', choices=('node', 'python', 'go', 'rust'))
    mode.add_argument('--native', action='store_true', help='Review actual native package identities; no runtime fixture or evidence is seeded')
    parser.add_argument('--version')
    parser.add_argument('--timeout', type=int, required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--accept-only', action='store_true', help='Run one real reviewed command; denial is covered by the QEMU control')
    action.add_argument('--deny-only', action='store_true', help='Record one actual nonterminal refusal; never part of a measured transaction')
    parser.add_argument('--require-review', action='store_true', help='Require a genuine warning and digest; native assessed-clean commands otherwise need no acceptance')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    require(command and 1 <= args.timeout <= 1500, 'invalid bounded runtime command')
    require(args.native or args.version, 'runtime mode requires its exact version')
    require(not args.native or args.accept_only or args.deny_only, 'native commands need --accept-only or a separate --deny-only control')
    command[0] = str(Path(command[0]).resolve(strict=True))
    def interrupted(signum, _frame): raise RuntimeError(f'runtime consent interrupted by signal {signum}')
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP): signal.signal(signum, interrupted)
    if args.deny_only:
        denied_code, transcript = run_denial(command, 'native' if args.native else args.runtime, args.version, time.monotonic() + args.timeout)
        code = 0
        receipt = {'schema_version': 1, 'runtime': 'native' if args.native else args.runtime,
                   'version': args.version, 'denied_exit_code': denied_code,
                   'accepted_review': None, 'accepted_reviews': [], 'accepted_exit_code': None,
                   'transcript_sha256': hashlib.sha256(transcript).hexdigest()}
    elif args.accept_only:
        code, transcript, receipt = run_terminal(command, 'native' if args.native else args.runtime, args.version, time.monotonic() + args.timeout, require_review=args.require_review or not args.native)
    else:
        code, transcript, receipt = run_install(command, args.runtime, args.version, args.timeout, Path.cwd())
    sys.stdout.buffer.write(transcript)
    print('\n' + ('OMG_QEMU_NATIVE_CONSENT=' if args.native else 'OMG_QEMU_RUNTIME_CONSENT=') + json.dumps(receipt, sort_keys=True))
    return code


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f'assertion failed: runtime advisory consent: {error}')

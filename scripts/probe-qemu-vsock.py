#!/usr/bin/env python3
"""Report ordinary-user host vsock capabilities without configuring a guest."""
from __future__ import annotations

import errno
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

OUTPUT_LIMIT = 64 * 1024


def bounded_run(command: list[str], directory: Path, label: str, seconds: float) -> tuple[int, bytes, bytes]:
    """Own the process group, output files and cleanup through every outcome."""
    with (directory / (label + '.stdout')).open('w+b') as stdout, (directory / (label + '.stderr')).open('w+b') as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + seconds
        try:
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError(label + ' exceeded its deadline')
                if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > OUTPUT_LIMIT:
                    raise ValueError(label + ' exceeded its output limit')
                time.sleep(0.02)
        finally:
            # Keep the leader waitable until its exclusively owned group is stopped.
            # Its PID cannot be recycled while surviving descendants are cleaned up.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            finally:
                child.wait()
        if os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size > OUTPUT_LIMIT:
            raise ValueError(label + ' exceeded its output limit')
        stdout.seek(0)
        stderr.seek(0)
        return child.returncode, stdout.read(OUTPUT_LIMIT), stderr.read(OUTPUT_LIMIT)


def report() -> dict[str, object]:
    receipt: dict[str, object] = {
        'schema_version': 1,
        'kind': 'qemu-vsock-host-capability',
        'complete': True,
        'status': 'unavailable',
        'ordinary_host_proven': False,
        'guest_cid_assigned': False,
        'guest_transport_proven': False,
        'default_transport_changed': False,
        'platform': sys.platform,
    }
    if not sys.platform.startswith('linux'):
        receipt['status'] = 'unsupported'
        receipt['reason'] = 'Linux vhost and AF_VSOCK are required'
        return receipt
    receipt.update(effective_uid=os.geteuid(), effective_gid=os.getegid(), kernel=os.uname().release, machine=os.uname().machine)
    if os.geteuid() == 0:
        receipt['status'] = 'unqualified'
        receipt['reason'] = 'Root cannot establish the ordinary-runner capability contract'
        return receipt
    compiler = shutil.which('cc')
    if compiler is None:
        receipt['status'] = 'unprobed'
        receipt['reason'] = 'No existing C compiler is available; no tools were installed'
        return receipt
    source = Path(__file__).with_name('qemu-vsock-capability.c')
    source_bytes = source.read_bytes()
    if not 0 < len(source_bytes) <= 16 * 1024:
        raise ValueError('Capability source exceeds its size limit')
    receipt['source_sha256'] = hashlib.sha256(source_bytes).hexdigest()
    receipt['reporter_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='omg-vsock-capability-') as temporary:
        directory = Path(temporary)
        executable = directory / 'probe'
        snapshot = directory / 'probe.c'
        snapshot.write_bytes(source_bytes)
        code, version, errors = bounded_run([compiler, '--version'], directory, 'compiler', 5)
        if code != 0:
            raise ValueError('Existing compiler version query failed')
        receipt['compiler_version'] = version.decode('utf-8', errors='backslashreplace').splitlines()[0][:256]
        command = [compiler, '-O2', '-Wall', '-Wextra', '-Werror', str(snapshot), '-o', str(executable)]
        code, output, errors = bounded_run(command, directory, 'build', 30)
        if code != 0:
            receipt.update(complete=False, status='harness_error', reason='Capability helper compilation failed', compiler_exit=code,
                           compiler_diagnostic_sha256=hashlib.sha256(errors).hexdigest())
            return receipt
        if executable.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Capability executable exceeds its size limit')
        receipt['binary_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
        code, output, errors = bounded_run([str(executable)], directory, 'probe', 5)
        if code != 0 or errors:
            raise ValueError('Capability helper failed its execution contract')
        observation = json.loads(output)
        if (not isinstance(observation, dict) or observation.get('effective_uid') != os.geteuid()
                or observation.get('effective_gid') != os.getegid()
                or observation.get('guest_cid_assigned') is not False
                or observation.get('guest_transport_proven') is not False):
            raise ValueError('Capability helper returned an invalid identity or scope')
        receipt['observation'] = observation
        available = (observation['device_open'] is True and observation['socket_created'] is True
                     and all(observation[field] == 0 for field in (
                         'device_owner_result', 'features_result', 'device_close_result', 'device_errno',
                         'host_bind_result', 'listen_result', 'socket_errno')))
        refused = any(observation[field] in (errno.EACCES, errno.EPERM)
                      for field in ('device_errno', 'socket_errno'))
        receipt.update(status='available' if available else 'refused' if refused else 'unavailable',
                       ordinary_host_proven=available)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository', 'source-sha', 'run-id', 'run-attempt', 'runner-label'):
        parser.add_argument('--' + name)
    args = parser.parse_args()
    hosted = dict(repository=args.repository, source_sha=args.source_sha, run_id=args.run_id,
                  run_attempt=args.run_attempt, runner_label=args.runner_label)
    if any(value is not None for value in hosted.values()):
        patterns = dict(repository=r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}',
                        source_sha=r'[0-9a-f]{40}', run_id=r'[1-9][0-9]{0,19}',
                        run_attempt=r'[1-9][0-9]{0,3}', runner_label=r'[a-z0-9][a-z0-9.-]{0,63}')
        if any(value is None or re.fullmatch(patterns[key], value) is None for key, value in hosted.items()):
            parser.error('hosted identity requires a complete valid repository/source/run/attempt/runner tuple')
    try:
        receipt = report()
    except (OSError, ValueError, TimeoutError, KeyError, IndexError) as error:
        receipt = {'schema_version': 1, 'kind': 'qemu-vsock-host-capability', 'complete': False,
                   'status': 'harness_error', 'reason': str(error), 'ordinary_host_proven': False,
                   'guest_cid_assigned': False, 'guest_transport_proven': False, 'default_transport_changed': False}
    if args.repository is not None:
        receipt['hosted_identity'] = hosted
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())

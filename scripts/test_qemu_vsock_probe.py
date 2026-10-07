#!/usr/bin/env python3
"""Real child-process boundary checks for the optional vsock reporter."""
import importlib.util
import ctypes
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import signal
import subprocess
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('vsock_probe', Path(__file__).with_name('probe-qemu-vsock.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process-group ownership contract')
class ChildBoundaryTests(unittest.TestCase):
    def test_complete_hosted_identity_accepts_real_dotted_runner_labels(self):
        for runner in ('ubuntu-24.04', 'ubuntu-24.04-arm'):
            with self.subTest(runner=runner):
                result = subprocess.run(
                    [sys.executable, '-B', str(Path(probe.__file__)),
                     '--repository', 'omg-cli/omg', '--source-sha', 'a' * 40,
                     '--run-id', '10', '--run-attempt', '1', '--runner-label', runner],
                    capture_output=True, timeout=45, check=False)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                receipt = json.loads(result.stdout)
                self.assertTrue(receipt['complete'])
                self.assertEqual(receipt['hosted_identity']['runner_label'], runner)
                self.assertFalse(receipt['guest_transport_proven'])

    def test_partial_or_malformed_hosted_identity_refuses_before_probe(self):
        valid = ['--repository', 'omg-cli/omg', '--source-sha', 'a' * 40,
                 '--run-id', '10', '--run-attempt', '1', '--runner-label', 'ubuntu-24.04']
        invalid = [valid[:2], valid[:-2]]
        for index, value in ((1, 'bad/repo/extra'), (3, 'bad'), (5, '0'),
                             (7, '10000'), (9, 'unsafe/runner')):
            changed = list(valid)
            changed[index] = value
            invalid.append(changed)
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, '-B', str(Path(probe.__file__)), *arguments],
                                        capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                self.assertIn(b'hosted identity requires', result.stderr)

    def test_fast_parent_exit_kills_and_reaps_remaining_descendant(self):
        libc = ctypes.CDLL(None, use_errno=True)
        original = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(original), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        descendant = None
        reaped = False
        try:
            with tempfile.TemporaryDirectory() as temporary:
                command = ('import os,time;pid=os.fork();'
                           'print(pid,flush=True) if pid else time.sleep(30)')
                code, stdout, stderr = probe.bounded_run(
                    [sys.executable, '-c', command], Path(temporary), 'fork', 5)
                descendant = int(stdout.strip())
                self.assertEqual((code, stderr), (0, b''))
                deadline = time.monotonic() + 2
                status = None
                while time.monotonic() < deadline:
                    found, observed = os.waitpid(descendant, os.WNOHANG)
                    if found:
                        reaped = True
                        status = observed
                        break
                    time.sleep(0.01)
                self.assertIsNotNone(status, 'owned descendant survived its parent completion')
                self.assertTrue(os.WIFSIGNALED(status))
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
        finally:
            if descendant is not None and not reaped:
                os.kill(descendant, signal.SIGKILL)
                os.waitpid(descendant, 0)
            self.assertEqual(libc.prctl(36, original.value, 0, 0, 0), 0)

    def assert_reaped(self, child):
        self.assertIsNotNone(child.returncode, 'caller must wait before returning')
        with self.assertRaises(ProcessLookupError):
            os.kill(child.pid, 0)

    def test_deadline_kills_and_reaps_the_owned_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            children = []
            real_spawn = probe.subprocess.Popen

            def spawn(*args, **kwargs):
                child = real_spawn(*args, **kwargs)
                children.append(child)
                return child

            with mock.patch.object(probe.subprocess, 'Popen', side_effect=spawn):
                with self.assertRaisesRegex(TimeoutError, 'deadline'):
                    probe.bounded_run([sys.executable, '-c', 'import time;time.sleep(30)'], root, 'deadline', 0.2)
            self.assertEqual(len(children), 1)
            self.assert_reaped(children[0])
            for suffix in ('stdout', 'stderr'):
                (root / ('deadline.' + suffix)).unlink()

    def test_output_overflow_kills_and_reaps_the_owned_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            children = []
            real_spawn = probe.subprocess.Popen

            def spawn(*args, **kwargs):
                child = real_spawn(*args, **kwargs)
                children.append(child)
                return child

            command = [sys.executable, '-c', 'import sys,time;sys.stdout.write("x"*' + str(probe.OUTPUT_LIMIT + 1) + ');sys.stdout.flush();time.sleep(30)']
            with mock.patch.object(probe.subprocess, 'Popen', side_effect=spawn):
                with self.assertRaisesRegex(ValueError, 'output limit'):
                    probe.bounded_run(command, root, 'overflow', 5)
            self.assertEqual(len(children), 1)
            self.assert_reaped(children[0])

    def test_fast_exit_cannot_bypass_output_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'output limit'):
                probe.bounded_run([sys.executable, '-c', 'print("x"*' + str(probe.OUTPUT_LIMIT) + ')'], root, 'fast', 5)

    def test_nonzero_exit_and_separate_streams_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, stdout, stderr = probe.bounded_run(
                [sys.executable, '-c', 'import sys;print("out");print("err",file=sys.stderr);sys.exit(23)'],
                Path(temporary), 'nonzero', 5)
            self.assertEqual((code, stdout, stderr), (23, b'out\n', b'err\n'))


if __name__ == '__main__':
    unittest.main()

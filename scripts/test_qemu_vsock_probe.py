#!/usr/bin/env python3
"""Real child-process boundary checks for the optional vsock reporter."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('vsock_probe', Path(__file__).with_name('probe-qemu-vsock.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process-group ownership contract')
class ChildBoundaryTests(unittest.TestCase):
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

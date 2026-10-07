#!/usr/bin/env python3
"""Check real child bounds and refusal before any Docker invocation."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'measurement', Path(__file__).with_name('measure-qemu-controller.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class MeasurementControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.subject = MODULE.Measurement.__new__(MODULE.Measurement)
        self.subject.output = Path(self.directory.name)
        self.subject.records = []

    def test_real_child_failure_is_retained_and_raised(self):
        with self.assertRaisesRegex(RuntimeError, 'command failed'):
            self.subject.run('failure', [sys.executable, '-c', 'print("actual failure"); raise SystemExit(17)'])
        record = json.loads((self.subject.output / 'steps.json').read_text())[0]
        self.assertEqual(record['exit'], 17)
        self.assertIn('actual failure', (self.subject.output / 'failure.log').read_text())

    @unittest.skipUnless(os.name == 'posix', 'Linux process-group bound')
    def test_real_child_timeout_is_retained_and_reaped(self):
        with self.assertRaisesRegex(TimeoutError, 'time or byte limit'):
            self.subject.run('timeout', [sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.05)
        record = json.loads((self.subject.output / 'steps.json').read_text())[0]
        self.assertLess(record['exit'], 0)
        self.assertIn('time or byte limit', record['failure'])
        self.assertLess(record['seconds'], 5)

    def test_same_step_cannot_overwrite_a_previous_receipt(self):
        self.subject.run('once', [sys.executable, '-c', 'print("first")'])
        original = (self.subject.output / 'once.log').read_bytes()
        with self.assertRaisesRegex(ValueError, 'already has a receipt'):
            self.subject.run('once', [sys.executable, '-c', 'print("second")'])
        self.assertEqual((self.subject.output / 'once.log').read_bytes(), original)

    def test_untrusted_packet_is_refused_before_docker(self):
        (self.subject.output / 'image.json').write_text('{}')
        self.subject.args = SimpleNamespace(input=str(self.subject.output), packet_sha='0' * 64)
        with self.assertRaisesRegex(ValueError, 'trusted producer output'):
            self.subject.consume()
        self.assertEqual(self.subject.records, [])


if __name__ == '__main__':
    unittest.main()

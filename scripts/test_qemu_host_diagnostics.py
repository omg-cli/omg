"""Bounded diagnostic capture preserves failures without admitting health."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).with_name('capture-qemu-host-diagnostics.py')


class HostCaptureTests(unittest.TestCase):
    def module(self):
        self.assertTrue(SCRIPT.is_file(), 'host-only capture entrypoint is missing')
        spec = importlib.util.spec_from_file_location('host_capture', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_query_retains_actual_nonzero_exit_and_bounded_output(self):
        capture = self.module()
        result = capture.observe([sys.executable, '-c', "print('x'*5000); raise SystemExit(7)"])
        self.assertEqual(result['exit'], 7)
        self.assertEqual(len(result['stdout']), 4096)
        self.assertTrue(result['truncated'])

    def test_query_timeout_remains_failure(self):
        capture = self.module()
        result = capture.observe([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.05)
        self.assertEqual(result['error'], 'TimeoutExpired')
        self.assertIsNone(result['exit'])

    def test_capture_cli_contains_no_health_admission_or_full_environment(self):
        self.module()
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=30)
        receipt = json.loads(result.stdout)
        self.assertEqual(set(receipt), {'source', 'boot_id', 'core_pattern', 'handler_executable', 'socket', 'processor'})
        self.assertNotIn('complete', receipt)
        self.assertEqual(set(receipt['source']), {'repository', 'event_name', 'run_id', 'run_attempt', 'expected_sha', 'observed_sha', 'observed_tree', 'ordered_parents'})
        failures = any(value.get('exit') != 0 or value.get('truncated')
                       for value in (receipt['socket'], receipt['processor']))
        if failures:
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()

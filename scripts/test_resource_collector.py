"""Real Linux child controls for the optional resource collector."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class ResourceCollectorTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("resource_collector.py")
        self.assertTrue(path.is_file(), "scoped collector is not implemented")
        spec = importlib.util.spec_from_file_location("resource_collector", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.scratch = tempfile.TemporaryDirectory(dir=os.environ.get("PAPERCLIP_RUN_SCRATCH_DIR"))
        self.addCleanup(self.scratch.cleanup)

    def run_child(self, code, timeout=3):
        result = self.module.collect([sys.executable, "-c", code], timeout, self.scratch.name)
        print(json.dumps(result, sort_keys=True))
        return result

    def test_cpu_positive_control(self):
        result = self.run_child("import time; end=time.process_time()+0.15\nwhile time.process_time()<end: pass")
        self.assertEqual(result["exit_code"], 0)
        self.assertGreater(result["user_cpu_seconds"] + result["system_cpu_seconds"], 0.1)
        self.assertGreaterEqual(result["elapsed_seconds"], 0.1)
        self.assertFalse(result["timed_out"])

    def test_memory_positive_control_and_no_previous_child_contamination(self):
        big = self.run_child("x=bytearray(64*1024*1024); print(len(x))")
        small = self.run_child("print('small')")
        self.assertGreater(big["max_rss_kib"], 64*1024)
        self.assertGreater(small["max_rss_kib"], 0)
        self.assertLess(small["max_rss_kib"], big["max_rss_kib"] - 32*1024)

    def test_nonzero_exit_and_binary_output_identity(self):
        result = self.run_child("import os; os.write(1,b'hello\\x00\\xff'); os.write(2,b'failure'); raise SystemExit(7)")
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["stdout_bytes"], 7)
        self.assertEqual(result["stderr_bytes"], 7)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"hello\x00\xff").hexdigest())
        self.assertEqual(result["stderr_sha256"], hashlib.sha256(b"failure").hexdigest())

    def test_timeout_reaps_owned_child(self):
        result = self.run_child("import time; time.sleep(30)", 0.15)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["exit_code"], -9)
        self.assertGreaterEqual(result["elapsed_seconds"], 0.15)
        self.assertLess(result["elapsed_seconds"], 2)
        with self.assertRaises(ChildProcessError):
            os.waitpid(result["pid"], os.WNOHANG)

    def test_sleep_elapsed_is_not_cpu(self):
        result = self.run_child("import time; time.sleep(0.2)")
        self.assertGreaterEqual(result["elapsed_seconds"], 0.2)
        self.assertLess(result["user_cpu_seconds"] + result["system_cpu_seconds"], result["elapsed_seconds"])
        self.assertEqual(result["elapsed_clock"], "monotonic")

    def test_invalid_timeout_and_missing_command_fail(self):
        for timeout in (0, -1, float("nan"), float("inf"), 61):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.module.collect([sys.executable], timeout, self.scratch.name)
        with self.assertRaises(FileNotFoundError):
            self.module.collect(["/nonexistent/per803-command"], 1, self.scratch.name)

    def test_cli_preserves_failure_and_emits_json(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("resource_collector.py")),
                                 "--scratch-dir", self.scratch.name, "--timeout", "3", "--",
                                 sys.executable, "-c", "raise SystemExit(7)"], capture_output=True, check=False)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(json.loads(result.stdout)["exit_code"], 7)
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()

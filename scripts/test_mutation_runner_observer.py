"""Real subprocess contracts for the Linux mutation runner observer."""
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("observe-mutation-runner.py")
PREFIX = "OMG_MUTATION_HEALTH "
SPEC = importlib.util.spec_from_file_location("mutation_runner_observer", SCRIPT)
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class MutationRunnerObserver(unittest.TestCase):
    def test_report_byte_limit_refuses_before_starting_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child-ran"
            report = Path(directory) / "health.jsonl"
            command = [sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"]
            with patch.object(OBSERVER, "MAX_REPORT_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "byte bound"):
                    OBSERVER.observe(command, report, 30)
            self.assertFalse(marker.exists())
            self.assertEqual(report.stat().st_size, 0)

    def test_invalid_required_memory_metric_refuses_before_starting_the_command(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "child-ran"
            report = Path(directory) / "health.jsonl"
            command = [sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"]
            with patch.object(Path, "read_text", return_value="MemTotal: 100 kB\nMemAvailable: -1 kB\nSwapFree: 0 kB\n"):
                with self.assertRaisesRegex(ValueError, "negative required memory"):
                    OBSERVER.observe(command, report, 30)
            self.assertFalse(marker.exists())
            self.assertEqual(report.stat().st_size, 0)

    def invoke(self, directory, code, interval="30", report=None):
        report = report or Path(directory) / "health.jsonl"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--report", str(report),
             "--interval", interval, "--", sys.executable, "-c", code],
            capture_output=True, text=True, timeout=8)
        records = [json.loads(line) for line in report.read_text().splitlines()] if report.exists() else []
        return result, records

    def test_reports_real_initial_and_final_metrics_and_preserves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            result, rows = self.invoke(directory, "import sys;print('child-out');print('child-error',file=sys.stderr)")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreaterEqual(len(rows), 3, "runner health must be recorded before and after the command")
            self.assertEqual(rows[0]["phase"], "start")
            self.assertEqual(rows[-1]["phase"], "finish")
            self.assertEqual(rows[-1]["child_returncode"], 0)
            for row in rows:
                self.assertGreater(row["memory_total_kib"], 0)
                self.assertGreaterEqual(row["memory_available_kib"], 0)
                self.assertLessEqual(row["memory_available_kib"], row["memory_total_kib"])
                self.assertGreaterEqual(row["kernel_oom_kills"], 0)
                self.assertGreater(row["workspace_free_bytes"], 0)
                self.assertGreater(row["workspace_free_inodes"], 0)
            plain = [line for line in result.stdout.splitlines() if not line.startswith(PREFIX)]
            self.assertEqual(plain, ["child-out"])
            self.assertEqual(result.stderr, "child-error\n")
            streamed = [json.loads(line[len(PREFIX):]) for line in result.stdout.splitlines() if line.startswith(PREFIX)]
            self.assertEqual(streamed, rows)

    def test_preserves_survivor_timeout_and_failure_exit_statuses(self):
        for status in (2, 3, 17):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                result, rows = self.invoke(directory, f"raise SystemExit({status})")
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(rows[-1]["child_returncode"], status)

    def test_emits_a_live_sample_while_the_child_waits_for_it(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "health.jsonl"
            code = ("import json,time;from pathlib import Path;"
                    f"p=Path({str(report)!r});end=time.monotonic()+3\n"
                    "while time.monotonic()<end:\n"
                    " if p.exists() and any(json.loads(line).get('phase')=='sample' for line in p.read_text().splitlines()):\n"
                    "  print('sample-observed');raise SystemExit(0)\n"
                    " time.sleep(0.01)\n"
                    "raise SystemExit(19)")
            result, rows = self.invoke(directory, code, interval="0.02", report=report)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("sample-observed", result.stdout)
            self.assertIn("sample", [row["phase"] for row in rows])

    def test_invalid_intervals_refuse_before_child_side_effects(self):
        for interval in ("0", "-1", "nan", "inf", "61"):
            with self.subTest(interval=interval), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "child-ran"
                result, _ = self.invoke(directory, f"from pathlib import Path;Path({str(marker)!r}).write_text('ran')", interval)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())

    def test_existing_report_is_preserved_and_the_child_is_not_started(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "health.jsonl"
            report.write_text('{"original":"retained"}\n')
            marker = Path(directory) / "child-ran"
            result, _ = self.invoke(directory, f"from pathlib import Path;Path({str(marker)!r}).write_text('ran')", report=report)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertEqual(report.read_text(), '{"original":"retained"}\n')

    def test_sigterm_is_forwarded_and_remains_fatal_when_child_returns_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "health.jsonl"
            marker = Path(directory) / "child-state"
            code = ("import signal,time;from pathlib import Path;"
                    f"p=Path({str(marker)!r})\n"
                    "def stop(signum,frame):\n"
                    " p.write_text('signal-handled');raise SystemExit(0)\n"
                    "signal.signal(signal.SIGTERM,stop);p.write_text('ready')\n"
                    "while True:time.sleep(0.1)")
            process = subprocess.Popen(
                [sys.executable, str(SCRIPT), "--report", str(report), "--interval", "0.02", "--", sys.executable, "-c", code],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 3
                ready = False
                while time.monotonic() < deadline:
                    if marker.exists() and report.exists():
                        records = [json.loads(line) for line in report.read_text().splitlines()]
                        ready = marker.read_text() == "ready" and any(row["phase"] == "spawn" for row in records)
                        if ready:
                            break
                    time.sleep(0.01)
                self.assertTrue(ready, "command and signal forwarding must be initialized")
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 143, stderr)
                self.assertEqual(marker.read_text(), "signal-handled")
                final = json.loads(report.read_text().splitlines()[-1])
                self.assertEqual(final["phase"], "finish")
                self.assertEqual(final["child_returncode"], 0)
                self.assertEqual(final["cancellation_signal"], signal.SIGTERM)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()

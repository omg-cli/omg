"""Real subprocess contracts for the Linux mutation runner observer."""
import importlib.util
import json
import os
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
    def test_invalid_scoped_and_unowned_records_do_not_fabricate_complete_rss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                123: '123 (invalid-owned) S 9 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 456 8192 -1',
                124: '124 (valid-owned) S 123 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 457 16384 4',
                125: '125 (invalid-unowned) S 9 125 125 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 458 8192 -1',
                126: '999 (wrong-identity) S 9 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 458 8192 2',
                127: 'x' * 4097,
            }
            for pid, stat in fixtures.items():
                (root / str(pid)).mkdir()
                (root / str(pid) / 'stat').write_text(stat)
            with patch.object(OBSERVER, 'PROC_ROOT', root):
                sample = OBSERVER.command_processes(123)
            self.assertEqual(sample['availability'], 'partial')
            self.assertEqual(sample['invalid_processes'], 4)
            self.assertFalse(sample['rss_sum_is_complete'])
            self.assertEqual(sample['process_count'], 1)
            self.assertEqual(sample['rss_sum_bytes'], 4 * os.sysconf('SC_PAGE_SIZE'))
            self.assertEqual([row['pid'] for row in sample['largest']], [124])

    def test_invalid_process_samples_preserve_real_child_completion_and_partial_evidence(self):
        for stat in (
            '123 (transient) S 9 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 456 8192 -1',
            '123 (truncated) S 9',
        ):
            with self.subTest(stat=stat), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'proc'
                (root / '123').mkdir(parents=True)
                (root / '123' / 'stat').write_text(stat)
                report = Path(directory) / 'health.jsonl'
                marker = Path(directory) / 'completed'
                code = (
                    'import time;from pathlib import Path;time.sleep(0.1);'
                    f'Path({str(marker)!r}).touch();raise SystemExit(17)'
                )
                with patch.object(OBSERVER, 'PROC_ROOT', root):
                    result = OBSERVER.observe([sys.executable, '-c', code], report, 0.02)
                self.assertEqual(result, 17)
                self.assertTrue(marker.exists())
                rows = [json.loads(line) for line in report.read_text().splitlines()]
                self.assertEqual(rows[-1]['phase'], 'finish')
                self.assertEqual(rows[-1]['child_returncode'], 17)
                self.assertIsNone(rows[-1]['cancellation_signal'])
                samples = [row['command_processes'] for row in rows[1:]]
                self.assertTrue(all(sample['availability'] == 'partial' for sample in samples))
                self.assertTrue(all(sample['invalid_processes'] == 1 for sample in samples))
                self.assertTrue(all(not sample['rss_sum_is_complete'] for sample in samples))
                self.assertTrue(all(sample['largest'] == [] for sample in samples))

    def test_process_stat_preserves_parentheses_in_names_and_uses_rss_pages(self):
        text = '123 (rustc ) worker) S 9 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 456 8192 2'
        self.assertEqual(OBSERVER.process_stat(text, 4096), dict(
            pid=123, parent_pid=9, process_group=123, session_id=123,
            start_ticks=456, name='rustc ) worker', rss_bytes=8192))

    def test_process_scan_excludes_other_sessions_and_marks_bounds_and_disappearance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                123: '123 (cargo-mutants) S 9 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 456 8192 2',
                124: '124 (rustc) S 123 123 123 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 457 16384 4',
                125: '125 (unrelated) S 9 125 125 0 -1 4194304 1 0 0 0 1 0 0 0 20 0 2 0 458 999999 999',
            }
            for pid, text in fixtures.items():
                (root / str(pid)).mkdir()
                (root / str(pid) / 'stat').write_text(text)
            with patch.object(OBSERVER, 'PROC_ROOT', root):
                result = OBSERVER.command_processes(123)
                self.assertEqual(result['process_count'], 2)
                self.assertEqual([row['pid'] for row in result['largest']], [124, 123])
                self.assertEqual(result['rss_sum_bytes'], 6 * os.sysconf('SC_PAGE_SIZE'))
                self.assertEqual(result['availability'], 'observed')
                with patch.object(OBSERVER, 'MAX_SESSION_PROCESSES', 1):
                    limited = OBSERVER.command_processes(123)
                    self.assertEqual(limited['process_count'], 1)
                    self.assertTrue(limited['scan_limited'])
                    self.assertEqual(limited['availability'], 'partial')
                with patch.object(OBSERVER, 'MAX_PROC_ENTRIES', 1):
                    limited = OBSERVER.command_processes(123)
                    self.assertEqual(limited['scanned_processes'], 1)
                    self.assertTrue(limited['scan_limited'])
                (root / '126').mkdir()
                partial = OBSERVER.command_processes(123)
                self.assertEqual(partial['vanished_processes'], 1)
                self.assertEqual(partial['availability'], 'partial')

    def test_memory_sample_identifies_command_and_resident_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "health.jsonl"
            marker = Path(directory) / "descendant.json"
            child_code = (
                "import json,os,time;from pathlib import Path;"
                "memory=bytearray(8*1024*1024);"
                f"Path({str(marker)!r}).write_text(json.dumps(dict(pid=os.getpid(),parent=os.getppid())));"
                "time.sleep(5)"
            )
            code = (
                "import json,subprocess,sys,time;from pathlib import Path\n"
                f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}])\n"
                f"report=Path({str(report)!r});marker=Path({str(marker)!r})\n"
                "try:\n"
                " end=time.monotonic()+3\n"
                " while time.monotonic()<end:\n"
                "  if marker.exists():\n"
                "   pid=json.loads(marker.read_text())['pid']\n"
                "   rows=[json.loads(line) for line in report.read_text().splitlines()]\n"
                "   if any(any(p['pid']==pid and p['rss_bytes']>=8*1024*1024 for p in row.get('command_processes',{}).get('largest',[])) for row in rows):\n"
                "    raise SystemExit(0)\n"
                "  time.sleep(0.01)\n"
                " raise SystemExit('resident descendant memory was not observed')\n"
                "finally:\n"
                " child.terminate();child.wait(timeout=2)\n"
            )
            result, rows = self.invoke(directory, code, interval="0.02", report=report)
            self.assertEqual(result.returncode, 0, result.stderr)
            identity = json.loads(marker.read_text())
            samples = [row['command_processes'] for row in rows if row['phase'] == 'sample']
            observed = next(sample for sample in samples if any(p['pid'] == identity['pid'] for p in sample['largest']))
            self.assertEqual(observed['session_id'], identity['parent'])
            self.assertIn(observed['availability'], ('observed', 'partial'))
            self.assertGreaterEqual(observed['process_count'], 2)
            self.assertTrue({identity['pid'], identity['parent']} <= {p['pid'] for p in observed['largest']})
            self.assertTrue(all(p['session_id'] == identity['parent'] for p in observed['largest']))
            self.assertGreaterEqual(observed['rss_sum_bytes'], sum(p['rss_bytes'] for p in observed['largest']))

    def test_cancellation_during_spawn_is_retained_and_forwarded(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "health.jsonl"
            code = (
                "import importlib.util,os,signal,sys;from pathlib import Path\n"
                f"spec=importlib.util.spec_from_file_location('observer',{str(SCRIPT)!r})\n"
                "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n"
                "original=module.subprocess.Popen\n"
                "def start(*args,**kwargs):\n"
                " os.kill(os.getpid(),signal.SIGTERM)\n"
                " return original(*args,**kwargs)\n"
                "module.subprocess.Popen=start\n"
                f"raise SystemExit(module.observe([sys.executable,'-c','import time;time.sleep(10)'],Path({str(report)!r}),0.02))\n"
            )
            result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 143, result.stderr)
            rows = [json.loads(line) for line in report.read_text().splitlines()]
            self.assertEqual(rows[-1]["phase"], "finish")
            self.assertEqual(rows[-1]["cancellation_signal"], signal.SIGTERM)
            self.assertEqual(rows[-1]["child_returncode"], -signal.SIGTERM)

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

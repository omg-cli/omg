"""Adversarial PTY probes for the bounded QEMU run --watch helper."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/qemu-run-watch-check.py"
FAKE_WATCHER = textwrap.dedent("""\
    #!/usr/bin/env python3
    import os
    from pathlib import Path
    import signal
    import sys
    import time

    if sys.argv[1:] != ['run', '--watch', 'smoke']:
        raise SystemExit(91)
    mode = os.environ['WATCH_MODE']
    marker = Path('watch-runs.marker')
    if mode == 'no-sigint':
        signal.signal(signal.SIGINT, signal.SIG_IGN)

    def task():
        with marker.open('a') as output:
            output.write('omg-qemu-watch-run\\n')
        print('smoke-task-ok', flush=True)

    task()
    if mode == 'early-double':
        task()
    print('Watching for changes...', flush=True)
    while Path('src/watch-trigger.txt').read_text() != 'changed once\\n':
        time.sleep(.02)
    if mode != 'no-rerun':
        print('File changed, re-running', flush=True)
        if mode == 'fake-print':
            print('smoke-task-ok', flush=True)
        else:
            task()
        if mode == 'storm':
            time.sleep(.12)
            task()
    if mode == 'background-leak':
        child = os.fork()
        if child == 0:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            while True:
                time.sleep(.05)
        Path('watch-background.pid').write_text(str(child))
    while True:
        time.sleep(.05)
    """)


@unittest.skipIf(os.name != "posix", "PTY helper requires POSIX")
class RunWatchCheck(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="omg-qemu-watch-test-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Path(self.temp.name)
        (self.fixture / "src").mkdir()
        (self.fixture / "src/watch-trigger.txt").write_text("initial\n")
        (self.fixture / "Makefile").write_text("smoke:\n\t@echo smoke-task-ok\n")
        self.binary = self.fixture / "fake-omg"
        self.binary.write_text(FAKE_WATCHER)
        self.binary.chmod(0o755)

    def probe(self, mode):
        return subprocess.run(
            [sys.executable, str(HELPER), str(self.binary), str(self.fixture),
             "--phase-timeout", "0.8", "--quiet-seconds", "0.3",
             "--shutdown-timeout", "0.5"],
            env={**os.environ, "WATCH_MODE": mode}, capture_output=True,
            text=True, timeout=5,
        )

    def test_one_source_edit_runs_task_twice_then_ctrl_c_stops_watcher(self):
        result = self.probe("normal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.fixture / "watch-runs.marker").read_text().splitlines(),
                         ["omg-qemu-watch-run"] * 2)
        self.assertEqual(result.stdout.count("smoke-task-ok"), 2)
        self.assertEqual(json.loads((self.fixture / "watch-evidence.json").read_text()), {
            "schema_version": 1, "initial_runs": 1, "runs_after_edit": 2,
            "readiness_seen": True, "rerun_seen": True, "ctrl_c_stopped": True,
        })

    def test_false_green_watchers_do_not_write_receipt(self):
        for mode in ("no-rerun", "fake-print", "early-double", "storm",
                     "no-sigint", "background-leak"):
            with self.subTest(mode=mode):
                marker = self.fixture / "watch-runs.marker"
                receipt = self.fixture / "watch-evidence.json"
                marker.unlink(missing_ok=True)
                receipt.unlink(missing_ok=True)
                (self.fixture / "src/watch-trigger.txt").write_text("initial\n")
                result = self.probe(mode)
                self.assertEqual(result.returncode, 1, (mode, result.stderr))
                self.assertIn("assertion failed: run --watch:", result.stderr)
                self.assertFalse(receipt.exists(), mode)
                if mode == "background-leak":
                    pid = int((self.fixture / "watch-background.pid").read_text())
                    deadline = time.monotonic() + 1.0
                    while time.monotonic() < deadline:
                        observed = subprocess.run(
                            ["ps", "-o", "stat=", "-p", str(pid)],
                            capture_output=True, text=True, check=False,
                        )
                        if not observed.stdout.strip() or observed.stdout.lstrip().startswith("Z"):
                            break
                        time.sleep(.05)
                    else:
                        self.fail("watch background child survived helper cleanup")


if __name__ == "__main__":
    unittest.main()

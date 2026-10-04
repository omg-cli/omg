import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("ci_smoke_report", Path(__file__).with_name("ci-smoke-report.py"))
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class ReportingTests(unittest.TestCase):
    def test_negative_delivery_fixture_does_not_annotate_the_workflow(self):
        result = subprocess.run(
            [sys.executable, '-B', '-m', 'unittest',
             'test_ci_smoke_report.ReportingTests.test_trixie_failure_keeps_its_identity_and_delivery_receipt'],
            cwd=Path(__file__).parent, capture_output=True, text=True, timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('::warning::', result.stdout)
        self.assertNotIn('::error::', result.stdout)

    def test_trixie_failure_keeps_its_identity_and_delivery_receipt(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(REPORT.subprocess, 'run') as run:
            run.return_value = type('Delivery', (), dict(returncode=1, stdout='', stderr='HTTP 429\n'))()
            root = Path(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(REPORT.status('debian-trixie', 'qemu-debian-trixie-lifecycle', 'failure', root), 0)
            self.assertIn('::warning::Sentry delivery failed', output.getvalue())
            row = json.loads((root / 'results.json').read_text())[0]
            self.assertEqual(row['distro'], 'debian-trixie')
            self.assertEqual(row['case_id'], 'qemu-debian-trixie-lifecycle')
            self.assertEqual(json.loads((root / 'reporting-status.json').read_text()), {'exit_code': 1})
            self.assertIn('429', (root / 'reporting.log').read_text())

    def test_secure_config_and_no_secret_export(self):
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "env"
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "GITHUB_ENV": str(export), "OMG_SMOKE_SENTRY_DSN": "https://abc@o1.ingest.sentry.io/123"}):
                REPORT.configure()
            config = Path(directory) / "omg-smoke-config/sentry.json"
            self.assertEqual(json.loads(config.read_text())["dsn"], "https://abc@o1.ingest.sentry.io/123")
            self.assertNotIn("https://", export.read_text())
            if os.name != "nt":
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_invalid_secret_does_not_write_config(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "OMG_SMOKE_SENTRY_DSN": "bad\nsecret"}):
                with self.assertRaises(ValueError):
                    REPORT.configure()
            self.assertFalse((Path(directory) / "omg-smoke-config").exists())

    def test_failure_projection_and_transport_failure_preserve_status(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(REPORT.subprocess, "run") as run:
                run.return_value.returncode = 1
                run.return_value.stdout = "Sentry rejected report with HTTP 429\n"
                run.return_value.stderr = ""
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(REPORT.status("arch", "qemu-arch-build", "failure", Path(directory)), 0)
                self.assertIn("::warning::Sentry delivery failed", output.getvalue())
            result = json.loads((Path(directory) / "results.json").read_text())
            self.assertEqual(result, [{"case_id": "qemu-arch-build", "distro": "arch", "result": "HARNESS_ERROR", "exit_code": 1, "elapsed_seconds": 0}])
            self.assertIn("429", (Path(directory) / "reporting.log").read_text())
            self.assertEqual(json.loads((Path(directory) / "reporting-status.json").read_text()), {"exit_code": 1})

    def test_success_and_skipped_never_send(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(REPORT.subprocess, "run") as run:
            for state in ("success", "skipped"):
                self.assertEqual(REPORT.status("arch", "qemu-arch-build", state, Path(directory)), 0)
            run.assert_not_called()

    def test_reject_untrusted_case_id(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(REPORT.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                REPORT.status("arch", "bad\nsecret", "failure", Path(directory))
            run.assert_not_called()

    def test_missing_secret_is_visible_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "OMG_SMOKE_SENTRY_DSN": ""}):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(REPORT.configure(), 0)
                self.assertIn("Sentry reporting disabled", output.getvalue())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_existing_config_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "omg-smoke-config"
            root.mkdir()
            config = root / "sentry.json"
            config.write_text("original")
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "OMG_SMOKE_SENTRY_DSN": "https://abc@o1.ingest.sentry.io/123"}):
                with self.assertRaises(FileExistsError):
                    REPORT.configure()
            self.assertEqual(config.read_text(), "original")

    def test_verify_accepts_successful_delivery_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            run = evidence / "run-safe"
            run.mkdir()
            (run / "reporting-status.json").write_text(
                json.dumps({"exit_code": 0}) + "\n", encoding="utf-8"
            )
            self.assertEqual(REPORT.verify(evidence), 0)

    def test_verify_rejects_failed_or_missing_delivery_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertNotEqual(REPORT.verify(evidence), 0)
            self.assertIn("::error::Sentry delivery receipt is missing", output.getvalue())
            run = evidence / "run-failed"
            run.mkdir()
            (run / "reporting-status.json").write_text(
                json.dumps({"exit_code": 1}) + "\n", encoding="utf-8"
            )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertNotEqual(REPORT.verify(evidence), 0)
            self.assertIn("::error::Sentry delivery failed: run-failed=exit-1", output.getvalue())

    def test_missing_bash_preserves_failure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(REPORT.subprocess, "run", side_effect=FileNotFoundError):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(REPORT.status("ubuntu", "qemu-ubuntu-preflight", "cancelled", Path(directory)), 0)
                self.assertIn("::warning::Sentry delivery failed", output.getvalue())
            self.assertEqual(json.loads((Path(directory) / "results.json").read_text())[0]["exit_code"], 130)
            self.assertEqual(json.loads((Path(directory) / "reporting-status.json").read_text())["exit_code"], 255)

    def test_setup_failure_has_results_and_delivery_receipt(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(REPORT.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = run.return_value.stderr = ""
            root = Path(directory)
            self.assertEqual(REPORT.ensure_failure("arch", "qemu-arch-lifecycle", "failure", root), 0)
            self.assertEqual(len(list(root.glob("run-*/results.json"))), 1)
            self.assertEqual(REPORT.verify(root), 0)
            REPORT.ensure_failure("arch", "qemu-arch-lifecycle", "failure", root)
            self.assertEqual(run.call_count, 1)

    def test_invalid_or_foreign_results_cannot_hide_failure(self):
        candidates = ["{", "[]", "null", json.dumps([{
            "case_id": "qemu-fedora-lifecycle", "distro": "fedora", "result": "HARNESS_ERROR",
            "exit_code": 1, "elapsed_seconds": 1,
        }])]
        for candidate in candidates:
            with self.subTest(candidate=candidate), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                original = root / "run-original"
                original.mkdir()
                (original / "results.json").write_text(candidate)
                with patch.object(REPORT.subprocess, "run", side_effect=FileNotFoundError):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        REPORT.ensure_failure("arch", "qemu-arch-lifecycle", "cancelled", root)
                    self.assertIn("::warning::Sentry delivery failed", output.getvalue())
                reports = list(root.glob("run-setup-*/results.json"))
                self.assertEqual(len(reports), 1)
                self.assertEqual(json.loads(reports[0].read_text())[0]["exit_code"], 130)
                self.assertEqual((original / "results.json").read_text(), candidate)

    def test_inventory_failure_does_not_fabricate_setup_failure(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(REPORT.subprocess, "run") as reporter:
            root = Path(directory)
            run = root / "run-completed"
            run.mkdir()
            (run / "results.json").write_text(json.dumps([{
                "case_id": "qemu-arch-lifecycle", "distro": "arch", "result": "PASS",
                "exit_code": 0, "elapsed_seconds": 1,
            }]))
            self.assertEqual(REPORT.ensure_failure("arch", "qemu-arch-lifecycle", "failure", root), 0)
            reporter.assert_not_called()
            self.assertEqual(len(list(root.glob("run-*"))), 1)

    def test_verify_requires_a_receipt_for_every_exported_run(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            good = evidence / "run-good"
            good.mkdir()
            (good / "reporting-status.json").write_text('{"exit_code": 0}')
            (evidence / "run-missing").mkdir()
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertNotEqual(REPORT.verify(evidence), 0)
            self.assertIn("::error::Invalid Sentry delivery receipt", output.getvalue())


if __name__ == "__main__":
    unittest.main()

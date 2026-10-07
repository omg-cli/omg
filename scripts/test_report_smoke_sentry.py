"""Exercise Sentry result admission without making a network request."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("report-smoke-sentry.sh")


class SentryResultAdmissionTests(unittest.TestCase):
    def run_rows(self, rows, identity=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = root / "envelope.jsonl"
            (root / "curl").write_text(
                '#!/bin/sh\ncat > "$FIXTURE_ENVELOPE"\nprintf 200\n')
            (root / "curl").chmod(0o755)
            config = root / "sentry.json"
            config.write_text(json.dumps({"dsn": "https://abc@fake.sentry.io/123"}))
            results = root / "results.json"
            results.write_text(json.dumps(rows))
            env = dict(os.environ, OMG_SMOKE_SENTRY_CONFIG=str(config),
                       OMG_SMOKE_ENVIRONMENT="qemu-matrix", OMG_SMOKE_RELEASE="unknown",
                       FIXTURE_ENVELOPE=str(envelope),
                       PATH=f"{root}{os.pathsep}{os.environ['PATH']}")
            for key in ("OMG_SMOKE_RUN_ID", "OMG_SMOKE_SOURCE_SHA", "OMG_SMOKE_RUN_ATTEMPT"):
                env.pop(key, None)
            env.update(identity or {})
            result = subprocess.run(["bash", str(SCRIPT), str(results)],
                                    env=env, capture_output=True, text=True,
                                    check=False, timeout=20)
            sent = ([json.loads(line) for line in envelope.read_text().splitlines()]
                    if envelope.exists() else None)
            return result, sent

    def test_explicit_hosted_identity_reaches_envelope_tags(self):
        identity = dict(OMG_SMOKE_RUN_ID="37151792590", OMG_SMOKE_SOURCE_SHA="a" * 40,
                        OMG_SMOKE_RUN_ATTEMPT="2")
        result, envelope = self.run_rows([
            dict(case_id="qemu-debian-trixie-lifecycle", distro="debian-trixie",
                 result="HARNESS_ERROR", exit_code=120, elapsed_seconds=2)], identity)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(envelope[2]["tags"], dict(run_id="37151792590", reporter="post-run",
                         source_sha="a" * 40, run_attempt="2"))

    def test_partial_or_malformed_hosted_identity_refuses_transport(self):
        valid = dict(OMG_SMOKE_RUN_ID="10", OMG_SMOKE_SOURCE_SHA="a" * 40,
                     OMG_SMOKE_RUN_ATTEMPT="2")
        invalid = [dict(valid, OMG_SMOKE_RUN_ID="tmp-unbound"),
                   dict(valid, OMG_SMOKE_RUN_ID="0"),
                   dict(valid, OMG_SMOKE_RUN_ID="1" * 21),
                   dict(valid, OMG_SMOKE_SOURCE_SHA="bad"),
                   dict(valid, OMG_SMOKE_RUN_ATTEMPT="0"),
                   dict(valid, OMG_SMOKE_RUN_ATTEMPT="10000"),
                   {key: "" for key in valid},
                   {key: value for key, value in valid.items() if key != "OMG_SMOKE_SOURCE_SHA"},
                   {key: value for key, value in valid.items() if key != "OMG_SMOKE_RUN_ATTEMPT"},
                   {key: value for key, value in valid.items() if key != "OMG_SMOKE_RUN_ID"}]
        for identity in invalid:
            with self.subTest(identity=identity):
                result, envelope = self.run_rows([
                    dict(case_id="ci-non-qemu-workflow", distro="matrix",
                         result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)], identity)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(envelope)

    def run_report(self, case_id):
        rows = [dict(case_id=case_id, distro="matrix", result="HARNESS_ERROR",
                     exit_code=1, elapsed_seconds=0)]
        return self.run_rows(rows)[0]

    def test_matrix_workflow_failure_is_reportable(self):
        result = self.run_report("qemu-matrix-x86-workflow")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Sentry accepted event", result.stdout)

    def test_pass_without_executed_exit_is_rejected_before_transport(self):
        result, envelope = self.run_rows([
            dict(case_id="qemu-arch-diff", distro="arch", result="PASS",
                 exit_code=-1, elapsed_seconds=0)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid result fields", result.stderr)
        self.assertIsNone(envelope)

    def test_executed_pass_preserves_declared_nonzero_expectations(self):
        # Inventory diff declares expected_exit=1; PASS does not imply exit 0.
        for code in (0, 1, 255):
            with self.subTest(code=code):
                result, envelope = self.run_rows([
                    dict(case_id="qemu-arch-diff", distro="arch", result="PASS",
                         exit_code=code, elapsed_seconds=0)])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("Sentry report not needed: no failures", result.stdout)
                self.assertIsNone(envelope)

    def test_failure_classifications_preserve_zero_and_missing_exits(self):
        rows = [dict(case_id=f"case-{index}", distro="arch", result=verdict,
                     exit_code=code, elapsed_seconds=0)
                for index, (verdict, code) in enumerate(
                    (("FAIL", 0), ("PRODUCT_FAIL", 0), ("HARNESS_ERROR", -1),
                     ("FAIL", -1), ("BLOCKED", -1), ("SKIPPED", -1),
                     ("EXPECTED_REJECTION", 1)))]
        result, envelope = self.run_rows(rows)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(envelope[2]["extra"]["failures"], rows[:4])

    def test_trixie_failure_reaches_sender_without_identity_rewrite(self):
        rows = [dict(case_id="qemu-debian-trixie-lifecycle", distro="debian-trixie",
                     result="HARNESS_ERROR", exit_code=120, elapsed_seconds=2)]
        result, envelope = self.run_rows(rows)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(envelope[2]["extra"], {"failures": rows})
        self.assertEqual(envelope[2]["fingerprint"],
                         ["omg-smoke", "unknown", "debian-trixie:qemu-debian-trixie-lifecycle:HARNESS_ERROR"])

    def test_unreviewed_trixie_neighbor_distros_are_rejected_before_transport(self):
        for distro in ("trixie", "debian-trixie-extra", "debian-13", "ubuntu-2604"):
            with self.subTest(distro=distro):
                result, envelope = self.run_rows([
                    dict(case_id="qemu-debian-trixie-lifecycle", distro=distro,
                         result="HARNESS_ERROR", exit_code=120, elapsed_seconds=2)])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid result fields", result.stderr)
                self.assertIsNone(envelope)

    def test_unrecognized_matrix_case_is_rejected(self):
        result = self.run_report("qemu-matrix-untrusted")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid result fields", result.stderr)

    def test_trusted_ci_reporter_failure_reaches_sentry_envelope(self):
        spec = importlib.util.spec_from_file_location(
            "qemu_reporting_sentry_fixture", SCRIPT.with_name("test_qemu_reporting.py"))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        boundary = fixture.ReportingBoundaryTests(methodName="runTest")
        jobs = [
            {"name": "Linux (debian-trixie)", "conclusion": "failure", "id": 11,
             "steps": []},
            {"name": "QEMU behavioral verification", "conclusion": "skipped", "id": 12,
             "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 13, "steps": []},
        ]
        previous = Path.cwd()
        try:
            os.chdir(SCRIPT.parent.parent)
            with redirect_stdout(io.StringIO()):
                calls, catalog = boundary.run_report_fixture(
                    [], workflow_path=".github/workflows/ci.yml", jobs=jobs,
                    artifact_listing_error=True)
        finally:
            os.chdir(previous)
        sender_calls = [call for call in calls if call[0] == "scripts/report-smoke-sentry.sh"]
        self.assertEqual(len(sender_calls), 1)
        rows = sender_calls[0][1]
        self.assertEqual(rows, catalog["failures"])
        self.assertEqual(rows, [dict(case_id="ci-non-qemu-workflow", distro="matrix",
                                     result="HARNESS_ERROR", exit_code=1,
                                     elapsed_seconds=0)])
        result, envelope = self.run_rows(rows)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Sentry accepted event", result.stdout)
        self.assertEqual(len(envelope), 3)
        header, item, event = envelope
        self.assertEqual(item, {"type": "event"})
        self.assertRegex(header["event_id"], r"^[0-9a-fA-F]{32}$")
        self.assertEqual(event["event_id"], header["event_id"])
        self.assertEqual(event["environment"], "qemu-matrix")
        self.assertEqual(event["release"], "unknown")
        self.assertEqual(event["extra"], {"failures": rows})
        self.assertEqual(event["fingerprint"],
                         ["omg-smoke", "unknown", "matrix:ci-non-qemu-workflow:HARNESS_ERROR"])

    def test_valid_guest_evidence_does_not_suppress_ci_failure_telemetry(self):
        spec = importlib.util.spec_from_file_location(
            "qemu_reporting_valid_evidence_fixture", SCRIPT.with_name("test_qemu_reporting.py"))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        boundary = fixture.ReportingBoundaryTests(methodName="runTest")
        expected = [dict(case_id="ci-non-qemu-workflow", distro="matrix",
                         result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)]
        for guest_result in ("PASS", "FAIL"):
            with self.subTest(guest_result=guest_result):
                jobs = [
                    {"name": "QEMU behavioral verification / Distro lane (arch) / QEMU guest (arch)",
                     "conclusion": "success" if guest_result == "PASS" else "failure",
                     "id": 11, "steps": []},
                    {"name": "Docs audit", "conclusion": "failure", "id": 12, "steps": []},
                    {"name": "CI Success", "conclusion": "failure", "id": 13, "steps": []},
                ]
                previous = Path.cwd()
                try:
                    os.chdir(SCRIPT.parent.parent)
                    with redirect_stdout(io.StringIO()):
                        calls, catalog = boundary.run_report_fixture(
                            [boundary.row(guest_result)], workflow_path=".github/workflows/ci.yml",
                            jobs=jobs)
                finally:
                    os.chdir(previous)
                self.assertFalse(catalog["evidence_invalid_or_unavailable"])
                senders = [call for call in calls if call[0] == "scripts/report-smoke-sentry.sh"]
                self.assertEqual(len(senders), 1)
                self.assertEqual(senders[0][1], expected)
                result, envelope = self.run_rows(senders[0][1])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(envelope[2]["extra"], {"failures": expected})
                self.assertEqual(envelope[2]["fingerprint"],
                                 ["omg-smoke", "unknown", "matrix:ci-non-qemu-workflow:HARNESS_ERROR"])

    def test_ci_matrix_neighbor_case_ids_remain_rejected(self):
        for case_id in ("ci-non-qemu-workflow-extra", "ci-non-qemu-workflows", "ci-workflow"):
            with self.subTest(case_id=case_id):
                result, envelope = self.run_rows([
                    dict(case_id=case_id, distro="matrix", result="HARNESS_ERROR",
                         exit_code=1, elapsed_seconds=0)])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid result fields", result.stderr)
                self.assertIsNone(envelope)


if __name__ == "__main__":
    unittest.main()

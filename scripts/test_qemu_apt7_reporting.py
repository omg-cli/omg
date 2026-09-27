"""Trusted reporting boundary for the manual APT 7 guest pilot."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "qemu_apt7_reporting", ROOT / "scripts/report-qemu-apt7-workflow.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class Apt7ReportingTests(unittest.TestCase):
    def identity(self):
        live = dict(id=42, run_attempt=2, head_sha="a" * 40, workflow_id=11,
                    name="QEMU APT 7 pilot", path=".github/workflows/qemu-apt7.yml",
                    event="workflow_dispatch", head_branch="main", status="completed",
                    conclusion="failure", repository={"full_name": "omg-cli/omg"})
        event = {"repository": {"full_name": "omg-cli/omg"},
                 "workflow_run": {key: live[key] for key in
                                  ("id", "run_attempt", "head_sha", "workflow_id")}}
        return event, live

    def test_accepts_exact_default_branch_dispatch_identity(self):
        event, live = self.identity()
        self.assertIs(REPORT.identity(event, live, "omg-cli/omg"), live)

    def test_rejects_untrusted_or_superseded_run(self):
        event, live = self.identity()
        for key, replacement in (("path", ".github/workflows/ci.yml"),
                                 ("name", "QEMU Matrix"), ("event", "pull_request"),
                                 ("head_branch", "feature"), ("run_attempt", 3),
                                 ("head_sha", "b" * 40), ("workflow_id", 12)):
            with self.subTest(key=key):
                changed = dict(live, **{key: replacement})
                with self.assertRaises(ValueError):
                    REPORT.identity(event, changed, "omg-cli/omg")
        changed = copy.deepcopy(live)
        changed["repository"]["full_name"] = "other/omg"
        with self.assertRaises(ValueError):
            REPORT.identity(event, changed, "omg-cli/omg")

    def test_failed_guests_keep_distinct_issue_identities(self):
        jobs = [{"name": "APT 7 guest (ubuntu2604) / QEMU guest (ubuntu2604)",
                 "conclusion": "failure"},
                {"name": "APT 7 guest (debian13) / Distro lane (debian13)",
                 "conclusion": "timed_out"},
                {"name": "APT 7 pilot result", "conclusion": "failure"}]
        self.assertEqual(REPORT.failed_cases(jobs, "failure"), [
            dict(case_id="qemu-debian13-lifecycle", distro="debian13",
                 result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0),
            dict(case_id="qemu-ubuntu2604-lifecycle", distro="ubuntu2604",
                 result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)])

    def test_build_failure_has_workflow_identity_and_cancellation_is_quiet(self):
        jobs = [{"name": "Build one Debian Trixie archive", "conclusion": "failure"},
                {"name": "APT 7 pilot result", "conclusion": "failure"}]
        self.assertEqual(REPORT.failed_cases(jobs, "failure"), [
            dict(case_id="qemu-apt7-workflow", distro="matrix",
                 result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)])
        self.assertEqual(REPORT.failed_cases(jobs, "cancelled"), [])
        self.assertEqual(REPORT.failed_cases(jobs, "success"), [])

    def test_main_uses_current_attempt_and_only_synthesized_results(self):
        event, live = self.identity()
        listing = {"total_count": 1, "jobs": [{
            "name": "APT 7 guest (debian13) / QEMU guest (debian13)",
            "conclusion": "failure", "untrusted": "do not publish"}]}
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            captured = {}

            def helper(arguments, **_kwargs):
                captured["arguments"] = arguments
                captured["rows"] = json.loads(Path(arguments[2]).read_text())

            with (patch.dict("os.environ", {"GITHUB_REPOSITORY": "omg-cli/omg",
                                          "GITHUB_EVENT_PATH": str(event_path)}),
                  patch.object(REPORT, "api", side_effect=[live, listing, live]) as api,
                  patch.object(REPORT.subprocess, "run", side_effect=helper)):
                self.assertEqual(REPORT.main(), 0)
            self.assertEqual(api.call_count, 3)
            self.assertEqual(captured["rows"][0]["distro"], "debian13")
            self.assertNotIn("untrusted", captured["rows"][0])
            self.assertIn("--source", captured["arguments"])
            self.assertIn("qemu-apt7", captured["arguments"])
            self.assertIn("https://github.com/omg-cli/omg/actions/runs/42/attempts/2",
                          captured["arguments"])

    def test_stale_rerun_never_reaches_issue_helper(self):
        event, live = self.identity()
        newer = dict(live, run_attempt=3)
        listing = {"total_count": 0, "jobs": []}
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            with (patch.dict("os.environ", {"GITHUB_REPOSITORY": "omg-cli/omg",
                                          "GITHUB_EVENT_PATH": str(event_path)}),
                  patch.object(REPORT, "api", side_effect=[live, listing, newer]),
                  patch.object(REPORT.subprocess, "run") as helper):
                with self.assertRaises(ValueError):
                    REPORT.main()
                helper.assert_not_called()

    def test_privileged_workflow_uses_default_branch_code_only(self):
        workflow = (ROOT / ".github/workflows/qemu-report.yml").read_text()
        pilot = (ROOT / ".github/workflows/qemu-apt7.yml").read_text()
        self.assertIn("workflows: [QEMU Matrix, CI, QEMU APT 7 pilot]", workflow)
        self.assertIn("github.event.workflow_run.event == 'workflow_dispatch'", workflow)
        self.assertIn("ref: ${{ github.sha }}", workflow)
        self.assertNotIn("workflow_run.head_sha", workflow)
        self.assertIn("OMG_SMOKE_SENTRY_DSN: ${{ secrets.OMG_SMOKE_SENTRY_DSN }}", pilot)


if __name__ == "__main__":
    unittest.main()

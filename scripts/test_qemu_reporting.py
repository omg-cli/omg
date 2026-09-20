import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qemu_reporting", ROOT / "scripts/report-qemu-workflow.py")
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


class ReportingBoundaryTests(unittest.TestCase):
    def row(self, result="FAIL"):
        return dict(case_id="qemu-arch-search", distro="arch", result=result,
                    exit_code=1 if result == "FAIL" else 0, elapsed_seconds=1)

    def archive(self, name, content, mode=0):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, content)
        return output.getvalue()

    def test_projection_removes_untrusted_fields_without_extraction(self):
        row = dict(self.row(), command="do not execute", environment={"secret": "private"})
        result = REPORT.archive_rows(
            self.archive("run-a/inventory/results.json", json.dumps([row])),
            {row["case_id"]},
        )
        self.assertEqual(result, [self.row()])

    def test_transaction_receipts_do_not_poison_case_reporting(self):
        output = io.BytesIO()
        case = self.row("PASS")
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([case]))
            archive.writestr("run-a/inventory/results.json", json.dumps([self.row()]))
            archive.writestr("run-a/transactions/results.json", json.dumps([
                {"id": "install-native-001", "operation": "install", "result": "PASS"}
            ]))
        self.assertEqual(REPORT.archive_rows(output.getvalue(), {case["case_id"]}),
                         [case, self.row()])

    def test_expected_refusal_pass_preserves_observed_nonzero_exit(self):
        # The inventory runner marks a checked expected refusal as PASS while
        # retaining the command's observed exit code. Do not reinterpret it.
        row = dict(self.row("PASS"), exit_code=1)
        self.assertEqual(
            REPORT.archive_rows(
                self.archive("run-a/results.json", json.dumps([row])),
                {row["case_id"]},
            ), [row],
        )

    def test_poisoned_archive_members_and_results_fail(self):
        for name, content, mode in (("../results.json", "[]", 0),
                                    ("/results.json", "[]", 0),
                                    ("run-a/results.json", "[]", stat.S_IFLNK | 0o777),
                                    ("run-a/results.json", "{" , 0),
                                    ("run-a/results.json", "x" * (1024 * 1024 + 1), 0)):
            with self.subTest(name=name, mode=mode):
                with self.assertRaises(ValueError):
                    REPORT.archive_rows(self.archive(name, content, mode), {self.row()["case_id"]})

    def test_report_rows_must_use_default_branch_case_identities(self):
        with self.assertRaises(ValueError):
            REPORT.archive_rows(
                self.archive("run-a/results.json", json.dumps([
                    dict(self.row(), case_id="attacker-selected-case")
                ])),
                {self.row()["case_id"]},
            )

    def test_policy_expands_only_reviewed_cases_and_lifecycle_receipts(self):
        policy = {"inventories": {"digest": {"cases": [
            {"id": "search", "tiers": ["hermetic"], "allowed_skips": {}}
        ]}}}
        cases = REPORT.canonical_case_ids(policy)
        self.assertIn("qemu-arch-search", cases)
        self.assertIn("qemu-fedora-aarch64-lifecycle", cases)
        self.assertIn("qemu-matrix-workflow", cases)

    def test_pr_or_non_main_success_never_closes_issues(self):
        self.assertEqual(REPORT.projection([self.row("PASS")], False), [])
        self.assertEqual(REPORT.projection([self.row("PASS")], True), [self.row("PASS")])
        self.assertEqual(REPORT.projection([self.row(), self.row("PASS")], True), [self.row()])

    def test_detailed_failures_replace_duplicate_aggregate_issue(self):
        aggregate = dict(self.row(), case_id="qemu-matrix-workflow", distro="ubuntu")
        for rows in ([aggregate, self.row()], [self.row(), aggregate]):
            self.assertEqual(REPORT.projection(rows, False), [self.row()])
        self.assertEqual(REPORT.projection([aggregate], False), [aggregate])
        self.assertEqual(REPORT.projection([aggregate, self.row("PASS")], False), [aggregate])

    def test_successful_main_can_still_close_historical_aggregate(self):
        aggregate = dict(self.row("PASS"), case_id="qemu-matrix-workflow", distro="ubuntu")
        self.assertEqual(REPORT.projection([aggregate], True), [aggregate])
        self.assertEqual(REPORT.projection([aggregate], False), [])

    def test_identity_binds_repo_workflow_commit_and_attempt(self):
        live = dict(repository={"full_name": "owner/repo"}, id=10, run_attempt=2,
                    head_sha="a" * 40, workflow_id=20, path=".github/workflows/qemu-matrix.yml",
                    status="completed", event="push")
        event = dict(repository={"full_name": "owner/repo"}, workflow_run=copy.deepcopy(live))
        self.assertEqual(REPORT.identity(event, live, "owner/repo"), live)
        for key, value in (("id", 11), ("run_attempt", 1), ("head_sha", "b" * 40),
                           ("path", ".github/workflows/evil.yml"), ("event", "pull_request"),
                           ("event", "pull_request_target")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                REPORT.identity(event, dict(live, **{key: value}), "owner/repo")

    def test_privileged_report_job_excludes_pull_request_runs(self):
        text = (ROOT / ".github/workflows/qemu-report.yml").read_text()
        self.assertIn("if: github.event.workflow_run.event != 'pull_request'", text)

    def test_reporter_checks_out_default_sha_and_never_executes_artifacts(self):
        text = (ROOT / ".github/workflows/qemu-report.yml").read_text()
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertNotIn("workflow_run.head_sha", text)
        self.assertNotIn("download-artifact", text)
        source = (ROOT / "scripts/report-qemu-workflow.py").read_text()
        self.assertNotIn("extractall", source)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main()

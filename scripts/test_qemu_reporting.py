import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import os
import tempfile
from unittest.mock import patch
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

    def test_failed_case_excerpt_is_bounded_and_does_not_include_other_files(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/inventory/results.json", json.dumps([self.row()]))
            archive.writestr("run-a/inventory/rows/search.log", "command result\n" + "x" * 2000)
            archive.writestr("run-a/inventory/rows/search.stderr.log", "the actual failure")
            archive.writestr("run-a/inventory/rows/other.stderr.log", "unrelated secret")
            archive.writestr("run-a/environment.txt", "private environment")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {self.row()["case_id"]}, diagnostics)
        excerpt = diagnostics[("qemu-arch-search", "arch")]
        self.assertIn("the actual failure", excerpt)
        self.assertNotIn("unrelated secret", excerpt)
        self.assertNotIn("private environment", excerpt)
        self.assertLessEqual(len(excerpt.encode("utf-8")), 1400)

    def test_excerpt_redacts_known_credentials_before_truncation(self):
        secret = "ghp_" + "a" * 1500
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/inventory/results.json", json.dumps([self.row()]))
            archive.writestr("run/inventory/rows/search.stderr.log",
                             secret + "\nBearer credential-value\n```\n\x1b[31mfailure\x1b[0m")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {self.row()["case_id"]}, diagnostics)
        excerpt = diagnostics[(self.row()["case_id"], "arch")]
        self.assertNotIn("a" * 20, excerpt)
        self.assertNotIn("credential-value", excerpt)
        self.assertNotIn("```", excerpt)
        self.assertNotIn("[31m", excerpt)
        self.assertIn("failure", excerpt)

    def test_lifecycle_excerpt_uses_only_its_run_root(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/guest-check.log", "daemon failed to restart")
            archive.writestr("run-b/guest-check.log", "unrelated run")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        self.assertIn("daemon failed to restart", diagnostics[(row["case_id"], "arch")])
        self.assertNotIn("unrelated run", diagnostics[(row["case_id"], "arch")])

    def test_successful_rows_never_supply_failure_excerpts(self):
        row = self.row("PASS")
        diagnostics = {}
        REPORT.archive_rows(self.archive("run/results.json", json.dumps([row])),
                            {row["case_id"]}, diagnostics)
        self.assertEqual(diagnostics, {})

    def test_lifecycle_failure_includes_later_stage_errors_after_guest_pass(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/guest-check.log", "PASS: package lifecycle")
            archive.writestr("run-a/transactions.log", "clone failed to become ready")
            archive.writestr("run-a/health-validation.log", "SSH connection refused")
            archive.writestr("run-b/transactions.log", "unrelated private output")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "arch")]
        self.assertIn("clone failed to become ready", excerpt)
        self.assertIn("SSH connection refused", excerpt)
        self.assertIn("transactions.log", excerpt)
        self.assertNotIn("unrelated private output", excerpt)
        self.assertLessEqual(len(excerpt.encode("utf-8")), 1400)

    def test_lifecycle_failure_includes_nested_daemon_shutdown_diagnostics(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/guest-check.log", "native package installed")
            archive.writestr("run-a/guest/evidence/daemon-direct.log",
                             "Bearer private-credential\nDaemon shutdown exceeded its deadline")
            archive.writestr("run-a/guest/evidence/daemon-advisory-shutdown.log",
                             "advisory cancellation failed")
            archive.writestr("run-b/guest/evidence/daemon-direct.log", "unrelated run secret")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "arch")]
        self.assertIn("Daemon shutdown exceeded its deadline", excerpt)
        self.assertIn("advisory cancellation failed", excerpt)
        self.assertNotIn("private-credential", excerpt)
        self.assertNotIn("unrelated run secret", excerpt)
        self.assertLessEqual(len(excerpt.encode("utf-8")), 1400)

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

    def test_duplicate_json_keys_cannot_replace_a_failure_with_success(self):
        payload = json.dumps([self.row()]).replace('"result": "FAIL"', '"result": "FAIL", "result": "PASS"')
        with self.assertRaises(ValueError):
            REPORT.archive_rows(self.archive("run/results.json", payload), {self.row()["case_id"]})

    def test_case_identity_must_match_its_distro(self):
        row = dict(self.row(), distro="debian")
        with self.assertRaises(ValueError):
            REPORT.archive_rows(self.archive("run/results.json", json.dumps([row])), {row["case_id"]})

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

    def test_unexecuted_inventory_stays_behind_the_lifecycle_failure(self):
        lifecycle = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR",
                         exit_code=1, elapsed_seconds=62)
        placeholders = [
            dict(self.row(), case_id=f"qemu-arch-case-{index}", result="BLOCKED",
                 exit_code=-1, elapsed_seconds=0)
            for index in range(30)
        ]
        other = dict(self.row(), case_id="qemu-debian-search", distro="debian")
        selected = REPORT.projection([lifecycle, *placeholders, other], False)
        self.assertEqual(selected, [lifecycle, other])

    def test_executed_inventory_block_survives_alongside_a_lifecycle_failure(self):
        lifecycle = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR", exit_code=1)
        executed = dict(self.row("PASS"), case_id="qemu-arch-search")
        blocked = dict(self.row(), case_id="qemu-arch-child", result="BLOCKED",
                       exit_code=-1, elapsed_seconds=0)
        selected = REPORT.projection([lifecycle, executed, blocked], True)
        self.assertEqual(selected, [
            lifecycle,
            executed,
            dict(blocked, result="HARNESS_ERROR"),
        ])

    def test_detailed_failures_replace_duplicate_aggregate_issue(self):
        for case_id in ("qemu-matrix-workflow", "qemu-matrix-x86-workflow",
                        "qemu-matrix-arm-workflow", "qemu-matrix-all-workflow"):
            with self.subTest(case_id=case_id):
                aggregate = dict(self.row(), case_id=case_id, distro="ubuntu")
                for rows in ([aggregate, self.row()], [self.row(), aggregate]):
                    self.assertEqual(REPORT.projection(rows, False), [self.row()])
                self.assertEqual(REPORT.projection([aggregate], False), [aggregate])
                self.assertEqual(REPORT.projection([aggregate, self.row("PASS")], False), [aggregate])

    def test_failure_overflow_preserves_every_identity_with_bounded_issues(self):
        failures = [dict(self.row(), case_id=f"qemu-arch-case-{n}") for n in range(26)]
        selected = REPORT.projection(failures, False)
        self.assertEqual(selected, failures)
        issues, catalog = REPORT.bound_issue_updates(selected)
        self.assertEqual(catalog, failures)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["case_id"], "qemu-matrix-workflow")
        self.assertEqual(issues[0]["result"], "HARNESS_ERROR")

    def test_issue_limit_boundary_keeps_individual_diagnoses(self):
        for count in (0, 1, 25):
            failures = [dict(self.row(), case_id=f"qemu-arch-case-{n}") for n in range(count)]
            issues, catalog = REPORT.bound_issue_updates(failures)
            self.assertEqual(issues, failures)
            self.assertEqual(catalog, failures)

    def test_overflow_cannot_both_open_and_close_aggregate(self):
        failures = [dict(self.row(), case_id=f"qemu-arch-case-{n}") for n in range(26)]
        aggregate_pass = dict(self.row("PASS"), case_id="qemu-matrix-workflow", distro="ubuntu")
        unrelated_pass = dict(self.row("PASS"), case_id="qemu-debian-search", distro="debian")
        issues, catalog = REPORT.bound_issue_updates(failures + [aggregate_pass, unrelated_pass])
        self.assertEqual(len(catalog), 26)
        self.assertEqual(issues[1:], [unrelated_pass])

    def test_successful_main_can_still_close_historical_aggregate(self):
        aggregate = dict(self.row("PASS"), case_id="qemu-matrix-workflow", distro="ubuntu")
        self.assertEqual(REPORT.projection([aggregate], True), [aggregate])
        self.assertEqual(REPORT.projection([aggregate], False), [])

    def test_arm_health_failure_has_distinct_identity_from_x86_matrix_success(self):
        arm_failure = REPORT.workflow_receipt([
            {"name": "ARM guest runner KVM health", "conclusion": "failure"},
            {"name": "Distro lane (arch) / QEMU guest (arch)", "conclusion": "success"},
        ], "failure")
        x86_success = REPORT.workflow_receipt([
            {"name": "ARM guest runner KVM health", "conclusion": "skipped"},
            {"name": "Distro lane (arch) / QEMU guest (arch)", "conclusion": "success"},
        ], "success")
        self.assertEqual(arm_failure, dict(
            case_id="qemu-arm-runner-kvm-health", distro="ubuntu",
            result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0,
        ))
        self.assertEqual(x86_success["case_id"], "qemu-matrix-x86-workflow")
        self.assertEqual(x86_success["result"], "PASS")
        self.assertNotEqual(arm_failure["case_id"], x86_success["case_id"])

    def run_report_fixture(self, rows, *, conclusion="failure", event_kind="push",
                           corrupt=False, expired=False, helper_fails=False, case_log=None,
                           log_case="search", main_shas=None, changed_attempt=False,
                           workflow_path=".github/workflows/qemu-matrix.yml", all_distros=False,
                           latest_tag="v0.1.224", provenance_override=None, commit_shas=None):
        run = dict(repository={"full_name": "owner/repo"}, id=10, run_attempt=2,
                   head_sha="a" * 40, workflow_id=20, path=workflow_path,
                   status="completed", event=event_kind, conclusion=conclusion,
                   head_branch="main", run_started_at="2026-09-20T00:00:00Z")
        event = dict(repository={"full_name": "owner/repo"}, workflow_run=run)
        artifact = dict(id=30, name="qemu-evidence-arch", size_in_bytes=100,
                        created_at=run["run_started_at"], expired=expired)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/inventory/results.json", "{" if corrupt else json.dumps(rows))
            if case_log is not None:
                archive.writestr(f"run/inventory/rows/{log_case}.stderr.log", case_log)
        payload = output.getvalue()
        artifacts = [artifact]
        payloads = {30: payload}
        if all_distros:
            artifacts, payloads = [], {}
            for identifier, distro in enumerate(REPORT.DISTROS, 30):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr("run/inventory/results.json",
                        json.dumps([row for row in rows if row["distro"] == distro]))
                    provenance = dict(staged=False, artifact_attestation_verified=True,
                                      artifact_tag="v0.1.224", harness_revision=run["head_sha"],
                                      inventory_revision="c" * 40, distro=distro, arch="x86_64")
                    if provenance_override:
                        provenance.update(provenance_override)
                    archive.writestr("provenance.json", json.dumps(provenance))
                payloads[identifier] = output.getvalue()
                artifacts.append(dict(artifact, id=identifier, name=f"qemu-evidence-{distro}",
                                      size_in_bytes=len(payloads[identifier])))
        calls = []
        main_refs = iter(main_shas or [run["head_sha"], run["head_sha"]])
        tag_commits = iter(commit_shas or ["c" * 40, "c" * 40])
        run_reads = 0
        def api(path, *args):
            nonlocal run_reads
            if path.endswith("/actions/runs/10"):
                run_reads += 1
                current = dict(run)
                if changed_attempt and run_reads > 1:
                    current["run_attempt"] += 1
                return json.dumps(current)
            if "/artifacts?" in path:
                return json.dumps(dict(total_count=len(artifacts), artifacts=artifacts))
            if "/artifacts/" in path and path.endswith("/zip"):
                return payloads[int(path.split('/')[-2])]
            if path.endswith("/git/ref/heads/main"):
                return json.dumps(dict(object=dict(sha=next(main_refs))))
            if path.endswith("/releases/latest"):
                return json.dumps(dict(tag_name=latest_tag))
            if path.endswith("/commits/v0.1.224"):
                return json.dumps(dict(sha=next(tag_commits)))
            if "/jobs?" in path:
                return json.dumps(dict(jobs=[]))
            self.fail(f"unexpected API request: {path}")
        def subprocess_run(argv, **kwargs):
            root = Path(argv[2]).parent
            transcripts = {path.parent.name: path.read_text() for path in root.glob("*/transcript.txt")}
            calls.append((argv[1], json.loads(Path(argv[2]).read_text()), transcripts, argv))
            if helper_fails and argv[1] == "scripts/qa-file-issue.sh":
                raise REPORT.subprocess.CalledProcessError(1, argv)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            event_path = path / "event.json"
            event_path.write_text(json.dumps(event))
            with patch.dict(os.environ, GITHUB_REPOSITORY="owner/repo", GITHUB_EVENT_PATH=str(event_path),
                            RUNNER_TEMP=directory, GITHUB_RUN_ID="50"), \
                 patch.object(REPORT, "api", side_effect=api), \
                 patch.object(REPORT, "canonical_case_ids", return_value={row["case_id"] for row in rows}), \
                 patch.object(REPORT.subprocess, "run", side_effect=subprocess_run):
                if changed_attempt:
                    with self.assertRaisesRegex(ValueError, "identity or attempt mismatch"):
                        REPORT.main()
                elif helper_fails:
                    with self.assertRaises(REPORT.subprocess.CalledProcessError):
                        REPORT.main()
                else:
                    self.assertEqual(REPORT.main(), 0)
            catalog_path = path / "qemu-issue-report/failures.json"
            return calls, json.loads(catalog_path.read_text()) if catalog_path.exists() else None

    def test_verified_published_success_sends_case_and_workflow_recovery_to_helper(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        calls, catalog = self.run_report_fixture(rows, conclusion="success",
            event_kind="workflow_dispatch", all_distros=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "scripts/qa-file-issue.sh")
        self.assertEqual(calls[0][1], rows + [dict(
            case_id="qemu-matrix-x86-workflow", distro="ubuntu", result="PASS",
            exit_code=0, elapsed_seconds=0)])
        self.assertNotIn("--failures-only", calls[0][3])
        self.assertEqual(catalog["failures"], [])

    def test_staged_main_success_never_closes_published_issue(self):
        calls, catalog = self.run_report_fixture([self.row("PASS")], conclusion="success")
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_stale_main_success_never_reaches_issue_helper(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        calls, catalog = self.run_report_fixture(
            rows, conclusion="success", event_kind="schedule",
            all_distros=True, main_shas=["b" * 40])
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_main_advancing_during_download_keeps_failures_but_blocks_recovery(self):
        failure = self.row()
        passed = dict(self.row("PASS"), case_id="qemu-arch-other")
        rows = [passed, failure] + [dict(passed, distro=distro,
            case_id=f"qemu-{distro}-search") for distro in REPORT.DISTROS if distro != "arch"]
        calls, catalog = self.run_report_fixture(
            rows, conclusion="success", event_kind="schedule", all_distros=True,
            main_shas=["b" * 40])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], [failure])
        self.assertEqual(catalog["failures"], [failure])

    def test_new_attempt_during_download_aborts_before_any_issue_mutation(self):
        calls, catalog = self.run_report_fixture([self.row()], changed_attempt=True)
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_reporter_overflow_reaches_helper_and_preserves_catalog_on_api_failure(self):
        failures = [dict(self.row(), case_id=f"qemu-arch-case-{n}") for n in range(26)]
        for helper_fails in (False, True):
            with self.subTest(helper_fails=helper_fails):
                calls, catalog = self.run_report_fixture(failures, helper_fails=helper_fails)
                self.assertEqual(catalog["failures"], failures)
                self.assertEqual(catalog["source_sha"], "a" * 40)
                self.assertEqual(catalog["attempt"], 2)
                self.assertFalse(catalog["evidence_invalid_or_unavailable"])
                self.assertEqual(len(calls[0][1]), 1)
                self.assertEqual(calls[0][1][0]["case_id"], "qemu-matrix-workflow")

    def test_case_diagnostic_reaches_issue_helper_with_identity_and_redaction(self):
        calls, _ = self.run_report_fixture([self.row()],
                                           case_log="expected package missing\nBearer private-token")
        transcript = calls[0][2]["arch-qemu-arch-search"]
        self.assertIn("expected package missing", transcript)
        self.assertIn("Commit: " + "a" * 40, transcript)
        self.assertIn("Attempt: 2", transcript)
        self.assertNotIn("private-token", transcript)
        self.assertIn("actions/runs/50", transcript)

    def test_counter_mismatch_and_reference_failure_reach_issue_helper_distinctly(self):
        for result, code, diagnostic in (
            ('FAIL', 0, 'native counter tc expected=188 actual=0'),
            ('BLOCKED', 2, 'native counter reference failed: arch tc exit=17\ndatabase-unavailable'),
        ):
            with self.subTest(result=result):
                row = dict(self.row(), case_id='qemu-arch-total-shortcut',
                           result=result, exit_code=code)
                calls, _ = self.run_report_fixture([row], case_log=diagnostic,
                                                   log_case='total-shortcut')
                # The issue helper excludes contextual BLOCKED rows, so the
                # trusted reporter intentionally projects them to HARNESS_ERROR.
                # Product mismatches must remain FAIL, including exit-zero ones.
                expected = dict(row, result='HARNESS_ERROR' if result == 'BLOCKED' else result)
                self.assertEqual(calls[0][1], [expected])
                transcript = calls[0][2]['arch-qemu-arch-total-shortcut']
                self.assertIn(diagnostic, transcript)
                self.assertIn('Commit: ' + 'a' * 40, transcript)
                self.assertIn('Attempt: 2', transcript)

    def test_unavailable_evidence_keeps_visible_aggregate(self):
        for options in (dict(corrupt=True), dict(expired=True)):
            with self.subTest(options=options):
                calls, catalog = self.run_report_fixture([self.row()], **options)
                self.assertTrue(catalog["evidence_invalid_or_unavailable"])
                self.assertEqual(calls[0][1][0]["result"], "HARNESS_ERROR")
                self.assertEqual(calls[0][1][0]["case_id"], "qemu-matrix-x86-workflow")

    def test_cancelled_run_makes_no_issue_updates(self):
        calls, catalog = self.run_report_fixture([self.row()], conclusion="cancelled")
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

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

    def test_integrated_ci_preserves_failure_reporting_and_rejects_untrusted_events(self):
        calls, catalog = self.run_report_fixture([self.row()],
            workflow_path=".github/workflows/ci.yml", case_log="retained guest failure")
        self.assertTrue(calls)
        self.assertIsNotNone(catalog)
        live = dict(repository={"full_name": "owner/repo"}, id=10, run_attempt=2,
                    head_sha="a" * 40, workflow_id=20, path=".github/workflows/ci.yml",
                    status="completed", event="push", head_branch="main")
        event = dict(repository={"full_name": "owner/repo"}, workflow_run=copy.deepcopy(live))
        self.assertEqual(REPORT.identity(event, live, "owner/repo"), live)
        for change in ({"event": "pull_request"}, {"event": "workflow_dispatch"},
                       {"head_branch": "untrusted"}, {"workflow_id": 21}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                REPORT.identity(event, dict(live, **change), "owner/repo")

    def test_successful_integrated_ci_requires_evidence_from_every_linux_distro(self):
        calls, catalog = self.run_report_fixture([self.row("PASS")], conclusion="success",
            workflow_path=".github/workflows/ci.yml")
        self.assertTrue(catalog["evidence_invalid_or_unavailable"])
        reported = [row for call in calls for row in call[1]]
        self.assertTrue(any(row["result"] == "HARNESS_ERROR" for row in reported))
        self.assertFalse(any(row["result"] == "PASS" for row in reported))

    def test_complete_integrated_ci_cannot_close_published_issues(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        calls, catalog = self.run_report_fixture(rows, conclusion="success",
            workflow_path=".github/workflows/ci.yml", all_distros=True)
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_published_provenance_mismatch_files_harness_error_without_closure(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        for options in (dict(provenance_override={"artifact_attestation_verified": False}),
                        dict(provenance_override={"inventory_revision": "d" * 40})):
            with self.subTest(options=options):
                all_distros = options.get("all_distros", True)
                fixture_options = {key: value for key, value in options.items() if key != "all_distros"}
                calls, catalog = self.run_report_fixture(rows, conclusion="success",
                    event_kind="workflow_dispatch", all_distros=all_distros, **fixture_options)
                self.assertTrue(catalog["evidence_invalid_or_unavailable"])
                self.assertEqual([row["result"] for row in calls[0][1]], ["HARNESS_ERROR"])
                self.assertIn("--failures-only", calls[0][3])

    def test_supported_staged_and_single_distro_dispatches_do_not_file_false_issues(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        for options in (dict(all_distros=True, provenance_override={"staged": True}),
                        dict(all_distros=False)):
            with self.subTest(options=options):
                calls, catalog = self.run_report_fixture(rows, conclusion="success",
                    event_kind="workflow_dispatch", **options)
                self.assertEqual(calls, [])
                self.assertIsNone(catalog)

    def test_superseded_release_does_not_close_or_file_an_issue(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        calls, catalog = self.run_report_fixture(rows, conclusion="success",
            event_kind="workflow_dispatch", all_distros=True, latest_tag="v0.1.225")
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_release_tag_moving_during_report_blocks_closure(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        calls, catalog = self.run_report_fixture(rows, conclusion="success",
            event_kind="schedule", all_distros=True,
            commit_shas=["c" * 40, "d" * 40])
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

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

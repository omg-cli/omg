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
            archive.writestr("run-a/inventory/rows/search.stdout.log", "No internet connection")
            archive.writestr("run-a/inventory/rows/other.stderr.log", "unrelated secret")
            archive.writestr("run-a/environment.txt", "private environment")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {self.row()["case_id"]}, diagnostics)
        excerpt = diagnostics[("qemu-arch-search", "arch")]
        self.assertIn("the actual failure", excerpt)
        self.assertIn("No internet connection", excerpt)
        self.assertNotIn("command result", excerpt)
        self.assertNotIn("unrelated secret", excerpt)
        self.assertNotIn("private environment", excerpt)
        self.assertLessEqual(len(excerpt.encode("utf-8")), 1400)

    def test_inventory_combined_log_is_used_when_stream_logs_are_empty(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/inventory/results.json", json.dumps([self.row()]))
            archive.writestr("run/inventory/rows/search.stderr.log", "")
            archive.writestr("run/inventory/rows/search.stdout.log", "")
            archive.writestr("run/inventory/rows/search.log", "combined command failure")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {self.row()["case_id"]}, diagnostics)
        self.assertIn("combined command failure", diagnostics[(self.row()["case_id"], "arch")])

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

    def test_doctor_connectivity_failure_is_named_in_lifecycle_issue_excerpt(self):
        row = dict(self.row(), case_id="qemu-fedora-lifecycle", distro="fedora",
                   result="PRODUCT_FAIL")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/results.json", json.dumps([row]))
            archive.writestr("run/guest/evidence/doctor-connectivity-fallback.log",
                             "assertion failed: Doctor alternate did not report kernel.org reachable")
            archive.writestr("run/guest-check.log",
                             "Doctor connectivity fallback failed (exit 1)")
            archive.writestr("run/kvm-probe.log", "routine KVM probe")
            archive.writestr("run/transactions.log", "unrelated transaction setup")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "fedora")]
        self.assertIn("doctor-connectivity-fallback.log", excerpt)
        self.assertIn("kernel.org reachable", excerpt)
        self.assertIn("Doctor connectivity fallback failed", excerpt)
        self.assertNotIn("routine KVM probe", excerpt)
        self.assertNotIn("unrelated transaction setup", excerpt)

    def test_fedora_metadata_refresh_failure_includes_native_output(self):
        row = dict(self.row(), case_id="qemu-fedora-lifecycle", distro="fedora",
                   result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/results.json", json.dumps([row]))
            archive.writestr("run/guest-check.log", "guest check exited 120")
            archive.writestr("run/guest/evidence/index-update.txt",
                             "Fedora metadata mirror timed out")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "fedora")]
        self.assertIn("Fedora metadata mirror timed out", excerpt)
        self.assertIn("guest check exited 120", excerpt)

    def test_preboot_image_failure_supplies_lifecycle_diagnostic(self):
        row = dict(self.row(), case_id="qemu-fedora-lifecycle",
                   distro="fedora", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/image-setup.log",
                             "Bearer private-credential\n"
                             "curl: (6) Could not resolve host: download.fedoraproject.org\n")
            archive.writestr("run-a/controller-setup.log", "controller setup succeeded")
            archive.writestr("run-b/image-setup.log", "unrelated run failure")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "fedora")]
        self.assertIn("image-setup.log", excerpt)
        self.assertIn("Could not resolve host", excerpt)
        self.assertNotIn("private-credential", excerpt)
        self.assertNotIn("controller setup succeeded", excerpt)
        self.assertNotIn("unrelated run failure", excerpt)

    def test_failed_clone_reports_its_network_serial_evidence(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/transactions/summary.json", json.dumps({
                "results": [
                    {"id": "install-native-001", "result": "PASS"},
                    {"id": "remove-native-001", "result": "HARNESS_ERROR"},
                ],
            }))
            archive.writestr("run-a/transactions/trials/remove-native-001/serial.log",
                             "eth0: Lost carrier\n" + "boot progress\n" * 20 +
                             "Failed to start Wait for Network to be Online.\n" +
                             "eth0 fe80::5054:ff:fe12:3456/64\n" + "login: \n" * 20)
            archive.writestr("run-a/transactions/trials/remove-native-001/boot.qemu-startup.log",
                             "QEMU launched with user network backend\n")
            archive.writestr("run-a/transactions/trials/install-native-001/boot.qemu-startup.log",
                             "unrelated prior trial output")
            archive.writestr("run-b/transactions/trials/remove-native-001/serial.log",
                             "unrelated private output")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "arch")]
        self.assertIn("remove-native-001/serial.log", excerpt)
        self.assertIn("remove-native-001/boot.qemu-startup.log", excerpt)
        self.assertIn("QEMU launched", excerpt)
        self.assertIn("Lost carrier", excerpt)
        self.assertIn("Wait for Network", excerpt)
        self.assertIn("fe80::", excerpt)
        self.assertNotIn("unrelated private output", excerpt)
        self.assertNotIn("unrelated prior trial output", excerpt)
        self.assertLessEqual(len(excerpt.encode("utf-8")), 1400)

    def test_failed_trial_before_qemu_launch_uses_boot_log(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/results.json", json.dumps([row]))
            archive.writestr("run/transactions/summary.json", json.dumps({
                "results": [{"id": "remove-native-001", "result": "HARNESS_ERROR"}],
            }))
            archive.writestr("run/transactions/trials/remove-native-001/boot.log",
                             "seed creation failed before QEMU launch")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        self.assertIn("seed creation failed", diagnostics[(row["case_id"], "arch")])

    def test_preparation_and_restore_clone_startup_logs_follow_phase(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        for phase, selected, rejected in (
            ("preparation", "prepare-install-boot.qemu-startup.log",
             "resume-boot.qemu-startup.log"),
            ("restore", "resume-boot.qemu-startup.log",
             "prepare-install-boot.qemu-startup.log"),
        ):
            with self.subTest(phase=phase):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr("run/results.json", json.dumps([row]))
                    archive.writestr("run/transactions/summary.json",
                                     json.dumps({"phase": phase, "results": []}))
                    archive.writestr(f"run/transactions/{selected}", "selected clone failure")
                    archive.writestr(f"run/transactions/{rejected}", "unrelated clone")
                diagnostics = {}
                REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
                excerpt = diagnostics[(row["case_id"], "arch")]
                self.assertIn(selected, excerpt)
                self.assertIn("selected clone failure", excerpt)
                self.assertNotIn("unrelated clone", excerpt)

    def test_preparation_and_restore_use_boot_log_before_qemu_launch(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        for phase, step, selected in (
            ("preparation", "prepare-install-boot", "prepare-install-boot.log"),
            ("restore", None, "resume-boot.log"),
        ):
            with self.subTest(phase=phase):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr("run/results.json", json.dumps([row]))
                    summary = {"phase": phase, "results": []}
                    if step is not None:
                        summary["preparation_step"] = step
                    archive.writestr("run/transactions/summary.json", json.dumps(summary))
                    archive.writestr(f"run/transactions/{selected}",
                                     "seed creation failed before QEMU launch")
                diagnostics = {}
                REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
                self.assertIn(selected, diagnostics[(row["case_id"], "arch")])
                self.assertIn("seed creation failed", diagnostics[(row["case_id"], "arch")])

    def test_preparation_failure_selects_its_own_command_log(self):
        row = dict(self.row(), case_id="qemu-fedora-lifecycle", distro="fedora",
                   result="HARNESS_ERROR")
        for step, selected in (
            ("automatic-updates", "automatic-updates.log"),
            ("prepare-remove", "prepare-remove.log"),
            ("remove-repository-state", "remove-repository-state.log"),
            ("stop-prepared-remove", "stop-prepared-remove.log"),
            ("prepare-install", "prepare-install.log"),
            ("install-repository-state", "install-repository-state.log"),
            ("stop-prepared-install", "stop-prepared-install.log"),
        ):
            with self.subTest(step=step):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr("run/results.json", json.dumps([row]))
                    archive.writestr("run/transactions/summary.json", json.dumps({
                        "phase": "preparation", "preparation_step": step, "results": [],
                    }))
                    archive.writestr(f"run/transactions/{selected}",
                                     f"decisive {step} failure")
                    archive.writestr("run/transactions/prepare-install-boot.qemu-startup.log",
                                     "unrelated earlier clone")
                diagnostics = {}
                REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
                excerpt = diagnostics[(row["case_id"], "fedora")]
                self.assertIn(selected, excerpt)
                self.assertIn(f"decisive {step} failure", excerpt)
                self.assertNotIn("unrelated earlier clone", excerpt)

    def test_unrecognized_preparation_step_does_not_select_stale_clone_log(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        for step in ("unknown", ["prepare-install-boot"]):
            with self.subTest(step=step):
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    archive.writestr("run/results.json", json.dumps([row]))
                    archive.writestr("run/transactions/summary.json", json.dumps({
                        "phase": "preparation", "preparation_step": step, "results": [],
                    }))
                    archive.writestr("run/transactions/prepare-install-boot.qemu-startup.log",
                                     "unrelated earlier clone")
                    archive.writestr("run/transactions.log", "current preparation failed")
                diagnostics = {}
                REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
                excerpt = diagnostics[(row["case_id"], "arch")]
                self.assertIn("current preparation failed", excerpt)
                self.assertNotIn("unrelated earlier clone", excerpt)

    def test_malformed_phase_keeps_generic_lifecycle_diagnostic(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/results.json", json.dumps([row]))
            archive.writestr("run/transactions/summary.json", json.dumps({
                "phase": ["preparation"], "results": [],
            }))
            archive.writestr("run/transactions.log", "preparation step failed")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        self.assertIn("preparation step failed", diagnostics[(row["case_id"], "arch")])

    def test_failed_transaction_reports_measured_command_output(self):
        row = dict(self.row(), case_id="qemu-fedora-lifecycle", distro="fedora",
                   result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/transactions/summary.json", json.dumps({
                "results": [{"id": "install-native-001", "result": "FAIL"}],
            }))
            trial = "run-a/transactions/trials/install-native-001/"
            archive.writestr(trial + "transaction-trial/transaction.stderr",
                             "Error: failed to download tree from Fedora mirror\n")
            archive.writestr(trial + "transaction-trial/transaction.stdout",
                             "Updating and loading repositories\n")
            archive.writestr(trial + "serial.log", "unrelated boot error\n")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "fedora")]
        self.assertIn("install-native-001/transaction-trial/transaction.stderr", excerpt)
        self.assertIn("failed to download tree", excerpt)
        self.assertIn("Updating and loading repositories", excerpt)
        self.assertNotIn("unrelated boot error", excerpt)
        self.assertLessEqual(len(excerpt.encode("utf-8")), 1400)

    def test_malformed_clone_receipt_does_not_hide_lifecycle_failure(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/transactions/summary.json", '{"results": [')
            archive.writestr("run-a/health-validation.log", "SSH connection refused")
        diagnostics = {}
        self.assertEqual(REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics),
                         [row])
        self.assertIn("SSH connection refused", diagnostics[(row["case_id"], "arch")])

    def test_kvm_preflight_failure_reaches_lifecycle_issue_excerpt(self):
        row = dict(self.row(), case_id="qemu-arch-lifecycle", result="HARNESS_ERROR")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run-a/results.json", json.dumps([row]))
            archive.writestr("run-a/kvm-probe.log", "kvm=inaccessible device=/dev/kvm\ngroup=render")
            archive.writestr("run-b/kvm-probe.log", "unrelated runner")
        diagnostics = {}
        REPORT.archive_rows(output.getvalue(), {row["case_id"]}, diagnostics)
        excerpt = diagnostics[(row["case_id"], "arch")]
        self.assertIn("kvm=inaccessible device=/dev/kvm", excerpt)
        self.assertIn("group=render", excerpt)
        self.assertNotIn("unrelated runner", excerpt)

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

    def test_missing_guest_provenance_admits_only_setup_lifecycle_failure(self):
        lifecycle = dict(self.row(), case_id="qemu-debian-aarch64-lifecycle",
                         distro="debian", result="HARNESS_ERROR")
        archive = self.archive("run-setup-123/results.json", json.dumps([lifecycle]))
        self.assertEqual(REPORT.archive_rows(
            archive, {lifecycle["case_id"]}, guest=("debian", "aarch64"), revision="a" * 40),
            [dict(lifecycle, arch="aarch64")])
        inventory = dict(lifecycle, case_id="qemu-debian-search")
        for path, row in (("run/inventory/results.json", inventory),
                          ("run-setup-123/results.json", inventory),
                          ("run/results.json", lifecycle)):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "lacks provenance"):
                    REPORT.archive_rows(self.archive(path, json.dumps([row])),
                                        {row["case_id"]}, guest=("debian", "aarch64"),
                                        revision="a" * 40)

    def test_guest_rows_cannot_claim_another_artifact_distro(self):
        row = dict(self.row(), case_id="qemu-ubuntu-search", distro="ubuntu")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/inventory/results.json", json.dumps([row]))
            archive.writestr("provenance.json", json.dumps(dict(
                harness_revision="a" * 40, distro="debian", arch="aarch64")))
        with self.assertRaisesRegex(ValueError, "distro differs"):
            REPORT.archive_rows(output.getvalue(), {row["case_id"]},
                                guest=("debian", "aarch64"), revision="a" * 40)

    def test_guest_rows_cannot_claim_another_artifact_architecture(self):
        row = dict(self.row(), case_id="qemu-debian-search", distro="debian",
                   arch="x86_64")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("run/inventory/results.json", json.dumps([row]))
            archive.writestr("provenance.json", json.dumps(dict(
                harness_revision="a" * 40, distro="debian", arch="aarch64")))
        with self.assertRaisesRegex(ValueError, "architecture differs"):
            REPORT.archive_rows(output.getvalue(), {row["case_id"]},
                                guest=("debian", "aarch64"), revision="a" * 40)

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

    def test_arm_blocked_placeholders_cannot_suppress_x86_failure(self):
        arm_lifecycle = dict(self.row(), case_id="qemu-debian-aarch64-lifecycle",
                             distro="debian", arch="aarch64", result="HARNESS_ERROR")
        arm_blocked = dict(self.row(), case_id="qemu-debian-search", distro="debian",
                           arch="aarch64", result="BLOCKED", exit_code=-1,
                           elapsed_seconds=0)
        x86_failure = dict(self.row(), case_id="qemu-debian-search", distro="debian",
                           arch="x86_64")
        self.assertEqual(REPORT.projection([arm_lifecycle, arm_blocked, x86_failure], False),
                         [arm_lifecycle, x86_failure])

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
        self.assertEqual(issues[0]["distro"], "matrix")
        self.assertEqual(issues[0]["result"], "HARNESS_ERROR")

    def test_failure_overflow_keeps_distinct_ci_prerequisite_issue(self):
        failures = [dict(self.row(), case_id=f"qemu-arch-case-{n}") for n in range(26)]
        ci = dict(case_id="ci-non-qemu-workflow", distro="matrix",
                  result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)
        issues, catalog = REPORT.bound_issue_updates([*failures, ci])
        self.assertEqual(catalog, [*failures, ci])
        self.assertEqual([row["case_id"] for row in issues],
                         ["qemu-matrix-workflow", "ci-non-qemu-workflow"])

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
        self.assertEqual(x86_success["distro"], "matrix")
        self.assertEqual(x86_success["result"], "PASS")
        self.assertNotEqual(arm_failure["case_id"], x86_success["case_id"])

    def test_workflow_failure_uses_the_only_failed_guest_distro(self):
        jobs = [
            {"name": "QEMU behavioral verification / Distro lane (fedora) / QEMU guest (fedora)",
             "conclusion": "failure"},
            {"name": "QEMU behavioral verification / Distro lane (ubuntu) / QEMU guest (ubuntu)",
             "conclusion": "success"},
            {"name": "QEMU behavioral verification / QEMU matrix result",
             "conclusion": "failure"},
        ]
        receipt = REPORT.workflow_receipt(jobs, "failure")
        self.assertEqual(receipt["case_id"], "qemu-matrix-x86-workflow")
        self.assertEqual(receipt["distro"], "fedora")

    def test_workflow_failure_without_one_guest_distro_uses_matrix_identity(self):
        jobs = [
            {"name": "QEMU behavioral verification / Distro lane (fedora) / QEMU guest (fedora)",
             "conclusion": "failure"},
            {"name": "QEMU behavioral verification / Distro lane (debian) / QEMU guest (debian)",
             "conclusion": "failure"},
        ]
        receipt = REPORT.workflow_receipt(jobs, "failure")
        self.assertEqual(receipt["distro"], "matrix")

    def run_report_fixture(self, rows, *, conclusion="failure", event_kind="push",
                           corrupt=False, expired=False, helper_fails=False, case_log=None,
                           log_case="search", main_shas=None, changed_attempt=False,
                           workflow_path=".github/workflows/qemu-matrix.yml", all_distros=False,
                           latest_tag="v0.1.224", provenance_override=None, commit_shas=None,
                           jobs=None, prior_attempt_artifact=False,
                           retained_guest_artifacts=False, arm_rows=None, arm_log=None,
                            arm_first=False, arm_provenance_override=None,
                            no_artifacts=False, artifact_listing_error=False):
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
            archive.writestr("provenance.json", json.dumps(dict(
                harness_revision=run["head_sha"], distro="arch", arch="x86_64", staged=True)))
            if case_log is not None:
                archive.writestr(f"run/inventory/rows/{log_case}.stderr.log", case_log)
        payload = output.getvalue()
        artifacts = [artifact]
        payloads = {30: payload}
        if no_artifacts:
            artifacts, payloads = [], {}
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
                    if case_log is not None and distro == "debian":
                        archive.writestr(f"run/inventory/rows/{log_case}.stderr.log", case_log)
                payloads[identifier] = output.getvalue()
                artifacts.append(dict(artifact, id=identifier, name=f"qemu-evidence-{distro}",
                                      size_in_bytes=len(payloads[identifier])))
        if arm_rows is not None:
            arm_distro = arm_rows[0]["distro"]
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("run/inventory/results.json", json.dumps(arm_rows))
                provenance = dict(harness_revision=run["head_sha"], distro=arm_distro,
                                  arch="aarch64", staged=True)
                if arm_provenance_override:
                    provenance.update(arm_provenance_override)
                archive.writestr("provenance.json", json.dumps(provenance))
                if arm_log is not None:
                    archive.writestr(f"run/inventory/rows/{log_case}.stderr.log", arm_log)
            payloads[40] = output.getvalue()
            arm_artifact = dict(artifact, id=40, name=f"qemu-arm-evidence-{arm_distro}",
                                size_in_bytes=len(payloads[40]))
            if arm_first:
                artifacts.insert(0, arm_artifact)
            else:
                artifacts.append(arm_artifact)
        if prior_attempt_artifact:
            artifacts.insert(0, dict(artifact, id=29, name="qemu-workflow-report",
                                     created_at="2026-09-19T23:00:00Z", expired=False))
            payloads[29] = payload
        if retained_guest_artifacts:
            old_start = "2026-09-19T23:00:00Z"
            old_end = "2026-09-19T23:20:00Z"
            for item in artifacts:
                if item["name"] in {f"qemu-evidence-{distro}" for distro in REPORT.DISTROS[:-1]}:
                    item["created_at"] = "2026-09-19T23:10:00Z"
            stale = dict(self.row(), case_id="qemu-fedora-search", distro="fedora")
            old_zip = io.BytesIO()
            with zipfile.ZipFile(old_zip, "w") as archive:
                archive.writestr("run/inventory/results.json", json.dumps([stale]))
            payloads[28] = old_zip.getvalue()
            artifacts.insert(0, dict(artifact, id=28, name="qemu-evidence-fedora",
                                     created_at="2026-09-19T23:10:00Z", expired=False,
                                     size_in_bytes=len(payloads[28])))
            jobs = [dict(name=f"QEMU guest ({distro})", conclusion="success",
                         started_at=old_start if distro != "fedora" else run["run_started_at"],
                         completed_at=old_end if distro != "fedora" else "2026-09-20T00:20:00Z")
                    for distro in REPORT.DISTROS]
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
                if artifact_listing_error:
                    raise ValueError("artifact listing unavailable")
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
                return json.dumps(dict(jobs=[] if jobs is None else jobs))
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
        self.assertEqual(calls[0][1], [dict(row, arch="x86_64") for row in rows] + [dict(
            case_id="qemu-matrix-x86-workflow", distro="matrix", result="PASS",
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
        self.assertEqual(calls[0][1], [dict(failure, arch="x86_64")])
        self.assertEqual(catalog["failures"], [dict(failure, arch="x86_64")])

    def test_new_attempt_during_download_aborts_before_any_issue_mutation(self):
        calls, catalog = self.run_report_fixture([self.row()], changed_attempt=True)
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_reporter_overflow_reaches_helper_and_preserves_catalog_on_api_failure(self):
        failures = [dict(self.row(), case_id=f"qemu-arch-case-{n}") for n in range(26)]
        for helper_fails in (False, True):
            with self.subTest(helper_fails=helper_fails):
                calls, catalog = self.run_report_fixture(failures, helper_fails=helper_fails)
                self.assertEqual(catalog["failures"], [dict(row, arch="x86_64") for row in failures])
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

    def test_same_case_failure_on_both_architectures_keeps_two_diagnoses(self):
        x86 = dict(self.row(), case_id="qemu-debian-search", distro="debian", exit_code=3)
        arm = dict(x86, exit_code=17)
        for arm_first in (False, True):
            with self.subTest(arm_first=arm_first):
                calls, catalog = self.run_report_fixture(
                    [x86], all_distros=True, arm_rows=[arm], arm_first=arm_first,
                    case_log="x86 package result is wrong", arm_log="ARM package result is wrong")
                self.assertEqual(len(calls), 1)
                reported = {row["arch"]: row for row in calls[0][1]}
                self.assertEqual(set(reported), {"x86_64", "aarch64"})
                self.assertEqual(reported["x86_64"]["exit_code"], 3)
                self.assertEqual(reported["aarch64"]["exit_code"], 17)
                self.assertEqual(len(catalog["failures"]), 2)
                transcripts = calls[0][2]
                self.assertIn("x86 package result is wrong",
                              transcripts["debian-qemu-debian-search"])
                self.assertNotIn("ARM package result is wrong",
                                 transcripts["debian-qemu-debian-search"])
                self.assertIn("ARM package result is wrong",
                              transcripts["debian-aarch64-qemu-debian-search"])
                self.assertNotIn("x86 package result is wrong",
                                 transcripts["debian-aarch64-qemu-debian-search"])

    def test_arm_failure_survives_same_case_x86_pass(self):
        passed = dict(self.row("PASS"), case_id="qemu-debian-search", distro="debian")
        failed = dict(passed, result="PRODUCT_FAIL", exit_code=2)
        calls, catalog = self.run_report_fixture(
            [passed], all_distros=True, arm_rows=[failed], arm_log="ARM-only break")
        self.assertEqual(calls[0][1], [dict(failed, arch="aarch64")])
        self.assertEqual(catalog["failures"], [dict(failed, arch="aarch64")])

    def test_arm_provenance_mismatch_becomes_workflow_harness_failure(self):
        case = dict(self.row(), case_id="qemu-debian-search", distro="debian")
        for override in ({"arch": "x86_64"}, {"distro": "ubuntu"},
                         {"harness_revision": "b" * 40}):
            with self.subTest(override=override):
                calls, catalog = self.run_report_fixture(
                    [case], all_distros=True, arm_rows=[case],
                    arm_provenance_override=override)
                self.assertEqual(len(catalog["failures"]), 1)
                self.assertEqual(catalog["failures"][0]["result"], "HARNESS_ERROR")
                self.assertTrue(catalog["evidence_invalid_or_unavailable"])
                self.assertEqual(calls[0][1][0]["case_id"], "qemu-matrix-x86-workflow")

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
                self.assertEqual(calls[0][1], [dict(expected, arch="x86_64")])
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

    def test_failed_fedora_setup_without_guest_evidence_is_not_labeled_ubuntu(self):
        jobs = [
            {"name": "QEMU behavioral verification / Distro lane (fedora) / QEMU guest (fedora)",
             "conclusion": "failure", "id": 11, "steps": [
                 {"name": "Reuse verified native CI binaries", "conclusion": "failure", "number": 4}]},
            {"name": "QEMU behavioral verification / Distro lane (ubuntu) / QEMU guest (ubuntu)",
             "conclusion": "success", "id": 12, "steps": []},
            {"name": "QEMU behavioral verification / QEMU matrix result",
             "conclusion": "failure", "id": 13, "steps": []},
        ]
        calls, catalog = self.run_report_fixture([self.row()], corrupt=True, jobs=jobs)
        self.assertTrue(catalog["evidence_invalid_or_unavailable"])
        self.assertEqual(len(calls[0][1]), 1)
        self.assertEqual(calls[0][1][0]["distro"], "fedora")
        self.assertEqual(calls[0][1][0]["case_id"], "qemu-matrix-x86-workflow")

    def test_failed_native_ci_before_qemu_uses_ci_prerequisite_identity(self):
        jobs = [
            {"name": "Linux (debian-trixie)", "conclusion": "failure", "id": 11,
             "steps": [{"name": "Run unit tests", "conclusion": "failure", "number": 13}]},
            {"name": "QEMU behavioral verification", "conclusion": "skipped", "id": 12,
             "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 13, "steps": []},
        ]
        calls, catalog = self.run_report_fixture(
            [], workflow_path=".github/workflows/ci.yml", no_artifacts=True,
            jobs=jobs)
        self.assertEqual(len(catalog["failures"]), 1)
        self.assertEqual(catalog["failures"][0]["case_id"], "ci-non-qemu-workflow")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1][0]["case_id"], "ci-non-qemu-workflow")
        self.assertEqual(calls[0][3][calls[0][3].index("--source") + 1], "ci")

    def test_failed_native_ci_with_unavailable_artifacts_does_not_invent_qemu_failure(self):
        jobs = [
            {"name": "Linux (debian-trixie)", "conclusion": "failure", "id": 11,
             "steps": []},
            {"name": "QEMU behavioral verification", "conclusion": "skipped", "id": 12,
             "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 13, "steps": []},
        ]
        calls, catalog = self.run_report_fixture(
            [], workflow_path=".github/workflows/ci.yml", jobs=jobs,
            artifact_listing_error=True)
        self.assertTrue(catalog["evidence_invalid_or_unavailable"])
        self.assertEqual([row["case_id"] for row in catalog["failures"]],
                         ["ci-non-qemu-workflow"])
        self.assertEqual(len(calls), 2)  # issue helper and telemetry
        self.assertEqual(calls[0][3][calls[0][3].index("--source") + 1], "ci")

    def test_failed_ci_success_gate_with_skipped_qemu_stays_outside_qemu(self):
        jobs = [
            {"name": "QEMU behavioral verification", "conclusion": "skipped", "id": 11,
             "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 12,
             "steps": [{"name": "Evaluate required jobs", "conclusion": "failure", "number": 3}]},
        ]
        calls, catalog = self.run_report_fixture(
            [], workflow_path=".github/workflows/ci.yml", no_artifacts=True,
            jobs=jobs)
        self.assertEqual([row["case_id"] for row in catalog["failures"]],
                         ["ci-non-qemu-workflow"])
        self.assertEqual(calls[0][3][calls[0][3].index("--source") + 1], "ci")
        self.assertIn("Evaluate required jobs", calls[0][2]["matrix-ci-non-qemu-workflow"])

    def test_failed_qemu_guest_inside_ci_keeps_qemu_identity(self):
        jobs = [
            {"name": "QEMU behavioral verification / Distro lane (arch) / QEMU guest (arch)",
             "conclusion": "failure", "id": 11, "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 12, "steps": []},
        ]
        calls, catalog = self.run_report_fixture(
            [self.row()], workflow_path=".github/workflows/ci.yml", jobs=jobs)
        self.assertEqual(catalog["failures"][0]["case_id"], "qemu-arch-search")
        self.assertEqual(calls[0][3][calls[0][3].index("--source") + 1], "qemu-matrix")

    def test_failed_native_ci_after_successful_qemu_keeps_ci_identity(self):
        jobs = [
            {"name": "QEMU behavioral verification / QEMU matrix result",
             "conclusion": "success", "id": 11, "steps": []},
            {"name": "Docs audit", "conclusion": "failure", "id": 12, "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 13, "steps": []},
        ]
        calls, catalog = self.run_report_fixture(
            [self.row("PASS")], workflow_path=".github/workflows/ci.yml", jobs=jobs)
        self.assertEqual([row["case_id"] for row in catalog["failures"]],
                         ["ci-non-qemu-workflow"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][3][calls[0][3].index("--source") + 1], "ci")

    def test_parallel_ci_and_qemu_failures_keep_both_identities(self):
        jobs = [
            {"name": "QEMU behavioral verification / Distro lane (arch) / QEMU guest (arch)",
             "conclusion": "failure", "id": 11, "steps": []},
            {"name": "Docs audit", "conclusion": "failure", "id": 12, "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 13, "steps": []},
        ]
        calls, catalog = self.run_report_fixture(
            [self.row()], workflow_path=".github/workflows/ci.yml", jobs=jobs)
        self.assertEqual({row["case_id"] for row in catalog["failures"]},
                         {"qemu-arch-search", "ci-non-qemu-workflow"})
        self.assertEqual({call[3][call[3].index("--source") + 1] for call in calls},
                         {"qemu-matrix", "ci"})
        qemu_transcript = calls[0][2]["arch-qemu-arch-search"]
        ci_transcript = calls[0][2]["matrix-ci-non-qemu-workflow"]
        self.assertIn("QEMU guest (arch)", qemu_transcript)
        self.assertNotIn("Docs audit", qemu_transcript)
        self.assertIn("Docs audit", ci_transcript)
        self.assertNotIn("QEMU guest (arch)", ci_transcript)

    def test_qemu_parent_failure_without_children_is_not_a_ci_prerequisite(self):
        jobs = [
            {"name": "QEMU behavioral verification", "conclusion": "failure",
             "id": 11, "steps": []},
            {"name": "CI Success", "conclusion": "failure", "id": 12, "steps": []},
        ]
        calls, catalog = self.run_report_fixture(
            [], workflow_path=".github/workflows/ci.yml", no_artifacts=True,
            jobs=jobs)
        self.assertEqual([row["case_id"] for row in catalog["failures"]],
                         ["qemu-matrix-x86-workflow"])
        self.assertEqual(calls[0][3][calls[0][3].index("--source") + 1], "qemu-matrix")

    def test_cancelled_run_makes_no_issue_updates(self):
        calls, catalog = self.run_report_fixture([self.row()], conclusion="cancelled")
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_identity_binds_repo_workflow_commit_and_attempt(self):
        live = dict(repository={"full_name": "owner/repo"}, id=10, run_attempt=2,
                    head_sha="a" * 40, workflow_id=20, path=".github/workflows/qemu-matrix.yml",
                    status="completed", event="push", head_branch="main")
        event = dict(repository={"full_name": "owner/repo"}, workflow_run=copy.deepcopy(live))
        self.assertEqual(REPORT.identity(event, live, "owner/repo"), live)
        for key, value in (("id", 11), ("run_attempt", 1), ("head_sha", "b" * 40),
                           ("path", ".github/workflows/evil.yml"), ("head_branch", "feature"),
                           ("event", "pull_request"),
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

    def test_successful_rerun_ignores_previous_attempt_failure_artifact(self):
        rows = [dict(self.row("PASS"), distro=distro, case_id=f"qemu-{distro}-search")
                for distro in REPORT.DISTROS]
        calls, catalog = self.run_report_fixture(
            rows, conclusion="success", workflow_path=".github/workflows/ci.yml",
            all_distros=True, prior_attempt_artifact=True,
            retained_guest_artifacts=True)
        self.assertEqual(calls, [])
        self.assertIsNone(catalog)

    def test_retained_arm_artifact_requires_the_successful_arm_job(self):
        artifact = dict(name="qemu-arm-evidence-debian",
                        created_at="2026-09-19T23:10:00Z")
        run = dict(run_started_at="2026-09-20T00:00:00Z")
        job = dict(name="QEMU guest arm64 (debian)", conclusion="success",
                   started_at="2026-09-19T23:00:00Z",
                   completed_at="2026-09-19T23:20:00Z")
        self.assertTrue(REPORT.retained_guest_artifact(artifact, run, [job]))
        self.assertFalse(REPORT.retained_guest_artifact(
            artifact, run, [dict(job, conclusion="failure")]))
        self.assertFalse(REPORT.retained_guest_artifact(
            artifact, run, [dict(job, name="QEMU guest (debian)")]))

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
                selected_rows = rows if options["all_distros"] else rows[:1]
                calls, catalog = self.run_report_fixture(selected_rows, conclusion="success",
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
        self.assertIn("    branches: [main]", text)
        self.assertIn("if: github.event.workflow_run.head_branch == 'main'", text)
        self.assertIn("github.event.workflow_run.event != 'pull_request'", text)

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

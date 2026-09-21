"""Allowlist and adversarial descriptor tests for the Linux CI evidence exporter."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("export_qemu_evidence", Path(__file__).with_name("export-qemu-evidence.py"))
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)

TRANSACTION_DIAGNOSTICS = (
    "command.json", "expected-identity.tsv",
    "omg-info-before.stdout", "omg-info-before.stderr",
    "native-info-before.stdout", "native-info-before.stderr",
    "omg-identity-before.tsv", "native-identity-before.tsv",
    "manual-before.stdout", "manual-before.stderr", "manual-after.stdout", "manual-after.stderr",
    "cache-before-paths.txt", "cache-after-paths.txt",
)
TRANSACTION_PRIVATE = (
    "data/usage.json", "cache/command.json", "config/expected-identity.tsv",
    "data/manual-before.stderr", "private/omg-info-before.stdout",
    "installed-before.raw", "omg-info-before.raw", "manual-before.raw",
    "command.json.bak", "private-identity-before.tsv", "client-key", "overlay.qcow2",
)


class AllowlistTests(unittest.TestCase):
    def test_native_query_diagnostics_are_confined_to_guest_evidence(self):
        names = ["native-explicit.txt", "native-explicit.json",
                 "daemon-direct-after-queries.txt", "daemon-foreground-after-queries.txt"]
        names += [f"{label}-{suffix}"
                  for label in ("daemon-direct", "daemon-foreground", "daemon-stopped")
                  for suffix in ("explicit.json", "count.txt", "shortcut.txt", "count.json")]
        names += [f"{label}{suffix}"
                  for label in ("daemon-direct-sigint", "daemon-foreground-sigint")
                  for suffix in (".log", "-status.txt", "-duplicate.txt", "-launcher.txt",
                                 "-after-queries.txt", "-explicit.json", "-count.txt",
                                 "-shortcut.txt", "-count.json")]
        for name in names:
            with self.subTest(name=name):
                self.assertTrue(exporter.allowed_file(("run-test", "guest", "evidence", name)))
                self.assertFalse(exporter.allowed_file(("run-test", name)))
                self.assertFalse(exporter.allowed_file(("run-test", "guest", "evidence", "config", name)))
                self.assertFalse(exporter.allowed_file(("run-test", "guest", "evidence", name + ".bak")))

    def test_transaction_diagnostics_are_allowed_only_at_trial_root(self):
        prefix = ("run-test", "transactions", "trials", "install-omg-001", "transaction-trial")
        for name in TRANSACTION_DIAGNOSTICS:
            with self.subTest(name=name):
                self.assertTrue(exporter.allowed_file((*prefix, name)))
                self.assertFalse(exporter.allowed_file(("run-test", "guest", "evidence", "benchmarks", name)))
                self.assertFalse(exporter.allowed_file((*prefix, "data", name)))
        for name in TRANSACTION_PRIVATE:
            with self.subTest(name=name):
                self.assertFalse(exporter.allowed_file((*prefix, *name.split("/"))))

    def test_known_diagnostics_preserve_report_hierarchy(self):
        for path in ("provenance.json", "run-fixture/results.json", "run-fixture/guest-check.log",
                     "run-fixture/reporting-status.json",
                     "run-fixture/controller-security.log",
                     "run-fixture/controller-pull.log",
                     "run-fixture/guest/evidence/rust-toolchain.txt",
                     "run-fixture/guest/serial.log", "run-fixture/guest/evidence/audit-directory-after.txt",
                     "run-fixture/guest/evidence/benchmarks/summary.json",
                     "run-fixture/guest/evidence/benchmarks/info.commands.json",
                     "run-fixture/guest/evidence/benchmarks/started-at.txt", "run-fixture/cases.tsv",
                     "run-fixture/inventory/results.json", "run-fixture/inventory/rows/search.stdout.log",
                     "run-fixture/transactions/trials/install-omg-1/transaction-trial/install.json"):
            with self.subTest(path=path):
                self.assertTrue(exporter.allowed_file(tuple(path.split("/"))))

    def test_state_and_arbitrary_files_are_excluded(self):
        for path in ("run-fixture/guest/evidence/benchmarks/data/usage.json",
                     "run-fixture/guest/client-key", "run-fixture/guest/overlay.qcow2",
                     "run-fixture/guest/evidence/benchmarks/config.json",
                     "run-fixture/guest/evidence/benchmarks/cache/results.json",
                     "run-fixture/guest/evidence/secret.txt", "run-fixture/unrelated.log",
                     "../results.json"):
            with self.subTest(path=path):
                self.assertFalse(exporter.allowed_file(tuple(path.split("/"))))

@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires POSIX dir_fd support")
class DescriptorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "export"

    def fixture(self, name, content=b"diagnostic"):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def run_export(self, **limits):
        status = exporter.export(str(self.source), str(self.destination), os.getuid(), os.getgid(), **limits)
        report = json.loads((self.destination / "export-report.json").read_text())
        return status, report

    def test_private_state_is_never_opened_and_results_remain_readable(self):
        self.fixture("run-test/results.json", b"[]")
        state = self.fixture("run-test/guest/evidence/benchmarks/data/usage.json", b"private")
        state.chmod(0)
        self.fixture("run-test/guest/evidence/benchmarks/summary.json", b"{}")
        status, report = self.run_export()
        self.assertEqual(status, 0, report)
        self.assertEqual((self.destination / "run-test/results.json").read_bytes(), b"[]")
        self.assertFalse((self.destination / "run-test/guest/evidence/benchmarks/data").exists())
        for path in self.destination.rglob("*"):
            self.assertEqual(path.stat().st_uid, os.getuid())
            self.assertTrue(path.stat().st_mode & stat.S_IRUSR)
        self.assertEqual(state.stat().st_mode & 0o777, 0)

    def test_transaction_diagnostics_export_without_private_or_raw_neighbors(self):
        prefix = "run-test/transactions/trials/install-omg-001/transaction-trial/"
        for name in TRANSACTION_DIAGNOSTICS:
            self.fixture(prefix + name, ("diagnostic:" + name).encode())
        for name in TRANSACTION_PRIVATE:
            self.fixture(prefix + name, b"private-state-must-not-export")
        status, report = self.run_export()
        self.assertEqual(status, 0, report)
        self.assertEqual(set(report["copied"]), {prefix + name for name in TRANSACTION_DIAGNOSTICS})
        for name in TRANSACTION_DIAGNOSTICS:
            self.assertEqual((self.destination / (prefix + name)).read_bytes(),
                             ("diagnostic:" + name).encode())
        for name in TRANSACTION_PRIVATE:
            self.assertFalse((self.destination / (prefix + name)).exists())

    def test_symlink_hardlink_and_fifo_cannot_export_external_bytes(self):
        external = self.root / "private"
        external.write_bytes(b"outside secret")
        run = self.source / "run-test"
        run.mkdir()
        (run / "results.json").symlink_to(external)
        os.link(external, run / "metadata.txt")
        os.mkfifo(run / "guest-check.log")
        (run / "guest").symlink_to(self.root, target_is_directory=True)
        status, report = self.run_export()
        self.assertEqual(status, 1)
        self.assertEqual(report["copied"], [])
        self.assertEqual(len(report["errors"]), 4)
        self.assertEqual(external.read_bytes(), b"outside secret")
        self.assertNotIn("outside secret", (self.destination / "export-report.json").read_text())

    def test_source_ancestor_symlink_and_existing_destination_fail_closed(self):
        alias = self.root / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            exporter.open_directory(str(alias))
        self.destination.mkdir()
        sentinel = self.destination / "keep"
        sentinel.write_text("unchanged")
        with self.assertRaises(FileExistsError):
            self.run_export()
        self.assertEqual(sentinel.read_text(), "unchanged")

    def test_replaced_source_directory_stays_anchored_to_open_descriptor(self):
        self.fixture("run-test/results.json", b"[]")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "results.json").write_bytes(b"outside secret")
        real_open = os.open
        swapped = False

        def swap_after_open(name, flags, *args, **kwargs):
            nonlocal swapped
            fd = real_open(name, flags, *args, **kwargs)
            if name == "run-test" and flags & os.O_NONBLOCK and not swapped:
                swapped = True
                (self.source / "run-test").rename(self.source / "retired")
                (self.source / "run-test").symlink_to(outside, target_is_directory=True)
            return fd

        with patch.object(exporter.os, "open", side_effect=swap_after_open):
            status, report = self.run_export()
        self.assertEqual(status, 0, report)
        self.assertTrue(swapped)
        self.assertEqual((self.destination / "run-test/results.json").read_bytes(), b"[]")
        self.assertEqual((outside / "results.json").read_bytes(), b"outside secret")

    def test_limits_preserve_partial_readable_manifest(self):
        self.fixture("run-test/guest/evidence/benchmarks/summary.json", b"0123456789")
        status, report = self.run_export(max_file=4)
        self.assertEqual(status, 1)
        self.assertEqual(report["bytes"], 0)
        self.assertFalse((self.destination / "run-test/guest/evidence/benchmarks/summary.json").exists())
        self.assertIn("budget", report["errors"][0]["error"])

    def test_total_and_entry_budgets(self):
        self.fixture("run-test/results.json", b"[]")
        self.fixture("run-test/metadata.txt", b"metadata")
        status, report = self.run_export(max_total=1, max_entries=2)
        self.assertEqual(status, 1)
        self.assertEqual(report["bytes"], 0)
        self.assertTrue(any("budget" in item["error"] for item in report["errors"]))

    @unittest.skipUnless(os.name == "posix" and os.environ.get("SUDO_UID"), "requires sudo fixture run")
    def test_root_owned_diagnostics_export_for_runner_without_changing_source(self):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
        log = self.fixture("run-test/guest/evidence/audit-directory-after.txt")
        log.chmod(0o600)
        self.assertEqual(log.stat().st_uid, 0)
        status = exporter.export(str(self.source), str(self.destination), uid, gid)
        self.assertEqual(status, 0)
        copied = self.destination / "run-test/guest/evidence/audit-directory-after.txt"
        self.assertEqual(copied.stat().st_uid, uid)
        self.assertEqual(copied.stat().st_gid, gid)
        self.assertEqual(copied.read_bytes(), b"diagnostic")
        self.assertEqual(log.stat().st_uid, 0)
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

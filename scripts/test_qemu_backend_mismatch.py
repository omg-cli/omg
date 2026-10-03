"""The negative QEMU gate must not admit incomplete or unchanged-only receipts."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "qemu_backend_mismatch", Path(__file__).with_name("qemu-backend-mismatch.py"))
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class BackendMismatchReceiptTests(unittest.TestCase):
    def test_trixie_mismatch_preserves_guest_identity_and_detects_apt_access(self):
        receipt = dict(self.receipt(), distro='debian-trixie')
        PROBE.validate_receipt(receipt, 'debian-trixie')
        for line in ('openat(AT_FDCWD, "/var/lib/dpkg/status", O_RDONLY) = 3',
                     'execve("/usr/bin/apt-get", ["apt-get"], 0x0) = 0'):
            with self.subTest(line=line):
                self.assertTrue(PROBE.native_db_access(line, 'debian-trixie'))
        with self.assertRaises(ValueError):
            PROBE.validate_receipt(dict(receipt, distro='debian'), 'debian-trixie')

    def test_probe_inventory_keeps_all_backend_entrypoints(self):
        self.assertEqual(tuple(name for name, _ in PROBE.PROBES), (
            "doctor", "info", "search", "status", "explicit_count",
            "install_dry_run", "remove_dry_run", "update_check", "clean_dry_run",
            "dash", "omgd"))

    def receipt(self):
        value = {"schema_version": 1, "distro": "arch", "fixture_distro": "fedora",
                 "complete": True, "failure_kind": "none", "db_before": "a" * 64,
                 "db_after": "a" * 64, "omgd_state_created": False}
        for command, _ in PROBE.PROBES:
            value[f"{command}_exit"] = 1
            value[f"{command}_mismatch"] = True
            value[f"{command}_native_db_access"] = False
        return value

    def test_only_complete_refusals_with_stable_database_pass(self):
        PROBE.validate_receipt(self.receipt(), "arch")
        for change in ({"doctor_mismatch": False}, {"info_exit": 0},
                       {"omgd_mismatch": False}, {"omgd_state_created": True},
                       {"db_after": "b" * 64}, {"db_before": None},
                       {"complete": False}, {"failure_kind": "harness"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                PROBE.validate_receipt(dict(self.receipt(), **change), "arch")

    def test_native_access_by_any_command_rejects_otherwise_passing_receipt(self):
        for command, _ in PROBE.PROBES:
            with self.subTest(command=command), self.assertRaises(ValueError):
                PROBE.validate_receipt(
                    dict(self.receipt(), **{f"{command}_native_db_access": True}), "arch")
            with self.subTest(command=command, missing=True), self.assertRaises(ValueError):
                receipt = self.receipt()
                del receipt[f"{command}_native_db_access"]
                PROBE.validate_receipt(receipt, "arch")

    def test_each_command_must_report_actionable_backend_mismatch(self):
        for command, _ in PROBE.PROBES:
            with self.subTest(command=command), self.assertRaises(ValueError):
                PROBE.validate_receipt(
                    dict(self.receipt(), **{f"{command}_mismatch": False}), "arch")

    def test_trace_detects_native_database_or_tool_use_for_every_distro(self):
        paths = {"arch": "/var/lib/pacman/local/bash-5", "debian": "/var/lib/dpkg/status",
                 "ubuntu": "/var/lib/apt/extended_states", "fedora": "/usr/lib/sysimage/rpm/rpmdb.sqlite"}
        tools = {"arch": "pacman", "debian": "dpkg-query", "ubuntu": "apt-cache",
                 "fedora": "dnf5"}
        paths['debian-trixie'] = '/var/lib/dpkg/status'
        tools['debian-trixie'] = 'dpkg-query'
        for distro in PROBE.DATABASE_PATHS:
            with self.subTest(distro=distro):
                self.assertTrue(PROBE.native_db_access(
                    f'openat(AT_FDCWD, "{paths[distro]}", O_RDONLY) = 3', distro))
                self.assertTrue(PROBE.native_db_access(
                    f'execve("/usr/bin/{tools[distro]}", ["{tools[distro]}"], 0x0) = 0', distro))
                self.assertFalse(PROBE.native_db_access(
                    'openat(AT_FDCWD, "/etc/os-release", O_RDONLY) = 3', distro))

    def test_repository_and_config_reads_reject_otherwise_passing_receipts(self):
        paths = {
            "arch": ("/var/lib/pacman/sync/core.db", "/etc/pacman.conf"),
            "debian": ("/var/lib/apt/lists/mirror_Packages", "/etc/apt/sources.list"),
            "ubuntu": ("/var/lib/apt/lists/mirror_Packages.lz4", "/etc/apt/apt.conf.d/fixture"),
            "fedora": ("/var/lib/dnf/history.sqlite", "/etc/yum.repos.d/fixture.repo"),
        }
        for distro, roots in paths.items():
            for path in roots:
                with self.subTest(distro=distro, path=path):
                    access = PROBE.native_db_access(
                        f'openat(AT_FDCWD, "{path}", O_RDONLY) = 3', distro)
                    self.assertTrue(access)
                    receipt = dict(self.receipt(), distro=distro,
                                   fixture_distro=PROBE.FAKE_ID[distro],
                                   update_check_native_db_access=access)
                    with self.assertRaises(ValueError):
                        PROBE.validate_receipt(receipt, distro)

    def test_relative_repository_reads_include_directory_descriptor_identity(self):
        self.assertTrue(PROBE.native_db_access(
            'openat(3</var/lib/pacman/sync>, "core.db", O_RDONLY) = 4', "arch"))
        self.assertTrue(PROBE.native_db_access(
            'openat(3</var/lib/apt/lists>, "mirror_Packages", O_RDONLY) = 4', "debian"))

    def test_fingerprints_include_repository_and_configuration_roots(self):
        for distro in ("debian", "ubuntu"):
            self.assertIn("/var/lib/apt", PROBE.DATABASE_PATHS[distro])
            self.assertIn("/etc/apt", PROBE.DATABASE_PATHS[distro])
        self.assertIn("/var/lib/pacman", PROBE.DATABASE_PATHS["arch"])
        self.assertIn("/etc/pacman.conf", PROBE.DATABASE_PATHS["arch"])
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "sync"
            repository.mkdir()
            config = Path(directory) / "pacman.conf"
            config.write_text("original")
            with patch.dict(PROBE.DATABASE_PATHS, {"arch": (str(repository), str(config))}):
                before = PROBE.database_snapshot("arch")
                (repository / "core.db").write_text("new index")
                self.assertNotEqual(before, PROBE.database_snapshot("arch"))
                before = PROBE.database_snapshot("arch")
                config.write_text("changed configuration")
                self.assertNotEqual(before, PROBE.database_snapshot("arch"))

    def test_package_database_snapshot_detects_content_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "local"
            database.mkdir()
            package = database / "installed"
            package.write_text("version=1")
            with patch.dict(PROBE.DATABASE_PATHS, {"arch": (str(database),)}):
                before = PROBE.database_snapshot("arch")
                package.write_text("version=2")
                self.assertNotEqual(before, PROBE.database_snapshot("arch"))

    def test_package_database_snapshot_detects_empty_directory_addition(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "local"
            database.mkdir()
            with patch.dict(PROBE.DATABASE_PATHS, {"arch": (str(database),)}):
                before = PROBE.database_snapshot("arch")
                (database / "new-package").mkdir()
                self.assertNotEqual(before, PROBE.database_snapshot("arch"))


if __name__ == "__main__":
    unittest.main()

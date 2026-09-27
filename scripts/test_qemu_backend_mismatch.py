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
    def receipt(self):
        value = {"schema_version": 1, "distro": "arch", "fixture_distro": "fedora",
                 "complete": True, "failure_kind": "none", "db_before": "a" * 64,
                 "db_after": "a" * 64, "info_native_db_access": False}
        for command in ("doctor", "info", "omgd"):
            value[f"{command}_exit"] = 1
            value[f"{command}_mismatch"] = True
        return value

    def test_only_complete_refusals_with_stable_database_pass(self):
        PROBE.validate_receipt(self.receipt(), "arch")
        for change in ({"doctor_mismatch": False}, {"info_exit": 0},
                       {"omgd_mismatch": False}, {"info_native_db_access": True},
                       {"db_after": "b" * 64}, {"db_before": None},
                       {"complete": False}, {"failure_kind": "harness"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                PROBE.validate_receipt(dict(self.receipt(), **change), "arch")

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

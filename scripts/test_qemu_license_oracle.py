"""Reject success-shaped but false Arch license inventory evidence."""

import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace


SOURCE = Path(__file__).with_name("qemu-license-oracle.py")
SPEC = importlib.util.spec_from_file_location("qemu_license_oracle", SOURCE)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class LicenseOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "local"
        self.db.mkdir()
        self.add_package("alpha", "1.0-1", ["MIT"])
        self.add_package("beta", "2.0-2", ["GPL-3.0-only", "Apache-2.0"])
        self.add_package("gamma", "3.0-1", [])
        self.pacman = "alpha 1.0-1\nbeta 2.0-2\ngamma 3.0-1\n"
        self.output = self.root / "report"

    def add_package(self, name, version, licenses):
        directory = self.db / f"{name}-{version}"
        directory.mkdir()
        fields = f"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n"
        if licenses:
            fields += "%LICENSE%\n" + "\n".join(licenses) + "\n\n"
        (directory / "desc").write_text(fields, encoding="utf-8")

    def native(self):
        with patch.object(ORACLE.subprocess, "run",
                          return_value=SimpleNamespace(stdout=self.pacman)) as run:
            packages = ORACLE.native_packages(self.db)
        self.assertEqual(run.call_args.args[0], ["pacman", "-Q"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30)
        self.assertEqual(run.call_args.kwargs["env"]["LC_ALL"], "C")
        return packages

    def audit_rows(self):
        return [
            {"name": "alpha", "version": "1.0-1", "license": "MIT", "category": "Permissive"},
            {"name": "beta", "version": "2.0-2", "license": "GPL-3.0-only, Apache-2.0",
             "category": "Copyleft"},
            {"name": "gamma", "version": "3.0-1", "license": "Unknown", "category": "Unknown"},
        ]

    def test_wrong_or_incomplete_audit_json_is_rejected(self):
        native = self.native()
        self.output.write_text(json.dumps(self.audit_rows()), encoding="utf-8")
        ORACLE.check("audit-json", self.output, native)
        for bad in (
            self.audit_rows()[:-1],
            [dict(row, version="9.0") if row["name"] == "beta" else row
             for row in self.audit_rows()],
            [dict(row, license="MIT") if row["name"] == "beta" else row
             for row in self.audit_rows()],
            self.audit_rows() + [self.audit_rows()[0]],
        ):
            self.output.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(AssertionError):
                ORACLE.check("audit-json", self.output, native)
        wrong_categories = [dict(row, category="Permissive") for row in self.audit_rows()]
        self.output.write_text(json.dumps(wrong_categories), encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("audit-json", self.output, native)
        duplicated = json.dumps(self.audit_rows()).replace(
            '"name": "alpha"', '"name": "alpha", "name": "alpha"', 1)
        self.output.write_text(duplicated, encoding="utf-8")
        with self.assertRaises((AssertionError, ValueError)):
            ORACLE.check("audit-json", self.output, native)

    def test_mit_filter_and_csv_export_are_native_bound(self):
        native = self.native()
        stderr = self.root / "stderr"
        stderr.write_text("Error: License policy check found 3 violation(s)\n", encoding="utf-8")
        self.output.write_text(json.dumps([self.audit_rows()[0]]), encoding="utf-8")
        ORACLE.check("audit-mit-json", self.output, native, stderr)
        self.output.write_text(json.dumps(self.audit_rows()), encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("audit-mit-json", self.output, native, stderr)
        self.output.write_text(json.dumps([self.audit_rows()[0]]), encoding="utf-8")
        ORACLE.check("audit-mit-json", self.output, native, stderr)
        stderr.write_text("Error: License policy check found 2 violation(s)\n", encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("audit-mit-json", self.output, native, stderr)

        with self.output.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["Package", "Version", "License", "Category"])
            for row in self.audit_rows():
                writer.writerow([row[k] for k in ("name", "version", "license", "category")])
        self.output.chmod(0o600)
        ORACLE.check("audit-csv", self.output, native)
        self.output.write_text("Package,Version,License,Category\nalpha,1.0-1,MIT,Permissive\n",
                               encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("audit-csv", self.output, native)
        # Spreadsheet-neutralized output is still the correct native license.
        native = dict(native, delta=("1.0-1", ["=HYPERLINK(\"https://example.invalid\")"]))
        with self.output.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["Package", "Version", "License", "Category"])
            for row in self.audit_rows():
                writer.writerow([row[k] for k in ("name", "version", "license", "category")])
            writer.writerow(["delta", "1.0-1", "'=HYPERLINK(\"https://example.invalid\")",
                             "Unknown"])
        self.output.chmod(0o600)
        ORACLE.check("audit-csv", self.output, native)

    def test_enterprise_json_checks_assignments_unknowns_and_violations(self):
        native = self.native()
        report = {"total": 3,
                  "by_license": {"MIT": 1, "GPL-3.0-only": 1, "Apache-2.0": 1},
                  "unknown": ["gamma"],
                  "violations": [{"package": "beta", "license": "GPL-3.0-only",
                                  "reason": "Copyleft license requires legal review"}]}
        self.output.write_text(json.dumps(report), encoding="utf-8")
        self.output.chmod(0o600)
        ORACLE.check("enterprise-json", self.output, native)
        for bad in (dict(report, total=0), dict(report, unknown=[]),
                    dict(report, by_license={"MIT": 3}), dict(report, violations=[]),
                    dict(report, by_license={"MIT": True, "GPL-3.0-only": 1,
                                             "Apache-2.0": 1})):
            self.output.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaises(AssertionError):
                ORACLE.check("enterprise-json", self.output, native)
        duplicated = json.dumps(report).replace('"total": 3', '"total": 3, "total": 3', 1)
        self.output.write_text(duplicated, encoding="utf-8")
        with self.assertRaises((AssertionError, ValueError)):
            ORACLE.check("enterprise-json", self.output, native)

    def test_native_database_rejects_malformed_duplicate_and_pacman_disagreement(self):
        self.native()
        gamma = self.db / "gamma-3.0-1" / "desc"
        original = gamma.read_text(encoding="utf-8")
        gamma.write_text("%NAME%\ngamma\n\n", encoding="utf-8")
        with self.assertRaises(AssertionError):
            self.native()
        gamma.write_text(original, encoding="utf-8")
        self.add_package("gamma", "9.0-1", ["MIT"])
        with self.assertRaises(AssertionError):
            self.native()
        (self.db / "gamma-9.0-1" / "desc").unlink()
        (self.db / "gamma-9.0-1").rmdir()
        self.pacman = "alpha 1.0-1\nbeta 2.0-2\ngamma 8.0-1\n"
        with self.assertRaises(AssertionError):
            self.native()

    def test_enterprise_text_requires_real_summary(self):
        native = self.native()
        self.output.write_text("[License Compliance Scan] 3 total packages\n"
                               "License Inventory\n│ Apache-2.0: 1 assignments (33%)\n"
                               "│ GPL-3.0-only: 1 assignments (33%)\n"
                               "│ MIT: 1 assignments (33%)\n",
                               encoding="utf-8")
        ORACLE.check("enterprise-text", self.output, native)
        self.output.write_text("[License Compliance Scan] 13 total packages\n"
                               "License Inventory\n│ Apache-2.0: 1 assignments (33%)\n",
                               encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("enterprise-text", self.output, native)
        self.output.write_text("[License Compliance Scan] 3 total packages\n"
                               "License Inventory\n│ Apache-2.0: 1 assignments (33%)\n"
                               "│ GPL-3.0-only: 1 assignments (33%)\n"
                               "│ MIT: 1 assignments (33%)\n"
                               "│ MIT: 1 assignments (33%)\n", encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("enterprise-text", self.output, native)
        self.output.write_text("[License Compliance Scan] 3 total packages\nLicense Inventory\n",
                               encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("enterprise-text", self.output, native)

    def test_enterprise_text_sorts_formatted_prefix_license_rows(self):
        native = dict(self.native(), delta=("1.0-1", ["Apache-2.0 OR MIT"]))
        self.output.write_text("[License Compliance Scan] 4 total packages\n"
                               "License Inventory\n"
                               "│ Apache-2.0 OR MIT: 1 assignments (25%)\n"
                               "│ Apache-2.0: 1 assignments (25%)\n"
                               "│ GPL-3.0-only: 1 assignments (25%)\n"
                               "│ MIT: 1 assignments (25%)\n", encoding="utf-8")
        ORACLE.check("enterprise-text", self.output, native)
        self.output.write_text(self.output.read_text(encoding="utf-8").replace(
            "│ Apache-2.0 OR MIT: 1 assignments (25%)\n"
            "│ Apache-2.0: 1 assignments (25%)",
            "│ Apache-2.0: 1 assignments (25%)\n"
            "│ Apache-2.0 OR MIT: 1 assignments (25%)"), encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("enterprise-text", self.output, native)

    def test_symlink_and_world_readable_exports_are_rejected(self):
        native = self.native()
        target = self.root / "target.json"
        target.write_text(json.dumps(self.audit_rows()), encoding="utf-8")
        self.output.symlink_to(target)
        with self.assertRaises(AssertionError):
            ORACLE.check("audit-json", self.output, native)
        self.output.unlink()
        self.output.write_text("Package,Version,License,Category\n", encoding="utf-8")
        self.output.chmod(0o644)
        with self.assertRaises(AssertionError):
            ORACLE.check("audit-csv", self.output, native)


if __name__ == "__main__":
    unittest.main()

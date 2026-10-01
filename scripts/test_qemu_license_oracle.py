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
                               "│ MIT: 1 assignments (33%)\n"
                               "Policy Violations\n│ beta - Copyleft license requires legal review\n"
                               "Unknown Licenses\n│ gamma\n",
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
                               "│ MIT: 1 assignments (25%)\n"
                               "Policy Violations\n│ beta - Copyleft license requires legal review\n"
                               "Unknown Licenses\n│ gamma\n", encoding="utf-8")
        ORACLE.check("enterprise-text", self.output, native)
        self.output.write_text(self.output.read_text(encoding="utf-8").replace(
            "│ Apache-2.0 OR MIT: 1 assignments (25%)\n"
            "│ Apache-2.0: 1 assignments (25%)",
            "│ Apache-2.0: 1 assignments (25%)\n"
            "│ Apache-2.0 OR MIT: 1 assignments (25%)"), encoding="utf-8")
        with self.assertRaises(AssertionError):
            ORACLE.check("enterprise-text", self.output, native)

    def test_advisory_identifier_literals_case_and_plus_boundaries(self):
        # Expectations are literal families, not read from Rust or OMG reports.
        families = {
            "StrongCopyleft": "AGPL AGPL1 AGPL3 AGPL-1.0 AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later".split(),
            "Copyleft": "GPL GPL1 GPL2 GPL3 LGPL LGPL2 LGPL3 LGPL2.1 GPL-1.0 GPL-1.0-only GPL-1.0-or-later GPL-2.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0 GPL-3.0-only GPL-3.0-or-later LGPL-2.0 LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later MPL MPL-1.0 MPL-1.1 MPL-2.0 MPL-2.0-no-copyleft-exception".split(),
            "Permissive": "MIT MIT-0 ISC Unlicense CC0 CC0-1.0 0BSD BSD BSD-2-Clause BSD-3-Clause BSD-4-Clause Apache Apache-1.0 Apache-1.1 Apache-2.0".split(),
            "Proprietary": ["Proprietary", "Commercial"],
        }
        for category, identifiers in families.items():
            for identifier in identifiers:
                for spelling in (identifier, identifier.lower(), identifier.upper()):
                    with self.subTest(identifier=spelling):
                        self.assertEqual(ORACLE.advisory_category(spelling), category)
                        self.assertEqual(ORACLE.advisory_category(spelling + "+"), category)
                        self.assertEqual(ORACLE.advisory_category(spelling + "++"), "Unknown")
                        self.assertEqual(ORACLE.advisory_category(spelling + "-custom"), "Unknown")
        for identifier in ("Apache-custom", "BSD-custom", "LicenseRef-GPL", "LicenseRef-Proprietary",
                           "GPL4", "AGPL2", "LGPL2.0", "SSPL-1.0", "BUSL-1.1", "Elastic-2.0"):
            self.assertEqual(ORACLE.advisory_category(identifier), "Unknown")

    def test_mixed_references_with_base_and_native_assignment_join(self):
        for reference in ("LicenseRef-private", "DocumentRef-x.1:LicenseRef-private"):
            self.assertEqual(ORACLE.advisory_category(reference), "Unknown")
            for operator in ("AND", "OR"):
                self.assertEqual(ORACLE.advisory_category(f"{reference} {operator} GPL2"), "Copyleft")
                self.assertEqual(ORACLE.advisory_category(f"MIT {operator} {reference}"), "Permissive")
                self.assertEqual(ORACLE.advisory_category(f"{reference} {operator} AGPL3+"), "StrongCopyleft")
        self.assertEqual(ORACLE.advisory_category("MIT WITH AGPL-3.0"), "Permissive")
        self.assertEqual(ORACLE.advisory_category("GPL2 WITH LicenseRef-exception"), "Copyleft")
        self.assertEqual(ORACLE.known_category(["GPL2", "LGPL3"]), "Copyleft")
        self.assertEqual(ORACLE.advisory_category("GPL2, LGPL3"), "Unknown")
        packages = {"libidn2": ("2.3.8-1", ["GPL2", "LGPL3"])}
        ORACLE.compare_audit_rows([{"name": "libidn2", "version": "2.3.8-1",
                                    "license": "GPL2, LGPL3", "category": "Copyleft"}],
                                  ORACLE.expected_audit(packages))
        counts, unknown, violations = ORACLE.expected_enterprise(packages)
        self.assertEqual(dict(counts), {"GPL2": 1, "LGPL3": 1})
        self.assertEqual(unknown, [])
        self.assertEqual(violations, [("libidn2", "GPL2", "Copyleft license requires legal review"),
                                      ("libidn2", "LGPL3", "Copyleft license requires legal review")])

    def test_expression_admission_bounds_and_malformed_inputs(self):
        for expression in ("MIT" + " " * 4093, " ".join(["MIT"] * 256), "(" * 32 + "MIT" + ")" * 32):
            self.assertEqual(ORACLE.advisory_category(expression), "Permissive")
        for expression in ("MIT" + " " * 4094, " ".join(["MIT"] * 257),
                           "(" * 33 + "MIT" + ")" * 33, " OR ".join(["MIT"] * 100_000),
                           "MIT!", "MIT & GPL2", "MIT/GPL2", "MIT:GPL2", "M+IT", "MIT++",
                           "DocumentRef-:LicenseRef-x OR MIT", "DocumentRef-x:LicenseRef- OR MIT",
                           "DocumentRef-x:LicenseRef-y:z OR MIT", "MIT OR", "MIT WITH",
                           "MIT WITH OR GPL2", "((MIT)", "MIT)", "MÍT"):
            self.assertEqual(ORACLE.advisory_category(expression), "Unknown")

    def test_enterprise_text_rejects_missing_extra_duplicate_and_wrong_percentages(self):
        packages = self.native()
        correct = ("[License Compliance Scan] 3 total packages\nLicense Inventory\n"
                   "│ Apache-2.0: 1 assignments (33%)\n│ GPL-3.0-only: 1 assignments (33%)\n"
                   "│ MIT: 1 assignments (33%)\nPolicy Violations\n"
                   "│ beta - Copyleft license requires legal review\nUnknown Licenses\n│ gamma\n")
        ORACLE.check_enterprise_text(correct, packages)
        bad_reports = [
            correct.replace("(33%)", "(999%)"),
            correct.replace("(33%)", "(34%)", 1),
            correct.replace("Policy Violations\n│ beta - Copyleft license requires legal review\n", ""),
            correct.replace("Unknown Licenses\n│ gamma\n", ""),
            correct.replace("│ beta - Copyleft license requires legal review", "│ beta - Copyleft license (GPL) requires legal review"),
            correct.replace("│ beta - Copyleft license requires legal review", "│ beta - Copyleft license requires legal review\n│ beta - Copyleft license requires legal review"),
            correct.replace("│ gamma", "│ alpha"),
            correct.replace("│ gamma", "│ gamma\n│ gamma"),
            correct.replace("│ gamma", "│ gamma\n│ invented"),
            correct + "Unknown Licenses\n│ gamma\n",
            correct + "│ ... and 1 more\n",
        ]
        for report in bad_reports:
            with self.subTest(report=report), self.assertRaises(AssertionError):
                ORACLE.check_enterprise_text(report, packages)
        # Actual table decorations must not change the semantic checks.
        boxed = correct.replace("License Inventory\n", "╭──────────────────╮\n│ License Inventory │\n├──────────────────┤\n")
        ORACLE.check_enterprise_text(boxed, packages)

    def test_enterprise_text_validates_renderer_limits_and_truncation(self):
        packages = {f"p{i:02}": ("1", ["GPL2" if i % 2 else "GPL3"]) for i in range(23)}
        packages.update({f"unknown{i}": ("1", []) for i in range(7)})
        correct = ("[License Compliance Scan] 30 total packages\nLicense Inventory\n"
                   "│ GPL2: 11 assignments (48%)\n│ GPL3: 12 assignments (52%)\n"
                   "Policy Violations\n" + "".join(f"│ p{i:02} - Copyleft license requires legal review\n" for i in range(20))
                   + "│ ... and 3 more\nUnknown Licenses\n"
                   + "".join(f"│ unknown{i}\n" for i in range(5)) + "│ ... and 2 more\n")
        ORACLE.check_enterprise_text(correct, packages)
        for bad in (correct.replace("... and 3 more", "... and 2 more"),
                    correct.replace("... and 2 more", "... and 3 more"),
                    correct.replace("│ ... and 3 more\n", ""),
                    correct.replace("│ p00 -", "│ invented -"),
                    correct.replace("│ unknown0\n", "│ unknown1\n")):
            with self.assertRaises(AssertionError):
                ORACLE.check_enterprise_text(bad, packages)
        many = {f"p{i:02}": ("1", [f"LicenseRef-{i:02}"]) for i in range(23)}
        inventory = ("[License Compliance Scan] 23 total packages\nLicense Inventory\n"
                     + "".join(f"│ LicenseRef-{i:02}: 1 assignments (4%)\n" for i in range(20))
                     + "│ ... and 3 more\n")
        ORACLE.check_enterprise_text(inventory, many)
        with self.assertRaises(AssertionError):
            ORACLE.check_enterprise_text(inventory.replace("... and 3 more", "... and 2 more"), many)
        self.assertEqual(ORACLE.assignment_percentage(1, 8), "12")
        self.assertEqual(ORACLE.assignment_percentage(3, 8), "38")
        self.assertEqual(ORACLE.assignment_percentage(1, 3), "33")
        self.assertEqual(ORACLE.assignment_percentage(2, 3), "67")

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

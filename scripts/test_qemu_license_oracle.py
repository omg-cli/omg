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

    def test_independent_spdx_families_and_native_aliases(self):
        # SPDX IDs are not arbitrary strings containing a family name.
        # Legacy native spellings are family aliases, not claims about
        # whether a package's license is "only" or "or later".
        families = {
            "Copyleft": {
                "GPL", "GPL1", "GPL2", "GPL3", "LGPL", "LGPL2", "LGPL2.1",
                "LGPL3", "MPL", "MPL-1.0", "MPL-1.1", "MPL-2.0",
                "MPL-2.0-no-copyleft-exception",
                "GPL-1.0", "GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
            },
            "StrongCopyleft": {"AGPL", "AGPL1", "AGPL3", "AGPL-1.0", "AGPL-3.0"},
        }
        for category, identifiers in families.items():
            for identifier in identifiers:
                with self.subTest(identifier=identifier):
                    self.assertEqual(ORACLE.known_category([identifier]), category)
                    self.assertEqual(ORACLE.known_category([identifier.lower()]), category)
        for base in ("GPL-1.0", "GPL-2.0", "GPL-3.0", "LGPL-2.0", "LGPL-2.1",
                     "LGPL-3.0", "AGPL-1.0", "AGPL-3.0"):
            category = "StrongCopyleft" if base.startswith("AGPL") else "Copyleft"
            for suffix in ("-only", "-or-later", "+"):
                with self.subTest(identifier=base + suffix):
                    self.assertEqual(ORACLE.known_category([base + suffix]), category)
        self.assertEqual(ORACLE.known_category(
            ["MIT OR (LGPL2.1 AND AGPL-3.0-only)"]), "StrongCopyleft")
        self.assertEqual(ORACLE.known_category(
            ["GPL-2.0-only WITH Linux-syscall-note OR MIT"]), "Copyleft")

    def test_custom_references_and_substrings_are_not_family_identifiers(self):
        for value in ("LicenseRef-Example", "LicenseRef-GPL-2.0-only",
                      "DocumentRef-GPL:LicenseRef-MPL-2.0", "custom:GPL",
                      "NotGPL", "GPLish", "example", "AGPL-99.0", "GPL-2.0-fake",
                      "MPL-2.0-made-up", "MIT WITH GPL-2.0-only"):
            with self.subTest(value=value):
                self.assertIsNone(ORACLE.known_category([value]))
                self.assertEqual(ORACLE.expected_enterprise(
                    {"custom": ("1", [value])})[2], [])
        self.assertEqual(ORACLE.known_category(
            ["LicenseRef-GPL OR AGPL-3.0-only"]), "StrongCopyleft")

    def test_enterprise_family_presence_is_not_substring_matching(self):
        packages = {
            "network": ("1", ["MIT OR AGPL-3.0-only"]),
            "library": ("1", ["LGPL2.1"]),
            "custom": ("1", ["LicenseRef-Example", "DocumentRef-GPL:LicenseRef-MPL"]),
            "source-available": ("1", ["SSPL-1.0", "BUSL-1.1"]),
        }
        self.assertEqual(ORACLE.expected_enterprise(packages)[2], [
            ("library", "LGPL2.1", "Copyleft license requires legal review"),
            ("network", "MIT OR AGPL-3.0-only",
             "Strong copyleft license (AGPL) requires legal review"),
        ])

    def test_advisory_single_plus_and_compact_alias_categories(self):
        # Independent literals for the parent's thirteen parity counterexamples.
        # These are advisory family spellings, not canonical SPDX/legal claims.
        for license_value, expected in (
            ("GPL+", "Copyleft"), ("LGPL+", "Copyleft"),
            ("AGPL+", "StrongCopyleft"), ("MPL+", "Copyleft"),
            ("GPL2+", "Copyleft"), ("GPL3+", "Copyleft"),
            ("LGPL2.1+", "Copyleft"), ("MPL-2.0+", "Copyleft"),
            ("GPL1", "Copyleft"), ("LGPL2", "Copyleft"),
            ("LGPL3", "Copyleft"), ("AGPL1", "StrongCopyleft"),
            ("AGPL3", "StrongCopyleft"),
        ):
            with self.subTest(license_value=license_value):
                self.assertEqual(ORACLE.known_category([license_value]), expected)
                self.assertEqual(ORACLE.known_category([license_value.lower()]), expected)
        self.assertEqual(ORACLE.known_category(["MIT OR GPL2+"]), "Copyleft")
        self.assertEqual(ORACLE.known_category(["GPL+ AND AGPL+"]), "StrongCopyleft")
        self.assertEqual(ORACLE.known_category(
            ["LGPL2.1+ WITH AGPL+"]), "Copyleft")

    def test_advisory_plus_does_not_accept_unknown_or_exception_atoms(self):
        for license_value in (
            "GPL++", "LGPL++", "AGPL++", "MPL++", "GPL2++", "GPL3++",
            "LGPL2.1++", "MPL-2.0++", "GPL-2.0++", "AGPL-3.0-only++",
            "GPL-extra+", "GPL2-extra+", "LGPL2.1-made-up+", "MPL-2.0-fake+",
            "AGPL-99.0+", "LicenseRef-GPL+", "LicenseRef-AGPL3+",
            "LicenseRef-MPL-2.0+", "DocumentRef-GPL:LicenseRef-LGPL2.1+",
            "custom:GPL+", "NotGPL+", "GPLish+", "GPL+extra",
            "MIT WITH GPL+", "MIT WITH AGPL+", "MIT WITH LGPL2.1+",
            "MIT WITH MPL-2.0+",
        ):
            with self.subTest(license_value=license_value):
                self.assertIsNone(ORACLE.known_category([license_value]))
                self.assertEqual(ORACLE.expected_enterprise(
                    {"negative": ("1", [license_value])})[2], [])
        self.assertEqual(ORACLE.known_category(
            ["LicenseRef-GPL+ OR MPL+"]), "Copyleft")

    def test_parity_spellings_require_exact_enterprise_reviews(self):
        packages = {
            "a": ("1", ["GPL+"]), "b": ("1", ["LGPL+"]),
            "c": ("1", ["AGPL+"]), "d": ("1", ["MPL+"]),
            "e": ("1", ["GPL2+"]), "f": ("1", ["GPL3+"]),
            "g": ("1", ["LGPL2.1+"]), "h": ("1", ["MPL-2.0+"]),
            "i": ("1", ["GPL1"]), "j": ("1", ["LGPL2"]),
            "k": ("1", ["LGPL3"]), "l": ("1", ["AGPL1"]),
            "m": ("1", ["AGPL3"]), "negative": ("1", ["LicenseRef-GPL+"]),
        }
        expected = [
            ("a", "GPL+", "Copyleft license requires legal review"),
            ("b", "LGPL+", "Copyleft license requires legal review"),
            ("c", "AGPL+", "Strong copyleft license (AGPL) requires legal review"),
            ("d", "MPL+", "Copyleft license requires legal review"),
            ("e", "GPL2+", "Copyleft license requires legal review"),
            ("f", "GPL3+", "Copyleft license requires legal review"),
            ("g", "LGPL2.1+", "Copyleft license requires legal review"),
            ("h", "MPL-2.0+", "Copyleft license requires legal review"),
            ("i", "GPL1", "Copyleft license requires legal review"),
            ("j", "LGPL2", "Copyleft license requires legal review"),
            ("k", "LGPL3", "Copyleft license requires legal review"),
            ("l", "AGPL1", "Strong copyleft license (AGPL) requires legal review"),
            ("m", "AGPL3", "Strong copyleft license (AGPL) requires legal review"),
        ]
        self.assertEqual(ORACLE.expected_enterprise(packages)[2], expected)
        # Export expectations are literal, never taken from oracle output.
        report = {"total": 14, "unknown": [], "by_license": {
            "GPL+": 1, "LGPL+": 1, "AGPL+": 1, "MPL+": 1,
            "GPL2+": 1, "GPL3+": 1, "LGPL2.1+": 1, "MPL-2.0+": 1,
            "GPL1": 1, "LGPL2": 1, "LGPL3": 1, "AGPL1": 1, "AGPL3": 1,
            "LicenseRef-GPL+": 1,
        }, "violations": [dict(package=name, license=value, reason=reason)
                          for name, value, reason in expected]}
        self.output.write_text(json.dumps(report), encoding="utf-8")
        self.output.chmod(0o600)
        ORACLE.check("enterprise-json", self.output, packages)
        for bad_rows in (
            report["violations"][1:],  # missing specifically a new plus review
            report["violations"] + [report["violations"][0]],
            report["violations"] + [{"package": "negative", "license": "LicenseRef-GPL+",
                                     "reason": "Copyleft license requires legal review"}],
        ):
            self.output.write_text(json.dumps(dict(report, violations=bad_rows)),
                                   encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "enterprise violations differ"):
                ORACLE.check("enterprise-json", self.output, packages)

    def test_retained_native_rows_have_an_exact_independent_violation_set(self):
        # Literal assignments transcribed from retained run 36605828415:
        # pr-702/qemu-arch/run-0KNsr4/inventory/rows/audit-licenses.stdout.log.
        # Categories from that product report are deliberately NOT used.
        packages = {
            "gptfdisk": ("1.0.10-2", ["GPL2"]),
            "grep": ("3.12-2", ["GPL3"]),
            "make": ("4.4.1-3", ["GPL3"]),
            "libmnl": ("1.0.5-2", ["LGPL2.1"]),
            "libidn2": ("2.3.8-1", ["GPL2", "LGPL3"]),
            "ca-certificates-mozilla": ("3.130-1", ["MPL-2.0"]),
            "libpsl": ("0.21.5-2", ["MIT"]),
        }
        reason = "Copyleft license requires legal review"
        expected = sorted([
            ("gptfdisk", "GPL2", reason), ("grep", "GPL3", reason),
            ("make", "GPL3", reason), ("libmnl", "LGPL2.1", reason),
            ("libidn2", "GPL2", reason), ("libidn2", "LGPL3", reason),
            ("ca-certificates-mozilla", "MPL-2.0", reason),
        ])
        counts, unknown, violations = ORACLE.expected_enterprise(packages)
        self.assertEqual(dict(counts),
                         {"GPL2": 2, "GPL3": 2, "LGPL2.1": 1, "LGPL3": 1,
                          "MPL-2.0": 1, "MIT": 1})
        self.assertEqual(unknown, [])
        self.assertEqual(violations, expected)
        report = {"total": 7, "by_license": dict(counts), "unknown": [],
                  "violations": [dict(package=name, license=license_value, reason=why)
                                 for name, license_value, why in expected]}
        self.output.write_text(json.dumps(report), encoding="utf-8")
        self.output.chmod(0o600)
        ORACLE.check("enterprise-json", self.output, packages)
        for bad_rows in (report["violations"][:-1],
                         report["violations"] + [report["violations"][0]],
                         report["violations"] + [dict(package="libpsl", license="MIT",
                                                       reason=reason)]):
            self.output.write_text(json.dumps(dict(report, violations=bad_rows)),
                                   encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "enterprise violations differ"):
                ORACLE.check("enterprise-json", self.output, packages)

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

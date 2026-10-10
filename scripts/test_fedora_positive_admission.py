"""Native Fedora positive advisory schema and outcome contracts."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location("fedora_positive", Path(__file__).with_name("qemu-fedora-advisory-oracle.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class FedoraAdvisoryTests(unittest.TestCase):
    def test_updateinfo_binds_native_nevra_and_equal_version_foreign_arch_controls(self):
        identity = {"name": "glibc", "epoch": "0", "version": "2.43", "release": "8.fc44", "arch": "x86_64"}
        feed = ET.fromstring(oracle.updateinfo(identity))
        rows = feed.findall("update")
        self.assertEqual([row.findtext("id") for row in rows], ["OMG-QEMU-FEDORA-616", "OMG-QEMU-FEDORA-FIXED", "OMG-QEMU-FEDORA-FOREIGN"])
        for row in rows:
            self.assertEqual(row.attrib["type"], "security")
            self.assertEqual(row.findtext("severity"), "Important")
            self.assertEqual(row.find("references/reference").attrib["id"], "CVE-OMG-QEMU-616")
        packages = [row.find("pkglist/collection/package").attrib for row in rows]
        self.assertEqual(packages, [dict(identity, release="8.fc44.omgqemu616"), identity,
                                    dict(identity, release="8.fc44.omgqemu616", arch="aarch64")])

    def test_incomplete_or_non_native_identity_is_refused(self):
        identity = {"name": "glibc", "epoch": "0", "version": "2.43", "release": "8.fc44", "arch": "x86_64"}
        for value in ({}, dict(identity, name="other"), dict(identity, epoch="-1"), dict(identity, version="2.43\n"), dict(identity, arch="unknown")):
            with self.subTest(value=value), self.assertRaises(ValueError): oracle.updateinfo(value)

    def test_native_important_severity_and_actual_findings_exit_are_required(self):
        stdout = "Found 1 vulnerabilities (1 high severity)\n  glibc (1 issues):\n    → OMG-QEMU-FEDORA-616 - Synthetic native DNF advisory [Advisory severity: Important]\n"
        oracle.verify_native_result(SimpleNamespace(returncode=0, stdout=stdout, stderr=""))
        oracle.verify_native_result(SimpleNamespace(returncode=1, stdout=stdout, stderr="Error: Vulnerability scan found 1 finding(s)\n"), True)
        for result in (SimpleNamespace(returncode=0, stdout=stdout, stderr="Error: Vulnerability scan found 1 finding(s)\n"),
                       SimpleNamespace(returncode=1, stdout=stdout.replace("Important", "High"), stderr="Error: Vulnerability scan found 1 finding(s)\n"),
                       SimpleNamespace(returncode=1, stdout=stdout+" [Score: 9.8]\n", stderr="Error: Vulnerability scan found 1 finding(s)\n")):
            with self.subTest(result=result), self.assertRaises(ValueError): oracle.verify_native_result(result, True)


if __name__ == "__main__":
    unittest.main()

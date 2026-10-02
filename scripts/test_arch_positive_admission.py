"""Behavioral controls for the native Arch advisory guest oracle."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location("arch_positive", Path(__file__).with_name("qemu-arch-advisory-oracle.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class ArchAdvisoryTests(unittest.TestCase):
    def test_feed_binds_exact_native_identity_and_exclusion_controls(self):
        feed = oracle.arch_feed("2.42+r33+g8be51d64b1e3-1")
        self.assertEqual(len(feed), 3)
        self.assertEqual([row["name"] for row in feed], ["AVG-OMG-QEMU-616", "AVG-OMG-QEMU-FIXED", "AVG-OMG-QEMU-NOT-AFFECTED"])
        for row in feed:
            self.assertEqual(row["packages"], ["glibc"])
            self.assertEqual(row["affected"], "2.42+r33+g8be51d64b1e3-1")
            self.assertEqual(row["severity"], "Critical")
            self.assertEqual(row["issues"], ["CVE-OMG-QEMU-616"])
        self.assertEqual([row["status"] for row in feed], ["Vulnerable", "Fixed", "Not affected"])
        self.assertIsNone(feed[0]["fixed"])
        self.assertEqual(feed[1]["fixed"], feed[1]["affected"])

    def test_transport_replays_exact_native_feed_and_rejects_partial_or_wrong_requests(self):
        version = "2.42-1"
        event = {"kind": "request", "method": "GET", "path": "/issues/all.json", "status": 200, "response": oracle.arch_feed(version)}
        self.assertEqual(oracle.verify_arch_requests([event, event], version, 2, 3), 2)
        for events in ([], [event], [event] * 4, [dict(event, path="/issues.json"), event],
                       [dict(event, method="POST"), event], [dict(event, status=500), event],
                       [dict(event, response=oracle.arch_feed("2.41-1")), event]):
            with self.subTest(events=events), self.assertRaises(AssertionError):
                oracle.verify_arch_requests(events, version, 2, 3)

    def test_private_nss_hosts_lookup_cannot_reach_parent_resolved_service(self):
        original = "passwd: files systemd\nhosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\nnetworks: files\n"
        self.assertEqual(oracle.private_hosts_nss(original), "passwd: files systemd\nhosts: files\nnetworks: files\n")
        for invalid in ("passwd: files\n", "hosts: files\nhosts: dns\n"):
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                oracle.private_hosts_nss(invalid)

    def result(self, fail=False):
        return SimpleNamespace(returncode=int(fail), stderr="Error: Vulnerability scan found 1 finding(s)\n" if fail else "",
                               stdout="Found 1 vulnerabilities (1 high severity)\n  glibc (1 issues):\n    → AVG-OMG-QEMU-616 - AVG-OMG-QEMU-616: synthetic fixture [Advisory severity: Critical]\n")

    def test_actual_native_severity_and_findings_exit_are_required(self):
        oracle.verify_native_result(self.result(), False)
        oracle.verify_native_result(self.result(True), True)
        for field, replacement in (("returncode", 0), ("stderr", "Error: Failed to query native security advisories\n"),
                                   ("stdout", self.result(True).stdout.replace("Critical", "High")),
                                   ("stdout", self.result(True).stdout.replace("glibc", "fixture")),
                                   ("stdout", self.result(True).stdout + " [Score: 9.8]\n"),
                                   ("stdout", self.result(True).stdout + "AVG-OMG-QEMU-FIXED\n")):
            result = copy.copy(self.result(True)); setattr(result, field, replacement)
            with self.subTest(field=field, replacement=replacement), self.assertRaises(AssertionError):
                oracle.verify_native_result(result, True)


if __name__ == "__main__":
    unittest.main()

"""Behavioral admission of native OSV queries and synthetic advisories."""
import copy
from datetime import datetime
import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("osv_oracle", Path(__file__).with_name("qemu-osv-positive-oracle.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

class QueryAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.ecosystem = "Debian:12"
        self.identities = {("glibc", "2.36-9+deb12u13"), ("apt", "2.6.1")}
        self.query = {"package": {"name": "glibc", "ecosystem": self.ecosystem}, "version": "2.36-9+deb12u13"}

    def reply(self, body, path="/v1/query"):
        return oracle.response_for_query(path, body, self.identities, self.ecosystem)

    def test_positive_advisory_is_interoperable_and_binds_exact_native_version(self):
        status, result = self.reply(self.query)
        self.assertEqual(status, 200)
        advisory, = result["vulns"]
        # The OSV interchange consumer needs required identity and modification
        # fields even though OMG's current deserializer consumes a subset.
        self.assertIn("modified", advisory)
        self.assertTrue(advisory["id"].startswith("x_"))
        self.assertEqual(datetime.fromisoformat(advisory["modified"]).isoformat(), "2026-10-02T00:00:00+00:00")
        self.assertEqual(advisory["affected"], [{"package": self.query["package"], "versions": [self.query["version"]]}])
        self.assertEqual(advisory["severity"], [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])

    def test_known_unaffected_identity_has_no_findings(self):
        query = {"package": {"name": "apt", "ecosystem": self.ecosystem}, "version": "2.6.1"}
        self.assertEqual(self.reply(query), (200, {"vulns": []}))

    def test_unknown_source_wrong_version_and_binary_identity_are_refused(self):
        for name, version in (("libc6", self.query["version"]), ("glibc", "0"), ("unknown", "1")):
            with self.subTest(name=name, version=version):
                query = copy.deepcopy(self.query)
                query["package"]["name"] = name
                query["version"] = version
                status, response = self.reply(query)
                self.assertEqual(status, 400)
                self.assertIn("error", response)
                self.assertNotIn("vulns", response)

    def test_different_ecosystem_path_and_extra_fields_are_refused(self):
        changes = [{"package": {"name": "glibc", "ecosystem": "Ubuntu:24.04:LTS"}}, {"commit": "fake"}, {"package": dict(self.query["package"], purl="pkg:deb/glibc") }]
        for change in changes:
            query = copy.deepcopy(self.query)
            query.update(change)
            self.assertEqual(self.reply(query)[0], 400)
        self.assertEqual(self.reply(self.query, "/v1/querybatch")[0], 400)

    def test_malformed_body_is_explicitly_refused(self):
        for body in (None, [], "query", {}, {"package": None}, {"package": [], "version": []}, {"package": self.query["package"], "version": [self.query["version"]]}):
            with self.subTest(body=body):
                status, response = self.reply(body)
                self.assertEqual(status, 400)
                self.assertIn("error", response)
                self.assertNotIn("vulns", response)


class FindingsAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.targets = ["libc-bin", "libc-l10n", "libc6", "locales"]
        self.output = "Secure  Vulnerability Scan\n  Found 4 vulnerabilities (4 high severity)\n"
        for name in self.targets:
            self.output += f"  {name} (1 issues):\n    → x_OMG-QEMU-616 - Synthetic fixture advisory [Score: 9.8]\n"
        self.error = "Error: Vulnerability scan found 4 finding(s)\n"

    def result(self, stdout=None, stderr=None, exit_code=1):
        return SimpleNamespace(stdout=self.output if stdout is None else stdout,
                               stderr=self.error if stderr is None else stderr,
                               returncode=exit_code)

    def test_complete_native_findings_and_plain_scan_are_admitted(self):
        oracle.verify_result(self.result(), self.targets, True)
        oracle.verify_result(self.result(stderr="", exit_code=0), self.targets, False)

    def test_exit_one_without_complete_positive_findings_is_refused(self):
        invalid = [self.result(stdout="No vulnerabilities found\n"),
                   self.result(stdout=self.output.replace("  libc6 (1 issues):", "  wrong-source (1 issues):")),
                   self.result(stdout=self.output.replace("[Score: 9.8]", "[Score: 0]", 1)),
                   self.result(stdout=self.output.replace("x_OMG-QEMU-616", "unknown-advisory", 1)),
                   self.result(stderr="Error: Failed to scan package libc6\n")]
        for result in invalid:
            with self.subTest(result=result), self.assertRaises(AssertionError):
                oracle.verify_result(result, self.targets, True)

    def test_findings_flag_must_preserve_real_exit_status(self):
        with self.assertRaises(AssertionError):
            oracle.verify_result(self.result(exit_code=0), self.targets, True)
        with self.assertRaises(AssertionError):
            oracle.verify_result(self.result(stderr="", exit_code=1), self.targets, False)


class RequestEvidenceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.ecosystem = "Debian:12"
        self.identities = {("glibc", "2.36-9+deb12u13"), ("apt", "2.6.1")}
        self.events = []
        for name, version in sorted(self.identities):
            body = {"package": {"name": name, "ecosystem": self.ecosystem}, "version": version}
            status, response = oracle.response_for_query("/v1/query", body, self.identities, self.ecosystem)
            self.events.append({"kind": "request", "path": "/v1/query", "body": body, "status": status, "response": response})

    def test_complete_query_evidence_is_admitted_once_per_native_identity(self):
        self.assertEqual(oracle.verify_requests(self.events, self.identities, self.ecosystem), 2)

    def test_missing_duplicate_and_http_failure_are_refused(self):
        failed = copy.deepcopy(self.events)
        failed[0]["status"] = 500
        for events in (self.events[:-1], self.events + self.events[:1], failed):
            with self.subTest(events=events), self.assertRaises(AssertionError):
                oracle.verify_requests(events, self.identities, self.ecosystem)

    def test_wrong_ecosystem_path_and_finding_response_are_refused(self):
        for field in ("ecosystem", "path", "response"):
            events = copy.deepcopy(self.events)
            if field == "ecosystem":
                events[0]["body"]["package"]["ecosystem"] = "Ubuntu:24.04:LTS"
            elif field == "path":
                events[0]["path"] = "/v1/querybatch"
            else:
                events[-1]["response"] = {"vulns": []}
            with self.subTest(field=field), self.assertRaises(AssertionError):
                oracle.verify_requests(events, self.identities, self.ecosystem)

if __name__ == "__main__":
    unittest.main()

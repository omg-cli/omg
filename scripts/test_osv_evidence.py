"""Reject partial or mismatched positive OSV receipts using raw native evidence."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("osv_evidence", Path(__file__).with_name("qemu-osv-evidence.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PositiveEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.archive = self.root / "native.tar.gz"
        binaries = {"omg": b"native product fixture", "omgd": b"native daemon fixture"}
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, data in binaries.items():
                member = tarfile.TarInfo("omg-v0.1.224-x86_64-linux-debian/" + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.fixture = Path(__file__).with_name("qemu-osv-positive-oracle.py")
        self.receipt = {
            "schema_version": 1, "accepted": True, "ecosystem": "Debian:12",
            "boot_id": "fdf475b0-7bfc-4836-9ebf-f95085eb21b8", "ordinary_user_uid": 1000,
            "isolated_vm_mount_and_network": True, "affected_binaries": ["libc-bin", "libc6"],
            "source_identities": 2, "fixture_id": "x_OMG-QEMU-616", "expected_score": 9.8,
            "native_archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            "fixture_sha256": hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
            "omg_sha256": hashlib.sha256(binaries["omg"]).hexdigest(),
            "omgd_sha256": hashlib.sha256(binaries["omgd"]).hexdigest(),
            "direct-plain_requests": 2, "direct-findings_requests": 2,
            "daemon_fixture_requests": 2, "daemon_requests_delta": 2,
            "native_state_unchanged": True,
            "native_state_before": {"/var/lib/dpkg/status": "a" * 64},
            "native_state_after": {"/var/lib/dpkg/status": "a" * 64},
        }
        (self.evidence / "native-query.tsv").write_text("libc-bin\tglibc\t2.36-9\tinstalled\nlibc6\tglibc\t2.36-9\tinstalled\napt\tapt\t2.6.1\tinstalled\n", encoding="utf-8", newline="\n")
        (self.evidence / "os-release").write_text('ID=debian\nVERSION_ID="12"\n', encoding="utf-8", newline="\n")
        output = "Found 2 vulnerabilities (2 high severity)\n"
        for name in self.receipt["affected_binaries"]:
            output += f"  {name} (1 issues):\n    → x_OMG-QEMU-616 - Synthetic fixture advisory [Score: 9.8]\n"
        for phase in ("direct-plain", "direct-findings", "daemon-plain", "daemon-findings"):
            (self.evidence / (phase + ".stdout")).write_text(output, encoding="utf-8", newline="\n")
            (self.evidence / (phase + ".stderr")).write_text("Error: Vulnerability scan found 2 finding(s)\n" if phase.endswith("findings") else "", encoding="utf-8", newline="\n")
        (self.evidence / "untrusted-tls.stdout").write_text("", encoding="utf-8", newline="\n")
        (self.evidence / "untrusted-tls.stderr").write_text("Error: Failed to scan package libc6: certificate verification failed\n", encoding="utf-8", newline="\n")
        for phase, count in (("before", 0), ("after", 2)):
            (self.evidence / ("daemon-" + phase + ".stdout")).write_text(f"omg_security_audit_requests_total {count}\n", encoding="utf-8", newline="\n")
            (self.evidence / ("daemon-" + phase + ".stderr")).write_text("", encoding="utf-8", newline="\n")
        self.events = [{"kind": "tls-error", "error": "certificate verify failed"}]
        identities = {("glibc", "2.36-9"), ("apt", "2.6.1")}
        for _ in range(3):
            for name, version in sorted(identities):
                body = {"package": {"name": name, "ecosystem": "Debian:12"}, "version": version}
                status, response = checker.oracle.response_for_query("/v1/query", body, identities, "Debian:12")
                self.events.append({"kind": "request", "path": "/v1/query", "body": body, "status": status, "response": response})
        self.receipt["product_results"] = {}
        for phase in ("direct-plain", "direct-findings", "daemon-plain", "daemon-findings"):
            finding = phase.endswith("findings")
            self.receipt["product_results"][phase] = {"argv": ["audit", "scan"] + (["--fail-on-findings"] if finding else []), "exit_code": int(finding)}
        self.receipt["product_results"]["untrusted-tls"] = {"argv": ["audit", "scan"], "exit_code": 1}
        for phase in ("daemon-before", "daemon-after"):
            self.receipt["product_results"][phase] = {"argv": ["metrics"], "exit_code": 0}
        self.receipt["original_system_files"] = {"/etc/hosts": "c" * 64, "/etc/ssl/certs/ca-certificates.crt": "d" * 64}
        for phase in ("before", "after"):
            (self.evidence / ("parent-system-" + phase + ".sha256")).write_text(
                "".join(digest + "  " + name + "\n" for name, digest in self.receipt["original_system_files"].items()), encoding="utf-8", newline="\n")
        self.write()

    def write(self):
        (self.evidence / "receipt.json").write_text(json.dumps(self.receipt), encoding="utf-8", newline="\n")
        (self.evidence / "fixture-events.json").write_text(json.dumps(self.events), encoding="utf-8", newline="\n")

    def admit(self):
        return checker.validate_evidence(self.evidence, self.archive, self.fixture, "debian")

    def test_complete_bound_native_evidence_is_admitted(self):
        self.assertEqual(self.admit(), self.receipt)

    def test_false_complete_wrong_archive_fixture_binary_and_native_state_are_refused(self):
        original = copy.deepcopy(self.receipt)
        changes = {"accepted": False, "native_archive_sha256": "b" * 64, "fixture_sha256": "b" * 64,
                   "omg_sha256": "b" * 64, "omgd_sha256": "b" * 64, "ordinary_user_uid": 0,
                   "native_state_after": {"/var/lib/dpkg/status": "b" * 64}, "daemon_requests_delta": 0,
                   "source_identities": 1, "affected_binaries": ["libc6"], "ecosystem": "Ubuntu:24.04:LTS"}
        for field, value in changes.items():
            with self.subTest(field=field):
                self.receipt = dict(original, **{field: value})
                self.write()
                with self.assertRaises(ValueError):
                    self.admit()

    def test_findings_without_matching_tls_queries_are_refused(self):
        original = copy.deepcopy(self.events)
        for events in (original[1:], original[:-1], original + original[-1:]):
            self.events = events
            self.write()
            with self.subTest(events=len(events)), self.assertRaises(ValueError):
                self.admit()

    def test_parent_guest_trust_or_hosts_changes_are_refused(self):
        files = {"/etc/hosts": "c" * 64, "/etc/ssl/certs/ca-certificates.crt": "d" * 64}
        self.receipt["original_system_files"] = files
        for phase in ("before", "after"):
            (self.evidence / ("parent-system-" + phase + ".sha256")).write_text(
                "".join(digest + "  " + name + "\n" for name, digest in files.items()), encoding="utf-8", newline="\n")
        self.write()
        self.assertEqual(self.admit(), self.receipt)
        for phase in ("before", "after"):
            path = self.evidence / ("parent-system-" + phase + ".sha256")
            original = path.read_bytes()
            path.write_bytes(original.replace(b"c" * 64, b"e" * 64))
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                self.admit()
            path.write_bytes(original)

    def test_exit_one_error_or_missing_native_finding_is_refused(self):
        for name, replacement in (("direct-findings.stdout", "No vulnerabilities found\n"),
                                  ("daemon-findings.stderr", "Error: Failed to scan package libc6\n")):
            path = self.evidence / name
            before = path.read_text()
            path.write_text(replacement, encoding="utf-8", newline="\n")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.admit()
            path.write_text(before, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    unittest.main()

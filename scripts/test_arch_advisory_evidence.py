"""Replay refusal controls for archive-bound native Arch advisory evidence."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("arch_evidence", Path(__file__).with_name("qemu-arch-advisory-evidence.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class ArchEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.evidence = self.root / "evidence"; self.evidence.mkdir()
        self.archive = self.root / "native.tar.gz"; self.fixture = Path(__file__).with_name("qemu-arch-advisory-oracle.py")
        binaries = {"omg": b"native CLI", "omgd": b"native daemon"}
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, data in binaries.items():
                member = tarfile.TarInfo("omg-v0.1.224-x86_64-linux-arch/" + name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.version = "2.42-1"
        native = "glibc 2.42-1\npacman 7.0-1\n"
        state = {"installed": native, "explicit": "pacman 7.0-1\n", "database_sha256": {"glibc-2.42-1/desc": "a" * 64, "glibc-2.42-1/files": "b" * 64}}
        self.receipt = {"schema_version": 1, "accepted": True, "ordinary_user_uid": 1000,
                        "boot_id": "3fd492c0-4023-4b4b-9b8c-9c6209355920", "isolated_vm_mount_and_network": True,
                        "fixture_id": "AVG-OMG-QEMU-616", "expected_native_severity": "Critical",
                        "native_glibc_version": self.version, "affected_binaries": ["glibc"],
                        "native_archive_sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                        "fixture_sha256": hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
                        "native_state_before": state, "native_state_after": copy.deepcopy(state), "native_state_unchanged": True,
                        "original_system_files": {"/etc/hosts": "c" * 64, "/etc/ssl/certs/ca-certificates.crt": "d" * 64, "/etc/nsswitch.conf": "e" * 64},
                        "direct-plain_requests": 1, "direct-findings_requests": 1, "daemon_fixture_requests": 2, "daemon_requests_delta": 2,
                        "product_results": {}}
        self.receipt.update({name + "_sha256": hashlib.sha256(data).hexdigest() for name, data in binaries.items()})
        self.put("native-query.tsv", native); self.put("os-release", "ID=arch\n")
        self.put("native-feed.json", json.dumps(checker.oracle.arch_feed(self.version)))
        original_nss = "passwd: files systemd\nhosts: resolve files dns\n"
        self.put("native-nss-before.conf", original_nss)
        self.receipt["original_system_files"]["/etc/nsswitch.conf"] = hashlib.sha256(original_nss.encode()).hexdigest()
        self.put("private-nss.conf", "passwd: files systemd\nhosts: files\n")
        self.put("dns-isolation.json", json.dumps({"resolved_addresses": ["127.0.0.1"]}))
        output = "Found 1 vulnerabilities (1 high severity)\n  glibc (1 issues):\n    → AVG-OMG-QEMU-616 - AVG-OMG-QEMU-616: synthetic fixture [Advisory severity: Critical]\n"
        for phase in ("direct-plain", "direct-findings", "daemon-plain", "daemon-findings", "untrusted-tls", "daemon-before", "daemon-after"):
            finding = phase.endswith("findings"); metrics = phase in ("daemon-before", "daemon-after")
            self.receipt["product_results"][phase] = {"argv": ["metrics"] if metrics else ["audit", "scan"] + (["--fail-on-findings"] if finding else []), "exit_code": int(finding or phase == "untrusted-tls")}
            stdout = ("omg_security_audit_requests_total " + str(2 if phase == "daemon-after" else 0) + "\n") if metrics else "" if phase == "untrusted-tls" else output
            stderr = "Error: Failed to query native security advisories: certificate verification failed\n" if phase == "untrusted-tls" else "Error: Vulnerability scan found 1 finding(s)\n" if finding else ""
            self.put(phase + ".stdout", stdout); self.put(phase + ".stderr", stderr)
        for phase in ("before", "after"):
            self.put("parent-system-" + phase + ".sha256", "".join(value + "  " + name + "\n" for name, value in self.receipt["original_system_files"].items()))
        event = {"kind": "request", "method": "GET", "path": "/issues/all.json", "status": 200, "response": checker.oracle.arch_feed(self.version)}
        self.events = [{"kind": "tls-error", "error": "certificate verification failed"}] + [copy.deepcopy(event) for _ in range(4)]
        self.write()

    def put(self, name, text):
        (self.evidence / name).write_text(text, encoding="utf-8", newline="\n")

    def write(self):
        self.put("receipt.json", json.dumps(self.receipt)); self.put("fixture-events.json", json.dumps(self.events))

    def admit(self):
        return checker.validate_evidence(self.evidence, self.archive, self.fixture)

    def test_complete_bound_native_arch_evidence_is_admitted(self):
        self.assertEqual(self.admit(), self.receipt)

    def test_native_database_format_marker_is_bound_without_admitting_arbitrary_files(self):
        self.receipt["native_state_before"]["database_sha256"]["ALPM_DB_VERSION"] = "9" * 64
        self.receipt["native_state_after"] = copy.deepcopy(self.receipt["native_state_before"])
        self.write()
        try:
            admitted = self.admit()
        except ValueError as error:
            self.fail("actual pacman format marker must be admitted: " + str(error))
        self.assertEqual(admitted, self.receipt)
        self.receipt["native_state_before"]["database_sha256"]["secret"] = "8" * 64
        self.receipt["native_state_after"] = copy.deepcopy(self.receipt["native_state_before"])
        self.write()
        with self.assertRaises(ValueError): self.admit()

    def test_wrong_identity_outcomes_state_and_feed_are_refused(self):
        original = copy.deepcopy(self.receipt)
        for field, value in {"accepted": False, "ordinary_user_uid": 0, "fixture_sha256": "f" * 64, "native_archive_sha256": "f" * 64,
                             "omgd_sha256": "f" * 64, "native_glibc_version": "2.41-1", "affected_binaries": [], "expected_native_severity": "High",
                             "native_state_after": {}, "daemon_requests_delta": 0}.items():
            self.receipt = dict(original, **{field: value}); self.write()
            with self.subTest(field=field), self.assertRaises(ValueError): self.admit()

    def test_partial_tls_requests_and_invented_numeric_score_are_refused(self):
        original = copy.deepcopy(self.events)
        for events in (original[1:], original[:-1], original + original[-1:], [dict(original[1], status=500)] + original[1:]):
            self.events = events; self.write()
            with self.subTest(events=len(events)), self.assertRaises(ValueError): self.admit()
        self.events = original; self.write()
        original_output = (self.evidence / "daemon-findings.stdout").read_text()
        self.put("daemon-findings.stdout", original_output + " [Score: 9.8]\n")
        with self.assertRaises(ValueError): self.admit()
        self.put("daemon-findings.stdout", "No vulnerabilities found\n")
        with self.assertRaises(ValueError): self.admit()

    def test_private_nss_cannot_change_non_hostname_services(self):
        self.put("private-nss.conf", "passwd: ldap\nhosts: files\n")
        with self.assertRaises(ValueError): self.admit()
        self.put("private-nss.conf", "passwd: files systemd\nhosts: files\n")
        self.put("native-nss-before.conf", "passwd: files\nhosts: dns\n")
        with self.assertRaises(ValueError): self.admit()

    def test_parent_nss_change_and_nonlocal_resolution_are_refused(self):
        for name, replacement in (("parent-system-after.sha256", "f" * 64 + "  /etc/nsswitch.conf\n"),
                                  ("dns-isolation.json", json.dumps({"resolved_addresses": ["95.217.239.55"]})),
                                  ("private-nss.conf", "hosts: resolve files dns\n")):
            original = (self.evidence / name).read_bytes(); self.put(name, replacement)
            with self.subTest(name=name), self.assertRaises(ValueError): self.admit()
            (self.evidence / name).write_bytes(original)


if __name__ == "__main__":
    unittest.main()

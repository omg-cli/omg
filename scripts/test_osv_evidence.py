"""Reject partial or mismatched positive OSV receipts using raw native evidence."""
import copy
import hashlib
import importlib.util
import io
import json
import http.client
import http.server
from pathlib import Path
import socket
import ssl
import subprocess
import tarfile
import tempfile
import threading
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
        self.events = [{"kind": "tls-error", "error": "certificate verify failed",
                        "ssl_error": ssl.SSL_ERROR_SSL, "reason": "TLSV1_ALERT_UNKNOWN_CA"}]
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

    def test_trixie_requires_its_archive_and_debian_13_ecosystem(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in {'omg': b'native product fixture', 'omgd': b'native daemon fixture'}.items():
                member = tarfile.TarInfo('omg-v0.1.224-x86_64-linux-debian-trixie/' + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.receipt['native_archive_sha256'] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.receipt['ecosystem'] = 'Debian:13'
        identities = {('glibc', '2.36-9'), ('apt', '2.6.1')}
        for event in self.events:
            if event['kind'] == 'request':
                event['body']['package']['ecosystem'] = 'Debian:13'
                event['status'], event['response'] = checker.oracle.response_for_query(
                    event['path'], event['body'], identities, 'Debian:13')
        (self.evidence / 'os-release').write_text('ID=debian\nVERSION_ID="13"\n')
        self.write()
        self.assertEqual(checker.validate_evidence(self.evidence, self.archive,
            self.fixture, 'debian-trixie'), self.receipt)
        for release in ('ID=debian\nVERSION_ID="12"\n', 'ID=ubuntu\nVERSION_ID="13"\n'):
            with self.subTest(release=release), self.assertRaises(ValueError):
                (self.evidence / 'os-release').write_text(release)
                checker.validate_evidence(self.evidence, self.archive, self.fixture, 'debian-trixie')
        (self.evidence / 'os-release').write_text('ID=debian\nVERSION_ID="13"\n')
        self.receipt['ecosystem'] = 'Debian:12'
        self.write()
        with self.assertRaises(ValueError):
            checker.validate_evidence(self.evidence, self.archive, self.fixture, 'debian-trixie')
    def test_retained_transport_eof_does_not_replace_certificate_refusal_or_requests(self):
        eof = {"kind": "transport-eof", "ssl_error": ssl.SSL_ERROR_EOF, "error": "TLS/SSL connection has been closed (EOF)"}
        original = copy.deepcopy(self.events)
        self.events = [eof] + original + [eof]
        self.write()
        self.assertEqual(self.admit(), self.receipt)
        for events in ([eof] + original[1:], original + [dict(eof, ssl_error=ssl.SSL_ERROR_SSL)],
                       original + [dict(eof, kind="unknown")], original + [original[0]],
                       original[:-1] + [eof], original + [original[-1]]):
            self.events = events
            self.write()
            with self.subTest(events=events), self.assertRaises(ValueError):
                self.admit()

    def test_non_certificate_tls_error_cannot_prove_untrusted_refusal(self):
        self.events[0]["reason"] = "UNEXPECTED_EOF_WHILE_READING"
        self.write()
        with self.assertRaises(ValueError):
            self.admit()

    def test_clean_tls_close_cannot_replace_refusal_or_native_queries(self):
        close = {"kind": "tls-close", "ssl_error": ssl.SSL_ERROR_ZERO_RETURN, "error": "TLS/SSL connection has been closed (EOF)"}
        original = copy.deepcopy(self.events)
        self.events = [close] + original + [close]
        self.write()
        self.assertEqual(self.admit(), self.receipt)
        for events in ([close] + original[1:], original[:-1] + [close],
                       original + [original[-1]], original + [dict(close, ssl_error=ssl.SSL_ERROR_EOF)],
                       original + [dict(close, ssl_error=True)], original + [dict(close, error="")],
                       original + [dict(close, reason=None)]):
            self.events = events
            self.write()
            with self.subTest(events=events), self.assertRaises(ValueError):
                self.admit()

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


class NativeTLSClassificationTests(unittest.TestCase):
    def test_real_unknown_ca_and_eof_remain_distinct_before_and_after_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            certificate, key = root / "cert.pem", root / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                            "-keyout", str(key), "-out", str(certificate)], check=True, capture_output=True, timeout=30)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            events = []
            changed = threading.Condition()

            def event(value):
                with changed:
                    events.append(value)
                    changed.notify_all()

            def wait_for(count):
                with changed:
                    self.assertTrue(changed.wait_for(lambda: len(events) >= count, timeout=8), events)

            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *args):
                    return

                def do_GET(self):
                    event({"kind": "request"})
                    self.send_response(204)
                    self.end_headers()

            server = checker.oracle.TLSEvidenceServer(("127.0.0.1", 0), Handler, context, event)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            port = server.server_address[1]
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5):
                    pass
                wait_for(1)
                with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        ssl.create_default_context().wrap_socket(stream, server_hostname="localhost")
                wait_for(2)
                connection = http.client.HTTPSConnection("localhost", port, timeout=5,
                                                       context=ssl.create_default_context(cafile=str(certificate)))
                try:
                    connection.request("GET", "/")
                    self.assertEqual(connection.getresponse().status, 204)
                finally:
                    connection.close()
                wait_for(3)
                with socket.create_connection(("127.0.0.1", port), timeout=5):
                    pass
                wait_for(4)
                with socket.create_connection(("127.0.0.1", port), timeout=5) as stream:
                    client_context = ssl.create_default_context(cafile=str(certificate))
                    client_context.maximum_version = ssl.TLSVersion.TLSv1_2
                    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                    client = client_context.wrap_bio(incoming, outgoing, server_hostname="localhost")
                    with self.assertRaises(ssl.SSLWantReadError):
                        client.do_handshake()
                    stream.sendall(outgoing.read())
                    self.assertTrue(stream.recv(65536))
                    stream.sendall(bytes.fromhex("15030300020100"))
                wait_for(5)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=8)
            self.assertFalse(thread.is_alive())
            self.assertEqual(events[4]["ssl_error"], ssl.SSL_ERROR_ZERO_RETURN)
            self.assertEqual([item["kind"] for item in events], ["transport-eof", "tls-error", "request", "transport-eof", "tls-close"])
            self.assertEqual(events[0]["ssl_error"], ssl.SSL_ERROR_EOF)
            self.assertEqual(events[1]["reason"], "TLSV1_ALERT_UNKNOWN_CA")
            self.assertEqual(events[3]["ssl_error"], ssl.SSL_ERROR_EOF)
            self.assertEqual(events[4]["ssl_error"], ssl.SSL_ERROR_ZERO_RETURN)


if __name__ == "__main__":
    unittest.main()

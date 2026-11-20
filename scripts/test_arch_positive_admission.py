"""Behavioral controls for the native Arch advisory guest oracle."""
import copy
import importlib.util
import hashlib
import json
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
        observed = "2026-11-13T02:00:00.000000Z"
        event = {"kind": "request", "method": "GET", "host": oracle.ARCH_HOST, "path": oracle.ARCH_PATH,
                 "status": 200, "observed_at": observed, "response": oracle.arch_snapshot(version, observed)}
        self.assertEqual(oracle.verify_arch_requests([event, event], version, 2, 3), 2)
        for events in ([], [event], [event] * 4, [dict(event, path="/issues.json"), event],
                       [dict(event, method="POST"), event], [dict(event, status=500), event],
                       [dict(event, status=200.0), event],
                       [dict(event, response=oracle.arch_snapshot("2.41-1", observed)), event]):
            with self.subTest(events=events), self.assertRaises(AssertionError):
                oracle.verify_arch_requests(events, version, 2, 3)

    def test_transport_accepts_production_cloudflare_envelope_with_original_payload_bytes(self):
        version = "2.42-1"
        observed = "2026-11-13T02:00:00.000000Z"
        payload = json.dumps(oracle.arch_feed(version), ensure_ascii=False, indent=2) + "\n"
        envelope = {
            "schema_version": 1,
            "source": "arch-security",
            "source_url": "https://security.archlinux.org/issues/all.json",
            "fetched_at": observed,
            "checked_at": observed,
            "complete": True,
            "payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "payload_json": payload,
        }
        event = {"kind": "request", "method": "GET", "host": "omg-advisories.latham.workers.dev",
                 "path": "/v1/arch/advisories", "status": 200, "observed_at": observed, "response": envelope}
        self.assertEqual(oracle.verify_arch_requests([event], version, 1, 1), 1)

    def test_snapshot_route_and_private_hosts_pin_the_production_destination(self):
        observed = "2026-11-13T02:00:00.000000Z"
        original = "127.0.0.1 localhost\n"
        self.assertEqual(oracle.ARCH_HOST, "omg-advisories.latham.workers.dev")
        self.assertEqual(oracle.ARCH_PATH, "/v1/arch/advisories")
        mapped = oracle.private_hosts(original)
        self.assertEqual(mapped, original + "\n127.0.0.1 omg-advisories.latham.workers.dev\n")
        with self.assertRaises(AssertionError):
            oracle.private_hosts(mapped)
        status, response = oracle.snapshot_response(oracle.ARCH_HOST, oracle.ARCH_PATH, "2.42-1", observed)
        self.assertEqual(status, 200)
        self.assertEqual(response, oracle.arch_snapshot("2.42-1", observed))
        for host, path in (("security.archlinux.org", "/issues/all.json"),
                           (oracle.ARCH_HOST, "/issues/all.json"), ("elsewhere.invalid", oracle.ARCH_PATH)):
            with self.subTest(host=host, path=path):
                self.assertEqual(oracle.snapshot_response(host, path, "2.42-1", observed)[0], 404)

    def test_snapshot_byte_integrity_and_provenance_cannot_be_changed_in_positive_evidence(self):
        observed = "2026-11-13T02:00:00.000000Z"
        envelope = oracle.arch_snapshot("2.42-1", observed)
        self.assertEqual(envelope["payload_sha256"], hashlib.sha256(envelope["payload_json"].encode("utf-8")).hexdigest())
        self.assertNotEqual(envelope["payload_sha256"], hashlib.sha256(json.dumps(json.loads(envelope["payload_json"])).encode()).hexdigest())
        event = {"kind": "request", "method": "GET", "host": oracle.ARCH_HOST, "path": oracle.ARCH_PATH,
                 "status": 200, "observed_at": observed, "response": envelope}
        for field, value in (("schema_version", True), ("schema_version", 1.0), ("complete", 1),
                             ("schema_version", 2), ("source", "other"), ("source_url", "https://elsewhere.invalid/issues"),
                             ("complete", False), ("payload_json", envelope["payload_json"] + " "),
                             ("payload_sha256", "0" * 64), ("checked_at", "2026-11-13T01:29:00.000000Z")):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                oracle.verify_arch_requests([dict(event, response=dict(envelope, **{field: value}))], "2.42-1", 1, 1)
        for mode in oracle.SNAPSHOT_REFUSALS:
            control = oracle.arch_snapshot("2.42-1", observed, mode)
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                oracle.verify_arch_requests([dict(event, response=control)], "2.42-1", 1, 1)

    def test_snapshot_controls_exercise_hash_age_future_and_order_refusals(self):
        observed = "2026-11-13T02:00:00.000000Z"
        now = oracle.utc_timestamp(observed)
        valid = oracle.arch_snapshot("2.42-1", observed)
        changed = oracle.arch_snapshot("2.42-1", observed, "tampered-payload")
        self.assertEqual(changed["payload_sha256"], valid["payload_sha256"])
        self.assertEqual(json.loads(changed["payload_json"]), json.loads(valid["payload_json"]))
        self.assertNotEqual(hashlib.sha256(changed["payload_json"].encode()).hexdigest(), changed["payload_sha256"])
        stale = oracle.arch_snapshot("2.42-1", observed, "stale-snapshot")
        self.assertGreater((now - oracle.utc_timestamp(stale["checked_at"])).total_seconds(), 30 * 60)
        future = oracle.arch_snapshot("2.42-1", observed, "future-snapshot")
        self.assertGreater((oracle.utc_timestamp(future["checked_at"]) - now).total_seconds(), 60)
        reversed_times = oracle.arch_snapshot("2.42-1", observed, "reversed-times")
        self.assertGreater(oracle.utc_timestamp(reversed_times["fetched_at"]), oracle.utc_timestamp(reversed_times["checked_at"]))
        for mode, reason in oracle.SNAPSHOT_REFUSALS.items():
            refused = SimpleNamespace(returncode=1, stdout="", stderr="Failed to query native security advisories: " + reason)
            oracle.verify_snapshot_refusal(refused, mode)
            refused.stderr = "Failed to query native security advisories: DNS failure"
            with self.subTest(mode=mode), self.assertRaises(AssertionError):
                oracle.verify_snapshot_refusal(refused, mode)

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

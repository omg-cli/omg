import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("qemu_health", Path(__file__).with_name("check-qemu-health.py"))
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)


class HealthTests(unittest.TestCase):
    def test_final_driver_uses_active_serial_and_expected_boot(self):
        source = Path(__file__).with_name("benchmark-qemu.sh").read_text()
        begin = source.index("health_rc=0\n")
        end = source.index("# Verdict map:", begin)
        for transactions, serial_fatal, stale_boot, accepted in (
            (0, False, False, True),
            (1, False, False, True),
            (1, True, False, False),
            (1, False, True, False),
        ):
            with self.subTest(transactions=transactions, fatal=serial_fatal, stale=stale_boot):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "guest").mkdir()
                    (root / "transactions").mkdir()
                    (root / "guest/serial.log").write_text("Linux version 6.12\n")
                    (root / "transactions/resume-serial.log").write_text(
                        "Kernel panic - not syncing: resumed guest\n" if serial_fatal
                        else "Linux version 6.12\n"
                    )
                    boot = "00000000-1111-2222-3333-555555555555"
                    observed = "00000000-1111-2222-3333-666666666666" if stale_boot else boot
                    (root / "receipt.json").write_text(json.dumps(dict(
                        schema_version=1, complete=True, boot_id=observed,
                        kernel_bytes=100, fatal_signatures=[], product_crashes=[]
                    )))
                    setup = '''set -euo pipefail
work="$PWD"
controller=fixture
rc=0
timeout() { [[ "$1" == --kill-after=* ]] && shift; shift; "$@"; }
docker() {
  if [[ "$1" == inspect ]]; then
    printf '{"Running":true,"OOMKilled":false,"ExitCode":0}\\n'
  elif [[ "$*" == *collect* ]]; then
    cat receipt.json
  else
    printf '00000000-1111-2222-3333-555555555555\\n'
  fi
}
'''
                    import shlex
                    setup += f"here={shlex.quote(str(Path(__file__).resolve().parent))}\n"
                    setup += f"transaction_samples={transactions}\n"
                    result = subprocess.run(
                        ["bash", "-c", setup + source[begin:end] + '\nexit "$rc"\n'],
                        cwd=root, capture_output=True, text=True, timeout=10
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.guest = self.root / "guest.json"
        self.serial = self.root / "serial.log"
        self.controller = self.root / "controller.json"
        self.payload = {"schema_version": 1, "complete": True,
                        "boot_id": "00000000-1111-2222-3333-444444444444",
                        "kernel_bytes": 100, "fatal_signatures": [], "product_crashes": []}
        self.guest.write_text(json.dumps(self.payload))
        self.serial.write_text("Linux version 6.12\nReached target Multi-User System.\n")
        self.controller.write_text('{"Running":true,"OOMKilled":false,"ExitCode":0}')

    def verify(self):
        return HEALTH.verify(self.guest, self.serial, self.controller)

    def test_clean_health_passes(self):
        self.assertEqual(self.verify(), 0)

    def test_trial_rejects_health_from_another_boot(self):
        self.assertEqual(HEALTH.verify_guest(self.guest, self.serial, self.payload["boot_id"]), 0)
        with self.assertRaises(ValueError):
            HEALTH.verify_guest(self.guest, self.serial, "00000000-1111-2222-3333-555555555555")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
                         and shutil.which("journalctl"), "Native root journal query runs in Linux QEMU preparation")
    def test_native_systemd_collection(self):
        receipt = HEALTH.collect()
        self.assertTrue(receipt["complete"])
        self.assertGreater(receipt["kernel_bytes"], 0)

    def test_collector_binds_optional_boot_argument_and_accepts_no_crashes(self):
        with patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                patch.object(HEALTH, "query", side_effect=["Linux version 6.12\n", ""]) as query:
            receipt = HEALTH.collect()
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["product_crashes"], [])
        for call in query.call_args_list:
            self.assertIn("--boot=" + self.payload["boot_id"].replace("-", ""), call.args[0])
            self.assertIn("--quiet", call.args[0])
            self.assertNotIn("--boot", call.args[0])

    def test_injected_crashes_cannot_pass(self):
        for message in ("Kernel panic - not syncing: fatal exception",
                        "BUG: unable to handle page fault", "Oops: 0002 [#1]",
                        "Out of memory: Killed process 12 (omg)",
                        "omg[42]: segfault at 0 ip 123"):
            with self.subTest(message=message):
                self.serial.write_text("[  2.345] " + message)
                with self.assertRaises(ValueError):
                    self.verify()

    def test_benign_security_messages_pass(self):
        self.serial.write_text("Kernel panic handler installed\nOOM killer enabled\n")
        self.assertEqual(self.verify(), 0)

    def test_serial_torn_utf8_does_not_hide_crash_signatures(self):
        self.serial.write_bytes(b"Linux version 6.12\n\xe2Reached target\n")
        self.assertEqual(self.verify(), 0)
        self.serial.write_bytes(b"\xe2\nKernel panic - not syncing: fixture\n")
        with self.assertRaises(ValueError):
            self.verify()
        self.guest.write_bytes(b"{\xe2}")
        with self.assertRaises(ValueError):
            self.verify()

    def test_named_worker_crash_is_identified_by_product_executable(self):
        core = json.dumps({"COREDUMP_COMM": "tokio-runtime-w", "COREDUMP_EXE": "/home/bench/release/omg",
                           "COREDUMP_SIGNAL": "11", "COREDUMP_ENVIRON": "private"})
        with patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                patch.object(HEALTH, "query", side_effect=["Linux version 6.12\n", core]):
            receipt = HEALTH.collect()
        self.assertEqual(receipt["product_crashes"], [{"process": "omg", "signal": 11}])
        self.assertNotIn("private", json.dumps(receipt))
        self.assertNotIn("/home/bench", json.dumps(receipt))

    def test_missing_truncated_or_oversized_evidence_fails(self):
        for content in ("", "{", "null", "x" * (HEALTH.LIMIT + 1)):
            with self.subTest(length=len(content)):
                self.guest.write_text(content)
                with self.assertRaises(ValueError):
                    self.verify()
        self.guest.unlink()
        with self.assertRaises(OSError):
            self.verify()

    def test_incomplete_crashed_or_invalid_guest_fails(self):
        for field, value in (("complete", False), ("boot_id", "unknown"),
                             ("kernel_bytes", 0), ("kernel_bytes", True),
                             ("fatal_signatures", ["Oops:"]),
                             ("product_crashes", [{"process": "omg", "signal": 11}])):
            with self.subTest(field=field):
                self.guest.write_text(json.dumps(dict(self.payload, **{field: value})))
                with self.assertRaises(ValueError):
                    self.verify()

    def test_controller_oom_or_exit_fails(self):
        for state in ({"Running": False, "OOMKilled": False, "ExitCode": 0},
                      {"Running": True, "OOMKilled": True, "ExitCode": 0},
                      {"Running": True, "OOMKilled": False, "ExitCode": 137}):
            self.controller.write_text(json.dumps(state))
            with self.assertRaises(ValueError):
                self.verify()


if __name__ == "__main__":
    unittest.main()

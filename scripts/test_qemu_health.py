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


def channel_fixture(boot):
    return {"kind": "systemd-coredump-pipe", "boot_id": boot,
            "core_pattern": "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h",
            "handler_executable": True,
            "socket": {"Id": "systemd-coredump.socket", "LoadState": "loaded",
                       "ActiveState": "active", "SubState": "listening",
                       "Result": "success", "UnitFileState": "static"},
            "processor": {"Id": "systemd-coredump@omg-health.service", "LoadState": "loaded",
                          "ActiveState": "inactive", "SubState": "dead",
                          "Result": "success", "UnitFileState": "static"}}


class HealthTests(unittest.TestCase):
    def test_final_driver_uses_active_serial_and_expected_boot(self):
        source = Path(__file__).with_name("benchmark-qemu.sh").read_text()
        begin = source.index("health_rc=0\n")
        end = source.index("# Verdict map:", begin)
        for transactions, serial_fatal, stale_boot, boot_probe_failure, accepted in (
            (0, False, False, False, True),
            (1, False, False, False, True),
            (1, True, False, False, False),
            (1, False, True, False, False),
            (1, False, False, True, False),
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
                        schema_version=2, complete=True, boot_id=observed,
                        kernel_bytes=100, fatal_signatures=[], product_crashes=[],
                        crash_channel=channel_fixture(observed)
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
    if [[ "$boot_probe_failure" == true ]]; then return 255; fi
    printf '00000000-1111-2222-3333-555555555555\\n'
  fi
}
'''
                    import shlex
                    setup += f"here={shlex.quote(str(Path(__file__).resolve().parent))}\n"
                    setup += f"transaction_samples={transactions}\n"
                    setup += f"boot_probe_failure={str(boot_probe_failure).lower()}\n"
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
        self.payload = {"schema_version": 2, "complete": True,
                        "boot_id": "00000000-1111-2222-3333-444444444444",
                        "kernel_bytes": 100, "fatal_signatures": [], "product_crashes": []}
        self.payload["crash_channel"] = channel_fixture(self.payload["boot_id"])
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

    def preparation_fixtures(self):
        transactions = self.root / "transactions"
        transactions.mkdir()
        (self.root / "guest").mkdir()
        (self.root / "guest/serial.log").write_text("Linux version 6.12\n")
        (transactions / "prepare-install-serial.log").write_text("Linux version 6.12\n")
        for operation, digit in (("remove", "5"), ("install", "6")):
            boot = "00000000-1111-2222-3333-" + digit * 12
            prefix = transactions / f"prepare-{operation}"
            Path(str(prefix) + "-boot-id.txt").write_text(boot + "\n")
            Path(str(prefix) + "-health.json").write_text(json.dumps(dict(
                self.payload, boot_id=boot, crash_channel=channel_fixture(boot))))

    def test_clean_distinct_preparation_boots_pass(self):
        self.preparation_fixtures()
        self.assertEqual(HEALTH.verify_preparations(self.root), 0)

    def test_preparation_admission_command_fails_closed(self):
        self.preparation_fixtures()
        command = [sys.executable, str(Path(__file__).with_name("check-qemu-health.py")),
                   "verify-preparations", "--root", str(self.root)]
        accepted = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        (self.root / "transactions/prepare-remove-health.json").unlink()
        self.assertEqual(self.verify(), 0)
        rejected = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(rejected.returncode, 2, rejected.stderr)
        self.assertIn("health evidence failed admission", rejected.stderr)

    def test_healthy_resumed_guest_cannot_hide_invalid_preparation(self):
        self.preparation_fixtures()
        for operation in ("remove", "install"):
            receipt = self.root / "transactions" / f"prepare-{operation}-health.json"
            original = receipt.read_text()
            clean = json.loads(original)
            variants = [None, "", "{", json.dumps(dict(clean, complete=False)),
                        json.dumps(dict(clean, boot_id=self.payload["boot_id"])),
                        json.dumps(dict(clean, product_crashes=[{"process": "omg", "signal": 6}])),
                        json.dumps(dict(clean, fatal_signatures=["Oops:"]))]
            for invalid in variants:
                with self.subTest(operation=operation, invalid=invalid):
                    if invalid is None:
                        receipt.unlink()
                    else:
                        receipt.write_text(invalid)
                    self.assertEqual(self.verify(), 0)  # Resume boot remains healthy.
                    with self.assertRaises((OSError, ValueError)):
                        HEALTH.verify_preparations(self.root)
                    receipt.write_text(original)

    def test_preparations_require_identity_and_serial_for_each_distinct_boot(self):
        self.preparation_fixtures()
        for relative in ("transactions/prepare-remove-boot-id.txt",
                         "transactions/prepare-install-boot-id.txt", "guest/serial.log",
                         "transactions/prepare-install-serial.log"):
            path = self.root / relative
            original = path.read_text()
            path.unlink()
            with self.subTest(missing=relative), self.assertRaises(OSError):
                HEALTH.verify_preparations(self.root)
            path.write_text(original)
        transactions = self.root / "transactions"
        (transactions / "prepare-install-boot-id.txt").write_text(
            (transactions / "prepare-remove-boot-id.txt").read_text())
        (transactions / "prepare-install-health.json").write_text(
            (transactions / "prepare-remove-health.json").read_text())
        with self.assertRaisesRegex(ValueError, "repeated preparation boot"):
            HEALTH.verify_preparations(self.root)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0
                         and shutil.which("journalctl"), "Native root journal query runs in Linux QEMU preparation")
    def test_native_systemd_collection(self):
        # Hosted helper runners can use apport or a plain core-file pattern.
        # Verify fail-closed behavior there; positive guest admission remains
        # mandatory in the launcher's actual collect/verify path.
        pattern = HEALTH.query(["cat", "/proc/sys/kernel/core_pattern"]).strip()
        if not HEALTH.CORE_PATTERN.fullmatch(pattern):
            with self.assertRaisesRegex(ValueError, "unsupported kernel crash handler"):
                HEALTH.collect()
            return
        receipt = HEALTH.collect()
        self.assertTrue(receipt["complete"])
        self.assertGreater(receipt["kernel_bytes"], 0)

    def test_native_host_probe_requires_collection_or_explicit_refusal(self):
        decorated = type(self).test_native_systemd_collection
        probe = getattr(decorated, "__wrapped__", decorated)
        for pattern in ("core", "|/usr/share/apport/apport %p %s %c %d %P"):
            with self.subTest(pattern=pattern), \
                    patch.object(HEALTH, "query", return_value=pattern), \
                    patch.object(HEALTH, "collect", side_effect=ValueError(
                        "unsupported kernel crash handler")) as collect:
                probe(self)
                collect.assert_called_once_with()
        with patch.object(HEALTH, "query", return_value="core"), \
                patch.object(HEALTH, "collect", return_value=self.payload):
            with self.assertRaises(AssertionError):
                probe(self)
        with patch.object(HEALTH, "query", return_value=channel_fixture(
                self.payload["boot_id"])["core_pattern"]), \
                patch.object(HEALTH, "collect", return_value=self.payload) as collect:
            probe(self)
            collect.assert_called_once_with()
        with patch.object(HEALTH, "query", return_value=channel_fixture(
                self.payload["boot_id"])["core_pattern"]), \
                patch.object(HEALTH, "collect", side_effect=ValueError("missing socket")):
            with self.assertRaisesRegex(ValueError, "missing socket"):
                probe(self)

    def test_collector_binds_optional_boot_argument_and_accepts_no_crashes(self):
        with patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                patch.object(HEALTH, "query", side_effect=self.processing_query(["", ""], "")) as query:
            receipt = HEALTH.collect()
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["product_crashes"], [])
        for call in query.call_args_list:
            if call.args[0][0] in ("cat", "test"):
                continue
            if call.args[0][0] == "systemctl":
                if call.args[0][-1] != "systemd-coredump@*.service":
                    self.assertIn("--property=Id,LoadState,ActiveState,SubState,Result,UnitFileState", call.args[0])
                    continue
                self.assertIn("--property=Id,ActiveState,SubState,Result", call.args[0])
                self.assertIn("systemd-coredump@*.service", call.args[0])
                continue
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

    def test_known_product_x86_traps_fail_cli_admission(self):
        command = [sys.executable, str(Path(__file__).with_name("check-qemu-health.py")),
                   "verify", "--guest", str(self.guest), "--serial", str(self.serial),
                   "--controller", str(self.controller), "--boot-id", self.payload["boot_id"]]
        for process in ("omg", "omgd"):
            for trap in ("invalid opcode", "divide error"):
                with self.subTest(process=process, trap=trap):
                    self.serial.write_text(
                        f"[  2.345] traps: {process}[123] trap {trap} "
                        f"ip:123 sp:456 error:0 in {process}[100+100]\n")
                    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("fatal guest signature", result.stderr)

    def test_x86_trap_attribution_and_benign_controls_pass(self):
        for message in ("traps: unrelated[123] trap invalid opcode ip:123 sp:456 error:0",
                        "traps: notomg[123] trap divide error ip:123 sp:456 error:0",
                        "traps: omg-worker[123] trap invalid opcode ip:123 sp:456 error:0",
                        "traps: omg[123] trap invalid opcode handler installed",
                        "traps: omgd[123] trap divide error handler installed",
                        "omg: Bus error"):
            with self.subTest(message=message):
                self.serial.write_text(message + "\n")
                self.assertEqual(self.verify(), 0)

    def test_x86_trap_signatures_redact_adjacent_evidence(self):
        for process in ("omg", "omgd"):
            for trap in ("invalid opcode", "divide error"):
                signature = f"{process}[123] trap {trap}"
                text = f"traps: {signature} ip:123 sp:456 error:0 in /private/path\n"
                self.assertEqual(HEALTH.crash_signatures(text), [signature])

    def test_product_coredump_signal6_still_rejects_admission(self):
        self.payload["product_crashes"] = [{"process": "omg", "signal": 6}]
        self.guest.write_text(json.dumps(self.payload))
        with self.assertRaisesRegex(ValueError, "guest crash"):
            self.verify()

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
                patch.object(HEALTH, "query", side_effect=self.processing_query(["", ""], core)):
            receipt = HEALTH.collect()
        self.assertEqual(receipt["product_crashes"], [{"process": "omg", "signal": 11}])
        self.guest.write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            self.verify()
        self.assertNotIn("private", json.dumps(receipt))
        self.assertNotIn("/home/bench", json.dumps(receipt))

    def processing_query(self, processors, core_rows=None, capability=None):
        """Return normal journals and successive systemd processing observations."""
        observations = iter(processors)
        if core_rows is None:
            core_rows = json.dumps({"COREDUMP_COMM": "omg-qemu-probe",
                                    "COREDUMP_EXE": "/usr/bin/python3.14", "COREDUMP_SIGNAL": "6"})

        def query(argv):
            if argv[0] == "cat":
                return "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n"
            if argv[0] == "test":
                return ""
            if argv[-1] in ("systemd-coredump.socket", "systemd-coredump@omg-health.service"):
                if isinstance(capability, Exception):
                    raise capability
                if capability is not None:
                    return capability
                if argv[-1].endswith(".socket"):
                    return ("Id=systemd-coredump.socket\nLoadState=loaded\nActiveState=active\n"
                            "SubState=listening\nResult=success\nUnitFileState=static\n")
                return ("Id=systemd-coredump@omg-health.service\nLoadState=loaded\n"
                        "ActiveState=inactive\nSubState=dead\nResult=success\nUnitFileState=static\n")
            if argv[0] == "systemctl":
                observed = next(observations)
                if isinstance(observed, Exception):
                    raise observed
                return observed
            return "Linux version 6.12\n" if "--dmesg" in argv else core_rows

        return query

    def test_empty_journal_without_crash_capability_is_incomplete(self):
        for capability in ("", "Id=systemd-coredump.socket\nLoadState=not-found\n",
                           "Id=systemd-coredump.socket\nLoadState=masked\n",
                           ValueError("crash capability query failed")):
            with self.subTest(capability=capability), \
                    patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                    patch.object(HEALTH, "query", side_effect=self.processing_query(["", ""], "", capability)):
                with self.assertRaises(ValueError):
                    HEALTH.collect()

    def test_legacy_empty_crash_receipt_cannot_admit(self):
        self.guest.write_text(json.dumps(dict(self.payload, schema_version=1)))
        with self.assertRaises(ValueError):
            self.verify()
        self.payload.pop("crash_channel", None)
        self.guest.write_text(json.dumps(self.payload))
        with self.assertRaises(ValueError):
            self.verify()

    def test_unhealthy_socket_or_template_cannot_admit_empty_journal(self):
        for unit in ("systemd-coredump.socket", "systemd-coredump@omg-health.service"):
            for field, value in (("LoadState", "not-found"), ("LoadState", "masked"),
                                 ("UnitFileState", "disabled"), ("ActiveState", "activating"),
                                 ("ActiveState", "failed"), ("Result", "exit-code"),
                                 ("SubState", "failed")):
                original = self.processing_query(["", ""], "")

                def query(argv):
                    result = original(argv)
                    if argv[-1] == unit:
                        lines = dict(line.split("=", 1) for line in result.splitlines())
                        lines[field] = value
                        return "\n".join(f"{key}={item}" for key, item in lines.items())
                    return result

                with self.subTest(unit=unit, field=field, value=value), \
                        patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                        patch.object(HEALTH, "query", side_effect=query):
                    with self.assertRaises(ValueError):
                        HEALTH.collect()

    def test_wrong_handler_or_missing_executable_cannot_admit(self):
        for pattern, unavailable in (("core", False), ("|/usr/share/apport/apport %p", False),
                                     ("|/usr/lib/systemd/systemd-coredump --backtrace", False),
                                     ("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %I %d", False),
                                     (channel_fixture(self.payload["boot_id"])["core_pattern"], True)):
            original = self.processing_query(["", ""], "")

            def query(argv):
                if argv[0] == "cat":
                    return pattern
                if argv[0] == "test" and unavailable:
                    raise ValueError("crash handler unavailable")
                return original(argv)

            with self.subTest(pattern=pattern, unavailable=unavailable), \
                    patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                    patch.object(HEALTH, "query", side_effect=query):
                with self.assertRaises(ValueError):
                    HEALTH.collect()

    def test_capability_loss_or_boot_change_during_collection_cannot_admit(self):
        for changed_boot in (False, True):
            original = self.processing_query(["", ""], "")
            sockets = 0

            def query(argv):
                nonlocal sockets
                result = original(argv)
                if argv[-1] == "systemd-coredump.socket":
                    sockets += 1
                    if sockets == 2 and not changed_boot:
                        return result.replace("ActiveState=active", "ActiveState=inactive")
                return result

            with self.subTest(changed_boot=changed_boot), \
                    patch.object(HEALTH.Path, "read_text", side_effect=[self.payload["boot_id"],
                                 "00000000-1111-2222-3333-555555555555"]), \
                    patch.object(HEALTH, "query", side_effect=query):
                with self.assertRaises(ValueError):
                    HEALTH.collect()

    def test_receipt_requires_positive_same_boot_capability(self):
        for field, value in (("boot_id", "00000000-1111-2222-3333-555555555555"),
                             ("handler_executable", False), ("socket", {}),
                             ("processor", {}), ("core_pattern", "core"), ("kind", "unknown")):
            channel = channel_fixture(self.payload["boot_id"])
            channel[field] = value
            self.guest.write_text(json.dumps(dict(self.payload, crash_channel=channel)))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()

    def test_pending_or_failed_processor_cannot_admit_clean_journals(self):
        for state, substate, result in (("activating", "start-pre", "success"),
                                       ("active", "running", "success"),
                                       ("deactivating", "stop-sigterm", "success"),
                                       ("failed", "failed", "exit-code")):
            processor = ("Id=systemd-coredump@1-4098-1046_4712-0.service\n"
                         f"ActiveState={state}\nSubState={substate}\nResult={result}\n")
            with self.subTest(state=state), \
                    patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                    patch.object(HEALTH, "query", side_effect=self.processing_query([processor])):
                with self.assertRaisesRegex(ValueError, "coredump|crash"):
                    HEALTH.collect()

    def test_processor_starting_during_collection_cannot_pass(self):
        processor = ("Id=systemd-coredump@1-4098-1046_4712-0.service\n"
                     "ActiveState=activating\nSubState=start-pre\nResult=success\n")
        with patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                patch.object(HEALTH, "query", side_effect=self.processing_query(["", processor])):
            with self.assertRaisesRegex(ValueError, "coredump|crash"):
                HEALTH.collect()

    def test_unavailable_processing_query_cannot_pass(self):
        for error in (ValueError("crash health query failed"),
                      subprocess.TimeoutExpired(["systemctl", "show"], 15)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                    patch.object(HEALTH, "query", side_effect=self.processing_query([error])):
                with self.assertRaises(type(error)):
                    HEALTH.collect()

    def test_completed_processor_and_empty_controls_preserve_clean_collection(self):
        completed = ("Id=systemd-coredump@1-4098-1046_4712-0.service\n"
                     "ActiveState=inactive\nSubState=dead\nResult=success\n")
        for processors in (["", ""], [completed, completed]):
            with self.subTest(processors=processors), \
                    patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                    patch.object(HEALTH, "query", side_effect=self.processing_query(processors)):
                receipt = HEALTH.collect()
            self.assertTrue(receipt["complete"])
            self.assertEqual(receipt["product_crashes"], [])
            self.assertEqual(receipt["boot_id"], self.payload["boot_id"])

    def test_invalid_processing_identity_or_state_cannot_pass(self):
        completed = ("Id=systemd-coredump@1-4098-1046_4712-0.service\n"
                     "ActiveState=inactive\nSubState=dead\nResult=success\n")
        for malformed in ("{", completed.replace("Result=success\n", ""),
                          completed + "Result=success\n",
                          completed.replace("systemd-coredump@", "unrelated@"),
                          completed.replace("ActiveState=inactive", "ActiveState=future-state"),
                          completed.replace("Result=success", "Result=true")):
            with self.subTest(processor=malformed), \
                    patch.object(HEALTH.Path, "read_text", return_value=self.payload["boot_id"]), \
                    patch.object(HEALTH, "query", side_effect=self.processing_query([malformed])):
                with self.assertRaises(ValueError):
                    HEALTH.collect()

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

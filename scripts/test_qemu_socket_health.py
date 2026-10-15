"""Declared OS-response fixtures for real health CLI collection; no native queries."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "socket_health_subject", Path(__file__).with_name("check-qemu-health.py"))
HEALTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HEALTH)
BOOT = "00000000-1111-2222-3333-444444444444"
PATTERN = "@@/run/systemd/coredumpd/kernel"
NAME = "/run/systemd/coredumpd/kernel"
COOKIE = (123, 456)
MANAGER = {
    "Id": "systemd-coredumpd.service", "LoadState": "loaded", "ActiveState": "active",
    "SubState": "running", "Result": "success", "UnitFileState": "enabled",
    "MainPID": "4242", "ControlGroup": "/system.slice/systemd-coredumpd.service",
    "PrivateNetwork": "yes", "ExecMainStartTimestampMonotonic": "1000000",
    "ConditionResult": "yes", "AssertResult": "yes",
    "Upholds": "systemd-coredump-register.service",
}
REGISTRATION = {
    "Id": "systemd-coredump-register.service", "LoadState": "loaded", "ActiveState": "active",
    "SubState": "exited", "Result": "success", "UnitFileState": "static",
    "ExecMainCode": "1", "ExecMainStatus": "0", "ExecMainStartTimestampMonotonic": "1000001",
    "ConditionResult": "yes", "AssertResult": "yes", "BindsTo": "systemd-coredumpd.service",
    "RefuseManualStart": "yes", "RefuseManualStop": "yes",
}
IDENTITY = {
    "pid": 4242, "start_ticks": 500, "namespace_inode": 900, "cgroup_pids": [4242],
    "subgroup_count": 0, "executable": "/usr/lib/systemd/systemd-coredump",
    "executable_uid": 0, "executable_mode": 0o100755, "socket_inode": 9001,
    "socket_fds": [7], "vfs_inode": 800, "vfs_major": 0, "vfs_minor": 32,
    "socket_uid": 0, "parent_uids": [0, 0, 0], "parent_modes": [0o40755] * 3,
    "endpoint_socket_inodes": [9001],
}
LISTENER = {
    "inode": 9001, "cookie": [123, 456], "name": NAME, "vfs_inode": 800,
    "vfs_major": 0, "vfs_minor": 32, "rqueue": 0, "wqueue": 4, "uid": 0, "shutdown": 0,
}


def attribute(kind, payload):
    length = len(payload) + 4
    return struct.pack("=HH", length, kind) + payload + bytes((-length) % 4)


class DeclaredOS:
    def __init__(self, fault=None, legacy=False):
        self.fault = fault
        self.legacy = legacy
        self.discovery_count = 0
        self.manager_reads = 0
        self.registration_reads = 0
        self.journal_started = False
        self.history_reads = 0
        self.trace = []

    def properties(self, argv, fields):
        if (len(argv) != 5 or argv[:3] != ["systemctl", "show", "--all"]
                or not argv[3].startswith("--property=")):
            raise AssertionError("undeclared systemctl argv: " + repr(argv))
        requested = argv[3].removeprefix("--property=").split(",")
        if len(requested) != len(set(requested)) or set(requested) != set(fields):
            raise AssertionError("undeclared systemctl property set: " + repr(argv))
        return "".join(key + "=" + fields[key] + "\n" for key in requested)

    def query(self, argv):
        self.trace.append(list(argv))
        if argv == ["cat", "/proc/sys/kernel/core_pattern"]:
            return ("|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"
                    if self.legacy else PATTERN) + "\n"
        if argv == ["test", "-x", "/usr/lib/systemd/systemd-coredump"] and self.legacy:
            return ""
        if argv and argv[0] == "systemctl":
            unit = argv[-1]
            if unit == "systemd-coredump@*.service":
                return self.empty_workers(argv)
            if unit == "systemd-coredumpd.service":
                fields = dict(MANAGER)
                self.manager_reads += 1
                if self.fault == "manager-pid-changes" and self.manager_reads > 1:
                    fields["MainPID"] = "4243"
                if self.fault in ("manager-disabled", "manager-indirect"):
                    fields["UnitFileState"] = self.fault.removeprefix("manager-")
                return self.properties(argv, fields)
            if unit == "systemd-coredump-register.service":
                fields = dict(REGISTRATION)
                self.registration_reads += 1
                if (self.fault == "transient-registration-after-observation"
                        and self.registration_reads == 2 and not self.journal_started):
                    fields["Result"] = "exit-code"
                    fields["ExecMainStatus"] = "1"
                if self.fault == "registration-missing":
                    fields["LoadState"] = "not-found"
                if self.fault == "registration-failed":
                    fields["Result"] = "exit-code"
                    fields["ExecMainStatus"] = "1"
                if self.fault == "registration-before-manager":
                    fields["ExecMainStartTimestampMonotonic"] = "999999"
                if self.fault in ("registration-disabled", "registration-indirect"):
                    fields["UnitFileState"] = self.fault.removeprefix("registration-")
                return self.properties(argv, fields)
            if self.legacy and unit in ("systemd-coredump.socket", "systemd-coredump@omg-health.service"):
                fields = {"Id": unit, "LoadState": "loaded", "Result": "success", "UnitFileState": "static",
                          "ActiveState": "active" if unit.endswith(".socket") else "inactive",
                          "SubState": "listening" if unit.endswith(".socket") else "dead"}
                return self.properties(argv, fields)
        kernel = ["journalctl", "--boot=" + BOOT.replace("-", ""), "--dmesg", "--quiet", "--no-pager", "--output=cat"]
        cores = ["journalctl", "--boot=" + BOOT.replace("-", ""), "--quiet", "--no-pager", "--output=json",
                 "--output-fields=COREDUMP_COMM,COREDUMP_EXE,COREDUMP_SIGNAL", "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1"]
        if argv == kernel:
            self.journal_started = True
            return "Linux version 7.2.9 declared fixture\n"
        if argv == cores:
            return ""
        manager_history = ["journalctl", "--boot=" + BOOT.replace("-", ""), "--quiet", "--no-pager", "--output=json",
                           "--output-fields=_BOOT_ID,_SYSTEMD_UNIT,PRIORITY", "--priority=warning",
                           "_SYSTEMD_UNIT=systemd-coredumpd.service"]
        if argv == manager_history:
            self.history_reads += 1
            if self.fault == "history-timeout":
                raise subprocess.TimeoutExpired(argv, 1)
            if self.fault == "history-query-failed":
                raise ValueError("declared manager history query failed")
            if self.fault == "history-query-oversized":
                raise ValueError("declared manager history query exceeded output limit")
            if self.fault == "history-second-warning" and self.history_reads == 2:
                return '{"_BOOT_ID":"00000000111122223333444444444444","_SYSTEMD_UNIT":"systemd-coredumpd.service","PRIORITY":"4"}\n'
            history_rows = {
                "history-auto-fields": '{"__CURSOR":"fixture","__REALTIME_TIMESTAMP":"1","__MONOTONIC_TIMESTAMP":"2","_BOOT_ID":"00000000111122223333444444444444","_SYSTEMD_UNIT":"systemd-coredumpd.service","PRIORITY":"4"}',
                "history-malformed": "not-json PRIVATE-HISTORY-SENTINEL",
                "history-duplicate": '{"PRIORITY":"4","PRIORITY":"4"}',
                "history-wrong-boot": '{"_BOOT_ID":"wrong","PRIORITY":"4"}',
                "history-boolean-priority": '{"PRIORITY":true}',
                "history-numeric-priority": '{"PRIORITY":4}',
            }
            if self.fault in history_rows:
                return history_rows[self.fault] + "\n"
            if self.fault == "completed-manager-worker-warning":
                return ('{"_BOOT_ID":"00000000111122223333444444444444",'
                        '"_SYSTEMD_UNIT":"systemd-coredumpd.service","PRIORITY":"4"}\n')
            return ""
        if argv and argv[0] == "/usr/bin/nsenter":
            return self.transport(argv)
        raise AssertionError("undeclared OS query: " + repr(argv))

    @staticmethod
    def empty_workers(argv):
        expected = ["systemctl", "show", "--all", "--property=Id,ActiveState,SubState,Result", "systemd-coredump@*.service"]
        if argv != expected:
            raise AssertionError("undeclared legacy worker query")
        return ""

    def transport(self, argv):
        if (len(argv) != 14 or argv[:9] != ["/usr/bin/nsenter", "--target", "4242", "--net", "--",
                                          "/usr/bin/python3", "-I", "-B", "-c"]
                or not isinstance(argv[9], str) or not argv[9].strip() or argv[10] != "4242"
                or any(not re.fullmatch(r"0|[1-9][0-9]*", value) for value in argv[11:14])):
            raise AssertionError("undeclared namespace transport argv")
        low, high, sequence = map(int, argv[11:14])
        if not 0 < sequence <= 0xFFFFFFFF or any(value > 0xFFFFFFFF for value in (low, high)):
            raise AssertionError("invalid literal request numbers")
        if (low, high) == (0xFFFFFFFF, 0xFFFFFFFF):
            self.discovery_count += 1
        elif (low, high) != COOKIE:
            raise AssertionError("unexpected exact cookie request")
        if self.fault == "query-timeout":
            raise subprocess.TimeoutExpired(argv, 1)
        identity = copy.deepcopy(IDENTITY)
        if self.fault == "live-worker":
            identity["cgroup_pids"] = [4242, 4243]
        if self.fault == "subgroup":
            identity["subgroup_count"] = 1
        if self.fault == "accepted-before-fork":
            identity["endpoint_socket_inodes"] = [9001, 9002]
        if self.fault == "embryonic-endpoint":
            identity["endpoint_socket_inodes"] = [9001, 0]
        if self.fault == "start-changes" and self.discovery_count >= 2:
            identity["start_ticks"] = 501
        if self.fault == "boolean-identity":
            identity["start_ticks"] = True
        if self.fault == "writable-executable":
            identity["executable_mode"] = 0o100775
        if self.fault == "unsafe-parent":
            identity["parent_modes"][2] = 0o40777
        reply_cookie = (123, 457) if self.fault == "cookie-mismatch" and (low, high) != (0xFFFFFFFF, 0xFFFFFFFF) else COOKIE
        record = struct.pack("=BBBBIII", 1, 1, 10, 0, 9001, *reply_cookie)
        attributes = attribute(0, NAME.encode() + b"\0") + attribute(1, struct.pack("=II", 800, 32))
        if self.fault != "missing-queue":
            queue_data = struct.pack("=I", 0) if self.fault == "short-queue" else struct.pack("=II", 1 if self.fault == "pending-queue" else 0, 4)
            attributes += attribute(4, queue_data)
        attributes += attribute(6, b"\0") + attribute(7, struct.pack("=I", 0))
        request = struct.pack("=IHHIIBBHIIIII", 40, 20, 1, sequence, 4321, 1, 0, 0, 1024, 9001, 83, low, high)
        reply = struct.pack("=IHHII", 16 + len(record) + len(attributes), 20, 0, sequence, 4321) + record + attributes
        result = {"identity": identity, "request_hex": request.hex(), "reply_hex": reply.hex(),
                  "sender": [0, 0], "msg_flags": 0, "ancillary_count": 0, "port_id": 4321,
                  "sequence": sequence, "namespace_inode": 901 if self.fault == "namespace-mismatch" else 900}
        if self.fault == "malformed-transport":
            return "{not-json"
        if self.fault == "oversized-transport":
            return " " * (1048576 + 1) + json.dumps(result)
        if self.fault == "duplicate-json-key":
            return json.dumps(result)[:-1] + ', "port_id": 4321}'
        return json.dumps(result)


class SocketHealthTests(unittest.TestCase):
    def collect(self, fault=None, legacy=False):
        fixture = DeclaredOS(fault, legacy)
        output, errors = io.StringIO(), io.StringIO()

        def boot_read(path, *args, **kwargs):
            if str(path).replace("\\", "/") != "/proc/sys/kernel/random/boot_id":
                raise AssertionError("undeclared boot/file read: " + str(path))
            return BOOT + "\n"

        with patch.object(sys, "argv", ["check-qemu-health.py", "collect"]), \
                patch.object(HEALTH.Path, "read_text", boot_read), \
                patch.object(HEALTH, "query", fixture.query), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = HEALTH.main()
        return code, output.getvalue(), errors.getvalue(), fixture.trace

    def test_socket_mode_collects_literal_healthy_channel(self):
        code, output, errors, trace = self.collect()
        self.assertEqual(code, 0, "real HEALTH.main refused declared healthy socket fixture: " + errors)
        self.assertEqual(errors, "")
        self.assertEqual(json.loads(output), {
            "schema_version": 2, "complete": True, "boot_id": BOOT,
            "crash_channel": {"kind": "systemd-coredump-kernel-socket", "boot_id": BOOT,
                              "core_pattern": PATTERN, "manager": MANAGER, "registration": REGISTRATION,
                              "identity": IDENTITY, "listener": LISTENER, "manager_warning_count": 0},
            "kernel_bytes": 37, "fatal_signatures": [], "product_crashes": [],
        })

    def test_socket_mode_refuses_completed_manager_warning_after_worker_retired(self):
        code, output, errors, _ = self.collect("completed-manager-worker-warning")
        self.assertEqual(code, 2, "completed manager warning was accepted as healthy: " + output)
        self.assertEqual(output, "")

    def test_socket_mode_refuses_nonempty_history_without_exporting_content(self):
        for fault in ("history-auto-fields", "history-malformed", "history-duplicate",
                      "history-wrong-boot", "history-boolean-priority", "history-numeric-priority"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""))
                self.assertNotIn("PRIVATE-HISTORY-SENTINEL", errors)

    def test_socket_mode_refuses_warning_only_in_final_history_snapshot(self):
        code, output, errors, _ = self.collect("history-second-warning")
        self.assertEqual((code, output), (2, ""), errors)

    def test_socket_mode_refuses_unavailable_history_query(self):
        for fault in ("history-timeout", "history-query-failed", "history-query-oversized"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""), errors)

    def test_socket_mode_refuses_pending_or_missing_queue(self):
        for fault in ("pending-queue", "missing-queue", "short-queue"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertIn("QEMU health evidence failed admission:", errors)

    def test_socket_mode_refuses_workers_or_unstable_identity(self):
        for fault in ("live-worker", "subgroup", "start-changes", "manager-pid-changes",
                      "boolean-identity", "writable-executable", "unsafe-parent", "cookie-mismatch", "namespace-mismatch"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("QEMU health evidence failed admission:", errors)

    def test_socket_mode_refuses_accepted_connection_before_worker_fork(self):
        for fault in ("accepted-before-fork", "embryonic-endpoint"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("QEMU health evidence failed admission:", errors)

    def test_socket_mode_refuses_transient_registration_failure_before_journals(self):
        code, output, errors, _ = self.collect("transient-registration-after-observation")
        self.assertEqual((code, output), (2, ""))
        self.assertIn("QEMU health evidence failed admission:", errors)

    def test_socket_mode_refuses_missing_or_failed_registration(self):
        for fault in ("registration-missing", "registration-failed", "registration-before-manager"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("QEMU health evidence failed admission:", errors)

    def test_socket_mode_refuses_disabled_or_indirect_unit_states(self):
        for fault in ("manager-disabled", "manager-indirect", "registration-disabled", "registration-indirect"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("QEMU health evidence failed admission:", errors)

    def test_socket_mode_refuses_malformed_oversized_or_timed_out_transport(self):
        for fault in ("malformed-transport", "oversized-transport", "query-timeout", "duplicate-json-key"):
            with self.subTest(fault=fault):
                code, output, errors, _ = self.collect(fault)
                self.assertEqual((code, output), (2, ""))
                self.assertIn("QEMU health evidence failed admission:", errors)

    def test_legacy_pipe_collect_control_preserves_schema(self):
        code, output, errors, _ = self.collect(legacy=True)
        self.assertEqual((code, errors), (0, ""))
        payload = json.loads(output)
        self.assertEqual((payload["schema_version"], payload["boot_id"], payload["complete"]), (2, BOOT, True))
        self.assertEqual(payload["crash_channel"]["kind"], "systemd-coredump-pipe")
        self.assertEqual(payload["product_crashes"], [])


def saved_payload(boot=BOOT):
    return {
        "schema_version": 2, "complete": True, "boot_id": boot,
        "crash_channel": {"kind": "systemd-coredump-kernel-socket", "boot_id": boot,
                          "core_pattern": PATTERN, "manager": copy.deepcopy(MANAGER),
                          "registration": copy.deepcopy(REGISTRATION), "identity": copy.deepcopy(IDENTITY),
                          "listener": copy.deepcopy(LISTENER), "manager_warning_count": 0},
        "kernel_bytes": 37, "fatal_signatures": [], "product_crashes": [],
    }


class SavedSocketHealthTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.guest = self.root / "guest.json"
        self.serial = self.root / "serial.log"
        self.controller = self.root / "controller.json"
        self.serial.write_text("Linux version 7.2.9 declared fixture\n", encoding="utf-8")
        self.controller.write_text('{"Running":true,"OOMKilled":false,"ExitCode":0}', encoding="utf-8")
        self.guest.write_text(json.dumps(saved_payload()), encoding="utf-8")

    def cli(self, arguments):
        return subprocess.run(
            [sys.executable, "-X", "utf8", "-I", "-B", HEALTH.__file__, *arguments],
            capture_output=True, text=True, encoding="utf-8", timeout=10)

    def trial_arguments(self, boot=BOOT):
        return ["verify-trial", "--guest", str(self.guest), "--serial", str(self.serial), "--boot-id", boot]

    def assert_success(self, arguments):
        result = self.cli(arguments)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def assert_refusal(self, arguments):
        result = self.cli(arguments)
        self.assertEqual((result.returncode, result.stdout), (2, ""), result.stderr)
        self.assertIn("QEMU health evidence failed admission:", result.stderr)

    def test_saved_trial_accepts_literal_complete_socket_channel(self):
        self.assert_success(self.trial_arguments())

    def test_saved_trial_refuses_missing_or_forged_socket_fields(self):
        self.assert_success(self.trial_arguments())
        variants = []
        for field in ("manager", "registration", "identity", "listener"):
            payload = saved_payload()
            del payload["crash_channel"][field]
            variants.append(("missing-" + field, payload))
        for section, field, value in (
            (None, "kind", "systemd-coredump-pipe"),
            (None, "core_pattern", "@@/private/forged"),
            ("manager", "MainPID", "4243"),
            ("manager", "UnitFileState", "disabled"),
            ("manager", "UnitFileState", "indirect"),
            ("registration", "ExecMainStatus", "1"),
            ("registration", "UnitFileState", "disabled"),
            ("registration", "UnitFileState", "indirect"),
            ("identity", "pid", True),
            ("identity", "subgroup_count", False),
            ("identity", "socket_uid", False),
            ("identity", "endpoint_socket_inodes", [9001, 9002]),
            ("identity", "endpoint_socket_inodes", [9001, 0]),
            ("listener", "rqueue", False),
            ("listener", "rqueue", 1),
            ("listener", "cookie", [0xFFFFFFFF, 0xFFFFFFFF]),
        ):
            payload = saved_payload()
            target = payload["crash_channel"] if section is None else payload["crash_channel"][section]
            target[field] = value
            variants.append((str(section) + "." + field + "=" + repr(value), payload))
        for label, payload in variants:
            with self.subTest(label=label):
                self.guest.write_text(json.dumps(payload), encoding="utf-8")
                self.assert_refusal(self.trial_arguments())

    def test_saved_trial_requires_exact_zero_manager_warning_witness(self):
        self.assert_success(self.trial_arguments())
        for value in (True, False, 0.0, "0", 1, -1, None):
            with self.subTest(value=value):
                payload = saved_payload()
                payload["crash_channel"]["manager_warning_count"] = value
                self.guest.write_text(json.dumps(payload), encoding="utf-8")
                self.assert_refusal(self.trial_arguments())
        payload = saved_payload()
        del payload["crash_channel"]["manager_warning_count"]
        self.guest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_refusal(self.trial_arguments())

    def test_saved_preparations_refuse_missing_history_witness(self):
        self.preparation_files()
        arguments = ["verify-preparations", "--root", str(self.root)]
        self.assert_success(arguments)
        health = self.root / "transactions/prepare-install-health.json"
        payload = json.loads(health.read_text(encoding="utf-8"))
        del payload["crash_channel"]["manager_warning_count"]
        health.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_refusal(arguments)

    def test_saved_final_refuses_nonzero_history_witness(self):
        arguments = ["verify", "--guest", str(self.guest), "--serial", str(self.serial),
                     "--controller", str(self.controller), "--boot-id", BOOT]
        self.assert_success(arguments)
        payload = saved_payload()
        payload["crash_channel"]["manager_warning_count"] = 1
        self.guest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_refusal(arguments)

    def test_saved_trial_requires_exact_boot_binding(self):
        self.assert_success(self.trial_arguments())
        self.assert_refusal(self.trial_arguments("00000000-1111-2222-3333-555555555555"))

    def preparation_files(self):
        (self.root / "transactions").mkdir()
        (self.root / "guest").mkdir()
        (self.root / "guest/serial.log").write_text("Linux version 7.2.9\n", encoding="utf-8")
        second_boot = "00000000-1111-2222-3333-555555555555"
        for operation, boot in (("remove", BOOT), ("install", second_boot)):
            prefix = self.root / "transactions" / ("prepare-" + operation)
            Path(str(prefix) + "-boot-id.txt").write_text(boot + "\n", encoding="utf-8")
            Path(str(prefix) + "-health.json").write_text(json.dumps(saved_payload(boot)), encoding="utf-8")
            if operation == "install":
                Path(str(prefix) + "-serial.log").write_text("Linux version 7.2.9\n", encoding="utf-8")

    def test_saved_preparations_accept_two_literal_distinct_socket_boots_and_refuse_forgery(self):
        self.preparation_files()
        arguments = ["verify-preparations", "--root", str(self.root)]
        self.assert_success(arguments)
        health = self.root / "transactions/prepare-install-health.json"
        payload = json.loads(health.read_text(encoding="utf-8"))
        payload["crash_channel"]["identity"]["endpoint_socket_inodes"] = [9001, 0]
        health.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_refusal(arguments)

    def test_saved_final_accepts_literal_socket_channel_and_requires_controller_health(self):
        arguments = ["verify", "--guest", str(self.guest), "--serial", str(self.serial),
                     "--controller", str(self.controller), "--boot-id", BOOT]
        self.assert_success(arguments)
        self.controller.write_text('{"Running":true,"OOMKilled":false,"ExitCode":1}', encoding="utf-8")
        self.assert_refusal(arguments)

    def test_saved_final_refuses_missing_queue_field(self):
        arguments = ["verify", "--guest", str(self.guest), "--serial", str(self.serial),
                     "--controller", str(self.controller), "--boot-id", BOOT]
        self.assert_success(arguments)
        payload = saved_payload()
        del payload["crash_channel"]["listener"]["rqueue"]
        self.guest.write_text(json.dumps(payload), encoding="utf-8")
        self.assert_refusal(arguments)


if __name__ == "__main__":
    unittest.main()

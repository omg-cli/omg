"""Exercise the controller's guest boot gate with completed and failed cloud-init records."""

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/check-qemu-cloud-init.sh"


def healthy_status():
    stage = {"errors": [], "recoverable_errors": {}, "finished": 100.0}
    return {"v1": {"datasource": "DataSourceNoCloud [seed=/dev/vdb]", "stage": None,
                   **{name: dict(stage) for name in
                      ("init-local", "init", "modules-config", "modules-final")}}}


class CloudInitReadyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for command in ("bash", "jq", "timeout"):
            if not shutil.which(command):
                raise RuntimeError(f"{command} is required for cloud-init readiness tests")

    def check(self, status, *, result=True, target_ready_after=1, failed_unit="",
              status_exit=0, target_exit=0, diagnostic_exit=0, status_timeout=False,
              diagnostic_journal_bytes=0, status_resets=0, target_resets=0, timeout_seconds=180):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp / "status.json").write_text(json.dumps(status), encoding="utf-8")
            records = temp / "cloud-init"
            records.mkdir()
            (records / "status.json").write_text(json.dumps(status), encoding="utf-8")
            (records / "result.json").write_text('{"errors": []}\n', encoding="utf-8")
            before = {record.name: record.read_bytes() for record in records.iterdir()}
            (temp / "journal.txt").write_text("fixture-journal-ssh-restart\n" + "x" * diagnostic_journal_bytes)
            ssh = temp / "ssh"
            ssh.write_text("""#!/usr/bin/env bash
if [[ "$*" == *'cloud_init_record='* ]]; then
  echo diagnostic >> "$MOCK_SSH_CALLS"
  script="${@: -1}"
  prefix=/run/cloud-init
  script="${script//"$prefix"/"$MOCK_CLOUD_INIT_DIR"}"
  bash -c "$script"
  exit "$MOCK_DIAGNOSTIC_EXIT"
elif [[ "$*" == *'/run/cloud-init/result.json'* ]]; then
  echo status >> "$MOCK_SSH_CALLS"
  calls=0
  [[ ! -e "$MOCK_STATUS_CALLS" ]] || read -r calls < "$MOCK_STATUS_CALLS"
  printf '%s\\n' "$((calls + 1))" > "$MOCK_STATUS_CALLS"
  (( calls >= MOCK_STATUS_RESETS )) || exit 255
  if [[ "$MOCK_STATUS_TIMEOUT" == yes ]]; then sleep 5; fi
  if (( MOCK_STATUS_EXIT != 0 )); then
    echo 'cloud-final.service failed before publishing result.json' >&2
    exit "$MOCK_STATUS_EXIT"
  fi
  [[ "$MOCK_RESULT" == present ]] || exit 1
  cat "$MOCK_STATUS"
else
  echo target >> "$MOCK_SSH_CALLS"
  if (( MOCK_TARGET_EXIT != 0 )); then exit "$MOCK_TARGET_EXIT"; fi
  calls=0
  [[ ! -e "$MOCK_SSH_TARGET_CALLS" ]] || read -r calls < "$MOCK_SSH_TARGET_CALLS"
  printf '%s\\n' "$((calls + 1))" > "$MOCK_SSH_TARGET_CALLS"
  (( calls >= MOCK_TARGET_RESETS )) || exit 255
  bash -c "${@: -1}"
fi
""", encoding="utf-8")
            ssh.chmod(0o755)
            systemctl = temp / "systemctl"
            systemctl.write_text("""#!/usr/bin/env bash
if [[ "$1" == show ]]; then
  printf 'Id=cloud-config.service\\nActiveState=failed\\nExecMainStatus=1\\n'
elif [[ "$1" == is-failed ]]; then
  [[ "$3" == "$MOCK_FAILED_UNIT" ]]
elif [[ "$1" == is-active && "$3" == cloud-init.target ]]; then
  count=0
  [[ ! -e "$MOCK_TARGET_CALLS" ]] || read -r count < "$MOCK_TARGET_CALLS"
  count=$((count + 1))
  printf '%s\\n' "$count" > "$MOCK_TARGET_CALLS"
  (( count >= MOCK_TARGET_READY_AFTER ))
else
  exit 1
fi
""", encoding="utf-8")
            systemctl.chmod(0o755)
            sudo = temp / "sudo"
            sudo.write_text('#!/usr/bin/env bash\n[[ "$1" == -n ]] || exit 3\nshift\nexec "$@"\n')
            sudo.chmod(0o755)
            journalctl = temp / "journalctl"
            journalctl.write_text('#!/usr/bin/env bash\ncat "$MOCK_JOURNAL"\n')
            journalctl.chmod(0o755)
            if status_timeout:
                timeout = temp / "timeout"
                timeout.write_text(f'''#!/usr/bin/env bash
if [[ "$1" == --kill-after=5s && "$2" == 180s ]]; then
  shift 2
  exec "{shutil.which("timeout")}" --kill-after=1s 0.1s "$@"
fi
exec "{shutil.which("timeout")}" "$@"
''', encoding="utf-8")
                timeout.chmod(0o755)
            env = dict(os.environ, PATH=f"{temp}{os.pathsep}{os.environ['PATH']}",
                       MOCK_STATUS=str(temp / "status.json"),
                       MOCK_RESULT="present" if result else "missing",
                       MOCK_TARGET_CALLS=str(temp / "target-calls"),
                       MOCK_TARGET_READY_AFTER=str(target_ready_after),
                       MOCK_FAILED_UNIT=failed_unit,
                       MOCK_SSH_CALLS=str(temp / "ssh-calls"),
                       MOCK_STATUS_EXIT=str(status_exit),
                       MOCK_TARGET_EXIT=str(target_exit),
                       MOCK_DIAGNOSTIC_EXIT=str(diagnostic_exit),
                       MOCK_CLOUD_INIT_DIR=str(records),
                       MOCK_JOURNAL=str(temp / "journal.txt"),
                       MOCK_STATUS_TIMEOUT="yes" if status_timeout else "no",
                       MOCK_STATUS_CALLS=str(temp / "status-calls"),
                       MOCK_SSH_TARGET_CALLS=str(temp / "ssh-target-calls"),
                       MOCK_STATUS_RESETS=str(status_resets),
                       MOCK_TARGET_RESETS=str(target_resets),
                       OMG_QEMU_CLOUD_INIT_TIMEOUT_SECONDS=str(timeout_seconds))
            completed = subprocess.run(["bash", str(CHECK), "bench@127.0.0.1", "-p", "2222"],
                                       env=env, text=True, capture_output=True, timeout=20)
            calls = int((temp / "target-calls").read_text()) if (temp / "target-calls").exists() else 0
            self.assertEqual({record.name: record.read_bytes() for record in records.iterdir()}, before,
                             "diagnostic collection must preserve cloud-init record bytes")
            return completed, calls

    def test_completed_clean_nocloud_boot_passes(self):
        result, _ = self.check(healthy_status())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified", result.stdout)

    def test_target_can_activate_after_result_is_published(self):
        result, calls = self.check(healthy_status(), target_ready_after=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, 3)

    def test_transient_ssh_resets_are_retried_in_both_boot_stages(self):
        result, _ = self.check(healthy_status(), status_resets=1, target_resets=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified", result.stdout)

    def test_failed_guest_command_is_not_reported_as_a_timeout(self):
        result, _ = self.check(healthy_status(), result=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guest command failed", result.stderr)
        self.assertNotIn("within 180 seconds", result.stderr)

    def test_transport_retries_obey_the_boot_deadline(self):
        result, _ = self.check(healthy_status(), status_resets=1000, timeout_seconds=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("within 1 seconds", result.stderr)

    def test_legacy_cloud_init_without_recoverable_errors_field_passes(self):
        status = healthy_status()
        for stage in ("init-local", "init", "modules-config", "modules-final"):
            del status["v1"][stage]["recoverable_errors"]
        result, _ = self.check(status)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_result_or_failed_unit_rejects_boot(self):
        missing, _ = self.check(healthy_status(), result=False)
        self.assertNotEqual(missing.returncode, 0)
        failed, _ = self.check(healthy_status(), target_ready_after=3,
                               failed_unit="cloud-final.service")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("cloud-final.service failed", failed.stderr)

    def test_incomplete_or_degraded_stage_rejects_boot(self):
        for change in ("unfinished", "error", "recoverable", "aggregate-recoverable",
                       "wrong-datasource"):
            status = healthy_status()
            if change == "unfinished":
                status["v1"]["modules-final"]["finished"] = None
            elif change == "error":
                status["v1"]["modules-final"]["errors"] = ["failed user-data"]
            elif change == "recoverable":
                status["v1"]["init"]["recoverable_errors"] = {"WARNING": ["bad config"]}
            elif change == "aggregate-recoverable":
                # A future stage could report recoverables without a stage name
                # this gate enumerates; the aggregate must still reject them.
                status["v1"]["recoverable_errors"] = {"WARNING": ["bad config"]}
            else:
                status["v1"]["datasource"] = "DataSourceNone"
            with self.subTest(change=change):
                result, _ = self.check(status)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("incomplete, errored, or degraded", result.stderr)

    def test_guest_launch_uses_controller_status_gate(self):
        benchmark = (ROOT / "scripts/benchmark-qemu.sh").read_text(encoding="utf-8")
        self.assertIn('cp "$here/check-qemu-cloud-init.sh" "$work/check-qemu-cloud-init.sh"', benchmark)
        self.assertIn('bash /work/check-qemu-cloud-init.sh bench@127.0.0.1 "${opts[@]}"', benchmark)
        self.assertNotIn("cloud-init status --wait --long", benchmark)

    def test_status_timeout_and_explicit_stage_failure_are_distinct(self):
        timeout, _ = self.check(healthy_status(), status_timeout=True)
        self.assertEqual(timeout.returncode, 1, timeout.stderr)
        self.assertIn("timeout_ssh_exit=124", timeout.stderr)
        failed, _ = self.check(healthy_status(), status_exit=1)
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertIn("timeout_ssh_exit=1", failed.stderr)
        self.assertIn("cloud-final.service failed", failed.stderr)
        for result in (timeout, failed):
            self.assertRegex(result.stderr, r"started_utc=\d{4}-\d{2}-\d{2}T")
            self.assertRegex(result.stderr, r"ended_utc=\d{4}-\d{2}-\d{2}T")
            self.assertIn("cloud_init_record=", result.stderr)
            self.assertIn("ExecMainStatus=1", result.stderr)
            self.assertIn("fixture-journal-ssh-restart", result.stderr)
            self.assertNotIn("verified", result.stdout)

    def test_failed_diagnostic_preserves_primary_failure(self):
        status, _ = self.check(healthy_status(), status_exit=255, diagnostic_exit=7, timeout_seconds=1)
        self.assertEqual(status.returncode, 1, status.stderr)
        self.assertIn("timeout_ssh_exit=255", status.stderr)
        self.assertIn("diagnostic_exit=7", status.stderr)
        target, _ = self.check(healthy_status(), target_exit=9, diagnostic_exit=7)
        self.assertEqual(target.returncode, 9, target.stderr)
        self.assertIn("cloud_init_phase=target", target.stderr)
        self.assertIn("timeout_ssh_exit=9", target.stderr)
        self.assertIn("diagnostic_exit=7", target.stderr)

    def test_diagnostic_output_is_bounded_without_changing_failure(self):
        result, _ = self.check(healthy_status(), status_exit=1, diagnostic_journal_bytes=40000)
        self.assertEqual(result.returncode, 1, result.stderr)
        diagnostic = result.stderr.split("cloud_init_record=", 1)[1].split(
            "\ncloud_init_diagnostics_ended_utc=", 1)[0]
        self.assertEqual(len(("cloud_init_record=" + diagnostic).encode()), 16384)
        self.assertNotIn("verified", result.stdout)

    def test_actual_ssh_connection_reset_is_not_reported_as_timeout(self):
        ssh = shutil.which("ssh")
        if not ssh:
            raise RuntimeError("ssh is required for the native transport fixture")
        with socket.socket() as listener, tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = root / "boot-seconds"
            clock.write_text("0\n")
            # Real SSH and timeout still execute. Advance only the helper's
            # private clock after SSH exits so host scheduling cannot skip it.
            source, replacements = re.subn(
                r"^boot_seconds\(\) \{[^\n]*\}$",
                lambda _: 'boot_seconds() { cat "$OMG_QEMU_TEST_CLOCK"; }',
                CHECK.read_text(), flags=re.M)
            self.assertEqual(replacements, 1, "one helper clock must be controlled")
            check = root / "check.sh"
            check.write_text(source)
            wrapper = root / "ssh"
            wrapper.write_text(
                "#!/usr/bin/env bash\n"
                f"{shlex.quote(ssh)} \"$@\"\n"
                "code=$?\n"
                'printf "5\\n" > "$OMG_QEMU_TEST_CLOCK"\n'
                'exit "$code"\n')
            wrapper.chmod(0o700)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(10)
            port = listener.getsockname()[1]
            accepted = []
            errors = []

            def reset_connections():
                try:
                    for _ in range(2):
                        connection, _ = listener.accept()
                        with connection:
                            connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                                  struct.pack("ii", 1, 0))
                        accepted.append(True)
                except OSError as error:
                    errors.append(str(error))

            server = threading.Thread(target=reset_connections)
            server.start()
            try:
                result = subprocess.run(
                    ["bash", str(check), "bench@127.0.0.1", "-F", "/dev/null",
                     "-o", "BatchMode=yes", "-o", "ConnectTimeout=2",
                     "-o", "StrictHostKeyChecking=yes", "-o",
                     f"UserKnownHostsFile={directory}/known_hosts", "-p",
                     str(port)],
                    env=dict(os.environ, OMG_QEMU_CLOUD_INIT_TIMEOUT_SECONDS="5",
                             OMG_QEMU_TEST_CLOCK=str(clock),
                             PATH=str(root) + os.pathsep + os.environ["PATH"]),
                    text=True, capture_output=True, timeout=15)
            finally:
                server.join(timeout=6)
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(accepted), 2, "one primary call and one diagnostic call")
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertRegex(
                result.stderr,
                rf"(?m)^(?:kex_exchange_identification: read: )?Connection reset by "
                rf"(?:peer|127\.0\.0\.1 port {port})$",
            )
            self.assertIn("timeout_ssh_exit=255", result.stderr)
            self.assertIn("diagnostic_exit=255", result.stderr)
            self.assertNotIn("timeout_ssh_exit=124", result.stderr)
            self.assertNotIn("verified", result.stdout)


if __name__ == "__main__":
    unittest.main()

"""Exercise the controller's guest boot gate with completed and failed cloud-init records."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
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
              status_resets=0, target_resets=0, timeout_seconds=180):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp / "status.json").write_text(json.dumps(status), encoding="utf-8")
            ssh = temp / "ssh"
            ssh.write_text("""#!/usr/bin/env bash
if [[ "$*" == *'/run/cloud-init/result.json'* ]]; then
  calls=0
  [[ ! -e "$MOCK_STATUS_CALLS" ]] || read -r calls < "$MOCK_STATUS_CALLS"
  printf '%s\\n' "$((calls + 1))" > "$MOCK_STATUS_CALLS"
  (( calls >= MOCK_STATUS_RESETS )) || exit 255
  [[ "$MOCK_RESULT" == present ]] || exit 1
  cat "$MOCK_STATUS"
else
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
if [[ "$1" == is-failed ]]; then
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
            env = dict(os.environ, PATH=f"{temp}{os.pathsep}{os.environ['PATH']}",
                       MOCK_STATUS=str(temp / "status.json"),
                       MOCK_RESULT="present" if result else "missing",
                       MOCK_TARGET_CALLS=str(temp / "target-calls"),
                       MOCK_TARGET_READY_AFTER=str(target_ready_after),
                       MOCK_FAILED_UNIT=failed_unit,
                       MOCK_STATUS_CALLS=str(temp / "status-calls"),
                       MOCK_SSH_TARGET_CALLS=str(temp / "ssh-target-calls"),
                       MOCK_STATUS_RESETS=str(status_resets),
                       MOCK_TARGET_RESETS=str(target_resets),
                       OMG_QEMU_CLOUD_INIT_TIMEOUT_SECONDS=str(timeout_seconds))
            completed = subprocess.run(["bash", str(CHECK), "bench@127.0.0.1", "-p", "2222"],
                                       env=env, text=True, capture_output=True, timeout=20)
            calls = int((temp / "target-calls").read_text()) if (temp / "target-calls").exists() else 0
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


if __name__ == "__main__":
    unittest.main()

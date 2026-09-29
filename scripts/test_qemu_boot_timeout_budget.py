"""Execute the generated boot phases with stub SSH and real GNU timeout.

Only time units are shortened in fixtures; phase logic is taken from the driver.
No QEMU, privileges, network, or package mutations are needed.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "scripts" / "benchmark-qemu.sh"

SSH = r'''#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$FIXTURE/ssh.log"
cmd=${*: -1}
if [[ "$cmd" == true ]]; then
  n=$(cat "$FIXTURE/initial-count"); echo $((n+1)) > "$FIXTURE/initial-count"
  if [[ "$SCENARIO" == initial-expiry ]]; then
    trap '' TERM
    sleep 30
  fi
  if [[ "$SCENARIO" == sequential && $n -lt 2 ]]; then exit 1; fi
fi
if [[ "$*" == *'cat /proc/sys/kernel/random/boot_id'* ]]; then
  n=$(cat "$FIXTURE/reboot-count"); echo $((n+1)) > "$FIXTURE/reboot-count"
  if [[ $n == 0 ]]; then echo before
  elif [[ "$SCENARIO" == reboot-expiry || ( "$SCENARIO" == sequential && $n -lt 3 ) ]]; then echo before
  else echo after; fi
fi
if [[ "$SCENARIO" == intermediate-expiry && "$*" == *daemon-reload* ]]; then
  trap '' TERM
  sleep 30
fi
'''


class BootDeadlineExecution(unittest.TestCase):
    def run_boot(self, scenario: str):
        source = DRIVER.read_text(encoding="utf-8")
        boot = source.split("<<'BOOT'\n", 1)[1].split("\nBOOT\n", 1)[0]
        # Run the actual readiness/SSH/reboot code, not QEMU setup.
        start_marker = "# Absolute phase deadlines" if "# Absolute phase deadlines" in boot else "opts=(-i client-key -p 2222"
        phases = boot[boot.index(start_marker):]
        phases = phases.replace("SSH_WAIT_BUDGET=1680", "SSH_WAIT_BUDGET=4")
        phases = phases.replace("SSH_ATTEMPT_TIMEOUT=12", "SSH_ATTEMPT_TIMEOUT=1")
        phases = phases.replace("SSH_KILL_GRACE=2", "SSH_KILL_GRACE=1")
        phases = phases.replace("SSH_RETRY_DELAY=2", "SSH_RETRY_DELAY=1")
        phases = phases.replace("sleep 2", "sleep 1")
        phases = phases.replace("--kill-after=2s 12s", "--kill-after=1s 1s")
        with tempfile.TemporaryDirectory(prefix="omg-boot-budget-") as directory:
            work = Path(directory)
            for name in ("initial-count", "reboot-count"):
                (work / name).write_text("0\n", encoding="utf-8")
            (work / "serial.log").write_text("Linux version fixture\nserial sentinel\n", encoding="utf-8")
            (work / "qemu-startup.log").write_text("startup sentinel\n", encoding="utf-8")
            for name, script in (("ssh", SSH), ("cloud-check", "#!/usr/bin/env bash\nexit 0\n")):
                path = work / name
                path.write_text(script, encoding="utf-8")
                path.chmod(0o755)
            phases = phases.replace("/work/check-qemu-cloud-init.sh", str(work / "cloud-check"))
            (work / "boot.sh").write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\ninitial=true\nvm_serial=serial.log\n" + phases,
                encoding="utf-8",
            )
            env = dict(os.environ, PATH=f"{work}:{os.environ['PATH']}", FIXTURE=str(work), SCENARIO=scenario)
            with subprocess.Popen(["sleep", "30"]) as qemu:
                (work / "qemu.pid").write_text(str(qemu.pid), encoding="utf-8")
                start = time.monotonic()
                try:
                    result = subprocess.run(
                        ["timeout", "--kill-after=1s", "12s", "bash", str(work / "boot.sh"), "bios", "sshd"],
                        cwd=work, env=env, capture_output=True, text=True, timeout=15,
                    )
                    elapsed = time.monotonic() - start
                    calls = (work / "ssh.log").read_text(encoding="utf-8")
                finally:
                    qemu.terminate()
                    qemu.wait()
            return result, elapsed, calls

    def test_slow_initial_and_reboot_waits_both_complete(self):
        result, elapsed, calls = self.run_boot("sequential")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reboot verified: before -> after", result.stdout)
        self.assertGreaterEqual(calls.count("bench@127.0.0.1 true"), 3)
        self.assertGreaterEqual(calls.count("cat /proc/sys/kernel/random/boot_id"), 4)
        self.assertGreater(elapsed, 3)
        self.assertLess(elapsed, 12)

    def test_initial_deadline_kills_stuck_ssh_and_preserves_diagnostics(self):
        result, elapsed, calls = self.run_boot("initial-expiry")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("initial SSH readiness deadline expired", result.stderr)
        self.assertIn("kernel_banner_seen=yes", result.stderr)
        self.assertIn("serial sentinel", result.stderr)
        self.assertNotIn("daemon-reload", calls)
        self.assertLess(elapsed, 8)

    def test_reboot_deadline_preserves_diagnostics(self):
        result, elapsed, calls = self.run_boot("reboot-expiry")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("post-reboot SSH readiness deadline expired", result.stderr)
        self.assertIn("qemu_state=", result.stderr)
        self.assertIn("serial_bytes=", result.stderr)
        self.assertIn("serial sentinel", result.stderr)
        self.assertIn("systemctl reboot", calls)
        self.assertLess(elapsed, 8)

    def test_intermediate_ssh_is_bounded_even_when_it_ignores_term(self):
        result, elapsed, calls = self.run_boot("intermediate-expiry")
        self.assertIn(result.returncode, (124, 137), result.stderr)
        self.assertIn("daemon-reload", calls)
        self.assertNotIn("systemctl reboot", calls)
        self.assertLess(elapsed, 6)

    def test_executable_outer_budget_covers_every_sequential_phase(self):
        source = DRIVER.read_text(encoding="utf-8")
        host = source.split("\nBOOT\n", 1)[1]
        budget_start = host.index("SSH_WAIT_ATTEMPTS=") if "SSH_WAIT_ATTEMPTS=" in host else host.index("SSH_WAIT_BUDGET=")
        block = host[budget_start:host.index("boot_timeout=$BOOT_TIMEOUT")]
        result = subprocess.run(["bash", "-c", block + '\nprintf "%s %s" "$BOOT_TIMEOUT" "$SSH_WAIT_BUDGET"'],
                                capture_output=True, text=True, check=True)
        # Independently collect each actual executable timeout and its kill grace.
        # Readiness loops have dynamic timeouts and separate absolute deadlines.
        boot = source.split("<<'BOOT'\n", 1)[1].split("\nBOOT\n", 1)[0]
        outer, wait = map(int, result.stdout.split())
        bounded_calls = re.findall(r"timeout --kill-after=(\d+)s (\d+)s", boot)
        self.assertGreaterEqual(len(bounded_calls), 8)
        other_phases = sum(int(grace) + int(duration) for grace, duration in bounded_calls)
        self.assertGreater(outer, 2 * wait + other_phases)
        self.assertIn('timeout --kill-after=5s "$boot_timeout" docker exec', source)
        self.assertIn('OMG_QEMU_SETUP_ONLY=1 timeout --kill-after=2s 180s bash "$0" "$@"', boot)
        self.assertIn('timeout --kill-after=2s 250s bash /work/check-qemu-cloud-init.sh', boot)


if __name__ == "__main__":
    unittest.main()

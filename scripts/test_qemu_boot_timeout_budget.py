"""Source-bound CPU/shell boot contracts. No VM or networking is exercised."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "scripts/benchmark-qemu.sh"
TRANSACTIONS = ROOT / "scripts/qemu-transactions.sh"
BUDGET = ROOT / "scripts/qemu-boot-budget.sh"


def boot_source():
    return DRIVER.read_text(encoding="utf-8").split("<<'BOOT'\n", 1)[1].split("\nBOOT\n", 1)[0]


def phase_source():
    return "boot_ssh() {" + boot_source().split("boot_ssh() {", 1)[1].split("\nwait_ssh\n", 1)[0]


def setup_dispatch():
    source = boot_source()
    return source[source.index('if timeout --kill-after="${BOOT_PHASE_KILL_GRACE}s"'):source.index('\nopts=')]


def budget_values():
    result = subprocess.run(
        ["bash", "-c", 'source "$1"; printf "%s %s %s\\n" "$SSH_WAIT_BUDGET" "$CLONE_BOOT_TIMEOUT" "$BOOT_TIMEOUT"', "_", str(BUDGET)],
        env=clean_env(), capture_output=True, text=True, timeout=5, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    return tuple(map(int, result.stdout.split()))


def clean_env():
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"}}


class BootTimeoutExceedsReadinessWait(unittest.TestCase):
    def test_driver_derives_boot_timeout_from_the_wait_budget(self):
        text = DRIVER.read_text(encoding="utf-8")
        self.assertIn('cp "$here/qemu-boot-budget.sh" "$work/qemu-boot-budget.sh"', text)
        self.assertIn('source "$work/qemu-boot-budget.sh"', text)
        self.assertIn('source /work/qemu-boot-budget.sh', boot_source())
        self.assertEqual(budget_values(), (1680, 2161, 3911))
        self.assertNotRegex(BUDGET.read_text(), r"SSH_WAIT_ATTEMPTS")

    def test_driver_no_longer_hardcodes_a_short_boot_timeout(self):
        self.assertNotRegex(DRIVER.read_text(), r"(?m)^\s*boot_timeout=\d+\s*$")

    def test_driver_boot_timeout_clears_the_inner_budget(self):
        wait, clone, initial = budget_values()
        self.assertEqual(clone, 182 + wait + 252 + 17 + 30)
        self.assertEqual(initial, clone + wait + 5 * 14)
        self.assertGreater(initial, 2 * wait)
        self.assertIn("boot_timeout=$(( BOOT_TIMEOUT * 2 ))", DRIVER.read_text())
        self.assertIn('timeout --kill-after=5s "$boot_timeout" docker exec', DRIVER.read_text())
        # The bounded cloud-init wrapper includes BOTH child command kill graces.
        cloud = (ROOT / "scripts/check-qemu-cloud-init.sh").read_text()
        self.assertIn('timeout --kill-after=5s 180s ssh', cloud)
        self.assertIn('timeout --kill-after=5s 60s ssh', cloud)

    def test_clone_timeout_clears_the_inner_budget(self):
        text = TRANSACTIONS.read_text()
        self.assertIn('source /work/qemu-boot-budget.sh', text)
        self.assertIn('clone_boot_timeout=$CLONE_BOOT_TIMEOUT', text)
        self.assertGreater(budget_values()[1], 182 + 1680 + 252 + 17)
        self.assertNotRegex(text, r"timeout --kill-after=5s 360\b")
        self.assertIn('timeout --kill-after=5s "$clone_boot_timeout" bash /work/boot.sh', text)

    def test_wait_loop_still_has_the_documented_shape(self):
        source = boot_source()
        self.assertEqual(source.count('local deadline=$(( SECONDS + SSH_WAIT_BUDGET ))'), 1)
        self.assertIn('wait_ssh "$before"', source)
        self.assertIn('(( remaining > SSH_KILL_GRACE )) || break', source)
        self.assertIn('probe_timeout=$(( remaining - SSH_KILL_GRACE ))', source)
        self.assertIn('(( delay <= remaining )) || delay=$remaining', source)
        self.assertEqual(source.count('\nboot_ssh '), 4)
        self.assertIn('before=$(boot_ssh cat /proc/sys/kernel/random/boot_id)', source)
        self.assertNotRegex(source, r"(?m)^ssh ")


class BootShellDeadlineTests(unittest.TestCase):
    def run_shell(self, root, script, args=(), limit=35):
        env = clean_env()
        env["PATH"] = str(root / "bin") + os.pathsep + env["PATH"]
        start = time.monotonic()
        result = subprocess.run(["bash", "-c", script, "_", *args], cwd=root, env=env,
                                capture_output=True, text=True, timeout=limit, check=False)
        return result, time.monotonic() - start

    def fixture(self, directory, ssh):
        root = Path(directory)
        (root / "bin").mkdir()
        stub = root / "bin/ssh"
        stub.write_text("#!/usr/bin/env python3\n" + ssh, encoding="utf-8")
        stub.chmod(0o755)
        (root / "serial.log").write_text("Linux version fixture\nlast serial marker\n")
        return root

    def prefix(self):
        return '''set -euo pipefail
opts=()
vm_serial=serial.log
printf '%s\\n' "$$" > qemu.pid
SSH_WAIT_BUDGET=4
SSH_ATTEMPT_TIMEOUT=1
SSH_KILL_GRACE=1
SSH_RETRY_DELAY=1
''' + phase_source() + "\n"

    def test_term_resistant_probe_keeps_readiness_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n")
            result, elapsed = self.run_shell(root, self.prefix() + 'wait_ssh\n', limit=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertLess(elapsed, 6)
            self.assertIn('SSH readiness timed out after 4 seconds', result.stderr)
            self.assertIn('kernel_banner_seen=yes', result.stderr)
            self.assertIn('last serial marker', result.stderr)

    def test_reboot_expiry_keeps_old_identity_and_serial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, "print('old-id')\n")
            result, elapsed = self.run_shell(root, self.prefix() + 'wait_ssh old-id\n', limit=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertLess(elapsed, 6)
            self.assertIn('Reboot readiness timed out: previous_boot_id=old-id', result.stderr)
            self.assertIn('last serial marker', result.stderr)

    def test_term_resistant_intermediate_command_has_total_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n")
            result, elapsed = self.run_shell(root, self.prefix() + 'boot_ssh stuck-command\n', limit=10)
            self.assertEqual(result.returncode, 137, result.stderr)
            self.assertLess(elapsed, 4)
            self.assertIn('Boot SSH command failed: exit=137', result.stderr)

    def test_setup_dispatch_preserves_exact_argument_vector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, "raise SystemExit(99)\n")
            args = ('space value', '', 'semi;colon', '$(not-executed)', 'quote"value', '*')
            script = 'set -euo pipefail\nBOOT_PHASE_KILL_GRACE=1\nBOOT_SETUP_TIMEOUT=2\nsetup_boot() { printf "<%s>\\n" "$@"; }\n' + setup_dispatch()
            result, _ = self.run_shell(root, script, args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), [f'<{arg}>' for arg in args])

    def test_setup_dispatch_stops_on_command_pipeline_and_nounset_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, "raise SystemExit(99)\n")
            for failure in ('false', 'false | true', 'printf "%s" "$UNDEFINED_BOOT_FIXTURE"'):
                with self.subTest(failure=failure):
                    script = 'set -euo pipefail\nBOOT_PHASE_KILL_GRACE=1\nBOOT_SETUP_TIMEOUT=2\nsetup_boot() { ' + failure + '; printf sentinel; }\n' + setup_dispatch()
                    result, _ = self.run_shell(root, script)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn('sentinel', result.stdout)
                    self.assertIn('Boot setup failed: exit=', result.stderr)

    def test_slow_successful_initial_and_clone_compositions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.fixture(directory, '''import pathlib, sys, time
time.sleep(0.7)
command = ' '.join(sys.argv[1:])
if '/proc/sys/kernel/random/boot_id' in command:
    print('new-id' if pathlib.Path('rebooted').exists() else 'old-id')
elif 'systemctl reboot' in command:
    pathlib.Path('rebooted').write_text('yes')
''')
            cloud = root / 'cloud.sh'
            cloud.write_text('sleep 0.7\nprintf "cloud fixture complete\\n"\n')
            tail = boot_source().split('\nwait_ssh\n', 1)[1]
            tail = tail.replace('/work/check-qemu-cloud-init.sh', str(cloud))
            budget = BUDGET.read_text()
            overrides = {'SSH_WAIT_BUDGET': 3, 'SSH_ATTEMPT_TIMEOUT': 1, 'SSH_KILL_GRACE': 1,
                         'SSH_RETRY_DELAY': 1, 'BOOT_SETUP_TIMEOUT': 2,
                         'BOOT_CLOUD_INIT_TIMEOUT': 2, 'BOOT_IDENTITY_TIMEOUT': 2,
                         'BOOT_PHASE_KILL_GRACE': 1, 'BOOT_OVERHEAD': 2}
            for name, value in overrides.items():
                budget, count = re.subn(rf'(?m)^{name}=\d+$', f'{name}={value}', budget)
                self.assertEqual(count, 1)
            body = self.prefix() + budget + '\nsetup_boot() { sleep 0.7; printf "setup fixture complete\\n"; }\n' + setup_dispatch() + '\nwait_ssh\n' + tail
            # Execute the actual clone wrapper against a disposable, extracted boot composition.
            clone_function = TRANSACTIONS.read_text().split('start_clone() {', 1)[1].split('\nfreeze_base() {', 1)[0]
            clone_function = 'start_clone() {' + clone_function
            subject = root / 'boot.sh'
            subject.write_text('initial=false\n' + body)
            clone_function = clone_function.replace('/work/boot.sh', str(subject))
            script = 'set -euo pipefail\n' + budget + '\nclone_boot_timeout=$CLONE_BOOT_TIMEOUT\nboot_args=(bios ssh)\n' + clone_function + '\nstart_clone disk vars serial.log clone.log\n'
            result, elapsed = self.run_shell(root, script)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater(elapsed, 2.5)
            self.assertIn('setup fixture complete', (root / 'clone.log').read_text())
            self.assertIn('cloud fixture complete', (root / 'clone.log').read_text())
            # Initial composition adds all five SSH commands and reboot readiness.
            (root / 'qemu.pid').unlink()
            subject.write_text('initial=true\n' + body)
            script = 'set -euo pipefail\n' + budget + '\ntimeout --kill-after=1s "$BOOT_TIMEOUT" bash "$1" bios ssh\n'
            result, elapsed = self.run_shell(root, script, (str(subject),))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater(elapsed, 6)
            self.assertIn('reboot verified: old-id -> new-id', result.stdout)


if __name__ == "__main__":
    unittest.main()

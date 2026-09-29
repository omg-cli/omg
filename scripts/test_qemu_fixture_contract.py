"""Verify real shell command lookup for the missing-Cargo guest fixture."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipIf(os.name == 'nt', 'Guest POSIX command lookup runs in hosted Linux CI')
class CargoFixtureTests(unittest.TestCase):
    def test_present_cargo_is_setup_failure_and_absent_cargo_is_valid(self):
        source = (Path(__file__).resolve().parent / 'benchmark-qemu.sh').read_text()
        begin = source.index('  if command -v cargo > evidence/rust-toolchain.txt; then')
        end = source.index('\n  fi', begin) + len('\n  fi')
        script = source[begin:end]
        bash = shutil.which('bash')
        self.assertIsNotNone(bash)
        for present in (False, True):
            with self.subTest(present=present), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'evidence').mkdir()
                (root / 'bin').mkdir()
                if present:
                    cargo = root / 'bin/cargo'
                    cargo.write_text('#!/bin/sh\nexit 0\n')
                    cargo.chmod(0o755)
                env = dict(os.environ, PATH=str(root / 'bin'))
                result = subprocess.run([bash, '-c', script], cwd=root, env=env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 120 if present else 0, result.stderr)
                evidence = (root / 'evidence/rust-toolchain.txt').read_text()
                self.assertEqual(bool(evidence.strip()), present)

    def test_failed_clone_keeps_its_own_qemu_startup_log_without_stale_reuse(self):
        source = (Path(__file__).resolve().parent / 'qemu-transactions.sh').read_text()
        begin = source.index('start_clone() {')
        end = source.index('\nfreeze_base() {', begin)
        function = source[begin:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'first').mkdir()
            (root / 'second').mkdir()
            script = '''set -euo pipefail
boot_args=()
# start_clone reads the derived clone boot timeout, which the real script
# defines at top level. The harness must supply it or `set -u` aborts.
SSH_WAIT_BUDGET=$(( 120 * (12 + 2) ))
clone_boot_timeout=$(( SSH_WAIT_BUDGET + 180 ))
timeout() {
  if [[ "$5" == first-disk ]]; then
    printf 'first clone QEMU failure\\n' > qemu-startup.log
  fi
  return 124
}
''' + function + '''
first=0
start_clone first-disk vars first/serial.log first/boot.log || first=$?
second=0
start_clone second-disk vars second/serial.log second/boot.log || second=$?
printf '%s %s\\n' "$first" "$second"
'''
            result = subprocess.run(['bash', '-c', script], cwd=root,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), '124 124')
            self.assertEqual((root / 'first/boot.qemu-startup.log').read_text(),
                             'first clone QEMU failure\n')
            self.assertFalse((root / 'second/boot.qemu-startup.log').exists())

    def test_timeout_or_killed_guest_is_not_reported_as_product_failure(self):
        source = (Path(__file__).resolve().parent / 'benchmark-qemu.sh').read_text()
        begin = source.index('case "$rc" in 0) result=PASS')
        end = source.index('\n[[ "$inventory_harness_error"', begin)
        verdict = source[begin:end]
        for code, expected in ((0, 'PASS'), (1, 'PRODUCT_FAIL'), (120, 'HARNESS_ERROR'),
                               (124, 'HARNESS_ERROR'), (137, 'HARNESS_ERROR')):
            with self.subTest(code=code):
                script = f'rc={code}\n{verdict}\nprintf "%s\\n" "$result"\n'
                result = subprocess.run(['bash', '-c', script], capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)


if __name__ == '__main__':
    unittest.main()

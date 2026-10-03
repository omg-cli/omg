"""Verify real shell command lookup for the missing-Cargo guest fixture."""
import os
import json
import shlex
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class CargoFixtureTests(unittest.TestCase):
    def test_preparation_health_gates_shutdown_and_snapshot_before_resume(self):
        source = (Path(__file__).resolve().parent / 'qemu-transactions.sh').read_text()
        begin = source.index('verify_preparation_health() {')
        end = source.index('\n: > "$output/boot-ids.txt"', begin)
        preparation = source[begin:end]
        for failed_operation, mode in ((None, 'clean'), ('remove', 'crash'), ('install', 'crash'),
                                       ('remove', 'mismatch'), ('install', 'incomplete'),
                                       ('remove', 'missing'), ('install', 'transport')):
            with self.subTest(operation=failed_operation, mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'guest').mkdir()
                (root / 'transactions').mkdir()
                (root / 'disks').mkdir()
                (root / 'guest/serial.log').write_text('Linux version 6.12\n')
                shutil.copyfile(Path(__file__).with_name('check-qemu-health.py'), root / 'check-qemu-health.py')
                for operation, digit in (('remove', '5'), ('install', '6')):
                    boot = '00000000-1111-2222-3333-' + digit * 12
                    receipt = dict(schema_version=1, complete=True, boot_id=boot, kernel_bytes=100,
                                   fatal_signatures=[], product_crashes=[])
                    if operation == failed_operation:
                        if mode == 'crash': receipt['product_crashes'] = [{'process': 'omg', 'signal': 6}]
                        if mode == 'mismatch': receipt['boot_id'] = '00000000-1111-2222-3333-777777777777'
                        if mode == 'incomplete': receipt['complete'] = False
                    (root / f'{operation}.json').write_text('' if operation == failed_operation and mode == 'missing'
                                                           else json.dumps(receipt))
                script = '''set -euo pipefail
output="$PWD/transactions"
disks="$PWD/disks"
boot_args=(bios)
distro=arch
active=remove
remote_argv() {
  if [[ "$1" == cat ]]; then
    if [[ "$active" == remove ]]; then printf '00000000-1111-2222-3333-555555555555\\n'
    else printf '00000000-1111-2222-3333-666666666666\\n'; fi
  elif [[ "$1" == pacman ]]; then printf 'tree 1.0\\n'
  else
    if [[ "$active" == "$failed_operation" && "$mode" == transport ]]; then return 255; fi
    cat "$active.json"
  fi
}
mask_units() { :; }
native_change() { :; }
capture_repository_state() { :; }
stop_guest() { printf 'stop:%s\\n' "$active" >> events; }
freeze_base() { printf 'freeze:%s\\n' "$2" >> events; }
qemu-img() { :; }
start_clone() { active=install; printf 'Linux version 6.12\\n' > "$3"; }
''' + f'failed_operation={shlex.quote(failed_operation or "none")}\nmode={shlex.quote(mode)}\n'
                script += preparation.replace('/work/', str(root) + '/')
                script += '\nprintf "healthy-resume\\n" >> events\n'
                result = subprocess.run(['bash', '-c', script], cwd=root,
                                        capture_output=True, text=True, timeout=10)
                events = (root / 'events').read_text().splitlines() if (root / 'events').exists() else []
                if failed_operation is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(events, ['stop:remove', 'freeze:remove', 'stop:install',
                                              'freeze:install', 'healthy-resume'])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(events, [] if failed_operation == 'remove' else
                                     ['stop:remove', 'freeze:remove'])

    def test_native_index_oracle_is_staged_before_controller_upload(self):
        scripts = Path(__file__).resolve().parent
        source = (scripts / 'benchmark-qemu.sh').read_text()
        begin = source.index('  cp "$here/qemu-inventory.sh"')
        end = source.index('  if [[ "$source_kind" == staged ]]', begin)
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, here=str(scripts), work=directory)
            result = subprocess.run(['bash', '-e', '-c', source[begin:end]],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = Path(directory) / 'qemu-doctor-index-oracle.py'
            self.assertTrue(staged.is_file(), 'the controller cannot upload an unstaged guest oracle')
            self.assertEqual(staged.read_bytes(), (scripts / staged.name).read_bytes())

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
  case "$4" in
    /work/boot.sh)
      if [[ "$5" == first-disk ]]; then
        printf 'first clone QEMU failure\\n' > qemu-startup.log
      fi
      return 124
      ;;
    /work/qemu-boot-diagnostics.sh)
      printf 'controlled observer receipt\\n'
      return 0
      ;;
    *) return 90 ;;
  esac
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
            for launch in ('first', 'second'):
                self.assertEqual((root / launch / 'boot.diagnostics.log').read_text(),
                                 'controlled observer receipt\n')

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

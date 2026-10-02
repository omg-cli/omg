"""Require real executor refusal evidence before opting into native mutations."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MutationRefusalTests(unittest.TestCase):
    def run_probe(self, fault=None):
        script = ROOT / 'scripts/qemu-mutation-refusal.py'
        self.assertTrue(script.is_file(), 'the native refusal probe is missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / 'scripts'
            scripts.mkdir()
            for source in (ROOT / 'scripts').iterdir():
                if source.is_file() and source.suffix in ('.py', '.sh'):
                    shutil.copyfile(source, scripts / source.name)
            if fault == 'gate-enabled':
                runner = scripts / 'qemu-inventory.sh'
                text = runner.read_text()
                self.assertIn('allow_mutations=false', text)
                runner.write_text(text.replace('allow_mutations=false', 'allow_mutations=true', 1))
            work = root / 'work'
            (work / 'guest').mkdir(parents=True)
            for name in ('client-key', 'known_hosts'):
                (work / 'guest' / name).write_text('fixture-only\n')
            commands = root / 'bin'
            commands.mkdir()
            calls = root / 'calls'
            ssh = commands / 'ssh'
            ssh.write_text('''#!/bin/bash
if [[ "$*" == *OMG_QEMU_RECEIPT* ]]; then
  printf 'OMG_QEMU_RECEIPT\\n' >> "$CALLS"
  printf 'tree official\\nOMG_QEMU_RECEIPT:product:0:0\\n'
  exit 0
fi
printf 'native-snapshot\\n' >> "$CALLS"
count=$(grep -vc OMG_QEMU_RECEIPT "$CALLS")
if [[ "$FAULT" == state-changed && "$count" -ge 2 ]]; then
  printf 'installed packages\\nbase 2.0\\ninstall reasons\\nbase\\n'
else
  printf 'installed packages\\nbase 1.0\\ninstall reasons\\nbase\\n'
fi
''')
            ssh.chmod(0o755)
            receipt = work / 'mutation-refusal.json'
            args = ['--distro', 'debian', '--tag', 'fixture', '--binary', '/fixture/omg',
                    '--tsv', str(ROOT / 'tests/cli_behavior_inventory.tsv')]
            result = subprocess.run(['python3', str(scripts / script.name), 'collect',
                                     '--work', str(work), '--receipt', str(receipt), *args],
                                    env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                                             CALLS=str(calls), FAULT=fault or ''),
                                    capture_output=True, text=True, timeout=90)
            self.assertTrue(receipt.is_file(), result.stderr)
            data = json.loads(receipt.read_text())
            verification = subprocess.run(['python3', str(scripts / script.name), 'verify',
                                           '--receipt', str(receipt), *args],
                                          capture_output=True, text=True, timeout=10)
            return result, verification, data, calls.read_text().splitlines()

    def test_actual_executor_refuses_both_rows_without_guest_execution(self):
        result, verification, receipt, calls = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(verification.returncode, 0, verification.stderr)
        self.assertTrue(receipt['complete'])
        self.assertEqual(len(calls), 3, 'only two native snapshots and the read-only control may use SSH')
        self.assertEqual(sum('OMG_QEMU_RECEIPT' in call for call in calls), 1)
        self.assertEqual(receipt['state_before_sha256'], receipt['state_after_sha256'])
        self.assertEqual([row['result'] for row in receipt['results']], ['PASS', 'SKIPPED', 'SKIPPED'])
        self.assertFalse(receipt['metadata']['allow_mutations'])

    def test_enabled_gate_and_changed_native_state_cannot_prove_refusal(self):
        for fault in ('gate-enabled', 'state-changed'):
            with self.subTest(fault=fault):
                result, verification, receipt, _ = self.run_probe(fault)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotEqual(verification.returncode, 0)
                self.assertFalse(receipt['complete'])
                self.assertTrue(receipt['error'])

    def test_oracle_is_staged_for_the_controller(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        begin = source.index('  cp "$here/qemu-inventory.sh"')
        end = source.index('  if [[ "$source_kind" == staged ]]', begin)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['bash', '-e', '-c', source[begin:end]],
                                    env=dict(os.environ, here=str(ROOT / 'scripts'),
                                             work=directory), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = Path(directory) / 'qemu-mutation-refusal.py'
            self.assertTrue(staged.is_file(), 'real lanes must stage the mutation refusal oracle')
            self.assertEqual(staged.read_bytes(), (ROOT / 'scripts/qemu-mutation-refusal.py').read_bytes())

    def test_refusal_inventory_is_independent_of_custom_selected_rows(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        self.assertIn('cp "$here/../tests/cli_behavior_inventory.tsv" "$work/mutation-refusal-cases.tsv"', source)
        self.assertIn('--tsv /work/mutation-refusal-cases.tsv', source)
        self.assertIn('--tsv "$here/../tests/cli_behavior_inventory.tsv"', source)

    def test_live_refusal_is_required_before_mutating_inventory(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        start = source.index('  inv_args=(--work /work')
        end = source.index('  inventory_rc=0', start)
        setup = source[start:end]
        self.assertIn('/work/qemu-mutation-refusal.py', setup)
        self.assertIn('mutation-refusal.json', setup)
        self.assertNotIn('|| true', setup)
        self.assertNotIn('continue-on-error', setup)


if __name__ == '__main__':
    unittest.main()

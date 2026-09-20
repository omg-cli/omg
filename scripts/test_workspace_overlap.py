"""Negative controls for the task fixture used by native and QEMU inventories."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'scripts/workspace-overlap-fixture.sh'


class WorkspaceOverlap(unittest.TestCase):
    def command(self, participant, attempts='200'):
        return [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'),
                str(FIXTURE), '.', participant, attempts]

    def test_concurrent_participants_complete_once_each(self):
        with tempfile.TemporaryDirectory() as directory:
            with subprocess.Popen(self.command('primary'), cwd=directory,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as first:
                try:
                    second = subprocess.run(self.command('nested'), cwd=directory,
                                            capture_output=True, text=True, timeout=25)
                    stdout, stderr = first.communicate(timeout=25)
                finally:
                    if first.poll() is None:
                        first.kill()
                        first.communicate()
                self.assertEqual(first.returncode, 0, stderr)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(stdout, 'smoke-task-ok\n')
                self.assertEqual(second.stdout, 'nested-smoke-task-ok\n')

    def test_serial_participants_fail_without_leaving_a_false_ready_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            for participant in ('primary', 'nested'):
                result = subprocess.run(self.command(participant, '2'), cwd=directory,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn('workspace peer did not overlap', result.stderr)
                self.assertFalse((Path(directory) / '.overlap' / participant).exists())


if __name__ == '__main__':
    unittest.main()

"""Real namespace regression: environment override must not retain Debian markers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/debian-checkpoint-isolation.py'


class MarkerIsolation(unittest.TestCase):
    def test_controlled_negative_masks_markers_without_changing_parent(self):
        # Removing the /etc projection or relying on the override alone must fail.
        self.assertTrue(SCRIPT.is_file(), 'checkpoint isolation entry point is absent')
        with tempfile.TemporaryDirectory(dir=os.environ.get('PAPERCLIP_RUN_SCRATCH_DIR')) as temporary:
            directory = Path(temporary)
            markers = directory / 'etc'
            markers.mkdir()
            (markers / 'debian_version').write_text('12.0\n')
            (markers / 'os-release').write_text('ID=debian\nNAME="Debian GNU/Linux"\n')
            (markers / 'sentinel').write_text('preserved\n')
            probe = directory / 'probe.py'
            probe.write_text('''import json, os
from pathlib import Path
print(json.dumps({'debian': Path('/etc/debian_version').exists(),
                  'os': Path('/etc/os-release').read_text(),
                  'sentinel': Path('/etc/sentinel').read_text(),
                  'distro': os.environ.get('OMG_TEST_DISTRO'), 'uid': os.geteuid()}))
''')
            for condition, expected in [('supported', True), ('controlled-unsupported', False)]:
                output = directory / condition
                command = ['bwrap', '--ro-bind', '/', '/', '--ro-bind', str(markers), '/etc',
                           '--bind', str(directory), str(directory),
                           '--proc', '/proc', '--dev', '/dev', '--', sys.executable, str(SCRIPT),
                           '--condition', condition, '--output', str(output), '--',
                           sys.executable, str(probe)]
                result = subprocess.run(command, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed = json.loads(result.stdout)
                self.assertEqual(observed['debian'], expected)
                self.assertEqual(observed['distro'], 'debian' if expected else 'arch')
                self.assertEqual(observed['sentinel'], 'preserved\n')
                self.assertEqual(observed['uid'], os.geteuid())
                receipt = json.loads((output / 'guard-inputs.json').read_text())
                self.assertEqual(receipt['actual_environment']['os_release'],
                                 'ID=debian\nNAME="Debian GNU/Linux"\n')
                self.assertEqual(receipt['guard_inputs']['is_debian'], expected)
                self.assertFalse(receipt['guard_inputs']['is_ubuntu'])
                self.assertNotEqual(receipt['parent_mount_namespace'], receipt['mount_namespace'])
            self.assertEqual((markers / 'debian_version').read_text(), '12.0\n')
            self.assertEqual((markers / 'os-release').read_text(),
                             'ID=debian\nNAME="Debian GNU/Linux"\n')

    def test_stale_condition_directory_is_refused_without_overwriting_evidence(self):
        # Reusing a condition directory must not turn old guard evidence into
        # evidence for a second invocation, even when the new command fails.
        with tempfile.TemporaryDirectory(dir=os.environ.get('PAPERCLIP_RUN_SCRATCH_DIR')) as temporary:
            directory = Path(temporary)
            markers = directory / 'etc'
            markers.mkdir()
            (markers / 'debian_version').write_text('12\n')
            (markers / 'os-release').write_text('ID=debian\n')
            output = directory / 'supported'
            output.mkdir()
            retained = output / 'guard-inputs.json'
            retained.write_text('historical evidence\n')
            command = ['bwrap', '--ro-bind', '/', '/', '--ro-bind', str(markers), '/etc',
                       '--bind', str(directory), str(directory), '--proc', '/proc', '--dev', '/dev',
                       '--', sys.executable, str(SCRIPT), '--condition', 'supported',
                       '--output', str(output), '--', 'false']
            result = subprocess.run(command, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('File exists', result.stderr)
            self.assertEqual(retained.read_text(), 'historical evidence\n')


if __name__ == '__main__':
    unittest.main()

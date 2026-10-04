"""Doctor index evidence must distinguish empty, corrupt and unreadable state."""
import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


class DoctorIndexReceiptTests(unittest.TestCase):
    def guest_identity(self, distro, release):
        source = Path(__file__).with_name('qemu-doctor-index-oracle.py')
        spec = importlib.util.spec_from_file_location('doctor_guest_identity', source)
        oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle)
        # Execute the actual admission guard before any privileged mount changes.
        guard = source.read_text().split('    release = ', 1)[1].split('\n', 1)[1]
        guard = guard.split('    account = ', 1)[0]
        namespace = dict(vars(oracle), distro=distro, release=release.splitlines())
        exec(compile(textwrap.dedent(guard), str(source), 'exec'), namespace)

    def test_debian_13_guest_keeps_trixie_lane_identity(self):
        for release in ('ID=debian\nVERSION_ID=13\n', "ID='debian'\nVERSION_ID=\"13\"\n"):
            with self.subTest(release=release):
                self.guest_identity('debian-trixie', release)

    def test_trixie_refuses_foreign_version_missing_or_ambiguous_identity(self):
        for release in ('ID=debian\nVERSION_ID=12\n', 'ID=ubuntu\nVERSION_ID=13\n',
                        'ID=debian\n', 'VERSION_ID=13\n',
                        'ID=debian\nID=ubuntu\nVERSION_ID=13\n',
                        'ID=debian\nVERSION_ID=13\nVERSION_ID=12\n'):
            with self.subTest(release=release), self.assertRaises(RuntimeError):
                self.guest_identity('debian-trixie', release)

    def test_existing_guest_backend_id_checks_remain_strict(self):
        for distro in ('debian', 'ubuntu'):
            self.guest_identity(distro, f'ID="{distro}"\nVERSION_ID=12\n')
            with self.assertRaises(RuntimeError):
                self.guest_identity(distro, 'ID=fedora\nVERSION_ID=44\n')

    def check(self, receipt):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            path.write_text(json.dumps(receipt), encoding='utf-8')
            return subprocess.run([sys.executable,
                str(Path(__file__).with_name('qemu-doctor-index-oracle.py')),
                '--distro', 'debian', '--receipt', str(path)],
                capture_output=True, text=True, timeout=10)

    def receipt(self):
        return {'schema_version': 1, 'distro': 'debian', 'complete': True,
                'db_before': 'a' * 64, 'db_after': 'a' * 64,
                'baseline_issues': 1, 'cases': {
                    'empty': {'exit': 1, 'issues': 1, 'diagnostic': True},
                    'corrupt-gzip': {'exit': 1, 'issues': 2, 'diagnostic': True},
                    'unreadable': {'exit': 1, 'issues': 2, 'diagnostic': True},
                    'corrupt-status': {'exit': 1, 'issues': 2, 'diagnostic': True}}}

    def test_complete_counted_negatives_and_stable_native_state_pass(self):
        result = self.check(self.receipt())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_health_strings_or_missing_negative_cases_cannot_pass(self):
        for alteration in ('missing', 'healthy', 'uncounted', 'no-diagnostic', 'changed-db', 'wrong-distro'):
            with self.subTest(alteration=alteration):
                receipt = self.receipt()
                if alteration == 'missing':
                    del receipt['cases']['unreadable']
                elif alteration == 'healthy':
                    receipt['cases']['corrupt-gzip']['exit'] = 0
                elif alteration == 'uncounted':
                    receipt['cases']['unreadable']['issues'] = 1
                elif alteration == 'no-diagnostic':
                    receipt['cases']['corrupt-status']['diagnostic'] = False
                elif alteration == 'changed-db':
                    receipt['db_after'] = 'b' * 64
                else:
                    receipt['distro'] = 'ubuntu'
                self.assertEqual(self.check(receipt).returncode, 1)


if __name__ == '__main__':
    unittest.main()

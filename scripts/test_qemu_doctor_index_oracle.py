"""Doctor index evidence must distinguish empty, corrupt and unreadable state."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class DoctorIndexReceiptTests(unittest.TestCase):
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

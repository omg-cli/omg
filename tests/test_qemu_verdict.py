"""Exercise the actual cleanup projection without requiring a VM or Docker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VerdictTests(unittest.TestCase):
    def run_cleanup(self, *, lifecycle='PASS', inventory_failure=True, exit_code=1):
        bash = os.environ.get('OMG_TEST_BASH') or shutil.which('bash')
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        cleanup = source[source.index('cleanup() {'):source.index('trap cleanup EXIT')]
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        work = Path(directory.name)
        (work / 'guest').mkdir()
        script = f'''set -euo pipefail
work=$TEST_WORK
repo_root=$TEST_ROOT
distro=arch
case_id=qemu-arch-lifecycle
result={lifecycle}
source_kind=staged
tag=v9.9.9
inventory_product_failure={'true' if inventory_failure else 'false'}
report_inventory='[{{"case_id":"qemu-arch-row","distro":"arch","result":"FAIL","exit_code":2,"elapsed_seconds":0}}]'
''' + cleanup + f'\ntrap cleanup EXIT\nexit {exit_code}\n'
        result = subprocess.run([bash, '-c', script], env=dict(os.environ,
            TEST_WORK=work.as_posix(), TEST_ROOT=ROOT.as_posix()), capture_output=True, text=True)
        return work, result

    def test_inventory_failure_does_not_rewrite_lifecycle(self):
        work, result = self.run_cleanup()
        self.assertEqual(result.returncode, 1, result.stderr)
        rows = json.loads((work / 'sentry-results.json').read_text())
        self.assertEqual((rows[0]['result'], rows[0]['exit_code']), ('PASS', 0))
        self.assertEqual(rows[1]['result'], 'FAIL')
        self.assertIn('arch lifecycle=PASS overall=PRODUCT_FAIL', result.stdout)

    def test_harness_failure_takes_priority_over_inventory_product_failure(self):
        _work, result = self.run_cleanup(lifecycle='HARNESS_ERROR', exit_code=3)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('arch lifecycle=HARNESS_ERROR overall=HARNESS_ERROR', result.stdout)


if __name__ == '__main__':
    unittest.main()

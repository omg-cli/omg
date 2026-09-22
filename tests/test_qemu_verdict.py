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
    def test_inventory_failure_does_not_rewrite_lifecycle(self):
        bash = os.environ.get('OMG_TEST_BASH') or shutil.which('bash')
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        cleanup = source[source.index('cleanup() {'):source.index('trap cleanup EXIT')]
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'guest').mkdir()
            script = '''set -euo pipefail
work=$TEST_WORK
repo_root=$TEST_ROOT
distro=arch
case_id=qemu-arch-lifecycle
result=PASS
source_kind=staged
tag=v9.9.9
inventory_product_failure=true
report_inventory='[{"case_id":"qemu-arch-row","distro":"arch","result":"FAIL","exit_code":2,"elapsed_seconds":0}]'
''' + cleanup + '\ntrap cleanup EXIT\nexit 1\n'
            result = subprocess.run([bash, '-c', script], env=dict(os.environ,
                TEST_WORK=work.as_posix(), TEST_ROOT=ROOT.as_posix()), capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            rows = json.loads((work / 'sentry-results.json').read_text())
            self.assertEqual((rows[0]['result'], rows[0]['exit_code']), ('PASS', 0))
            self.assertEqual(rows[1]['result'], 'FAIL')
            self.assertIn('arch lifecycle=PASS overall=PRODUCT_FAIL', result.stdout)


if __name__ == '__main__':
    unittest.main()

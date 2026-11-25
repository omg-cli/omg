"""Exercise the actual benchmark transaction selector with controlled PTY commands."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'Genuine foreground terminal behavior requires POSIX')
class TransactionConsent(unittest.TestCase):
    def test_actual_receipt_gate_rejects_missing_malformed_or_failed_decisions(self):
        source = (ROOT / 'benchmark-hyperfine.sh').read_text()
        predicate = re.search(r"jq -e '(\.cli_exit_code==0[^']+)'", source)[1]
        for payload, accepted in [({'cli_exit_code': 0, 'reviews': []}, True),
                                  ({'cli_exit_code': 0, 'reviews': ['a' * 64]}, True),
                                  ({'cli_exit_code': 0, 'reviews': ['proceed']}, True),
                                  ({'cli_exit_code': 0, 'reviews': ['install-unsafe']}, True),
                                  ({'cli_exit_code': 0, 'reviews': ['unsafe']}, False),
                                  ({'cli_exit_code': 1, 'reviews': ['install-unsafe']}, False),
                                  ({'cli_exit_code': 1, 'reviews': ['a' * 64]}, False),
                                  ({'cli_exit_code': 0}, False),
                                  ({'cli_exit_code': 0, 'reviews': ['x' * 64]}, False),
                                  ({'cli_exit_code': 0, 'reviews': [True]}, False),
                                  ({'cli_exit_code': 0, 'reviews': ['a' * 64] * 65}, False)]:
            with self.subTest(payload=payload):
                result = subprocess.run(['jq', '-e', predicate], input=json.dumps(payload).encode(), capture_output=True, timeout=3)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def selected(self, distro, operation='install', tool='omg', finding=False, helper=True):
        source = (ROOT / 'benchmark-hyperfine.sh').read_text()
        begin = source.index('        if [[ "$GUEST_TOOL" == omg ]]; then')
        end = source.index('        command_json "$transaction_label"', begin)
        selection = source[begin:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / 'evidence'
            evidence.mkdir()
            if helper:
                shutil.copyfile(ROOT / 'scripts/attend-unknown-fixture.py', root / 'attend-unknown-fixture.py')
            product = root / 'omg'
            program = '''#!/usr/bin/env python3
import os,sys
assert sys.argv[1:] in [['install','--yes','tree'],['remove','--yes','tree']]
if sys.argv[1]=='remove':
    print('controlled remove executed'); raise SystemExit(0)
tty=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
assert os.tcgetpgrp(tty)==os.getpgrp()
'''
            details = ('SECURITY WARNING: the selected transaction has disclosed advisory findings.' if finding
                       else 'SECURITY WARNING: advisory coverage for the selected transaction is unknown.')
            program += ('os.write(tty,' + repr((details + '\nPackage: tree 2.3.2-1\nType accept ' + 'a' * 64
                                               + ' within 60 seconds to continue (default: cancel): ').encode()) + ')\n'
                        + 'assert os.read(tty,192)==' + repr(b'accept ' + b'a' * 64 + b'\n') + '\n'
                        + "print('controlled install accepted')\n")
            product.write_text(program, newline='\n')
            product.chmod(0o755)
            script = '''set -euo pipefail
REPO_ROOT=$1 EXPORT_DIR=$1/evidence OMG=$1/omg
distro=$2 GUEST_TRANSACTION=$3 GUEST_TOOL=$4
privileged=()
transaction_native=controlled-native
transaction_args=(printf 'controlled native executed\\n')
''' + selection + '\nprintf "%s\\n" "${transaction[@]}" > "$EXPORT_DIR/selected.argv"\n"${transaction[@]}"\n'
            result = subprocess.run(['bash', '-c', script, 'transaction-control', str(root), distro, operation, tool],
                                    capture_output=True, timeout=8, start_new_session=True)
            receipt = evidence / 'security-review.json'
            return result, json.loads(receipt.read_text()) if receipt.exists() else None

    def test_every_omg_install_uses_real_foreground_unknown_only_consent(self):
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            with self.subTest(distro=distro):
                result, receipt = self.selected(distro)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(b'controlled install accepted', result.stdout)
                self.assertEqual(receipt, {'reviews': ['a' * 64], 'cli_exit_code': 0})

    def test_disclosed_findings_and_missing_helper_fail_closed(self):
        for finding, helper, reason in ((True, True, b'Unknown-only'), (False, False, b'Missing actual native security-consent driver')):
            with self.subTest(finding=finding, helper=helper):
                result, receipt = self.selected('arch', finding=finding, helper=helper)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(reason, result.stderr)
                self.assertIsNone(receipt)

    def test_native_install_and_omg_remove_do_not_add_security_review(self):
        for operation, tool, message in (('install', 'native', b'controlled native executed'),
                                         ('remove', 'omg', b'controlled remove executed')):
            with self.subTest(operation=operation, tool=tool):
                result, receipt = self.selected('arch', operation, tool, helper=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(message, result.stdout)
                self.assertIsNone(receipt)


if __name__ == '__main__':
    unittest.main()

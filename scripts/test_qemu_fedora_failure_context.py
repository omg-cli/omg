"""Execute failed-row diagnostics with bounded native-command fixtures."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest

INVENTORY = Path(__file__).with_name('qemu-inventory.sh')


class FedoraFailureContext(unittest.TestCase):
    def run_context(self, case='release-package-remove-tree', code=1, assertion=1, mode='normal'):
        source = INVENTORY.read_text()
        match = re.search(r'^capture_fedora_failure_context\(\) \{\n.*?^\}', source, re.M | re.S)
        self.assertIsNotNone(match, 'failed Fedora row must capture native context before cleanup')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                'sudo': '#!/bin/bash\n[[ $1 == -n ]] || exit 91\nshift\nexec "$@"\n',
                'dnf': '#!/bin/bash\nprintf "%s\\n" "$*" > "$CONTEXT_ARGS"\n'
                       'case "$CONTEXT_MODE" in\n'
                       'stall) exec sleep 30 ;;\n'
                       'large) exec python3 -c "import sys; sys.stdout.write(\'x\'*1000000)" ;;\n'
                       'esac\n'
                       'printf \'[{"id":41,"comment":"omg-fixture","status":"Started","packages":[{"action":"Remove","nevra":"tree-0:2.2.1-4.fc44.x86_64"}]}]\\n\'\n'
                       'printf "native-history-error\\n" >&2\nexit 7\n',
                'rpm': '#!/bin/bash\nprintf "package tree is not installed\\n" >&2\nexit 1\n',
                'journalctl': '#!/bin/bash\nprintf "kernel-fixture-record\\n"\n',
            }
            for name, content in fixtures.items():
                path = root / name
                path.write_text(content)
                path.chmod(0o755)
            environment = dict(os.environ, PATH=str(root) + ':/usr/bin:/bin',
                               CONTEXT_ARGS=str(root / 'args'), CONTEXT_MODE=mode)
            program = match[0] + '\nrc=$2; assertion=$3; capture_fedora_failure_context "$1" "$rc" "$assertion" >&2; printf "receipt:%s:%s\\n" "$rc" "$assertion"\n'
            started = time.monotonic()
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', program, '_', case, str(code), str(assertion)],
                                    env=environment, capture_output=True, text=True, timeout=12, check=False)
            elapsed = time.monotonic() - started
            args = (root / 'args').read_text() if (root / 'args').exists() else None
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'receipt:{code}:{assertion}\n')
        return result.stderr, args, elapsed

    def test_failed_row_keeps_started_history_native_errors_and_product_receipt(self):
        output, args, _ = self.run_context()
        self.assertIn('"status":"Started"', output)
        self.assertIn('"comment":"omg-fixture"', output)
        self.assertIn('"action":"Remove"', output)
        self.assertIn('native-history-error', output)
        self.assertIn('dnf-history command_exit=7 reader_exit=0', output)
        self.assertIn('rpm-tree command_exit=1 reader_exit=0', output)
        self.assertIn('kernel-fixture-record', output)
        self.assertEqual(args, 'history info --json last\n')

    def test_success_and_unrelated_rows_do_not_probe(self):
        for case, code, assertion in [('release-package-remove-tree', 0, 0), ('status', 1, 1)]:
            with self.subTest(case=case):
                output, args, _ = self.run_context(case, code, assertion)
                self.assertEqual(output, '')
                self.assertIsNone(args)

    def test_assertion_failure_after_exit_zero_still_probes(self):
        output, args, _ = self.run_context(code=0, assertion=1)
        self.assertIn('"status":"Started"', output)
        self.assertIsNotNone(args)

    def test_stalled_probe_is_bounded_and_later_probes_survive(self):
        output, _, elapsed = self.run_context(mode='stall')
        self.assertLess(elapsed, 6)
        self.assertIn('dnf-history command_exit=124 reader_exit=0', output)
        self.assertIn('kernel-fixture-record', output)

    def test_large_output_is_bounded_without_losing_later_probe_status(self):
        output, _, _ = self.run_context(mode='large')
        self.assertLess(len(output.encode()), 26000)
        self.assertIn('output_limit_bytes=24576', output)
        self.assertIn('kernel-fixture-record', output)

    def test_actual_inventory_keeps_failed_row_and_exports_context_before_cleanup(self):
        import test_qemu_output_contracts as contracts
        rows = [line for line in
                (INVENTORY.parents[1] / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
                if line.startswith('release-package-install-tree\t')]
        self.assertEqual(len(rows), 1)
        commands = {
            'sudo': '[[ $1 == -n ]] || exit 91\nshift\nexec "$@"\n',
            'rpm': 'case "$1" in\n-q) exit 1 ;;\n'
                   '-qa) printf "base\\t0\\t1.0\\t1\\tx86_64\\n" ;;\n*) exit 92 ;;\nesac\n',
            'dnf': 'case "$1" in\nhistory) printf \'[{"id":41,"comment":"omg-fixture","status":"Started","packages":[]}]\\n\' ;;\n'
                   '--cacheonly) [[ $2 == "--disable-repo=*" && $3 == repoquery ]] || exit 93; printf "base x86_64 user\\n" ;;\n*) exit 93 ;;\nesac\n',
            'journalctl': 'printf "kernel-fixture-record\\n"\n',
        }
        product = 'printf "Error: DNF operation failed; transaction unresolved Started\\n" >&2\nexit 1\n'
        result, evidence, logs = contracts.OutputContracts().run_inventory(
            product, rows, native_commands=commands, distro='fedora', tiers='container',
            allow_mutations=True, fake_tree_binary=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['FAIL'], logs)
        self.assertEqual(evidence[0]['exit_code'], 1, logs)
        output = logs['release-package-install-tree.stderr.log']
        self.assertIn('"status":"Started"', output)
        self.assertIn('kernel-fixture-record', output)
        self.assertIn('history_selection=last', output)


if __name__ == '__main__':
    unittest.main()

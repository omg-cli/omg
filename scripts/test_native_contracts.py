"""Receipts must derive from observed executions of reviewed assertions."""
import importlib.util
import json
from pathlib import Path
import unittest

from test_contract_coverage import fixture

SPEC = importlib.util.spec_from_file_location(
    'native_contracts', Path(__file__).with_name('run-native-contracts.py'))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


def parser_fixture():
    manifest, _, _, provenance, required = fixture()
    contract = manifest['contracts'][0]
    contract['requires'] = ['parser']
    contract['assertions'] = {'parser': ['value-preserved']}
    contract['tests'][0].update(lane='native-parser', evidence=['parser'], assertions=['value-preserved'])
    provenance['lane'] = 'native-parser'
    report = {'tests': {'install-dry-run-state': {
        'runtime_skip': False, 'attempts': [{'result': 'PASS', 'duration_ms': 2}]}}}
    return manifest, provenance, report, required


class NativeReceipts(unittest.TestCase):
    def test_platform_policy_matches_real_native_selection(self):
        root = Path(__file__).resolve().parents[1]
        policy = json.loads((root / 'tests/contracts/platforms.json').read_text())
        for owner in policy['owners']:
            args = NATIVE.cargo_test_args(','.join(owner['features']))
            actual = {args[index + 1] for index, value in enumerate(args) if value == '--test'}
            with self.subTest(owner=owner['id']):
                self.assertEqual(actual, set(owner['native_integration_suites']) | {'cli_surface'})

    def test_native_backend_files_are_selected_on_compatible_owners(self):
        common_debian = {'debian_tests', 'debian_daemon_tests', 'debian_ipc_tests',
                         'debian_search_integration', 'debian_cache_tests', 'debian_e2e_tests'}
        for features, expected in (
            ('pgp,license', set()), ('arch,pgp,license', set()),
            ('debian,pgp,license', common_debian),
            ('debian-pure', common_debian | {'debian_pure_integration'}),
            ('fedora,pgp,license', {'fedora_tests'}),
        ):
            with self.subTest(features=features):
                args = NATIVE.cargo_test_args(features)
                tests = {args[index + 1] for index, value in enumerate(args) if value == '--test'}
                self.assertEqual(tests, expected | {'cli_surface'})

    def test_receipt_binds_reviewed_parser_assertion_and_harness_identity(self):
        manifest, provenance, report, required = parser_fixture()
        receipts, selected = NATIVE.parser_receipts(manifest, provenance, report)
        self.assertEqual(selected, required)
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        for key in ('source_sha', 'run_attempt', 'recipe_sha256', 'features', 'platform'):
            self.assertEqual(receipt[key], provenance[key])
        self.assertEqual(receipt['binary_sha256'], provenance['binaries']['omg'])
        self.assertEqual(receipt['assertions'], ['value-preserved'])
        self.assertEqual(receipt['attempt_count'], 1)
        _, surfaces, _, _, _ = fixture()
        admitted = NATIVE.COVERAGE.admit(manifest, surfaces, receipts, provenance, selected)
        self.assertTrue(admitted['passed'])
        self.assertEqual(admitted['evidence']['parser']['passed'], 1)
        self.assertEqual(admitted['evidence']['state']['passed'], 0)

    def test_missing_execution_and_nonparser_mapping_rejected(self):
        for mode in ('missing', 'state', 'empty'):
            manifest, provenance, report, _ = parser_fixture()
            if mode == 'missing':
                report['tests'].clear()
            elif mode == 'state':
                manifest['contracts'][0]['requires'] = ['state']
            else:
                manifest['contracts'].clear()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                NATIVE.parser_receipts(manifest, provenance, report)

    def test_retry_failure_remains_and_cannot_claim_pass_assertions(self):
        manifest, provenance, report, _ = parser_fixture()
        report['tests']['install-dry-run-state']['attempts'].insert(0, {'result': 'FAIL', 'duration_ms': 1})
        receipts, _ = NATIVE.parser_receipts(manifest, provenance, report)
        self.assertEqual([row['result'] for row in receipts], ['FAIL', 'PASS'])
        self.assertEqual(receipts[0]['assertions'], [])
        self.assertEqual(receipts[0]['attempt_count'], 2)

    def test_runtime_skip_is_blocked_not_a_pass(self):
        manifest, provenance, report, _ = parser_fixture()
        report['tests']['install-dry-run-state'].update(runtime_skip=True, attempts=[{'result': 'SKIPPED', 'duration_ms': 0}])
        receipts, _ = NATIVE.parser_receipts(manifest, provenance, report)
        self.assertEqual(receipts[0]['result'], 'BLOCKED')
        self.assertEqual(receipts[0]['assertions'], [])
        self.assertEqual(receipts[0]['cleanup'], 'NOT_STARTED')


if __name__ == '__main__':
    unittest.main()

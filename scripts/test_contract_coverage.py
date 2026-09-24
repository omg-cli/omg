"""Adversarial admission tests; none of these fixtures claim product coverage."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    'contract_coverage', Path(__file__).with_name('check-contract-coverage.py'))
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)


def fixture():
    provenance = {
        'schema_version': 1, 'source_sha': 'a' * 40, 'run_id': '123', 'run_attempt': 1,
        'recipe_sha256': 'b' * 64, 'binaries': {'omg': 'c' * 64},
        'platform': 'arch', 'os': 'linux', 'arch': 'x86_64',
        'features': ['arch', 'license', 'pgp'], 'lane': 'qemu',
    }
    contract = {
        'id': 'omg.install.dry-run', 'source': 'src/cli/args.rs', 'binary': 'omg',
        'surface': 'omg install --dry-run', 'platforms': ['arch'],
        'requires': ['success', 'state'], 'critical': True,
        'assertions': {'success': ['exit-zero'], 'state': ['database-unchanged']},
        'tests': [{'lane': 'qemu', 'id': 'install-dry-run-state',
                   'evidence': ['success', 'state'],
                   'assertions': ['exit-zero', 'database-unchanged']}],
    }
    manifest = {'schema_version': 1, 'contracts': [contract], 'gaps': [
        {'surface': 'omg install', 'platforms': ['arch'], 'owner': 'cli',
         'reason': 'success assertions not mapped yet', 'missing': ['success', 'state']},
    ]}
    surface = {'schema_version': 1, 'binary': 'omg', 'available': True,
               'build': {key: provenance[key] for key in
                         ('source_sha', 'platform', 'os', 'arch', 'features')},
               'commands': [{'path': 'omg install', 'arguments': [
                   {'id': 'dry_run', 'long': 'dry-run', 'short': None, 'index': None}]}]}
    manifest['surface_digests'] = [{
        'binary': 'omg', 'platform': 'arch', 'features': provenance['features'],
        'sha256': hashlib.sha256(json.dumps(
            {key: value for key, value in surface.items() if key != 'build'},
            sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(),
    }]
    receipt = {key: provenance[key] for key in
               ('source_sha', 'run_id', 'run_attempt', 'recipe_sha256',
                'platform', 'os', 'arch', 'features', 'lane')}
    receipt.update(schema_version=1, contract=contract['id'], binary='omg',
                   binary_sha256=provenance['binaries']['omg'],
                   test_id='install-dry-run-state', attempt=1, attempt_count=1, result='PASS',
                   evidence=['success', 'state'],
                   assertions=['exit-zero', 'database-unchanged'], duration_ms=1,
                   seed=None, cleanup='PASS')
    return manifest, [surface], [receipt], provenance, [contract['id']]


class ContractAdmission(unittest.TestCase):
    def test_native_owner_union_requires_every_reviewed_contract(self):
        manifest, surfaces, receipts, provenance, required = fixture()
        manifest['gaps'][0]['missing'] = ['help']
        manifest['behavioral_inventory_reviewed'] = True
        provenance['lane'] = 'native-cli-fixture'
        manifest['contracts'][0]['tests'][0]['lane'] = 'native-cli-fixture'
        receipts[0]['lane'] = 'native-cli-fixture'
        report = COVERAGE.admit(manifest, surfaces, receipts, provenance, required)
        admission = (provenance, report, required)
        aggregate = COVERAGE.aggregate_admissions(manifest, [admission])
        self.assertEqual(aggregate['contracts'], {'supported': 1, 'selected': 1, 'passed': 1})
        self.assertEqual(aggregate['behavioral_progress']['covered'], 1)
        self.assertTrue(aggregate['behavioral_progress']['target_met'])

        with self.assertRaisesRegex(ValueError, 'missing contract owner'):
            COVERAGE.aggregate_admissions(manifest, [])
        with self.assertRaisesRegex(ValueError, 'duplicate lane'):
            COVERAGE.aggregate_admissions(manifest, [admission, admission])
        foreign = copy.deepcopy(provenance)
        foreign['source_sha'] = 'f' * 40
        with self.assertRaisesRegex(ValueError, 'source identity mismatch'):
            COVERAGE.aggregate_admissions(manifest, [admission, (foreign, report, required)])

    def test_native_owner_union_does_not_hide_retry_or_unreviewed_inventory(self):
        manifest, surfaces, receipts, provenance, required = fixture()
        manifest['gaps'][0]['missing'] = ['help']
        provenance['lane'] = 'native-cli-fixture'
        manifest['contracts'][0]['tests'][0]['lane'] = 'native-cli-fixture'
        receipts[0]['lane'] = 'native-cli-fixture'
        report = COVERAGE.admit(manifest, surfaces, receipts, provenance, required)
        aggregate = COVERAGE.aggregate_admissions(manifest, [(provenance, report, required)])
        self.assertFalse(aggregate['behavioral_progress']['target_met'])
        retried = copy.deepcopy(report)
        retried['counts']['retried'] = 1
        with self.assertRaisesRegex(ValueError, 'retry'):
            COVERAGE.aggregate_admissions(manifest, [(provenance, retried, required)])

    def test_future_qemu_owner_is_visible_but_not_claimed_by_native_union(self):
        manifest, surfaces, receipts, provenance, required = fixture()
        manifest['gaps'][0]['missing'] = ['help']
        manifest['behavioral_inventory_reviewed'] = True
        provenance['lane'] = 'native-cli-fixture'
        manifest['contracts'][0]['tests'][0]['lane'] = 'native-cli-fixture'
        receipts[0]['lane'] = 'native-cli-fixture'
        report = COVERAGE.admit(manifest, surfaces, receipts, provenance, required)
        qemu = copy.deepcopy(manifest['contracts'][0])
        qemu['id'] = 'omg.install.dry-run.qemu'
        qemu['tests'][0]['lane'] = 'qemu'
        qemu['tests'][0]['id'] = 'qemu-install-dry-run-state'
        manifest['contracts'].append(qemu)
        report = COVERAGE.admit(manifest, surfaces, receipts, provenance, required)
        combined = COVERAGE.aggregate_admissions(manifest, [(provenance, report, required)])
        self.assertEqual(combined['contracts'], {'supported': 2, 'selected': 1, 'passed': 1})
        self.assertEqual(combined['behavioral_progress']['covered'], 0)
        self.assertFalse(combined['behavioral_progress']['target_met'])

    def test_behavioral_progress_keeps_unmapped_and_partial_surfaces_uncovered(self):
        report = COVERAGE.admit(*fixture())
        progress = report['behavioral_progress']
        self.assertEqual(progress['supported'], 2)
        self.assertEqual(progress['covered'], 1)
        self.assertEqual(progress['percent'], 50)
        self.assertFalse(progress['target_met'])
        self.assertEqual(progress['uncovered_surfaces'], ['omg install'])

    def test_parser_passes_cannot_inflate_behavioral_progress(self):
        contract = fixture()[0]['contracts'][0]
        contracts = {'behavior': contract}
        before = COVERAGE.behavioral_progress(contracts, [], {'behavior'})
        for index in range(100):
            contracts[str(index)] = dict(contract, surface=f'omg parser{index}', requires=['parser'])
        self.assertEqual(COVERAGE.behavioral_progress(contracts, [], set(contracts)), before)
        contracts['unexecuted'] = dict(contract)
        self.assertEqual(COVERAGE.behavioral_progress(contracts, [], {'behavior'})['covered'], 0)
        self.assertEqual(COVERAGE.behavioral_progress({'behavior': contract},
            [{'surface': contract['surface'], 'missing': ['fault']}], {'behavior'})['covered'], 0)

    def test_failed_blocked_or_bad_cleanup_cannot_earn_behavioral_credit(self):
        for result, cleanup in [('FAIL', 'NOT_STARTED'), ('BLOCKED', 'NOT_STARTED'),
                                ('HARNESS_ERROR', 'NOT_STARTED'), ('PASS', 'FAIL')]:
            with self.subTest(result=result, cleanup=cleanup):
                args = list(fixture())
                args[2][0].update(result=result, cleanup=cleanup)
                progress = COVERAGE.admit(*args)['behavioral_progress']
                self.assertEqual(progress['covered'], 0)
                self.assertFalse(progress['target_met'])

    def test_behavioral_target_never_rounds_up_or_accepts_an_empty_inventory(self):
        empty = COVERAGE.behavioral_progress({}, [], set())
        self.assertIsNone(empty['percent'])
        self.assertFalse(empty['target_met'])
        contracts = {str(index): {'surface': f'omg command{index}', 'requires': ['success']}
                     for index in range(2001)}
        progress = COVERAGE.behavioral_progress(contracts, [], {str(index) for index in range(1900)}, inventory_reviewed=True)
        self.assertEqual(progress['percent'], 94.95)
        self.assertFalse(progress['target_met'])
        progress = COVERAGE.behavioral_progress(contracts, [], {str(index) for index in range(1901)}, inventory_reviewed=True)
        self.assertTrue(progress['target_met'])
        self.assertFalse(COVERAGE.behavioral_progress(contracts, [], set(contracts))['target_met'])

    def test_valid_receipt_has_separate_evidence_totals_and_visible_debt(self):
        report = COVERAGE.admit(*fixture())
        self.assertTrue(report['passed'])
        self.assertEqual(report['platform'], 'arch')
        self.assertEqual(report['counts']['passed'], 1)
        self.assertEqual(report['counts']['gaps'], 1)
        self.assertEqual(report['evidence']['state']['passed'], 1)
        self.assertEqual(report['evidence']['help']['passed'], 0)

    def test_readable_summary_keeps_gaps_and_evidence_kinds_separate(self):
        summary = COVERAGE.render_markdown(COVERAGE.admit(*fixture()))
        self.assertIn('Explicit gaps: 1', summary)
        self.assertIn('| state | 1 | 1 | 1 | 0 | 0 |', summary)
        self.assertIn('| help | 0 | 0 | 0 | 0 | 0 |', summary)

    def test_missing_duplicate_unknown_and_empty_selection_are_rejected(self):
        for change in ('missing', 'duplicate', 'unknown', 'empty', 'duplicate-contract'):
            with self.subTest(change=change):
                args = list(fixture())
                if change == 'missing':
                    args[2].clear()
                elif change == 'duplicate':
                    args[2].append(copy.deepcopy(args[2][0]))
                elif change == 'unknown':
                    args[2][0]['contract'] = 'unknown'
                elif change == 'empty':
                    args[4].clear()
                else:
                    args[0]['contracts'].append(copy.deepcopy(args[0]['contracts'][0]))
                with self.assertRaises(ValueError):
                    COVERAGE.admit(*args)

    def test_every_identity_component_is_checked(self):
        changes = {'source_sha': 'd'*40, 'binary_sha256': 'd'*64,
                   'recipe_sha256': 'd'*64, 'features': ['arch'],
                   'platform': 'debian', 'os': 'macos', 'arch': 'aarch64',
                   'run_id': '124', 'run_attempt': 2, 'lane': 'native', 'binary': 'omgd'}
        for key, value in changes.items():
            with self.subTest(key=key):
                args = list(fixture())
                args[2][0][key] = value
                with self.assertRaises(ValueError):
                    COVERAGE.admit(*args)

    def test_help_cannot_replace_success_or_state(self):
        args = list(fixture())
        args[2][0]['evidence'] = ['help']
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_missing_required_assertion_is_not_evidence(self):
        args = list(fixture())
        args[2][0]['assertions'] = ['exit-zero']
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_first_critical_failure_survives_a_passing_retry(self):
        args = list(fixture())
        args[2][0]['attempt_count'] = 2
        retry = copy.deepcopy(args[2][0])
        retry['attempt'] = 2
        args[2][0]['result'] = 'FAIL'
        args[2].append(retry)
        report = COVERAGE.admit(*args)
        self.assertFalse(report['passed'])
        self.assertEqual(report['counts']['failed'], 1)
        self.assertEqual(report['counts']['retried'], 1)

    def test_missing_attempt_and_boolean_attempt_are_rejected(self):
        for attempt in (True, 0, 2, 1.0):
            with self.subTest(attempt=attempt):
                args = list(fixture())
                args[2][0]['attempt'] = attempt
                with self.assertRaises(ValueError):
                    COVERAGE.admit(*args)

    def test_unapproved_skip_is_rejected(self):
        args = list(fixture())
        args[2][0].update(result='SKIPPED', reason='network unavailable')
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_approved_skip_stays_unexecuted_and_does_not_pass_contract(self):
        args = list(fixture())
        args[0]['contracts'][0]['allowed_skips'] = {'arch': 'unsupported backend'}
        args[2][0].update(result='SKIPPED', reason='unsupported backend',
                          assertions=[], evidence=[], cleanup='NOT_STARTED')
        report = COVERAGE.admit(*args)
        self.assertFalse(report['passed'])
        self.assertEqual(report['counts']['skipped'], 1)
        self.assertEqual(report['counts']['executed'], 0)

    def test_failed_cleanup_cannot_become_product_pass(self):
        args = list(fixture())
        args[2][0]['cleanup'] = 'FAIL'
        self.assertFalse(COVERAGE.admit(*args)['passed'])

    def test_new_surface_requires_contract_or_explicit_gap(self):
        args = list(fixture())
        args[1][0]['commands'][0]['arguments'].append(
            {'id': 'force', 'long': 'force', 'short': None, 'index': None})
        with self.assertRaisesRegex(ValueError, 'unmapped'):
            COVERAGE.admit(*args)

    def test_surface_source_and_feature_mismatch_are_rejected(self):
        for key, value in [('source_sha', 'd'*40), ('features', ['license'])]:
            args = list(fixture())
            args[1][0]['build'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                COVERAGE.admit(*args)

    def test_stale_contract_surface_is_rejected(self):
        args = list(fixture())
        args[0]['contracts'][0]['surface'] = 'omg install --removed'
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_malformed_external_shapes_raise_value_error(self):
        for section, field, value in [
            ('surface', 'binary', []), ('gap', 'surface', {}),
            ('receipt', 'result', []), ('receipt', 'features', ['arch', 'arch']),
            ('receipt', 'duration_ms', float('inf')),
        ]:
            args = list(fixture())
            target = {'surface': args[1][0], 'gap': args[0]['gaps'][0],
                      'receipt': args[2][0]}[section]
            target[field] = value
            with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                COVERAGE.admit(*args)

    def test_original_failure_details_remain_in_report(self):
        args = list(fixture())
        args[2][0]['attempt_count'] = 2
        retry = copy.deepcopy(args[2][0])
        retry['attempt'] = 2
        args[2][0].update(result='FAIL', seed='saved-seed')
        args[2].append(retry)
        report = COVERAGE.admit(*args)
        self.assertEqual(report['attempts'][0]['attempts'][0]['result'], 'FAIL')
        self.assertEqual(report['attempts'][0]['attempts'][0]['seed'], 'saved-seed')

    def test_missing_final_attempt_is_not_assumed_to_be_a_clean_run(self):
        args = list(fixture())
        args[2][0]['attempt_count'] = 2
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_existing_option_constraints_cannot_change_without_inventory_review(self):
        args = list(fixture())
        args[1][0]['commands'][0]['arguments'][0]['possible_values'] = ['new-value']
        with self.assertRaisesRegex(ValueError, 'surface digest'):
            COVERAGE.admit(*args)

    def test_missing_surface_digest_is_not_implicitly_trusted(self):
        args = list(fixture())
        args[0]['surface_digests'] = []
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_non_cli_contract_requires_an_explicit_owned_interface(self):
        args = list(fixture())
        contract = args[0]['contracts'][0]
        args[0]['gaps'].append({
            'surface': contract['surface'], 'platforms': ['arch'], 'owner': 'cli',
            'reason': 'not mapped', 'missing': ['success', 'state'],
        })
        contract.update(surface='config:telemetry', source='src/core/config.rs')
        args[0]['interfaces'] = [{
            'id': 'config:telemetry', 'binary': 'omg', 'source': 'src/core/config.rs',
            'platforms': ['arch'],
        }]
        self.assertTrue(COVERAGE.admit(*args)['passed'])
        args[0]['interfaces'].clear()
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_grouped_gaps_remain_exact_without_wildcards_or_duplicates(self):
        args = list(fixture())
        gap = args[0]['gaps'][0]
        gap['surfaces'] = [gap.pop('surface')]
        self.assertEqual(COVERAGE.admit(*args)['counts']['gaps'], 1)
        gap['surfaces'].append(gap['surfaces'][0])
        with self.assertRaises(ValueError):
            COVERAGE.admit(*args)

    def test_large_inventory_reconciles_repeated_feature_owners(self):
        args = list(fixture())
        extra = []
        for index in range(1000):
            path = f'omg fixture-{index}'
            args[1][0]['commands'].append({'path': path, 'arguments': [
                {'id': 'limit', 'long': 'limit', 'short': None, 'index': None}]})
            extra.extend([path, path + ' --limit'])
        args[0]['gaps'].append({
            'surfaces': extra, 'platforms': ['arch'], 'owner': 'fixture',
            'reason': 'synthetic checker scale test, not product coverage',
            'missing': ['parser', 'help', 'refusal', 'success', 'state', 'fault', 'concurrency'],
        })
        payload = {key: value for key, value in args[1][0].items() if key != 'build'}
        args[0]['surface_digests'][0]['sha256'] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        for features in (['arch', 'license', 'pgp'], ['debian-pure'], [], ['license']) * 3:
            args[3]['features'] = features
            args[1][0]['build']['features'] = features
            args[2][0]['features'] = features
            args[0]['surface_digests'][0]['features'] = features
            report = COVERAGE.admit(*args)
            self.assertTrue(report['passed'])
            self.assertEqual(report['counts']['gaps'], 2001)


class StrictEvidenceReader(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'real filesystem symlink check requires Unix owner')
    def test_symlink_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence.json'
            target = Path(directory) / 'target.json'
            target.write_text('{}')
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                COVERAGE.read_json(path)

    def test_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        for value in ('{"result":"FAIL","result":"PASS"}', '{"duration":NaN}'):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'evidence.json'
                path.write_text(value)
                with self.assertRaises(ValueError):
                    COVERAGE.read_json(path)

    def test_file_size_bound_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence.json'
            path.write_text(' ' * (COVERAGE.MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                COVERAGE.read_json(path)

    def test_valid_json_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'evidence.json'
            path.write_text(json.dumps({'schema_version': 1}))
            self.assertEqual(COVERAGE.read_json(path), {'schema_version': 1})


class CommandLineAdmission(unittest.TestCase):
    def test_real_entrypoint_reports_success_and_rejects_mutated_receipts(self):
        for mutation in ('none', 'missing', 'digest'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest, surfaces, receipts, provenance, required = fixture()
                if mutation == 'missing':
                    receipts.clear()
                elif mutation == 'digest':
                    receipts[0]['binary_sha256'] = 'd' * 64
                values = {'manifest': manifest, 'surface': surfaces[0], 'receipts': receipts,
                          'provenance': provenance, 'required': required}
                command = [sys.executable, str(Path(__file__).with_name('check-contract-coverage.py'))]
                for name, value in values.items():
                    path = root / (name + '.json')
                    path.write_text(json.dumps(value))
                    command.extend(['--' + name, str(path)])
                summary = root / 'summary.md'
                command.extend(['--summary', str(summary)])
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if mutation == 'none' else 2, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['passed'], mutation == 'none')
                self.assertEqual(summary.exists(), mutation == 'none')


if __name__ == '__main__':
    unittest.main()

"""Receipts must derive from observed executions of reviewed assertions."""
import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import unittest
import tempfile
import os
import shutil
import subprocess
from unittest.mock import patch

from test_contract_coverage import fixture

SPEC = importlib.util.spec_from_file_location(
    'native_contracts', Path(__file__).with_name('run-native-contracts.py'))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)


@unittest.skipUnless(os.name == 'posix' and shutil.which('runuser'), 'requires Linux runuser')
class NativeRunner(unittest.TestCase):
    def test_cli_runner_drops_root_and_preserves_arguments_and_exit(self):
        runner = Path(__file__).with_name('native-test-runner.sh').resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            for name in ('cli_comprehensive-fixture', 'e2e_runtime_management-fixture',
                         'env_lockfile_integrity-fixture', 'other-fixture'):
                binary = root / name
                binary.write_text('#!/bin/sh\nid -u\nprintf "%s\\n" "$1"\nexit 23\n')
                binary.chmod(0o755)
                result = subprocess.run(['bash', str(runner), str(binary), 'argument with spaces'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 23, result.stderr)
                uid, argument = result.stdout.splitlines()
                self.assertEqual(argument, 'argument with spaces')
                if os.getuid() == 0 and name != 'other-fixture':
                    self.assertNotEqual(int(uid), 0)
                else:
                    self.assertEqual(int(uid), os.getuid())


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
    def test_fault_and_concurrency_receipts_require_reviewed_daemon_owners(self):
        for name, kind in (
            ('concurrent_pings_preserve_boundary_ids_and_backend_state', 'concurrency'),
            ('incomplete_frames_disconnect_without_breaking_a_fresh_client', 'fault'),
        ):
            manifest, provenance, report, _ = parser_fixture()
            identity = 'omg::coverage_18::' + name
            contract = manifest['contracts'][0]
            contract.update(binary='omgd', requires=[kind], assertions={kind: ['observed-condition']})
            contract['tests'][0].update(lane='native-daemon-fixture', id=identity,
                evidence=[kind], assertions=['observed-condition', 'fixture-cleanup'])
            provenance.update(lane='native-daemon-fixture', binaries={'omgd': 'd' * 64})
            report['tests'][identity] = report['tests'].pop('install-dry-run-state')
            rows, _ = NATIVE.behavior_receipts(manifest, provenance, report)
            self.assertEqual(rows[0]['evidence'], [kind])
            provenance['lane'] = 'native-cli-fixture'
            contract['tests'][0]['lane'] = 'native-cli-fixture'
            with self.assertRaises(ValueError):
                NATIVE.behavior_receipts(manifest, provenance, report)

    def test_daemon_subject_is_the_owned_production_server_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            target.mkdir()
            harness = target / 'coverage-18'
            harness.write_bytes(b'production server inside integration harness')
            before = NATIVE.sha256_file(harness)
            _, _, _, provenance, _ = fixture()
            observed = NATIVE.daemon_provenance(provenance, {'source': 'fixture'}, harness, before)
            self.assertEqual(observed['binaries']['omgd'], before)
            self.assertEqual(observed['subject_kind'], 'production-server-test-harness-injected-backend')
            harness.write_bytes(b'replaced harness')
            with self.assertRaisesRegex(ValueError, 'changed during execution'):
                NATIVE.daemon_provenance(provenance, {'source': 'fixture'}, harness, before)
            listing = {'rust-build-meta': {'target-directory': str(target)}, 'rust-suites': {
                'omg::bin/omgd': {'package-id': 'omg'},
                'omg::coverage_18': {'package-id': 'omg', 'binary-path': str(harness)}}}
            self.assertEqual(NATIVE.daemon_subject(listing, root), harness)
            listing['rust-suites']['omg::coverage_18']['package-id'] = 'foreign'
            with self.assertRaisesRegex(ValueError, 'package'):
                NATIVE.daemon_subject(listing, root)
            listing['rust-suites']['omg::coverage_18']['package-id'] = 'omg'
            listing['rust-suites']['omg::coverage_18']['binary-path'] = str(root / 'outside')
            (root / 'outside').write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError, 'harness'):
                NATIVE.daemon_subject(listing, root)

    def test_daemon_receipts_preserve_failures_skips_and_harness_identity(self):
        manifest, provenance, report, required = parser_fixture()
        identity = 'omg::coverage_18::package_inventory_and_updates_survive_the_production_transport'
        contract = manifest['contracts'][0]
        contract.update(binary='omgd', requires=['success'], assertions={'success': ['exact-inventory']})
        contract['tests'][0].update(lane='native-daemon-fixture', id=identity,
            evidence=['success'], assertions=['exact-inventory', 'fixture-cleanup'])
        provenance.update(lane='native-daemon-fixture', binaries={'omgd': 'd' * 64})
        report['tests'][identity] = report['tests'].pop('install-dry-run-state')
        rows, selected = NATIVE.behavior_receipts(manifest, provenance, report)
        self.assertEqual(selected, required)
        self.assertEqual(rows[0]['binary_sha256'], 'd' * 64)
        self.assertEqual(rows[0]['evidence'], ['success'])
        contract['surface'] = 'ipc:Status'
        contract['source'] = 'src/daemon/protocol.rs'
        manifest['interfaces'] = [dict(id='ipc:Status', binary='omgd', source='src/daemon/protocol.rs', platforms=['arch'])]
        manifest['gaps'] = [dict(surface='omgd', platforms=['arch'], owner='daemon',
                                reason='process behavior remains unverified', missing=['success'])]
        surface = dict(schema_version=1, binary='omgd', available=True,
                       build={key: provenance[key] for key in ('source_sha', 'platform', 'os', 'arch', 'features')},
                       commands=[dict(path='omgd', arguments=[])])
        manifest['surface_digests'] = [dict(binary='omgd', platform='arch', features=provenance['features'],
            sha256=hashlib.sha256(json.dumps({key: value for key, value in surface.items() if key != 'build'},
                sort_keys=True, separators=(',', ':')).encode()).hexdigest())]
        admitted = NATIVE.COVERAGE.admit(manifest, [surface], rows, provenance, selected)
        self.assertTrue(admitted['passed'])
        self.assertFalse(admitted['behavioral_progress']['target_met'])
        report['tests'][identity]['attempts'].insert(0, {'result': 'FAIL', 'duration_ms': 1})
        rows, _ = NATIVE.behavior_receipts(manifest, provenance, report)
        self.assertEqual([row['result'] for row in rows], ['FAIL', 'PASS'])
        self.assertEqual(rows[0]['assertions'], [])
        self.assertFalse(NATIVE.COVERAGE.admit(manifest, [surface], rows, provenance, selected)['passed'])
        report['tests'][identity]['runtime_skip'] = True
        rows, _ = NATIVE.behavior_receipts(manifest, provenance, report)
        self.assertEqual([row['result'] for row in rows], ['BLOCKED', 'BLOCKED'])
        self.assertTrue(all(not row['evidence'] for row in rows))
        contract['tests'][0]['id'] = 'omg::coverage_18::unreviewed'
        with self.assertRaises(ValueError):
            NATIVE.behavior_receipts(manifest, provenance, report)

    def test_real_daemon_manifest_has_only_reviewed_production_server_assertions(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'tests/contracts/manifest.json').read_text())
        mapped = [contract for contract in manifest['contracts']
                  if any(binding['lane'] == 'native-daemon-fixture' for binding in contract['tests'])]
        self.assertEqual(len(mapped), 22)
        selected = set()
        for contract in mapped:
            self.assertEqual(contract['binary'], 'omgd')
            self.assertTrue(contract['critical'])
            self.assertIn('not native package transactions', contract['scope'])
            for binding in contract['tests']:
                self.assertIn(binding['id'], NATIVE.DAEMON_TESTS)
                self.assertIn('fixture-cleanup', binding['assertions'])
                promised = {assertion for kind in binding['evidence']
                            for assertion in contract['assertions'][kind]}
                self.assertTrue(promised <= set(binding['assertions']))
                selected.add(binding['id'])
        self.assertEqual(selected, NATIVE.DAEMON_TESTS)
        health = next(c for c in mapped if c['id'] == 'omgd.health-live-process.server-fixture')
        policy = json.loads((root / 'tests/contracts/platforms.json').read_text())
        self.assertEqual(set(health['platforms']), {o['id'] for o in policy['owners'] if o['os'] == 'linux'})
        capacity = next(c for c in mapped if c['id'] == 'omgd.connection-capacity.server-fixture')
        self.assertEqual(capacity['source'], 'src/daemon/server.rs')
        self.assertEqual(set(capacity['requires']), {'concurrency', 'state'})
        gaps = list(NATIVE.COVERAGE.expand_gaps(json.loads((root / 'tests/contracts/gaps.json').read_text())['gaps']))
        self.assertTrue(any(g['surface'] == capacity['surface'] for g in gaps),
                        'one capacity test does not exhaust the broader transport contract')

    def test_reviewed_ping_requires_all_contracts_before_surface_credit(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'tests/contracts/manifest.json').read_text())
        gaps = list(NATIVE.COVERAGE.expand_gaps(json.loads((root / 'tests/contracts/gaps.json').read_text())['gaps']))
        contracts = {c['id']: c for c in manifest['contracts'] if c['surface'] == 'ipc:Ping'}
        self.assertEqual(len(contracts), 3)
        self.assertFalse(any(g['surface'] == 'ipc:Ping' for g in gaps))
        for identity in contracts:
            partial = NATIVE.COVERAGE.behavioral_progress(contracts, [], set(contracts) - {identity})
            self.assertEqual(partial['covered'], 0)
        complete = NATIVE.COVERAGE.behavioral_progress(contracts, [], set(contracts))
        self.assertEqual(complete['covered_surfaces'], ['ipc:Ping'])
        self.assertFalse(complete['target_met'], 'one domain cannot certify inventory review')

    def test_entrypoint_loads_contracts_before_binding_and_reports_binding_failure(self):
        manifest = {'contracts': [{'id': 'reviewed-contract'}]}
        gaps = [{'id': 'known-gap'}]
        listing = {'rust-suites': {
            name: {'binary-path': name} for name in ('omg::cli_surface', 'omg::bin/omgd')}}

        def read_json(path):
            return {'manifest.json': manifest, 'gaps.json': {'gaps': gaps},
                    'list.json': listing}[Path(path).name]

        def reject_binding(loaded, provenance, observed, root):
            self.assertEqual(loaded['contracts'], manifest['contracts'])
            self.assertEqual(loaded['gaps'], gaps)
            self.assertEqual(observed, listing)
            raise ValueError('owning behavior harness is missing')

        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {'OMG_CONTRACT_SURFACE_OUT': directory,
                    'OMG_CONTRACT_SOURCE_SHA': 'current-source', 'GITHUB_RUN_ID': '123',
                    'GITHUB_RUN_ATTEMPT': '1', 'OMG_CONTRACT_PLATFORM': 'test-owner'}), \
                patch.object(NATIVE.sys, 'argv', ['runner', '--features', 'arch']), \
                patch.object(NATIVE.sys, 'platform', 'win32'), \
                patch.object(NATIVE, 'command_output', return_value='current-source'), \
                patch.object(NATIVE, 'sha256_file', return_value='a' * 64), \
                patch.object(NATIVE.COVERAGE, 'read_json', side_effect=read_json), \
                patch.object(NATIVE.SELECTION, 'selected_tests'), \
                patch.object(NATIVE, 'mapped_behavior_subjects', side_effect=reject_binding) as binding, \
                patch.object(NATIVE.subprocess, 'run') as command:
            self.assertEqual(NATIVE.main(), 2)
            binding.assert_called_once()
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][:3], ['cargo', 'nextest', 'list'])
            error = json.loads((Path(directory) / 'execution/admission-error.json').read_text())
            self.assertEqual(error['error'], 'owning behavior harness is missing')

    def test_runtime_and_environment_contracts_have_all_platform_owners(self):
        policy = json.loads((Path(__file__).resolve().parents[1] / 'tests/contracts/platforms.json').read_text())
        required = {'e2e_runtime_management', 'env_lockfile_integrity'}
        for owner in policy['owners']:
            with self.subTest(owner=owner['id']):
                args = NATIVE.cargo_test_args(','.join(owner['features']))
                selected = {args[index + 1] for index, value in enumerate(args) if value == '--test'}
                self.assertTrue(required <= selected)
                self.assertTrue(required <= set(owner['native_integration_suites']))

    def test_behavior_subjects_bind_real_product_pair_and_owning_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'target'
            (target / 'debug').mkdir(parents=True)
            for name in ('omg', 'omgd', 'suite'):
                (target / 'debug' / name).write_bytes(name.encode())
            listing = {
                'rust-build-meta': {'target-directory': str(target), 'non-test-binaries': {
                    'owning-package': [dict(name=name, kind='bin-exe', path='debug/' + name,
                                           **{'build-platform': 'target'}) for name in ('omg', 'omgd')]}},
                'rust-suites': {'omg::debian_e2e_tests': {
                    'package-id': 'owning-package', 'binary-path': str(target / 'debug/suite')}}}
            subjects = NATIVE.behavior_subjects(listing, root)
            self.assertEqual(set(subjects), {'omg', 'omgd', 'harness'})
            self.assertEqual(subjects['omg'], target / 'debug/omg')
            (target / 'debug/search-suite').write_bytes(b'search harness')
            listing['rust-suites']['omg::cli_comprehensive'] = {
                'package-id': 'owning-package', 'binary-path': str(target / 'debug/search-suite')}
            (target / 'debug/runtime-suite').write_bytes(b'runtime harness')
            listing['rust-suites']['omg::e2e_runtime_management'] = {
                'package-id': 'owning-package', 'binary-path': str(target / 'debug/runtime-suite')}
            (target / 'debug/env-suite').write_bytes(b'environment harness')
            listing['rust-suites']['omg::env_lockfile_integrity'] = {
                'package-id': 'owning-package', 'binary-path': str(target / 'debug/env-suite')}
            manifest, _, _, provenance, _ = fixture()
            manifest['contracts'][0]['tests'] = [
                {'lane': 'native-cli-fixture', 'id': name} for name in sorted(NATIVE.BEHAVIOR_TESTS)]
            combined = NATIVE.mapped_behavior_subjects(manifest, provenance, listing, root)
            self.assertEqual(set(combined), {'omg', 'omgd',
                'harness:omg::debian_e2e_tests', 'harness:omg::cli_comprehensive',
                'harness:omg::e2e_runtime_management', 'harness:omg::env_lockfile_integrity'})
            missing = copy.deepcopy(listing)
            del missing['rust-suites']['omg::cli_comprehensive']
            with self.assertRaisesRegex(ValueError, 'missing owning'):
                NATIVE.mapped_behavior_subjects(manifest, provenance, missing, root)
            foreign = copy.deepcopy(listing)
            (target / 'debug/foreign-omg').write_bytes(b'wrong product')
            foreign['rust-suites']['omg::cli_comprehensive']['package-id'] = 'other-package'
            foreign['rust-build-meta']['non-test-binaries']['other-package'] = [
                dict(row, path='debug/foreign-omg' if row['name'] == 'omg' else row['path'])
                for row in foreign['rust-build-meta']['non-test-binaries']['owning-package']]
            with self.assertRaisesRegex(ValueError, 'different product'):
                NATIVE.mapped_behavior_subjects(manifest, provenance, foreign, root)
            for fault in ('missing', 'duplicate', 'kind', 'platform', 'foreign-harness'):
                invalid = copy.deepcopy(listing)
                binaries = invalid['rust-build-meta']['non-test-binaries']['owning-package']
                if fault == 'missing':
                    binaries.pop()
                elif fault == 'duplicate':
                    binaries.append(dict(binaries[0]))
                elif fault == 'kind':
                    binaries[0]['kind'] = 'lib'
                elif fault == 'platform':
                    binaries[0]['build-platform'] = 'host'
                else:
                    (root / 'foreign').write_bytes(b'foreign harness')
                    invalid['rust-suites']['omg::debian_e2e_tests']['binary-path'] = str(root / 'foreign')
                with self.subTest(fault=fault), self.assertRaises(ValueError):
                    NATIVE.behavior_subjects(invalid, root)
            for path in ('../foreign', str(root / 'foreign')):
                listing['rust-build-meta']['non-test-binaries']['owning-package'][0]['path'] = path
                with self.subTest(path=path), self.assertRaises(ValueError):
                    NATIVE.behavior_subjects(listing, root)

    def test_behavior_adapter_cannot_promote_unreviewed_test_or_skip(self):
        manifest, provenance, report, _ = parser_fixture()
        contract = manifest['contracts'][0]
        contract.update(requires=['success', 'state'], assertions={'success': ['exact-status'], 'state': ['read-only']})
        binding = contract['tests'][0]
        identity = 'omg::debian_e2e_tests::test_cli_status_shows_debian_info'
        binding.update(lane='native-cli-fixture', id=identity, evidence=['success', 'state'],
                       assertions=['exact-status', 'read-only', 'fixture-cleanup'])
        provenance['lane'] = 'native-cli-fixture'
        report['tests'][identity] = report['tests'].pop('install-dry-run-state')
        receipts, _ = NATIVE.behavior_receipts(manifest, provenance, report)
        self.assertEqual(receipts[0]['evidence'], ['success', 'state'])
        self.assertEqual(receipts[0]['cleanup'], 'PASS')
        _, surfaces, _, _, _ = fixture()
        admission = NATIVE.COVERAGE.admit(manifest, surfaces, receipts, provenance, [contract['id']])
        self.assertTrue(admission['passed'])
        self.assertEqual(admission['evidence']['parser']['passed'], 0)
        self.assertEqual(admission['evidence']['state']['passed'], 1)
        binding['assertions'].remove('fixture-cleanup')
        with self.assertRaisesRegex(ValueError, 'cleanup'):
            NATIVE.behavior_receipts(manifest, provenance, report)
        binding['assertions'].append('fixture-cleanup')
        report['tests'][identity]['attempts'].insert(0, {'result': 'FAIL', 'duration_ms': 1})
        receipts, _ = NATIVE.behavior_receipts(manifest, provenance, report)
        self.assertEqual([row['result'] for row in receipts], ['FAIL', 'PASS'])
        self.assertEqual(receipts[0]['cleanup'], 'NOT_STARTED')
        self.assertEqual(receipts[0]['evidence'], [])
        report['tests'][identity]['runtime_skip'] = True
        receipts, _ = NATIVE.behavior_receipts(manifest, provenance, report)
        self.assertEqual(receipts[0]['result'], 'BLOCKED')
        self.assertEqual(receipts[0]['evidence'], [])
        binding['id'] = 'unreviewed-test'
        with self.assertRaises(ValueError):
            NATIVE.behavior_receipts(manifest, provenance, report)

    def test_real_behavior_manifest_has_only_reviewed_mappings_and_explicit_cleanup(self):
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / 'tests/contracts/manifest.json').read_text())
        mapped = [contract for contract in manifest['contracts']
                  if any(binding['lane'] == 'native-cli-fixture' for binding in contract['tests'])]
        self.assertEqual({contract['id'] for contract in mapped}, {
            'omg.status.fixture', 'omg.status.json.fixture', 'omg.install.consent.fixture',
            'omg.search.records.fixture', 'omg.search.query.fixture',
            'omg.search.limit.fixture', 'omg.search.json.fixture',
            'omg.explicit.records.fixture', 'omg.explicit.count.fixture'} | {
                'omg.counter.' + name + '.fixture' for name in ('ec', 'tc', 'oc', 'uc')} | {
                'omg.runtime.' + name + '.fixture' for name in (
                    'nvmrc', 'python-pin', 'tool-versions', 'go-mod', 'multi-runtime',
                    'pin-precedence', 'rust-pin', 'rust-pin-locked', 'engines-range', 'which-node',
                    'uninstall-lifecycle', 'which-registry', 'list-installed', 'list-runtime', 'list-json',
                    'list-installed-backend-errors', 'list-runtime-backend-errors', 'list-json-backend-errors')} | {
                'omg.environment.' + name + '.fixture' for name in (
                    'capture-registry', 'php-restore', 'registry-restore', 'unsupported-capture')} | {
                'omg.snapshot.list-index-failures.fixture',
                'omg.snapshot.delete-index-failures.fixture'})
        for contract in mapped:
            self.assertTrue(contract['critical'])
            self.assertIn('not native package transactions', contract['scope'])
            for binding in contract['tests']:
                self.assertIn(binding['id'], NATIVE.BEHAVIOR_TESTS)
                self.assertIn('fixture-cleanup', binding['assertions'])
                promised = {assertion for kind in binding['evidence']
                            for assertion in contract['assertions'][kind]}
                self.assertTrue(promised <= set(binding['assertions']),
                                f"{contract['id']}: {binding['id']} lacks {promised - set(binding['assertions'])}")

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
                shared = {'cli_surface', 'git_hooks_contract', 'coverage_18',
                          'e2e_runtime_management', 'env_lockfile_integrity'}
                if set(features.split(',')) & {'arch', 'debian', 'debian-pure', 'fedora'}:
                    shared.add('cli_comprehensive')
                self.assertEqual(tests, expected | shared)

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

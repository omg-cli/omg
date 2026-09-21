#!/usr/bin/env python3
"""Run native tests once, retaining separate parser and CLI fixture evidence.

Parser subjects are test harnesses; CLI fixture subjects are debug executables.
Neither is a release or native transaction attestation. Only reviewed assertion
mappings are accepted; these local receipts are diagnostic evidence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location(
    'test_selection', Path(__file__).with_name('check-test-selection.py'))
SELECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTION)
COVERAGE = SELECTION.COVERAGE
require = COVERAGE.require


BEHAVIOR_TESTS = frozenset({
    'omg::security_daemon_optional::sbom_without_daemon_exports_shared_inventory_and_preserves_report_on_failure',
    'omg::security_daemon_optional::security_scan_without_daemon_preserves_inventory_errors_and_recovers',
}) | frozenset('omg::debian_e2e_tests::' + name for name in (
    'test_cli_status_shows_debian_info', 'test_cli_debian_respects_ci_mode')) | frozenset({
    'omg::cli_comprehensive::search_json_preserves_exact_records_ranking_limits_and_package_state',
    'omg::cli_comprehensive::explicit_shortcut_uses_the_same_isolated_state_as_explicit_count',
    'omg::cli_comprehensive::prompt_counters_preserve_exact_counts_with_global_flags_and_reject_extra_arguments'}) | frozenset(
    'omg::e2e_runtime_management::' + name for name in (
        'test_detect_nvmrc', 'test_detect_python_version', 'test_detect_tool_versions',
        'test_go_mod_version', 'test_multi_runtime_detection', 'test_conflicting_version_files',
        'test_rust_toolchain_toml', 'rust_stable_pin_refuses_a_concurrent_mutation_without_activation',
        'test_package_json_engines', 'test_which_shows_active_runtime',
        'which_resolves_every_runtime_with_project_parent_global_precedence_without_mutation',
        'list_reports_exact_installed_versions_for_every_runtime_and_excludes_incomplete_state',
        'list_rejects_duplicate_json_flags_and_reports_backend_errors_once',
        'every_runtime_uninstall_preserves_active_siblings_and_external_state')) | frozenset(
    'omg::env_lockfile_integrity::' + name for name in (
        'snapshot_index_access_failures_never_report_empty_or_delete_saved_state',
        'capture_records_every_registered_runtime_and_check_detects_its_drift',
        'snapshot_restores_installed_php_offline_without_replacing_its_payload',
        'snapshot_restores_all_registered_installed_runtimes_and_executes_selected_payloads',
        'capture_without_package_backend_refuses_without_creating_or_overwriting_lockfile'))


DAEMON_TESTS = frozenset('omg::coverage_18::' + name for name in (
    'security_audit_backend_failure_cannot_report_a_clean_scan',
    'debian_search_preserves_catalog_limits_cache_and_refusal_over_real_ipc',
    'version_mismatch_gets_exact_parse_error_then_connection_closes',
    'frame_too_short_for_header_gets_parse_error_then_connection_closes',
    'undecodable_payload_gets_parse_error_validation_failure_then_close',
    'oversized_frame_tears_down_silently_without_any_response_frame',
    'exact_frame_size_boundaries_reach_protocol_validation',
    'connection_capacity_refuses_overflow_and_recovers_released_permits',
    'health_reports_live_uptime_rss_and_worker_state_without_mutating_packages',
    'concurrent_pings_preserve_boundary_ids_and_backend_state',
    'incomplete_frames_disconnect_without_breaking_a_fresh_client',
    'rate_limited_burst_rejects_with_exact_envelope_and_keeps_connection_open',
    'suggestions_preserve_catalog_order_limits_refusal_and_state_over_real_ipc',
    'package_inventory_and_updates_survive_the_production_transport',
    'clearing_search_cache_forces_a_new_lookup_over_real_ipc',
    'package_info_cache_preserves_metadata_and_missing_package_identity',
    'isolated_refresh_refusal_preserves_server_liveness',
    'fragmented_then_coalesced_frames_preserve_response_order_and_ids',
    'active_connection_metric_returns_to_baseline_after_disconnect'))


def daemon_subject(listing, root):
    """The production server runs inside coverage_18, not a child omgd binary."""
    target = Path(listing['rust-build-meta']['target-directory']).resolve(strict=True)
    require(target.is_relative_to(root.resolve()), 'target directory escapes checkout')
    suite = listing['rust-suites']['omg::coverage_18']
    require(suite['package-id'] == listing['rust-suites']['omg::bin/omgd']['package-id'],
            'daemon harness package mismatch')
    path = Path(suite['binary-path'])
    require(path.is_file() and not path.is_symlink() and path.resolve(strict=True).is_relative_to(target),
            'invalid daemon harness')
    return path


def daemon_provenance(provenance, recipe, path, before_hash):
    require(sha256_file(path) == before_hash, 'daemon harness changed during execution')
    result = dict(provenance, lane='native-daemon-fixture',
        subject_kind='production-server-test-harness-injected-backend',
        binaries=dict(provenance['binaries'], omgd=before_hash),
        harnesses_sha256={'omg::coverage_18': before_hash})
    result['recipe_sha256'] = hashlib.sha256(json.dumps(
        {'recipe': recipe, 'daemon_harness': before_hash}, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    return result


def parser_receipts(manifest, provenance, report):
    return execution_receipts(manifest, provenance, report, behavior=False)


def behavior_receipts(manifest, provenance, report):
    return execution_receipts(manifest, provenance, report, behavior=True)


def behavior_subjects(listing, root, suite_name='omg::debian_e2e_tests'):
    """Resolve the same package's child executables, never its parser harness."""
    meta = listing['rust-build-meta']
    target = Path(meta['target-directory']).resolve(strict=True)
    require(target.is_relative_to(root.resolve()), 'target directory escapes checkout')
    suite = listing['rust-suites'][suite_name]
    subjects = {'harness': Path(suite['binary-path'])}
    for row in meta['non-test-binaries'][suite['package-id']]:
        if row['name'] not in ('omg', 'omgd'):
            continue
        relative = Path(row['path'])
        require(not relative.is_absolute() and '..' not in relative.parts
                and row['kind'] == 'bin-exe' and row['build-platform'] == 'target',
                'invalid child executable metadata')
        require(row['name'] not in subjects, 'duplicate child executable')
        subjects[row['name']] = target / relative
    require(set(subjects) == {'omg', 'omgd', 'harness'}, 'missing behavior executable')
    for path in subjects.values():
        require(path.is_file() and not path.is_symlink()
                and path.resolve(strict=True).is_relative_to(target), 'unsafe behavior executable')
    return subjects


def mapped_behavior_subjects(manifest, provenance, listing, root):
    """Bind every reviewed owning harness, refusing foreign product pairs."""
    suites = set()
    for contract in manifest['contracts']:
        if COVERAGE.applies(contract, provenance):
            for binding in contract['tests']:
                if binding['lane'] == 'native-cli-fixture':
                    require(binding['id'] in BEHAVIOR_TESTS, 'unreviewed behavior test')
                    suites.add(binding['id'].rsplit('::', 1)[0])
    combined = {}
    for suite in sorted(suites):
        require(suite in listing['rust-suites'], 'missing owning behavior harness')
        subjects = behavior_subjects(listing, root, suite)
        for name in ('omg', 'omgd'):
            require(name not in combined or combined[name] == subjects[name],
                    'behavior harnesses use different product executables')
            combined[name] = subjects[name]
        combined['harness:' + suite] = subjects['harness']
    return combined


def execution_receipts(manifest, provenance, report, *, behavior):
    receipts, required = [], []
    for contract in manifest['contracts']:
        if not COVERAGE.applies(contract, provenance):
            continue
        bindings = [binding for binding in contract['tests'] if binding['lane'] == provenance['lane']]
        if not bindings:
            continue
        if not behavior:
            require(contract['requires'] == ['parser'], 'native parser adapter cannot certify behavioral evidence')
        required.append(contract['id'])
        for binding in bindings:
            if behavior:
                reviewed = DAEMON_TESTS if provenance['lane'] == 'native-daemon-fixture' else BEHAVIOR_TESTS
                if provenance['lane'] == 'native-daemon-fixture':
                    require(contract['binary'] == 'omgd', 'daemon fixture cannot certify a CLI binary')
                require(binding['id'] in reviewed and 'fixture-cleanup' in binding['assertions'],
                        'behavior test or cleanup assertion has not been reviewed')
                allowed = {'success', 'state', 'refusal'}
                if provenance['lane'] == 'native-daemon-fixture':
                    allowed |= {'fault', 'concurrency'}
                require(set(binding['evidence']) <= allowed, 'unsupported fixture evidence')
            else:
                require(binding['evidence'] == ['parser'], 'nonparser binding')
            require(binding['id'] in report['tests'], 'missing mapped execution')
            execution = report['tests'][binding['id']]
            for index, attempt in enumerate(execution['attempts'], 1):
                result = attempt['result']
                # These reviewed fixtures have no approved runtime skip path.
                if result == 'SKIPPED' or execution['runtime_skip']:
                    result = 'BLOCKED'
                receipt = {key: provenance[key] for key in COVERAGE.IDENTITY}
                receipt.update(
                    schema_version=1, contract=contract['id'], test_id=binding['id'],
                    binary=contract['binary'], binary_sha256=provenance['binaries'][contract['binary']],
                    attempt=index, attempt_count=len(execution['attempts']), result=result,
                    evidence=binding['evidence'] if result == 'PASS' else [],
                    assertions=binding['assertions'] if result == 'PASS' else [],
                    duration_ms=attempt['duration_ms'], seed=None,
                    cleanup='PASS' if result == 'PASS' else 'NOT_STARTED',
                )
                receipts.append(receipt)
    require(required, 'zero contract denominator')
    return receipts, sorted(required)


def sha256_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'invalid binary or recipe file')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def cargo_test_args(features):
    active = COVERAGE.strings(features.split(','))
    suites = ['cli_surface', 'git_hooks_contract', 'coverage_18',
              'e2e_runtime_management', 'env_lockfile_integrity']
    if active & {'arch', 'debian', 'debian-pure', 'fedora'}:
        suites.append('cli_comprehensive')
    if active & {'arch', 'debian', 'fedora'}:
        suites.append('security_daemon_optional')
    if active & {'debian', 'debian-pure'}:
        suites.extend(['debian_tests', 'debian_daemon_tests', 'debian_ipc_tests',
                       'debian_search_integration', 'debian_cache_tests', 'debian_e2e_tests'])
    if 'debian-pure' in active:
        suites.append('debian_pure_integration')
    if 'fedora' in active:
        suites.append('fedora_tests')
    return ['--lib', '--bins'] + [arg for suite in suites for arg in ('--test', suite)] + [
        '--no-default-features', '--features', features,
        '--locked', '--profile', 'ci',
    ]


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def command_output(argv):
    return subprocess.check_output(argv, text=True, encoding='utf-8').strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', required=True)
    args = parser.parse_args()
    directory = Path(os.environ['OMG_CONTRACT_SURFACE_OUT'])
    directory.mkdir(parents=True, exist_ok=True)
    evidence = directory / 'execution'
    evidence.mkdir(exist_ok=True)
    try:
        for name in ('recipe.json', 'list.json', 'provenance.json', 'junit.xml',
                     'selection.json', 'receipts.json', 'required.json', 'coverage.json',
                     'admission-error.json'):
            (evidence / name).unlink(missing_ok=True)
        source = command_output(['git', 'rev-parse', 'HEAD'])
        require(source == os.environ['OMG_CONTRACT_SOURCE_SHA'], 'checkout source mismatch')
        manifest = COVERAGE.read_json('tests/contracts/manifest.json')
        manifest['gaps'] = COVERAGE.read_json('tests/contracts/gaps.json')['gaps']
        features = args.features.split(',')
        # Cargo/nextest target runners apply to the host platform too. Preserve
        # all other suites' privilege model; only the isolated CLI harness drops root.
        if sys.platform == 'linux' and os.geteuid() == 0:
            host = command_output(['rustc', '-vV']).split('host: ', 1)[1].splitlines()[0]
            runner_key = 'CARGO_TARGET_' + host.upper().replace('-', '_') + '_RUNNER'
            require(runner_key not in os.environ, 'root native runner conflicts with configured target runner')
            os.environ[runner_key] = 'bash scripts/native-test-runner.sh'
        COVERAGE.strings(features)
        cargo_args = cargo_test_args(args.features)
        recipe = {
            'source_sha': source, 'args': cargo_args,
            'rustc': command_output(['rustc', '-vV']),
            'cargo': command_output(['cargo', '--version']),
            'nextest': command_output(['cargo', 'nextest', '--version']),
            'env': {key: value for key, value in sorted(os.environ.items())
                    if key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                               'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET')
                    or key.startswith('CARGO_PROFILE_')
                    or (key.startswith('CARGO_TARGET_') and key.endswith('_RUNNER'))},
            'files': {name: sha256_file(name) for name in
                      ('Cargo.toml', 'Cargo.lock', '.config/nextest.toml', '.github/workflows/ci.yml',
                       'scripts/native-test-runner.sh')},
        }
        if Path('.cargo/config.toml').is_file():
            recipe['files']['.cargo/config.toml'] = sha256_file('.cargo/config.toml')
        write_json(evidence / 'recipe.json', recipe)
        with (evidence / 'list.json').open('wb') as stream:
            subprocess.run(['cargo', 'nextest', 'list', *cargo_args, '--message-format', 'json'],
                           stdout=stream, check=True)
        listing = COVERAGE.read_json(evidence / 'list.json')
        required_binaries = ['omg::bin/omgd'] + [
            'omg::' + cargo_args[index + 1] for index, value in enumerate(cargo_args) if value == '--test']
        SELECTION.selected_tests(listing, required_binaries)
        subjects = {'omg': 'omg::cli_surface', 'omgd': 'omg::bin/omgd'}
        binaries = {binary: sha256_file(listing['rust-suites'][identity]['binary-path'])
                    for binary, identity in subjects.items()}
        provenance = {
            'schema_version': 1, 'source_sha': source,
            'run_id': os.environ['GITHUB_RUN_ID'], 'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT']),
            'recipe_sha256': hashlib.sha256(json.dumps(recipe, sort_keys=True,
                                                      separators=(',', ':')).encode()).hexdigest(),
            'binaries': binaries, 'subject_kind': 'parser-test-harness',
            'platform': os.environ['OMG_CONTRACT_PLATFORM'],
            'os': {'linux': 'linux', 'darwin': 'macos'}.get(sys.platform, sys.platform),
            'arch': {'AMD64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine()),
            'features': sorted(features), 'lane': 'native-parser',
        }
        write_json(evidence / 'provenance.json', provenance)
        behavior_paths = mapped_behavior_subjects(manifest, provenance, listing, Path.cwd())
        behavior_hashes = {name: sha256_file(path) for name, path in behavior_paths.items()}
        daemon_path = daemon_subject(listing, Path.cwd())
        daemon_hash = sha256_file(daemon_path)
        behavior_directory = evidence / 'behavior'
        behavior_directory.mkdir(exist_ok=True)
        daemon_directory = evidence / 'daemon'
        daemon_directory.mkdir(exist_ok=True)
        for name in ('provenance.json', 'receipts.json', 'required.json', 'coverage.json'):
            (behavior_directory / name).unlink(missing_ok=True)
            (daemon_directory / name).unlink(missing_ok=True)
        junit = Path('target/nextest/ci/junit.xml')
        # Clear only this invocation's outputs so restored/stale artifacts cannot pass.
        for path in (junit, directory / 'omg.json', directory / 'omgd.json'):
            path.unlink(missing_ok=True)
        run_env = dict(os.environ)
        if behavior_paths:
            run_env['OMG_CONTRACT_EXPECTED_CLI'] = str(behavior_paths['omg'])
        result = subprocess.run(['cargo', 'nextest', 'run', *cargo_args], check=False, env=run_env)
        require(junit.is_file() and not junit.is_symlink()
                and junit.stat().st_size <= COVERAGE.MAX_BYTES, 'missing or invalid execution report')
        shutil.copyfile(junit, evidence / 'junit.xml')
        for binary, identity in subjects.items():
            require(sha256_file(listing['rust-suites'][identity]['binary-path']) == binaries[binary],
                    'test binary changed between listing and execution')
        execution = SELECTION.reconcile(listing, junit.read_bytes(), required_binaries)
        write_json(evidence / 'selection.json', execution)
        require(execution['executed_required_binaries'], 'required test binary had no executed tests')
        receipts, required = parser_receipts(manifest, provenance, execution)
        write_json(evidence / 'receipts.json', receipts)
        write_json(evidence / 'required.json', required)
        report = COVERAGE.admit(manifest, [COVERAGE.read_json(directory / (binary + '.json'))
                                         for binary in subjects], receipts, provenance, required)
        write_json(evidence / 'coverage.json', report)
        summary = COVERAGE.render_markdown(report)
        passed = report['passed']
        if behavior_paths:
            require(all(sha256_file(path) == behavior_hashes[name]
                        for name, path in behavior_paths.items()), 'behavior executable changed during execution')
            behavior_provenance = dict(provenance, lane='native-cli-fixture', subject_kind='debug-cli-mock-backend',
                                       binaries={name: behavior_hashes[name] for name in ('omg', 'omgd')},
                                       harnesses_sha256={name.removeprefix('harness:'): value
                                                        for name, value in behavior_hashes.items()
                                                        if name.startswith('harness:')})
            behavior_provenance['recipe_sha256'] = hashlib.sha256(json.dumps(
                {'recipe': recipe, 'subjects': behavior_hashes}, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            write_json(behavior_directory / 'provenance.json', behavior_provenance)
            behavior_rows, behavior_required = behavior_receipts(manifest, behavior_provenance, execution)
            write_json(behavior_directory / 'receipts.json', behavior_rows)
            write_json(behavior_directory / 'required.json', behavior_required)
            behavior_report = COVERAGE.admit(manifest, [COVERAGE.read_json(directory / (binary + '.json'))
                                                        for binary in subjects], behavior_rows,
                                             behavior_provenance, behavior_required)
            write_json(behavior_directory / 'coverage.json', behavior_report)
            summary += '\n' + COVERAGE.render_markdown(behavior_report)
            passed = passed and behavior_report['passed']
        service_provenance = daemon_provenance(provenance, recipe, daemon_path, daemon_hash)
        write_json(daemon_directory / 'provenance.json', service_provenance)
        daemon_rows, daemon_required = behavior_receipts(manifest, service_provenance, execution)
        write_json(daemon_directory / 'receipts.json', daemon_rows)
        write_json(daemon_directory / 'required.json', daemon_required)
        daemon_report = COVERAGE.admit(manifest, [COVERAGE.read_json(directory / (binary + '.json'))
                                                for binary in subjects], daemon_rows,
                                     service_provenance, daemon_required)
        write_json(daemon_directory / 'coverage.json', daemon_report)
        summary += '\n' + COVERAGE.render_markdown(daemon_report)
        passed = passed and daemon_report['passed']
        print(summary)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as stream:
                stream.write(summary)
        return 1 if result.returncode or not passed else 0
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        write_json(evidence / 'admission-error.json', {'schema_version': 1, 'error': str(error)})
        print('Native contract admission failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

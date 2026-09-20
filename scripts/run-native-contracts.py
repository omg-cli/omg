#!/usr/bin/env python3
"""Run the existing native tests once, retaining exact parser execution evidence.

The binary subjects are compiled test harnesses, NOT release executables. Only
reviewed parser assertion mappings are accepted by this adapter. These local
receipts are diagnostic evidence from this job, not signed attestations.
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


def parser_receipts(manifest, provenance, report):
    receipts, required = [], []
    for contract in manifest['contracts']:
        if not COVERAGE.applies(contract, provenance):
            continue
        bindings = [binding for binding in contract['tests'] if binding['lane'] == provenance['lane']]
        if not bindings:
            continue
        require(contract['requires'] == ['parser'], 'native parser adapter cannot certify behavioral evidence')
        required.append(contract['id'])
        for binding in bindings:
            require(binding['evidence'] == ['parser'], 'nonparser binding')
            require(binding['id'] in report['tests'], 'missing mapped execution')
            execution = report['tests'][binding['id']]
            for index, attempt in enumerate(execution['attempts'], 1):
                result = attempt['result']
                # A parser fixture has no approved runtime skip path.
                if result == 'SKIPPED' or execution['runtime_skip']:
                    result = 'BLOCKED'
                receipt = {key: provenance[key] for key in COVERAGE.IDENTITY}
                receipt.update(
                    schema_version=1, contract=contract['id'], test_id=binding['id'],
                    binary=contract['binary'], binary_sha256=provenance['binaries'][contract['binary']],
                    attempt=index, attempt_count=len(execution['attempts']), result=result,
                    evidence=['parser'] if result == 'PASS' else [],
                    assertions=binding['assertions'] if result == 'PASS' else [],
                    duration_ms=attempt['duration_ms'], seed=None,
                    cleanup='NOT_STARTED' if result == 'BLOCKED' else 'PASS',
                )
                receipts.append(receipt)
    require(required, 'zero parser contract denominator')
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
    suites = ['cli_surface']
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
        features = args.features.split(',')
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
                    or key.startswith('CARGO_PROFILE_')},
            'files': {name: sha256_file(name) for name in
                      ('Cargo.toml', 'Cargo.lock', '.config/nextest.toml', '.github/workflows/ci.yml')},
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
        junit = Path('target/nextest/ci/junit.xml')
        # Clear only this invocation's outputs so restored/stale artifacts cannot pass.
        for path in (junit, directory / 'omg.json', directory / 'omgd.json'):
            path.unlink(missing_ok=True)
        result = subprocess.run(['cargo', 'nextest', 'run', *cargo_args], check=False)
        require(junit.is_file() and not junit.is_symlink()
                and junit.stat().st_size <= COVERAGE.MAX_BYTES, 'missing or invalid execution report')
        shutil.copyfile(junit, evidence / 'junit.xml')
        for binary, identity in subjects.items():
            require(sha256_file(listing['rust-suites'][identity]['binary-path']) == binaries[binary],
                    'test binary changed between listing and execution')
        execution = SELECTION.reconcile(listing, junit.read_bytes(), required_binaries)
        write_json(evidence / 'selection.json', execution)
        require(execution['executed_required_binaries'], 'required test binary had no executed tests')
        manifest = COVERAGE.read_json('tests/contracts/manifest.json')
        manifest['gaps'] = COVERAGE.read_json('tests/contracts/gaps.json')['gaps']
        receipts, required = parser_receipts(manifest, provenance, execution)
        write_json(evidence / 'receipts.json', receipts)
        write_json(evidence / 'required.json', required)
        report = COVERAGE.admit(manifest, [COVERAGE.read_json(directory / (binary + '.json'))
                                         for binary in subjects], receipts, provenance, required)
        write_json(evidence / 'coverage.json', report)
        summary = COVERAGE.render_markdown(report)
        print(summary)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a', encoding='utf-8') as stream:
                stream.write(summary)
        return 1 if result.returncode or not report['passed'] else 0
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        write_json(evidence / 'admission-error.json', {'schema_version': 1, 'error': str(error)})
        print('Native contract admission failed: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

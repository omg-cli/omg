#!/usr/bin/env python3
"""Reconcile a default (non-partitioned, non-ignored) nextest run exactly.

This accounts for execution, not assertion quality or production coverage.
First failures stay visible even when nextest accepts a retry.
"""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location(
    'contract_coverage', Path(__file__).with_name('check-contract-coverage.py'))
COVERAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COVERAGE)
require = COVERAGE.require


def selected_tests(listing, required_binaries):
    require(isinstance(listing, dict), 'invalid test list')
    required = COVERAGE.strings(required_binaries)
    suites = listing.get('rust-suites')
    require(isinstance(suites, dict) and suites, 'missing test binaries')
    tests, binaries, nonempty = {}, set(), set()
    for key, suite in suites.items():
        require(isinstance(suite, dict) and key == suite.get('binary-id')
                and COVERAGE.text(key) and key not in binaries, 'duplicate or invalid binary')
        binaries.add(key)
        require(suite.get('status') == 'listed', 'binary was not listed')
        cases = suite.get('testcases')
        require(isinstance(cases, dict), 'invalid test cases')
        for name, case in cases.items():
            require(COVERAGE.text(name) and isinstance(case, dict)
                    and type(case.get('ignored')) is bool, 'invalid test case')
            match = case.get('filter-match')
            require(isinstance(match, dict) and match.get('status') in ('matches', 'mismatch'),
                    'invalid filter result')
            identity = key + '::' + name
            require(identity not in tests, 'duplicate test ID')
            state = 'ignored' if case['ignored'] else ('selected' if match['status'] == 'matches' else 'filtered')
            tests[identity] = {'state': state, 'binary_id': key}
            if state == 'selected':
                nonempty.add(key)
    require(type(listing.get('test-count')) is int and listing['test-count'] == len(tests),
            'test count mismatch')
    require(required <= binaries and required <= nonempty, 'required binary missing or selects zero tests')
    require(nonempty, 'zero test denominator')
    return tests


def duration(element):
    try:
        seconds = float(element.attrib['time'])
    except (KeyError, ValueError) as error:
        raise ValueError('missing or invalid test duration') from error
    require(math.isfinite(seconds * 1000) and seconds >= 0, 'invalid test duration')
    return seconds * 1000


def read_junit(data):
    require(isinstance(data, bytes) and len(data) <= COVERAGE.MAX_BYTES, 'oversized or invalid JUnit')
    try:
        document = data.decode('utf-8')
        require('<!DOCTYPE' not in document.upper() and '<!ENTITY' not in document.upper(), 'XML declarations forbidden')
        root = ET.fromstring(document)
    except (UnicodeError, ET.ParseError) as error:
        raise ValueError('invalid JUnit XML') from error
    require(root.tag == 'testsuites', 'invalid JUnit root')
    observed = {}
    for suite in root:
        require(suite.tag == 'testsuite' and COVERAGE.text(suite.get('name')), 'invalid JUnit suite')
        for case in suite:
            if case.tag in ('properties', 'system-out', 'system-err'):
                continue
            require(case.tag == 'testcase' and COVERAGE.text(case.get('name'))
                    and case.get('classname') == suite.get('name'), 'invalid JUnit test identity')
            identity = case.get('classname') + '::' + case.get('name')
            require(identity not in observed, 'duplicate JUnit test')
            groups = {tag: case.findall(tag) for tag in
                      ('skipped', 'failure', 'error', 'flakyFailure', 'flakyError', 'rerunFailure', 'rerunError')}
            require(all(child.tag in {*groups, 'system-out', 'system-err', 'properties'} for child in case),
                    'unknown JUnit verdict')
            failed = groups['failure'] + groups['error']
            flaky = [child for child in case if child.tag in ('flakyFailure', 'flakyError')]
            rerun = [child for child in case if child.tag in ('rerunFailure', 'rerunError')]
            skipped = groups['skipped']
            require(len(failed) <= 1 and len(skipped) <= 1 and not (flaky and (failed or rerun))
                    and not (rerun and not failed) and not (skipped and (failed or flaky or rerun)),
                    'conflicting JUnit verdicts')
            output = '\n'.join(''.join(child.itertext()) for child in case
                               if child.tag in ('system-out', 'system-err'))
            runtime_skip = '[omg-skip]' in output
            attempts = []
            if skipped:
                attempts.append({'result': 'SKIPPED', 'duration_ms': 0.0})
            elif failed:
                attempts.append({'result': 'FAIL', 'duration_ms': duration(case)})
                attempts.extend({'result': 'FAIL', 'duration_ms': duration(child)} for child in rerun)
            else:
                attempts.extend({'result': 'FAIL', 'duration_ms': duration(child)} for child in flaky)
                attempts.append({'result': 'SKIPPED' if runtime_skip else 'PASS', 'duration_ms': duration(case)})
            require(len(attempts) <= 100, 'too many execution attempts')
            observed[identity] = {'attempts': attempts, 'runtime_skip': runtime_skip}
    return observed


def reconcile(listing, xml, required_binaries):
    tests = selected_tests(listing, required_binaries)
    observed = read_junit(xml)
    selected = {identity for identity, case in tests.items() if case['state'] == 'selected'}
    require(set(observed) <= set(tests), 'foreign execution')
    require(selected <= set(observed), 'missing selected execution')
    executed_binaries = set()
    counts = dict(discovered=len(tests), selected=len(selected), executed=0, passed=0,
                  failed=0, skipped=0, filtered=0, retried=0)
    for identity, case in tests.items():
        if case['state'] != 'selected':
            require(identity not in observed or all(attempt['result'] == 'SKIPPED'
                    for attempt in observed[identity]['attempts']), 'unselected test executed')
            counts['skipped' if case['state'] == 'ignored' else 'filtered'] += 1
            continue
        attempts = observed[identity]['attempts']
        counts['retried'] += len(attempts) > 1
        counts['executed'] += any(attempt['result'] != 'SKIPPED' for attempt in attempts)
        if any(attempt['result'] != 'SKIPPED' for attempt in attempts):
            executed_binaries.add(case['binary_id'])
        verdict = ('failed' if any(attempt['result'] == 'FAIL' for attempt in attempts)
                   else 'passed' if attempts[-1]['result'] == 'PASS' else 'skipped')
        counts[verdict] += 1
    return {'schema_version': 1, 'counts': counts, 'tests': observed,
            'executed_required_binaries': set(required_binaries) <= executed_binaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listing', type=Path, required=True)
    parser.add_argument('--junit', type=Path, required=True)
    parser.add_argument('--required-binary', action='append', required=True)
    args = parser.parse_args()
    try:
        require(not args.junit.is_symlink() and args.junit.stat().st_size <= COVERAGE.MAX_BYTES, 'invalid JUnit file')
        report = reconcile(COVERAGE.read_json(args.listing), args.junit.read_bytes(), args.required_binary)
        print(json.dumps(report, indent=2))
        return 1 if report['counts']['failed'] or not report['executed_required_binaries'] else 0
    except (ValueError, OSError) as error:
        print(json.dumps({'schema_version': 1, 'error': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

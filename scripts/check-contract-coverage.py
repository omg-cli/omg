#!/usr/bin/env python3
"""Admit contract receipts for one exact execution owner; gaps are never passes.

The caller supplies independently established provenance and the required set.
Self-reported JSON is not a signature or a substitute for a trusted producer.
Different source revisions/recipes are reported separately, never pooled.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re

MAX_BYTES = 8 * 1024 * 1024
KINDS = frozenset(('parser', 'help', 'refusal', 'success', 'state', 'fault', 'concurrency'))
IDENTITY = ('source_sha', 'run_id', 'run_attempt', 'recipe_sha256',
            'platform', 'os', 'arch', 'features', 'lane')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('nonfinite JSON number: ' + value)


def read_json(path):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), 'invalid evidence file')
    require(path.stat().st_size <= MAX_BYTES, 'oversized evidence file')
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'evidence exceeded limit')
    try:
        return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid JSON encoding or nesting') from error


def text(value):
    return isinstance(value, str) and 0 < len(value) <= 1024 and all(ord(c) >= 32 for c in value)


def strings(value, *, empty=False):
    require(isinstance(value, list) and len(value) <= 20000, 'invalid string list')
    require((empty or bool(value)) and all(text(item) for item in value), 'empty or invalid string list')
    require(len(value) == len(set(value)), 'duplicate list entry')
    return set(value)


def digest(value, length):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def schema(value):
    require(isinstance(value, dict) and type(value.get('schema_version')) is int
            and value['schema_version'] == 1, 'unsupported schema')


def matches_identity(actual, expected, fields):
    require(isinstance(actual, dict), 'missing identity')
    for key in fields:
        if key == 'features':
            require(strings(actual.get(key), empty=True) == strings(expected.get(key), empty=True),
                    'feature identity mismatch')
        else:
            require(type(actual.get(key)) is type(expected.get(key))
                    and actual.get(key) == expected.get(key), 'identity mismatch: ' + key)


def applies(record, provenance):
    platforms = strings(record.get('platforms'))
    required = strings(record.get('features', []), empty=True)
    excluded = strings(record.get('without_features', []), empty=True)
    require(not required & excluded, 'contradictory feature requirement')
    active = set(provenance['features'])
    return provenance['platform'] in platforms and required <= active and not excluded & active


def surface_ids(surfaces, provenance):
    require(isinstance(surfaces, list) and surfaces, 'missing compiled surfaces')
    observed, binaries = set(), set()
    for surface in surfaces:
        schema(surface)
        binary = surface.get('binary')
        require(text(binary) and binary in provenance['binaries'] and binary not in binaries, 'unknown or duplicate binary surface')
        binaries.add(binary)
        require(surface.get('available') is True, 'required binary unavailable')
        matches_identity(surface.get('build'), provenance, ('source_sha', 'platform', 'os', 'arch', 'features'))
        commands = surface.get('commands')
        require(isinstance(commands, list) and commands, 'empty compiled surface')
        for command in commands:
            require(isinstance(command, dict), 'invalid command')
            path = command.get('path')
            require(text(path) and (path == binary or path.startswith(binary + ' ')), 'foreign command')
            require(path not in observed, 'duplicate command surface')
            observed.add(path)
            arguments = command.get('arguments')
            require(isinstance(arguments, list), 'invalid arguments')
            ids = set()
            for arg in arguments:
                require(isinstance(arg, dict) and text(arg.get('id')), 'invalid argument')
                require(arg['id'] not in ids, 'duplicate argument ID')
                ids.add(arg['id'])
                if arg.get('long') is not None:
                    require(text(arg['long']), 'invalid long option')
                    spelling = '--' + arg['long']
                elif arg.get('short') is not None:
                    require(text(arg['short']) and len(arg['short']) == 1, 'invalid short option')
                    spelling = '-' + arg['short']
                else:
                    require(type(arg.get('index')) is int and arg['index'] > 0, 'invalid positional')
                    spelling = '<' + arg['id'] + '>'
                identity = path + ' ' + spelling
                require(identity not in observed, 'duplicate argument surface')
                observed.add(identity)
    require(binaries == set(provenance['binaries']), 'missing binary surface')
    return observed


def check_surface_digests(manifest, surfaces, provenance):
    records = manifest.get('surface_digests')
    require(isinstance(records, list) and records, 'missing surface digest policy')
    selected = {}
    for record in records:
        require(isinstance(record, dict) and text(record.get('binary'))
                and text(record.get('platform')) and digest(record.get('sha256'), 64),
                'invalid surface digest policy')
        features = strings(record.get('features'), empty=True)
        if record['platform'] == provenance['platform'] and features == set(provenance['features']):
            require(record['binary'] not in selected, 'duplicate surface digest policy')
            selected[record['binary']] = record['sha256']
    require(set(selected) == set(provenance['binaries']), 'missing or extra surface digest policy')
    for surface in surfaces:
        payload = {key: value for key, value in surface.items() if key != 'build'}
        actual = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
                                           ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        require(actual == selected[surface['binary']], 'compiled surface digest changed; review inventory')


def admit(manifest, surfaces, receipts, provenance, required_contracts):
    schema(manifest)
    schema(provenance)
    require(digest(provenance.get('source_sha'), 40) and digest(provenance.get('recipe_sha256'), 64),
            'invalid provenance digest')
    require(type(provenance.get('run_attempt')) is int and provenance['run_attempt'] > 0,
            'invalid run attempt')
    for key in ('run_id', 'platform', 'os', 'arch', 'lane'):
        require(text(provenance.get(key)), 'invalid provenance ' + key)
    strings(provenance.get('features'), empty=True)
    binaries = provenance.get('binaries')
    require(isinstance(binaries, dict) and binaries and set(binaries) <= {'omg', 'omgd'}
            and all(digest(value, 64) for value in binaries.values()), 'invalid binary provenance')
    observed = surface_ids(surfaces, provenance)
    required = strings(required_contracts)
    records = manifest.get('contracts')
    require(isinstance(records, list), 'invalid contract manifest')
    contracts, relevant, mapped = {}, {}, set()
    for contract in records:
        require(isinstance(contract, dict) and text(contract.get('id')), 'invalid contract')
        identity = contract['id']
        require(identity not in contracts, 'duplicate contract')
        contracts[identity] = contract
        require(text(contract.get('source')) and text(contract.get('surface')), 'missing contract owner/surface')
        require(type(contract.get('critical')) is bool, 'missing critical policy')
        kinds = strings(contract.get('requires'))
        require(kinds <= KINDS, 'unknown evidence requirement')
        assertions = contract.get('assertions')
        require(isinstance(assertions, dict) and set(assertions) == kinds, 'missing assertion policy')
        for values in assertions.values():
            strings(values)
        if applies(contract, provenance):
            require(text(contract.get('binary')) and contract['binary'] in binaries, 'unknown contract binary')
            require(contract['surface'] == contract['binary']
                    or contract['surface'].startswith(contract['binary'] + ' '), 'foreign contract surface')
            require(contract['surface'] in observed, 'stale contract surface')
            relevant[identity] = contract
            mapped.add(contract['surface'])
    gaps = manifest.get('gaps', [])
    require(isinstance(gaps, list), 'invalid gap inventory')
    current_gaps = []
    gap_keys = set()
    for gap in gaps:
        require(isinstance(gap, dict) and text(gap.get('owner')) and text(gap.get('reason')), 'unowned gap')
        require(strings(gap.get('missing')) <= KINDS, 'invalid missing evidence')
        if applies(gap, provenance):
            surface = gap.get('surface')
            require(text(surface) and surface in observed and surface not in gap_keys, 'stale or duplicate gap')
            gap_keys.add(surface)
            mapped.add(surface)
            current_gaps.append(gap)
    require(observed == mapped, 'unmapped compiled surface')
    check_surface_digests(manifest, surfaces, provenance)
    require(required <= set(relevant), 'unknown or unsupported required contract')
    expected = {}
    for identity in required:
        contract = relevant[identity]
        bindings = contract.get('tests')
        require(isinstance(bindings, list) and bindings, 'empty test selection')
        supplied = set()
        for binding in bindings:
            require(isinstance(binding, dict) and text(binding.get('id')) and text(binding.get('lane')), 'invalid test binding')
            evidence = strings(binding.get('evidence'))
            require(evidence <= set(contract['requires']), 'test substitutes evidence kind')
            assertions = strings(binding.get('assertions'))
            required_assertions = set().union(*(set(contract['assertions'][kind]) for kind in evidence))
            require(required_assertions <= assertions, 'test lacks required assertion')
            if binding['lane'] == provenance['lane']:
                key = (identity, binding['id'])
                require(key not in expected, 'duplicate test binding')
                expected[key] = binding
                supplied.update(evidence)
        require(supplied == set(contract['requires']), 'owner does not cover required evidence kinds')
    require(expected, 'zero test denominator')
    require(isinstance(receipts, list) and receipts, 'missing execution receipts')
    attempts = {}
    for row in receipts:
        schema(row)
        matches_identity(row, provenance, IDENTITY)
        key = (row.get('contract'), row.get('test_id'))
        require(all(text(part) for part in key) and key in expected, 'unknown execution receipt')
        contract, binding = relevant[key[0]], expected[key]
        binary = row.get('binary')
        require(binary == contract['binary'] and row.get('binary_sha256') == binaries[binary], 'binary identity mismatch')
        attempt = row.get('attempt')
        require(type(attempt) is int and 1 <= attempt <= 100, 'invalid execution attempt')
        executions = attempts.setdefault(key, {})
        require(attempt not in executions, 'duplicate execution attempt')
        result = row.get('result')
        require(result in ('PASS', 'FAIL', 'SKIPPED', 'BLOCKED', 'HARNESS_ERROR'), 'invalid verdict')
        duration = row.get('duration_ms')
        require(type(duration) in (int, float) and math.isfinite(duration) and duration >= 0, 'invalid duration')
        require(row.get('seed') is None or text(row['seed']), 'invalid seed')
        require(row.get('cleanup') in ('PASS', 'FAIL', 'NOT_STARTED'), 'missing cleanup outcome')
        evidence = strings(row.get('evidence'), empty=True)
        assertions = strings(row.get('assertions'), empty=True)
        require(evidence <= set(binding['evidence']) and assertions <= set(binding['assertions']), 'unknown assertion/evidence')
        if result == 'SKIPPED':
            reason = contract.get('allowed_skips', {}).get(provenance['platform'])
            require(text(reason) and row.get('reason') == reason and not evidence and not assertions, 'unapproved or ambiguous skip')
        elif result == 'PASS':
            require(evidence == set(binding['evidence']) and assertions == set(binding['assertions']), 'incomplete successful evidence')
        executions[attempt] = row
    require(set(attempts) == set(expected), 'missing expected test execution')
    outcomes = {}
    for key, executions in attempts.items():
        require(set(executions) == set(range(1, len(executions) + 1)), 'missing execution attempt')
        rows = [executions[index] for index in range(1, len(executions) + 1)]
        considered = rows if relevant[key[0]]['critical'] else rows[-1:]
        failed = any(row['result'] in ('FAIL', 'BLOCKED', 'HARNESS_ERROR')
                     or row['cleanup'] == 'FAIL'
                     or (row['result'] == 'PASS' and row['cleanup'] != 'PASS') for row in considered)
        outcomes[key] = 'FAIL' if failed else ('PASS' if rows[-1]['result'] == 'PASS' else 'SKIPPED')
    counts = dict(supported=len(relevant), required=len(required), executed=0,
                  passed=0, failed=0, skipped=0, retried=0, gaps=len(current_gaps))
    evidence_counts = {kind: dict(required=0, executed=0, passed=0, failed=0, skipped=0) for kind in sorted(KINDS)}
    for identity in sorted(required):
        keys = [key for key in expected if key[0] == identity]
        results = [outcomes[key] for key in keys]
        executed = any(row['result'] in ('PASS', 'FAIL') for key in keys for row in attempts[key].values())
        counts['executed'] += executed
        counts['retried'] += any(len(attempts[key]) > 1 for key in keys)
        outcome = 'failed' if 'FAIL' in results else ('passed' if all(result == 'PASS' for result in results) else 'skipped')
        counts[outcome] += 1
        for kind in relevant[identity]['requires']:
            selected = [key for key in keys if kind in expected[key]['evidence']]
            total = evidence_counts[kind]
            total['required'] += 1
            total['executed'] += any(row['result'] in ('PASS', 'FAIL') for key in selected for row in attempts[key].values())
            statuses = [outcomes[key] for key in selected]
            verdict = 'failed' if 'FAIL' in statuses else ('passed' if all(status == 'PASS' for status in statuses) else 'skipped')
            total[verdict] += 1
    history = [
        {'contract': key[0], 'test_id': key[1], 'attempts': [
            {field: row[field] for field in ('attempt', 'result', 'cleanup', 'seed', 'duration_ms')}
            for _, row in sorted(executions.items())]}
        for key, executions in sorted(attempts.items())
    ]
    return {'schema_version': 1, 'platform': provenance['platform'], 'lane': provenance['lane'],
            'source_sha': provenance['source_sha'], 'counts': counts, 'evidence': evidence_counts,
            'gaps': current_gaps, 'attempts': history,
            'passed': counts['passed'] == counts['required']}


def render_markdown(report):
    counts = report['counts']
    rows = [
        'Contract execution for ' + report['platform'].replace('|', '\\|').replace('`', "'") + '.',
        '',
        f"Supported contracts: {counts['supported']}; required: {counts['required']}; "
        f"executed: {counts['executed']}; passed: {counts['passed']}; "
        f"failed: {counts['failed']}; skipped: {counts['skipped']}.",
        f"Explicit gaps: {counts['gaps']}. Gaps and skips are not passing coverage.",
        '',
        '| Evidence | Required | Executed | Passed | Failed | Skipped |',
        '| --- | ---: | ---: | ---: | ---: | ---: |',
    ]
    for kind, values in sorted(report['evidence'].items()):
        rows.append('| ' + kind + ' | ' + ' | '.join(str(values[key]) for key in
                    ('required', 'executed', 'passed', 'failed', 'skipped')) + ' |')
    return '\n'.join(rows) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'receipts', 'provenance', 'required'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--surface', action='append', type=Path, required=True)
    parser.add_argument('--gaps', type=Path)
    parser.add_argument('--summary', type=Path)
    args = parser.parse_args()
    try:
        manifest = read_json(args.manifest)
        if args.gaps:
            manifest['gaps'] = read_json(args.gaps)['gaps']
        report = admit(manifest, [read_json(path) for path in args.surface],
                       read_json(args.receipts), read_json(args.provenance), read_json(args.required))
        print(json.dumps(report, indent=2))
        if args.summary:
            args.summary.write_text(render_markdown(report), encoding='utf-8')
        return 0 if report['passed'] else 1
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({'schema_version': 1, 'passed': False, 'error': str(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Classify CI checks from the complete local Git diff."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


def documentation_only(paths):
    return bool(paths) and all(
        path in ('README.md', 'CHANGELOG.md') or
        (path.startswith('docs/') and path.endswith('.md') and
         '..' not in PurePosixPath(path).parts)
        for path in paths
    )


QEMU_COVERAGE_IRRELEVANT = {
    '.github/workflows/qemu-lane.yml',
    '.github/workflows/qemu-matrix.yml',
    '.github/workflows/qemu-report.yml',
    'scripts/benchmark-qemu.sh',
    'scripts/export-qemu-evidence.py',
    'scripts/qemu-backend-mismatch.py',
    'scripts/check-qemu-runner-isolation.py',
    'scripts/ci-smoke-report.py',
    'scripts/report-qemu-workflow.py',
    'scripts/qemu_inventory_policy.py',
    'scripts/add-qemu-inventory-snapshot.py',
    'scripts/test_ci_smoke_report.py',
    'scripts/test_export_qemu_evidence.py',
    'scripts/test_qemu_runner_isolation.py',
    'tests/qemu-inventory-policy.json',
}


def coverage_irrelevant(paths):
    """QEMU harness changes need QEMU checks, not Rust instrumentation."""
    return bool(paths) and all(
        '..' not in PurePosixPath(path).parts and (
            documentation_only([path])
            or path in QEMU_COVERAGE_IRRELEVANT
            or (path.startswith('tests/qemu-inventory-policy.d/') and path.endswith('.json'))
            or (path.startswith('scripts/qemu-') and path.endswith('.sh'))
            or (path.startswith('scripts/test_qemu_') and path.endswith('.py'))
        )
        for path in paths
    )


def changed_paths(event, cwd=None):
    base = event['pull_request']['base']['sha']
    head = event['pull_request']['head']['sha']
    return git_diff_paths(base, head, '...', cwd)


def git_diff_paths(base, head, separator, cwd):
    if not all(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha)
               for sha in (base, head)):
        raise ValueError('Invalid commit identity')
    # Disable rename folding: moving code into docs must include the deleted
    # source path. NUL separators preserve whitespace and unusual filenames.
    result = subprocess.run(
        ['git', 'diff', '--name-only', '--no-renames', '-z', f'{base}{separator}{head}', '--'],
        cwd=cwd, check=True, capture_output=True, timeout=60,
    )
    return [path for path in result.stdout.decode('utf-8', errors='surrogateescape').split('\0') if path]


def classify_scope(event_name, event, cwd=None):
    # Exact-commit coverage is required for main, merge queues, and manual runs.
    if event_name != 'pull_request':
        return True, True
    paths = changed_paths(event, cwd)
    return not documentation_only(paths), not coverage_irrelevant(paths)


def requires_build(event_name, event, cwd=None):
    return classify_scope(event_name, event, cwd)[0]


def distro_e2e_required(event_name, event, cwd=None):
    if event_name != 'push':
        return True
    try:
        paths = git_diff_paths(event['before'], event['after'], '..', cwd)
    except (KeyError, ValueError, subprocess.SubprocessError):
        # A shallow checkout can be missing the old commit during a batched push.
        return True
    return not paths or not all(
        documentation_only([path]) or (
            path.startswith('services/advisories/') and '..' not in PurePosixPath(path).parts
        )
        for path in paths
    )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distro-e2e', action='store_true')
    args = parser.parse_args()
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    event_name = os.environ['GITHUB_EVENT_NAME']
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        if args.distro_e2e:
            required = distro_e2e_required(event_name, event)
            output.write(f'required={str(required).lower()}\n')
            print(f'Distro E2E required: {required}')
        else:
            required, coverage_required = classify_scope(event_name, event)
            output.write(f'required={str(required).lower()}\n')
            output.write(f'coverage_required={str(coverage_required).lower()}\n')
            print(f'Build required: {required}; instrumented Rust coverage required: {coverage_required}')

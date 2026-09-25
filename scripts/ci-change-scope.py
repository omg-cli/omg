#!/usr/bin/env python3
"""Classify PR checks from the complete local Git diff."""
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
    'scripts/benchmark-qemu.sh',
    'scripts/check-qemu-runner-isolation.py',
    'scripts/test_qemu_runner_isolation.py',
}


def coverage_irrelevant(paths):
    """QEMU harness changes need QEMU checks, not Rust instrumentation."""
    return bool(paths) and all(
        '..' not in PurePosixPath(path).parts and (
            documentation_only([path])
            or path in QEMU_COVERAGE_IRRELEVANT
            or (path.startswith('scripts/qemu-') and path.endswith('.sh'))
            or (path.startswith('scripts/test_qemu_') and path.endswith('.py'))
        )
        for path in paths
    )


def changed_paths(event, cwd=None):
    base = event['pull_request']['base']['sha']
    head = event['pull_request']['head']['sha']
    if not all(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{40}', sha)
               for sha in (base, head)):
        raise ValueError('Invalid PR commit identity')
    # Disable rename folding: moving code into docs must include the deleted
    # source path. NUL separators preserve whitespace and unusual filenames.
    result = subprocess.run(
        ['git', 'diff', '--name-only', '--no-renames', '-z', f'{base}...{head}', '--'],
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


if __name__ == '__main__':
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    required, coverage_required = classify_scope(os.environ['GITHUB_EVENT_NAME'], event)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write(f'required={str(required).lower()}\n')
        output.write(f'coverage_required={str(coverage_required).lower()}\n')
    print(f'Build required: {required}; instrumented Rust coverage required: {coverage_required}')

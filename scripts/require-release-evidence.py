#!/usr/bin/env python3
"""Admit a release only when all required main-push runs on its SHA pass."""

import argparse
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


REQUIRED = {
    'ci.yml': 'CI',
    'benchmark.yml': 'Benchmark',
    'audit.yml': 'Security Audit',
    'secrets.yml': 'Secret Scanning',
    'codeql.yml': 'CodeQL',
    'coverage.yml': 'Coverage',
    'docker-e2e.yml': 'Docker E2E',
}
PENDING = {'queued', 'in_progress', 'requested', 'waiting', 'pending'}
MAX_RUNS = 100
POLL_SECONDS = 15
WAIT_SECONDS = 99 * 60


@dataclass(frozen=True)
class Run:
    id: int
    attempt: int
    created_at: datetime
    status: str
    conclusion: str | None


def latest_required_runs(document, repository, sha):
    rows = document.get('workflow_runs')
    total = document.get('total_count')
    if not isinstance(rows, list) or type(total) is not int or not 0 <= total == len(rows) <= MAX_RUNS:
        raise ValueError('Incomplete GitHub workflow run listing')
    latest = {}
    seen_ids = set()
    for row in rows:
        path, separator, ref = row['path'].partition('@')
        if separator and ref not in ('main', 'refs/heads/main'):
            continue
        file = path.removeprefix('.github/workflows/')
        if file not in REQUIRED or path != f'.github/workflows/{file}':
            continue
        label = REQUIRED[file]
        if (row['head_sha'], row['head_branch'], row['event'], row['repository']['full_name']) != (
            sha, 'main', 'push', repository,
        ):
            raise ValueError(f'Unexpected {label} workflow run identity')
        identifier, attempt = row['id'], row['run_attempt']
        if any(type(value) is not int or value < 1 for value in (identifier, attempt)):
            raise ValueError(f'Invalid {label} workflow run identifier or attempt')
        if identifier in seen_ids:
            raise ValueError(f'Duplicate {label} workflow run {identifier}')
        seen_ids.add(identifier)
        created = datetime.strptime(row['created_at'], '%Y-%m-%dT%H:%M:%SZ')
        run = Run(identifier, attempt, created, row['status'], row.get('conclusion'))
        prior = latest.get(file)
        if prior is None or (run.created_at, run.id) > (prior.created_at, prior.id):
            latest[file] = run

    missing = [label for file, label in REQUIRED.items() if file not in latest]
    if missing:
        raise ValueError(f'No main-push run on {sha} for {", ".join(missing)}')
    return latest


def github_snapshot(repository, sha):
    result = subprocess.run(
        [
            'gh', 'api', '--method', 'GET', f'repos/{repository}/actions/runs',
            '-f', 'event=push', '-f', 'branch=main', '-f', f'head_sha={sha}',
            '-F', f'per_page={MAX_RUNS}',
        ],
        check=True, stdout=subprocess.PIPE, timeout=30,
    )
    return json.loads(result.stdout)


def require_release_evidence(repository, sha, snapshot=github_snapshot):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid GitHub repository name')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Release requires a full commit SHA')

    deadline = time.monotonic() + WAIT_SECONDS
    admitted = None
    last_pending = None
    while True:
        latest = latest_required_runs(snapshot(repository, sha), repository, sha)
        pending = []
        identities = {file: (run.id, run.attempt) for file, run in latest.items()}
        if admitted is not None and identities != admitted:
            changed = [REQUIRED[file] for file in REQUIRED if identities[file] != admitted[file]]
            raise ValueError(f'Latest workflow evidence changed while waiting for {", ".join(changed)}')
        admitted = identities
        for file, label in REQUIRED.items():
            run = latest[file]
            if run.status in PENDING and run.conclusion is None:
                pending.append(label)
            elif run.status != 'completed' or run.conclusion != 'success':
                raise ValueError(f'{label} run {run.id} did not succeed: {run.status}/{run.conclusion}')

        if not pending:
            for file, label in REQUIRED.items():
                run = latest[file]
                print(f'{label} passed for {sha} in run {run.id} attempt {run.attempt}', flush=True)
            return latest['ci.yml']
        if pending != last_pending:
            print(f'Waiting for {", ".join(pending)} on {sha}', flush=True)
            last_pending = pending
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError(f'Timed out waiting for {", ".join(pending)} on {sha}')
        time.sleep(min(POLL_SECONDS, remaining))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('commit')
    parser.add_argument('--stage-linux', type=Path)
    parser.add_argument('--include-macos', action='store_true')
    arguments = parser.parse_args()
    if arguments.include_macos and arguments.stage_linux is None:
        parser.error('--include-macos requires --stage-linux')
    try:
        ci_run = require_release_evidence(os.environ['GITHUB_REPOSITORY'], arguments.commit)
        if arguments.stage_linux is not None:
            command = [
                sys.executable, str(Path(__file__).with_name('native-build-artifact.py')),
                'stage-release', '--destination', str(arguments.stage_linux),
                '--commit', arguments.commit, '--ci-run', str(ci_run.id), '--ci-attempt', str(ci_run.attempt),
            ]
            if arguments.include_macos:
                command.append('--include-macos')
            subprocess.run(command, check=True)
        if output := os.environ.get('GITHUB_OUTPUT'):
            with open(output, 'a', encoding='utf-8') as stream:
                stream.write(f'ci-run={ci_run.id}\nci-attempt={ci_run.attempt}\n')
    except (KeyError, OSError, TypeError, ValueError, AttributeError, subprocess.SubprocessError) as error:
        print(f'::error::Release evidence rejected: {error}', file=sys.stderr)
        sys.exit(1)

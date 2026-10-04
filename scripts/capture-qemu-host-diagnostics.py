#!/usr/bin/env python3
"""Read bounded host/source facts; never configure or admit a crash channel."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PROPERTIES = 'Id,LoadState,ActiveState,SubState,Result,UnitFileState'


def observe(command, timeout=5):
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'exit': None, 'error': type(error).__name__, 'stdout': '', 'truncated': False}
    return {'exit': result.returncode, 'stdout': result.stdout[:4096].decode('utf-8', errors='replace'),
            'truncated': len(result.stdout) > 4096}


def read_fact(path, limit):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(limit + 1)
        return {'value': data[:limit].decode('utf-8', errors='replace').strip(),
                'truncated': len(data) > limit}
    except OSError as error:
        return {'error': type(error).__name__}


def capture():
    source = {key: os.environ.get(env, '') for key, env in (
        ('repository', 'GITHUB_REPOSITORY'), ('event_name', 'GITHUB_EVENT_NAME'),
        ('run_id', 'GITHUB_RUN_ID'), ('run_attempt', 'GITHUB_RUN_ATTEMPT'),
        ('expected_sha', 'GITHUB_SHA'))}
    for key, command in (
            ('observed_sha', ['git', 'rev-parse', 'HEAD']),
            ('observed_tree', ['git', 'rev-parse', 'HEAD^{tree}']),
            ('ordered_parents', ['git', 'show', '-s', '--format=%P', 'HEAD'])):
        source[key] = observe(command)
    pattern = read_fact('/proc/sys/kernel/core_pattern', 256)
    handler = re.match(r'^\|(/[^\s]+)(?:\s|$)', pattern.get('value', ''))
    facts = {'source': source, 'boot_id': read_fact('/proc/sys/kernel/random/boot_id', 64),
             'core_pattern': pattern,
             'handler_executable': os.access(handler[1], os.X_OK) if handler else None}
    for name, unit in (('socket', 'systemd-coredump.socket'),
                       ('processor', 'systemd-coredump@omg-health.service')):
        facts[name] = observe(['systemctl', 'show', '--all', '--property=' + PROPERTIES, unit])
    return facts


def main():
    facts = capture()
    print(json.dumps(facts, sort_keys=True))
    observations = [facts['socket'], facts['processor'], *(
        facts['source'][key] for key in ('observed_sha', 'observed_tree', 'ordered_parents'))]
    failed = any(item['exit'] != 0 or item['truncated'] for item in observations)
    failed = failed or any(item.get('error') or item.get('truncated')
                           for item in (facts['boot_id'], facts['core_pattern']))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())

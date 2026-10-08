#!/usr/bin/env python3
"""Configure an opt-in R2 compiler cache for the trusted portable CI job only."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid


def configuration(env):
    if env.get('OMG_R2_CACHE_ENABLED') != 'true':
        return {}
    if (env.get('GITHUB_REPOSITORY') != 'omg-cli/omg'
            or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch')
            or env.get('GITHUB_JOB') != 'portable'):
        raise ValueError('R2 compiler cache is restricted to the trusted main portable job')
    account = env.get('OMG_R2_CACHE_ACCOUNT_ID', '')
    if not re.fullmatch(r'[a-f0-9]{32}', account):
        raise ValueError('a valid R2 account ID is required')
    for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'):
        if not env.get(name) or any(c in env[name] for c in '\r\n\0'):
            raise ValueError('R2 cache credentials are missing or invalid')
    if env.get('RUSTC_WRAPPER') or env.get('RUSTC_WORKSPACE_WRAPPER'):
        raise ValueError('refusing to replace an existing compiler wrapper')
    return {
        'SCCACHE_BUCKET': 'omg-ci-compiler-cache',
        'SCCACHE_ENDPOINT': f'https://{account}.r2.cloudflarestorage.com',
        'SCCACHE_REGION': 'auto',
        'SCCACHE_S3_USE_SSL': 'true',
        'SCCACHE_S3_KEY_PREFIX': 'portable-v1/',
        'SCCACHE_S3_RW_MODE': 'READ_WRITE',
        'SCCACHE_IDLE_TIMEOUT': '0',
        'SCCACHE_SERVER_UDS': str(Path(tempfile.gettempdir()) / f'omg-r2-{uuid.uuid4().hex}.sock'),
        'RUSTC_WRAPPER': 'sccache',
    }


def cache_counters(env, run):
    result = run(['sccache', '--show-stats', '--stats-format=json'], env=env,
                 check=True, timeout=10, capture_output=True, text=True)
    # sccache v0.18.0 serializes ServerInfo.stats and PerLanguageCount.counts.
    try:
        stats = json.loads(result.stdout)['stats']
        counters = (stats['cache_writes'], stats['cache_misses']['counts'].get('Rust', 0),
                    stats['cache_hits']['counts'].get('Rust', 0), stats['cache_write_errors'])
        if any(type(value) is not int or value < 0 for value in counters):
            raise ValueError('invalid cache counters')
        return counters
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError('invalid sccache statistics') from None


def verify_cache(env, run=subprocess.run):
    before = cache_counters(env, run)
    with tempfile.TemporaryDirectory(prefix='omg-r2-probe-') as directory:
        root = Path(directory)
        name = 'omg_r2_probe_' + uuid.uuid4().hex
        source = root / 'probe.rs'
        source.write_text(f'pub const PROBE: &str = "{name}";\n', encoding='utf-8')
        command = ['sccache', 'rustc', '--crate-name', name, '--crate-type', 'rlib',
                   '--emit=link', '--out-dir', str(root), str(source)]
        run(command, env=env, check=True, timeout=45, capture_output=True, text=True)
        first = cache_counters(env, run)
        if first != (before[0] + 1, before[1] + 1, before[2], before[3]):
            raise ValueError('R2 cache probe did not record a successful Rust cache write')
        artifact = root / f'lib{name}.rlib'
        original = artifact.read_bytes()
        if not original:
            raise ValueError('R2 cache probe produced an empty library')
        artifact.unlink()
        run(command, env=env, check=True, timeout=45, capture_output=True, text=True)
        second = cache_counters(env, run)
        if second != (first[0], first[1], first[2] + 1, first[3]):
            raise ValueError('R2 cache probe did not record a Rust cache hit')
        if artifact.read_bytes() != original:
            raise ValueError('R2 cache probe did not restore the compiled library')


def configure(env, run=subprocess.run):
    config = configuration(env)
    if not config:
        print('R2 compiler cache disabled; existing build path retained')
        return
    server_env = dict(env, **config)
    client_env = {name: value for name, value in server_env.items()
                  if name not in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')}
    try:
        # Startup can silently downgrade to read-only. Prove a write and replay
        # without credentials in the client environment before enabling builds.
        run(['sccache', '--start-server'], env=server_env, check=True, timeout=45,
            capture_output=True, text=True)
        verify_cache(client_env, run)
        with Path(env['GITHUB_ENV']).open('a', encoding='utf-8') as stream:
            for name, value in config.items():
                stream.write(f'{name}={value}\n')
        with Path(env['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
            stream.write('enabled=true\n')
    except Exception:
        # The invocation owns a unique socket, including when startup times out.
        try:
            run(['sccache', '--stop-server'], env=client_env, check=True, timeout=10,
                capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError):
            print('R2 cache cleanup could not stop the probe server')
        raise
    print('R2 compiler cache write and replay verified; native producers unchanged')


if __name__ == '__main__':
    try:
        configure(dict(os.environ))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Never serialize the child environment or credentials in diagnostics.
        raise SystemExit(f'R2 compiler cache setup failed: {type(error).__name__}') from None

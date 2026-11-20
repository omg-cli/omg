#!/usr/bin/env python3
"""Prove trusted-main writes or a seeded, read-only own-PR R2 hit before compiling."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid


# cc-rs only inherits RUSTC_WRAPPER for known executable names such as sccache.
COMPILER_WRAPPER = Path(__file__).resolve().with_name('ci-compiler') / 'sccache'
PROBE_CWD = Path('/tmp/omg-r2-read-probe-v1')
PROBE_SOURCE = b'pub const OMG_R2_READ_PROBE: u64 = 0x525f325f7631;\n'
PROBE_ARGS = ['--crate-name', 'omg_r2_read_probe_v1', '--crate-type', 'rlib', '--edition=2024',
              '--emit=link', '-C', 'opt-level=0', '--out-dir', 'out', 'probe.rs']
AUDIENCE = 'omg-pr-r2-cache-v1'
PR_MINIMUM_LIFETIME = 40 * 60 + 120


def server_configuration(account, prefix, mode):
    if not re.fullmatch(r'[a-f0-9]{32}', account):
        raise ValueError('a valid R2 account ID is required')
    return {
        'SCCACHE_BUCKET': 'omg-ci-compiler-cache',
        'SCCACHE_ENDPOINT': f'https://{account}.r2.cloudflarestorage.com',
        'SCCACHE_REGION': 'auto', 'SCCACHE_S3_USE_SSL': 'true',
        'SCCACHE_S3_KEY_PREFIX': prefix, 'SCCACHE_S3_RW_MODE': mode,
        'SCCACHE_IDLE_TIMEOUT': '0',
        'SCCACHE_SERVER_UDS': str(Path(tempfile.gettempdir()) / f'omg-r2-{uuid.uuid4().hex}.sock'),
        'RUSTC_WRAPPER': str(COMPILER_WRAPPER),
    }


def configuration(env):
    if env.get('OMG_R2_CACHE_ENABLED') != 'true':
        return {}
    if (env.get('GITHUB_REPOSITORY') != 'omg-cli/omg'
            or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch', 'schedule')
            or (env.get('GITHUB_EVENT_NAME') == 'schedule' and env.get('GITHUB_JOB') != 'benchmark')
            or env.get('GITHUB_JOB') not in ('portable', 'portable-release', 'benchmark')):
        raise ValueError('R2 compiler cache is restricted to trusted main build jobs')
    account = env.get('OMG_R2_CACHE_ACCOUNT_ID', '')
    if not re.fullmatch(r'[a-f0-9]{32}', account):
        raise ValueError('a valid R2 account ID is required')
    for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'):
        if not env.get(name) or any(c in env[name] for c in '\r\n\0'):
            raise ValueError('R2 cache credentials are missing or invalid')
    if env.get('RUSTC_WRAPPER') or env.get('RUSTC_WORKSPACE_WRAPPER'):
        raise ValueError('refusing to replace an existing compiler wrapper')
    isolated = env.get('OMG_R2_CACHE_ISOLATED', 'false')
    prefix = 'benchmark-v1/' if env['GITHUB_JOB'] == 'benchmark' else 'portable-v1/'
    if isolated == 'true':
        run_id = env.get('GITHUB_RUN_ID', '')
        if env['GITHUB_EVENT_NAME'] != 'workflow_dispatch' or not re.fullmatch(r'[1-9][0-9]{0,19}', run_id):
            raise ValueError('isolated R2 cache requires a trusted manual run identity')
        prefix = f'portable-diagnostic-v1/{run_id}/'
    elif isolated != 'false':
        raise ValueError('invalid isolated cache selection')
    return server_configuration(account, prefix, 'READ_WRITE')


def cache_counters(env, run):
    counters = read_counters(env, run)
    if any(counters[4:]):
        raise ValueError('R2 cache read error or timeout')
    return counters[:4]


def verify_cache(env, run=subprocess.run):
    before = cache_counters(env, run)
    with tempfile.TemporaryDirectory(prefix='omg-r2-probe-') as directory:
        root = Path(directory)
        name = 'omg_r2_probe_' + uuid.uuid4().hex
        source = root / 'probe.rs'
        source.write_text(f'pub const PROBE: &str = "{name}";\n', encoding='utf-8')
        command = [env['RUSTC_WRAPPER'], 'rustc', '--crate-name', name, '--crate-type', 'rlib',
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


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def probe_environment(env):
    # Rust hashing includes every CARGO_* variable and the literal cwd.
    return {name: value for name, value in env.items() if not name.startswith('CARGO_')
            and name not in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
                             'RUSTFLAGS', 'RUSTC_WORKSPACE_WRAPPER')}


def probe_recipe(env, run=subprocess.run):
    compiler = run(['rustc', '-vV'], env=probe_environment(env), check=True, timeout=10,
                   capture_output=True, text=True).stdout
    if 'host: x86_64-unknown-linux-gnu\n' not in compiler:
        raise ValueError('unsupported probe compiler target')
    recipe = dict(compilerIdentityDigest=hash_bytes(compiler.encode()), target='x86_64-unknown-linux-gnu',
                  cwd=str(PROBE_CWD), sourceDigest=hash_bytes(PROBE_SOURCE), argumentsDigest=hash_bytes(canonical(PROBE_ARGS)))
    return dict(recipe, recipeDigest=hash_bytes(canonical(recipe)))


@contextmanager
def probe_directory():
    PROBE_CWD.mkdir(mode=0o700)
    try:
        (PROBE_CWD / 'probe.rs').write_bytes(PROBE_SOURCE)
        (PROBE_CWD / 'out').mkdir(mode=0o700)
        yield PROBE_CWD
    finally:
        shutil.rmtree(PROBE_CWD)


def read_counters(env, run):
    # sccache 0.18 serializes ServerInfo.stats and PerLanguageCount.counts.
    result = run(['sccache', '--show-stats', '--stats-format=json'], env=env, check=True,
                 timeout=10, capture_output=True, text=True)
    try:
        stats = json.loads(result.stdout)['stats']
        counters = (stats['cache_writes'], stats['cache_misses']['counts'].get('Rust', 0),
                    stats['cache_hits']['counts'].get('Rust', 0), stats['cache_write_errors'],
                    stats['cache_read_errors'], stats['cache_timeouts'])
        if any(type(value) is not int or value < 0 for value in counters):
            raise ValueError('invalid cache counters')
        return counters
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError('invalid sccache statistics') from None


def verify_read_cache(env, root, seed, run=subprocess.run):
    client = probe_environment(env)
    before = read_counters(client, run)
    artifact = root / 'out/libomg_r2_read_probe_v1.rlib'
    artifact.unlink(missing_ok=True)
    run([env['RUSTC_WRAPPER'], 'rustc', *PROBE_ARGS], env=client, cwd=str(root), check=True,
        timeout=45, capture_output=True, text=True)
    after = read_counters(client, run)
    if before != (0, 0, 0, 0, 0, 0) or after != (0, 0, 1, 0, 0, 0):
        raise ValueError('fresh read-only daemon did not record exactly one remote Rust hit')
    if artifact.stat().st_size != seed['outputBytes'] or hash_bytes(artifact.read_bytes()) != seed['outputDigest']:
        raise ValueError('remote seeded output does not match original compiler bytes')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, headers, method='GET'):
    with build_opener(NoRedirect).open(Request(url, headers=headers, method=method), timeout=10) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('oversized broker response')
        return json.loads(raw)


def r2_request(method, account, key, credentials, *, bucket='omg-ci-compiler-cache', query='', data=b'', create=False):
    """Small SigV4 canary transport; endpoints stay fixed to this R2 account."""
    now = datetime.now(timezone.utc)
    day, timestamp = now.strftime('%Y%m%d'), now.strftime('%Y%m%dT%H%M%SZ')
    host = f'{account}.r2.cloudflarestorage.com'
    path = '/' + bucket + '/' + quote(key, safe='/~')
    payload = hash_bytes(data)
    headers = {'host': host, 'x-amz-content-sha256': payload, 'x-amz-date': timestamp}
    if credentials.get('sessionToken'):
        headers['x-amz-security-token'] = credentials['sessionToken']
    if create:
        headers['if-none-match'] = '*'
    signed_headers = ';'.join(sorted(headers))
    canonical_headers = ''.join(f'{name}:{headers[name]}\n' for name in sorted(headers))
    canonical_request = '\n'.join([method, path, query, canonical_headers, signed_headers, payload])
    scope = f'{day}/auto/s3/aws4_request'
    signing = ('AWS4' + credentials['secretAccessKey']).encode()
    for part in (day, 'auto', 's3', 'aws4_request'):
        signing = hmac.digest(signing, part.encode(), 'sha256')
    signature = hmac.new(signing, f'AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{hash_bytes(canonical_request.encode())}'.encode(), 'sha256').hexdigest()
    headers['authorization'] = (f'AWS4-HMAC-SHA256 Credential={credentials["accessKeyId"]}/{scope}, '
                                f'SignedHeaders={signed_headers}, Signature={signature}')
    request = Request(f'https://{host}{path}' + (f'?{query}' if query else ''), method=method,
                      headers=headers, data=data if method in ('PUT', 'POST') else None)
    try:
        with build_opener(NoRedirect).open(request, timeout=10) as response:
            body = response.read(65537)
            if len(body) > 65536:
                raise ValueError('oversized canary response')
            return response.status, body
    except HTTPError as error:
        with error:
            error.read(65537)
        return error.code, b''


def marker_key(seed):
    return f'portable-v1/admission-v1/{seed["recipeDigest"]}/{seed["producerRunId"]}-{seed["producerAttempt"]}.json'


def outside_marker_key(seed):
    return marker_key(seed).replace('portable-v1/', 'benchmark-v1/', 1)


def verify_read_scope(account, value, send=r2_request):
    key = marker_key(value['seed'])
    for method in ('GET', 'HEAD'):
        status, body = send(method, account, key, value)
        if status != 200 or (method == 'GET' and body != canonical(value['seed']) + b'\n'):
            raise ValueError('temporary credential positive read canary failed')
    harmless = 'portable-v1/admission-v1/negative-' + uuid.uuid4().hex
    for method, bucket, path, query, data in (
            ('PUT', 'omg-ci-compiler-cache', harmless, '', b'permission-canary'),
            ('DELETE', 'omg-ci-compiler-cache', harmless, '', b''),
            ('PUT', 'omg-ci-compiler-cache', harmless, 'partNumber=1&uploadId=omg-read-only-canary', b'permission-canary'),
            ('GET', 'omg-ci-compiler-cache', '', 'list-type=2&prefix=portable-v1%2F', b''),
            ('GET', 'omg-ci-compiler-cache', outside_marker_key(value['seed']), '', b''),
            ('GET', 'omg-native-ci', key, '', b'')):
        if send(method, account, path, value, bucket=bucket, query=query, data=data)[0] != 403:
            print(f'R2 authority canary failed for {method} {bucket}/{path}')
            raise ValueError('temporary credential authority exceeded fixed GET/HEAD prefix policy')
    for token in ('', value['sessionToken'][:-4] + 'AAAA'):
        credentials = dict(value, sessionToken=token)
        if send('GET', account, key, credentials)[0] not in (400, 401, 403):
            raise ValueError('invalid session token canary was not denied')


class InsufficientLifetime(ValueError):
    pass


def admitted_response(value, env, recipe, now):
    names = {'schemaVersion', 'accessKeyId', 'secretAccessKey', 'sessionToken', 'endpoint', 'bucket',
             'region', 'prefix', 'mode', 'expiresAt', 'policyVersion', 'admitted', 'seed'}
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError('invalid credential schema')
    if (value['schemaVersion'] != 1 or value['mode'] != 'READ_ONLY' or value['prefix'] != 'portable-v1/'
            or value['bucket'] != 'omg-ci-compiler-cache' or value['region'] != 'auto'
            or value['endpoint'] != f'https://{env["OMG_R2_CACHE_ACCOUNT_ID"]}.r2.cloudflarestorage.com'
            or value['policyVersion'] != 'portable-read-v1' or type(value['expiresAt']) is not int
            or not now + 60 <= value['expiresAt'] <= now + 2700):
        raise ValueError('wrong credential policy')
    if value['expiresAt'] < now + PR_MINIMUM_LIFETIME:
        raise InsufficientLifetime('temporary authority cannot cover the bounded job')
    admitted = dict(repositoryId='1133413326', runId=env['GITHUB_RUN_ID'],
                    runAttempt=int(env['GITHUB_RUN_ATTEMPT']), sourceSha=env['GITHUB_SHA'],
                    pullRequest=int(env['GITHUB_REF'].split('/')[2]))
    if value['admitted'] != admitted:
        raise ValueError('wrong consumer identity')
    seed = value['seed']
    expected = set(recipe) | {'schemaVersion', 'outputDigest', 'outputBytes', 'producerSourceSha',
                              'producerRunId', 'producerAttempt'}
    if (not isinstance(seed, dict) or set(seed) != expected or seed['schemaVersion'] != 1
            or any(seed[name] != expected_value for name, expected_value in recipe.items())
            or not isinstance(seed['outputDigest'], str) or not re.fullmatch(r'[a-f0-9]{64}', seed['outputDigest'])
            or type(seed['outputBytes']) is not int or not 0 < seed['outputBytes'] <= 1024 * 1024
            or not re.fullmatch(r'[a-f0-9]{40}', str(seed['producerSourceSha']))
            or not re.fullmatch(r'[1-9][0-9]{0,19}', str(seed['producerRunId']))
            or type(seed['producerAttempt']) is not int or seed['producerAttempt'] < 1):
        raise ValueError('wrong seeded recipe')
    for name in ('accessKeyId', 'secretAccessKey', 'sessionToken'):
        if not isinstance(value[name], str) or not re.fullmatch(r'[A-Za-z0-9_+/=.-]{1,8192}', value[name]):
            raise ValueError('missing temporary credential')
    return value


def disposition(env, reason):
    with Path(env['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
        stream.write(f'enabled=false\ndisposition={reason}\n')
    print(f'R2 PR cache continued cold: {reason}')


def configure_pr(env, run=None, fetch=None, *, verify_scope=False):
    run = run or subprocess.run
    if env.get('OMG_R2_CACHE_ENABLED') != 'true' or env.get('OMG_R2_PR_CACHE_ENABLED') != 'true':
        disposition(env, 'disabled')
        return
    fetch = fetch or request_json
    client = None
    stage = 'ineligible'
    try:
        if (env.get('GITHUB_REPOSITORY') != 'omg-cli/omg' or env.get('GITHUB_EVENT_NAME') != 'pull_request'
                or env.get('GITHUB_JOB') not in ('portable', 'portable-release')
                or not re.fullmatch(r'refs/pull/[1-9][0-9]{0,9}/merge', env.get('GITHUB_REF', ''))
                or not re.fullmatch(r'[a-f0-9]{40}', env.get('GITHUB_SHA', ''))
                or not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', ''))
                or not re.fullmatch(r'[1-9][0-9]{0,5}', env.get('GITHUB_RUN_ATTEMPT', ''))
                or any(env.get(name) for name in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                    'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN'))
                or any(name.startswith('SCCACHE_') for name in env)):
            raise ValueError('ineligible PR cache setup')
        config = server_configuration(env.get('OMG_R2_CACHE_ACCOUNT_ID', ''), 'portable-v1/', 'READ_ONLY')
        broker = urlsplit(env.get('OMG_R2_CACHE_BROKER_URL', ''))
        if (broker.scheme != 'https' or not broker.hostname or not broker.hostname.endswith('.workers.dev')
                or broker.username or broker.password or broker.port or broker.query or broker.fragment
                or broker.path not in ('', '/')):
            raise ValueError('invalid broker endpoint')
        stage = 'oidc-unavailable'
        oidc = urlsplit(env.get('ACTIONS_ID_TOKEN_REQUEST_URL', ''))
        if (oidc.scheme != 'https' or not oidc.hostname or not oidc.hostname.endswith('.actions.githubusercontent.com')
                or oidc.username or oidc.password or oidc.port or oidc.fragment):
            raise ValueError('invalid OIDC endpoint')
        query = parse_qsl(oidc.query, keep_blank_values=True)
        if any(key == 'audience' for key, _ in query):
            raise ValueError('unexpected OIDC audience')
        if not env.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN'):
            raise ValueError('missing OIDC request capability')
        oidc_url = urlunsplit(oidc._replace(query=urlencode([*query, ('audience', AUDIENCE)])))
        token = fetch(oidc_url, {'Authorization': f'Bearer {env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]}'})
        if not isinstance(token, dict) or not isinstance(token.get('value'), str) or not 1 <= len(token['value']) <= 16377:
            raise ValueError('missing OIDC token')
        github_token = env.get('GITHUB_TOKEN', '')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,4096}', github_token):
            raise ValueError('missing job metadata token')
        stage = 'broker-unavailable'
        value = fetch(f'https://{broker.hostname}/v1/compiler-cache/credentials',
                      {'Authorization': f'Bearer {token["value"]}', 'X-GitHub-Token': github_token}, 'POST')
        stage = 'invalid-response'
        recipe = probe_recipe(env, run)
        value = admitted_response(value, env, recipe, int(time.time()))
        for name in ('accessKeyId', 'secretAccessKey', 'sessionToken'):
            print(f'::add-mask::{value[name]}')
        server = dict(env, **config, AWS_ACCESS_KEY_ID=value['accessKeyId'],
                      AWS_SECRET_ACCESS_KEY=value['secretAccessKey'], AWS_SESSION_TOKEN=value['sessionToken'])
        client = {name: item for name, item in server.items()
                  if name not in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')}
        stage = 'seed-proof-failed'
        run(['sccache', '--start-server'], env=server, check=True, timeout=45, capture_output=True, text=True)
        with probe_directory() as root:
            verify_read_cache(client, root, value['seed'], run)
        if verify_scope:
            stage = 'scope-proof-failed'
            verify_read_scope(env['OMG_R2_CACHE_ACCOUNT_ID'], value)
        config.update(OMG_R2_CACHE_MODE='READ_ONLY', OMG_R2_CACHE_SEED_RECIPE=recipe['recipeDigest'],
                      OMG_R2_CACHE_POLICY=value['policyVersion'], OMG_R2_CACHE_EXPIRES_AT=str(value['expiresAt']))
        stage = 'activation-failed'
        with Path(env['GITHUB_ENV']).open('a', encoding='utf-8') as stream:
            for name, item in config.items():
                stream.write(f'{name}={item}\n')
        with Path(env['GITHUB_OUTPUT']).open('a', encoding='utf-8') as stream:
            stream.write('enabled=true\ndisposition=verified-read\n')
        print('R2 PR read-only seeded Rust hit verified')
    except (ValueError, OSError, subprocess.SubprocessError, URLError) as error:
        if isinstance(error, InsufficientLifetime):
            stage = 'insufficient-lifetime'
        if client is not None:
            try:
                run(['sccache', '--stop-server'], env=client, check=True, timeout=10, capture_output=True, text=True)
            except (OSError, subprocess.SubprocessError):
                raise ValueError('owned cache daemon cleanup failed') from None
        if stage == 'activation-failed':
            raise ValueError('cache activation failed') from None
        disposition(env, stage)


def seed_cache(env, receipt, run=subprocess.run, send=r2_request):
    if (env.get('GITHUB_ACTIONS') != 'true' or env.get('GITHUB_REPOSITORY') != 'omg-cli/omg' or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch')
            or env.get('GITHUB_JOB') != 'deploy' or env.get('GITHUB_WORKFLOW_REF') !=
            'omg-cli/omg/.github/workflows/cloudflare-artifacts.yml@refs/heads/main'
            or not re.fullmatch(r'[a-f0-9]{40}', env.get('GITHUB_SHA', ''))
            or not re.fullmatch(r'[1-9][0-9]{0,19}', env.get('GITHUB_RUN_ID', ''))
            or not re.fullmatch(r'[1-9][0-9]{0,5}', env.get('GITHUB_RUN_ATTEMPT', ''))
            or any(env.get(name) for name in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'AWS_SESSION_TOKEN'))
            or any(name.startswith('SCCACHE_') for name in env)):
        raise ValueError('seed requires the trusted-main artifact deployment role')
    for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'):
        if not env.get(name) or any(char in env[name] for char in '\r\n\0'):
            raise ValueError('seed credentials missing')
    config = server_configuration(env.get('OMG_R2_CACHE_ACCOUNT_ID', ''), 'portable-v1/', 'READ_WRITE')
    server = dict(env, **config)
    client = probe_environment(server)
    recipe = probe_recipe(client, run)
    started = False
    try:
        with probe_directory() as root:
            artifact = root / 'out/libomg_r2_read_probe_v1.rlib'
            run(['rustc', *PROBE_ARGS], env=client, cwd=str(root), check=True, timeout=45, capture_output=True, text=True)
            output = artifact.read_bytes()
            if not 0 < len(output) <= 1024 * 1024:
                raise ValueError('invalid direct seed output')
            seed = dict(recipe, schemaVersion=1, outputDigest=hash_bytes(output), outputBytes=len(output),
                        producerSourceSha=env['GITHUB_SHA'], producerRunId=env['GITHUB_RUN_ID'],
                        producerAttempt=int(env['GITHUB_RUN_ATTEMPT']))
            artifact.unlink()
            started = True
            run(['sccache', '--start-server'], env=server, check=True, timeout=45, capture_output=True, text=True)
            before = read_counters(client, run)
            run([config['RUSTC_WRAPPER'], 'rustc', *PROBE_ARGS], env=client, cwd=str(root), check=True,
                timeout=45, capture_output=True, text=True)
            after = read_counters(client, run)
            if before != (0, 0, 0, 0, 0, 0) or after not in ((1, 1, 0, 0, 0, 0), (0, 0, 1, 0, 0, 0)):
                raise ValueError('seed did not prove remote hit or successful write')
            if artifact.read_bytes() != output:
                raise ValueError('seed cache changed direct compiler bytes')
    finally:
        if started:
            first_error = os.sys.exception()
            try:
                run(['sccache', '--stop-server'], env=client, check=True, timeout=10, capture_output=True, text=True)
            except (OSError, subprocess.SubprocessError):
                if first_error is None:
                    raise
                print('R2 seed daemon cleanup failed; original failure retained')
    marker = canonical(seed) + b'\n'
    credentials = dict(accessKeyId=env['AWS_ACCESS_KEY_ID'], secretAccessKey=env['AWS_SECRET_ACCESS_KEY'])
    for key in (marker_key(seed), outside_marker_key(seed)):
        status, _ = send('PUT', env['OMG_R2_CACHE_ACCOUNT_ID'], key, credentials, data=marker, create=True)
        if status not in (200, 412):
            raise ValueError('seed admission marker publication failed')
        if send('GET', env['OMG_R2_CACHE_ACCOUNT_ID'], key, credentials) != (200, marker):
            raise ValueError('seed admission marker bytes differ')
    # Independent official-format vector proves actual R2 expiry without a 45-minute sleep.
    now = int(time.time())
    encode = lambda value: base64.urlsafe_b64encode(canonical(value)).decode().rstrip('=')
    unsigned = encode(dict(alg='HS256', typ='JWT')) + '.' + encode(dict(
        sub=env['OMG_R2_CACHE_ACCOUNT_ID'], iss=credentials['accessKeyId'],
        aud=f'{env["OMG_R2_CACHE_ACCOUNT_ID"]}.r2.cloudflarestorage.com', iat=now - 120, exp=now - 60,
        bucket='omg-ci-compiler-cache', actions=['GetObject', 'HeadObject'], paths=dict(prefixPaths=['portable-v1/'])))
    signature = base64.urlsafe_b64encode(hmac.digest(credentials['secretAccessKey'].encode(), unsigned.encode(), 'sha256')).decode().rstrip('=')
    token = unsigned + '.' + signature
    expired = dict(accessKeyId=credentials['accessKeyId'], secretAccessKey=hash_bytes(token.encode()),
                   sessionToken=base64.b64encode(('jwt/' + token).encode()).decode())
    if send('GET', env['OMG_R2_CACHE_ACCOUNT_ID'], marker_key(seed), expired)[0] != 403:
        raise ValueError('expired temporary credential was not denied by R2')
    Path(receipt).write_bytes(marker)
    print('R2 seed original compiler bytes and remote storage verified')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('main', 'pr-read', 'seed'), default='main')
    parser.add_argument('--receipt')
    parser.add_argument('--verify-scope', action='store_true', help='also prove positive reads and denied R2 operations on an own-PR canary')
    args = parser.parse_args(argv)
    if args.mode == 'seed' and not args.receipt:
        parser.error('--receipt is required for seed')
    if args.verify_scope and args.mode != 'pr-read':
        parser.error('--verify-scope requires pr-read mode')
    if args.receipt and args.mode != 'seed':
        parser.error('--receipt requires seed mode')
    env = dict(os.environ)
    if args.mode == 'pr-read':
        configure_pr(env, verify_scope=args.verify_scope)
    elif args.mode == 'seed':
        seed_cache(env, args.receipt)
    else:
        configure(env)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f'R2 compiler cache setup failed: {type(error).__name__}') from None

"""Exercise cache trust boundaries and setup failure without cloud credentials."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from test_ci_gates import CI_YML, job_block

SPEC = importlib.util.spec_from_file_location('r2_cache', Path(__file__).with_name('ci-r2-cache.py'))
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)


def trusted():
    return dict(OMG_R2_CACHE_ENABLED='true', GITHUB_REPOSITORY='omg-cli/omg',
                GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='push', GITHUB_JOB='portable',
                OMG_R2_CACHE_ACCOUNT_ID='a' * 32, AWS_ACCESS_KEY_ID='test-access',
                AWS_SECRET_ACCESS_KEY='test-secret')


def statistics(writes=0, misses=0, hits=0, errors=0, language='Rust'):
    return json.dumps({'stats': {'cache_writes': writes, 'cache_write_errors': errors,
                                'cache_read_errors': 0, 'cache_timeouts': 0,
                                'cache_misses': {'counts': {language: misses}},
                                'cache_hits': {'counts': {language: hits}}}})


class R2CacheTests(unittest.TestCase):
    def pr_fixture(self, root, *, fail=None, counts=None, corrupt=False, change=None):
        env = dict(OMG_R2_CACHE_ENABLED='true', OMG_R2_PR_CACHE_ENABLED='true',
                   GITHUB_REPOSITORY='omg-cli/omg', GITHUB_EVENT_NAME='pull_request',
                   GITHUB_JOB='portable', GITHUB_REF='refs/pull/12/merge', GITHUB_SHA='b' * 40,
                   GITHUB_RUN_ID='456', GITHUB_RUN_ATTEMPT='1', GITHUB_TOKEN='ghs_ephemeral',
                   OMG_R2_CACHE_ACCOUNT_ID='a' * 32, OMG_R2_CACHE_BROKER_URL='https://omg-ci-artifacts.example.workers.dev',
                   ACTIONS_ID_TOKEN_REQUEST_URL='https://run.actions.githubusercontent.com/token?api-version=2.0',
                   ACTIONS_ID_TOKEN_REQUEST_TOKEN='request-capability', GITHUB_ENV=str(root / 'env'),
                   GITHUB_OUTPUT=str(root / 'output'), CARGO_INCREMENTAL='0')
        compiler = 'rustc 1.95.0\nhost: x86_64-unknown-linux-gnu\n'
        recipe = CACHE.probe_recipe(env, Mock(return_value=subprocess.CompletedProcess([], 0, stdout=compiler)))
        seed = dict(recipe, schemaVersion=1, outputDigest=CACHE.hash_bytes(b'rlib'), outputBytes=4,
                    producerSourceSha='d' * 40, producerRunId='123', producerAttempt=1)
        value = dict(schemaVersion=1, accessKeyId='temporary-access', secretAccessKey='temporary-secret',
                     sessionToken='temporary-session', endpoint=f'https://{"a" * 32}.r2.cloudflarestorage.com',
                     bucket='omg-ci-compiler-cache', region='auto', prefix='portable-v1/', mode='READ_ONLY',
                     expiresAt=int(CACHE.time.time()) + 2600, policyVersion='portable-read-v1', seed=seed,
                     admitted=dict(repositoryId='1133413326', runId='456', runAttempt=1,
                                   sourceSha='b' * 40, pullRequest=12))
        if change:
            value.update(change)
        snapshots = iter(counts or [statistics(), statistics(hits=1)])
        calls = []
        probe = root / 'owned-probe'
        @contextlib.contextmanager
        def directory():
            probe.mkdir(); (probe / 'probe.rs').write_bytes(CACHE.PROBE_SOURCE); (probe / 'out').mkdir()
            try:
                yield probe
            finally:
                CACHE.shutil.rmtree(probe)
        def run(command, **kwargs):
            calls.append(command)
            if command == ['rustc', '-vV']:
                self.assertNotIn('CARGO_INCREMENTAL', kwargs['env'])
                return subprocess.CompletedProcess(command, 0, stdout=compiler)
            if command[1] == '--start-server':
                self.assertEqual(kwargs['env']['AWS_SESSION_TOKEN'], 'temporary-session')
                self.assertEqual(kwargs['env']['SCCACHE_S3_RW_MODE'], 'READ_ONLY')
            else:
                self.assertFalse(any(name.startswith('AWS_') for name in kwargs['env']))
            if command[1] == fail:
                raise subprocess.CalledProcessError(1, command, stderr='temporary-secret')
            if command[1] == '--show-stats':
                return subprocess.CompletedProcess(command, 0, stdout=next(snapshots))
            if command[1] == 'rustc':
                self.assertEqual(kwargs['cwd'], str(probe))
                self.assertNotIn('CARGO_INCREMENTAL', kwargs['env'])
                (probe / 'out/libomg_r2_read_probe_v1.rlib').write_bytes(b'wrong' if corrupt else b'rlib')
            return subprocess.CompletedProcess(command, 0, stdout='')
        def fetch(url, headers, method='GET'):
            if method == 'GET':
                self.assertIn('audience=omg-pr-r2-cache-v1', url)
                self.assertEqual(headers, {'Authorization': 'Bearer request-capability'})
                return {'value': 'oidc-token'}
            self.assertEqual(url, 'https://omg-ci-artifacts.example.workers.dev/v1/compiler-cache/credentials')
            self.assertEqual(headers, {'Authorization': 'Bearer oidc-token', 'X-GitHub-Token': 'ghs_ephemeral'})
            return value
        return env, run, fetch, directory, calls

    def test_pr_setup_publishes_only_nonsecret_config_after_actual_seeded_hit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, run, fetch, probe, calls = self.pr_fixture(root)
            with patch.object(CACHE, 'probe_directory', probe), patch.object(CACHE, 'request_json', fetch), \
                    patch.object(CACHE.subprocess, 'run', run), patch.dict(os.environ, env, clear=True), \
                    contextlib.redirect_stdout(io.StringIO()):
                CACHE.main(['--mode', 'pr-read'])
            exported = (root / 'env').read_text()
            self.assertIn('SCCACHE_S3_RW_MODE=READ_ONLY\n', exported)
            self.assertIn('OMG_R2_CACHE_SEED_RECIPE=', exported)
            self.assertNotIn('temporary-', exported)
            self.assertNotIn('TOKEN', exported)
            self.assertEqual((root / 'output').read_text(), 'enabled=true\ndisposition=verified-read\n')
            self.assertNotIn(['sccache', '--stop-server'], calls)
            self.assertFalse((root / 'owned-probe').exists())

    def test_pr_bad_response_continues_cold_without_daemon_or_exports(self):
        for change in ({'bucket': 'other'}, {'endpoint': 'https://evil'}, {'mode': 'READ_WRITE'},
                       {'prefix': 'benchmark-v1/'}, {'sessionToken': ''}, {'extra': 'value'},
                       {'expiresAt': 1}, {'admitted': {}}, {'seed': {}}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env, run, fetch, probe, calls = self.pr_fixture(root, change=change)
                with contextlib.redirect_stdout(io.StringIO()):
                    CACHE.configure_pr(env, run, fetch)
                self.assertFalse((root / 'env').exists())
                self.assertEqual((root / 'output').read_text(), 'enabled=false\ndisposition=invalid-response\n')
                self.assertNotIn(['sccache', '--start-server'], calls)

    def test_short_remaining_first_mint_lifetime_cannot_activate_a_forty_minute_job(self):
        for remaining in (120, 2519):
            with self.subTest(remaining=remaining), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                now = int(CACHE.time.time())
                env, run, fetch, probe, calls = self.pr_fixture(root, change={'expiresAt': now + remaining})
                with patch.object(CACHE.time, 'time', return_value=now), patch.object(CACHE, 'probe_directory', probe), \
                        contextlib.redirect_stdout(io.StringIO()):
                    CACHE.configure_pr(env, run, fetch)
                self.assertFalse((root / 'env').exists())
                self.assertNotIn(['sccache', '--start-server'], calls)
                self.assertEqual((root / 'output').read_text(), 'enabled=false\ndisposition=insufficient-lifetime\n')

    def test_pr_startup_probe_and_read_error_failures_stop_only_owned_daemon_then_continue_cold(self):
        error_stats = json.loads(statistics(hits=1)); error_stats['stats']['cache_read_errors'] = 1
        for kwargs in ({'fail': '--start-server'}, {'fail': 'rustc'}, {'corrupt': True},
                       {'counts': [statistics(), statistics(misses=1)]},
                       {'counts': [statistics(), json.dumps(error_stats)]}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env, run, fetch, probe, calls = self.pr_fixture(root, **kwargs)
                with patch.object(CACHE, 'probe_directory', probe), contextlib.redirect_stdout(io.StringIO()):
                    CACHE.configure_pr(env, run, fetch)
                self.assertEqual(calls[-1], ['sccache', '--stop-server'])
                self.assertFalse((root / 'env').exists())
                self.assertEqual((root / 'output').read_text(), 'enabled=false\ndisposition=seed-proof-failed\n')

    def test_pr_foreign_cache_mixed_secrets_and_missing_oidc_are_cold_before_network(self):
        for change in ({'GITHUB_EVENT_NAME': 'pull_request_target'}, {'GITHUB_REPOSITORY': 'fork/omg'},
                       {'AWS_SECRET_ACCESS_KEY': 'parent-secret'}, {'SCCACHE_DIR': 'foreign'},
                       {'RUSTC_WRAPPER': 'foreign'}, {'ACTIONS_ID_TOKEN_REQUEST_TOKEN': ''}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env, run, fetch, probe, calls = self.pr_fixture(root)
                env.update(change)
                network = Mock(side_effect=AssertionError('must not fetch'))
                with contextlib.redirect_stdout(io.StringIO()):
                    CACHE.configure_pr(env, run, network)
                self.assertFalse(network.called)
                self.assertFalse((root / 'env').exists())

    def test_pr_cleanup_failure_is_fatal_and_never_claims_cold_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env, run, fetch, probe, calls = self.pr_fixture(root, fail='--stop-server', corrupt=True)
            with patch.object(CACHE, 'probe_directory', probe), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                CACHE.configure_pr(env, run, fetch)
            self.assertFalse((root / 'output').exists())
            self.assertFalse((root / 'env').exists())

    def test_seed_trusted_producer_direct_bytes_then_remote_hit_or_write(self):
        for result in ('write', 'hit', 'corrupt', 'error', 'outside-missing'):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(trusted(), GITHUB_ACTIONS='true', GITHUB_JOB='deploy', GITHUB_SHA='d' * 40,
                           GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                           GITHUB_WORKFLOW_REF='omg-cli/omg/.github/workflows/cloudflare-artifacts.yml@refs/heads/main')
                @contextlib.contextmanager
                def probe():
                    (root / 'out').mkdir(); (root / 'probe.rs').write_bytes(CACHE.PROBE_SOURCE)
                    yield root
                calls = []
                snapshots = iter([statistics(), statistics(hits=1) if result == 'hit' else statistics(1, 1)])
                def run(command, **kwargs):
                    calls.append(command)
                    if command == ['rustc', '-vV']:
                        return subprocess.CompletedProcess(command, 0, stdout='rustc 1.95.0\nhost: x86_64-unknown-linux-gnu\n')
                    if command[1] == '--start-server':
                        self.assertEqual(kwargs['env']['AWS_SECRET_ACCESS_KEY'], 'test-secret')
                    else:
                        self.assertFalse(any(name.startswith('AWS_') for name in kwargs['env']))
                    if command[1] == '--show-stats':
                        return subprocess.CompletedProcess(command, 0, stdout=next(snapshots))
                    if command[0] == 'rustc' or command[1] == 'rustc':
                        cached = command[0] != 'rustc'
                        if cached and result == 'error':
                            raise subprocess.CalledProcessError(1, command, stderr='test-secret')
                        (root / 'out/libomg_r2_read_probe_v1.rlib').write_bytes(b'wrong' if cached and result == 'corrupt' else b'rlib')
                    return subprocess.CompletedProcess(command, 0, stdout='')
                receipt = root / 'receipt.json'
                marker = []
                published_keys = []
                def send(method, account, key, credentials, **kwargs):
                    if credentials.get('sessionToken'):
                        raw = CACHE.base64.b64decode(credentials['sessionToken']).decode()
                        self.assertTrue(raw.startswith('jwt/'))
                        token = raw[4:]
                        header, claims, signature = token.split('.')
                        expected = CACHE.hmac.digest(b'test-secret', f'{header}.{claims}'.encode(), 'sha256')
                        self.assertEqual(CACHE.base64.urlsafe_b64decode(signature + '=' * (-len(signature) % 4)), expected)
                        self.assertEqual(credentials['secretAccessKey'], CACHE.hash_bytes(token.encode()))
                        payload = json.loads(CACHE.base64.urlsafe_b64decode(claims + '=' * (-len(claims) % 4)))
                        self.assertLess(payload['exp'], CACHE.time.time())
                        self.assertEqual(payload['actions'], ['GetObject', 'HeadObject'])
                        return 403, b''
                    self.assertEqual(credentials['secretAccessKey'], 'test-secret')
                    if method == 'PUT':
                        published_keys.append(key)
                        self.assertTrue(kwargs['create']); marker.append(kwargs['data']); return 200, b''
                    if result == 'outside-missing' and key.startswith('benchmark-v1/'):
                        return 403, b''
                    return 200, marker[0]
                with patch.object(CACHE, 'probe_directory', probe):
                    if result in ('corrupt', 'error', 'outside-missing'):
                        with self.assertRaises((ValueError, subprocess.SubprocessError)):
                            CACHE.seed_cache(env, receipt, run, send)
                        self.assertFalse(receipt.exists())
                    else:
                        CACHE.seed_cache(env, receipt, run, send)
                        value = json.loads(receipt.read_text())
                        self.assertEqual(value['outputDigest'], CACHE.hash_bytes(b'rlib'))
                        self.assertEqual(value['producerSourceSha'], 'd' * 40)
                        self.assertNotIn('test-secret', receipt.read_text())
                        self.assertEqual(set(published_keys), {
                            f'portable-v1/admission-v1/{value["recipeDigest"]}/123-1.json',
                            f'benchmark-v1/admission-v1/{value["recipeDigest"]}/123-1.json'})
                self.assertEqual(calls[-1], ['sccache', '--stop-server'])

    def test_seed_refuses_non_main_or_non_deploy_role_before_compiler(self):
        runner = Mock(side_effect=AssertionError('must not compile'))
        with self.assertRaises(ValueError):
            CACHE.seed_cache(trusted(), 'unused.json', runner)
        self.assertFalse(runner.called)

    def test_probe_directory_refuses_foreign_existing_path_without_removing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'probe'
            path.mkdir(); marker = path / 'owner-data'; marker.write_text('retain')
            with patch.object(CACHE, 'PROBE_CWD', path), self.assertRaises(FileExistsError):
                with CACHE.probe_directory():
                    self.fail('foreign path admitted')
            self.assertEqual(marker.read_text(), 'retain')
            marker.unlink(); path.rmdir()
            with patch.object(CACHE, 'PROBE_CWD', path):
                with CACHE.probe_directory() as owned:
                    self.assertEqual((owned / 'probe.rs').read_bytes(), CACHE.PROBE_SOURCE)
            self.assertFalse(path.exists())

    def test_scope_canary_requires_real_positive_bytes_and_denied_operations(self):
        seed = dict(recipeDigest='c' * 64, producerRunId='123', producerAttempt=1)
        value = dict(seed=seed, accessKeyId='temporary-access', secretAccessKey='temporary-secret', sessionToken='temporary-session')
        for failure in ('none', 'wrong-bytes', 'write-allowed', 'listing-not-found', 'token-allowed'):
            with self.subTest(failure=failure):
                calls = []
                def send(method, account, key, credentials, **kwargs):
                    calls.append((method, key, kwargs))
                    if credentials['sessionToken'] != value['sessionToken']:
                        return (200 if failure == 'token-allowed' else 403), b''
                    if key == CACHE.marker_key(seed) and kwargs.get('bucket', 'omg-ci-compiler-cache') == 'omg-ci-compiler-cache':
                        return 200, b'wrong' if failure == 'wrong-bytes' else CACHE.canonical(seed) + b'\n'
                    if method == 'PUT' and failure == 'write-allowed':
                        return 200, b''
                    if kwargs.get('query', '').startswith('list-type') and failure == 'listing-not-found':
                        return 404, b''
                    return 403, b''
                if failure == 'none':
                    CACHE.verify_read_scope('a' * 32, value, send)
                    self.assertTrue(any(row[1] == f'benchmark-v1/admission-v1/{"c" * 64}/123-1.json' for row in calls))
                    self.assertTrue(any('uploadId=' in row[2].get('query', '') for row in calls))
                    self.assertTrue(any(row[2].get('bucket') == 'omg-native-ci' for row in calls))
                else:
                    with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                        CACHE.verify_read_scope('a' * 32, value, send)

    def test_sigv4_transport_keeps_session_in_headers_and_refuses_redirects(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 403
        response.read.return_value = b''
        opener = Mock(); opener.open.return_value = response
        with patch.object(CACHE, 'build_opener', return_value=opener) as builder:
            CACHE.r2_request('PUT', 'a' * 32, 'portable-v1/admission-v1/space name',
                             dict(accessKeyId='id', secretAccessKey='secret', sessionToken='session'),
                             data=b'canary', create=True)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, f'https://{"a" * 32}.r2.cloudflarestorage.com/omg-ci-compiler-cache/portable-v1/admission-v1/space%20name')
        self.assertEqual(request.get_header('X-amz-security-token'), 'session')
        self.assertEqual(request.get_header('If-none-match'), '*')
        self.assertIn('SignedHeaders=host;if-none-match;x-amz-content-sha256;x-amz-date;x-amz-security-token',
                      request.get_header('Authorization'))
        self.assertNotIn('secret', request.full_url)
        self.assertIs(builder.call_args.args[0], CACHE.NoRedirect)
        self.assertIsNone(CACHE.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil'))

    def test_normal_pr_cli_disabled_emits_cold_disposition_without_secret_or_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            env = dict(os.environ, GITHUB_OUTPUT=str(output), OMG_R2_CACHE_ENABLED='false')
            result = subprocess.run([os.sys.executable, str(CACHE.__file__), '--mode', 'pr-read'],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text(), 'enabled=false\ndisposition=disabled\n')

    def test_pr_seeded_hit_requires_exact_bytes_and_no_write_or_miss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = CACHE.configuration(trusted())
            env = dict(config, SCCACHE_S3_RW_MODE='READ_ONLY')
            recipe = CACHE.probe_recipe(env, Mock(return_value=subprocess.CompletedProcess([], 0,
                                      stdout='rustc 1.95.0\nhost: x86_64-unknown-linux-gnu\n')))
            seed = dict(recipe, schemaVersion=1, outputDigest=CACHE.hash_bytes(b'rlib'), outputBytes=4,
                        producerSourceSha='b' * 40, producerRunId='123', producerAttempt=1)
            for bad in ('none', 'miss', 'write', 'wrong-bytes'):
                with self.subTest(bad=bad):
                    counts = iter([statistics(), statistics(hits=1) if bad in ('none', 'wrong-bytes')
                                   else statistics(misses=1) if bad == 'miss' else statistics(writes=1, hits=1)])
                    def execute(command, **kwargs):
                        self.assertNotIn('AWS_SESSION_TOKEN', kwargs['env'])
                        if command[1] == '--show-stats':
                            return subprocess.CompletedProcess(command, 0, stdout=next(counts))
                        self.assertEqual(kwargs['cwd'], str(root))
                        (root / 'out').mkdir(exist_ok=True)
                        (root / 'out/libomg_r2_read_probe_v1.rlib').write_bytes(b'bad' if bad == 'wrong-bytes' else b'rlib')
                        return subprocess.CompletedProcess(command, 0, stdout='')
                    if bad == 'none':
                        CACHE.verify_read_cache(env, root, seed, execute)
                    else:
                        with self.assertRaises(ValueError):
                            CACHE.verify_read_cache(env, root, seed, execute)

    @unittest.skipUnless(os.name == 'posix', 'portable compiler wrapper runs on Linux')
    def test_assembler_help_reaches_compiler_while_real_builds_use_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            compiler = root / 'cc'
            cache = root / 'sccache'
            for path, label, status in ((compiler, 'compiler', 17), (cache, 'cache', 23)):
                path.write_text(f'#!/bin/sh\nprintf "%s\\n" {label} "$@"\nexit {status}\n')
                path.chmod(0o755)
            env = dict(os.environ, PATH=f'{root}{os.pathsep}{os.environ["PATH"]}')
            wrapper = CACHE.configuration(trusted())['RUSTC_WRAPPER']
            probe = ['-Wa,--help', '-c', '-o', 'null.123.o', '-x', 'assembler', '/dev/null']
            direct = subprocess.run([wrapper, str(compiler), *probe], env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual((direct.returncode, direct.stdout.splitlines()), (17, ['compiler', *probe]))
            for tool, args in ((str(compiler), ['-c', 'real.S', '-o', 'real.o']),
                               (str(compiler), [*probe[:-1], 'real.S']),
                               ('rustc', ['--crate-name', 'fixture', 'file with spaces.rs'])):
                with self.subTest(tool=tool, args=args):
                    cached = subprocess.run([wrapper, tool, *args], env=env,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual((cached.returncode, cached.stdout.splitlines()),
                                     (23, ['cache', tool, *args]))

    def test_release_owner_and_isolated_manual_generation_keep_the_cache_boundary(self):
        for job in ('portable', 'portable-release'):
            config = CACHE.configuration(dict(trusted(), GITHUB_JOB=job))
            self.assertEqual(config['SCCACHE_S3_KEY_PREFIX'], 'portable-v1/')
            isolated = dict(trusted(), GITHUB_JOB=job, GITHUB_EVENT_NAME='workflow_dispatch',
                            OMG_R2_CACHE_ISOLATED='true', GITHUB_RUN_ID='123456789')
            self.assertEqual(CACHE.configuration(isolated)['SCCACHE_S3_KEY_PREFIX'],
                             'portable-diagnostic-v1/123456789/')
            for name, value in [('GITHUB_EVENT_NAME', 'push'), ('GITHUB_RUN_ID', '0'),
                                ('GITHUB_RUN_ID', '../123'), ('GITHUB_RUN_ID', '1\nINJECT=true'),
                                ('OMG_R2_CACHE_ISOLATED', 'yes')]:
                with self.subTest(job=job, name=name, value=value), self.assertRaises(ValueError):
                    CACHE.configuration(dict(isolated, **{name: value}))

    def test_benchmark_uses_r2_with_its_own_prefix_for_trusted_events(self):
        for event in ('push', 'workflow_dispatch', 'schedule'):
            with self.subTest(event=event):
                config = CACHE.configuration(dict(trusted(), GITHUB_JOB='benchmark', GITHUB_EVENT_NAME=event))
                self.assertEqual(config['SCCACHE_S3_KEY_PREFIX'], 'benchmark-v1/')
                self.assertEqual(config['SCCACHE_S3_RW_MODE'], 'READ_WRITE')
        for job in ('portable', 'portable-release'):
            with self.subTest(job=job), self.assertRaises(ValueError):
                CACHE.configuration(dict(trusted(), GITHUB_JOB=job, GITHUB_EVENT_NAME='schedule'))
        for name, value in [('GITHUB_EVENT_NAME', 'pull_request'),
                            ('GITHUB_EVENT_NAME', 'pull_request_target'),
                            ('GITHUB_REF', 'refs/heads/topic'),
                            ('GITHUB_REPOSITORY', 'someone/omg')]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                CACHE.configuration(dict(trusted(), GITHUB_JOB='benchmark', **{name: value}))

    def server(self, root, snapshots=None, failure=None, corrupt_replay=False):
        snapshots = iter(snapshots if snapshots is not None else
                         [statistics(), statistics(1, 1), statistics(1, 1, 1)])
        compilations = []

        def execute(command, **kwargs):
            # Activation cannot precede any of the actual server/probe calls.
            self.assertFalse((root / 'env').exists())
            self.assertFalse((root / 'output').exists())
            self.assertTrue(kwargs['capture_output'])
            self.assertTrue(kwargs['text'])
            self.assertLessEqual(kwargs['timeout'], 45)
            if command[1] == '--start-server':
                self.assertEqual(kwargs['env']['AWS_SECRET_ACCESS_KEY'], 'test-secret')
            else:
                self.assertNotIn('AWS_SECRET_ACCESS_KEY', kwargs['env'])
                self.assertNotIn('AWS_ACCESS_KEY_ID', kwargs['env'])
            if command[1] == failure:
                raise subprocess.CalledProcessError(1, command, stderr='test-secret')
            if command[1] == '--show-stats':
                return subprocess.CompletedProcess(command, 0, stdout=next(snapshots))
            if command[1] == 'rustc':
                name = command[command.index('--crate-name') + 1]
                artifact = Path(command[command.index('--out-dir') + 1]) / f'lib{name}.rlib'
                self.assertFalse(artifact.exists(), 'probe must remove the initial output')
                if compilations:
                    self.assertEqual(command, compilations[0])
                compilations.append(command.copy())
                artifact.write_bytes(b'corrupt' if corrupt_replay and len(compilations) == 2 else b'rlib')
            return subprocess.CompletedProcess(command, 0, stdout='')

        return Mock(side_effect=execute), compilations

    def test_opt_in_and_trust_boundary(self):
        self.assertEqual(CACHE.configuration({}), {})
        for name, value in [('GITHUB_EVENT_NAME', 'pull_request'),
                            ('GITHUB_EVENT_NAME', 'pull_request_target'),
                            ('GITHUB_EVENT_NAME', 'merge_group'),
                            ('GITHUB_REF', 'refs/heads/topic'),
                            ('GITHUB_REPOSITORY', 'someone/omg'),
                            ('GITHUB_JOB', 'linux-matrix'),
                            ('GITHUB_JOB', 'ubuntu'), ('GITHUB_JOB', 'qemu'),
                            ('OMG_R2_CACHE_ACCOUNT_ID', 'a\nINJECT=true'),
                            ('AWS_SECRET_ACCESS_KEY', ''), ('AWS_ACCESS_KEY_ID', ''),
                            ('RUSTC_WRAPPER', 'foreign-wrapper')]:
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                CACHE.configuration(dict(trusted(), **{name: value}))

    def test_outputs_follow_write_and_replay_without_client_credentials(self):
        names = []
        sockets = []
        for job in ('portable', 'portable-release', 'benchmark'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(trusted(), GITHUB_JOB=job, GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'output'))
                runner, compilations = self.server(root)
                CACHE.configure(env, runner)
                content = (root / 'env').read_text()
                self.assertIn(f'RUSTC_WRAPPER={compilations[0][0]}\n', content)
                self.assertIn('SCCACHE_REGION=auto\n', content)
                self.assertNotIn('test-secret', content)
                self.assertNotIn('test-access', content)
                self.assertEqual((root / 'output').read_text(), 'enabled=true\n')
                self.assertEqual(len(compilations), 2)
                names.append(compilations[0][compilations[0].index('--crate-name') + 1])
                sockets.append(runner.call_args_list[0].kwargs['env']['SCCACHE_SERVER_UDS'])
                self.assertFalse(Path(compilations[0][-1]).exists(), 'temporary probe must be removed')
        self.assertNotEqual(names[0], names[1])
        self.assertNotEqual(sockets[0], sockets[1])

    def test_read_only_miss_missing_rust_hit_and_invalid_stats_cannot_enable_cache(self):
        cases = {
            'read-only': [statistics(), statistics(0, 1, 0, 1)],
            'no-write': [statistics(), statistics(0, 1)],
            'initial-hit': [statistics(), statistics(0, 0, 1)],
            'second-miss': [statistics(), statistics(1, 1), statistics(2, 2)],
            'wrong-language': [statistics(), statistics(1, 1), statistics(1, 1, 1, language='C/C++')],
            'malformed-json': ['not JSON'],
            'missing-counters': ['{"stats": {}}'],
            'invalid-count': [statistics(writes=True)],
        }
        for case, snapshots in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(trusted(), GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'output'))
                runner, _ = self.server(root, snapshots)
                with self.assertRaises(ValueError):
                    CACHE.configure(env, runner)
                self.assertEqual(runner.call_args.args[0], ['sccache', '--stop-server'])
                self.assertFalse((root / 'env').exists())
                self.assertFalse((root / 'output').exists())

    def test_startup_or_compile_failure_stops_owned_server(self):
        for command in ('--start-server', 'rustc', '--show-stats'):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(trusted(), GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'output'))
                runner, _ = self.server(root, failure=command)
                with self.assertRaises(subprocess.CalledProcessError):
                    CACHE.configure(env, runner)
                self.assertEqual(runner.call_args.args[0], ['sccache', '--stop-server'])

    def test_cache_hit_must_restore_identical_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(trusted(), GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'output'))
            runner, _ = self.server(root, corrupt_replay=True)
            with self.assertRaisesRegex(ValueError, 'restore'):
                CACHE.configure(env, runner)
            self.assertEqual(runner.call_args.args[0], ['sccache', '--stop-server'])

    def test_startup_timeout_attempts_cleanup_and_preserves_original_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = dict(trusted(), GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'output'))
            failure = subprocess.TimeoutExpired('sccache', 45, stderr='test-secret')
            runner = Mock(side_effect=[failure, OSError('test-secret')])
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaises(subprocess.TimeoutExpired) as raised:
                CACHE.configure(env, runner)
            self.assertIs(raised.exception, failure)
            self.assertEqual(runner.call_args.args[0], ['sccache', '--stop-server'])
            self.assertNotIn('test-secret', output.getvalue())
            self.assertFalse((root / 'env').exists())
            self.assertFalse((root / 'output').exists())

    def test_native_producers_keep_their_cache_and_no_pr_credentials(self):
        source = CI_YML.read_text()
        for job in ('portable', 'portable-release'):
            portable = job_block(source, job)
            self.assertIn('python3 scripts/ci-r2-cache.py', portable)
            self.assertIn("github.event_name == 'push' || github.event_name == 'workflow_dispatch'", portable)
            self.assertIn("github.ref == 'refs/heads/main'", portable)
            self.assertIn("inputs.skip-cache != true", portable)
            self.assertIn('sccache@0.18.0', portable)
            self.assertIn('sccache --show-stats', portable)
        for job in ('linux-matrix', 'ubuntu', 'macos', 'qemu'):
            block = job_block(source, job)
            self.assertNotIn('ci-r2-cache.py', block)
            self.assertNotIn('OMG_R2_CACHE_SECRET_ACCESS_KEY', block)

    def test_pr_workflow_cannot_broaden_the_secret_main_step_or_send_parent_keys(self):
        import re
        source = CI_YML.read_text()
        main_condition = ("vars.OMG_R2_CACHE_ENABLED == 'true' && inputs.skip-cache != true && "
                          "github.ref == 'refs/heads/main' && "
                          "(github.event_name == 'push' || github.event_name == 'workflow_dispatch')")
        pr_condition = ("github.event_name == 'pull_request' && "
                        "github.event.pull_request.head.repo.full_name == github.repository && "
                        "vars.OMG_R2_CACHE_ENABLED == 'true' && "
                        "vars.OMG_R2_PR_CACHE_ENABLED == 'true' && inputs.skip-cache != true")
        for job in ('portable', 'portable-release'):
            block = job_block(source, job)
            steps = dict(re.findall(r'^      - name: ([^\n]+)\n(.*?)(?=^      - (?:name:|uses:)|\Z)',
                                    block, re.MULTILINE | re.DOTALL))
            for name, expected in (('Configure portable R2 cache', main_condition),
                                   ('Configure PR read-only R2 cache', pr_condition)):
                condition = re.search(r'        if: >-\n(.*?)\n        env:', steps[name], re.DOTALL)
                self.assertIsNotNone(condition)
                self.assertEqual(' '.join(condition.group(1).split()), expected)
            pr = steps['Configure PR read-only R2 cache']
            self.assertNotIn('secrets.', pr)
            self.assertNotIn('AWS_', pr)
            self.assertNotIn('continue-on-error', pr)
            self.assertIn('GITHUB_TOKEN: ${{ github.token }}', pr)
            self.assertIn('python3 scripts/ci-r2-cache.py --mode pr-read', pr)
            header = block.split('    steps:', 1)[0]
            self.assertIn('      contents: read\n      id-token: write\n      pull-requests: read\n', header)
            for name in ('Report portable compiler cache', 'Preserve portable compiler cache diagnostics'):
                self.assertIn("steps.r2-cache.outputs.enabled == 'true' || steps.r2-pr-cache.outputs.enabled == 'true'", steps[name])

    def test_benchmark_workflow_verifies_cache_before_compiling_and_keeps_diagnostics(self):
        source = (CI_YML.parent / 'benchmark.yml').read_text()
        block = job_block(source, 'benchmark')
        self.assertIn('sccache@0.18.0', block)
        self.assertIn('python3 scripts/ci-r2-cache.py', block)
        self.assertLess(block.index('python3 scripts/ci-r2-cache.py'), block.index('run: cargo build'))
        self.assertNotIn('SCCACHE_GHA_ENABLED', block)
        for name in ('Install benchmark compiler cache', 'Configure benchmark R2 cache'):
            step = block.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertIn("github.ref == 'refs/heads/main'", step)
            self.assertIn("vars.OMG_R2_CACHE_ENABLED == 'true'", step)
        self.assertIn("if: always() && steps.r2-cache.outputs.enabled == 'true'", block)
        self.assertIn('sccache --stop-server', block)
        self.assertIn('sccache --show-stats --stats-format=json', block)
        self.assertIn('compiler-cache-${{ github.job }}-${{ github.run_attempt }}', block)


if __name__ == '__main__':
    unittest.main()

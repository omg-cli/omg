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
                                'cache_misses': {'counts': {language: misses}},
                                'cache_hits': {'counts': {language: hits}}}})


class R2CacheTests(unittest.TestCase):
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

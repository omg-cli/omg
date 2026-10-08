"""Exercise cache trust boundaries and setup failure without cloud credentials."""
import importlib.util
import contextlib
import io
import json
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
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                env = dict(trusted(), GITHUB_ENV=str(root / 'env'), GITHUB_OUTPUT=str(root / 'output'))
                runner, compilations = self.server(root)
                CACHE.configure(env, runner)
                content = (root / 'env').read_text()
                self.assertIn('RUSTC_WRAPPER=sccache\n', content)
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

    def test_workflow_cache_is_portable_only_and_no_pr_credentials(self):
        source = CI_YML.read_text()
        portable = job_block(source, 'portable')
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


if __name__ == '__main__':
    unittest.main()

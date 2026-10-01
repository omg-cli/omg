"""Admission and workflow negatives; fixtures do not prove runtime installs."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('runtime_usage_ci', Path(__file__).with_name('runtime-usage-ci.py'))
USAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(USAGE)
from test_native_build_artifact import fixture, bundle

EXPECTED = dict(repository='omg-cli/omg', source='a' * 40, run=123, attempt=1)
RUN = dict(id=123, run_attempt=1, repository={'full_name': 'omg-cli/omg'},
           path='.github/workflows/ci.yml', head_sha='a' * 40, status='in_progress', conclusion=None)
JOB = dict(name='Linux (ubuntu)', status='completed', conclusion='success', head_sha='a' * 40)
ARTIFACT = dict(id=456, name='native-release-ubuntu-1', expired=False, size_in_bytes=1024,
                workflow_run=dict(id=123, head_sha='a' * 40))


class AdmissionTests(unittest.TestCase):
    def test_current_run_owner_and_artifact_accept_without_whole_workflow_completion(self):
        USAGE.validate_run(RUN, EXPECTED)
        self.assertEqual(USAGE.select_artifact([ARTIFACT], [JOB], EXPECTED), ARTIFACT)

    def test_foreign_source_workflow_run_attempt_and_cancelled_run_fail(self):
        for field, value in [('id', 124), ('run_attempt', 2), ('head_sha', 'b' * 40),
                             ('path', '.github/workflows/release.yml'), ('conclusion', 'cancelled'),
                             ('conclusion', 'failure')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                USAGE.validate_run(dict(RUN, **{field: value}), EXPECTED)

    def test_duplicate_expired_wrong_attempt_wrong_source_and_foreign_artifact_refused(self):
        variants = [[], [ARTIFACT, ARTIFACT], [dict(ARTIFACT, expired=True)],
                    [dict(ARTIFACT, name='native-release-ubuntu-2')],
                    [dict(ARTIFACT, workflow_run=dict(id=124, head_sha='a' * 40))],
                    [dict(ARTIFACT, workflow_run=dict(id=123, head_sha='b' * 40))]]
        for artifacts in variants:
            with self.subTest(artifacts=artifacts), self.assertRaises(ValueError):
                USAGE.select_artifact(artifacts, [JOB], EXPECTED)

    def test_unsuccessful_or_ambiguous_ubuntu_owner_refused(self):
        for jobs in ([], [JOB, JOB], [dict(JOB, conclusion='failure')],
                     [dict(JOB, conclusion='cancelled')], [dict(JOB, conclusion='skipped')],
                     [dict(JOB, status='in_progress')], [dict(JOB, head_sha='b' * 40)]):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                USAGE.select_artifact([ARTIFACT], jobs, EXPECTED)

    def test_real_validator_rejects_recipe_digest_and_source_changes(self):
        expected, provenance, payload = fixture('ubuntu')
        expected['image'] = 'ubuntu-24.04'
        provenance['image'] = expected['image']
        data = bundle(provenance, payload)
        server_digest = 'sha256:' + hashlib.sha256(data).hexdigest()
        admitted, _ = USAGE.native.validate_bundle(data, server_digest, expected)
        self.assertEqual(admitted, provenance)
        for field, value in [('image', 'ubuntu-26.04'), ('features', ['debian-pure']),
                             ('source_sha', 'b' * 40), ('run_id', '124'), ('run_attempt', 2)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                USAGE.native.validate_bundle(data, server_digest, dict(expected, **{field: value}))
        with self.assertRaises(ValueError):
            USAGE.native.validate_bundle(data, 'sha256:' + '0' * 64, expected)

    def test_changed_live_attempt_rejected_before_binary_write(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'bin').mkdir()
            responses = [RUN, dict(jobs=[JOB]), dict(artifacts=[ARTIFACT]), dict(RUN, run_attempt=2)]
            provenance = dict(archive='subject.tar.gz')
            with patch.object(USAGE, 'checked_state', return_value=EXPECTED), \
                    patch.object(USAGE.native, 'command_output', return_value='a' * 40), \
                    patch.object(USAGE.native, 'api_json', side_effect=responses), \
                    patch.object(USAGE.native, 'download_artifact', return_value=b'fixture'), \
                    patch.object(USAGE.native, 'validate_bundle', return_value=(provenance, {})):
                with self.assertRaisesRegex(ValueError, 'superseded'):
                    USAGE.admit(state, {})
            self.assertEqual(list((state / 'bin').iterdir()), [])

    def test_product_environment_excludes_token_and_inherited_runtime_variables(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'fixture-token', 'OMG_DATA_DIR': '/foreign', 'NODE_OPTIONS': '--bad'}):
            environment = USAGE.product_environment(Path('/private'))
        self.assertEqual(set(environment), {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL'})
        self.assertEqual(environment['HOME'], '/private/home')

    def test_cleanup_refuses_redirected_state_without_deleting_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'protected'
            target.mkdir()
            marker = target / 'keep'
            marker.write_text('retained')
            link = root / 'runtime-usage-123-1'
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'redirected'):
                USAGE.cleanup(link, {})
            self.assertEqual(marker.read_text(), 'retained')

    def test_private_state_lifecycle_and_child_redirect_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            context = dict(RUNNER_TEMP=str(parent), GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                           GITHUB_REPOSITORY='omg-cli/omg', GITHUB_SHA='a' * 40)
            state = parent / 'runtime-usage-123-1'
            self.assertNotEqual(os.getuid(), 0, 'run lifecycle checks as an actual ordinary user')
            USAGE.initialize(state, context)
            self.assertEqual(USAGE.checked_state(state, context)['run'], 123)
            home = state / 'home'
            home.rmdir()
            protected = parent / 'protected'
            protected.mkdir()
            home.symlink_to(protected, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'redirected'):
                USAGE.cleanup(state, context)
            self.assertTrue(protected.exists())
            home.unlink()
            home.mkdir(mode=0o700)
            USAGE.cleanup(state, context)
            self.assertFalse(state.exists())

    def test_root_identity_rejected_before_creating_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'runtime-usage-123-1'
            with patch.object(USAGE.os, 'getuid', return_value=0), \
                    patch.object(USAGE.os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(ValueError, 'ordinary'):
                    USAGE.initialize(state, {})
            self.assertFalse(state.exists())


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (USAGE.ROOT / '.github/workflows/ci.yml').read_text()
        self.body = self.text.split('\n  runtime-usage:\n', 1)[1].split('\n  ci-success:', 1)[0]

    def test_consumer_binding_deadlines_permissions_and_failure_evidence(self):
        self.assertIn('needs: [quick-gate, ubuntu]', self.body)
        self.assertIn('runs-on: ubuntu-24.04', self.body)
        self.assertNotIn('container:', self.body)
        self.assertIn('timeout-minutes: 15', self.body)
        self.assertIn('actions: read', self.body)
        self.assertNotIn('actions: write', self.body)
        blocks = self.body.split('      - name: ')
        token_blocks = [block for block in blocks if 'GH_TOKEN:' in block]
        self.assertEqual(len(token_blocks), 1)
        self.assertTrue(token_blocks[0].startswith("Admit this attempt's Ubuntu release"))
        self.assertIn('--kill-after=5s 60s', token_blocks[0])
        self.assertIn('--kill-after=5s 800s', self.body)
        self.assertIn('if: always()\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a', self.body)
        self.assertIn("if: always() && steps.upload-runtime-evidence.outcome == 'success'", self.body)
        self.assertIn('if-no-files-found: error', self.body)

    def test_actual_ci_success_shell_requires_runtime_success_for_builds(self):
        body = self.text.split('\n  ci-success:\n', 1)[1].split('\n  release-tag:', 1)[0]
        self.assertIn('docs-audit, runtime-usage]', body)
        self.assertIn('RUNTIME_USAGE: ${{ needs.runtime-usage.result }}', body)
        script = body.split('        run: |\n', 1)[1].split('\n  #', 1)[0]
        script = '\n'.join(line[10:] for line in script.splitlines())
        keys = ['QUICK_GATE', 'PORTABLE', 'LINUX_MATRIX', 'SANDBOX_CANCELLATION',
                'FEATURE_INTERSECTIONS', 'MACOS', 'UBUNTU', 'QEMU', 'DOCS_AUDIT']
        for required, status, accepted in [('true', 'success', True), ('true', 'failure', False),
                                            ('true', 'cancelled', False), ('true', 'skipped', False),
                                            ('false', 'skipped', True), ('false', 'failure', False)]:
            with self.subTest(required=required, status=status), tempfile.TemporaryDirectory() as directory:
                environment = dict(os.environ, **dict.fromkeys(keys, 'success'),
                                   BUILD_REQUIRED=required, RUNTIME_USAGE=status, QEMU_REQUIRED='false',
                                   GITHUB_STEP_SUMMARY=str(Path(directory) / 'summary'))
                result = subprocess.run(['bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                                        env=environment, capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_original_accounting_assertions_and_all_switch_deadlines_retained(self):
        script = (USAGE.ROOT / 'scripts/test-runtime-usage.sh').read_text()
        self.assertIn('for telemetry in 0 1;', script)
        self.assertIn('for count in 1 2;', script)
        self.assertIn('timeout --kill-after=5s 180 "$binary" use node 24.21.0', script)
        self.assertIn('timeout --kill-after=5s 10 "$OMG_DATA_DIR/versions/node/current/bin/node"', script)
        for assertion in ("usage['runtime_usage_counts']['node'] == count", "usage['commands']['runtime_switch'] == count",
                          "usage['total_commands'] == count", "process.version !== \"v24.21.0\" || 6*7 !== 42"):
            self.assertIn(assertion, script)


if __name__ == '__main__':
    unittest.main()

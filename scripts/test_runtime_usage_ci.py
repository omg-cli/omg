"""Admission and workflow negatives; fixtures do not prove runtime installs."""
import hashlib
import importlib.util
import json
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

EXPECTED = dict(repository='omg-cli/omg', source='a' * 40, api_head='a' * 40, event='push', run=123, attempt=1)
RUN = dict(id=123, run_attempt=1, repository={'full_name': 'omg-cli/omg'},
           path='.github/workflows/ci.yml', event='push', head_sha='a' * 40, status='in_progress', conclusion=None)
JOB = dict(name='Linux (ubuntu)', status='completed', conclusion='success', head_sha='a' * 40,
           run_id=123, run_attempt=1)
ARTIFACT = dict(id=456, name='native-release-ubuntu-1', expired=False, size_in_bytes=1024,
                workflow_run=dict(id=123, head_sha='a' * 40))


class EventIdentityTests(unittest.TestCase):
    # Actual PR 691 run 36891723110 reports this head, while its native
    # provenance records the distinct tested merge and Git commit tree.
    HEAD = 'b7c50f884af5a3f4e3a3d963f9a8de5037a06c47'
    BASE = '624bd8a1294a0b8cbcec1bc8a14f25aa2ff56638'
    MERGE = '886c5674d514e0862a90fb7b210a69d5a5ee22cf'
    TREE = '67b2400c52c16a2b883fec3ed79bed539f75447a'

    def pr_fixture(self):
        side = lambda sha, ref: dict(sha=sha, ref=ref, repo=dict(id=1133413326, full_name='omg-cli/omg'))
        event = dict(repository={'full_name': 'omg-cli/omg'}, number=691,
                     pull_request=dict(head=side(self.HEAD, 'fix/qemu-semantic-combined'),
                                       base=side(self.BASE, 'main')))
        context = dict(GITHUB_REPOSITORY='omg-cli/omg', GITHUB_SHA=self.MERGE,
                       GITHUB_RUN_ID='36891723110', GITHUB_RUN_ATTEMPT='1',
                       GITHUB_EVENT_NAME='pull_request', GITHUB_REF='refs/pull/691/merge')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            path.write_text(json.dumps(event))
            expected = USAGE.identity(dict(context, GITHUB_EVENT_PATH=str(path)))
        api_pr = dict(number=691, head=event['pull_request']['head'], base=event['pull_request']['base'])
        run = dict(RUN, id=36891723110, event='pull_request', head_sha=self.HEAD, pull_requests=[api_pr])
        commit = dict(sha=self.MERGE, tree=dict(sha=self.TREE),
                      parents=[dict(sha=self.BASE), dict(sha=self.HEAD)])
        return expected, run, commit

    def test_pr_api_head_differs_from_tested_merge_without_weakening_recipe(self):
        expected, run, commit = self.pr_fixture()
        self.assertEqual(expected['source'], self.MERGE)
        self.assertEqual(expected['api_head'], self.HEAD)
        USAGE.validate_run(run, expected)
        USAGE.validate_commit(commit, expected, self.TREE)
        job = dict(JOB, run_id=36891723110, head_sha=self.HEAD)
        artifact = dict(ARTIFACT, workflow_run=dict(id=36891723110, head_sha=self.HEAD))
        self.assertEqual(USAGE.select_artifact([artifact], [job], expected), artifact)
        recipe, provenance, payload = fixture('ubuntu')
        recipe.update(source_sha=self.MERGE, run_id='36891723110', image='ubuntu-24.04')
        provenance.update(source_sha=self.MERGE, run_id='36891723110', image='ubuntu-24.04')
        data = bundle(provenance, payload)
        digest = 'sha256:' + hashlib.sha256(data).hexdigest()
        USAGE.native.validate_bundle(data, digest, recipe)
        with self.assertRaisesRegex(ValueError, 'source_sha'):
            USAGE.native.validate_bundle(data, digest, dict(recipe, source_sha=self.HEAD))

    def test_wrong_pr_head_base_number_event_and_refs_fail(self):
        expected, run, _ = self.pr_fixture()
        for field, value in [('head_sha', self.MERGE), ('event', 'push'), ('run_attempt', 2)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                USAGE.validate_run(dict(run, **{field: value}), expected)
        for side, field, value in [('base', 'ref', 'foreign'), ('head', 'ref', 'foreign')]:
            wrong = json.loads(json.dumps(run))
            wrong['pull_requests'][0][side][field] = value
            with self.subTest(side=side, field=field), self.assertRaises(ValueError):
                USAGE.validate_run(wrong, expected)
        wrong = json.loads(json.dumps(run))
        wrong['pull_requests'][0]['number'] = 692
        with self.assertRaisesRegex(ValueError, 'another PR'):
            USAGE.validate_run(wrong, expected)
        for side in ('head', 'base'):
            wrong = json.loads(json.dumps(run))
            wrong['pull_requests'][0][side]['repo']['id'] = 999
            with self.subTest(side=side), self.assertRaises(ValueError):
                USAGE.validate_run(wrong, expected)

    def test_mutable_pr_association_shas_do_not_replace_immutable_run_or_tested_source(self):
        expected, run, commit = self.pr_fixture()
        refreshed = json.loads(json.dumps(run))
        # Observed drift on the same run after normal branch/main refresh.
        refreshed['pull_requests'][0]['head']['sha'] = '98d0145f60364ac724c23e22b84f85f3c853eeab'
        refreshed['pull_requests'][0]['base']['sha'] = 'a3817fede533981d85f431d9b7d787bbaac932fb'
        USAGE.validate_run(refreshed, expected)
        USAGE.validate_commit(commit, expected, self.TREE)
        self.assertEqual(expected['api_head'], self.HEAD)
        self.assertEqual(expected['source'], self.MERGE)
        with self.assertRaises(ValueError):
            USAGE.validate_run(dict(refreshed, head_sha=refreshed['pull_requests'][0]['head']['sha']), expected)
        with self.assertRaises(ValueError):
            USAGE.validate_commit(dict(commit, parents=[dict(sha='a3817fede533981d85f431d9b7d787bbaac932fb'),
                                                        dict(sha=self.HEAD)]), expected, self.TREE)

    def test_wrong_tree_source_or_merge_parent_link_fails(self):
        expected, _, commit = self.pr_fixture()
        for wrong, tree in [(commit, 'a' * 40), (dict(commit, sha=self.HEAD), self.TREE),
                            (dict(commit, parents=[dict(sha=self.HEAD), dict(sha=self.BASE)]), self.TREE),
                            (dict(commit, parents=[dict(sha=self.BASE), dict(sha='a' * 40)]), self.TREE)]:
            with self.subTest(wrong=wrong, tree=tree), self.assertRaises(ValueError):
                USAGE.validate_commit(wrong, expected, tree)

    def test_main_manual_and_merge_group_keep_exact_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'event.json'
            for name, event in [('push', dict(after='a' * 40)), ('workflow_dispatch', {}),
                                ('merge_group', dict(merge_group=dict(head_sha='a' * 40, head_ref='refs/heads/queue')))]:
                event['repository'] = {'full_name': 'omg-cli/omg'}
                path.write_text(json.dumps(event))
                context = dict(GITHUB_REPOSITORY='omg-cli/omg', GITHUB_SHA='a' * 40,
                               GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME=name,
                               GITHUB_REF='refs/heads/queue', GITHUB_EVENT_PATH=str(path))
                expected = USAGE.identity(context)
                self.assertEqual(expected['api_head'], expected['source'])
                USAGE.validate_run(dict(RUN, event=name), expected)


class AdmissionTests(unittest.TestCase):
    def test_rejected_merge_retains_identity_tree_and_ordered_parents_without_secrets(self):
        expected, run, commit = EventIdentityTests().pr_fixture()
        wrong = dict(commit, parents=[dict(sha='c' * 40), commit['parents'][1]],
                     message='fixture-secret', verification={'signature': 'fixture-secret'})
        run = dict(run, token='fixture-secret', body='fixture-secret')
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'evidence').mkdir()
            (state / 'bin').mkdir()
            with patch.object(USAGE, 'checked_state', return_value=expected), \
                    patch.object(USAGE.native, 'command_output', side_effect=[expected['source'], EventIdentityTests.TREE]), \
                    patch.object(USAGE.native, 'api_json', side_effect=[run, wrong]), \
                    patch.object(USAGE.native, 'download_artifact') as download:
                with self.assertRaisesRegex(ValueError, 'exact PR base and head'):
                    USAGE.admit(state, {'GH_TOKEN': 'fixture-secret'})
            receipt_path = state / 'evidence/admission-inputs.json'
            self.assertTrue(receipt_path.is_file(), 'rejected merge must retain admission inputs')
            receipt = json.loads(receipt_path.read_text())
            self.assertEqual(receipt['trustedIdentity'], expected)
            self.assertEqual(receipt['checkoutSource'], expected['source'])
            self.assertEqual(receipt['checkoutTree'], EventIdentityTests.TREE)
            self.assertEqual(receipt['sourceCommit']['parents'], wrong['parents'])
            self.assertEqual(receipt['sourceCommit']['tree'], commit['tree'])
            self.assertEqual(receipt['producer']['pull_requests'], run['pull_requests'])
            self.assertNotIn('fixture-secret', receipt_path.read_text())
            self.assertFalse((state / 'evidence/admission.json').exists())
            self.assertEqual(list((state / 'bin').iterdir()), [])
            download.assert_not_called()

    def test_rejected_checkout_or_producer_retains_available_inputs(self):
        for source, run, message in [('b' * 40, RUN, 'checkout source'),
                                      (EXPECTED['source'], dict(RUN, run_attempt=2), 'superseded')]:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                (state / 'evidence').mkdir()
                with patch.object(USAGE, 'checked_state', return_value=EXPECTED), \
                        patch.object(USAGE.native, 'command_output', return_value=source), \
                        patch.object(USAGE.native, 'api_json', return_value=run):
                    with self.assertRaisesRegex(ValueError, message):
                        USAGE.admit(state, {})
                receipt = json.loads((state / 'evidence/admission-inputs.json').read_text())
                self.assertEqual(receipt['trustedIdentity'], EXPECTED)
                self.assertEqual(receipt['checkoutSource'], source)
                if source == EXPECTED['source']:
                    self.assertEqual(receipt['producer']['run_attempt'], 2)
                self.assertNotIn('sourceCommit', receipt)

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
            (state / 'evidence').mkdir()
            responses = [RUN, dict(sha='a' * 40, tree=dict(sha='a' * 40)),
                         dict(jobs=[JOB]), dict(artifacts=[ARTIFACT]), dict(RUN, run_attempt=2)]
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
                           GITHUB_REPOSITORY='omg-cli/omg', GITHUB_SHA='a' * 40,
                           GITHUB_EVENT_NAME='push', GITHUB_EVENT_PATH=str(parent / 'event.json'),
                           GH_TOKEN='fixture-secret')
            (parent / 'event.json').write_text(json.dumps(dict(repository={'full_name': 'omg-cli/omg'},
                                                             after='a' * 40, body='fixture-secret')))
            state = parent / 'runtime-usage-123-1'
            self.assertNotEqual(os.getuid(), 0, 'run lifecycle checks as an actual ordinary user')
            USAGE.initialize(state, context)
            self.assertEqual(USAGE.checked_state(state, context)['run'], 123)
            self.assertEqual(json.loads((state / 'evidence/identity.json').read_text()),
                             json.loads((state / 'ownership.json').read_text()))
            self.assertNotIn('fixture-secret', (state / 'evidence/identity.json').read_text())
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
        keys = ['QUICK_GATE', 'STANDALONE_SUITES', 'PORTABLE', 'LINUX_MATRIX', 'SANDBOX_CANCELLATION',
                'FEATURE_INTERSECTIONS', 'MACOS', 'MACOS_NEXTEST_SOURCE', 'UBUNTU', 'QEMU', 'DOCS_AUDIT']
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

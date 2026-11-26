"""Exercise release decisions from complete and changing GitHub snapshots."""

import contextlib
import copy
import io
from pathlib import Path
import runpy
import unittest
from unittest import mock


GATE = runpy.run_path(str(Path(__file__).with_name('require-release-evidence.py')))
REPO = 'omg-cli/omg'
SHA = 'a' * 40
WORKFLOWS = (
    'ci.yml', 'benchmark.yml', 'audit.yml', 'secrets.yml',
    'codeql.yml', 'coverage.yml', 'docker-e2e.yml',
)


def release_snapshot():
    return {
        'total_count': len(WORKFLOWS),
        'workflow_runs': [
            dict(id=index, run_attempt=1, path=f'.github/workflows/{file}',
                 head_sha=SHA, head_branch='main', event='push', repository={'full_name': REPO},
                 created_at='2026-06-01T00:00:00Z', status='completed', conclusion='success')
            for index, file in enumerate(WORKFLOWS, start=1)
        ],
    }


class RequireReleaseEvidence(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(GATE['time'], 'sleep')
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)
        output = contextlib.redirect_stdout(io.StringIO())
        self.stdout = output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def invoke(self, *snapshots):
        read = mock.Mock(side_effect=snapshots)
        GATE['require_release_evidence'](REPO, SHA, read)
        return read

    def test_all_seven_checks_pass_from_one_snapshot(self):
        read = self.invoke(release_snapshot())
        read.assert_called_once_with(REPO, SHA)
        self.assertEqual(self.stdout.getvalue().count(' passed for '), len(WORKFLOWS))
        self.sleep.assert_not_called()

    def test_a_known_failure_refuses_while_ci_is_pending(self):
        data = release_snapshot()
        data['workflow_runs'][0].update(status='in_progress', conclusion=None)
        data['workflow_runs'][5].update(conclusion='failure')
        with self.assertRaisesRegex(ValueError, 'Coverage run 6 did not succeed: completed/failure'):
            self.invoke(data)
        self.sleep.assert_not_called()

    def test_workflow_path_allows_one_main_ref_suffix(self):
        data = release_snapshot()
        data['workflow_runs'][0]['path'] += '@main'
        data['workflow_runs'][1]['path'] += '@refs/heads/main'
        self.invoke(data).assert_called_once_with(REPO, SHA)

        data['workflow_runs'][1]['path'] += '@main'
        with self.assertRaisesRegex(ValueError, 'No main-push run.*Benchmark'):
            self.invoke(data)

    def test_pending_runs_must_complete_on_the_same_attempt(self):
        complete = release_snapshot()
        pending = copy.deepcopy(complete)
        pending['workflow_runs'][0].update(status='queued', conclusion=None)
        read = self.invoke(pending, complete)
        self.assertEqual(read.call_args_list, [mock.call(REPO, SHA)] * 2)
        self.sleep.assert_called_once_with(GATE['POLL_SECONDS'])

    def test_replacement_run_or_attempt_after_wait_refuses(self):
        for change in (dict(run_attempt=2), dict(id=99)):
            with self.subTest(change=change):
                complete = release_snapshot()
                pending = copy.deepcopy(complete)
                pending['workflow_runs'][1].update(status='in_progress', conclusion=None)
                complete['workflow_runs'][0].update(change)
                with self.assertRaisesRegex(ValueError, 'Latest workflow evidence changed.*CI'):
                    self.invoke(pending, complete)

    def test_a_newer_failed_run_overrides_an_older_success(self):
        data = release_snapshot()
        newer = copy.deepcopy(data['workflow_runs'][0])
        newer.update(id=99, created_at='2026-06-01T00:01:00Z', conclusion='cancelled')
        data['workflow_runs'].append(newer)
        data['total_count'] += 1
        with self.assertRaisesRegex(ValueError, 'CI run 99 did not succeed'):
            self.invoke(data)

    def test_missing_large_or_foreign_evidence_refuses(self):
        missing = release_snapshot()
        missing['workflow_runs'].pop()
        missing['total_count'] -= 1
        incomplete = release_snapshot()
        incomplete['total_count'] = 101
        cases = [(missing, 'No main-push run.*Docker E2E'), (incomplete, 'Incomplete')]
        for change in ({'head_sha': 'b' * 40}, {'head_branch': 'review'}, {'event': 'pull_request'},
                       {'repository': {'full_name': 'another/omg'}}):
            foreign = release_snapshot()
            foreign['workflow_runs'][0].update(change)
            cases.append((foreign, 'Unexpected CI workflow run identity'))
        for data, error in cases:
            with self.subTest(error=error):
                with self.assertRaisesRegex(ValueError, error):
                    self.invoke(data)


if __name__ == '__main__':
    unittest.main()

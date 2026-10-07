"""Actual checker and Git fixtures; no hosted enforcement claim."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('debt-ratchet.py')
MARKER = 'TO' + 'DO'


class IndependentDebtBaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='omg-debt-base-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git('init', '--initial-branch=main')
        self.write('src/a.py', '# ' + MARKER + '\n')
        seeded = self.run_checker('--refresh')
        self.assertEqual(seeded.returncode, 0, seeded.stderr)
        self.base = self.commit()
        self.write('src/clean.py', '# clean\n')
        self.head = self.commit()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def git(self, *arguments):
        result = subprocess.run(['git', '-C', str(self.root), *arguments],
                                check=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip()

    def commit(self):
        self.git('add', '--all')
        self.git('-c', 'user.name=Debt fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def run_checker(self, *arguments, environment=None):
        env = dict(os.environ)
        if environment:
            env.update(environment)
        return subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root), *arguments],
                              env=env, capture_output=True, text=True, timeout=60)

    def independent(self, *arguments):
        return self.run_checker('--base-revision', self.base, *arguments)

    def test_manual_candidate_floor_cannot_authorize_new_debt(self):
        self.write('src/a.py', ('# ' + MARKER + '\n') * 2)
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        self.head = self.commit()
        result = self.independent()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('candidate baseline increased', result.stderr)
        self.assertIn('debt exceeds independent base', result.stderr)

    def test_candidate_floor_increase_fails_even_without_new_debt(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        result = self.independent()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('candidate baseline increased', result.stderr)

    def test_unlisted_candidate_floor_cannot_authorize_new_file(self):
        self.write('src/b.py', '# ' + MARKER + '\n')
        self.write('scripts/debt-ratchets/todo-markers.baseline', '1 = src/a.py\n1 = src/b.py\n')
        result = self.independent()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('unlisted in base', result.stderr)

    def test_unchanged_and_decreased_floors_pass(self):
        result = self.independent()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.write('src/a.py', '# clean\n')
        self.write('scripts/debt-ratchets/todo-markers.baseline', '')
        result = self.independent()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lower_candidate_floor_still_requires_matching_cleanup(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '')
        result = self.independent()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_missing_or_invalid_candidate_baseline_fails_closed(self):
        path = self.root / 'scripts/debt-ratchets/todo-markers.baseline'
        for text in (None, 'garbage', '1 = src/a.py\n2 = src/a.py\n'):
            with self.subTest(text=text):
                if text is None:
                    path.unlink()
                else:
                    path.write_text(text, encoding='utf-8')
                result = self.independent()
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def test_invalid_unavailable_and_candidate_base_commits_are_refused(self):
        for base in ('main', '0' * 40, 'f' * 40, self.head):
            with self.subTest(base=base):
                result = self.run_checker('--base-revision', base)
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def test_missing_or_malformed_base_blob_is_not_seeded(self):
        path = self.root / 'scripts/debt-ratchets/todo-markers.baseline'
        for content in (None, 'garbage', ' 1 = src/a.py\n'):
            with self.subTest(content=content):
                if content is None:
                    path.unlink()
                else:
                    path.write_text(content, encoding='utf-8')
                base = self.commit()
                path.write_text('1 = src/a.py\n', encoding='utf-8')
                self.commit()
                result = self.run_checker('--base-revision', base)
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def test_unrelated_base_is_not_an_ancestor(self):
        tree = self.git('rev-parse', self.base + '^{tree}')
        unrelated = self.git('-c', 'user.name=Debt fixture', '-c', 'user.email=fixture@example.invalid',
                             'commit-tree', tree, '-m', 'unrelated root')
        result = self.run_checker('--base-revision', unrelated)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def test_base_check_cannot_refresh_or_read_an_external_floor(self):
        result = self.independent('--refresh')
        self.assertEqual(result.returncode, 2, result.stderr)
        with tempfile.TemporaryDirectory() as outside:
            result = self.independent('--baseline-dir', outside)
            self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def ci(self, kind, event, **overrides):
        if isinstance(event, dict):
            event.setdefault('repository', {'full_name': 'omg-cli/omg'})
        path = self.root / '.git/debt-event.json'
        path.write_text(json.dumps(event), encoding='utf-8')
        environment = dict(GITHUB_EVENT_PATH=str(path), GITHUB_EVENT_NAME=kind,
                           GITHUB_SHA=self.head, GITHUB_REPOSITORY='omg-cli/omg')
        environment.update(overrides)
        return self.run_checker('--ci', environment=environment)

    def test_ci_binds_all_supported_events_to_real_commits(self):
        cases = (
            ('push', {'before': self.base, 'after': self.head}),
            ('merge_group', {'merge_group': {'base_sha': self.base, 'head_sha': self.head}}),
            ('workflow_dispatch', {}),
        )
        for kind, event in cases:
            with self.subTest(kind=kind):
                result = self.ci(kind, event)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Verified debt base: ' + self.base, result.stdout)

    def test_pr_requires_exact_merge_parents_and_repository(self):
        candidate = self.head
        self.git('branch', 'candidate', candidate)
        self.git('checkout', 'main')
        self.git('reset', '--hard', self.base)
        self.write('src/base.py', '# base change\n')
        self.base = self.commit()
        self.git('-c', 'user.name=Debt fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'merge', '--no-ff', 'candidate', '-m', 'merge fixture')
        self.head = self.git('rev-parse', 'HEAD')
        event = {'pull_request': {'base': {'sha': self.base, 'repo': {'full_name': 'omg-cli/omg'}},
                                  'head': {'sha': candidate}}}
        result = self.ci('pull_request', event)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        event['pull_request']['base']['repo']['full_name'] = 'other/repo'
        self.assertEqual(self.ci('pull_request', event).returncode, 4)
        event['pull_request']['base']['repo']['full_name'] = 'omg-cli/omg'
        event['pull_request']['head']['sha'] = self.base
        self.assertEqual(self.ci('pull_request', event).returncode, 4)

    def test_zero_candidate_floor_does_not_increase_implicit_zero(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '1 = src/a.py\n0 = src/clean.py\n')
        result = self.independent()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_local_replacement_cannot_raise_the_verified_floor(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        self.git('add', '--all')
        replacement_tree = self.git('write-tree')
        replacement = self.git('-c', 'user.name=Debt fixture', '-c', 'user.email=fixture@example.invalid',
                               'commit-tree', replacement_tree, '-m', 'replacement')
        self.git('replace', self.base, replacement)
        result = self.independent()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('candidate baseline increased', result.stderr)

    def test_ci_missing_unknown_and_wrong_identities_fail_closed(self):
        cases = (
            ('push', {'before': self.base, 'after': 'f' * 40}, {}),
            ('push', {'before': '0' * 40, 'after': self.head}, {}),
            ('push', {'before': self.base, 'after': self.head}, {'GITHUB_SHA': self.base}),
            ('merge_group', {'merge_group': {'base_sha': self.base, 'head_sha': self.base}}, {}),
            ('merge_group', {'merge_group': []}, {}),
            ('pull_request', {'pull_request': {'base': {'sha': self.base},
                                              'head': {'sha': 'f' * 40}}}, {}),
            ('pull_request', {}, {}),
            ('unknown', {}, {}),
            ('push', [], {}),
            ('push', {'before': self.base, 'after': self.head,
                      'repository': {'full_name': 'other/repo'}}, {}),
        )
        for kind, event, overrides in cases:
            with self.subTest(kind=kind, event=event):
                result = self.ci(kind, event, **overrides)
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)

    def test_hosted_workflow_selects_independent_ci_mode(self):
        workflow = SCRIPT.parents[1] / '.github/workflows/ci.yml'
        text = workflow.read_text(encoding='utf-8')
        self.assertIn('run: python3 scripts/debt-ratchet.py --ci', text)
        self.assertIn('fetch-depth: 0', text)


if __name__ == '__main__':
    unittest.main()

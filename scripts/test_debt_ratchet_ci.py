"""Real Git/event fixtures for the debt command selected by CI."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MARKER = 'TO' + 'DO'
REPOSITORY = 'omg-cli/omg'


class DebtRatchetCITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'repo'
        self.root.mkdir()
        self.event_path = self.root.parent / 'event.json'
        self.git('init', '-b', 'main')
        self.git('config', 'user.name', 'Debt regression')
        self.git('config', 'user.email', 'regression@example.invalid')
        self.write('src/a.py', f'# {MARKER}\n')
        self.write('scripts/debt-ratchets/todo-markers.baseline', '1 = src/a.py\n')
        self.write('scripts/debt-ratchets/dead-code-allows.baseline', '')
        self.base = self.commit()

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME='Debt regression',
                   GIT_COMMITTER_NAME='Debt regression',
                   GIT_AUTHOR_EMAIL='regression@example.invalid',
                   GIT_COMMITTER_EMAIL='regression@example.invalid')
        result = subprocess.run(['git', *args], cwd=self.root,
                                env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def commit(self):
        self.git('add', '.')
        self.git('commit', '--allow-empty', '-m', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def run_ci(self, event_name='push', event=None, sha=None, extra=()):
        head = self.git('rev-parse', 'HEAD')
        if event is None:
            event = {'before': self.base, 'after': head}
        event.setdefault('repository', {'full_name': REPOSITORY})
        self.event_path.write_text(json.dumps(event), encoding='utf-8')
        env = dict(os.environ, GITHUB_EVENT_NAME=event_name,
                   GITHUB_EVENT_PATH=str(self.event_path), GITHUB_SHA=sha or head,
                   GITHUB_REPOSITORY=REPOSITORY, GITHUB_ACTIONS='true')
        # Exercise the workflow's executable command, including its selected mode.
        workflow = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        command = re.search(r'- name: Debt ratchet \(gating\)\s+run: ([^\n]+)', workflow)
        self.assertIsNotNone(command)
        argv = shlex.split(command.group(1))
        return subprocess.run([sys.executable, str(ROOT / argv[1]), *argv[2:],
                               '--root', str(self.root), *extra], env=env,
                              capture_output=True, text=True, timeout=60)

    def assert_exit(self, result, expected):
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_candidate_debt_and_floor_increase_is_rejected(self):
        self.write('src/a.py', f'# {MARKER}\n# {MARKER}\n')
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        self.commit()
        result = self.run_ci()
        self.assert_exit(result, 1)
        self.assertIn('ratchet todo-markers: fail', result.stdout)

    def test_floor_increase_without_current_debt_is_rejected(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        self.commit()
        self.assert_exit(self.run_ci(), 1)

    def test_unchanged_and_lowered_floors_pass(self):
        head = self.commit()
        self.assert_exit(self.run_ci(), 0)
        self.assert_exit(self.run_ci('merge_group', {
            'merge_group': {'base_sha': self.base, 'head_sha': head}}), 0)
        self.assert_exit(self.run_ci('workflow_dispatch', {}), 0)
        self.write('src/a.py', '# clean\n')
        self.write('scripts/debt-ratchets/todo-markers.baseline', '')
        self.commit()
        self.assert_exit(self.run_ci(), 0)

    def test_lowered_floor_still_bounds_actual_debt(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '')
        self.commit()
        self.assert_exit(self.run_ci(), 1)

    def test_unverifiable_identity_fails_closed(self):
        head = self.commit()
        events = [
            {'before': '0' * 40, 'after': head},
            {'before': 'f' * 40, 'after': head},
            {'before': 'main', 'after': head},
            {'before': self.base, 'after': self.base},
            {'before': self.base, 'after': head, 'repository': {'full_name': 'other/repo'}},
            {},
        ]
        for event in events:
            with self.subTest(event=event):
                self.assert_exit(self.run_ci(event=event), 4)
        self.assert_exit(self.run_ci(sha=self.base), 4)
        self.assert_exit(self.run_ci(event_name='unknown'), 4)

    def test_missing_base_and_candidate_baselines_fail_closed(self):
        path = self.root / 'scripts/debt-ratchets/todo-markers.baseline'
        path.unlink()
        self.base = self.commit()
        self.write('scripts/debt-ratchets/todo-markers.baseline', '1 = src/a.py\n')
        self.commit()
        self.assert_exit(self.run_ci(), 4)
        self.base = self.git('rev-parse', 'HEAD')
        path.unlink()
        self.commit()
        self.assert_exit(self.run_ci(), 4)

    def test_ci_cannot_seed_or_refresh(self):
        self.commit()
        self.assert_exit(self.run_ci(extra=('--refresh',)), 2)
        self.assert_exit(self.run_ci(extra=('--baseline-dir', str(self.root))), 2)

    def test_other_ratchet_cannot_add_a_positive_floor_for_a_new_file(self):
        self.write('scripts/debt-ratchets/dead-code-allows.baseline', '1 = src/new.rs\n')
        self.commit()
        self.assert_exit(self.run_ci(), 1)

    def test_missing_or_malformed_event_is_configuration_failure(self):
        self.commit()
        self.assert_exit(self.run_ci(event={'repository': None}), 4)
        self.assert_exit(self.run_ci('pull_request', {}), 4)
        self.assert_exit(self.run_ci('merge_group', {}), 4)

    def test_nonancestor_base_is_not_a_valid_prior_floor(self):
        self.git('checkout', '--orphan', 'unrelated')
        # Distinct tree prevents two root fixtures hashing to the same commit
        # when fast Linux execution gives them identical second-resolution dates.
        self.write('src/unrelated.py', '# unrelated root\n')
        unrelated = self.commit()
        self.assertNotEqual(unrelated, self.base)
        self.git('checkout', 'main')
        head = self.commit()
        self.assert_exit(self.run_ci(event={'before': unrelated, 'after': head}), 4)

    def test_unchanged_pr_merge_passes(self):
        self.git('checkout', '-b', 'candidate')
        self.write('src/clean.py', '# clean\n')
        candidate = self.commit()
        self.git('checkout', 'main')
        base = self.commit()
        self.git('merge', '--no-ff', 'candidate', '-m', 'merge fixture')
        event = {'pull_request': {'base': {'sha': base, 'repo': {'full_name': REPOSITORY}},
                                  'head': {'sha': candidate}}}
        self.assert_exit(self.run_ci('pull_request', event), 0)

    def test_merge_group_and_manual_dispatch_use_prior_floor(self):
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        head = self.commit()
        event = {'merge_group': {'base_sha': self.base, 'head_sha': head}}
        self.assert_exit(self.run_ci('merge_group', event), 1)
        self.assert_exit(self.run_ci('workflow_dispatch', {}), 1)

    def test_pr_merge_uses_event_base_and_validates_parents(self):
        self.git('checkout', '-b', 'candidate')
        self.write('src/a.py', f'# {MARKER}\n# {MARKER}\n')
        self.write('scripts/debt-ratchets/todo-markers.baseline', '2 = src/a.py\n')
        candidate = self.commit()
        self.git('checkout', 'main')
        base = self.commit()
        self.git('merge', '--no-ff', 'candidate', '-m', 'merge fixture')
        event = {'pull_request': {'base': {'sha': base, 'repo': {'full_name': REPOSITORY}},
                                  'head': {'sha': candidate}}}
        self.assert_exit(self.run_ci('pull_request', event), 1)
        event['pull_request']['base']['sha'] = self.base
        refused = self.run_ci('pull_request', event)
        self.assert_exit(refused, 1)
        self.assertIn(f'Verified debt base: {base}', refused.stdout)
        event['pull_request']['head']['sha'] = self.base
        refused = self.run_ci('pull_request', event)
        self.assert_exit(refused, 4)
        self.assertIn(f'event base/head={self.base} {self.base}', refused.stderr)
        self.assertIn(f'actual parents={base} {candidate}', refused.stderr)
        self.assertIn(f'checkout={self.git("rev-parse", "HEAD")}', refused.stderr)

    def advanced_merge(self, tighten=False):
        self.git('checkout', '-b', 'candidate')
        self.write('src/clean.py', '# clean candidate\n')
        candidate = self.commit()
        self.git('checkout', 'main')
        if tighten:
            self.write('src/a.py', '# cleaned base\n')
            self.write('scripts/debt-ratchets/todo-markers.baseline', '')
        else:
            self.write('src/base.py', '# advanced base\n')
        base = self.commit()
        # Construct a real two-parent merge with the candidate tree. This also
        # exercises a merge resolution that tries to retain the old debt floor.
        merge = self.git('commit-tree', candidate + '^{tree}', '-p', base,
                         '-p', candidate, '-m', 'synthetic PR merge')
        self.git('checkout', '--detach', merge)
        event = {'pull_request': {
            'base': {'sha': self.base, 'repo': {'full_name': REPOSITORY}},
            'head': {'sha': candidate}}}
        return event, base, candidate, merge

    def test_advanced_base_clean_merge_passes(self):
        event, base, _, _ = self.advanced_merge()
        result = self.run_ci('pull_request', event)
        self.assert_exit(result, 0)
        self.assertIn(f'Verified debt base: {base}', result.stdout)
        self.assertIn(f'event={self.base}; merge={base}', result.stdout)

    def test_advanced_base_uses_tightened_actual_floor(self):
        event, base, _, _ = self.advanced_merge(tighten=True)
        result = self.run_ci('pull_request', event)
        self.assert_exit(result, 1)
        self.assertIn(f'Verified debt base: {base}', result.stdout)
        self.assertIn('ratchet todo-markers: fail', result.stdout)

    def test_advanced_base_rejects_unrelated_event_base(self):
        event, _, _, merge = self.advanced_merge()
        self.git('checkout', '--orphan', 'unrelated')
        self.write('src/unrelated.py', '# unrelated root\n')
        unrelated = self.commit()
        self.git('checkout', '--detach', merge)
        event['pull_request']['base']['sha'] = unrelated
        self.assert_exit(self.run_ci('pull_request', event), 4)

    def test_advanced_base_rejects_reversed_parents(self):
        event, base, candidate, _ = self.advanced_merge()
        reversed_merge = self.git('commit-tree', candidate + '^{tree}',
                                  '-p', candidate, '-p', base,
                                  '-m', 'reversed PR merge')
        self.git('checkout', '--detach', reversed_merge)
        self.assert_exit(self.run_ci('pull_request', event), 4)

    def test_advanced_base_rejects_nonmerge_checkout(self):
        event, _, candidate, _ = self.advanced_merge()
        self.git('checkout', '--detach', candidate)
        self.assert_exit(self.run_ci('pull_request', event), 4)

    def test_advanced_base_rejects_event_base_descendant(self):
        event, _, _, merge = self.advanced_merge()
        event['pull_request']['base']['sha'] = merge
        self.assert_exit(self.run_ci('pull_request', event), 4)

    def test_advanced_base_rejects_three_parents(self):
        event, base, candidate, _ = self.advanced_merge()
        merge = self.git('commit-tree', candidate + '^{tree}', '-p', base,
                         '-p', candidate, '-p', self.base, '-m', 'three parents')
        self.git('checkout', '--detach', merge)
        self.assert_exit(self.run_ci('pull_request', event), 4)

    def test_advanced_base_rejects_duplicate_source_parents(self):
        event, _, candidate, _ = self.advanced_merge()
        tree = self.git('rev-parse', candidate + '^{tree}')
        commit_file = self.root / '.git/duplicate-parent-commit'
        commit_file.write_text(
            f'tree {tree}\nparent {candidate}\nparent {candidate}\n'
            'author Debt regression <regression@example.invalid> 1 +0000\n'
            'committer Debt regression <regression@example.invalid> 1 +0000\n'
            '\nduplicate source parents\n', encoding='utf-8')
        merge = self.git('hash-object', '-t', 'commit', '-w', str(commit_file))
        self.git('checkout', '--detach', merge)
        self.assertEqual(self.git('show', '-s', '--format=%P', merge).split(),
                         [candidate, candidate])
        self.assert_exit(self.run_ci('pull_request', event), 4)


if __name__ == '__main__':
    unittest.main()

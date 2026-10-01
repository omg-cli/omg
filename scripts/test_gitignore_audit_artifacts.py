"""The checkout's audit export ignore rule must work without ambient Git state."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUN_ARTIFACT = '.audit/run-36304589368-ubuntu/export-report.json'
AUDIT_RECORD = '.audit/deep-audit.tsv'


def git(*args, root=ROOT, inherited=None):
    environment = dict(os.environ if inherited is None else inherited)
    environment = {key: value for key, value in environment.items()
                   if not key.upper().startswith('GIT_')}
    environment.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')
    return subprocess.run(
        ['git', '-c', 'core.excludesFile=' + os.devnull,
         '-c', 'core.hooksPath=' + os.devnull, '-c', 'maintenance.auto=false',
         '-c', 'gc.auto=0', '-C', str(root), *args],
        env=environment, capture_output=True, text=True, timeout=30)


class GitignoreAuditArtifacts(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='omg-ignore-')
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name)
        result = git('init', root=self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Only the checkout rule is admitted, not .git/info/exclude or global
        # excludes. Never initialize or write Git metadata in the real checkout.
        (self.repo / '.gitignore').write_bytes((ROOT / '.gitignore').read_bytes())
        for path, content in [(RUN_ARTIFACT, '{}\n'), (AUDIT_RECORD, 'audit\n')]:
            target = self.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding='utf-8')

    def ignored(self, path, inherited=None):
        return git('check-ignore', '--no-index', '-v', path,
                   root=self.repo, inherited=inherited)

    def test_run_artifact_directory_is_ignored(self):
        result = self.ignored(RUN_ARTIFACT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        origin, path = result.stdout.strip().split('\t')
        self.assertEqual(path, RUN_ARTIFACT)
        source, _line, pattern = origin.split(':', 2)
        self.assertEqual(source, '.gitignore')
        self.assertEqual(pattern, '/.audit/run-*/')

    def test_audit_record_is_not_ignored(self):
        result = git('check-ignore', '--no-index', AUDIT_RECORD, root=self.repo)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_audit_record_is_tracked(self):
        tracked = git('ls-files', '--', AUDIT_RECORD)
        self.assertEqual(tracked.returncode, 0, tracked.stdout + tracked.stderr)
        self.assertEqual(tracked.stdout.strip(), AUDIT_RECORD)

    def test_run_directory_is_absent_from_status(self):
        result = git('status', '--porcelain', '--untracked-files=all', '--', '.audit',
                     root=self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('run-', result.stdout, result.stdout)
        self.assertEqual(result.stdout.strip(), '?? ' + AUDIT_RECORD)
        added = git('add', '--', AUDIT_RECORD, root=self.repo)
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        result = git('status', '--porcelain', '--untracked-files=all', '--', '.audit',
                     root=self.repo)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'A  ' + AUDIT_RECORD)

    def test_ambient_selectors_and_excludes_cannot_supply_missing_rule(self):
        # Synthetic poison points at a nonexistent repository and an exclude
        # file that would conceal removal of the checkout's run rule.
        exclude = self.repo / 'ambient-excludes'
        exclude.write_text('.audit/\n', encoding='utf-8')
        environment = dict(os.environ)
        environment.update(GIT_DIR=str(self.repo / 'foreign.git'),
                           GIT_WORK_TREE=str(self.repo / 'foreign-tree'),
                           GIT_INDEX_FILE=str(self.repo / 'foreign-index'),
                           GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='core.excludesFile',
                           GIT_CONFIG_VALUE_0=str(exclude),
                           GIT_CONFIG_PARAMETERS="'core.excludesFile=" + str(exclude) + "'")
        rule = self.repo / '.gitignore'
        rule.write_text(rule.read_text(encoding='utf-8').replace('/.audit/run-*/', ''),
                        encoding='utf-8')
        result = self.ignored(RUN_ARTIFACT, environment)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertFalse((self.repo / 'foreign-index').exists())

    def test_broad_rule_is_detected_even_for_tracked_audit_record(self):
        added = git('add', '--', AUDIT_RECORD, root=self.repo)
        self.assertEqual(added.returncode, 0, added.stdout + added.stderr)
        with (self.repo / '.gitignore').open('a', encoding='utf-8') as rules:
            rules.write('\n/.audit/\n')
        result = self.ignored(AUDIT_RECORD)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('/.audit/', result.stdout)


if __name__ == '__main__':
    unittest.main()

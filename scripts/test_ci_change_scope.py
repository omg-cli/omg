import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

spec = importlib.util.spec_from_file_location('ci_scope', Path(__file__).with_name('ci-change-scope.py'))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def test_coverage_aggregate_rejects_missing_failed_or_cancelled_work(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/coverage.yml').read_text(encoding='utf-8')
        block = workflow.split('      - name: Require selected coverage\n')[1]
        script = textwrap.dedent(block.split('        run: |\n')[1])
        bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
        with tempfile.TemporaryDirectory() as directory:
            for classification, required, coverage, passes in [
                ('success', 'true', 'success', True),
                ('success', 'false', 'skipped', True),
                ('failure', 'false', 'skipped', False),
                ('cancelled', 'true', 'success', False),
                ('success', '', 'skipped', False),
                ('success', 'true', 'skipped', False),
                ('success', 'true', 'failure', False),
                ('success', 'true', 'cancelled', False),
            ]:
                with self.subTest(classification=classification, required=required, coverage=coverage):
                    result = subprocess.run([bash, '-c', script], env=dict(os.environ,
                        CLASSIFICATION=classification, REQUIRED=required, COVERAGE=coverage,
                        GITHUB_STEP_SUMMARY=(Path(directory) / 'summary').as_posix()),
                        capture_output=True, timeout=10)
                    self.assertEqual(result.returncode == 0, passes)

    def test_allowlist_and_unknown_paths(self):
        self.assertTrue(scope.documentation_only(['README.md', 'docs/nested/a.md']))
        for paths in ([], ['src/a.rs'], ['docs/example.sh'], ['AGENTS.md'],
                      ['SECURITY.md'], ['README.md', 'Cargo.lock'], ['docs/../src/a.md']):
            with self.subTest(paths=paths):
                self.assertFalse(scope.documentation_only(paths))

        self.assertTrue(scope.coverage_irrelevant([
            '.github/workflows/qemu-lane.yml',
            '.github/workflows/qemu-report.yml',
            'scripts/qemu-daemon-check.sh',
            'scripts/ci-smoke-report.py',
            'scripts/export-qemu-evidence.py',
            'scripts/qemu-backend-mismatch.py',
            'scripts/report-qemu-workflow.py',
            'scripts/test_ci_smoke_report.py',
            'scripts/test_export_qemu_evidence.py',
            'scripts/test_qemu_runner_isolation.py',
            'tests/qemu-inventory-policy.json',
            'tests/qemu-inventory-policy.d/' + 'a' * 64 + '.json',
            'docs/local-ci-runner.md',
        ]))
        for paths in ([], ['src/cli/args.rs'], ['tests/fedora_tests.rs'],
                      ['tests/cli_behavior_inventory.tsv'],
                      ['Cargo.lock'], ['.github/workflows/coverage.yml'],
                      ['scripts/ci-change-scope.py'],
                      ['scripts/qemu-inventory.rs'],
                      ['scripts/qemu-fixture/../src/fake.sh'],
                      ['scripts/qemu-daemon-check.sh', 'src/cli/args.rs']):
            with self.subTest(paths=paths):
                self.assertFalse(scope.coverage_irrelevant(paths))

    def test_non_pr_events_always_build(self):
        for event in ('push', 'merge_group', 'schedule', 'workflow_dispatch', 'unknown'):
            self.assertTrue(scope.requires_build(event, {}))
            self.assertEqual(scope.classify_scope(event, {}), (True, True))

    def test_malformed_identity_fails(self):
        with self.assertRaises(ValueError):
            scope.requires_build('pull_request', {'pull_request': {
                'base': {'sha': '--help'}, 'head': {'sha': 'a' * 40}}})

    def test_real_git_renames_deletions_and_missing_commits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Test', '-c',
                    'user.email=test@example.invalid', *args], cwd=root).decode().strip()
            git('init', '-q')
            (root / 'source.rs').write_text('source')
            (root / 'README.md').write_text('old')
            git('add', '.')
            git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')
            (root / 'README.md').write_text('new')
            git('commit', '-qam', 'docs')
            def event(head):
                return {'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}
            self.assertFalse(scope.requires_build('pull_request', event(git('rev-parse', 'HEAD')), root))
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (False, False))
            (root / 'scripts').mkdir()
            (root / 'scripts/qemu-daemon-check.sh').write_text('test harness')
            git('add', '.')
            git('commit', '-qm', 'QEMU harness')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, False))
            (root / '.github/workflows').mkdir(parents=True)
            (root / 'tests').mkdir()
            (root / '.github/workflows/qemu-report.yml').write_text('reporter')
            (root / 'tests/qemu-inventory-policy.json').write_text('{}')
            git('add', '.')
            git('commit', '-qm', 'QEMU reporter and policy')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, False))
            (root / 'tests/cli_behavior_inventory.tsv').write_text('behavior')
            git('add', '.')
            git('commit', '-qm', 'Rust-consumed inventory')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, True))
            (root / 'docs').mkdir()
            git('mv', 'source.rs', 'docs/renamed.md')
            git('commit', '-qm', 'rename code')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, True))
            with self.assertRaises(subprocess.CalledProcessError):
                scope.requires_build('pull_request', event('f' * 40), root)

    def test_real_git_sentry_reporting_paths_do_not_require_rust_instrumentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Test', '-c',
                    'user.email=test@example.invalid', *args], cwd=root).decode().strip()

            git('init', '-q')
            (root / 'scripts').mkdir()
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_text('pub fn value() -> u8 { 1 }\n')
            git('add', '.')
            git('commit', '-qm', 'base')
            base = git('rev-parse', 'HEAD')

            (root / 'scripts/ci-smoke-report.py').write_text('print("report")\n')
            (root / 'scripts/test_ci_smoke_report.py').write_text('print("test")\n')
            git('add', '.')
            git('commit', '-qm', 'reporter tests')
            def event():
                return {'pull_request': {'base': {'sha': base},
                                         'head': {'sha': git('rev-parse', 'HEAD')}}}
            self.assertEqual(scope.classify_scope('pull_request', event(), root), (True, False))

            (root / 'src/lib.rs').write_text('pub fn value() -> u8 { 2 }\n')
            git('commit', '-qam', 'Rust change')
            self.assertEqual(scope.classify_scope('pull_request', event(), root), (True, True))


if __name__ == '__main__':
    unittest.main()

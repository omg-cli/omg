import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ci_scope', Path(__file__).with_name('ci-change-scope.py'))
scope = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scope)


class ScopeTests(unittest.TestCase):
    def test_portable_mutation_baseline_covers_existing_pr_paths(self):
        selected = (
            'tests/exhaustive_cli_matrix.rs', 'tests/integration_suite.rs',
            'tests/property_tests.rs', 'tests/property_tests.proptest-regressions',
            'tests/metrics_tests.rs', 'tests/security_tests.rs',
            'src/cli/tea/status_model.rs', 'tests/coverage_15.rs',
            'tests/coverage_4.rs', 'tests/coverage_5.rs', 'tests/common/nested/mod.rs',
            'src/core/archive.rs', 'src/core/runtime_resolver.rs', 'src/core/http.rs',
            'src/core/security/nested/example.rs', 'scripts/check-mutation-results.py',
            'scripts/test_mutation_reports.py', 'scripts/observe-mutation-runner.py',
            'scripts/test_mutation_runner_observer.py', 'scripts/test_mutation_build_budget.py',
            '.github/workflows/mutation.yml',
        )
        for path in selected:
            with self.subTest(path=path), patch.object(scope, 'changed_paths', return_value=[path]):
                self.assertEqual(scope.classify_scope('pull_request', {}), (True, True, True))
        for path, build in [('docs/notes.md', False), ('src/core/security.rs', True),
                            ('tests/commonplace.rs', True), ('src/package_managers/dnf.rs', True)]:
            with self.subTest(path=path), patch.object(scope, 'changed_paths', return_value=[path]):
                self.assertEqual(scope.classify_scope('pull_request', {}), (build, build, False))

    def test_coverage_aggregate_rejects_missing_failed_or_cancelled_work(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/coverage.yml').read_text(encoding='utf-8')
        block = workflow.split('      - name: Require selected coverage\n')[1]
        script = textwrap.dedent(block.split('        run: |\n')[1].split('\n      - ', 1)[0])
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
            self.assertEqual(scope.classify_scope(event, {}), (True, True, False))

    def test_distro_push_requires_native_inputs_and_defaults_to_running(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Test', '-c',
                    'user.email=test@example.invalid', *args], cwd=root, text=True).strip()

            def commit(message):
                git('add', '-A')
                git('commit', '-qm', message)
                return git('rev-parse', 'HEAD')

            git('init', '-q')
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_text('pub const VALUE: u8 = 1;\n')
            base = commit('native source')
            cloud = root / 'services/advisories/wrangler.jsonc'
            cloud.parent.mkdir(parents=True)
            cloud.write_text('{}\n')
            (root / 'README.md').write_text('Updated docs\n')
            service_head = commit('advisory service and docs')
            event = {'before': base, 'after': service_head}
            self.assertFalse(scope.distro_e2e_required('push', event, root))
            self.assertTrue(scope.requires_build('push', event, root))
            for name in ('pull_request', 'merge_group', 'schedule', 'workflow_dispatch'):
                with self.subTest(event=name):
                    self.assertTrue(scope.distro_e2e_required(name, event, root))
            for before in (base[:8], 'f' * 40, '0' * 40, service_head, None):
                with self.subTest(before=before):
                    self.assertTrue(scope.distro_e2e_required('push', {'before': before, 'after': service_head}, root))
            docs = root / 'docs'
            docs.mkdir()
            for index in range(301):
                (docs / f'{index:03}.md').write_text('Docs\n')
            git('mv', 'src/lib.rs', 'docs/moved.md')
            moved = commit('move native source into docs')
            self.assertTrue(scope.distro_e2e_required('push', {'before': service_head, 'after': moved}, root))

    def test_distro_workflow_only_skips_after_successful_push_classification(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/distro-e2e.yml').read_text()
        classifier = workflow.split('\n  scope:\n', 1)[1].split('\n  container-e2e:\n', 1)[0]
        self.assertIn("if: github.event_name == 'push'", classifier)
        self.assertIn('python3 scripts/ci-change-scope.py --distro-e2e', classifier)
        for job in ('container-e2e', 'systemd-daemon-e2e'):
            header = workflow.split(f'\n  {job}:\n', 1)[1].split('    steps:\n', 1)[0]
            self.assertIn('needs: scope', header)
            self.assertIn("!cancelled() && (needs.scope.result != 'success' || needs.scope.outputs.required != 'false')", header)

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
                event(git('rev-parse', 'HEAD')), root), (False, False, False))
            (root / 'scripts').mkdir()
            (root / 'scripts/qemu-daemon-check.sh').write_text('test harness')
            git('add', '.')
            git('commit', '-qm', 'QEMU harness')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, False, False))
            (root / '.github/workflows').mkdir(parents=True)
            (root / 'tests').mkdir()
            (root / '.github/workflows/qemu-report.yml').write_text('reporter')
            (root / 'tests/qemu-inventory-policy.json').write_text('{}')
            git('add', '.')
            git('commit', '-qm', 'QEMU reporter and policy')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, False, False))
            (root / 'tests/cli_behavior_inventory.tsv').write_text('behavior')
            git('add', '.')
            git('commit', '-qm', 'Rust-consumed inventory')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, True, False))
            (root / 'docs').mkdir()
            git('mv', 'source.rs', 'docs/renamed.md')
            git('commit', '-qm', 'rename code')
            self.assertEqual(scope.classify_scope('pull_request',
                event(git('rev-parse', 'HEAD')), root), (True, True, False))
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
            self.assertEqual(scope.classify_scope('pull_request', event(), root), (True, False, False))

            (root / 'src/lib.rs').write_text('pub fn value() -> u8 { 2 }\n')
            git('commit', '-qam', 'Rust change')
            self.assertEqual(scope.classify_scope('pull_request', event(), root), (True, True, False))


if __name__ == '__main__':
    unittest.main()

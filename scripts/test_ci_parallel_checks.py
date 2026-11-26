"""Keep expensive workflow checks required without serializing native builds."""
import unittest

from test_ci_gates import CI_YML, job_block
import test_ci_required_results


class ParallelChecksTests(unittest.TestCase):
    def test_portable_checks_the_locked_fuzz_graph_before_application_compiles(self):
        portable = job_block(CI_YML.read_text(encoding='utf-8'), 'portable')
        fuzz = 'cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked'
        self.assertEqual(portable.count(fuzz), 1)
        self.assertLess(portable.index(fuzz), portable.index('cargo clippy'))
        self.assertLess(portable.index(fuzz), portable.index('cargo test'))

    def test_standalone_suites_share_the_required_mac_runtime_runner(self):
        source = CI_YML.read_text(encoding='utf-8')
        linux = job_block(source, 'standalone-suites')
        mac = job_block(source, 'macos')
        self.assertIn('runs-on: ubuntu-24.04', linux)
        self.assertNotIn('macos-15', linux)
        self.assertIn('runs-on: macos-15', mac)
        for manifest in ('tests/mise-compat/Cargo.toml', 'tests/env-portable/Cargo.toml'):
            command = f'run: cargo test --manifest-path {manifest} --locked'
            for job in (linux, mac):
                self.assertEqual(job.count(command), 1)
        final = job_block(source, 'ci-success')
        self.assertIn('STANDALONE_SUITES: ${{ needs.standalone-suites.result }}', final)
        self.assertIn('MACOS: ${{ needs.macos.result }}', final)

    def test_platform_prerequisite_only_classifies_changes(self):
        source = CI_YML.read_text(encoding='utf-8')
        gate = job_block(source, 'quick-gate')
        self.assertIn('python3 scripts/ci-change-scope.py', gate)
        self.assertNotIn('test_ci_change_scope.py', gate)
        self.assertNotIn('make ci-workflow-quick', gate)
        self.assertNotIn('rust-toolchain@', gate)
        checks = job_block(source, 'workflow-checks')
        for command in ('make ci-workflow-static', 'scripts/workflow-helpers.py run --shard', 'scripts/debt-ratchet.py --ci',
                        'bash tests/installer_security.sh', 'run: cargo-machete'):
            self.assertIn(command, checks)
        docs_steps = [step for step in checks.split('\n      - name:') if 'test_ci_change_scope.py' in step]
        self.assertEqual(len(docs_steps), 1)
        docs = docs_steps[0]
        self.assertIn("matrix.shard == 0", docs)
        self.assertIn("github.event_name != 'push'", docs)
        self.assertIn("checks-required != 'true'", docs)
        self.assertIn('test_ci_change_scope.py', docs)
        for job in ('portable', 'linux-matrix', 'ubuntu', 'macos', 'standalone-suites'):
            header = job_block(source, job).split('    steps:', 1)[0]
            self.assertNotIn('workflow-checks', header)
        final = job_block(source, 'ci-success')
        self.assertIn('workflow-checks', final.split('    steps:', 1)[0])
        self.assertIn('WORKFLOW_CHECKS: ${{ needs.workflow-checks.result }}', final)
        self.assertIn('workflow-helpers.py admit --current-run', final)

    def test_workflow_checks_cannot_be_skipped_or_failed_even_on_docs(self):
        evaluator = test_ci_required_results.RequiredResultsTests()
        for required in ('true', 'false'):
            for state in ('failure', 'cancelled', 'skipped', '', None):
                with self.subTest(required=required, state=state):
                    result = evaluator.evaluate(required, {'WORKFLOW_CHECKS': state})
                    self.assertNotEqual(result.returncode, 0)
            self.assertEqual(evaluator.evaluate(required, {'WORKFLOW_CHECKS': 'success'}).returncode, 0)


if __name__ == '__main__':
    unittest.main()

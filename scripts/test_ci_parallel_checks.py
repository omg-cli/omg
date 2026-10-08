"""Keep expensive workflow checks required without serializing native builds."""
import unittest

from test_ci_gates import CI_YML, job_block
import test_ci_required_results


class ParallelChecksTests(unittest.TestCase):
    def test_platform_prerequisite_only_classifies_changes(self):
        source = CI_YML.read_text(encoding='utf-8')
        gate = job_block(source, 'quick-gate')
        self.assertIn('python3 scripts/ci-change-scope.py', gate)
        self.assertIn('test_ci_change_scope.py', gate)
        self.assertNotIn('make ci-workflow-quick', gate)
        self.assertNotIn('rust-toolchain@', gate)
        checks = job_block(source, 'workflow-checks')
        for command in ('make ci-workflow-quick', 'scripts/debt-ratchet.py --ci',
                        'bash tests/installer_security.sh', 'run: cargo-machete'):
            self.assertIn(command, checks)
        for job in ('portable', 'linux-matrix', 'ubuntu', 'macos', 'standalone-suites'):
            header = job_block(source, job).split('    steps:', 1)[0]
            self.assertNotIn('workflow-checks', header)
        final = job_block(source, 'ci-success')
        self.assertIn('workflow-checks', final.split('    steps:', 1)[0])
        self.assertIn('WORKFLOW_CHECKS: ${{ needs.workflow-checks.result }}', final)

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

"""Require scheduler dependencies instead of racing native producer runners."""
from pathlib import Path
import os
import re
import subprocess
import unittest

from test_ci_gates import job_block
from test_release_workflow_boundaries import BASH, step_script

ROOT = Path(__file__).resolve().parents[1]


class QemuProducerDependency(unittest.TestCase):
    def test_release_uses_integrated_ci_gate_without_external_qemu_wait(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        release = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
        self.assertFalse('require-workflow-success.sh qemu-matrix.yml' in ci + release,
                         'release must not wait for a removed automatic workflow')
        self.assertRegex(job_block(ci, 'release-tag'), r'needs: \[[^\]]*\bci-success\b')
        self.assertIn('require-workflow-success.sh ci.yml', release)

    def test_required_guest_failures_and_skips_fail_the_executed_ci_gate(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        script = step_script(job_block(ci, 'ci-success'), 'Evaluate results')
        start = script.index('if [[ "$QEMU_REQUIRED"')
        end = re.search(r'\n\s*fi\b', script[start:])
        self.assertIsNotNone(end)
        guard = script[start:start + end.end()]
        for required in ('true', 'false'):
            for outcome in ('success', 'failure', 'cancelled', 'skipped', ''):
                with self.subTest(required=required, outcome=outcome):
                    result = subprocess.run([BASH, '-eu', '-c', guard],
                        env=dict(os.environ, QEMU_REQUIRED=required, QEMU=outcome),
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0,
                                     required == 'false' or outcome == 'success')

    def test_automatic_guests_wait_for_both_native_producer_jobs(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertTrue('\n  qemu:\n' in ci,
                      'automatic QEMU must be scheduled by its native producer workflow')
        qemu = job_block(ci, 'qemu')
        needs = re.search(r'^    needs: \[([^]]+)\]', qemu, re.MULTILINE)
        self.assertIsNotNone(needs)
        self.assertTrue({'linux-matrix', 'ubuntu'} <=
                        {item.strip() for item in needs.group(1).split(',')})
        self.assertIn('uses: ./.github/workflows/qemu-matrix.yml', qemu)
        final = job_block(ci, 'ci-success')
        self.assertRegex(final, r'needs: \[[^\]]*\bqemu\b')

    def test_reusable_guests_do_not_start_a_second_automatic_workflow(self):
        matrix = (ROOT / '.github/workflows/qemu-matrix.yml').read_text(encoding='utf-8')
        triggers = matrix.split('\non:\n', 1)[1].split('\nconcurrency:', 1)[0]
        self.assertTrue('\n  workflow_call:' in '\n' + triggers,
                        'QEMU matrix must expose a reusable workflow entry point')
        self.assertNotRegex(triggers, r'(?m)^  (push|pull_request):')
        self.assertIn('  schedule:', triggers)
        self.assertIn('  workflow_dispatch:', triggers)
        self.assertNotIn('Wait once for native release artifacts', matrix)


if __name__ == '__main__':
    unittest.main()

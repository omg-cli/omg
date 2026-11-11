"""Require scheduler dependencies instead of racing native producer runners."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_ci_gates import job_block
from test_release_workflow_boundaries import BASH, step_script

ROOT = Path(__file__).resolve().parents[1]


class QemuProducerDependency(unittest.TestCase):
    def test_guest_readiness_is_independent_of_linux_clippy_completion(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        native = job_block(ci, 'linux-matrix')
        phases = re.search(r'^        phase: \[([^]]+)\]', native, re.MULTILINE)
        self.assertIsNotNone(phases)
        self.assertEqual(phases.group(1).split(', '), ['validation'])
        clippy = job_block(ci, 'linux-clippy')
        self.assertIn('needs: [quick-gate, linux-matrix]', clippy)
        self.assertIn('!cancelled()', clippy)
        self.assertNotIn('needs.linux-matrix.result', clippy)
        self.assertIn('      max-parallel: 5\n', clippy)
        self.assertNotIn('linux-clippy', job_block(ci, 'qemu').split('    steps:', 1)[0])
        self.assertIn('linux-clippy', job_block(ci, 'ci-success').split('    steps:', 1)[0])

    def test_failed_or_missing_linux_clippy_cannot_pass_final_admission(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        script = step_script(job_block(ci, 'ci-success'), 'Evaluate results')
        results = dict(QUICK_GATE='success', WORKFLOW_CHECKS='success', BUILD_REQUIRED='true',
                       STANDALONE_SUITES='success', PORTABLE='success', PORTABLE_RELEASE='success',
                       LINUX_MATRIX='success',
                       FEDORA_SQLITE='success', SANDBOX_CANCELLATION='success',
                       FEATURE_INTERSECTIONS='success', MACOS='success', MACOS_NEXTEST_SOURCE='success',
                       UBUNTU='success', RUNTIME_USAGE='success', QEMU='success',
                       QEMU_REQUIRED='true', DOCS_AUDIT='success')
        for state in ('success', 'failure', 'cancelled', 'skipped', ''):
            with self.subTest(clippy=state), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([BASH, '-eu', '-c', script],
                    env=dict(os.environ, **results, LINUX_CLIPPY=state,
                             GITHUB_STEP_SUMMARY=str(Path(directory) / 'summary')),
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, state == 'success', result.stdout + result.stderr)

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

    def test_preflight_runs_alongside_producers_and_guests_require_its_success(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        preflight = job_block(ci, 'qemu-preflight')
        guests = job_block(ci, 'qemu')
        self.assertRegex(preflight, r'(?m)^    needs: quick-gate$')
        self.assertIn('uses: ./.github/actions/qemu-preflight', preflight)
        self.assertIn('ref: ${{ github.sha }}', preflight)
        self.assertIn('persist-credentials: false', preflight)
        self.assertIn('qemu-preflight', re.search(r'(?m)^    needs: \[([^]]+)\]$', guests)[1].split(', '))
        self.assertIn('preflight-complete: true', guests)
        condition = re.search(r'^    if: >-\n((?:      .*\n)+)', guests, re.MULTILINE)[1]
        expression = ' '.join(condition.split())
        for result, cancelled in (('success', False), ('failure', False), ('cancelled', False),
                                  ('skipped', False), ('success', True)):
            with self.subTest(preflight=result, cancelled=cancelled):
                check = expression.replace('needs.qemu-preflight.result', repr(result)).replace(
                    '!cancelled()', '0 == 1' if cancelled else '0 == 0')
                result_code = subprocess.run([BASH, '-c', '[[ ' + check + ' ]]'], timeout=10).returncode
                self.assertEqual(result_code, 0 if result == 'success' and not cancelled else 1)

    def test_native_failure_still_schedules_guests_after_a_successful_quick_gate(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        qemu = job_block(ci, 'qemu')
        self.assertIn('needs: [qemu-preflight, linux-matrix, ubuntu, fedora-sqlite]', qemu)
        self.assertIn('!cancelled()', qemu)
        self.assertNotIn('needs.linux-matrix.result', qemu)
        self.assertNotIn('needs.ubuntu.result', qemu)
        preflight = job_block(ci, 'qemu-preflight')
        condition = re.search(r'^    if: >-\n((?:      .*\n)+)', preflight, re.MULTILINE)
        self.assertIsNotNone(condition)
        expression = condition.group(1)
        self.assertIn("needs.quick-gate.result == 'success'", expression)
        self.assertIn("needs.quick-gate.outputs.should-build == 'true'", expression)
        self.assertIn("github.event_name == 'push'", expression)
        self.assertIn("github.event_name == 'pull_request'", expression)

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

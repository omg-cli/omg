"""Require scheduler dependencies instead of racing native producer runners."""
from pathlib import Path
import itertools
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
        self.assertNotIn('strategy:', clippy)
        self.assertIn('native-build-artifact.py clippy-verify', clippy)
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
                       UBUNTU='success', RUNTIME_USAGE='success', QEMU='success', QEMU_FEDORA='success',
                       QEMU_REQUIRED='true', NATIVE_READINESS='success', DOCS_AUDIT='success')
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
        start = script.index('if [[ "$QEMU_REQUIRED" == "true" && ( "$QEMU"')
        end = re.search(r'\n\s*fi\b', script[start:])
        self.assertIsNotNone(end)
        guard = script[start:start + end.end()]
        outcomes = ('success', 'failure', 'cancelled', 'skipped', '')
        for required, outcome, fedora in itertools.product(('true', 'false'), outcomes, outcomes):
            with self.subTest(required=required, non_fedora=outcome, fedora=fedora):
                result = subprocess.run([BASH, '-eu', '-c', guard],
                    env=dict(os.environ, QEMU_REQUIRED=required, NATIVE_READINESS='success', QEMU=outcome, QEMU_FEDORA=fedora),
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0,
                                 required == 'false' or outcome == fedora == 'success')

    def test_automatic_guests_wait_for_shared_current_native_readiness(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        final = job_block(ci, 'ci-success')
        self.assertIn('QEMU_FEDORA: ${{ needs.qemu-fedora.result }}', final)
        for name, partition, expected_needs in (
                ('qemu', 'non-fedora', {'qemu-preflight', 'native-readiness'}),
                ('qemu-fedora', 'fedora', {'qemu-preflight', 'native-readiness', 'fedora-sqlite'})):
            with self.subTest(caller=name):
                qemu = job_block(ci, name)
                needs = re.search(r'^    needs: \[([^]]+)\]', qemu, re.MULTILINE)
                self.assertIsNotNone(needs)
                self.assertEqual({item.strip() for item in needs.group(1).split(',')}, expected_needs)
                self.assertIn('uses: ./.github/workflows/qemu-matrix.yml', qemu)
                self.assertIn('partition: ' + partition, qemu)
                self.assertRegex(final, r'needs: \[[^\]]*\b' + name + r'\b')

    def test_preflight_admits_the_complete_helper_owner_alongside_native_producers(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        preflight = job_block(ci, 'qemu-preflight')
        self.assertIn('needs: [quick-gate, workflow-checks]', preflight)
        self.assertIn("current-ci-helpers: 'true'", preflight)
        self.assertIn('actions: read', preflight)
        self.assertIn('uses: ./.github/actions/qemu-preflight', preflight)
        self.assertIn('ref: ${{ github.sha }}', preflight)
        self.assertIn('persist-credentials: false', preflight)
        for name in ('qemu', 'qemu-fedora'):
            with self.subTest(caller=name):
                guests = job_block(ci, name)
                self.assertIn('qemu-preflight', re.search(r'(?m)^    needs: \[([^]]+)\]$', guests)[1].split(', '))
                self.assertIn('preflight-result: ${{ needs.qemu-preflight.result }}', guests)

    def test_preflight_failure_still_runs_both_qemu_failure_coordinators(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        self.assertIn('name: QEMU behavioral verification preflight', job_block(ci, 'qemu-preflight'))
        for name in ('qemu', 'qemu-fedora'):
            guests = job_block(ci, name)
            self.assertIn('name: QEMU behavioral verification', guests)
            condition = re.search(r'^    if: >-\n((?:      .*\n)+)', guests, re.MULTILINE)[1]
            expression = ' '.join(condition.split())
            for result, cancelled in (('success', False), ('failure', False), ('cancelled', False),
                                      ('skipped', False), ('success', True)):
                with self.subTest(caller=name, preflight=result, cancelled=cancelled):
                    check = expression.replace('needs.qemu-preflight.result', repr(result)).replace(
                        '!cancelled()', '0 == 1' if cancelled else '0 == 0')
                    result_code = subprocess.run([BASH, '-c', '[[ ' + check + ' ]]'], timeout=10).returncode
                    self.assertEqual(result_code, 0 if result != 'skipped' and not cancelled else 1)

    def test_partition_names_do_not_depend_on_successful_preparation(self):
        matrix = (ROOT / '.github/workflows/qemu-matrix.yml').read_text(encoding='utf-8')
        self.assertIn('      partition:\n        type: string\n        default: all\n', matrix)
        workflow_group = re.search(r'^  group: (.+)$', matrix, re.MULTILINE)[1]
        self.assertIn("${{ inputs.partition || 'all' }}", workflow_group)
        self.assertIn("PARTITION: ${{ inputs.partition || 'all' }}", matrix)
        report = job_block(matrix, 'summary').split('      - name: Preserve workflow reporting evidence\n', 1)[1]
        self.assertIn("inputs.partition == 'non-fedora' && '-non-fedora'", report)
        self.assertIn("inputs.partition == 'fedora' && '-fedora'", report)
        self.assertNotIn('needs.prepare.outputs', report)

    def test_failed_early_preflight_blocks_guest_selection(self):
        matrix = (ROOT / '.github/workflows/qemu-matrix.yml').read_text(encoding='utf-8')
        prepare = job_block(matrix, 'prepare')
        self.assertLess(prepare.index('name: Require early QEMU preflight'), prepare.index('name: Resolve selection'))
        gate = prepare.split('      - name: Require early QEMU preflight\n', 1)[1].split('      - name: ', 1)[0]
        expression = re.search(r'^        if: (.+)$', gate, re.MULTILINE)[1]
        guard = step_script(prepare, 'Require early QEMU preflight')
        for status in ('', 'success', 'failure', 'cancelled', 'skipped', 'invalid'):
            with self.subTest(preflight=status):
                check = expression.replace('inputs.preflight-result', repr(status))
                command = 'if [[ ' + check + ' ]]; then\n' + guard + '\nfi\nprintf selected'
                result = subprocess.run([BASH, '-c', command], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if status in ('', 'success') else 1, result.stderr)
                self.assertEqual(result.stdout.endswith('selected'), status in ('', 'success'))

    def test_failed_native_readiness_blocks_selection_without_waiting_for_guests(self):
        matrix = (ROOT / '.github/workflows/qemu-matrix.yml').read_text(encoding='utf-8')
        prepare = job_block(matrix, 'prepare')
        self.assertLess(prepare.index('name: Require native artifact readiness'), prepare.index('name: Resolve selection'))
        gate = prepare.split('      - name: Require native artifact readiness\n', 1)[1].split('      - name: ', 1)[0]
        expression = re.search(r'^        if: (.+)$', gate, re.MULTILINE)[1]
        guard = step_script(prepare, 'Require native artifact readiness')
        for status in ('', 'success', 'failure', 'cancelled', 'skipped', 'invalid'):
            with self.subTest(readiness=status):
                check = expression.replace('inputs.native-readiness-result', repr(status))
                result = subprocess.run([BASH, '-c', 'if [[ ' + check + ' ]]; then\n' + guard + '\nfi\nprintf selected'],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if status in ('', 'success') else 1)
                self.assertEqual(result.stdout.endswith('selected'), status in ('', 'success'))
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        for name in ('qemu', 'qemu-fedora'):
            self.assertIn('native-readiness-result: ${{ needs.native-readiness.result }}', job_block(ci, name))

    def test_native_failure_still_schedules_guests_after_a_successful_quick_gate(self):
        ci = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        for name in ('qemu', 'qemu-fedora'):
            qemu = job_block(ci, name)
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

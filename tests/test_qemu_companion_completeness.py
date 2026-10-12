"""Exercise fixed required companion identities through the real unittest CLI."""
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures' / 'qemu-companion-completeness-sensitivity'
RUNNER = ROOT / 'scripts' / 'run_qemu_boot_timeout_budget.py'
TARGET = 'test_qemu_boot_timeout_budget.BootTimeoutExceedsReadinessWait.test_driver_derives_boot_timeout_from_the_wait_budget'
EXTRA = 'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_unexpected_companion_identity'
SETUP_ERROR = 'setUpClass (test_qemu_boot_timeout_budget.BootShellDeadlineTests)'


class RequiredCompanionObserverCliTests(unittest.TestCase):
    def _run_control(self, mode):
        expected = json.loads((FIXTURES / 'expected-identities.json').read_text())['identities']
        wanted = Counter(expected)
        starts = wanted.copy()
        successes = wanted.copy()
        adverse = []
        if mode == 'duplicate':
            starts[TARGET] += 1
            successes[TARGET] += 1
        elif mode == 'extra':
            starts[EXTRA] += 1
            successes[EXTRA] += 1
        elif mode in ('expected-failure', 'subtest-failure'):
            del successes[TARGET]
            adverse = [{'identity': TARGET, 'kind': 'expected-failure' if mode == 'expected-failure' else 'subtest'}]
        elif mode == 'class-setup-failure':
            starts = Counter(name for name in expected if '.BootShellDeadlineTests.' not in name)
            successes = starts.copy()
            adverse = [{'identity': SETUP_ERROR, 'kind': 'error'}]
        discovered = wanted.copy()
        if mode in ('duplicate', 'extra'):
            discovered = starts.copy()
        with tempfile.TemporaryDirectory(prefix='qemu-observer-cli-') as directory:
            fixture = Path(directory) / 'fixture'
            shutil.copytree(FIXTURES / mode, fixture)
            env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}
            env.update(PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
            argv = [sys.executable, '-B', str(RUNNER), 'discover', '-s', 'scripts', '-p', 'test_qemu_boot_timeout_budget.py']
            result = subprocess.run(argv, cwd=fixture, env=env, capture_output=True, text=True, timeout=5, check=False)
        reports = [json.loads(line.removeprefix('REQUIRED_QEMU_COMPANION ')) for line in result.stderr.splitlines() if line.startswith('REQUIRED_QEMU_COMPANION ')]
        self.assertEqual(len(reports), 1, result.stdout + result.stderr)
        gate = reports[0]
        self.assertEqual(Counter(gate['required']), wanted)
        self.assertEqual(Counter(gate['starts']), starts)
        self.assertEqual(Counter(gate['successes']), successes)
        self.assertEqual(gate['adverse'], adverse)
        self.assertIs(gate['complete'], mode == 'intact')
        discovered_records = [json.loads(line.removeprefix('FIXTURE_DISCOVERED ')) for line in result.stdout.splitlines() if line.startswith('FIXTURE_DISCOVERED ')]
        self.assertEqual(len(discovered_records), 1, result.stdout)
        self.assertEqual(Counter(discovered_records[0]), discovered)
        bodies = [line.removeprefix('FIXTURE_BODY_EXECUTED ') for line in result.stdout.splitlines() if line.startswith('FIXTURE_BODY_EXECUTED ')]
        self.assertEqual(Counter(bodies), starts)
        if mode == 'class-setup-failure':
            self.assertIn('FIXTURE_CLASS_SETUP_FAILURE BootShellDeadlineTests', result.stdout)
        observed = dict(mode=mode, argv=argv, returncode=result.returncode, gate=gate, discovered=discovered_records[0], bodies=bodies, stdout=result.stdout, stderr=result.stderr)
        print('OBSERVER_SENSITIVITY_OBSERVED ' + json.dumps(observed), flush=True)
        self.assertEqual(result.returncode, 0 if mode == 'intact' else 1, result.stdout + result.stderr)

    def test_complete_required_cli_control(self):
        self._run_control('intact')

    def test_duplicate_required_cli_is_rejected(self):
        self._run_control('duplicate')

    def test_extra_cli_identity_is_rejected(self):
        self._run_control('extra')

    def test_expected_failure_cli_is_rejected(self):
        self._run_control('expected-failure')

    def test_failed_subtest_cli_is_rejected(self):
        self._run_control('subtest-failure')

    def test_class_setup_failure_cli_is_rejected(self):
        self._run_control('class-setup-failure')

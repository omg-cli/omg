"""Regression checks for the consolidated CI optimization contracts."""
import os
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github/workflows'
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'


def step_script(workflow, name):
    text = (WORKFLOWS / workflow).read_text(encoding='utf-8')
    step = text.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


class OptimizationContracts(unittest.TestCase):
    def test_native_cache_recipe_keys_are_valid_and_keep_compatibility_boundaries(self):
        script = step_script('ci.yml', 'Compute native cache identity')
        recipes = [
            ('debian', 'debian@sha256:abc', 'debian,pgp,license'),
            ('debian', 'debian@sha256:def', 'debian,pgp,license'),
            ('debian', 'debian@sha256:abc', 'debian,pgp'),
            ('debian-trixie', 'debian@sha256:abc', 'debian,pgp,license'),
        ]
        keys = []
        for platform, image, features in recipes:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'output'
                result = subprocess.run(
                    [BASH, '-e', '-c', script],
                    env=dict(os.environ, CACHE_PLATFORM=platform, CACHE_IMAGE=image,
                             CACHE_FEATURES=features, GITHUB_OUTPUT=str(output)),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                key = output.read_text().strip().removeprefix('key=')
                self.assertRegex(key, r'^[a-f0-9]{64}$')
                expected = hashlib.sha256(
                    ''.join(value + '\0' for value in (platform, image, features)).encode()
                ).hexdigest()
                self.assertEqual(key, expected)
                keys.append(key)
        self.assertEqual(len(keys), len(set(keys)))

    def test_combined_audit_runs_every_policy_and_preserves_failure(self):
        script = step_script('audit.yml', 'Run cargo-deny (Supply Chain Security)')
        for status in (0, 1, 2, 4, 8):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                log = Path(directory) / 'calls'
                summary = Path(directory) / 'summary'
                mock = '''cargo() {
                    printf '%s\\n' "$*" >> "$CALLS"
                    echo policy-diagnostics
                    return "$POLICY_STATUS"
                }
                '''
                result = subprocess.run(
                    [BASH, '-e', '-c', mock + script],
                    env=dict(os.environ, CALLS=str(log), GITHUB_STEP_SUMMARY=str(summary),
                             POLICY_STATUS=str(status)), capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(log.read_text().splitlines(),
                                 ['deny check advisories licenses bans sources'])
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn('policy-diagnostics', summary.read_text(encoding='utf-8'))

    def test_raw_target_owners_use_compatible_dependency_caches(self):
        for filename in ('ci.yml', 'coverage.yml', 'benchmark.yml'):
            with self.subTest(workflow=filename):
                text = (WORKFLOWS / filename).read_text()
                self.assertNotRegex(text, r'(?m)^\s+path: target$')
                self.assertIn('cache-workspace-crates: false', text)
        ci = (WORKFLOWS / 'ci.yml').read_text()
        self.assertEqual(ci.count('shared-key: ${{ steps.cache-key.outputs.key }}'), 2)
        coverage = (WORKFLOWS / 'coverage.yml').read_text()
        self.assertIn('workspaces: . -> target/llvm-cov-target', coverage)
        self.assertIn('cargo llvm-cov nextest', coverage)
        self.assertIn('--no-report', coverage)
        self.assertIn('--lcov', coverage)
        self.assertIn('--summary-only', coverage)

    def test_mutation_baseline_mode_cannot_weaken_full_score_gate(self):
        text = (WORKFLOWS / 'mutation.yml').read_text()
        self.assertIn('cargo test --package omg --no-default-features --features pgp,license --locked --no-fail-fast', text)
        self.assertIn('if [ "$score" -lt 75 ]', text)
        self.assertIn('exit "$mutants_exit"', text)
        self.assertEqual(text.count("if: github.event_name != 'pull_request' && inputs.baseline-only != true"), 3)

    def test_heavy_schedules_do_not_start_at_top_of_hour(self):
        schedules = []
        for filename in ('audit.yml', 'benchmark.yml', 'mutation.yml'):
            text = (WORKFLOWS / filename).read_text()
            cron = re.search(r'cron: "([^\"]+)"', text).group(1)
            self.assertNotEqual(cron.split()[0], '0')
            schedules.append(cron)
        self.assertEqual(len(schedules), len(set(schedules)))


if __name__ == '__main__':
    unittest.main()

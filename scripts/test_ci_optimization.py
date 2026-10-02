"""Regression checks for the consolidated CI optimization contracts."""
import os
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github/workflows'
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'


def step_script(workflow, name):
    text = (WORKFLOWS / workflow).read_text(encoding='utf-8')
    step = text.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


class OptimizationContracts(unittest.TestCase):
    def test_portable_and_benchmark_preserve_native_cache_budget(self):
        for filename, old_prefix, new_prefix in (
            ('ci.yml', 'v2-portable', 'v3-portable-registry'),
            ('benchmark.yml', 'v2-benchmark-dependencies', 'v3-benchmark-registry'),
        ):
            with self.subTest(workflow=filename):
                text = (WORKFLOWS / filename).read_text()
                blocks = re.split(r'(?m)^      - ', text)
                caches = [block for block in blocks
                          if 'uses: Swatinem/rust-cache@' in block and new_prefix in block]
                self.assertEqual(len(caches), 1, 'registry-only cache must use a fresh prefix')
                self.assertIn('cache-targets: false', caches[0])
                self.assertIn('cache-bin: false', caches[0])
                self.assertNotIn(old_prefix, text)

    def test_ci_profiles_do_not_retry_failures(self):
        config = tomllib.loads((ROOT / '.config/nextest.toml').read_text())
        for name in ('ci', 'ci-junit'):
            with self.subTest(profile=name):
                self.assertEqual(config['profile'][name]['retries'], 0)

    def test_coverage_preserves_first_attempt_failures(self):
        script = step_script('coverage.yml', 'Run tests with coverage instrumentation')
        self.assertRegex(script, r'--retries\s+0(?:\s|$)')
        self.assertIn('--no-fail-fast', script)

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
        from test_mutation_reports import MutationReportsTests, SOURCE, mutant

        text = (WORKFLOWS / 'mutation.yml').read_text()
        self.assertIn('cargo test --package omg --no-default-features --features pgp,license --locked --no-fail-fast', text)
        self.assertIn('exit "$mutants_exit"', text)
        full_condition = "if: github.event_name != 'pull_request' && inputs.baseline-only != true"
        for name in ('Install cargo-mutants', 'Run mutation testing',
                     'Download all mutation shards', 'Require complete mutation coverage and score'):
            block = text.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertIn(full_condition, block)

        barrier = step_script('mutation.yml', 'Require successful complete jobs')
        for status in ('success', 'failure', 'cancelled', 'skipped'):
            with self.subTest(job_status=status):
                result = subprocess.run([BASH, '-e', '-c', barrier],
                                        env=dict(os.environ, MUTATION_RESULT=status),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if status == 'success' else 1,
                                 result.stdout + result.stderr)

        fixture = MutationReportsTests('test_complete_partition_accepts_original_global_75_percent_floor')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        directory = fixture.root
        fixture.root = directory / 'mutation-shards'
        fixture.root.mkdir()
        scripts = directory / 'scripts'
        scripts.mkdir()
        (scripts / 'check-mutation-results.py').write_bytes((ROOT / 'scripts/check-mutation-results.py').read_bytes())
        fixture.manifest = [mutant(i) for i in range(64)]
        script = step_script('mutation.yml', 'Require complete mutation coverage and score')
        environment = dict(os.environ, GITHUB_SHA=SOURCE, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        for caught, expected_exit in ((48, 0), (47, 1)):
            with self.subTest(caught=caught):
                fixture.make_reports(['CaughtMutant'] * caught + ['MissedMutant'] * (64 - caught), shards=16)
                result = subprocess.run([BASH, '-e', '-c', script], cwd=directory,
                                        env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)
        fixture.make_reports(['CaughtMutant'] * 64, shards=16)
        fixture.change('shard-15/mutants.out/outcomes.json', lambda value: value.update(end_time=None))
        result = subprocess.run([BASH, '-e', '-c', script], cwd=directory,
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('incomplete', result.stderr)

    def test_mutation_expands_http_scope_and_reuses_downloads_without_cache_growth(self):
        text = (WORKFLOWS / 'mutation.yml').read_text()
        self.assertIn('--file src/core/http.rs', text)
        begin = text.index('      - name: Setup Rust cache')
        end = text.index('      - name: Validate portable mutation baseline', begin)
        cache = text[begin:end]
        for setting in ('prefix-key: "v3-portable-registry"', 'shared-key: portable',
                        'cache-targets: false', 'cache-bin: false', 'cache-workspace-crates: false', 'save-if: false'):
            self.assertIn(setting, cache)
        self.assertNotIn('cache-on-failure: true', cache)
        self.assertNotIn('--exclude-re', text)

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

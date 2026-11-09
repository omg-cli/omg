"""Regression checks for the consolidated CI optimization contracts."""
import os
import hashlib
import gzip
import json
from pathlib import Path
import re
import subprocess
import sys
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
    def test_privileged_coverage_case_requires_real_execution_and_profiles(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        self.assertIn('run_case() {', script)
        function = textwrap.dedent(re.search(r'(?ms)^ +run_case\(\) \{.*?^ +\}', script).group())
        fixture = """\
        #!/bin/bash
        set -eu
        test "$1" = --exact
        test "$3" = --include-ignored
        profile=${LLVM_PROFILE_FILE//%p/123}
        profile=${profile//%m/1}
        profile=${profile//%c/}
        case "$FIXTURE_BEHAVIOR" in
          fail) exit 23 ;;
          missing-profile) ;;
          empty-profile) : > "$profile" ;;
          *) printf counters > "$profile" ;;
        esac
        case "$FIXTURE_BEHAVIOR" in
          skipped) printf '[omg-skip] fixture did not execute\\n' ;;
          profile-error) printf 'LLVM Profile Error: cannot write profile\\n' >&2 ;;
        esac
        if [ "$FIXTURE_BEHAVIOR" = empty-selection ]; then
          printf 'test result: ok. 0 passed; 0 failed; 0 ignored;\\n'
        else
          printf 'test result: ok. 1 passed; 0 failed; 0 ignored;\\n'
        fi
        """
        for behavior in ('pass', 'fail', 'skipped', 'profile-error', 'empty-selection',
                         'missing-profile', 'empty-profile', 'missing-registry'):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary = root / 'fixture'
                binary.write_bytes(textwrap.dedent(fixture).encode())
                binary.chmod(0o755)
                profiles, evidence = root / 'profiles', root / 'evidence'
                profiles.mkdir(); evidence.mkdir()
                (evidence / 'registry.txt').write_bytes(b'' if behavior == 'missing-registry' else b'probe::case: test\n')
                body = '\n'.join((function,
                    'fixture_binary=$TEST_BINARY', 'fixture_profiles=$TEST_PROFILES',
                    'fixture_evidence=$TEST_EVIDENCE', 'run_case probe::case'))
                result = subprocess.run([BASH, '-euo', 'pipefail', '-c', body],
                    env=dict(os.environ, TEST_BINARY=binary.as_posix(), TEST_PROFILES=profiles.as_posix(),
                             TEST_EVIDENCE=evidence.as_posix(), FIXTURE_BEHAVIOR=behavior),
                    capture_output=True, text=True)
                if behavior == 'pass':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual((evidence / 'passed.tsv').read_text(), 'probe::case\t1\n')
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse((evidence / 'passed.tsv').exists())

    def test_privileged_coverage_keeps_isolation_and_state_mount_last(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        cases = re.search(r'(?ms)^ +cases=\(\n(.*?)^ +\)', script)
        self.assertIsNotNone(cases, 'coverage must select its required fixture cases explicitly')
        selected = [line.strip() for line in cases.group(1).splitlines() if line.strip()]
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(len(selected), 14)
        self.assertEqual(selected[0], 'package_managers::alpm_direct::tests::native_inventory_and_search_match_pacman')
        self.assertEqual(selected[-1], 'core::usage::tests::elevated_state_roundtrip_preserves_caller_files')
        self.assertIn('mkdir -m 1777 /profiles', script)
        self.assertIn('--network none --pids-limit 128 --memory 1g --cpus 2', script)
        self.assertIn('mount -t tmpfs -o nosuid,nodev,noexec,mode=755 tmpfs /var/lib', script)
        self.assertNotIn('--env GH_TOKEN', script)
        self.assertNotIn('--env GITHUB_TOKEN', script)

    def test_privileged_coverage_receipt_requires_complete_nonempty_profiles(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        payload = re.search(r"(?ms)^python3 - .* <<'PY'\n(.*?)^PY$", script).group(1)
        for behavior in ('pass', 'missing-result', 'duplicate-result', 'reordered-results',
                         'missing-profile', 'empty-profile', 'wrong-profile-count'):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                binary, profiles, evidence = root / 'fixture', root / 'profiles', root / 'evidence'
                binary.write_bytes(b'fixture binary')
                profiles.mkdir(); evidence.mkdir()
                names = ['probe::first', 'probe::second']
                (evidence / 'expected-tests.txt').write_text('\n'.join(names) + '\n')
                rows = [name + '\t1' for name in names]
                if behavior == 'missing-result': rows.pop()
                if behavior == 'duplicate-result': rows.append(rows[0])
                if behavior == 'reordered-results': rows.reverse()
                if behavior == 'wrong-profile-count': rows[0] = names[0] + '\t2'
                (evidence / 'passed.tsv').write_text('\n'.join(rows) + '\n')
                for name in names:
                    profile = profiles / ('omg-fixture-' + name.replace('::', '_') + '-123-1.profraw')
                    if behavior != 'missing-profile' or name != names[0]:
                        profile.write_bytes(b'' if behavior == 'empty-profile' else b'counters')
                result = subprocess.run([sys.executable, '-c', payload, str(binary), str(profiles),
                                         str(evidence), 'a' * 40], capture_output=True, text=True)
                receipt = evidence / 'receipt.json'
                if behavior == 'pass':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    value = json.loads(receipt.read_text())
                    self.assertEqual(value['binary_sha256'], hashlib.sha256(b'fixture binary').hexdigest())
                    self.assertEqual([case['name'] for case in value['tests']], names)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertFalse(receipt.exists())

    def test_continuous_profiles_require_the_verified_coverage_toolchain(self):
        workflow = (WORKFLOWS / 'coverage.yml').read_text()
        self.assertNotIn('runtime-counter-relocation', workflow.split('jobs:', 1)[0])
        coverage = workflow.split('  coverage:\n', 1)[1].split('\n  coverage-result:', 1)[0]
        self.assertIn('RUSTFLAGS: -C llvm-args=-runtime-counter-relocation', coverage)
        self.assertIn('LLVM_PROFILE_FILE_NAME: omg-%p-%m%c.profraw', coverage)
        self.assertIn('tool: cargo-llvm-cov@0.9.0,nextest', coverage)

    def test_sandbox_coverage_requires_one_existing_instrumented_binary(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        selection = script.split('docker build', 1)[0]
        for count, expected in ((0, 1), (1, 0), (2, 1)):
            with self.subTest(binaries=count), tempfile.TemporaryDirectory() as directory:
                deps = Path(directory) / 'target/llvm-cov-target/debug/deps'
                deps.mkdir(parents=True)
                for number in range(count):
                    binary = deps / f'omg_lib-fixture{number}'
                    binary.write_text('#!/bin/sh\nexit 0\n')
                    binary.chmod(0o755)
                result = subprocess.run(
                    [BASH, '-c', 'cargo() { return 97; };\n' + selection
                     + 'printf "%s" "$binary"'],
                    env={**os.environ, 'GITHUB_WORKSPACE': Path(directory).as_posix(),
                         'RUNNER_TEMP': Path(directory).as_posix()},
                    text=True, capture_output=True)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                if count == 1:
                    self.assertEqual(Path(result.stdout), deps / 'omg_lib-fixture0')

    def test_function_report_is_isolated_and_requires_nonempty_output(self):
        script = step_script('coverage.yml', 'Generate function coverage evidence')
        exporter = """
        cargo() {
            test "$*" = 'llvm-cov report' || return 99
            test "$REPORT_STATUS" = 0 || return "$REPORT_STATUS"
            test "$SILENT" = 1 || printf '%s' 'audit.rs functions'
        }
        """
        for status, silent, expected in ((0, '0', 0), (23, '0', 23), (1, '0', 1), (0, '1', 1)):
            with self.subTest(report_status=status, silent=silent), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run(
                    [BASH, '-e', '-c', textwrap.dedent(exporter) + script], cwd=directory,
                    env=dict(os.environ, REPORT_STATUS=str(status), SILENT=silent),
                    capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 0:
                    self.assertEqual((Path(directory) / 'coverage-functions.txt').read_text().strip(), 'audit.rs functions')

    def test_coverage_region_evidence_preserves_export_and_failure(self):
        script = step_script('coverage.yml', 'Generate region evidence')
        for export_status in (0, 23):
            with self.subTest(export_status=export_status), tempfile.TemporaryDirectory() as directory:
                exporter = """
                cargo() {
                    test "$*" = 'llvm-cov report --json --output-path coverage-regions.json' || return 99
                    test "$EXPORT_STATUS" = 0 || return "$EXPORT_STATUS"
                    printf '%s' '{"data":[{"functions":[{"regions":[[16,29,16,86,10,0,0,0]]}]}]}' > coverage-regions.json
                }
                """
                result = subprocess.run(
                    [BASH, '-e', '-c', textwrap.dedent(exporter) + script],
                    cwd=directory, env=dict(os.environ, EXPORT_STATUS=str(export_status)),
                    capture_output=True, text=True,
                )
                artifact = Path(directory) / 'coverage-regions.json.gz'
                if export_status:
                    self.assertEqual(result.returncode, export_status, result.stderr)
                    self.assertFalse(artifact.exists(), 'failed export must not publish evidence')
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    with gzip.open(artifact, 'rt', encoding='utf-8') as handle:
                        self.assertEqual(json.load(handle)['data'][0]['functions'][0]['regions'][0][4], 10)

    def test_region_artifact_survives_downstream_comparison_failure_with_short_retention(self):
        text = (WORKFLOWS / 'coverage.yml').read_text()
        for name in ('Generate region evidence', 'Preserve region evidence'):
            block = text.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertIn("steps.instrumented_tests.outcome == 'success'", block)
            self.assertIn("steps.instrumented_tests.outcome == 'failure'", block)
            self.assertNotIn('continue-on-error', block)
        artifact = text.split('      - name: Preserve region evidence\n', 1)[1].split('\n      - ', 1)[0]
        self.assertIn('name: coverage-regions', artifact)
        self.assertIn('path: coverage-regions.json.gz', artifact)
        lcov = text.split('      - name: Preserve LCOV evidence\n', 1)[1].split('\n      - ', 1)[0]
        retention = []
        for block in (lcov, artifact):
            values = re.findall(r'(?m)^          retention-days: ([0-9]+)$', block)
            self.assertEqual(len(values), 1, 'paired reports require explicit bounded retention')
            retention.append(int(values[0]))
        self.assertGreater(retention[0], 0)
        self.assertGreaterEqual(retention[1], retention[0], 'region evidence must outlive the LCOV evidence it accompanies')
        self.assertIn('if-no-files-found: error', artifact)

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

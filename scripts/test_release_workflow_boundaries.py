"""Offline guards for release selection, prerequisite gates and failure evidence."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

from test_ci_gates import job_block

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / '.github/workflows'
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'


def step_script(block, name):
    step = block.split(f'      - name: {name}\n', 1)[1]
    step = step.split('\n      - ', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


class ReleaseWorkflowBoundaryTests(unittest.TestCase):
    def test_published_upgrade_requires_explicit_installer_method(self):
        workflow = (WORKFLOWS / 'release-smoke.yml').read_text(encoding='utf-8')
        script = step_script(job_block(workflow, 'upgrade'),
                             'Verify source release and exercise self-update')
        dispatch = 'case "$UPGRADE_METHOD"' + script.split('case "$UPGRADE_METHOD"', 1)[1].split('esac', 1)[0] + 'esac'
        for method in ('self-update', 'installer', 'unexpected'):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'omg').write_bytes(b'#!/bin/sh\nprintf "self:%s\\n" "$*" >> calls\n')
                (root / 'omg').chmod(0o700)
                (root / 'install.sh').write_bytes(b'#!/bin/sh\nprintf "installer:%s:%s:%s\\n" "$INSTALL_DIR" "$OMG_VERSION" "$OMG_SKIP_SHELL" >> calls\n')
                env = dict(os.environ, UPGRADE_METHOD=method, TARGET_TAG='v0.1.222',
                           trial=root.as_posix(), GITHUB_WORKSPACE=root.as_posix())
                result = subprocess.run([BASH, '-c', dispatch], cwd=root, env=env,
                                        capture_output=True, text=True, encoding='utf-8', timeout=10)
                self.assertEqual(result.returncode, 1 if method == 'unexpected' else 0, result.stderr)
                calls = root / 'calls'
                if method == 'unexpected':
                    self.assertFalse(calls.exists())
                elif method == 'self-update':
                    self.assertEqual(calls.read_text().strip(), 'self:self-update --version 0.1.222')
                else:
                    self.assertEqual(calls.read_text().strip(), f'installer:{root.as_posix()}:v0.1.222:1')

    def test_published_upgrade_selects_source_signer_before_download(self):
        workflow = (WORKFLOWS / 'release-smoke.yml').read_text(encoding='utf-8')
        script = step_script(job_block(workflow, 'upgrade'),
                             'Verify source release and exercise self-update')
        selection = script.split('trial=$(mktemp -d)', 1)[0]
        for tag, expected in [('v0.1.220', 'PyRo1121/omg'),
                              ('v0.1.221', 'PyRo1121/omg'),
                              ('v0.1.222', 'omg-cli/omg'),
                              ('v0.2.0', 'omg-cli/omg'),
                              ('v1.0.0', 'omg-cli/omg')]:
            with self.subTest(tag=tag):
                result = subprocess.run(
                    [BASH, '-c', selection + '\nprintf "%s" "$source_signer"'],
                    env=dict(os.environ, SOURCE_TAG=tag, TARGET_TAG='v9.9.9'),
                    capture_output=True, text=True, encoding='utf-8', timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
        self.assertIn('--repo "$source_signer"', script)
        self.assertIn('--signer-workflow "$source_signer/.github/workflows/release.yml"', script)

    def test_immutable_tag_waits_for_other_workflows_without_waiting_on_itself(self):
        block = job_block((WORKFLOWS / 'ci.yml').read_text(), 'release-tag')
        tag = block.index('git tag "$TAG" "$GITHUB_SHA"')
        for workflow in ('benchmark.yml', 'audit.yml', 'secrets.yml', 'codeql.yml',
                         'coverage.yml', 'docker-e2e.yml'):
            self.assertLess(block.index(f'scripts/require-workflow-success.sh {workflow}'), tag)
        self.assertNotIn('scripts/require-workflow-success.sh ci.yml', block)
        self.assertIn('ci-success]', block)

    def test_dispatch_executes_exact_gates_without_evaluating_input(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        script = step_script(job_block(release, 'gate-on-ci'),
                             'Require successful CI and benchmark runs for this commit')
        expected = [
            'ci.yml fixture-commit CI', 'benchmark.yml fixture-commit Benchmark',
            'audit.yml fixture-commit Security Audit', 'secrets.yml fixture-commit Secret Scanning',
            'codeql.yml fixture-commit CodeQL', 'coverage.yml fixture-commit Coverage',
            'docker-e2e.yml fixture-commit Docker E2E',
        ]
        for value in ('true', 'false', '$(touch injected)'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gate = root / 'scripts/require-workflow-success.sh'
                gate.parent.mkdir()
                gate.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> gate-calls\n')
                gate.chmod(0o700)
                env = dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch',
                           GITHUB_SHA='fixture-commit', GITHUB_REF='refs/tags/v1.2.3', DRY_RUN=value)
                result = subprocess.run([BASH, '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((root / 'injected').exists())
                calls = (root / 'gate-calls').read_text().splitlines() if (root / 'gate-calls').exists() else []
                self.assertEqual(calls, [] if value == 'true' else expected)

    def test_release_requires_all_security_and_guest_prerequisites(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        gate = job_block(release, 'gate-on-ci')
        for workflow in ('ci.yml', 'benchmark.yml', 'audit.yml', 'secrets.yml',
                         'codeql.yml', 'coverage.yml', 'docker-e2e.yml'):
            self.assertIn(f'scripts/require-workflow-success.sh {workflow} "$GITHUB_SHA"', gate)
            source = (WORKFLOWS / workflow).read_text(encoding='utf-8')
            push = re.search(r'^  push:\n((?:    .*\n)+)', source, re.M)
            self.assertIsNotNone(push, workflow)
            self.assertIn('branches: [main]', push[1], workflow)
            self.assertNotRegex(push[1], r'paths(?:-ignore)?:', workflow)

    def test_fixture_and_single_tag_gate_all_smoke_jobs(self):
        text = (WORKFLOWS / 'release-smoke.yml').read_text()
        for job in ('smoke', 'smoke-macos'):
            block = job_block(text, job)
            self.assertIn('needs: [runner-fixtures, resolve-release]', block)
            self.assertIn('needs.resolve-release.outputs.release_tag', block)
            self.assertNotIn("inputs.release_tag || 'latest'", block)

    def test_resolved_tag_rejects_output_injection_and_resolves_once(self):
        text = (WORKFLOWS / 'release-smoke.yml').read_text()
        script = step_script(job_block(text, 'resolve-release'), 'Resolve one release tag')
        for value, expected in [('v1.2.3', 0), ('v1.2.3\nother=value', 1), ('../main', 1)]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'output'
                env = dict(os.environ, RELEASE_TAG='latest', GITHUB_REPOSITORY='owner/repo',
                           FAKE_TAG=value, GITHUB_OUTPUT=str(output))
                fake = 'gh() { printf "%s\\n" "$FAKE_TAG"; }\n'
                result = subprocess.run([BASH, '-c', fake + script], env=env,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stderr)
                if expected == 0:
                    self.assertEqual(output.read_text(), 'release_tag=v1.2.3\n')
                else:
                    self.assertFalse(output.exists())
        self.assertEqual(script.count('gh release view'), 1)

    def test_sentry_is_data_and_setup_failures_keep_evidence(self):
        text = (WORKFLOWS / 'release-smoke.yml').read_text()
        for job in ('smoke', 'smoke-macos'):
            block = job_block(text, job)
            self.assertIn('run: python3 scripts/ci-smoke-report.py configure', block)
            self.assertNotIn("dsn='${{", block)
            self.assertIn('ci-smoke-report.py status', block)
            self.assertIn('JOB_STATUS: ${{ job.status }}', block)
        self.assertNotIn('merge-multiple: true', job_block(text, 'file-issues'))

    def test_pull_requests_never_configure_sentry_credentials(self):
        text = (WORKFLOWS / 'release-smoke.yml').read_text()
        for job in ('smoke', 'smoke-macos'):
            block = job_block(text, job)
            step = block.split('      - name: Configure smoke Sentry reporting (opt-in)\n', 1)[1]
            step = step.split('\n      - ', 1)[0]
            self.assertIn("if: github.event_name != 'pull_request'", step)
            self.assertIn('OMG_SMOKE_SENTRY_DSN: ${{ secrets.OMG_SMOKE_SENTRY_DSN }}', step)

    def test_issue_collection_visits_nested_artifacts_without_merging(self):
        text = (WORKFLOWS / 'release-smoke.yml').read_text()
        script = step_script(job_block(text, 'file-issues'), 'File or update failure issues')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for distro in ('arch', 'macos'):
                path = root / 'evidence' / f'release-smoke-{distro}' / 'same-run' / 'results.json'
                path.parent.mkdir(parents=True)
                path.write_text('[]')
            (root / 'scripts').mkdir()
            (root / 'scripts/qa-file-issue.sh').write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$1" >> visited\n')
            (root / 'scripts/qa-file-issue.sh').chmod(0o755)
            env = dict(os.environ, GITHUB_SERVER_URL='https://example.invalid',
                       GITHUB_REPOSITORY='owner/repo', GITHUB_RUN_ID='123')
            result = subprocess.run([BASH, '-c', script], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            visited = (root / 'visited').read_text().splitlines() if (root / 'visited').exists() else []
            self.assertEqual(len(visited), 2)
            self.assertEqual(len(set(visited)), 2)

    def test_release_path_and_exact_commit_benchmark_availability(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        debian = job_block(release, 'build-debian')
        self.assertNotIn("echo 'export PATH=", debian)
        self.assertIn('echo "$CARGO_HOME/bin" >> "$GITHUB_PATH"', debian)
        benchmark = (WORKFLOWS / 'benchmark.yml').read_text(encoding='utf-8')
        push = benchmark.split('  push:\n', 1)[1].split('  schedule:', 1)[0]
        # All main pushes include build-input changes and workflow-only fixes.
        self.assertNotRegex(push, r'paths(?:-ignore)?:')
        self.assertIn('branches: [main]', push)
        self.assertIn('workflow_dispatch:', benchmark)
        self.assertIn('      - name: Upload Benchmark Report\n        if: always()', benchmark)
        ci = (WORKFLOWS / 'ci.yml').read_text(encoding='utf-8')
        self.assertIn("should-build: ${{ github.event_name == 'push' || steps.changes.outputs.required == 'true' }}", ci)

    def test_publication_requires_tag_but_branch_dry_run_remains_valid(self):
        text = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        script = step_script(job_block(text, 'gate-on-ci'), 'Require successful CI and benchmark runs for this commit')
        script = script.split('scripts/require-workflow-success.sh', 1)[0]
        for dry_run, ref, expected in [('true', 'refs/heads/review', 0), ('false', 'refs/heads/main', 1), ('false', 'refs/tags/v1.2.3', 0)]:
            with self.subTest(dry_run=dry_run, ref=ref):
                env = dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch', DRY_RUN=dry_run, GITHUB_REF=ref)
                result = subprocess.run([BASH, '-c', script], env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_setup_fallback_only_sends_when_failed_and_harness_has_no_report(self):
        text = (WORKFLOWS / 'release-smoke.yml').read_text(encoding='utf-8')
        script = step_script(job_block(text, 'smoke'), 'Preserve setup failure and surface reporting')
        for state, existing, expected in [('success', False, False), ('failure', False, True), ('failure', True, False)]:
            with self.subTest(state=state, existing=existing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                if existing:
                    report = root / 'release-smoke-evidence/case/results.json'
                    report.parent.mkdir(parents=True)
                    report.write_text('[]', encoding='utf-8')
                env = dict(os.environ, JOB_STATUS=state, DISTRO='arch', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
                fake = 'python3() { printf "%s\\n" "$*" >> telemetry; }\n'
                result = subprocess.run([BASH, '-c', fake + script], cwd=root, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / 'telemetry').exists(), expected)


if __name__ == '__main__':
    unittest.main()

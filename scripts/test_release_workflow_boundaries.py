"""Offline guards for release selection, prerequisite gates and failure evidence."""
import os
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import textwrap
import unittest

from test_ci_gates import job_block

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / '.github/workflows'
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
EVIDENCE_SCRIPT = 'scripts/require-release-evidence.py'
EVIDENCE_GATE = f'python3 {EVIDENCE_SCRIPT} "$GITHUB_SHA"'


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

    def test_immutable_tag_requires_explicit_dispatch_and_push_evidence(self):
        ci = (WORKFLOWS / 'ci.yml').read_text()
        legacy = job_block(ci, 'release-tag')
        authorization = (WORKFLOWS / 'authorize-release.yml').read_text()
        block = job_block(authorization, 'tag')
        tag = block.index('git tag "$TAG" "$GITHUB_SHA"')
        self.assertIn("if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' "
                      "&& github.run_attempt == '1'", block)
        self.assertIn("RELEASE_CANDIDATE: ${{ inputs['release-candidate'] }}", block)
        self.assertIn('  workflow_dispatch:', authorization)
        self.assertIn('  workflow_call:', authorization)
        self.assertRegex(authorization, r'(?m)^      publish:\n        description: [^\n]+\n'
                                        r'        type: boolean\n        default: false$')
        self.assertNotIn('needs:', block)
        self.assertIn('uses: ./.github/workflows/authorize-release.yml', legacy)
        self.assertIn('ci-success]', legacy)
        for platform in ('linux-matrix', 'sandbox-cancellation', 'feature-intersections', 'macos', 'ubuntu'):
            self.assertIn(f"needs.{platform}.result == 'success'", legacy)
        self.assertRegex(ci, r'(?m)^      release-candidate:\n        description: [^\n]+\n'
                             r'        type: string\n        default: ""$')
        self.assertLess(block.index(EVIDENCE_GATE), tag)

    def test_release_concurrency_cannot_collide_with_pr_branch_name(self):
        ci = (WORKFLOWS / 'ci.yml').read_text()
        group = re.search(r'(?m)^  group: (.*)$', ci)[1]
        release_format = re.search(r"format\('([^']+)', github.ref\)", group)[1]
        pr_format = re.search(r"format\('([^']+)', github.head_ref \|\| github.ref\)", group)[1]
        self.assertTrue(release_format.startswith('release-ci-'))
        self.assertTrue(pr_format.startswith('ci-'))
        release_group = release_format.format('refs/heads/main')
        for branch in ('main', 'ci-authorized-release-refs/heads/main', 'authorized-release-refs/heads/main',
                       release_group, release_group.upper(), 'refs/heads/main'):
            with self.subTest(branch=branch):
                self.assertNotEqual(release_group.casefold(), pr_format.format(branch).casefold())

    def test_release_dispatch_cannot_tag_without_exact_authorization_and_push_ci(self):
        workflow = (WORKFLOWS / 'authorize-release.yml').read_text()
        script = step_script(job_block(workflow, 'tag'), 'Verify and authorize the release candidate')
        sha = 'a' * 40
        approved = f'v0.1.225@{sha}'
        main = 'refs/heads/main'
        all_lookups = [EVIDENCE_SCRIPT]
        for label, overrides, expected_lookups, tagged, dispatched in (
            ('push', {'GITHUB_EVENT_NAME': 'push'}, [], False, False),
            ('pull request', {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_REF': 'refs/pull/1/merge'},
             [], False, False),
            ('off-main', {'GITHUB_REF': 'refs/heads/other'}, [], False, False),
            ('no authorization', {'RELEASE_CANDIDATE': ''}, [], False, False),
            ('wrong version', {'RELEASE_CANDIDATE': f'v0.1.224@{sha}'}, [], False, False),
            ('wrong SHA', {'RELEASE_CANDIDATE': 'v0.1.225@' + 'b' * 40}, [], False, False),
            ('short SHA', {'RELEASE_CANDIDATE': f'v0.1.225@{sha[:7]}'}, [], False, False),
            ('metacharacters', {'RELEASE_CANDIDATE': '$(touch injected)'}, [], False, False),
            ('replay', {'GITHUB_RUN_ATTEMPT': '2'}, [], False, False),
            ('missing attempt', {'GITHUB_RUN_ATTEMPT': ''}, [], False, False),
            ('invalid publish input', {'PUBLISH_RELEASE': ''}, [], False, False),
            ('failed push CI', {'PUSH_CI': 'failure'}, all_lookups, False, False),
            ('refused native archive', {'NATIVE_STAGE': 'failure'}, all_lookups, False, False),
            ('validation with failed CI', {'PUSH_CI': 'failure', 'PUBLISH_RELEASE': 'false'},
             all_lookups, False, False),
            ('drift before tag', {'BEFORE_TAG': 'drifted'}, all_lookups, False, False),
            ('validation with drift', {'BEFORE_TAG': 'drifted', 'PUBLISH_RELEASE': 'false'},
             all_lookups, False, False),
            ('unreadable before tag', {'BEFORE_TAG': 'unreadable'}, all_lookups, False, False),
            ('drift after tag', {'AFTER_TAG': 'drifted'}, all_lookups, True, False),
            ('unreadable after tag', {'AFTER_TAG': 'unreadable'}, all_lookups, True, False),
            ('validate without publishing', {'PUBLISH_RELEASE': 'false'}, all_lookups, False, False),
            ('exact fresh authorization', {}, all_lookups, True, True),
        ):
            with self.subTest(label=label), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'Cargo.toml').write_text('version = "0.1.225"\n', encoding='utf-8')
                fixtures = {
                    'git': 'case "$1" in\n'
                           '  ls-remote)\n'
                           '    if [ "$*" = "ls-remote --exit-code --refs origin refs/heads/main" ]; then\n'
                           '      state=$BEFORE_TAG\n'
                           '      if [ -f pushed ]; then state=$AFTER_TAG; fi\n'
                           '      printf "%s\\n" "$state" >> main-reads\n'
                           '      case "$state" in\n'
                           '        unreadable) exit 128;;\n'
                           '        drifted) printf "%040d\\trefs/heads/main\\n" 0;;\n'
                           '        current) printf "%s\\trefs/heads/main\\n" "$GITHUB_SHA";;\n'
                           '        *) exit 99;;\n'
                           '      esac\n'
                           '    else test -f tagged; fi;;\n'
                           '  tag) printf "%s\\n" "$*" > tagged;;\n'
                           '  push) printf "%s\\n" "$*" > pushed;;\n'
                           '  *) exit 99;;\n'
                           'esac\n',
                    'gh': 'printf "%s\\n" "$*" > dispatched\n',
                    'python3': f'if [ "$1" != {EVIDENCE_SCRIPT} ]; then\n'
                               '  touch advisory-status-called; exit 1\n'
                               'fi\nprintf "%s %s\\n" "$1" "$2" >> lookups\n'
                               'test "$PUSH_CI" = success || exit 1\n'
                               '[ "$3" = --stage-linux ] || exit 2\n'
                               '[ "$5" = --include-macos ] || exit 2\n'
                               'test "$NATIVE_STAGE" = success\n',
                }
                (root / 'scripts').mkdir()
                for name, body in fixtures.items():
                    fixture = root / name
                    fixture.write_text('#!/bin/sh\n' + body, encoding='utf-8', newline='\n')
                    fixture.chmod(0o700)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                           GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF=main, GITHUB_SHA=sha,
                           GITHUB_RUN_ATTEMPT='1', GITHUB_STEP_SUMMARY=str(root / 'summary'),
                           RUNNER_TEMP=str(root),
                           RELEASE_CANDIDATE=approved, BEFORE_TAG='current', AFTER_TAG='current',
                           PUSH_CI='success', NATIVE_STAGE='success', PUBLISH_RELEASE='true')
                env.update(overrides)
                result = subprocess.run([BASH, '-e', '-o', 'pipefail', '-c', script], cwd=root,
                                        env=env, capture_output=True, text=True, timeout=10)
                lookups = root / 'lookups'
                self.assertEqual(lookups.read_text().splitlines() if lookups.exists() else [],
                                 [f'{name} {sha}' for name in expected_lookups])
                validated = label == 'validate without publishing'
                self.assertEqual(result.returncode == 0, dispatched or validated, result.stdout + result.stderr)
                if validated:
                    self.assertIn(f'v0.1.225 at {sha}', (root / 'summary').read_text())
                self.assertFalse((root / 'advisory-status-called').exists())
                reads = root / 'main-reads'
                preflight_passed = env['PUSH_CI'] == env['NATIVE_STAGE'] == 'success'
                expected_reads = [env['BEFORE_TAG']] if expected_lookups and preflight_passed else []
                if tagged:
                    expected_reads.append(env['AFTER_TAG'])
                self.assertEqual(reads.read_text().splitlines() if reads.exists() else [], expected_reads)
                self.assertEqual((root / 'tagged').exists(), tagged)
                self.assertEqual((root / 'pushed').exists(), tagged)
                self.assertEqual((root / 'dispatched').exists(), dispatched)
                self.assertFalse((root / 'injected').exists())
                if tagged:
                    self.assertEqual((root / 'tagged').read_text().strip(), f'tag v0.1.225 {sha}')
                    self.assertEqual((root / 'pushed').read_text().strip(), 'push origin refs/tags/v0.1.225')
                if dispatched:
                    self.assertEqual((root / 'dispatched').read_text().strip(),
                                     'workflow run release.yml --ref v0.1.225 -f dry_run=false')

    def test_dispatch_executes_exact_gates_without_evaluating_input(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        script = step_script(job_block(release, 'gate-on-ci'),
                             'Require successful CI and benchmark runs for this commit')
        expected = [f'{EVIDENCE_SCRIPT} fixture-commit']
        for value in ('true', 'false', '$(touch injected)'):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                gate = root / 'python3'
                gate.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> gate-calls\n')
                gate.chmod(0o700)
                env = dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch',
                           GITHUB_SHA='fixture-commit', GITHUB_REF='refs/tags/v1.2.3', DRY_RUN=value,
                           PATH=str(root) + os.pathsep + os.environ['PATH'])
                result = subprocess.run([BASH, '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((root / 'injected').exists())
                calls = (root / 'gate-calls').read_text().splitlines() if (root / 'gate-calls').exists() else []
                self.assertEqual(calls, [] if value == 'true' else expected)

    def test_release_requires_all_security_and_guest_prerequisites(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        gate = job_block(release, 'gate-on-ci')
        expected = {'ci.yml', 'benchmark.yml', 'audit.yml', 'secrets.yml',
                    'codeql.yml', 'coverage.yml', 'docker-e2e.yml'}
        self.assertIn(EVIDENCE_GATE, gate)
        self.assertEqual(set(runpy.run_path(str(ROOT / EVIDENCE_SCRIPT))['REQUIRED']), expected)
        for workflow in expected:
            source = (WORKFLOWS / workflow).read_text(encoding='utf-8')
            push = re.search(r'^  push:\n((?:    .*\n)+)', source, re.M)
            self.assertIsNotNone(push, workflow)
            self.assertIn('branches: [main]', push[1], workflow)
            self.assertNotRegex(push[1], r'paths(?:-ignore)?:', workflow)

    def test_ci_archive_smoke_requires_a_dry_run_and_a_full_sha(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        gate = job_block(release, 'gate-on-ci')
        script = step_script(gate, 'Require evidence for CI archive smoke')
        preflight = "git() { printf 'git %s\\n' \"$*\"; }\npython3() { printf 'gate %s\\n' \"$*\"; }\n"
        sha = 'a' * 40
        for commit, dry_run, sync, expected in (
            (sha, 'true', '', 0), (sha, 'false', '', 1),
            (sha, 'true', 'v1.2.3', 1), ('$(touch injected)', 'true', '', 1),
        ):
            with self.subTest(commit=commit, dry_run=dry_run, sync=sync):
                env = dict(os.environ, GITHUB_EVENT_NAME='workflow_dispatch',
                           SMOKE_CI_SHA=commit, DRY_RUN=dry_run, SYNC_EXISTING_TAG=sync)
                result = subprocess.run([BASH, '-eu', '-o', 'pipefail', '-c', preflight + script],
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                expected_gate = [] if expected else [f'gate {EVIDENCE_SCRIPT} {sha}']
                self.assertEqual([line for line in result.stdout.splitlines() if line.startswith('gate ')],
                                 expected_gate)
        self.assertIn("if: inputs.smoke_ci_sha == ''", job_block(release, 'build-macos'))
        self.assertIn("inputs.smoke_ci_sha == ''", job_block(release, 'sync-r2'))
        self.assertIn("inputs.smoke_ci_macos != true", job_block(release, 'sync-r2'))

    def test_reused_linux_bytes_are_matched_before_attesting(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        gate = job_block(release, 'gate-on-ci')
        for distro in ('arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora'):
            self.assertIn(f'name: {distro}-build\n          path: verified-native/{distro}-build/', gate)
            self.assertIn("if: needs.gate-on-ci.outputs.staged-version == ''",
                          job_block(release, f'build-{distro}'))
        publish = job_block(release, 'release')
        match = 'Match release bytes to verified CI archives'
        self.assertLess(publish.index('Collect and verify exact release files'), publish.index(match))
        self.assertLess(publish.index(match), publish.index('Attest release archives and SBOM'))
        self.assertIn('.source_sha == $sha', step_script(publish, match))
        self.assertIn('["arch", "debian", "debian-trixie", "fedora", "macos", "ubuntu"]',
                      step_script(publish, match))
        self.assertIn('sha256sum --strict --check', step_script(publish, match))
        dependencies = re.search(r'^    needs: \[([^\]]+)\]', publish, re.M)[1].split(', ')
        condition = publish.split('permissions:', 1)[0]
        self.assertEqual(re.findall(r"needs\.([\w-]+)\.result == 'success'", condition), dependencies)
        self.assertNotIn('needs.*.result', condition)

    def test_publish_run_reports_a_skipped_release_or_r2_sync(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        completion = job_block(release, 'verify-publication')
        self.assertIn("inputs.smoke_ci_sha == ''", completion)
        self.assertIn("inputs.smoke_ci_macos != true", completion)
        self.assertIn("inputs.dry_run == 'false'", completion)
        self.assertIn("needs: [release, sync-r2]", completion)
        script = step_script(completion, 'Require release and mirror completion')
        for sync_only, publish, sync, expected in (
            ('false', 'success', 'success', 0), ('false', 'skipped', 'skipped', 1),
            ('false', 'failure', 'success', 1), ('false', 'success', 'skipped', 1),
            ('true', 'skipped', 'success', 0), ('true', 'skipped', 'failure', 1),
        ):
            with self.subTest(sync_only=sync_only, publish=publish, sync=sync):
                result = subprocess.run([BASH, '-eu', '-o', 'pipefail', '-c', script], capture_output=True,
                                        text=True, timeout=5, env=dict(os.environ, SYNC_ONLY=sync_only,
                                            PUBLISH_RESULT=publish, SYNC_RESULT=sync))
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_archive_stage_requires_macos_for_publication_and_explicit_smoke(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        script = step_script(job_block(release, 'gate-on-ci'), 'Stage verified native archives')
        commands = (
            'python3() { printf "%s\\n" "$@" > arguments; }\n'
            'jq() { case "$2" in *fedora*) echo 1.2.3;; *) echo "$MACOS_DIGEST";; esac; }\n'
        )
        sha, digest = 'a' * 40, 'b' * 64
        for smoke, include, value, expected, status in (
            ('', 'false', digest, True, 0), (sha, 'true', digest, True, 0),
            (sha, 'false', '', False, 0), ('', 'false', '', True, 1),
        ):
            with self.subTest(smoke=smoke, include=include, status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / 'output'
                env = dict(os.environ, SOURCE_SHA=sha, CI_RUN='123', CI_ATTEMPT='1',
                           SMOKE_CI_SHA=smoke, SMOKE_CI_MACOS=include, MACOS_DIGEST=value,
                           GITHUB_OUTPUT=str(output))
                result = subprocess.run([BASH, '-eu', '-o', 'pipefail', '-c', commands + script],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                self.assertEqual('--include-macos' in (root / 'arguments').read_text().splitlines(), expected)
                if status:
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(output.read_text().splitlines(), ['version=1.2.3', 'macos-sha256=' + value])

    def test_every_rebuilt_release_platform_is_smoked_before_publication(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        publish = job_block(release, 'release')
        for job in ('smoke-apt-debian', 'smoke-apt-ubuntu', 'smoke-apt-trixie',
                    'smoke-arch', 'smoke-fedora', 'smoke-macos'):
            self.assertIn(job, publish.split('steps:', 1)[0])
        for distro in ('arch', 'fedora'):
            with self.subTest(distro=distro):
                linux = job_block(release, f'smoke-{distro}')
                other = 'fedora' if distro == 'arch' else 'arch'
                self.assertIn(f'needs: [gate-on-ci, build-{distro}]', linux)
                self.assertIn("needs.gate-on-ci.result == 'success'", linux)
                self.assertIn(f"needs.build-{distro}.result == 'success'", linux)
                self.assertNotIn(f'build-{other}', linux)
                self.assertIn(f'name: {distro}-build', linux)
                self.assertIn('--staged-dir staged-release', linux)
                self.assertIn(f'--distro {distro}', linux)
                self.assertIn(f'name: staged-linux-smoke-{distro}', linux)
        macos = job_block(release, 'smoke-macos')
        self.assertIn('name: macos-build', macos)
        self.assertIn('needs: [gate-on-ci, build-macos]', macos)
        self.assertIn("needs.gate-on-ci.result == 'success'", macos)
        self.assertIn("needs.gate-on-ci.outputs.macos-sha256 != '' && needs.build-macos.result == 'skipped'", macos)
        self.assertIn("needs.build-macos.result == 'success'", macos)
        self.assertIn('needs.build-macos.outputs.archive_sha256', macos)
        self.assertIn('test "$actual" = "$ARCHIVE_SHA256"', macos)
        self.assertIn('--staged-dir staged-release', macos)
        self.assertIn('--executor native', macos)

    def test_apt_smoke_depends_only_on_its_archive_builder(self):
        release = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        publish = job_block(release, 'release').split('steps:', 1)[0]
        for job, build, artifact in (
            ('smoke-apt-debian', 'build-debian', 'debian-build'),
            ('smoke-apt-ubuntu', 'build-ubuntu', 'ubuntu-build'),
            ('smoke-apt-trixie', 'build-debian-trixie', 'debian-trixie-build'),
        ):
            with self.subTest(job=job):
                smoke = job_block(release, job)
                self.assertEqual(re.search(r'^    needs: (.+)$', smoke, re.M)[1],
                                 f'[gate-on-ci, {build}]')
                self.assertIn(f"needs.{build}.result == 'success'", smoke)
                self.assertIn("needs.gate-on-ci.result == 'success'", smoke)
                self.assertIn(f'name: {artifact}', smoke)
                self.assertIn('if: always()', smoke)
                self.assertIn(job, publish)
        for build in ('build-debian', 'build-ubuntu', 'build-debian-trixie'):
            self.assertEqual(re.search(r'^    needs: (.+)$', job_block(release, build), re.M)[1],
                             'gate-on-ci')
        self.assertNotIn('matrix:', job_block(release, 'build-debian'))
        self.assertNotIn('matrix:', job_block(release, 'build-debian-trixie'))
        trixie = job_block(release, 'smoke-apt-trixie')
        self.assertIn('fail-fast: false', trixie)
        self.assertIn('distro: [debian, ubuntu]', trixie)

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

            import json
            import sys
            script = step_script(block, 'Preserve setup failure and surface reporting')
            distro = 'arch' if job == 'smoke' else 'macos'
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'scripts').mkdir()
                command = root / 'scripts/ci-smoke-report.py'
                command.write_text(
                    'import importlib.util, os, subprocess, sys\n'
                    'from unittest.mock import patch\n'
                    'spec = importlib.util.spec_from_file_location("report", os.environ["REPORT_HELPER"])\n'
                    'report = importlib.util.module_from_spec(spec)\n'
                    'spec.loader.exec_module(report)\n'
                    'with patch.object(report.subprocess, "run", return_value=subprocess.CompletedProcess([], 23, "local sender rejected", "")):\n'
                    '    sys.exit(report.main())\n', encoding='utf-8', newline='\n')
                env = dict(os.environ, JOB_STATUS='failure', DISTRO=distro,
                           GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                           REPORT_HELPER=(ROOT / 'scripts/ci-smoke-report.py').as_posix(),
                           TEST_PYTHON=Path(sys.executable).as_posix())
                result = subprocess.run(
                    [BASH, '-c', 'python3() { "$TEST_PYTHON" "$@"; }\n' + script],
                    cwd=root, env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence = root / ('release-smoke-evidence' if job == 'smoke'
                                   else 'release-smoke-evidence-macos') / 'run-123-1'
                self.assertTrue((evidence / 'results.json').is_file(), result.stdout + result.stderr)
                self.assertEqual(json.loads((evidence / 'results.json').read_text()), [{
                    'case_id': f'smoke-{distro}-setup', 'distro': distro,
                    'result': 'HARNESS_ERROR', 'exit_code': 1, 'elapsed_seconds': 0,
                }])
                self.assertEqual(json.loads((evidence / 'reporting-status.json').read_text()),
                                 {'exit_code': 23})
                self.assertIn('local sender rejected', (evidence / 'reporting.log').read_text())

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
            self.assertEqual(set(visited), {
                'evidence/release-smoke-arch/same-run/results.json',
                'evidence/release-smoke-macos/same-run/results.json',
            })

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

    def test_benchmark_measurement_and_helpers_run_independently_but_both_gate_history(self):
        workflow = (WORKFLOWS / 'benchmark.yml').read_text(encoding='utf-8')
        for job in ('benchmark', 'workflow-helpers'):
            with self.subTest(job=job):
                self.assertNotRegex(job_block(workflow, job).split('    steps:', 1)[0],
                                    r'(?m)^    needs:')
        history = job_block(workflow, 'commit-results').split('    steps:', 1)[0]
        dependencies = re.search(r'(?m)^    needs: \[([^\]]+)\]$', history)
        self.assertIsNotNone(dependencies)
        self.assertEqual(set(dependencies.group(1).split(', ')), {'benchmark', 'workflow-helpers'})
        self.assertNotRegex(history, r'\balways\(')

    def test_main_benchmark_uses_helper_coverage_required_by_release_ci(self):
        benchmark = (WORKFLOWS / 'benchmark.yml').read_text(encoding='utf-8')
        helpers = job_block(benchmark, 'workflow-helpers')
        self.assertIn("    if: github.event_name != 'push' && inputs.rust-comparison != true\n", helpers)
        self.assertIn('Admit exact successful CI helper owners', helpers)
        self.assertIn('Execute independent complete helper owner', helpers)
        self.assertIn('Performance Regression Gate', job_block(benchmark, 'benchmark'))

        ci = (WORKFLOWS / 'ci.yml').read_text(encoding='utf-8')
        ci_gate = job_block(ci, 'ci-success')
        self.assertIn('needs: [quick-gate, workflow-checks,', ci_gate)
        self.assertIn("github.event_name == 'push' || needs.quick-gate.outputs.checks-required == 'true'", ci_gate)
        self.assertIn('scripts/workflow-helpers.py admit --current-run', ci_gate)
        for filename in ('authorize-release.yml', 'release.yml'):
            with self.subTest(workflow=filename):
                gate = (WORKFLOWS / filename).read_text(encoding='utf-8')
                self.assertIn(EVIDENCE_GATE, gate)

    def test_benchmark_uses_the_job_release_pair_without_rebuilding(self):
        workflow = (WORKFLOWS / 'benchmark.yml').read_text(encoding='utf-8')
        launcher = step_script(job_block(workflow, 'benchmark'), 'Run Benchmarks (Hyperfine)')
        launcher = launcher.split('# Extract metrics', 1)[0]
        benchmark = (ROOT / 'benchmark-hyperfine.sh').read_text(encoding='utf-8')
        selection = benchmark[benchmark.index('\nTARGET_DIR='):]
        selection = selection.split('\nif [[ "$GUEST_MODE" == true ]]; then', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / 'target/release'
            release.mkdir(parents=True)
            for name in ('omg', 'omgd'):
                binary = release / name
                binary.write_bytes(b'#!/bin/sh\nexit 0\n')
                binary.chmod(0o700)
            (root / 'benchmark-hyperfine.sh').write_bytes((
                '#!/usr/bin/env bash\nset -euo pipefail\n'
                'GUEST_MODE=false UPDATE_MODE=false BLUE= RED= NC=\n'
                'cargo() { echo unexpected-rebuild >&2; return 47; }\n'
                + selection + '\n'
                '[[ "$OMG" -ef "$GITHUB_WORKSPACE/target/release/omg" ]]\n'
                '[[ "$OMGD" -ef "$GITHUB_WORKSPACE/target/release/omgd" ]]\n'
                '[[ "$*" == --fast ]]\n'
            ).encode())
            environment = dict(os.environ, GITHUB_WORKSPACE=root.as_posix(), OMG_BENCH_BINARY='')
            result = subprocess.run([BASH, '-ec', launcher], cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('unexpected-rebuild', result.stdout + result.stderr)

    def test_publication_requires_tag_but_branch_dry_run_remains_valid(self):
        text = (WORKFLOWS / 'release.yml').read_text(encoding='utf-8')
        script = step_script(job_block(text, 'gate-on-ci'), 'Require successful CI and benchmark runs for this commit')
        script = script.split(EVIDENCE_GATE, 1)[0]
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
                if expected:
                    self.assertEqual((root / 'telemetry').read_text().splitlines(), [
                        'scripts/ci-smoke-report.py status --distro arch --case-id smoke-arch-setup '
                        '--status failure --evidence-dir release-smoke-evidence/run-123-1',
                    ])


if __name__ == '__main__':
    unittest.main()

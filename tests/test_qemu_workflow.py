"""Run workflow selection and failure gates locally with Bash and jq (no guests)."""
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/qemu-matrix.yml'
PARENT = WORKFLOW.read_text(encoding='utf-8')
LANE = WORKFLOW.with_name('qemu-lane.yml').read_text(encoding='utf-8')
TEXT = PARENT.replace('\n  guest:\n', '\n  lane-caller:\n') + LANE


def literal(text, key, indent):
    match = re.search(r'^' + ' ' * indent + re.escape(key) + r': \|\n((?: {' + str(indent + 1) + r',}[^\n]*\n|\n)*)', text, re.M)
    if match is None:
        raise AssertionError(f'Missing literal {key}')
    return textwrap.dedent(match[1])


def step(name):
    start = TEXT.index('      - name: ' + name + '\n')
    remaining = TEXT[start + 1:]
    end = re.search(r'^      - |^  [a-z][\w-]*:', remaining, re.M)
    return TEXT[start:start + 1 + end.start()] if end else TEXT[start:]


class QemuWorkflowTests(unittest.TestCase):
    def test_all_qa_reporting_harnesses_gate_guest_builds(self):
        reporting = step('Verify harness and reporting fixtures before guest builds')
        for name in ('qa-file-issue', 'qa-audit', 'qa-open-pr'):
            self.assertIn(f'./scripts/test-{name}.sh', reporting)
        ci = WORKFLOW.with_name('ci.yml').read_text(encoding='utf-8')
        self.assertIn('  pull_request:\n  merge_group:', ci)
        self.assertIn('uses: ./.github/workflows/qemu-matrix.yml', ci)
        self.assertLess(PARENT.index(reporting), PARENT.index('      - name: Resolve selection'))

    @classmethod
    def setUpClass(cls):
        cls.bash = os.environ.get('OMG_TEST_BASH') or shutil.which('bash')
        if not cls.bash or not shutil.which('jq'):
            raise RuntimeError('Workflow regression tests require Bash and jq on PATH')

    def run_script(self, script, env, directory):
        environment = dict(os.environ, **env)
        environment['GITHUB_OUTPUT'] = (directory / 'output').as_posix()
        environment['GITHUB_STEP_SUMMARY'] = (directory / 'summary').as_posix()
        environment['GITHUB_SHA'] = 'f' * 40
        environment['GITHUB_REPOSITORY'] = 'test/omg'
        result = subprocess.run([self.bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                                cwd=WORKFLOW.parents[2], env=environment, text=True, capture_output=True)
        output = directory / 'output'
        values = dict(line.split('=', 1) for line in output.read_text().splitlines()) if output.exists() else {}
        return result, values

    def selection(self, directory, staged, distro, arch, tag='', event_name='workflow_dispatch'):
        block = step('Resolve selection')
        env = dict(STAGED=str(staged).lower(), REQUESTED_DISTRO=distro,
                   REQUESTED_ARCH=arch, REQUESTED_RELEASE_TAG=tag, EVENT_NAME=event_name,
                   BUILD_X64=literal(block, 'BUILD_X64', 10), BUILD_ARM64=literal(block, 'BUILD_ARM64', 10))
        # A local shell function replaces the only release API call.
        return self.run_script('gh() { printf "v9.8.7\\n"; }\n' + literal(block, 'run', 8), env, directory)

    def test_dispatch_cross_product(self):
        for staged, distro, arch in itertools.product([False, True], ['all', 'arch', 'debian', 'ubuntu', 'fedora'], ['all', 'x64', 'arm64']):
            with self.subTest(staged=staged, distro=distro, arch=arch), tempfile.TemporaryDirectory() as tmp:
                result, values = self.selection(Path(tmp), staged, distro, arch)
                invalid = arch == 'arm64' and (not staged or distro == 'arch')
                self.assertEqual(result.returncode != 0, invalid, result.stderr)
                if invalid:
                    continue
                self.assertEqual(values['x64'], str(arch != 'arm64').lower())
                self.assertEqual(values['arm64'], str(staged and arch != 'x64' and distro != 'arch').lower())
                self.assertEqual(json.loads(values['distros']), ['arch', 'debian', 'ubuntu', 'fedora'] if distro == 'all' else [distro])
                self.assertEqual(sorted(row['distro'] for row in json.loads(values['lanes'])),
                                 sorted(json.loads(values['distros'])))
                for key, allowed in [('build-x64', ['arch', 'debian', 'fedora']), ('build-arm64', ['debian', 'fedora'])]:
                    self.assertEqual([row['distro'] for row in json.loads(values[key])], allowed if distro == 'all' else [distro] if distro in allowed else [])
                self.assertEqual(values['tag'], 'v' + re.search(r'^version = "([^"]+)"', (WORKFLOW.parents[2] / 'Cargo.toml').read_text(), re.M)[1] if staged else 'v9.8.7')

    def test_staged_tag_conflict_and_bad_release_fail(self):
        for staged, tag in [(True, 'v1.2.3'), (False, 'invalid'), (False, 'v1.2.3\nother')]:
            with self.subTest(staged=staged, tag=tag), tempfile.TemporaryDirectory() as tmp:
                result, _ = self.selection(Path(tmp), staged, 'all', 'all', tag)
                self.assertNotEqual(result.returncode, 0)

    def test_explicit_release_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, values = self.selection(Path(tmp), False, 'debian', 'x64', 'v1.2.3')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(values['tag'], 'v1.2.3')

    def test_guest_uses_resolved_artifact_mode_for_every_event(self):
        selection = step('Resolve selection')
        self.assertIn("github.event_name == 'schedule'", selection.split('STAGED:', 1)[1].split('\n', 1)[0])
        download = step('Download staged binaries')
        self.assertIn("if: inputs.staged", download)
        guest = step('Run disposable guest lifecycle + read benchmarks + inventory rows')
        self.assertIn('STAGED: ${{ inputs.staged }}', guest)
        script = literal(guest, 'run', 8)
        script = script.replace('${{ inputs.distro }}', 'arch').replace('${{ inputs.tag }}', 'v1.2.3')
        # The runner-isolation probe deliberately rejects WSL/DrvFs hosts such
        # as /mnt/c (a supported local QEMU environment), so stub only that
        # probe and keep asserting the step still runs it. The probe's own
        # behavior is covered by scripts/test_qemu_runner_isolation.py.
        self.assertIn('python3 scripts/check-qemu-runner-isolation.py', script)
        script = script.replace('python3 scripts/check-qemu-runner-isolation.py', 'true')
        # Execute the real argument-selection shell, substituting only the VM launch.
        script = script.replace('./scripts/benchmark-qemu.sh', 'printf "%s\\n"')
        for event, staged in [('push', True), ('pull_request', True),
                              ('workflow_dispatch', True), ('workflow_dispatch', False),
                              ('schedule', True)]:
            with self.subTest(event=event, staged=staged), tempfile.TemporaryDirectory() as tmp:
                result, _ = self.run_script(script, {'STAGED': str(staged).lower(),
                    'RUNNER_TEMP': tmp, 'GITHUB_EVENT_NAME': event,
                    'QEMU_EVIDENCE_NAME': 'qemu-evidence-123-1-arch'}, Path(tmp))
                self.assertEqual(result.returncode, 0, result.stderr)
                args = result.stdout.splitlines()
                self.assertEqual('--staged-dir' in args, staged)
                self.assertEqual('--release-dir' in args, not staged)
                self.assertEqual('--inventory-file' in args, not staged)

    def test_nightly_builds_restore_native_caches_without_extra_saves(self):
        ci = WORKFLOW.with_name('ci.yml').read_text(encoding='utf-8')
        container_build = LANE.split('\n  build-staged:\n', 1)[1].split('\n  build-staged-ubuntu:\n', 1)[0]
        ubuntu_build = LANE.split('\n  build-staged-ubuntu:\n', 1)[1].split('\n  guest:\n', 1)[0]
        for build in (container_build, ubuntu_build):
            for variable in ('CARGO_NET_RETRY: 10', 'RUSTUP_MAX_RETRIES: 10',
                             'RUST_BACKTRACE: short', 'CARGO_PROFILE_DEV_LTO: "off"',
                             'CARGO_PROFILE_TEST_LTO: "off"'):
                self.assertIn(variable, ci)
                self.assertIn(variable, build)
        self.assertIn('20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c', container_build)
        self.assertNotIn('dtolnay/rust-toolchain@', container_build)
        native_identity = ci.split('      - name: Compute native cache identity\n', 1)[1].split('      - name: Cache Rust dependencies\n', 1)[0]
        staged_identity = LANE.split('      - name: Compute native cache identity\n', 1)[1].split('      - name: Restore native compiled dependencies\n', 1)[0]
        self.assertEqual(staged_identity, native_identity.replace('matrix.platform', 'inputs.distro').replace('matrix.image', 'inputs.image').replace('matrix.features', 'inputs.features'))
        native_cache = LANE.split('      - name: Restore native compiled dependencies\n', 1)[1].split('      - name: Run library and binary unit tests', 1)[0]
        ubuntu_cache = LANE.split('      - name: Restore native compiled dependencies\n', 2)[2].split('      - name: Run library and binary unit tests', 1)[0]
        self.assertIn('prefix-key: v2-platform-dependencies', native_cache)
        self.assertIn('shared-key: ${{ steps.cache-key.outputs.key }}', native_cache)
        self.assertIn('prefix-key: v1-ubuntu-debian', ubuntu_cache)
        self.assertIn('shared-key: ubuntu', ubuntu_cache)
        for cache in (native_cache, ubuntu_cache):
            self.assertIn('save-if: false', cache)
            self.assertNotIn('qemu-staged-v1', cache)

    def test_pull_request_never_selects_configurable_arm_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, values = self.selection(Path(tmp), True, 'all', 'all', event_name='pull_request')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(values['x64'], 'true')
            self.assertEqual(values['arm64'], 'false')

    def test_summary_rejects_failed_cancelled_and_missing_selected_jobs(self):
        script = literal(step('Summarize and require selected guest jobs'), 'run', 8)
        for x64, arm in itertools.product([False, True], repeat=2):
            good = {'prepare': {'result': 'success', 'outputs': {'x64': str(x64).lower(), 'arm64': str(arm).lower()}},
                    'build-staged': {'result': 'skipped'},
                    'arm-runner-health': {'result': 'success' if arm else 'skipped'},
                    'guest': {'result': 'success' if x64 else 'skipped'},
                    'guest-arm': {'result': 'success' if arm else 'skipped'}}
            variants = [(good, True)]
            for job in good:
                for status in ['failure', 'cancelled'] + (['skipped'] if job == 'prepare' or job == 'guest' and x64 or job in ('guest-arm', 'arm-runner-health') and arm else []):
                    changed = json.loads(json.dumps(good))
                    changed[job]['result'] = status
                    variants.append((changed, False))
            missing_health = json.loads(json.dumps(good))
            del missing_health['arm-runner-health']
            variants.append((missing_health, False))
            for values, expected in variants:
                with self.subTest(values=values), tempfile.TemporaryDirectory() as tmp:
                    result, _ = self.run_script(script, {'JOB_RESULTS': json.dumps(values)}, Path(tmp))
                    self.assertEqual(result.returncode == 0, expected, result.stderr)


class ReportingIntegrationTests(unittest.TestCase):
    def test_published_guests_resolve_contract_before_running_without_token(self):
        prepare = step('Prepare published release')
        self.assertIn("if: ${{ !inputs.staged }}", prepare)
        self.assertIn('prepare-qemu-release.py', prepare)
        run = step('Run disposable guest lifecycle + read benchmarks + inventory rows')
        self.assertIn('--release-dir published', run)
        self.assertIn('--inventory-file published/cases.tsv', run)
        self.assertNotIn('GH_TOKEN:', run)

    def test_guests_configure_reporter_and_preserve_delivery_logs(self):
        for job in ('guest', 'guest-arm'):
            body = TEXT.split('\n  ' + job + ':\n', 1)[1].split('\n  #', 1)[0]
            self.assertIn('run: python3 scripts/ci-smoke-report.py configure', body)
            self.assertIn('OMG_SMOKE_SENTRY_DSN: ${{ secrets.OMG_SMOKE_SENTRY_DSN }}', body)
            self.assertIn('find "$RUNNER_TEMP/$QEMU_UPLOAD_NAME" -name reporting.log', body)
            self.assertNotIn('${{ env.HOME }}', body)
            # Export only bounded diagnostics: guest-owned raw state may be
            # unreadable, and failed cleanup may retain keys or disk images.
            self.assertIn('sudo -n timeout --kill-after=5s 60s python3 scripts/export-qemu-evidence.py', body)
            self.assertIn('--source "$RUNNER_TEMP/$QEMU_EVIDENCE_NAME" --destination "$RUNNER_TEMP/$QEMU_UPLOAD_NAME"', body)
            self.assertIn('path: ${{ runner.temp }}/${{ env.QEMU_UPLOAD_NAME }}/', body)
            self.assertNotIn('qemu-evidence/**/*', body)
            self.assertIn('- name: Export allowlisted guest evidence\n        if: always()', body)
            self.assertIn('- name: Upload guest evidence\n        id: upload-evidence\n        if: always()', body)

    def test_guest_evidence_paths_are_unique_per_run_attempt_and_distro(self):
        for job, distro in (('guest', 'inputs.distro'), ('guest-arm', 'matrix.distro')):
            body = TEXT.split('\n  ' + job + ':\n', 1)[1].split('\n  #', 1)[0]
            for name in ('QEMU_EVIDENCE_NAME', 'QEMU_UPLOAD_NAME'):
                self.assertRegex(body, rf'{name}: qemu-(?:evidence|upload)-\$\{{\{{ github.run_id \}}\}}-\$\{{\{{ github.run_attempt \}}\}}-\$\{{\{{ {distro} \}}\}}')
            self.assertIn('mkdir -p "$RUNNER_TEMP/$QEMU_EVIDENCE_NAME"', body)
            self.assertIn('--evidence-root "$RUNNER_TEMP/$QEMU_EVIDENCE_NAME"', body)
            self.assertIn('--evidence-root "$RUNNER_TEMP/$QEMU_UPLOAD_NAME"', body)
            self.assertIn('id: upload-evidence', body)
            self.assertIn("if: always() && steps.upload-evidence.outcome == 'success'", body)
            self.assertIn('run: sudo -n rm -rf -- "$RUNNER_TEMP/$QEMU_EVIDENCE_NAME" "$RUNNER_TEMP/$QEMU_UPLOAD_NAME"', body)

    def test_workflow_failure_reports_even_when_guests_never_start(self):
        body = TEXT.split('\n  summary:\n', 1)[1]
        self.assertIn('if: always()', body)
        self.assertIn('build-staged', body)
        self.assertIn('--case-id qemu-matrix-workflow --status failure', body)
        self.assertIn('if: always() && failure()', body)
        self.assertIn('OMG_SMOKE_ENVIRONMENT: qemu-matrix', body)


class SecurityBoundaryTests(unittest.TestCase):
    def test_pr_jobs_never_receive_sentry_secrets(self):
        blocks = re.split(r'(?=^      - )', TEXT, flags=re.M)
        secret_blocks = [block for block in blocks if '          OMG_SMOKE_SENTRY_DSN:' in block]
        self.assertEqual(len(secret_blocks), 3)
        for block in secret_blocks:
            self.assertIn("        if: github.event_name != 'pull_request'", block)
        self.assertIn("OMG_SMOKE_SENTRY_DSN: ${{ github.event_name != 'pull_request' && secrets.OMG_SMOKE_SENTRY_DSN || '' }}", PARENT)
        self.assertNotIn('secrets: inherit', PARENT)

    def test_manual_builds_are_independent_and_automatic_guests_follow_producers(self):
        caller = PARENT.split('\n  guest:\n', 1)[1].split('\n  arm-runner-health:', 1)[0]
        self.assertIn('needs: prepare', caller)
        self.assertIn('uses: ./.github/workflows/qemu-lane.yml', caller)
        self.assertNotIn('needs: [prepare, build', caller)
        self.assertNotIn('native-build-artifact.py ready', PARENT)
        ci = WORKFLOW.with_name('ci.yml').read_text(encoding='utf-8')
        automatic = ci.split('\n  qemu:\n', 1)[1].split('\n  ci-success:', 1)[0]
        self.assertIn('needs: [quick-gate, linux-matrix, ubuntu]', automatic)
        self.assertIn('inputs.staged && inputs.reuse-ci', LANE)
        self.assertIn('needs: [build-staged, build-staged-ubuntu]', LANE)
        self.assertIn("inputs.distro != 'ubuntu' && needs.build-staged.result == 'success'", LANE)
        self.assertIn("inputs.distro == 'ubuntu' && needs.build-staged-ubuntu.result == 'success'", LANE)
        self.assertNotIn('concurrency:', LANE)

    def test_guest_images_are_downloaded_and_verified_not_shared_via_actions_caches(self):
        # Measured on main run 36170417749 (2026-09-25): four qemu-image-v1
        # entries held 2.04 GiB of a 10 GiB repository cache quota, one lane's
        # entry had already been evicted, and a pinned 533 MiB guest image
        # downloaded in about two seconds on the hosted runner. Lanes now
        # download the digest-pinned image each run; the provenance manifest
        # stays the integrity gate, and guest bytes are never cached.
        for workflow in (PARENT, LANE):
            self.assertNotIn('qemu-image-cache', workflow)
            self.assertNotIn('qemu-image-v1-', workflow)
            self.assertNotIn('--image-cache', workflow)
            self.assertIn('--image-policy tests/qemu-image-provenance/manifest.json', workflow)

    def test_all_distros_keep_daemon_release_compilation_and_unit_tests(self):
        self.assertEqual(TEXT.count('cargo test --lib --bins '), 4)
        self.assertEqual(TEXT.count('cargo build --timings --release --no-default-features '), 4)
        self.assertNotIn('--bin omg', TEXT)

    def test_github_token_is_step_scoped(self):
        self.assertNotRegex(TEXT, r'(?m)^  GH_TOKEN:')
        for block in re.split(r'(?=^      - )', TEXT, flags=re.M):
            if 'GH_TOKEN:' in block:
                if any(name in block for name in ('- name: Wait once for native release artifacts',
                                                  '- name: Reuse verified native CI binaries')):
                    self.assertIn('GH_TOKEN: ${{ github.token }}', block)
                    self.assertIn('scripts/native-build-artifact.py', block)
                    # PR artifact reads are intentional. The guest/coordinator
                    # must not acquire the trusted reporter's write privileges.
                    self.assertNotRegex(TEXT, r'(?m)^\s+(?:actions|contents|issues): write\s*$')
                    continue
                self.assertTrue(any(name in block for name in (
                    '- name: Resolve selection', '- name: Prepare published release',
                    '- name: File or update failure issues')), block)
                self.assertIn("github.event_name != 'pull_request'", block)

    def test_kvm_access_is_user_scoped_and_mandatory(self):
        block = step('Open KVM device permissions')
        self.assertNotIn('chmod 666', block)
        self.assertNotIn('|| true', block)
        self.assertIn('setfacl -m "u:$(id -u):rw" /dev/kvm', block)

    def test_pull_requests_cannot_select_configurable_arm_runners(self):
        bash = os.environ.get('OMG_TEST_BASH') or shutil.which('bash')
        if not bash:
            self.skipTest('requires Bash')
        run = literal(step('Resolve selection'), 'run', 8)
        flag_logic = run[run.index('x64=true'):run.index('if [[ "$REQUESTED_DISTRO" == all')]
        command = flag_logic + "printf '%s %s\\n' \"$x64\" \"$arm64\"\n"
        base = dict(os.environ, STAGED='true', REQUESTED_ARCH='all', REQUESTED_DISTRO='all')
        pull_request = subprocess.run(
            [bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', command],
            env=dict(base, EVENT_NAME='pull_request'), text=True, capture_output=True,
        )
        dispatch = subprocess.run(
            [bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', command],
            env=dict(base, EVENT_NAME='workflow_dispatch'), text=True, capture_output=True,
        )
        self.assertEqual((pull_request.returncode, pull_request.stdout.strip()), (0, 'true false'))
        self.assertEqual((dispatch.returncode, dispatch.stdout.strip()), (0, 'true true'))
        push = subprocess.run(
            [bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', command],
            env=dict(base, EVENT_NAME='push'), text=True, capture_output=True,
        )
        self.assertEqual((push.returncode, push.stdout.strip()), (0, 'true false'))

    def test_custom_arm_runner_permissions_are_preconfigured(self):
        body = TEXT.split('\n  guest-arm:\n', 1)[1].split('\n  #', 1)[0]
        self.assertNotIn('chmod 666 /dev/kvm', body)

    def test_guest_jobs_enforce_telemetry_delivery_receipts(self):
        for job in ('guest', 'guest-arm'):
            body = TEXT.split('\n  ' + job + ':\n', 1)[1].split('\n  #', 1)[0]
            self.assertIn('ci-smoke-report.py verify', body)
            self.assertIn('--evidence-root "$RUNNER_TEMP/$QEMU_UPLOAD_NAME"', body)


if __name__ == '__main__':
    unittest.main()

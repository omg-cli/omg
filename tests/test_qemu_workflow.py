"""Run workflow selection and failure gates locally with Bash and jq (no guests)."""
import hashlib
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
    def test_benchmark_all_runs_complete_arch_specific_profile(self):
        source = (WORKFLOW.parents[2] / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        defaults = source[:source.index('here=$(cd')]
        begin = source.index('if [[ "$distro" == all ]]; then')
        end = source.index('case_id="qemu-${distro}${case_suffix}-lifecycle"', begin)
        child = '''#!/usr/bin/env bash
set -euo pipefail
while (($#)); do
  case "$1" in --distro) target=$2; shift 2 ;; --evidence-dir) output=$2; shift 2 ;; *) shift ;; esac
done
[[ "$target" != "${OMIT_GUEST:-}" ]] || exit 1
mkdir -p "$output/run-control"
result=PASS; rc=0
if [[ "$target" == "${FAIL_GUEST:-}" ]]; then result=FAIL; rc=1; fi
jq -n --arg target "$target" --arg result "$result" --argjson rc "$rc" '[{case_id:("qemu-"+$target+"-lifecycle"),distro:$target,result:$result,exit_code:$rc}]' > "$output/run-control/results.json"
exit "$rc"
'''
        for arch, failed, omitted, expected in (
            ('x86_64', '', '', ['arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora']),
            ('aarch64', '', '', ['debian', 'ubuntu', 'fedora']),
            ('x86_64', 'debian-trixie', '', ['arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora']),
            ('x86_64', '', 'debian-trixie', ['arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora'])):
            with self.subTest(arch=arch, failed=failed, omitted=omitted), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                script = root / 'guest-control.sh'
                script.write_text(child)
                script.chmod(0o755)
                command = defaults + '\nroot="$SUITE_ROOT"; arch="$SUITE_ARCH"; source_kind=staged; case_suffix=\n' + source[begin:end]
                result = subprocess.run([self.bash, '-c', command, str(script)], capture_output=True, text=True,
                    env=dict(os.environ, SUITE_ROOT=str(root), SUITE_ARCH=arch, FAIL_GUEST=failed, OMIT_GUEST=omitted), timeout=15)
                self.assertEqual(result.returncode, 1 if failed or omitted else 0, result.stderr)
                rows = json.loads(next(root.glob('suite-*/results.json')).read_text())
                self.assertEqual([row['distro'] for row in rows], expected)
                for row in rows:
                    self.assertEqual(row['result'], 'FAIL' if row['distro'] == failed else
                                     'INCOMPLETE' if row['distro'] == omitted else 'PASS')

    def test_trixie_recipe_executes_only_native_package_arguments(self):
        recipes = json.loads(literal(TEXT, 'BUILD_X64', 10))
        recipe = next(row for row in recipes if row['distro'] == 'debian-trixie')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = root / 'apt-get'
            tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$CAPTURE"\n')
            tool.chmod(0o755)
            result = subprocess.run([self.bash, '-e', '-c', recipe['setup']],
                env=dict(os.environ, PATH=directory + ':' + os.environ['PATH'], CAPTURE=str(root / 'args')),
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = (root / 'args').read_text().splitlines()
            self.assertNotIn('+', arguments, 'diff markers became native package arguments')
            self.assertIn('libapt-pkg-dev', arguments)
            self.assertIn('python3-apt', arguments)

    def test_debian_build_recipes_install_external_lock_probe(self):
        for architecture in ('BUILD_X64', 'BUILD_ARM64'):
            for recipe in json.loads(literal(PARENT, architecture, 10)):
                if 'debian' not in recipe['features'].split(','):
                    continue
                with self.subTest(architecture=architecture, distro=recipe['distro']):
                    capture = 'apt-get() { if [[ "$1" == install ]]; then printf "%s\\n" "$@"; fi; };\n'
                    result = subprocess.run([self.bash, '-e', '-c', capture + recipe['setup']],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('python3', result.stdout.splitlines(),
                        'Debian transaction tests require an external Python POSIX lock probe')

    def copy_inventory_to_controller(self, root):
        repository = WORKFLOW.parents[2]
        source = (repository / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        anchor = source.index('  # The inventory executor runs inside the controller')
        begin = source.rfind('if [[ -n "$inventory_tiers" ]]; then\n', 0, anchor)
        end = source.index('\nif [[ "$benchmark" == true ]]; then\n', anchor)
        self.assertGreaterEqual(begin, 0)
        controller = root / 'controller'
        controller.mkdir()
        result = subprocess.run(
            [self.bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', source[begin:end]],
            env=dict(os.environ, here=str(repository / 'scripts'), work=str(controller),
                     tsv=str(repository / 'tests/cli_behavior_inventory.tsv'),
                     inventory_policy=str(repository / 'tests/qemu-inventory-policy.json'),
                     inventory_tiers='hermetic', inventory_isolation='true', source_kind='staged'),
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return controller

    @unittest.skipIf(os.name == 'nt', 'Controller packaging needs POSIX shell paths')
    def test_controller_ships_exact_executed_inventory_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = self.copy_inventory_to_controller(Path(directory))
            for name in ('qemu-inventory.sh', 'qemu-local-oracle.py', 'qemu-license-oracle.py',
                         'qemu-fingerprint-oracle.py', 'qemu-fedora-update-fixture.sh',
                         'qemu-doctor-turbo-oracle.py',
                         'workspace-overlap-fixture.sh'):
                with self.subTest(helper=name):
                    copied = controller / name
                    self.assertTrue(copied.is_file() and not copied.is_symlink(),
                                    f'Controller is missing executed helper {name}')
                    self.assertEqual(copied.read_bytes(),
                                     (WORKFLOW.parents[2] / 'scripts' / name).read_bytes())

    def run_relocated_inventory(self, root, controller):
        home, tools, guest = (root / name for name in ('home', 'bin', 'guest'))
        for path in (home, tools, guest):
            path.mkdir()
        product = root / 'product'
        product.write_text('#!/bin/sh\nprintf "Usage: relocated fixture\\n"\n', encoding='utf-8')
        product.chmod(0o755)
        ssh = tools / 'ssh'
        ssh.write_text('#!/usr/bin/env bash\nexec bash -c "${@: -1}"\n', encoding='utf-8')
        ssh.chmod(0o755)
        cases = controller / 'cases.tsv'
        cases.write_text(
            'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup\n'
            'help\t["--help"]\thelp-boundary\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop\n',
            encoding='utf-8')
        result = subprocess.run(
            [self.bash, str(controller / 'qemu-inventory.sh'), '--work', str(root),
             '--binary', str(product), '--tsv', str(cases), '--distro', 'arch',
             '--tiers', 'hermetic', '--tag', 'fixture'],
            cwd=controller, env=dict(os.environ, HOME=str(home),
                                    PATH=str(tools) + os.pathsep + os.environ['PATH']),
            capture_output=True, text=True, timeout=30)
        return result, root / 'inventory'

    @unittest.skipIf(os.name == 'nt', 'Relocated controller needs POSIX shell descriptors')
    def test_relocated_controller_executes_rows_and_receipts_local_oracle_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = self.copy_inventory_to_controller(root)
            result, evidence = self.run_relocated_inventory(root, controller)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows = json.loads((evidence / 'results.json').read_text())
            self.assertEqual([row['result'] for row in rows], ['PASS'])
            receipts = {
                Path(filename).name: digest
                for digest, filename in (
                    line.split('  ', 1)
                    for line in (evidence / 'input-sha256.txt').read_text().splitlines())}
            self.assertEqual(receipts.get('qemu-local-oracle.py'),
                             hashlib.sha256((controller / 'qemu-local-oracle.py').read_bytes()).hexdigest(),
                             'Executed local oracle bytes are absent from controller input receipts')

    @unittest.skipIf(os.name == 'nt', 'Relocated controller needs POSIX shell descriptors')
    def test_relocated_controller_missing_local_oracle_cannot_record_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = self.copy_inventory_to_controller(root)
            (controller / 'qemu-local-oracle.py').unlink(missing_ok=True)
            result, evidence = self.run_relocated_inventory(root, controller)
            self.assertNotEqual(result.returncode, 0)
            results = evidence / 'results.json'
            self.assertEqual(json.loads(results.read_text()) if results.exists() else [], [])

    def test_merge_group_requires_current_candidate_guests_and_native_reuse(self):
        ci = WORKFLOW.with_name('ci.yml').read_text(encoding='utf-8')
        automatic = ci.split('\n  qemu:\n', 1)[1].split('\n  docs-audit:', 1)[0]
        expressions = {
            'producer': ' '.join(line.strip() for line in re.search(
                r'^    if: >-\n((?:      [^\n]+\n)+)', automatic, re.M)[1].splitlines()),
            'required': re.search(r'^          QEMU_REQUIRED: \$\{\{ (.+) \}\}$', ci, re.M)[1],
            'staged': re.search(r'^          STAGED: \$\{\{ (.+) \}\}$', PARENT, re.M)[1],
            'reuse': re.search(r'^      reuse-ci: \$\{\{ (.+) \}\}$', PARENT, re.M)[1],
        }
        for name, expression in expressions.items():
            with self.subTest(boundary=name):
                expression = expression.replace('github.event_name', "'merge_group'").replace(
                    'needs.quick-gate.outputs.should-build', "'false'").replace('inputs.staged', '0 == 1').replace(
                    'needs.quick-gate.result', "'success'").replace('!cancelled()', '0 == 0')
                result = subprocess.run([self.bash, '-c', '[[ ' + expression + ' ]]'],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
        producer = expressions['producer'].replace('github.event_name', "'merge_group'").replace(
            'needs.quick-gate.outputs.should-build', "'false'")
        for quick_gate, cancelled, expected in (('success', False, 0),
                                               ('failure', False, 1),
                                               ('success', True, 1)):
            with self.subTest(quick_gate=quick_gate, cancelled=cancelled):
                expression = producer.replace('needs.quick-gate.result', repr(quick_gate)).replace(
                    '!cancelled()', '0 == 1' if cancelled else '0 == 0')
                result = subprocess.run([self.bash, '-c', '[[ ' + expression + ' ]]'],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)
        for job in ('linux-matrix', 'ubuntu'):
            body = re.split(r'\n  [a-z][\w-]*:', ci.split('\n  ' + job + ':\n', 1)[1])[0]
            expression = re.search(r'^    if: (.+)$', body, re.M)[1].replace(
                'github.event_name', "'merge_group'").replace(
                'needs.quick-gate.outputs.should-build', "'false'")
            result = subprocess.run([self.bash, '-c', '[[ ' + expression + ' ]]'],
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            result, values = self.selection(Path(tmp), True, 'all', 'all', event_name='merge_group')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((values['x64'], values['arm64']), ('true', 'false'))

    def test_arm_guests_reject_windows_drives_before_preparation_and_launch(self):
        arm = PARENT.split('\n  guest-arm:\n', 1)[1].split('\n  #', 1)[0]
        guard = 'python3 scripts/check-qemu-runner-isolation.py'
        self.assertEqual(arm.count(guard), 2)
        self.assertLess(arm.index(guard), arm.index('name: Download staged arm64 binaries'))
        launch = arm.split('      - name: Run disposable ARM guest lifecycle + read benchmarks + inventory rows\n', 1)[1]
        script = literal(launch, 'run', 8).replace('${{ matrix.distro }}', 'debian').replace(
            '${{ needs.prepare.outputs.tag }}', 'v1.2.3')
        script = script.replace('./scripts/benchmark-qemu.sh', 'printf launched')
        result = subprocess.run([self.bash, '-e', '-c', 'python3() { return 1; }\n' + script],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('launched', result.stdout)

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
        for staged, distro, arch in itertools.product([False, True], ['all', 'arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora'], ['all', 'x64', 'arm64']):
            with self.subTest(staged=staged, distro=distro, arch=arch), tempfile.TemporaryDirectory() as tmp:
                result, values = self.selection(Path(tmp), staged, distro, arch)
                invalid = arch == 'arm64' and (not staged or distro in ('arch', 'debian-trixie'))
                self.assertEqual(result.returncode != 0, invalid, result.stderr)
                if invalid:
                    continue
                self.assertEqual(values['x64'], str(arch != 'arm64').lower())
                self.assertEqual(values['arm64'], str(staged and arch != 'x64' and distro not in ('arch', 'debian-trixie')).lower())
                self.assertEqual(json.loads(values['distros']), ['arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora'] if distro == 'all' else [distro])
                self.assertEqual(sorted(row['distro'] for row in json.loads(values['lanes'])),
                                 sorted(json.loads(values['distros'])))
                for key, allowed in [('build-x64', ['arch', 'debian', 'debian-trixie', 'fedora']), ('build-arm64', ['debian', 'fedora'])]:
                    self.assertEqual([row['distro'] for row in json.loads(values[key])], allowed if distro == 'all' else [distro] if distro in allowed else [])
                self.assertEqual(values['tag'], 'v' + re.search(r'^version = "([^"]+)"', (WORKFLOW.parents[2] / 'Cargo.toml').read_text(), re.M)[1] if staged else 'v9.8.7')

    def test_staged_tag_conflict_and_bad_release_fail(self):
        for staged, tag in [(True, 'v1.2.3'), (False, 'invalid'), (False, 'v1.2.3\nother')]:
            with self.subTest(staged=staged, tag=tag), tempfile.TemporaryDirectory() as tmp:
                result, _ = self.selection(Path(tmp), staged, 'all', 'all', tag)
                self.assertNotEqual(result.returncode, 0)

    def test_trixie_selects_its_apt7_native_recipe_without_enabling_arm(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, values = self.selection(Path(tmp), True, 'debian-trixie', 'all')
            self.assertEqual(result.returncode, 0, result.stderr)
            lanes = json.loads(values['lanes'])
            self.assertEqual([row['distro'] for row in lanes], ['debian-trixie'])
            self.assertEqual(lanes[0]['features'], 'debian,pgp,license')
            self.assertTrue(lanes[0]['image'].startswith('debian:trixie@sha256:'))
            self.assertEqual((values['x64'], values['arm64']), ('true', 'false'))
        with tempfile.TemporaryDirectory() as tmp:
            result, values = self.selection(Path(tmp), True, 'debian-trixie', 'arm64')
            self.assertNotEqual(result.returncode, 0, 'Trixie ARM has no verified native build recipe')
            self.assertEqual(values, {}, 'unsupported ARM selection must fail before publishing outputs')

    def test_automatic_all_keeps_bookworm_and_adds_a_distinct_trixie_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, values = self.selection(Path(tmp), True, 'all', 'all', event_name='pull_request')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(values['distros']), ['arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora'])
            self.assertEqual(sorted(row['distro'] for row in json.loads(values['lanes'])),
                             ['arch', 'debian', 'debian-trixie', 'fedora', 'ubuntu'])
            self.assertEqual((values['x64'], values['arm64']), ('true', 'false'))

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
                tiers = args[args.index('--inventory-tiers') + 1].split(',')
                self.assertIn('network', tiers, 'current-head guests must execute live-network inventory')

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
        block = step('Select and verify KVM device')
        self.assertNotIn('chmod 666', block)
        self.assertNotIn('|| true', block)
        self.assertIn('RUNNER_ENVIRONMENT: ${{ runner.environment }}', block)
        self.assertIn('python3 scripts/omg-kvm-device.py check', block)
        self.assertIn('python3 scripts/omg-kvm-device.py probe-hosted', block)
        self.assertIn('setfacl -m "u:$(id -u):rw" /dev/kvm', block)
        self.assertIn('OMG_QEMU_KVM_DEVICE=/var/lib/omg-runner/kvm', block)
        self.assertIn('OMG_QEMU_KVM_DEVICE=/dev/kvm', block)
        self.assertIn('docker_device_args=(--device "$kvm_device:/dev/kvm")',
                      (WORKFLOW.parents[2] / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8'))

        # The self-hosted branch must not export a device if the private
        # node fails its real verifier. Unknown runner types also fail closed.
        bash = os.environ.get('OMG_TEST_BASH') or shutil.which('bash')
        if not bash:
            self.skipTest('requires Bash')
        run = literal(block, 'run', 8)
        fake_python = 'python3() { [[ "$*" == "scripts/omg-kvm-device.py check" && "$VERIFY" == pass ]]; };\n'
        for environment, verify, passed in (('self-hosted', 'pass', True),
                                            ('self-hosted', 'fail', False),
                                            ('unknown', 'pass', False)):
            with self.subTest(environment=environment, verify=verify), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'github-env'
                result = subprocess.run(
                    [bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', fake_python + run],
                    env=dict(os.environ, RUNNER_ENVIRONMENT=environment, VERIFY=verify,
                             GITHUB_ENV=str(output)), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)
                self.assertEqual(output.read_text(encoding='utf-8').strip() if output.exists() else '',
                                 'OMG_QEMU_KVM_DEVICE=/var/lib/omg-runner/kvm' if passed else '')

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

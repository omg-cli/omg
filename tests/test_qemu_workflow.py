"""Run workflow selection and failure gates locally with Bash and jq (no guests)."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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
    def _required_companion_prepare_control(self, mode):
        script = literal(step('Workflow selection regression checks'), 'run', 8)
        fixture_base = WORKFLOW.parents[2] / 'tests' / 'fixtures' / 'qemu-companion-completeness'
        expected = sorted(json.loads((fixture_base / 'expected-identities.json').read_text())["identities"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'fixture'
            shutil.copytree(fixture_base / mode, fixture)
            tools = root / 'bin'
            tools.mkdir()
            capture = root / 'arguments.jsonl'
            python = tools / 'python3'
            python.write_text(f'#!{sys.executable}\n' + "import json, os, subprocess, sys\nargs = sys.argv[1:]\nwith open(os.environ['CAPTURE'], 'a') as stream:\n    stream.write(json.dumps(args) + '\\n')\nif args == ['scripts/run_qemu_boot_timeout_budget.py', 'discover', '-s', 'scripts', '-p', 'test_qemu_boot_timeout_budget.py']:\n    env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}\n    result = subprocess.run([sys.executable, os.environ['COMPANION_RUNNER'], *args[1:]], cwd=os.environ['FIXTURE_CWD'], env=env,\n                            capture_output=True, timeout=5, check=False)\n    os.write(1, result.stdout)\n    os.write(2, result.stderr)\n    raise SystemExit(result.returncode)\n")
            python.chmod(0o755)
            env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}
            env.update(PATH=str(tools) + os.pathsep + os.environ['PATH'], CAPTURE=str(capture),
                       FIXTURE_CWD=str(fixture), COMPANION_RUNNER=str(WORKFLOW.parents[2] / 'scripts/run_qemu_boot_timeout_budget.py'), PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
            result = subprocess.run([self.bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                                    cwd=WORKFLOW.parents[2], env=env, capture_output=True, text=True, timeout=10)
            lines = result.stdout.splitlines()
            discovered = [json.loads(line.removeprefix('FIXTURE_DISCOVERED ')) for line in lines if line.startswith('FIXTURE_DISCOVERED ')]
            outcomes = [json.loads(line.removeprefix('FIXTURE_OUTCOME ')) for line in lines if line.startswith('FIXTURE_OUTCOME ')]
            bodies = [line.removeprefix('FIXTURE_BODY_EXECUTED ') for line in lines if line.startswith('FIXTURE_BODY_EXECUTED ')]
            calls = [json.loads(line) for line in capture.read_text().splitlines()]
            dispatch = ['scripts/run_qemu_boot_timeout_budget.py', 'discover', '-s', 'scripts', '-p', 'test_qemu_boot_timeout_budget.py']
            self.assertEqual(calls.count(dispatch), 1, result.stderr)
            actual_expected = [name for name in expected if name != 'test_qemu_boot_timeout_budget.BootShellDeadlineTests.test_slow_successful_initial_and_clone_compositions'] if mode == 'partial-omission' else expected
            self.assertEqual(discovered, [actual_expected], result.stdout + result.stderr)
            self.assertEqual([row['identity'] for row in outcomes], actual_expected, result.stdout)
            for row in outcomes:
                self.assertEqual(row['actual_result_delta'], dict(testsRun=1, skipped=int(mode == 'all-skipped'),
                                 failures=0, errors=0, expectedFailures=0, unexpectedSuccesses=0), result.stdout)
                self.assertEqual(row['outcome'], 'skipped' if mode == 'all-skipped' else 'success', result.stdout)
            self.assertEqual(bodies, [] if mode == 'all-skipped' else actual_expected, result.stdout)
            gate_records = [json.loads(line.removeprefix('REQUIRED_QEMU_COMPANION '))
                            for line in result.stderr.splitlines() if line.startswith('REQUIRED_QEMU_COMPANION ')]
            self.assertEqual(len(gate_records), 1, result.stdout + result.stderr)
            gate = gate_records[0]
            self.assertEqual(sorted(gate['required']), expected)
            self.assertEqual(gate['starts'], actual_expected)
            self.assertEqual(gate['successes'], [] if mode == 'all-skipped' else actual_expected)
            self.assertEqual(gate['adverse'], [{'identity': name, 'kind': 'skip'} for name in actual_expected]
                             if mode == 'all-skipped' else [])
            self.assertIs(gate['complete'], mode == 'intact')
            observed = dict(mode=mode, returncode=result.returncode, expected_identities=expected, gate=gate,
                            discovered=discovered[0], outcomes=outcomes, bodies=bodies,
                            missing=[name for name in expected if name not in discovered[0]],
                            stdout=result.stdout, stderr=result.stderr, dispatch_count=calls.count(dispatch))
            print('REQUIRED_PREPARE_OBSERVED ' + json.dumps(observed), flush=True)
            return result

    def test_prepare_rejects_missing_required_companion_identity(self):
        result = self._required_companion_prepare_control('partial-omission')
        self.assertEqual(result.returncode, 1, 'prepare accepted a missing required identity: ' + result.stdout + result.stderr)

    def test_prepare_rejects_skipped_required_companion_bodies(self):
        result = self._required_companion_prepare_control('all-skipped')
        self.assertEqual(result.returncode, 1, 'prepare accepted skipped required bodies: ' + result.stdout + result.stderr)

    def test_prepare_accepts_all_required_companion_bodies(self):
        result = self._required_companion_prepare_control('intact')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_prepare_executes_boot_observer_and_budget_regressions_before_selection(self):
        # Execute the real prepare step. The private executables record the
        # discovery payload and fail on demand; they do not run guests or sudo.
        regression = step('Workflow selection regression checks')
        self.assertLess(PARENT.index(regression), PARENT.index('      - name: Resolve selection\n'))
        script = literal(regression, 'run', 8)
        observer = ['-m', 'unittest', 'discover', '-s', 'scripts', '-p', 'test_qemu_boot_diagnostics.py']
        budget = ['scripts/run_qemu_boot_timeout_budget.py', 'discover', '-s', 'scripts', '-p', 'test_qemu_boot_timeout_budget.py']
        for failed, expected in (('', 0), ('test_qemu_boot_diagnostics.py', 37),
                                 ('test_qemu_boot_timeout_budget.py', 37)):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = root / 'arguments.jsonl'
                python = root / 'python3'
                python.write_text(f'#!{sys.executable}\n' +
                    'import json, os, sys\n'
                    'with open(os.environ["CAPTURE"], "a") as stream:\n'
                    '    stream.write(json.dumps(sys.argv[1:]) + "\\n")\n'
                    'if os.environ["FAIL_TEST"] and sys.argv[-1] == os.environ["FAIL_TEST"]:\n'
                    '    print("fixture regression failed", file=sys.stderr)\n'
                    '    sys.exit(37)\n')
                python.chmod(0o755)
                sudo = root / 'sudo'
                sudo.write_text('#!/bin/sh\n[ "$1" != -n ] || shift\nexec "$@"\n')
                sudo.chmod(0o755)
                result = subprocess.run([self.bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                    cwd=WORKFLOW.parents[2], env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                    CAPTURE=str(capture), FAIL_TEST=failed), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                calls = [json.loads(line) for line in capture.read_text().splitlines()]
                self.assertIn(observer, calls)
                if failed == 'test_qemu_boot_diagnostics.py':
                    self.assertEqual(calls[-1], observer)
                    self.assertNotIn(budget, calls)
                else:
                    self.assertIn(budget, calls)
                    self.assertLess(calls.index(observer), calls.index(budget))
                    if failed:
                        self.assertEqual(calls[-1], budget)

        script = literal(step('Workflow selection regression checks'), 'run', 8)
        dispatch = ['-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_qemu_companion_completeness.py']
        control_root = WORKFLOW.parents[2]
        wanted = [
            'test_qemu_companion_completeness.RequiredCompanionObserverCliTests.test_complete_required_cli_control',
            'test_qemu_companion_completeness.RequiredCompanionObserverCliTests.test_duplicate_required_cli_is_rejected',
            'test_qemu_companion_completeness.RequiredCompanionObserverCliTests.test_extra_cli_identity_is_rejected',
            'test_qemu_companion_completeness.RequiredCompanionObserverCliTests.test_expected_failure_cli_is_rejected',
            'test_qemu_companion_completeness.RequiredCompanionObserverCliTests.test_failed_subtest_cli_is_rejected',
            'test_qemu_companion_completeness.RequiredCompanionObserverCliTests.test_class_setup_failure_cli_is_rejected',
        ]
        wrapper = textwrap.dedent("""\
            import json, os, subprocess, sys
            args = sys.argv[1:]
            with open(os.environ['CAPTURE'], 'a') as stream:
                stream.write(json.dumps(args) + '\\n')
            dispatch = ['-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_qemu_companion_completeness.py']
            if args == dispatch:
                if os.environ['FAIL_OBSERVER'] == '1':
                    print('CI_OBSERVER_DISPATCH_FAILURE37', file=sys.stderr)
                    raise SystemExit(37)
                env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}
                result = subprocess.run([sys.executable, '-B', *dispatch, '-v'],
                                        cwd=os.environ['CONTROL_ROOT'], env=env,
                                        capture_output=True, timeout=5, check=False)
                os.write(1, result.stdout)
                os.write(2, result.stderr)
                raise SystemExit(result.returncode)
            """)
        for failed in (False, True):
            with self.subTest(observer_failure=failed), tempfile.TemporaryDirectory(prefix='qemu-observer-dispatch-') as directory:
                root = Path(directory)
                capture = root / 'arguments.jsonl'
                python = root / 'python3'
                python.write_text(f'#!{sys.executable}\n' + wrapper)
                python.chmod(0o755)
                sudo = root / 'sudo'
                sudo.write_text('#!/bin/sh\n[ "$1" != -n ] || shift\nexec "$@"\n')
                sudo.chmod(0o755)
                env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP')}
                env.update(PATH=str(root) + os.pathsep + os.environ['PATH'], CAPTURE=str(capture),
                           CONTROL_ROOT=str(control_root), FAIL_OBSERVER=str(int(failed)),
                           PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1')
                command = script + "\nprintf '%s\\n' 'CI_OBSERVER_SELECTION_REACHED'\n"
                result = subprocess.run([self.bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', command],
                                        cwd=control_root, env=env, capture_output=True, text=True, timeout=10)
                calls = [json.loads(line) for line in capture.read_text().splitlines()]
                records = [json.loads(line.removeprefix('OBSERVER_SENSITIVITY_OBSERVED '))
                           for line in result.stdout.splitlines() if line.startswith('OBSERVER_SENSITIVITY_OBSERVED ')]
                named = re.findall(r'^test_\w+ \(([^)]+)\) \.\.\. ok$', result.stderr, re.M)
                observed = dict(failed=failed, actual_prepare_exit=result.returncode, dispatch_count=calls.count(dispatch),
                                calls=calls, owning_named_successes=named, owning_records=records,
                                selection_boundary_reached='CI_OBSERVER_SELECTION_REACHED' in result.stdout,
                                stdout=result.stdout, stderr=result.stderr)
                print('CI_OBSERVER_DISPATCH_OBSERVED ' + json.dumps(observed), flush=True)
                self.assertEqual(calls.count(dispatch), 1, 'prepare omitted the real observer-control dispatch: ' + json.dumps(observed))
                self.assertEqual(result.returncode, 37 if failed else 0, result.stdout + result.stderr)
                if failed:
                    self.assertEqual(calls[-1], dispatch)
                    self.assertNotIn('CI_OBSERVER_SELECTION_REACHED', result.stdout)
                    self.assertIn('CI_OBSERVER_DISPATCH_FAILURE37', result.stderr)
                    self.assertEqual(named, [])
                    self.assertEqual(records, [])
                else:
                    self.assertLess(calls.index(dispatch), calls.index(['-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_qemu_verdict.py']))
                    self.assertIn('CI_OBSERVER_SELECTION_REACHED', result.stdout)
                    self.assertEqual(named, sorted(wanted))
                    self.assertEqual(len(records), 6)
                    actual = {row['mode']: row for row in records}
                    self.assertEqual(set(actual), {'intact', 'duplicate', 'extra', 'expected-failure', 'subtest-failure', 'class-setup-failure'})
                    for mode, discovered, starts, successes, adverse in (
                            ('intact', 11, 11, 11, 0), ('duplicate', 12, 12, 12, 0),
                            ('extra', 12, 12, 12, 0), ('expected-failure', 11, 11, 10, 1),
                            ('subtest-failure', 11, 11, 10, 1), ('class-setup-failure', 11, 5, 5, 1)):
                        row = actual[mode]
                        self.assertEqual(row['returncode'], 0 if mode == 'intact' else 1)
                        self.assertEqual(len(row['discovered']), discovered)
                        self.assertEqual(len(row['gate']['starts']), starts)
                        self.assertEqual(len(row['gate']['successes']), successes)
                        self.assertEqual(len(row['gate']['adverse']), adverse)
                        self.assertEqual(len(row['bodies']), starts)
                        self.assertIs(row['gate']['complete'], mode == 'intact')
                        embedded_gate = [json.loads(line.removeprefix('REQUIRED_QEMU_COMPANION '))
                                         for line in row['stderr'].splitlines() if line.startswith('REQUIRED_QEMU_COMPANION ')]
                        embedded_bodies = [line.removeprefix('FIXTURE_BODY_EXECUTED ')
                                           for line in row['stdout'].splitlines() if line.startswith('FIXTURE_BODY_EXECUTED ')]
                        embedded_discovery = [json.loads(line.removeprefix('FIXTURE_DISCOVERED '))
                                              for line in row['stdout'].splitlines() if line.startswith('FIXTURE_DISCOVERED ')]
                        self.assertEqual(embedded_gate, [row['gate']])
                        self.assertEqual(embedded_bodies, row['bodies'])
                        self.assertEqual(embedded_discovery, [row['discovered']])

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

    def build_recipes(self, architecture):
        expected = {
            'BUILD_X64': [('arch', 'arch,pgp,license'), ('debian', 'debian,pgp,license'),
                          ('debian-trixie', 'debian,pgp,license'), ('fedora', 'fedora,pgp,license')],
            'BUILD_ARM64': [('debian', 'debian,pgp,license'), ('fedora', 'fedora,pgp,license')],
        }
        recipes = json.loads(literal(PARENT, architecture, 10))
        self.assertEqual(sorted((row['distro'], row['features']) for row in recipes),
                         sorted(expected[architecture]), 'Required native build recipe identities changed')
        return recipes

    def test_debian_build_recipes_install_external_lock_probe(self):
        for architecture in ('BUILD_X64', 'BUILD_ARM64'):
            for recipe in self.build_recipes(architecture):
                if 'debian' not in recipe['features'].split(','):
                    continue
                with self.subTest(architecture=architecture, distro=recipe['distro']):
                    capture = 'apt-get() { if [[ "$1" == install ]]; then printf "%s\\n" "$@"; fi; };\n'
                    result = subprocess.run([self.bash, '-e', '-c', capture + recipe['setup']],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('python3', result.stdout.splitlines(),
                        'Debian transaction tests require an external Python POSIX lock probe')

    def test_unit_build_recipes_install_python_venv_and_fish_prerequisites(self):
        for architecture in ('BUILD_X64', 'BUILD_ARM64'):
            for recipe in self.build_recipes(architecture):
                with self.subTest(architecture=architecture, distro=recipe['distro']):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        for name in ('apt-get', 'pacman', 'dnf', 'rpm'):
                            tool = root / name
                            tool.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$CAPTURE"\n')
                            tool.chmod(0o755)
                        result = subprocess.run(
                            [self.bash, '-e', '-c', recipe['setup']],
                            env=dict(os.environ, PATH=directory + ':' + os.environ['PATH'],
                                     CAPTURE=str(root / 'args')),
                            capture_output=True, text=True, timeout=15,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        arguments = (root / 'args').read_text().splitlines()
                        required = ('python', 'fish') if recipe['distro'] == 'arch' else ('python3', 'fish')
                        if 'debian' in recipe['features'].split(','):
                            required += ('python3-venv',)
                        for package in required:
                            self.assertIn(package, arguments)

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

    def test_staged_fedora_target_is_executed_and_reconciled(self):
        bash = shutil.which('bash')
        self.assertIsNotNone(bash, 'staged workflow regression requires Bash')
        for (label, workflow, feature_expression), mode in itertools.product((
            ('lane', LANE, '${{ inputs.features }}'),
            ('matrix-arm', PARENT, '${{ matrix.features }}'),
        ), ('intact', 'missing-target', 'missing-library', 'missing-cli', 'missing-declaration', 'missing-body', 'selected-skip',
            'default-ignored', 'ignored-selected', 'default-filtered', 'reused-refusal')):
            with self.subTest(workflow=label, mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / 'bin'
                tools.mkdir()
                capture = root / 'calls.jsonl'
                for name in ('Cargo.toml', 'Cargo.lock', '.config/nextest.toml',
                             'tests/fedora_tests.rs', 'tests/common/mod.rs', 'tests/platform_semantics.rs'):
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(WORKFLOW.parents[2] / name, target)
                cargo = tools / 'cargo'
                cargo.write_text(f'#!{sys.executable}\n' + r'''
import json, os, pathlib, sys, xml.etree.ElementTree as ET
args = sys.argv[1:]
with open(os.environ['CAPTURE'], 'a') as output: output.write(json.dumps(args)+'\n')
fedora = {'dnf_integration::native_daemon_starts_and_searches_without_installed_inventory_changes': False, 'dnf_integration::native_catalog_observation_survives_readonly_rpm_and_dnf_queries': False, 'dnf_integration::native_catalog_observation_survives_ordinary_user_readonly_wal': False, 'dnf_integration::test_dnf_package_manager_creation': False, 'dnf_integration::repository_lookup_finds_uninstalled_package': False, 'dnf_integration::repository_info_resolves_architecture_and_nevra_selectors': False, 'dnf_integration::installed_info_resolves_native_full_nevra_with_zero_epoch': False, 'dnf_integration::installed_status_resolves_native_full_nevra_with_zero_epoch': False, 'dnf_integration::cli_info_resolves_native_full_nevra': False, 'dnf_integration::cli_json_info_resolves_native_full_nevra': False, 'dnf_integration::repository_search_has_one_installed_row_per_architecture': False, 'dnf_integration::explicit_cli_matches_native_backend_without_a_daemon': False, 'dnf_integration::size_cli_matches_native_installed_packages': False, 'dnf_integration::installed_metadata_does_not_hide_excluded_packages': False, 'dnf_integration::why_cli_matches_native_reasons_and_reverse_requirements': False, 'dnf_integration::blame_cli_uses_native_details_and_canonical_omg_history': False, 'dnf_integration::native_transactions_record_install_remove_and_ignore_noops': False, 'dnf_integration::native_history_honors_custom_and_disabled_service_history': False, 'dnf_integration::cleanup_preview_preserves_installed_packages': False, 'dnf_integration::test_search_common_package': False, 'dnf_integration::test_search_nonexistent_package': False, 'dnf_integration::test_list_installed_packages': False, 'dnf_integration::installed_rpm_selection_rejects_inexact_or_noninstalled_records': False, 'dnf_integration::test_list_updates': False, 'dnf_integration::test_is_installed_check': False, 'dnf_rpm_database::test_rpm_database_query': False, 'dnf_operations::test_orphan_cleanup_history': True, 'dnf_operations::test_update_all_packages': True, 'dnf_operations::test_sync_repository_metadata': True, 'dnf_error_handling::test_install_invalid_package': False, 'common::tests::explicit_timeout_overrides_inherited_timeout': False}
listing = {'rust-suites': {
    'omg': {'binary-id': 'omg', 'status': 'listed', 'testcases': {
        'library_smoke': {'ignored': False, 'filter-match': {'status': 'matches'}}}},
    'omg::bin/omg': {'binary-id': 'omg::bin/omg', 'status': 'listed', 'testcases': {
        'cli_smoke': {'ignored': False, 'filter-match': {'status': 'matches'}}}},
    'omg::bin/omgd': {'binary-id': 'omg::bin/omgd', 'status': 'listed', 'testcases': {
        'daemon_smoke': {'ignored': False, 'filter-match': {'status': 'matches'}}}},
    'omg::fedora_tests': {'binary-id': 'omg::fedora_tests', 'status': 'listed', 'testcases': {
        name: {'ignored': ignored, 'filter-match': {'status': 'matches'}} for name, ignored in fedora.items()}}}}
mode = os.environ['STAGED_FIXTURE']
if mode == 'missing-target': del listing['rust-suites']['omg::fedora_tests']
if mode == 'missing-library': del listing['rust-suites']['omg']
if mode == 'missing-cli': del listing['rust-suites']['omg::bin/omg']
if mode == 'missing-declaration':
    del listing['rust-suites']['omg::fedora_tests']['testcases']['dnf_integration::installed_info_resolves_native_full_nevra_with_zero_epoch']
if mode in ('default-ignored', 'default-filtered'):
    case = listing['rust-suites']['omg::fedora_tests']['testcases']['dnf_integration::installed_info_resolves_native_full_nevra_with_zero_epoch']
    if mode == 'default-ignored': case['ignored'] = True
    else: case['filter-match']['status'] = 'mismatch'
if mode == 'ignored-selected':
    listing['rust-suites']['omg::fedora_tests']['testcases']['dnf_operations::test_orphan_cleanup_history']['ignored'] = False
listing['test-count'] = sum(len(suite['testcases']) for suite in listing['rust-suites'].values())
if args[:2] == ['nextest', 'list']:
    print(json.dumps(listing))
elif args[:2] == ['nextest', 'run']:
    junit = pathlib.Path('target/nextest/ci/junit.xml')
    junit.parent.mkdir(parents=True, exist_ok=True)
    document = ET.Element('testsuites')
    for identity, values in listing['rust-suites'].items():
        suite = ET.SubElement(document, 'testsuite', name=identity)
        for name, case in values['testcases'].items():
            if not case['ignored']:
                ET.SubElement(suite, 'testcase', classname=identity, name=name, time='0.001')
    junit.write_text(ET.tostring(document, encoding='unicode'))
    if mode in ('missing-body', 'selected-skip'):
        document = ET.fromstring(junit.read_text())
        suite = document.find("testsuite[@name='omg::fedora_tests']")
        if mode == 'missing-body': suite.remove(suite[-1])
        else: ET.SubElement(suite[0], 'skipped')
        junit.write_text(ET.tostring(document, encoding='unicode'))
''')
                cargo.chmod(0o755)
                git = tools / 'git'
                git.write_text('#!/bin/sh\nprintf "%s\\n" fixture-stage-source\n')
                git.chmod(0o755)
                block = workflow.split('- name: Run library and binary unit tests (including omgd)\n', 1)[1]
                match = re.match(r'        run: (.*)\n', block)
                self.assertIsNotNone(match)
                script = match.group(1).replace(feature_expression, 'fedora,pgp,license')
                script = script.replace('scripts/run-native-contracts.py', str(WORKFLOW.parents[2] / 'scripts/run-native-contracts.py'))
                env = dict(os.environ, PATH=str(tools)+os.pathsep+os.environ['PATH'],
                           CAPTURE=str(capture), STAGED_FIXTURE=mode, RUNNER_TEMP=str(root), GITHUB_SHA='fixture-stage-source',
                           OMG_CONTRACT_SOURCE_SHA='fixture-stage-source', PYTHONDONTWRITEBYTECODE='1')
                result = subprocess.run([bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                                        cwd=root, env=env, capture_output=True, text=True, timeout=10)
                if mode == 'reused-refusal':
                    self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                    output = root / 'staged-unit-tests'
                    evidence = ('source-tests.json', 'list.json', 'list.stderr.log', 'selection.json',
                                'recipe.json', 'run.stdout.log', 'run.stderr.log', 'junit.xml')
                    self.assertTrue(all((output / name).is_file() for name in evidence))
                    (output / 'unrelated.txt').write_text('retain unrelated output')
                    source = root / 'tests/fedora_tests.rs'
                    source.write_text(source.read_text().replace('feature = "fedora"', 'feature = "arch"', 1))
                    first_status = result.returncode
                    result = subprocess.run([bash, '--noprofile', '--norc', '-euo', 'pipefail', '-c', script],
                                            cwd=root, env=env, capture_output=True, text=True, timeout=10)
                    calls = [json.loads(line) for line in capture.read_text().splitlines()]
                    remaining = [name for name in evidence if (output / name).exists()]
                    error = json.loads((output / 'admission-error.json').read_text())
                    print('STAGED_UNIT_REUSE '+json.dumps(dict(workflow=label, first_status=first_status,
                          refusal_status=result.returncode, remaining_owned_evidence=remaining,
                          unrelated=(output / 'unrelated.txt').read_text(), calls=calls, error=error)))
                    self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
                    self.assertIn('unreviewed Fedora target cfg', error['error'])
                    self.assertEqual(len(calls), 2, 'source refusal must not invoke cargo')
                    self.assertEqual((output / 'unrelated.txt').read_text(), 'retain unrelated output')
                    self.assertEqual(remaining, [], 'failed reuse must remove prior owned run evidence')
                    continue
                calls = [json.loads(line) for line in capture.read_text().splitlines()]
                self.assertTrue(any('--test' in args and args[args.index('--test')+1] == 'fedora_tests'
                                    for args in calls), result.stdout+result.stderr+repr(calls))
                error = root / 'staged-unit-tests' / 'admission-error.json'
                self.assertEqual(result.returncode, int(mode != 'intact'), result.stdout+result.stderr+
                                 (error.read_text() if error.exists() else ''))
                if mode in ('missing-target', 'missing-library', 'missing-cli', 'missing-declaration', 'missing-body',
                            'default-ignored', 'ignored-selected', 'default-filtered'):
                    self.assertIn('required binary missing' if mode in ('missing-target', 'missing-library', 'missing-cli') else
                                  'Fedora declaration missing' if mode == 'missing-declaration' else
                                  'Fedora declaration disposition mismatch' if mode in
                                  ('default-ignored', 'ignored-selected', 'default-filtered') else 'missing selected execution',
                                  json.loads(error.read_text())['error'])
                    self.assertEqual(len(calls), 2 if mode == 'missing-body' else 1)
                    print('STAGED_UNIT_FIXTURE '+json.dumps(dict(workflow=label, mode=mode,
                          status=result.returncode, calls=calls, error=json.loads(error.read_text()))))
                    continue
                observed = json.loads((root / 'staged-unit-tests' / 'selection.json').read_text())
                self.assertEqual(observed['counts'], dict(discovered=34, selected=31, executed=31,
                                  passed=31, failed=0, skipped=3, filtered=0, retried=0) if mode == 'intact'
                                  else dict(discovered=34, selected=31, executed=30, passed=30, failed=0,
                                            skipped=4, filtered=0, retried=0))
                self.assertTrue(observed['executed_required_binaries'])
                self.assertEqual(set(observed['tests']), {'omg::bin/omg::cli_smoke', 'omg::fedora_tests::dnf_integration::installed_rpm_selection_rejects_inexact_or_noninstalled_records', 'omg::fedora_tests::dnf_integration::explicit_cli_matches_native_backend_without_a_daemon', 'omg::fedora_tests::dnf_integration::test_is_installed_check', 'omg::fedora_tests::dnf_integration::why_cli_matches_native_reasons_and_reverse_requirements', 'omg::fedora_tests::dnf_integration::installed_metadata_does_not_hide_excluded_packages', 'omg::fedora_tests::dnf_integration::cli_info_resolves_native_full_nevra', 'omg::fedora_tests::dnf_integration::test_search_common_package', 'omg::fedora_tests::dnf_integration::repository_search_has_one_installed_row_per_architecture', 'omg::fedora_tests::dnf_integration::size_cli_matches_native_installed_packages', 'omg::fedora_tests::dnf_integration::native_catalog_observation_survives_ordinary_user_readonly_wal', 'omg::fedora_tests::dnf_integration::test_list_installed_packages', 'omg::fedora_tests::dnf_rpm_database::test_rpm_database_query', 'omg::fedora_tests::dnf_integration::repository_lookup_finds_uninstalled_package', 'omg::fedora_tests::dnf_integration::native_catalog_observation_survives_readonly_rpm_and_dnf_queries', 'omg::fedora_tests::dnf_integration::cleanup_preview_preserves_installed_packages', 'omg::fedora_tests::dnf_integration::test_list_updates', 'omg::library_smoke', 'omg::fedora_tests::dnf_integration::installed_status_resolves_native_full_nevra_with_zero_epoch', 'omg::fedora_tests::dnf_integration::native_transactions_record_install_remove_and_ignore_noops', 'omg::fedora_tests::dnf_integration::native_daemon_starts_and_searches_without_installed_inventory_changes', 'omg::fedora_tests::dnf_integration::repository_info_resolves_architecture_and_nevra_selectors', 'omg::bin/omgd::daemon_smoke', 'omg::fedora_tests::dnf_integration::native_history_honors_custom_and_disabled_service_history', 'omg::fedora_tests::dnf_integration::installed_info_resolves_native_full_nevra_with_zero_epoch', 'omg::fedora_tests::common::tests::explicit_timeout_overrides_inherited_timeout', 'omg::fedora_tests::dnf_error_handling::test_install_invalid_package', 'omg::fedora_tests::dnf_integration::test_dnf_package_manager_creation', 'omg::fedora_tests::dnf_integration::test_search_nonexistent_package', 'omg::fedora_tests::dnf_integration::cli_json_info_resolves_native_full_nevra', 'omg::fedora_tests::dnf_integration::blame_cli_uses_native_details_and_canonical_omg_history'})
                print('STAGED_UNIT_FIXTURE '+json.dumps(dict(workflow=label, mode=mode,
                      status=result.returncode, calls=calls, selection=observed)))

    def test_all_distros_keep_daemon_release_compilation_and_unit_tests(self):
        self.assertEqual(TEXT.count('cargo test --lib --bins ') +
                         TEXT.count('--staged-units --features '), 4)
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

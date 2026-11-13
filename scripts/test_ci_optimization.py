"""Regression checks for the consolidated CI optimization contracts."""
import os
import hashlib
import gzip
import json
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import tomllib
import unittest

from test_ci_gates import job_block

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github/workflows'
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else (shutil.which('bash') or 'bash')


def step_script(workflow, name):
    text = (WORKFLOWS / workflow).read_text(encoding='utf-8')
    step = text.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
    return textwrap.dedent(step.split('        run: |\n', 1)[1])


class OptimizationContracts(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "The hosted service workflow uses POSIX executable scripts")
    def test_advisory_service_is_verified_without_remote_deployment(self):
        workflow = job_block((WORKFLOWS / 'ci.yml').read_text(), 'workflow-checks')
        steps = dict(re.findall(r'^      - name: ([^\n]+)\n(.*?)(?=^      - (?:name:|uses:)|\Z)',
                                workflow, re.MULTILINE | re.DOTALL))
        scripts = [textwrap.dedent(block.split('        run: |\n', 1)[1])
                   for name, block in steps.items() if name == 'Verify Arch advisory service']
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / 'commands.jsonl'
            commands.touch()
            recorder = root / 'bun'
            recorder.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                                'with open(os.environ["BUN_COMMANDS"], "a") as stream: '
                                'stream.write(json.dumps(sys.argv[1:])+"\\n")\n')
            recorder.chmod(0o755)
            for script in scripts:
                result = subprocess.run([BASH, '-euo', 'pipefail', '-c', script],
                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get('PATH', ''),
                             BUN_COMMANDS=str(commands)), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = [json.loads(line) for line in commands.read_text().splitlines()]
            self.assertEqual(calls, [
                ['install', '--cwd', 'services/advisories', '--frozen-lockfile', '--ignore-scripts'],
                ['run', '--cwd', 'services/advisories', 'test'],
                ['run', '--cwd', 'services/advisories', 'check'],
                ['run', '--cwd', 'services/advisories', 'dry-run'],
            ], 'The advisory service must have frozen dependencies, behavioral tests, types and a non-deploying build')

    @unittest.skipIf(os.name == 'nt', 'Native Arch input permissions require POSIX mode bits')
    def test_native_coverage_stages_protected_inputs_from_writable_sources(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        start = script.index('docker cp "$binary"')
        end = script.index('\nbash scripts/benchmark-qemu.sh', start)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts, evidence, runner = root / 'scripts', root / 'evidence', root / 'runner'
            for path in (scripts, evidence, runner):
                path.mkdir()
            producer = scripts / 'native-cli-coverage.py'
            producer.write_bytes(b'print("fixture producer")\n')
            producer.chmod(0o666)
            artifacts = {}
            for role in ('coverage14', 'arch-contracts', 'comprehensive', 'cli-unit', 'cli', 'daemon'):
                artifact = root / (role + ' source')
                artifact.write_bytes(('fixture executable ' + role).encode())
                artifact.chmod(0o666)
                artifacts[role] = {'path': str(artifact)}
            manifest = evidence / 'cli-manifest.json'
            manifest.write_text(json.dumps({'artifacts': artifacts}))
            manifest.chmod(0o666)
            originals = {path: (stat.S_IMODE(path.stat().st_mode), path.read_bytes())
                         for path in (producer, manifest, *(Path(a['path']) for a in artifacts.values()))}
            fixture = root / 'fixture'
            fixture.write_bytes(b'native fixture')
            fixture.chmod(0o755)
            capture = root / 'copy-arguments'
            rows = root / 'manifest-rows.py'
            rows.write_text('import json,sys\n'
                            'with open(sys.argv[1]) as stream: artifacts=json.load(stream)["artifacts"]\n'
                            'for role, artifact in artifacts.items(): print(role+"\\t"+artifact["path"])\n')
            driver = '''umask 000
docker() { test "$1" = cp; printf '%s\\0%s\\0' "$2" "$3" >> "$COPY_CAPTURE"; }
jq() { "$TEST_PYTHON" "$MANIFEST_ROWS" "$3"; }
''' + script[start:end]
            result = subprocess.run([BASH, '-euo', 'pipefail', '-c', driver], cwd=root,
                env=dict(os.environ, COPY_CAPTURE=str(capture), TEST_PYTHON=sys.executable,
                         MANIFEST_ROWS=str(rows), binary=str(fixture), container='fixture-container',
                         RUNNER_TEMP=str(runner), evidence_dir=str(evidence)),
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            arguments = capture.read_bytes().split(b'\0')[:-1]
            copied = {target.decode(): (root / source.decode()).resolve()
                      for source, target in zip(arguments[::2], arguments[1::2])}
            self.assertEqual(copied, {'fixture-container:/fixture': fixture})
            for original, name in ((producer, 'native-cli-coverage.py'),
                                   (manifest, 'native-cli-manifest.json')):
                staged = runner / 'native-cli-inputs' / name
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o644,
                                 'Supplemental input must be staged without group/other write permissions')
                self.assertNotEqual(staged, original)
                self.assertTrue(staged.is_relative_to(runner))
                self.assertEqual(staged.read_bytes(), original.read_bytes())
            binaries = runner / 'native-cli-inputs/bin'
            self.assertEqual(stat.S_IMODE(binaries.stat().st_mode), 0o755)
            self.assertEqual({p.name for p in binaries.iterdir()}, set(artifacts))
            for role, artifact in artifacts.items():
                self.assertEqual(stat.S_IMODE((binaries / role).stat().st_mode), 0o755)
                self.assertEqual((binaries / role).read_bytes(), Path(artifact['path']).read_bytes())
            for path, identity in originals.items():
                self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.read_bytes()), identity)

    def test_native_coverage_passes_one_complete_guest_script_to_docker(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        start = script.index('container=$(docker create')
        end = script.index("\ndocker cp", start)
        command = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'docker-arguments'
            driver = (
                'docker() { printf \'%s\\0\' "$@" > "$ARGV_CAPTURE"; '
                'printf \'%s\' fixture-container; }\nfixture_apparmor=test-profile\n' + command
            )
            result = subprocess.run(
                [BASH, '-eu', '-c', driver],
                env=dict(os.environ, ARGV_CAPTURE=capture.as_posix()),
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            arguments = capture.read_bytes().split(b'\0')[:-1]
            guest = arguments[arguments.index(b'-c') + 1:]
            self.assertEqual(len(guest), 1, 'Docker must receive the entire guest program as one argument')
            syntax = subprocess.run([BASH, '-n'], input=guest[0], capture_output=True)
            self.assertEqual(syntax.returncode, 0, syntax.stderr.decode())

    def test_fixture_profile_lifecycle_is_bounded_and_cleans_up(self):
        script = step_script('coverage.yml', 'Cover sandbox descendant cancellation')
        script = script.split('python3 scripts/native-cli-coverage.py verify', 1)[0]
        script = script.split('python3 - "$binary"', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'target/llvm-cov-target/debug/deps/omg_lib-test'
            binary.parent.mkdir(parents=True)
            binary.write_text('fixture')
            binary.chmod(0o755)
            (root / 'scripts').mkdir()
            (root / 'scripts/native-cli-coverage.py').write_bytes(
                (ROOT / 'scripts/native-cli-coverage.py').read_bytes())
            for name in ('debug/omg', 'debug/omgd',
                         'debug/deps/coverage_14-1111111111111111',
                         'debug/deps/arch_cli_contracts-1111111111111111',
                         'debug/deps/cli_comprehensive-1111111111111111',
                         'debug/deps/omg-1111111111111111'):
                artifact = root / 'target/llvm-cov-target' / name
                artifact.write_text('fixture executable')
                artifact.chmod(0o755)
            benchmark = root / 'scripts/benchmark-qemu.sh'
            benchmark.write_text('''#!/usr/bin/env bash
set -euo pipefail
test "$1" = --distro && test "$2" = arch
while test "$#" -gt 0; do
  if test "$1" = --evidence-dir; then
    mkdir -p "$2/unit-transport/native-evidence/cli" "$2/unit-transport/native-profiles"
    exit 0
  fi
  shift
done
exit 2
''')
            readelf = root / 'readelf'
            readelf.write_text('#!/bin/sh\nprintf "__llvm_covmap __llvm_prf_cnts\\n"\n')
            readelf.chmod(0o755)
            sysctl = root / 'restriction'
            sysctl.write_text('1\n')
            script = script.replace('/proc/sys/kernel/apparmor_restrict_unprivileged_userns', str(sysctl))
            for name in ('coverage-seccomp.json', 'coverage-sandbox-seccomp.json'):
                script = script.replace('/tmp/' + name, str(root / name))
            docker = root / 'docker'
            docker.write_text('''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
data = sys.stdin.read() if args and args[0] == 'run' and '--interactive' in args else ''
with open(os.environ['TRACE'], 'a') as trace:
    trace.write(json.dumps([args, data]) + '\\n')
if args and args[0] == 'create': print('fixture-container')
if args[:2] == ['start', '--attach']: sys.exit(int(os.environ['START_STATUS']))
if args and args[0] == 'rm': sys.exit(int(os.environ.get('REMOVE_STATUS', '0')))
if '--remove' in args: sys.exit(int(os.environ.get('UNLOAD_STATUS', '0')))
''')
            docker.chmod(0o755)
            launcher = '''curl() { :; }
sha256sum() { if [ "$1" = --check ]; then cat >/dev/null; else command sha256sum "$@"; fi; }
jq() { :; }
git() { printf '%040d\\n' 1; }
'''
            for run_id, attempt, status, remove, unload, expected in [
                    ('123', '1', 0, 0, 0, 0), ('123', '2', 23, 0, 0, 23),
                    ('123', '3', 23, 7, 9, 23), ('123', '4', 0, 7, 0, 7),
                    ('123', '5', 0, 0, 9, 9)]:
                trace = root / f'trace-{attempt}'
                runner_temp = root / ('runner-' + attempt)
                runner_temp.mkdir()
                result = subprocess.run([BASH, '-e', '-c', launcher + script], cwd=root,
                    env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                             TRACE=str(trace), START_STATUS=str(status), REMOVE_STATUS=str(remove),
                             UNLOAD_STATUS=str(unload), GITHUB_RUN_ID=run_id,
                             GITHUB_RUN_ATTEMPT=attempt, GITHUB_WORKSPACE=str(root), RUNNER_TEMP=str(runner_temp)),
                    text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                calls = [json.loads(line) for line in trace.read_text().splitlines()]
                loaders = [(args, data) for args, data in calls if '--entrypoint' in args]
                self.assertEqual(len(loaders), 1 if remove else 2)
                name = f'omg-coverage-{run_id}-{attempt}'
                for (args, data), operation in zip(loaders, ('--replace', '--remove')):
                    self.assertIn(operation, args)
                    self.assertIn('--network=none', args)
                    self.assertIn('--cap-drop=ALL', args)
                    self.assertIn('--cap-add=MAC_ADMIN', args)
                    self.assertIn('--security-opt=apparmor=unconfined', args)
                    self.assertIn('--pids-limit=32', args)
                    self.assertIn('--memory=256m', args)
                    self.assertIn('--cpus=1', args)
                    self.assertIn('--read-only', args)
                    self.assertEqual([arg for arg in args if arg.startswith(('--volume=', '--mount='))],
                                     ['--mount=type=bind,src=/sys/kernel/security,dst=/sys/kernel/security'])
                    self.assertTrue(data.startswith('abi <abi/4.0>,\n'))
                    self.assertIn('profile ' + name + ' flags=(unconfined)', data)
                    self.assertIn('userns,', data)
                create = next(args for args, _ in calls if args[0] == 'create')
                self.assertIn('apparmor=' + name, create)
                self.assertIn('--network', create)
                removal = next(i for i, (args, _) in enumerate(calls) if args[:2] == ['rm', '--force'])
                unloads = [i for i, (args, _) in enumerate(calls) if '--remove' in args]
                if remove:
                    self.assertEqual(unloads, [])
                    self.assertIn('retaining AppArmor profile', result.stderr)
                else:
                    self.assertEqual(len(unloads), 1)
                    self.assertLess(removal, unloads[0])

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
        self.assertIn('package_managers::alpm_ops::tests::native_reason_write_failure_preserves_durable_reason', selected)
        self.assertIn('package_managers::aur::utils::tests::native_lifecycle_original_user_ownership', selected)
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(len(selected), 22)
        self.assertIn("package_managers::arch_install::native_tests::native_installation_preserves_mixed_intents", selected)
        self.assertIn('package_managers::aur::client::tests::attended_review_requires_hardened_confirmation_even_with_yes', selected)
        self.assertIn('package_managers::aur::client::tests::native_isolated_fixture_builds_reviewed_source_without_installing', selected)
        self.assertIn('package_managers::aur::client::tests::native_isolated_history_requires_hardened_review', selected)
        self.assertIn('runner=(runuser -u nobody -- env HOME=/home/omg-fixture', script)
        self.assertIn('NOPASSWD: /usr/bin/true', script)
        self.assertNotIn('NOPASSWD: ALL', script)
        self.assertIn('config::settings::tests::hardened_aur_settings_refuse_incompatible_build_options', selected)
        self.assertIn('grep -F "parent_uid=0"', script)
        self.assertIn('grep -F "uid=65534 "', script)
        self.assertEqual(selected[0], 'package_managers::alpm_direct::tests::native_inventory_and_search_match_pacman')
        self.assertEqual(selected[-1], 'core::usage::tests::elevated_state_roundtrip_preserves_caller_files')
        self.assertIn('mkdir -m 1777 /profiles', script)
        self.assertIn('--network none --add-host aur.archlinux.org:127.0.0.1 --pids-limit 128 --memory 1g --cpus 2', script)
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

    def test_exit_flush_and_native_continuous_profiles_require_the_verified_coverage_toolchain(self):
        workflow = (WORKFLOWS / 'coverage.yml').read_text()
        self.assertNotIn('runtime-counter-relocation', workflow.split('jobs:', 1)[0])
        coverage = workflow.split('  coverage:\n', 1)[1].split('\n  coverage-result:', 1)[0]
        self.assertIn('RUSTFLAGS: -C llvm-args=-runtime-counter-relocation', coverage)
        self.assertIn('LLVM_PROFILE_FILE_NAME: omg-%p-%m.profraw', coverage)
        self.assertIn('LLVM_PROFILE_FILE="$fixture_profiles/omg-fixture-$case_id-%p-%m%c.profraw"', coverage)
        self.assertIn('--default-toolchain 1.95.0', coverage)
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
                    test "$*" = 'llvm-cov report --json --output-path coverage-regions.json --verbose' || return 99
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
                self.assertEqual(len(caches), 2 if filename == 'ci.yml' else 1,
                                 'registry-only cache must use a fresh prefix')
                for cache in caches:
                    self.assertIn('cache-targets: false', cache)
                    self.assertIn('cache-bin: false', cache)
                if filename == 'ci.yml':
                    for role in ('portable', 'portable-release'):
                        self.assertEqual(job_block(text, role).count(new_prefix), 1)
                self.assertNotIn(old_prefix, text)

    def test_compiler_cache_upload_contains_both_diagnostics_in_one_directory(self):
        for filename, job in (('ci.yml', 'portable'), ('ci.yml', 'portable-release'),
                              ('benchmark.yml', 'benchmark')):
            with self.subTest(workflow=filename, job=job), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                tools = root / 'bin'
                tools.mkdir()
                cache = tools / 'sccache'
                cache.write_text('#!/bin/sh\nif [ "$*" = "--show-stats --stats-format=json" ]; then\n'
                                 '  printf \'{"stats":{"cache_read_errors":0}}\\n\'\nfi\n')
                cache.chmod(0o755)
                block = job_block((WORKFLOWS / filename).read_text(), job)
                report = re.search(r'(?m)^      - name: Report .* compiler cache\n', block)
                report_step = block[report.end():].split('\n      - ', 1)[0]
                script = textwrap.dedent(report_step.split('        run: |\n', 1)[1])
                result = subprocess.run([BASH, '-eu', '-c', script], capture_output=True, text=True,
                    env=dict(os.environ, PATH=tools.as_posix() + os.pathsep + os.environ['PATH'],
                             RUNNER_TEMP=root.as_posix(), GITHUB_SHA='a' * 40,
                             SCCACHE_S3_KEY_PREFIX='benchmark-v1/'), timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                upload = re.split(r'      - name: Preserve .* compiler cache diagnostics\n', block)[1]
                path = re.search(r'(?m)^          path: (.+)$', upload).group(1)
                self.assertNotEqual(path, '|', 'Container uploads need one scalar directory path')
                uploaded = Path(path.replace('${{ runner.temp }}', root.as_posix()))
                self.assertEqual(sorted(item.name for item in uploaded.iterdir()),
                                 ['omg-r2-cache-context.txt', 'omg-r2-cache-stats.json'])
                self.assertEqual(json.loads((uploaded / 'omg-r2-cache-stats.json').read_text()),
                                 {'stats': {'cache_read_errors': 0}})
                self.assertEqual((uploaded / 'omg-r2-cache-context.txt').read_text(),
                                 'source=' + 'a' * 40 + '\nprefix=benchmark-v1/\n')

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


class CoverageProducerDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / 'scripts').mkdir()
        (self.directory / 'scripts/check-line-coverage.py').write_bytes(
            (ROOT / 'scripts/check-line-coverage.py').read_bytes())
        (self.directory / '.github/workflows').mkdir(parents=True)
        (self.directory / '.github/workflows/coverage.yml').write_bytes(
            (WORKFLOWS / 'coverage.yml').read_bytes())
        (self.directory / 'src').mkdir()
        (self.directory / 'src/a.rs').write_text('fn a() {}\n')
        for command in (['git', 'init', '-q'], ['git', 'add', 'src/a.rs'],
                        ['git', '-c', 'user.name=Coverage fixture', '-c',
                         'user.email=coverage@example.invalid', 'commit', '-qm', 'fixture']):
            subprocess.run(command, cwd=self.directory, check=True, capture_output=True)
        self.revision = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=self.directory, text=True).strip()
        self.environment = dict(os.environ, GITHUB_SHA=self.revision, GITHUB_RUN_ID='123',
                                GITHUB_RUN_ATTEMPT='2', GITHUB_JOB='coverage',
                                RUNNER_TEMP=self.directory.as_posix(), TEST_PYTHON=sys.executable)

    def reports(self, count=1, schema='3.1.0'):
        (self.directory / 'lcov.info').write_text(
            'SF:/fixture/src/a.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n')
        document = {'type': 'llvm.coverage.json.export', 'version': schema, 'data': [{
            'files': [{'filename': '/fixture/src/a.rs', 'summary': {'lines': {'count': 1, 'covered': 1}}}],
            'functions': [{'name': 'a', 'filenames': ['/fixture/src/a.rs'],
                           'regions': [[1, 1, 1, 10, count, 0, 0, 0]]}]}]}
        (self.directory / 'export.json').write_text(json.dumps(document))

    def run_shell(self, script, environment=None):
        launcher = 'python3() { "$TEST_PYTHON" "$@"; };\n'
        return subprocess.run([BASH, '-e', '-c', launcher + script], cwd=self.directory,
                              env=environment or self.environment, text=True,
                              capture_output=True, timeout=30)

    def export_and_validate(self):
        exporter = '''cargo() {
          test "$EXPORT_STATUS" = 0 || return "$EXPORT_STATUS"
          cp export.json coverage-regions.json
        };\n'''
        script = step_script('coverage.yml', 'Generate region evidence')
        text = (WORKFLOWS / 'coverage.yml').read_text()
        if '      - name: Validate local coverage evidence\n' in text:
            script += step_script('coverage.yml', 'Validate local coverage evidence')
        return self.run_shell(exporter + script, dict(self.environment, EXPORT_STATUS='0'))

    def test_producer_rejects_saturation_before_runner_disappears(self):
        self.reports(2**63 - 1)
        result = self.export_and_validate()
        self.assertNotEqual(result.returncode, 0, 'producer accepted a saturated region')
        self.assertIn('wrapped or saturated count', result.stderr)
        self.assertTrue((self.directory / 'coverage-regions.json.gz').is_file())

    def test_producer_preserves_healthy_report_and_rejects_bad_schema(self):
        self.reports()
        result = self.export_and_validate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.directory / 'coverage-diagnostics').exists())
        self.reports(schema='unsupported')
        (self.directory / 'coverage-regions.json.gz').unlink()
        result = self.export_and_validate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unsupported region schema', result.stderr)

    def collect(self, member_calls=None, input_budget=None, projection_budget=None):
        script = step_script('coverage.yml', 'Collect invalid coverage diagnostics')
        if member_calls is not None:
            script = script.replace("members = {'calls_left': 8192,", "members = {'calls_left': " + str(member_calls) + ",")
        if input_budget is not None:
            script = script.replace('budget = 128 * 1024 * 1024', 'budget = ' + str(input_budget))
        if projection_budget is not None:
            script = script.replace('projection_budget = 16 * 1024 * 1024', 'projection_budget = ' + str(projection_budget))
        result = self.run_shell(script)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = Path(self.environment['RUNNER_TEMP']) / 'coverage-diagnostics'
        return json.loads((output / 'receipt.json').read_text()), output / 'profiles.tar.gz'

    def without_diagnostic_tools(self):
        tools = self.directory / 'empty-tool-path'
        tools.mkdir()
        self.environment['PATH'] = tools.as_posix()

    def diagnostic_tools(self):
        tools = self.directory / 'toolchain/bin'
        tools.mkdir(parents=True)
        script = f'#!{sys.executable}\n' + textwrap.dedent('''
            import json, os, pathlib, sys, time
            name = pathlib.Path(sys.argv[0]).name
            if '--version' in sys.argv or '-vV' in sys.argv:
                print('fixture tool version')
            elif name == 'rustc':
                print(pathlib.Path(__file__).parent.parent / 'lib')
            elif name == 'llvm-cov':
                assert sys.argv[1] == 'convert-for-testing'
                if os.environ.get('TEST_LARGE_MAP'):
                    with pathlib.Path(sys.argv[2]).open('rb') as source:
                        size = 9 * 1024 * 1024 if source.read(3) == b'BIG' else 3 * 1024 * 1024
                    with pathlib.Path(sys.argv[4]).open('wb') as output:
                        output.truncate(size)
                else:
                    pathlib.Path(sys.argv[4]).write_bytes(b'coverage map only')
                for projection in pathlib.Path(os.environ['RUNNER_TEMP']).glob('coverage-diagnostics/*.proftext'):
                    behavior = os.environ.get('TEST_PROJECTION_TAMPER')
                    if behavior == 'alter': projection.write_bytes(b'corrupted')
                    if behavior == 'oversize': projection.write_bytes(b'x' * 65537)
                    if behavior == 'symlink':
                        projection.unlink()
                        projection.symlink_to(pathlib.Path(os.environ['RUNNER_TEMP']) / 'outside')
            elif name == 'llvm-profdata':
                assert sys.argv[1:3] == ['show', '--text']
                wanted = sys.argv[3].split('=', 1)[1]
                with pathlib.Path(sys.argv[4]).open('rb') as stream:
                    values = json.loads(stream.read(64).rstrip(b'\\0').strip())
                if os.environ.get('TEST_RAW_TAMPER') == 'mmap':
                    marker = pathlib.Path(os.environ['RUNNER_TEMP']) / 'probe-started'
                    marker.touch()
                    until = time.monotonic() + 3
                    while not marker.with_name('raw-mutated').exists() and time.monotonic() < until:
                        time.sleep(0.005)
                elif os.environ.get('TEST_RAW_TAMPER'):
                    pathlib.Path(os.readlink(sys.argv[4])).write_text('{"a": 20}')
                for function, count in values.items():
                    if wanted in function:
                        print(function + '\\n# Func Hash:\\n1\\n# Num Counters:\\n1\\n# Counter Values:\\n' + str(count))
                if os.environ.get('TEST_CORRUPT_RECORD'):
                    print(wanted + '\\n# Func Hash:\\n1\\n# Num Counters:\\n2\\n# Counter Values:\\n1')
                if os.environ.get('TEST_PROBE_OVERSIZE'):
                    print('x' * 65537)
        ''')
        for name in ('rustc', 'cargo', 'llvm-cov', 'llvm-profdata'):
            path = tools / name
            path.write_text(script)
            path.chmod(0o755)
        self.environment['PATH'] = tools.as_posix() + os.pathsep + self.environment['PATH']

    def test_diagnostics_prioritize_saturated_function_and_retain_only_coverage_map(self):
        self.diagnostic_tools()
        runner = tempfile.TemporaryDirectory()
        self.addCleanup(runner.cleanup)
        self.environment['RUNNER_TEMP'] = runner.name
        self.reports(2**64 - 1)
        with gzip.open(self.directory / 'coverage-regions.json.gz', 'wb') as stream:
            stream.write((self.directory / 'export.json').read_bytes())
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        (target / (self.directory.name + '.profdata')).write_bytes(b'merged')
        (target / (self.directory.name + '-profraw-list')).write_text('raw inventory\n')
        filler = target / 'omg-100-111_0.profraw'
        with filler.open('wb') as stream:
            stream.write(b'{"a_suffix": 1}')
            stream.truncate(128 * 1024 * 1024 - 1024)
        (target / 'omg-200-222_0.profraw').write_text('{"a": 0}')
        relevant = target / 'omg-999-222_0.profraw'
        relevant.write_text('{"a": 19}' + ' ' * 2048)
        executable = target / 'fixture-object'
        executable.write_bytes(b'ELF executable must never be archived or executed')
        (self.directory / 'coverage-region-export.log').write_text(
            'Running `llvm-cov export -object ' + shlex.quote(executable.as_posix()) + '`\n')
        receipt, archive = self.collect()
        with tarfile.open(archive) as bundle:
            self.assertIn(relevant.relative_to(self.directory).as_posix(), bundle.getnames())
            maps = [name for name in bundle.getnames() if name.endswith('.covmap')]
            self.assertEqual(len(maps), 1)
            self.assertEqual(bundle.extractfile(maps[0]).read(), b'coverage map only')
            self.assertNotIn(executable.relative_to(self.directory).as_posix(), bundle.getnames())
        self.assertEqual(receipt['objects'][0]['sha256'], hashlib.sha256(executable.read_bytes()).hexdigest())
        self.assertLessEqual(receipt['captured_input_bytes'], 128 * 1024 * 1024)

    def projection_fixture(self):
        self.diagnostic_tools()
        self.reports(2**63 - 1)
        with gzip.open(self.directory / 'coverage-regions.json.gz', 'wb') as stream:
            stream.write((self.directory / 'export.json').read_bytes())
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        raw = target / 'omg-200-222_0.profraw'
        with raw.open('wb') as stream:
            stream.write(b'{"a": 19}')
            stream.truncate(2048)
        executable = target / 'fixture-object'
        executable.write_bytes(b'ELF fixture')
        (self.directory / 'coverage-region-export.log').write_text(
            'Running `llvm-cov export -object ' + shlex.quote(executable.as_posix()) + '`\n')
        return raw

    def test_diagnostics_keep_exact_projection_when_whole_raw_exceeds_archive_budget(self):
        raw = self.projection_fixture()
        expected = b'a\n# Func Hash:\n1\n# Num Counters:\n1\n# Counter Values:\n19\n'
        receipt, archive = self.collect(input_budget=1024)
        probes = receipt['targeting']['probes']
        self.assertEqual(len(probes), 1)
        self.assertIn('projection', probes[0], 'nonzero counter record was lost with the oversized whole raw')
        probe = probes[0]
        self.assertEqual(probe['raw_sha256'], hashlib.sha256(raw.read_bytes()).hexdigest())
        self.assertEqual(probe['raw_identity']['inode'], raw.stat().st_ino)
        self.assertFalse(probe['changed_during_collection'])
        self.assertTrue(probe['projection'].startswith('profile-projections/'))
        self.assertEqual(Path(probe['projection']).name, '0.proftext')
        self.assertEqual(probe['projection_sha256'], hashlib.sha256(expected).hexdigest())
        self.assertTrue(receipt['targeting']['projection_diagnostic_only'])
        with tarfile.open(archive) as bundle:
            self.assertEqual(bundle.getnames()[0], probe['projection'])
            self.assertEqual(bundle.extractfile(probe['projection']).read(), expected)
            self.assertNotIn(raw.relative_to(self.directory).as_posix(), bundle.getnames())
        self.assertFalse(receipt['complete'])

    def test_diagnostics_refuse_changed_unsafe_or_oversize_projection(self):
        import shutil
        for behavior in ('alter', 'oversize', 'symlink'):
            with self.subTest(behavior=behavior):
                self.projection_fixture()
                (self.directory / 'outside').write_bytes(b'private')
                self.environment['TEST_PROJECTION_TAMPER'] = behavior
                receipt, archive = self.collect(input_budget=1024 * 1024)
                projection = receipt['targeting']['probes'][0]['projection']
                entry = next(entry for entry in receipt['files'] if entry['path'] == projection)
                self.assertIn('omitted', entry)
                self.assertIn('symlinks' if behavior == 'symlink' else 'projection changed', entry['omitted'])
                with tarfile.open(archive) as bundle:
                    self.assertNotIn(projection, bundle.getnames())
                shutil.rmtree(self.directory / 'coverage-diagnostics')
                shutil.rmtree(self.directory / 'target')
                shutil.rmtree(self.directory / 'toolchain')

    def test_diagnostics_refuse_changed_raw_snapshot(self):
        self.projection_fixture()
        self.environment['TEST_RAW_TAMPER'] = '1'
        receipt, archive = self.collect(input_budget=1024)
        probe = receipt['targeting']['probes'][0]
        self.assertTrue(probe['changed_during_collection'])
        self.assertIn('profile shrank', probe['error'])
        self.assertEqual(probe['raw_final_identity']['bytes'], len(b'{"a": 20}'))
        self.assertNotIn('projection', probe)
        with tarfile.open(archive) as bundle:
            self.assertFalse(any(name.endswith('.proftext') for name in bundle.getnames()))

    def test_diagnostics_refuse_mmap_counter_change_without_metadata_change(self):
        import mmap
        import threading
        import time
        raw = self.projection_fixture()
        self.environment['TEST_RAW_TAMPER'] = 'mmap'
        # Freeze observed metadata to isolate content-change detection.
        observer = self.directory / 'frozen-metadata-python'
        observer.write_text(f'#!{sys.executable}\n' + f'raw = {str(raw)!r}\n' + textwrap.dedent('''
            import os, sys
            original = os.stat(raw)
            identity = (original.st_dev, original.st_ino)
            def frozen(info):
                return original if (info.st_dev, info.st_ino) == identity else info
            real_fstat, real_stat, real_lstat = os.fstat, os.stat, os.lstat
            os.fstat = lambda *args, **kwargs: frozen(real_fstat(*args, **kwargs))
            os.stat = lambda *args, **kwargs: frozen(real_stat(*args, **kwargs))
            os.lstat = lambda *args, **kwargs: frozen(real_lstat(*args, **kwargs))
            sys.argv = sys.argv[1:]
            assert sys.argv == ['-']
            exec(compile(sys.stdin.read(), '<stdin>', 'exec'))
        '''))
        observer.chmod(0o755)
        self.environment['TEST_PYTHON'] = str(observer)
        with raw.open('r+b') as stream, mmap.mmap(stream.fileno(), 0) as counters:
            counters[6:8] = b'19'
            counters.flush()
            mutated = []
            def mutate_live_counters():
                until = time.monotonic() + 5
                while not (self.directory / 'probe-started').exists() and time.monotonic() < until:
                    time.sleep(0.005)
                counters[6:8] = b'20'
                counters.flush()
                mutated.append(True)
                (self.directory / 'raw-mutated').touch()
            writer = threading.Thread(target=mutate_live_counters)
            writer.start()
            try:
                receipt, archive = self.collect(input_budget=1024)
            finally:
                writer.join(timeout=6)
        self.assertEqual(mutated, [True])
        self.assertEqual(raw.read_bytes()[6:8], b'20')
        probe = receipt['targeting']['probes'][0]
        self.assertTrue(probe['changed_during_collection'],
                        'live mmap counters changed while observed metadata stayed identical')
        self.assertEqual(probe['raw_identity'], probe['raw_final_identity'])
        self.assertEqual(probe['raw_identity'], probe['raw_path_final_identity'])
        self.assertNotIn('projection', probe)
        with tarfile.open(archive) as bundle:
            self.assertFalse(any(name.endswith('.proftext') for name in bundle.getnames()))

    def test_diagnostics_refuse_corrupt_counter_record(self):
        self.projection_fixture()
        self.environment['TEST_CORRUPT_RECORD'] = '1'
        receipt, _ = self.collect(input_budget=1024)
        probe = receipt['targeting']['probes'][0]
        self.assertIn('invalid counter record', probe['error'])
        self.assertNotIn('projection', probe)

    def test_diagnostics_bound_projection_total_and_probe_output(self):
        import shutil
        for behavior in ('total', 'output'):
            with self.subTest(behavior=behavior):
                self.projection_fixture()
                if behavior == 'output': self.environment['TEST_PROBE_OVERSIZE'] = '1'
                receipt, archive = self.collect(input_budget=1024,
                    projection_budget=1 if behavior == 'total' else None)
                self.assertTrue(receipt['targeting']['errors'])
                self.assertNotIn('projection', receipt['targeting']['probes'][0])
                with tarfile.open(archive) as bundle:
                    self.assertFalse(any(name.endswith('.proftext') for name in bundle.getnames()))
                shutil.rmtree(self.directory / 'coverage-diagnostics')
                shutil.rmtree(self.directory / 'target')
                shutil.rmtree(self.directory / 'toolchain')

    def test_diagnostics_keep_large_main_map_before_smaller_object_maps(self):
        self.diagnostic_tools()
        self.environment['TEST_LARGE_MAP'] = '1'
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        smaller, larger = target / 'aaa-small', target / 'zzz-large'
        smaller.write_bytes(b'small')
        larger.write_bytes(b'BIG' + b'x' * 100)
        (self.directory / 'coverage-region-export.log').write_text(
            'Running `llvm-cov export -object ' + shlex.quote(smaller.as_posix())
            + ' -object ' + shlex.quote(larger.as_posix()) + '`\n')
        receipt, archive = self.collect(input_budget=10 * 1024 * 1024)
        objects = {entry['path']: entry for entry in receipt['objects']}
        with tarfile.open(archive) as bundle:
            self.assertIn(objects[larger.as_posix()]['coverage_map'], bundle.getnames())
            self.assertNotIn(objects[smaller.as_posix()]['coverage_map'], bundle.getnames())
            self.assertEqual(bundle.getmember(objects[larger.as_posix()]['coverage_map']).size,
                             9 * 1024 * 1024)

    def test_diagnostics_report_missing_targeting_tools(self):
        self.reports(2**63 - 1)
        with gzip.open(self.directory / 'coverage-regions.json.gz', 'wb') as stream:
            stream.write((self.directory / 'export.json').read_bytes())
        receipt, _ = self.collect()
        self.assertFalse(receipt['complete'])
        self.assertTrue(receipt['targeting']['errors'])

    def test_diagnostics_keep_observed_nonzero_when_discovery_is_incomplete(self):
        self.diagnostic_tools()
        self.reports(2**63 - 1)
        with gzip.open(self.directory / 'coverage-regions.json.gz', 'wb') as stream:
            stream.write((self.directory / 'export.json').read_bytes())
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        filler = target / 'omg-100-0_0.profraw'
        with filler.open('wb') as stream:
            stream.write(b'{"a_suffix": 1}')
            stream.truncate(128 * 1024 * 1024 - 1024)
        relevant = target / 'omg-200-1_0.profraw'
        relevant.write_text('{"a": 19}' + ' ' * 2048)
        for signature in range(2, 256):
            (target / f'omg-{signature + 300}-{signature}_0.profraw').write_text('{"a_suffix": 1}')
        receipt, archive = self.collect()
        with tarfile.open(archive) as bundle:
            self.assertIn(relevant.relative_to(self.directory).as_posix(), bundle.getnames())
        self.assertFalse(receipt['complete'])
        self.assertTrue(any('budget exhausted' in error for error in receipt['targeting']['errors']))
        probes = receipt['targeting']['probes']
        self.assertLessEqual(len(probes), 256)
        self.assertEqual(sum(probe['path'] == relevant.relative_to(self.directory).as_posix()
                             for probe in probes), 1)

    def test_diagnostics_share_member_budget_across_matching_groups(self):
        self.diagnostic_tools()
        self.reports(2**63 - 1)
        with gzip.open(self.directory / 'coverage-regions.json.gz', 'wb') as stream:
            stream.write((self.directory / 'export.json').read_bytes())
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        filler = target / 'omg-100-0_0.profraw'
        with filler.open('wb') as stream:
            stream.write(b'{"a_suffix": 1}')
            stream.truncate(128 * 1024 * 1024 - 1024)
        for process in range(200, 456):
            (target / f'omg-{process}-1_0.profraw').write_text('{"a": 0}')
        (target / 'omg-500-2_0.profraw').write_text('{"a": 0}')
        relevant = target / 'omg-999-2_0.profraw'
        relevant.write_text('{"a": 19}' + ' ' * 2048)
        receipt, archive = self.collect(member_calls=128)
        with tarfile.open(archive) as bundle:
            self.assertIn(relevant.relative_to(self.directory).as_posix(), bundle.getnames())
        self.assertFalse(receipt['complete'])
        self.assertLessEqual(len(receipt['targeting']['probes']), 256)

    def test_diagnostics_prioritize_native_fixture_profile_names(self):
        self.diagnostic_tools()
        self.reports(2**63 - 1)
        with gzip.open(self.directory / 'coverage-regions.json.gz', 'wb') as stream:
            stream.write((self.directory / 'export.json').read_bytes())
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        filler = target / 'omg-100-0_0.profraw'
        with filler.open('wb') as stream:
            stream.write(b'{"a_suffix": 1}')
            stream.truncate(128 * 1024 * 1024 - 1024)
        (target / 'omg-200-2_0.profraw').write_text('{"a": 0}')
        relevant = target / 'omg-fixture-package_managers_alpm_direct_tests_native_inventory_and_search_match_pacman-49-2_0.profraw'
        relevant.write_text('{"a": 19}' + ' ' * 2048)
        receipt, archive = self.collect()
        with tarfile.open(archive) as bundle:
            self.assertIn(relevant.relative_to(self.directory).as_posix(), bundle.getnames())
        self.assertTrue(any(probe['path'] == relevant.relative_to(self.directory).as_posix()
                            and probe['nonzero'] for probe in receipt['targeting']['probes']))

    def assert_bad_region_report_preserves_diagnostics(self, report):
        self.diagnostic_tools()
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        merged = target / (self.directory.name + '.profdata')
        merged.write_bytes(b'merged')
        raw = target / 'one.profraw'
        raw.write_bytes(b'raw')
        executable = target / 'fixture-object'
        executable.write_bytes(b'ELF fixture')
        (self.directory / 'coverage-region-export.log').write_text(
            'Running `llvm-cov export -object ' + shlex.quote(executable.as_posix()) + '`\n')
        (self.directory / 'coverage-regions.json.gz').write_bytes(report)
        receipt, archive = self.collect()
        self.assertFalse(receipt['complete'])
        self.assertTrue(receipt['targeting']['errors'])
        self.assertEqual(receipt['objects'][0]['sha256'], hashlib.sha256(executable.read_bytes()).hexdigest())
        with tarfile.open(archive) as bundle:
            self.assertEqual(bundle.extractfile(merged.relative_to(self.directory).as_posix()).read(), b'merged')
            self.assertEqual(bundle.extractfile(raw.relative_to(self.directory).as_posix()).read(), b'raw')
            self.assertEqual(bundle.extractfile('coverage-maps/0.covmap').read(), b'coverage map only')

    def test_diagnostics_preserve_evidence_after_corrupt_deflate(self):
        self.assert_bad_region_report_preserves_diagnostics(
            b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x06')

    def test_diagnostics_preserve_evidence_after_malformed_region_unit(self):
        self.assert_bad_region_report_preserves_diagnostics(gzip.compress(b'{"data": [null]}'))

    def test_diagnostics_preserve_evidence_after_malformed_region_function(self):
        self.assert_bad_region_report_preserves_diagnostics(
            gzip.compress(b'{"data": [{"functions": [null]}]}'))

    def test_diagnostics_preserve_evidence_after_excessive_json_nesting(self):
        self.assert_bad_region_report_preserves_diagnostics(
            gzip.compress(b'[' * 100000 + b'0' + b']' * 100000))

    def test_failure_diagnostics_capture_profiles_and_object_identity_without_executable(self):
        self.without_diagnostic_tools()
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        (target / (self.directory.name + '.profdata')).write_bytes(b'merged')
        (target / (self.directory.name + '-profraw-list')).write_text('one.profraw\n')
        (target / 'one.profraw').write_bytes(b'raw profile')
        executable = target / 'fixture-object'
        executable.write_bytes(b'\x7fELF executable remains outside archive')
        self.environment['GITHUB_TOKEN'] = 'diagnostic-secret-must-not-be-recorded'
        (self.directory / 'coverage-region-export.log').write_text(
            'Running `llvm-cov export -object ' + shlex.quote(executable.as_posix()) + '`\n')
        receipt, archive = self.collect()
        self.assertEqual((receipt['source_commit'], receipt['run_id'], receipt['run_attempt']),
                         (self.revision, '123', '2'))
        self.assertEqual(receipt['objects'], [{'path': executable.as_posix(),
            'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(), 'bytes': executable.stat().st_size,
            'changed_during_collection': False}])
        self.assertEqual(receipt['workflow_sha256'], hashlib.sha256((WORKFLOWS / 'coverage.yml').read_bytes()).hexdigest())
        self.assertIn('@sha256:', receipt['image'])
        self.assertEqual(receipt['archive_sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertNotIn(self.environment['GITHUB_TOKEN'], json.dumps(receipt))
        with tarfile.open(archive) as bundle:
            raw = bundle.extractfile('target/llvm-cov-target/one.profraw').read()
            self.assertEqual(raw, b'raw profile')
            files = {item['path']: item for item in receipt['files']}
            self.assertEqual(files['target/llvm-cov-target/one.profraw']['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertFalse(any('fixture-object' in name for name in bundle.getnames()))
        self.assertIn('rustc', receipt['tools'])
        self.assertIn('error', receipt['tools']['rustc'])

    def test_diagnostics_read_colored_export_commands(self):
        self.without_diagnostic_tools()
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        executable = target / 'fixture object'
        executable.write_bytes(b'\x7fELF colored-log fixture')
        (self.directory / 'coverage-region-export.log').write_text(
            '\x1b[1;32mRunning\x1b[0m `llvm-cov export -object '
            + shlex.quote(executable.as_posix()) + '`\n')
        receipt, _ = self.collect()
        self.assertEqual(receipt['objects'], [{'path': executable.as_posix(),
            'sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'bytes': executable.stat().st_size, 'changed_during_collection': False}])
        self.assertIn('error', receipt['tools']['rustc'])

    def test_diagnostics_bound_input_and_report_missing_and_symlink_profiles(self):
        target = self.directory / 'target/llvm-cov-target'
        target.mkdir(parents=True)
        (target / 'one.profraw').write_bytes(b'raw')
        with (target / 'oversize.profraw').open('wb') as stream:
            stream.truncate(128 * 1024 * 1024 + 1)
        outside = self.directory / 'private.txt'
        outside.write_text('must not be archived')
        try:
            (target / 'linked.profraw').symlink_to(outside)
        except OSError as error:
            self.skipTest(f'symlink fixture unavailable: {error}')
        receipt, archive = self.collect()
        self.assertFalse(receipt['complete'])
        self.assertLessEqual(receipt['captured_input_bytes'], 128 * 1024 * 1024)
        self.assertLessEqual(receipt['admitted_input_bytes'], 128 * 1024 * 1024)
        files = {Path(item['path']).name: item for item in receipt['files']}
        self.assertIn('budget', files['oversize.profraw']['omitted'])
        self.assertIn('symlinks', files['linked.profraw']['omitted'])
        self.assertIn('omitted', files[self.directory.name + '.profdata'])
        with tarfile.open(archive) as bundle:
            self.assertEqual(bundle.getnames(), ['target/llvm-cov-target/one.profraw'])

    def test_missing_profiles_are_explicit_and_uploads_do_not_mask_validation(self):
        receipt, _ = self.collect()
        self.assertTrue(receipt['raw_profiles_missing'])
        self.assertFalse(receipt['complete'])
        text = (WORKFLOWS / 'coverage.yml').read_text()
        for name in ('Collect invalid coverage diagnostics', 'Preserve invalid coverage diagnostics'):
            block = text.split(f'      - name: {name}\n', 1)[1].split('\n      - ', 1)[0]
            self.assertIn("!cancelled() && steps.coverage_sanity.outcome == 'failure'", block)
        validator = text.split('      - name: Validate local coverage evidence\n', 1)[1].split('\n      - ', 1)[0]
        self.assertNotIn('continue-on-error', validator)
        for name in ('lcov', 'regions', 'comparison', 'diagnostics'):
            self.assertIn('name: coverage-' + name + '-${{ github.run_id }}-${{ github.run_attempt }}', text)


if __name__ == '__main__':
    unittest.main()

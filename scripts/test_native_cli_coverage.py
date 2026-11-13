"""The native coverage job must execute its supplemental CLI producer."""

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
SPEC = importlib.util.spec_from_file_location('native_cli_coverage',
                                             ROOT / 'scripts/native-cli-coverage.py')
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)


class HostedProducer(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'QEMU transport preflight requires POSIX Bash')
    def test_native_coverage_transport_reaches_preflight_with_bound_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            inputs = owner / 'inputs'
            binaries = inputs / 'bin'
            binaries.mkdir(parents=True)
            artifacts = {}
            for role in PRODUCER.ROLES:
                executable = binaries / role
                executable.write_bytes(b'preflight-only fixture, never executed\n')
                executable.chmod(0o755)
                artifacts[role] = dict(path='/compiled/' + role, bytes=executable.stat().st_size,
                                       sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
            manifest = dict(source_commit=commit,
                            producer_sha256=PRODUCER.sha(ROOT / 'scripts/native-cli-coverage.py'),
                            artifacts=artifacts)
            (inputs / 'native-cli-manifest.json').write_text(json.dumps(manifest))
            fake_tools = owner / 'tools'
            fake_tools.mkdir()
            docker = fake_tools / 'docker'
            docker.write_text('#!/bin/sh\nprintf "%s\n" "$*" >> "$FAKE_DOCKER_LOG"\nexit 7\n')
            docker.chmod(0o755)
            staged = owner / 'staged'
            staged.mkdir()
            calls = owner / 'docker-calls'
            environment = dict(os.environ, PATH=str(fake_tools) + os.pathsep + os.environ['PATH'],
                               OMG_QEMU_ALLOW_NO_KVM='1', FAKE_DOCKER_LOG=str(calls))
            benchmark = os.environ.get('OMG_NATIVE_BENCHMARK_UNDER_TEST', str(ROOT / 'scripts/benchmark-qemu.sh'))
            args = [BASH, benchmark, '--distro', 'arch', '--arch', 'x86_64', '--release', 'v0.1.224',
                    '--staged-dir', str(staged), '--native-cli-coverage-dir', str(inputs),
                    '--evidence-dir', str(owner / 'evidence')]
            result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertTrue(calls.is_file(), 'Closed native transport was not admitted to its Docker preflight')
            self.assertEqual(calls.read_text(), 'version --format {{.Server.Version}}\n')
            reports = list((owner / 'evidence').glob('run-*/results.json'))
            self.assertEqual(len(reports), 1)
            self.assertEqual(json.loads(reports[0].read_text())[0]['case_id'], 'qemu-arch-native-cli-coverage')
            calls.unlink()
            (binaries / 'cli').write_bytes(b'tampered')
            refused = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse(calls.exists(), 'Unbound executable bytes reached Docker')

    @unittest.skipIf(os.name == 'nt', 'Controller launch uses POSIX Bash')
    def test_native_controller_reaps_exited_qemu_without_changing_other_modes(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        launch = source[source.index('controller_work=$work\n'):
                        source.index('if [[ "$restrict_egress" == true ]]; then', source.index('controller_work=$work\n'))]
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            docker = owner / 'docker'
            docker.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                              'if sys.argv[1] == "run":\n'
                              ' with open(os.environ["CAPTURE"], "w") as f: json.dump(sys.argv[2:],f)\n'
                              ' print("unit-controller")\n'
                              'elif sys.argv[1] == "inspect":\n'
                              ' print(json.dumps([dict(Type="bind", Source=os.environ["WORK"], Destination=os.environ["WORK"], RW=True)]))\n')
            docker.chmod(0o755)
            capture = owner / 'launch.json'
            for native in ('/admitted-fixture', ''):
                prefix = 'work="$WORK"; here="$PRODUCER_DIRECTORY"; controller=unit-controller; controller_image=fixture; docker_device_args=(); native_cli_coverage_dir="$NATIVE";\n'
                result = subprocess.run([BASH, '-euo', 'pipefail', '-c', prefix + launch],
                                        env=dict(os.environ, PATH=str(owner) + os.pathsep + os.environ['PATH'],
                                                 WORK=str(owner), PRODUCER_DIRECTORY=str(ROOT / 'scripts'),
                                                 CAPTURE=str(capture), NATIVE=native),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual('--init' in json.loads(capture.read_text()), bool(native),
                                 'The native controller must reap QEMU after clean poweroff')

    def test_signed_fixture_package_has_native_signature_preflight_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = PRODUCER.fixture_package(Path(directory), 'fixture-app', '3-1',
                                               'usr/share/fixture/value', b'updated', ('fixture-dep>=1-1',))
            with tarfile.open(archive) as package:
                metadata = package.extractfile('.PKGINFO').read().decode()
                self.assertIn('packager = ', metadata)
                self.assertIn('depend = fixture-dep>=1-1\n', metadata)
                self.assertEqual(package.extractfile('usr/share/fixture/value').read(), b'updated')
                self.assertIsNotNone(package.getmember('.MTREE'))

    def test_guest_archive_transport_extracts_only_bounded_regular_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            archive = owner / 'returned.tar'
            with tarfile.open(archive, 'w') as tar:
                member = tarfile.TarInfo('cli/real.log')
                value = b'actual captured evidence\n'
                member.size = len(value)
                tar.addfile(member, io.BytesIO(value))
            destination = owner / 'evidence'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                     'unpack', '--archive', str(archive), '--directory', str(destination)],
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((destination / 'cli/real.log').read_bytes(), value)
            self.assertFalse((destination / 'cli/real.log').is_symlink())

    def test_guest_archive_transport_refuses_escape_links_devices_and_duplicates(self):
        cases = [('../escape', tarfile.REGTYPE, ''), ('/absolute', tarfile.REGTYPE, ''),
                 ('cli/link', tarfile.SYMTYPE, '../../escape'),
                 ('cli/hard', tarfile.LNKTYPE, 'cli/real.log'), ('cli/fifo', tarfile.FIFOTYPE, '')]
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            sentinel = owner / 'escape'
            sentinel.write_bytes(b'unchanged')
            for index, (name, kind, target) in enumerate(cases):
                archive = owner / ('bad-' + str(index) + '.tar')
                with tarfile.open(archive, 'w') as tar:
                    member = tarfile.TarInfo(name)
                    member.type, member.linkname = kind, target
                    tar.addfile(member)
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                         'unpack', '--archive', str(archive),
                                         '--directory', str(owner / ('evidence-' + str(index)))],
                                        text=True, capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertEqual(sentinel.read_bytes(), b'unchanged')
            archive = owner / 'duplicate.tar'
            with tarfile.open(archive, 'w') as tar:
                for _ in range(2):
                    tar.addfile(tarfile.TarInfo('same'))
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                     'unpack', '--archive', str(archive), '--directory', str(owner / 'duplicate')],
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_controller_mapping_uses_the_most_specific_writable_bind(self):
        mounts = [
            {'Type': 'bind', 'Source': '/home/runner/work', 'Destination': '/__w', 'RW': True},
            {'Type': 'bind', 'Source': '/runner/temp', 'Destination': '/__w/_temp', 'RW': True},
        ]
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                 'controller-path', '--path', '/__w/_temp/owned-native/run-one'],
                                input=json.dumps(mounts), text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '/runner/temp/owned-native/run-one\n')

    def test_controller_mapping_refuses_unmapped_ambiguous_or_unsafe_paths(self):
        writable = {'Type': 'bind', 'Source': '/runner/temp', 'Destination': '/__w/_temp', 'RW': True}
        cases = [
            ('/__w/_temporary/run', [writable]),
            ('/__w/_temp/../outside', [writable]),
            ('/__w/_temp/run,other', [writable]),
            ('/__w/_temp/run', [dict(writable, RW=False)]),
            ('/__w/_temp/run', [dict(writable, Type='volume')]),
            ('/__w/_temp/run', [writable, dict(writable, Source='/different')]),
            ('/__w/_temp/run', [dict(writable, Source='relative')]),
        ]
        for path, mounts in cases:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                     'controller-path', '--path', path], input=json.dumps(mounts),
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0, path)
            self.assertFalse(result.stdout, 'Refused mount mappings must not produce a usable host path')

    def test_native_image_installs_supplemental_runtime_dependencies(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        image = workflow.split("docker build --tag omg-coverage-sandbox - <<'DOCKERFILE'", 1)[1]
        image = image.split('DOCKERFILE', 1)[0]
        install = next(line.strip() for line in image.splitlines() if line.strip().startswith('RUN pacman '))
        packages = set(shlex.split(install.split('&&', 1)[0]))
        required = {'git', 'make', 'jq', 'diffutils'}
        self.assertFalse(required - packages,
                         'Native supplemental fixtures lack runtime packages: ' + ', '.join(sorted(required - packages)))

    @unittest.skipIf(os.name == 'nt', 'Native prerequisite shell requires POSIX Bash')
    def test_native_runtime_preflight_reports_all_missing_commands_and_refuses(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        line = next(line for line in script.splitlines() if 'prerequisites.txt' in line)
        args = shlex.split(line)
        self.assertEqual(args[:3], ['ordinary', 'bash', '-c'])
        loop = args[3]
        self.assertIn('git make jq cmp', loop)
        missing = ['omg-fixture-missing-tool-a', 'omg-fixture-missing-tool-b']
        for tools, expected in [('true printf', 0), ('true ' + missing[0] + ' printf ' + missing[1], 1)]:
            result = subprocess.run([BASH, '-euo', 'pipefail', '-c', loop.replace('git make jq cmp', tools)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ['true', 'printf'])
            if expected:
                for tool in missing:
                    self.assertIn('Missing native fixture command: ' + tool, result.stderr)

    def test_private_loopback_fixture_has_required_network_capability(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        native = workflow.split('      - name: Cover sandbox descendant cancellation\n', 1)[1]
        create = native.split('container=$(docker create ', 1)[1].split("/bin/bash -euo pipefail -c '", 1)[0]
        self.assertIn('--cap-add NET_ADMIN', create,
                      'Private network namespace cannot raise loopback without NET_ADMIN')
        self.assertIn('--network none', create)

    def test_supplemental_cli_execution_precedes_the_state_mount(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        native = workflow.split('      - name: Cover sandbox descendant cancellation\n', 1)[1]
        native = native.split('\n      - name:', 1)[0]
        self.assertIn('python3 scripts/native-cli-coverage.py prepare', native,
                      'Hosted native coverage omits the six-artifact supplemental CLI producer')
        self.assertIn('--native-cli-coverage-dir', native)
        self.assertNotIn('python /native-cli-coverage.py run', native)
        self.assertIn('python3 scripts/native-cli-coverage.py verify', native)
        self.assertLess(native.index('--native-cli-coverage-dir'),
                        native.index('docker start --attach'))

    def test_missing_runtime_directory_keeps_the_lock_private(self):
        names = {'omarchy-runtime-fallback', 'omarchy-runtime-foreign-lock'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys(),
                        'Native coverage omits session runtime fallback and foreign lock refusal')
        self.assertEqual(PRODUCER.OMARCHY_CASES['omarchy-runtime-fallback'].lock_location, 'temporary')
        self.assertEqual(PRODUCER.OMARCHY_CASES['omarchy-runtime-foreign-lock'].lock_location, 'foreign')
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('runtime_environment=()', script)
        self.assertIn('coordination_lock=/tmp/omarchy-update.lock', script)
        self.assertIn('flock --nonblock 9 9< \"$coordination_lock\"', script)
        self.assertIn('foreign fallback lock was preserved', script)

    def test_authorization_refresh_cases_require_real_sudo_audit_records(self):
        names = {'omarchy-authorization-refresh', 'omarchy-authorization-denied'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys(),
                        'The real authorization keeper is never exercised past its interval')
        for stage in names:
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertEqual(case.scene, 'authorization-hold')
            self.assertIn(case.authorization, ('refresh', 'denied'))
            self.assertTrue(case.native_committed)
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('omarchy-update-dev:authorization-hold) sleep 65', script)
        self.assertIn("producer['authorization_audit']", script)
        self.assertIn('!/usr/bin/true', script)

    def test_attended_reboot_cases_require_prompt_and_terminal_receipts(self):
        names = {'omarchy-reboot-decline', 'omarchy-reboot-accept', 'omarchy-reboot-failure'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys(),
                        'Native coverage does not exercise the attended reboot prompt')
        for stage in names:
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertIn(case.reboot_answer, ('y', 'n'))
            self.assertTrue(case.native_committed)
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('pty.fork()', script)
        self.assertIn('signal.SIGWINCH', script)
        self.assertIn("b'Reboot now?'", script)

    def test_declared_optional_and_required_helper_cases_execute_the_real_cli(self):
        required = {'omarchy-snapshot-missing', 'omarchy-snapshot-unsupported',
                    'omarchy-required-helper-missing'}
        self.assertTrue(required <= PRODUCER.OMARCHY_CASES.keys(),
                        'Native lifecycle coverage omits missing/unsupported helper scenarios')
        script = PRODUCER.omarchy_guest_script()
        stages = script.split('for stage in ', 1)[1].split('; do', 1)[0].split()
        self.assertEqual(stages, list(PRODUCER.OMARCHY_CASES),
                         'Every declared scenario must execute once in declaration order')
        for stage in required:
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertIn(stage + ')', script)
            self.assertIn('OMARCHY_FIXTURE_SCENE="$scene"', script)
            if case.absent_helper:
                self.assertIn(case.absent_helper, script)

    def test_generated_omarchy_cases_use_the_real_cli_in_a_private_namespace(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        self.assertIn("OMG_OMARCHY_NAMESPACE", script)
        self.assertIn('ID=omarchy', script)
        self.assertIn('mount --bind "$fixture/release" /etc/os-release', script)
        self.assertIn('omarchy-success', script)
        self.assertIn('omarchy-vendor-failure', script)
        self.assertIn('omarchy-migration-refusal', script)
        self.assertIn('test -u /usr/bin/sudo', script)
        self.assertNotIn('mount --bind "$fixture/sudo"', script)
        self.assertIn('exec /omg-extra-bin/cli update', script)

    @unittest.skipIf(os.name == 'nt', 'Guest sentinel scripts require POSIX Bash')
    def test_package_helper_sentinels_refuse_instead_of_faking_success(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'bin').mkdir()
            trace = root / 'helpers.tsv'
            environment = dict(os.environ, OMARCHY_PATH=str(root),
                               OMARCHY_FIXTURE_CASE='omarchy-success', OMARCHY_HELPER_TRACE=str(trace))
            for name in ('omarchy-update-pkg-prune', 'omarchy-update-keyring',
                         'omarchy-update-system-pkgs', 'omarchy-update-orphan-pkgs',
                         'pacman', 'pacman-key', 'paccache', 'yay', 'aura', 'paru'):
                program = root / 'bin' / name
                program.write_text(helper)
                program.chmod(0o755)
                result = subprocess.run([str(program)], env=environment, text=True,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 99,
                                 name + ' must refuse with the package sentinel status: ' + result.stderr)
                self.assertEqual(trace.read_text().splitlines()[-1], name,
                                 'Forbidden execution must leave a real invocation record')

    @unittest.skipIf(os.name == 'nt', 'Guest lifecycle helpers require POSIX Bash')
    def test_lifecycle_helper_refusals_have_real_exit_statuses(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'bin').mkdir()
            for name, scene, expected in [('omarchy-snapshot', 'snapshot-unsupported', 127),
                                          ('omarchy-system', 'reboot-failure', 7)]:
                program = root / 'bin' / name
                program.write_text(helper)
                result = subprocess.run([BASH, str(program)],
                    env=dict(os.environ, OMARCHY_PATH=str(root), OMARCHY_FIXTURE_SCENE=scene,
                             OMARCHY_FIXTURE_CASE='inert-lifecycle-control',
                             OMARCHY_HELPER_TRACE=str(root / 'helpers.tsv')),
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_inert_omarchy_helpers_record_arguments_and_reject_external_aur(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'bin').mkdir()
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-success',
                       OMARCHY_HELPER_TRACE=str(trace), OMARCHY_PATH=str(root))
            for name, args, source, status in (
                    ('omarchy-update-dev', [], helper, 0),
                    ('omarchy-shell', ['-q', 'omarchy.system-update', 'clear'], helper, 0),
                    ('yay', ['-Sua'], helper, 99)):
                path = root / 'bin' / name
                path.write_text(source)
                result = subprocess.run([BASH, str(path), *args], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, status, result.stderr)
            self.assertEqual(trace.read_text().splitlines(), [
                'omarchy-update-dev', 'omarchy-shell\t-q\tomarchy.system-update\tclear',
                'yay\t-Sua'])

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_inert_omarchy_helper_rejects_mismatched_runtime_before_trace(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / 'checkout'
            (checkout / 'bin').mkdir(parents=True)
            other = root / 'other-checkout'
            other.mkdir()
            path = checkout / 'bin/omarchy-update-dev'
            path.write_text(helper)
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-success',
                       OMARCHY_HELPER_TRACE=str(trace), OMARCHY_PATH=str(checkout))
            accepted = subprocess.run([BASH, str(path)], env=env, text=True, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(trace.read_text(), 'omarchy-update-dev\n')
            trace.unlink()
            env['OMARCHY_PATH'] = str(other)
            refused = subprocess.run([BASH, str(path)], env=env, text=True, capture_output=True)
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertIn('OMARCHY_PATH does not match this Omarchy command.', refused.stderr)
            self.assertFalse(trace.exists(), 'Rejected runtime must not execute a stage')

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_foreign_optional_helper_marks_execution_before_source_guard(self):
        script = PRODUCER.omarchy_guest_script()
        stage = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        prefix = script.split("<<'OMG_FOREIGN_OMARCHY_STAGE_PREFIX'\n", 1)[1].split(
            '\nOMG_FOREIGN_OMARCHY_STAGE_PREFIX', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'installed').mkdir()
            (root / 'foreign/bin').mkdir(parents=True)
            helper = root / 'foreign/bin/omarchy-snapshot'
            helper.write_text(prefix + '\n' + stage.split('\n', 1)[1])
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-optional-failures',
                       OMARCHY_HELPER_TRACE=str(trace), OMARCHY_PATH=str(root / 'installed'))
            result = subprocess.run([BASH, str(helper), 'create'], env=env,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('OMARCHY_PATH does not match this Omarchy command.', result.stderr)
            self.assertEqual(Path(str(trace) + '.unexpected').read_text(),
                             'foreign helper executed: ' + str(helper) + '\n')
            self.assertFalse(trace.exists(), 'Foreign helper must fail before normal stage trace')

    @unittest.skipIf(os.name == 'nt', 'Native sync archive fixture requires POSIX tar')
    def test_omarchy_fixture_database_uses_supported_compression(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = PRODUCER.fixture_package(Path(directory), 'fixture', '1-1',
                                               'usr/share/fixture/value', b'data')
            with tarfile.open(archive, 'r:gz') as package:
                self.assertEqual(package.extractfile('usr/share/fixture/value').read(), b'data')


    def test_generated_guest_program_is_one_valid_bash_program(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        result = subprocess.run([BASH, '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('unshare --mount --net --fork', script)
        self.assertIn('test "$(id -u)" -ne 0', script)
        self.assertIn('test "$(id -u)" = 0', script)
        self.assertNotIn('systemd-detect-virt', script)


def evidence_fixture(root):
    evidence, profiles = root / 'evidence', root / 'profiles'
    evidence.mkdir()
    profiles.mkdir()
    artifacts = {role: dict(path='/build/' + role, sha256='a' * 64, bytes=16)
                 for role in PRODUCER.ROLES}
    (evidence / 'all-stages-pass.txt').write_text('PASS\n')
    rows = ['\t'.join(row) for row in PRODUCER.CASES]
    (evidence / 'expected-tests.tsv').write_text('\n'.join(rows) + '\n')
    (evidence / 'passed.tsv').write_text('\n'.join(row + '\tPASS' for row in rows) + '\n')
    (evidence / 'process-checks.tsv').write_text('\n'.join(stage + '\t0' for stage in PRODUCER.PROCESS_STAGES) + '\n')
    for name in ('db-before.txt', 'db-after.txt'):
        (evidence / name).write_text('unchanged private guest DB\n')
    (evidence / 'identity.txt').write_text('actual_id=arch ordinary_uid=65534 root_uid=0\n')
    (evidence / 'artifacts.sha256').write_text(''.join(
        f"{a['sha256']}  /omg-extra-bin/{r}\n" for r, a in artifacts.items()))
    for role in PRODUCER.ROLES:
        (evidence / f'abi-{role}.txt').write_text('all dependencies present\n')
    for role, names in PRODUCER.TESTS.items():
        (evidence / f'registry-{role}.txt').write_text(''.join(name + ': test\n' for name in names))
    for stage in PRODUCER.STAGES:
        (profiles / f'omg-extra-{stage}-123-100_0.profraw').write_bytes(bytes.fromhex('8172666f72706cff') + b'fixture')
    for stage, role, name in PRODUCER.CASES:
        log = f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        if role == 'cli-unit':
            log += '[extra-root-test] uid=0\n'
        else:
            log += '[native-arch-fixture] uid=65534 actual_id=arch\n'
            (profiles / f'omg-extra-{stage}-124-200_0.profraw').write_bytes(bytes.fromhex('8172666f72706cff') + b'fixture')
        if role == 'comprehensive':
            log += '[native-inventory-coverage] unavailable_rows=0;\n'
        (evidence / f'{stage}.log').write_text(log)
    (evidence / 'inventory').mkdir()
    (evidence / 'inventory/index.tsv').write_text('header\n' + ''.join(
        f'{name}\tcli\targs\t0\t0\tnone\tavailable\n'
        for name in ('why', 'why-reverse', 'size', 'size-tree', 'blame')))
    (evidence / 'daemon.log').write_text('[extra-daemon] startup_socket=ready uid=65534\n'
                                       '[extra-daemon] sigterm_exit=0 socket_removed=yes\n')
    for stage, case in PRODUCER.OMARCHY_CASES.items():
        status, helpers = case.exit_status, case.helpers
        (evidence / f'{stage}-exit.txt').write_text(f'{status}\n')
        (evidence / f'{stage}-helpers.tsv').write_text(''.join(row + '\n' for row in helpers))
        if helpers:
            (evidence / f'{stage}-coordination.txt').write_text(
                'released private lock; owned transcript mode=600\n')
            (evidence / f'{stage}-transcript.log').write_text('OMG Omarchy update started\nOMG Omarchy update finished: exit status: 0\n')
        if case.native_committed:
            (evidence / f'{stage}-native-state.json').write_text(json.dumps(dict(status='PASS_SIGNED_NATIVE_STATE')))
        if case.lock_location == 'foreign':
            (evidence / f'{stage}-layout.txt').write_text(
                'foreign fallback lock was preserved; transcript unchanged\n')
        if case.authorization:
            authorization_log = evidence / f'{stage}-authorization.log'
            authorization_log.write_text(
                'Nov 13 23:59:30 : nobody : USER=root ;\n    COMMAND=/usr/bin/true\n'
                + 'Nov 14 00:00:30 : nobody : '
                + ('command not allowed ; ' if case.authorization == 'denied' else '')
                + 'USER=root ;\n    COMMAND=/usr/bin/true\n')
            (evidence / f'{stage}-authorization.json').write_text(json.dumps(dict(
                initial_authorizations=1, refresh_count=1, refresh_after_seconds=60,
                denied=case.authorization == 'denied', log_uid=0,
                log_sha256=PRODUCER.sha(authorization_log))))
        if case.reboot_answer:
            (evidence / f'{stage}-interaction.json').write_text(json.dumps(dict(
                prompt_observed=True, answer=case.reboot_answer, resize_sent=1,
                cli_exit_code=case.exit_status)))
        if case.absent_helper:
            (evidence / f'{stage}-layout.txt').write_text(
                'absent helper restored after genuine CLI execution\n')
        if stage == 'omarchy-optional-failures':
            (evidence / f'{stage}-layout.txt').write_text(
                'foreign optional helpers never executed; original helpers restored\n')
        log = {
            'omarchy-success': '| System is up to date',
            'omarchy-runtime-fallback': '| System is up to date',
            'omarchy-runtime-foreign-lock': 'Omarchy coordination file must be single-link',
            'omarchy-authorization-refresh': '| System is up to date',
            'omarchy-authorization-denied': '| System is up to date\nOmarchy update authorization refresh stopped',
            'omarchy-reboot-decline': '| System is up to date\nReboot now?',
            'omarchy-reboot-accept': '| System is up to date\nReboot now?',
            'omarchy-reboot-failure': '| System is up to date\nReboot now?\nOmarchy reboot failed',
            'omarchy-snapshot-missing': '| System is up to date',
            'omarchy-snapshot-unsupported': '| System is up to date',
            'omarchy-required-helper-missing': 'Omarchy update did not complete: omarchy-update-dev',
            'omarchy-optional-failures': '| System is up to date\n! Continuing without a snapshot\n! Some mise tools could not be updated',
            'omarchy-vendor-failure': 'Omarchy update did not complete',
            'omarchy-declined': 'declined',
            'omarchy-migration-refusal': 'external package helper',
            'omarchy-unsupported-mode': 'complete update lifecycle',
            'omarchy-invalid-transport': 'Incomplete Omarchy update transport',
        }[stage]
        (evidence / f'{stage}.log').write_text(log)
    return evidence, profiles, artifacts


class SupplementalEvidence(unittest.TestCase):
    def test_authorization_audit_requires_initial_success_and_one_real_interval(self):
        initial = 'Nov 13 23:59:30 : nobody : USER=root ;\n    COMMAND=/usr/bin/true\n'
        refresh = 'Nov 14 00:00:30 : nobody : USER=root ;\n    COMMAND=/usr/bin/true\n'
        observation = PRODUCER.authorization_audit(initial + refresh)
        self.assertEqual(observation, dict(initial_authorizations=1, refresh_count=1,
                                          refresh_after_seconds=60, denied=False))
        denied = ('Nov 14 00:00:30 : nobody : command not allowed ; PWD=/home/bench ;\n'
                  '    USER=root ; COMMAND=/usr/bin/true\n')
        self.assertEqual(PRODUCER.authorization_audit(initial + denied),
                         dict(initial_authorizations=1, refresh_count=1,
                              refresh_after_seconds=60, denied=True))
        for text in (initial, initial + refresh + refresh,
                     initial + refresh.replace('/usr/bin/true', '/usr/bin/true-extra'),
                     initial + refresh.replace('00:00:30', '23:59:31'),
                     initial.replace('nobody', 'root') + refresh,
                     initial.replace('USER=root', 'USER=nobody') + refresh,
                     initial.replace('USER=root', 'command not allowed ; USER=root') + refresh):
            with self.subTest(text=text), self.assertRaises(ValueError):
                PRODUCER.authorization_audit(text)

    def test_complete_observed_selection_and_processes_have_a_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            files = PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            receipt = json.loads((evidence / 'verification.json').read_text())
            self.assertEqual(len(receipt['tests']), 14)
            self.assertEqual(len(receipt['process_checks']), 22)
            self.assertEqual(len(files), len(receipt['profiles']))

    def test_forged_omarchy_helper_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            (evidence / 'omarchy-success-helpers.tsv').write_text('yay\t-Sua\n')
            with self.assertRaises(ValueError):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            self.assertFalse((evidence / 'verification.json').exists())

    def test_incomplete_or_misleading_guest_evidence_is_refused(self):
        mutations = {
            'missing-stage': lambda e, p: (p / 'omg-extra-daemon-123-100_0.profraw').unlink(),
            'missing-child': lambda e, p: (p / 'omg-extra-test-01-123-100_0.profraw').unlink(),
            'bad-raw-magic': lambda e, p: (p / 'omg-extra-daemon-123-100_0.profraw').write_bytes(b'wrong'),
            'empty-profile': lambda e, p: (p / 'omg-extra-daemon-123-100_0.profraw').write_bytes(b''),
            'skip-marker': lambda e, p: (e / 'test-01.log').write_text((e / 'test-01.log').read_text() + '[omg-skip]\n'),
            'zero-tests': lambda e, p: (e / 'test-01.log').write_text('test result: ok. 0 passed; 0 failed; 0 ignored;\n'),
            'changed-db': lambda e, p: (e / 'db-after.txt').write_text('changed'),
            'no-daemon-cleanup': lambda e, p: (e / 'daemon.log').write_text('[extra-daemon] startup_socket=ready uid=65534'),
            'duplicate-result': lambda e, p: (e / 'passed.tsv').write_text((e / 'passed.tsv').read_text() * 2),
            'missing-process': lambda e, p: (e / 'process-checks.tsv').write_text('cli-q\t0\n'),
            'wrong-artifact': lambda e, p: (e / 'artifacts.sha256').write_text('different'),
            'llvm-warning': lambda e, p: (e / 'cli-q.log').write_text('LLVM Profile Warning: write failed'),
            'omarchy-failed-status': lambda e, p: (e / 'omarchy-success-exit.txt').write_text('1\n'),
            'omarchy-skipped-aur': lambda e, p: (e / 'omarchy-success.log').write_text('only vendor commands ran'),
            'omarchy-false-transcript': lambda e, p: (e / 'omarchy-success-transcript.log').write_text('fake output'),
            'omarchy-no-update-result': lambda e, p: (e / 'omarchy-success.log').write_text('No update result was emitted'),
            'omarchy-foreign-helper-executed': lambda e, p: (e / 'omarchy-optional-failures-layout.txt').write_text('foreign helper executed'),
            'omarchy-hidden-optional-warnings': lambda e, p: (e / 'omarchy-optional-failures.log').write_text('| System is up to date'),
            'omarchy-old-logger': lambda e, p: (e / 'omarchy-success-transcript.log').write_text('Script started on fixture\nScript done on fixture\n'),
            'omarchy-no-cleanup': lambda e, p: (e / 'omarchy-success-coordination.txt').write_text('lock still held'),
            'omarchy-no-refusal': lambda e, p: (e / 'omarchy-migration-refusal.log').write_text('failed for another reason'),
            'foreign-fallback-was-overwritten': lambda e, p: (e / 'omarchy-runtime-foreign-lock-layout.txt').write_text('overwritten'),
            'foreign-fallback-no-ownership-diagnostic': lambda e, p: (e / 'omarchy-runtime-foreign-lock.log').write_text('failed for another reason'),
            'no-real-authorization-refresh': lambda e, p: (e / 'omarchy-authorization-refresh-authorization.json').write_text('{}'),
            'authorization-log-changed': lambda e, p: (e / 'omarchy-authorization-refresh-authorization.log').write_text('different'),
            'authorization-refusal-hidden': lambda e, p: (e / 'omarchy-authorization-denied.log').write_text('System is up to date'),
            'no-attended-reboot-prompt': lambda e, p: (e / 'omarchy-reboot-accept-interaction.json').write_text('{}'),
            'reboot-failure-hidden': lambda e, p: (e / 'omarchy-reboot-failure.log').write_text('System is up to date\nReboot now?'),
            'missing-helper-not-restored': lambda e, p: (e / 'omarchy-snapshot-missing-layout.txt').write_text('still absent'),
            'unsupported-snapshot-skips-native': lambda e, p: (e / 'omarchy-snapshot-unsupported-native-state.json').write_text('{"status":"UNCOMMITTED"}'),
            'required-helper-false-success': lambda e, p: (e / 'omarchy-required-helper-missing-exit.txt').write_text('0\n'),
            'omarchy-wrong-cli': lambda e, p: (p / 'omg-extra-omarchy-success-123-100_0.profraw').rename(
                p / 'omg-extra-omarchy-success-123-200_0.profraw'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                evidence, profiles, artifacts = evidence_fixture(Path(directory))
                mutate(evidence, profiles)
                with self.assertRaises(ValueError):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                self.assertFalse((evidence / 'verification.json').exists())


class ArtifactAdmission(unittest.TestCase):
    def make_target(self, root):
        deps = root / 'debug/deps'
        deps.mkdir(parents=True)
        paths = ['debug/omg', 'debug/omgd'] + [f'debug/deps/{prefix}-' + '1' * 16
                 for prefix in ('coverage_14', 'arch_cli_contracts', 'cli_comprehensive', 'omg')]
        for name in paths:
            path = root / name
            path.write_bytes(name.encode())
            path.chmod(0o755)
        os.link(root / 'debug/omg', deps / ('omg-' + '2' * 16))

    def test_cli_unit_selection_excludes_the_normal_cli_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_target(root)
            with patch.object(PRODUCER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, '__llvm_covmap __llvm_prf_cnts')):
                manifest = PRODUCER.prepare(root, 'b' * 40)
            self.assertEqual(manifest['artifacts']['cli-unit']['path'],
                             str(root / 'debug/deps' / ('omg-' + '1' * 16)))

    def test_stale_second_test_harness_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_target(root)
            extra = root / 'debug/deps' / ('omg-' + '3' * 16)
            extra.write_bytes(b'stale harness')
            extra.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'exactly one instrumented harness for cli-unit'):
                PRODUCER.prepare(root, 'b' * 40)

    def test_manifest_refuses_changed_producer_source_or_incomplete_artifacts(self):
        for scenario in ('complete', 'wrong-producer', 'missing-artifact', 'invalid-commit', 'invalid-size'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_target(root)
                with patch.object(PRODUCER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 0, '__llvm_covmap __llvm_prf_cnts')):
                    manifest = PRODUCER.prepare(root, 'b' * 40)
                if scenario == 'wrong-producer':
                    manifest['producer_sha256'] = '0' * 64
                elif scenario == 'missing-artifact':
                    del manifest['artifacts']['cli-unit']
                elif scenario == 'invalid-commit':
                    manifest['source_commit'] = 'main'
                elif scenario == 'invalid-size':
                    manifest['artifacts']['cli-unit']['bytes'] = False
                path = root / 'manifest.json'
                path.write_text(json.dumps(manifest))
                if scenario == 'complete':
                    self.assertEqual(PRODUCER.read_manifest(path), manifest)
                else:
                    with self.assertRaises(ValueError):
                        PRODUCER.read_manifest(path)


if __name__ == '__main__':
    unittest.main()

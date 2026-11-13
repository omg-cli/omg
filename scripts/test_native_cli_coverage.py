"""The native coverage job must execute its supplemental CLI producer."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
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
        self.assertIn('python /native-cli-coverage.py run', native)
        self.assertIn('python3 scripts/native-cli-coverage.py verify', native)
        self.assertLess(native.index('python /native-cli-coverage.py run'),
                        native.index('mount -t tmpfs -o nosuid,nodev,noexec,mode=755 tmpfs /var/lib'))

    def test_generated_omarchy_cases_use_the_real_cli_in_a_private_namespace(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        self.assertIn("OMG_OMARCHY_NAMESPACE", script)
        self.assertIn('ID=omarchy', script)
        self.assertIn('mount --bind "$fixture/release" /etc/os-release', script)
        self.assertIn('omarchy-success', script)
        self.assertIn('omarchy-vendor-failure', script)
        self.assertIn('omarchy-migration-refusal', script)
        self.assertIn('mount --bind "$fixture/sudo"', script)
        self.assertIn('exec /omg-extra-bin/cli update', script)

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_inert_omarchy_helpers_record_arguments_and_reject_external_aur(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        sudo = script.split("<<'OMG_INERT_SUDO'\n", 1)[1].split('\nOMG_INERT_SUDO', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-success', OMARCHY_HELPER_TRACE=str(trace))
            for name, args, source, status in (
                    ('omarchy-update-dev', [], helper, 0),
                    ('omarchy-shell', ['-q', 'omarchy.system-update', 'clear'], helper, 0),
                    ('sudo', ['true'], sudo, 0),
                    ('sudo', ['-n', 'true'], sudo, 0),
                    ('yay', ['-Sua'], helper, 99),
                    ('sudo', ['pacman', '-Syu'], sudo, 99)):
                path = root / name
                path.write_text(source)
                result = subprocess.run([BASH, str(path), *args], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, status, result.stderr)
            self.assertEqual(trace.read_text().splitlines(), [
                'omarchy-update-dev', 'omarchy-shell\t-q\tomarchy.system-update\tclear',
                'sudo\ttrue', 'sudo\t-n\ttrue', 'yay\t-Sua'])

    @unittest.skipIf(os.name == 'nt', 'Native sync archive fixture requires POSIX tar')
    def test_omarchy_fixture_database_uses_supported_compression(self):
        command = next(line.strip() for line in PRODUCER.omarchy_guest_script().splitlines()
                       if line.strip().startswith('tar ') and 'db/sync/core.db' in line)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'db/sync').mkdir(parents=True)
            result = subprocess.run(
                [BASH, '-euo', 'pipefail', '-c', 'case_dir="$OMARCHY_FIXTURE_DIRECTORY"\n' + command],
                env=dict(os.environ, OMARCHY_FIXTURE_DIRECTORY=str(root)),
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            with tarfile.open(root / 'db/sync/core.db', 'r:gz') as archive:
                self.assertEqual(archive.getmembers(), [])

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
    for stage, (status, helpers) in PRODUCER.OMARCHY_CASES.items():
        (evidence / f'{stage}-exit.txt').write_text(f'{status}\n')
        (evidence / f'{stage}-helpers.tsv').write_text(''.join(row + '\n' for row in helpers))
        if helpers:
            (evidence / f'{stage}-coordination.txt').write_text(
                'released private lock; owned transcript mode=600\n')
            (evidence / f'{stage}-transcript.log').write_text('OMG Omarchy update started\nOMG Omarchy update finished: exit status: 0\n')
        log = {
            'omarchy-success': '| System is up to date',
            'omarchy-optional-failures': '| System is up to date\n! Continuing without a snapshot\n! Some mise tools could not be updated',
            'omarchy-vendor-failure': 'Omarchy update did not complete',
            'omarchy-declined': 'declined',
            'omarchy-migration-refusal': 'external AUR helper',
            'omarchy-unsupported-mode': 'complete update lifecycle',
            'omarchy-invalid-transport': 'Incomplete Omarchy update transport',
        }[stage]
        (evidence / f'{stage}.log').write_text(log)
    return evidence, profiles, artifacts


class SupplementalEvidence(unittest.TestCase):
    def test_complete_observed_selection_and_processes_have_a_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            files = PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            receipt = json.loads((evidence / 'verification.json').read_text())
            self.assertEqual(len(receipt['tests']), 14)
            self.assertEqual(len(receipt['process_checks']), 12)
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
            'omarchy-hidden-optional-warnings': lambda e, p: (e / 'omarchy-optional-failures.log').write_text('| System is up to date'),
            'omarchy-old-logger': lambda e, p: (e / 'omarchy-success-transcript.log').write_text('Script started on fixture\nScript done on fixture\n'),
            'omarchy-no-cleanup': lambda e, p: (e / 'omarchy-success-coordination.txt').write_text('lock still held'),
            'omarchy-no-refusal': lambda e, p: (e / 'omarchy-migration-refusal.log').write_text('failed for another reason'),
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

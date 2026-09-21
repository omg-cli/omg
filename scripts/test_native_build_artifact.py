"""Bounded fixture archives are not release or product execution evidence."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'native_build', Path(__file__).with_name('native-build-artifact.py'))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


def fixture(distro='debian'):
    binary = b'fixture, never executed'
    archive = io.BytesIO()
    base = 'omg-v1.2.3-x86_64-linux-' + distro
    with tarfile.open(fileobj=archive, mode='w:gz') as stream:
        for name, content in [('omg', binary), ('omgd', binary), ('README.md', b'readme'), ('LICENSE', b'license')]:
            entry = tarfile.TarInfo(base + '/' + name)
            entry.size = len(content)
            entry.mode = 0o755 if name in ('omg', 'omgd') else 0o644
            stream.addfile(entry, io.BytesIO(content))
    payload = archive.getvalue()
    expected = {
        'repository': 'omg-cli/omg', 'source_sha': 'a' * 40, 'run_id': '123', 'run_attempt': 1,
        'distro': distro, 'image': ('debian:trixie' if distro == 'debian-trixie' else 'debian:bookworm') + '@sha256:' + 'b' * 64,
        'features': ['debian', 'license', 'pgp'], 'target': 'x86_64-unknown-linux-gnu',
        'profile': 'release', 'instrumentation': 'none', 'cpu': 'generic', 'toolchain': '1.95.0',
        'workflow_path': '.github/workflows/ci.yml',
    }
    provenance = dict(expected, schema_version=1, version='1.2.3', archive=base + '.tar.gz',
                      compiler='rustc 1.95.0 (fixture)\nhost: x86_64-unknown-linux-gnu',
                      build_argv=['cargo', 'build', '--timings', '--release', '--no-default-features',
                                  '--features', 'debian,pgp,license', '--locked'],
                      archive_sha256=hashlib.sha256(payload).hexdigest(),
                      binaries={name: hashlib.sha256(binary).hexdigest() for name in ('omg', 'omgd')})
    return expected, provenance, payload


def bundle(provenance, payload, extra=None):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('native-build.json', json.dumps(provenance))
        archive.writestr(provenance['archive'], payload)
        archive.writestr(provenance['archive'] + '.sha256', provenance['archive_sha256'] + '  ' + provenance['archive'] + '\n')
        if extra:
            archive.writestr(*extra)
    return result.getvalue()


class NativeBuildAdmission(unittest.TestCase):
    def test_trixie_pair_retains_its_native_abi_recipe_identity(self):
        expected, provenance, payload = fixture('debian-trixie')
        argv, environment = BUILD.build_command('debian-trixie', 'debian,pgp,license', {})
        self.assertEqual(argv, provenance['build_argv'])
        self.assertEqual(environment['RUSTFLAGS'], '')
        data = bundle(provenance, payload)
        digest = 'sha256:' + hashlib.sha256(data).hexdigest()
        admitted, _ = BUILD.validate_bundle(data, digest, expected)
        self.assertEqual(admitted, provenance)
        for field, foreign in [('distro', 'debian'), ('image', 'debian:bookworm@sha256:' + 'b' * 64),
                               ('features', ['debian-pure'])]:
            wrong_recipe = dict(expected, **{field: foreign})
            with self.subTest(field=field), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, digest, wrong_recipe)
        with self.assertRaises(ValueError):
            BUILD.build_command('debian-trixie', 'debian-pure', {})

    def test_reuse_failure_preserves_diagnostic_for_lifecycle_issue(self):
        from test_ci_optimization import BASH, step_script
        script = step_script('qemu-lane.yml', 'Reuse verified native CI binaries')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mock = '''python3() {
                if [[ "$2" == reuse ]]; then
                    echo 'Native build admission failed: archive checksum mismatch'
                    return 23
                fi
                printf '%s\\n' "$*" > "$RUNNER_TEMP/report-call"
            }
            '''
            result = subprocess.run([BASH, '-e', '-o', 'pipefail', '-c', mock + script],
                                    env=dict(os.environ, RUNNER_TEMP=root.as_posix(), DISTRO='debian',
                                             BUILD_IMAGE='fixture', BUILD_FEATURES='debian,pgp,license'),
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 23, result.stderr)
            log = root / 'qemu-evidence/run-native-build/guest-check.log'
            self.assertIn('archive checksum mismatch', log.read_text())
            self.assertIn('status --distro debian --case-id qemu-debian-lifecycle --status failure',
                          (root / 'report-call').read_text())

    def test_automatic_lanes_reuse_ci_while_manual_keeps_serial_test_owner(self):
        from test_ci_gates import job_block
        root = Path(__file__).resolve().parents[1]
        ci = (root / '.github/workflows/ci.yml').read_text(encoding='utf-8')
        lane = (root / '.github/workflows/qemu-lane.yml').read_text(encoding='utf-8')
        matrix = (root / '.github/workflows/qemu-matrix.yml').read_text(encoding='utf-8')
        self.assertNotIn('native-build-artifact.py ready', job_block(matrix, 'prepare'))
        self.assertIn('needs: [quick-gate, linux-matrix, ubuntu]', job_block(ci, 'qemu'))
        for owner in ('linux-matrix', 'ubuntu'):
            block = job_block(ci, owner)
            self.assertIn('native-build-artifact.py build', block)
            self.assertLess(block.index('name: Upload native release pair'), block.index('name: Platform clippy'))
            self.assertIn('--locked --no-fail-fast -- --test-threads=1', block)
        for owner in ('build-staged', 'build-staged-ubuntu'):
            block = job_block(lane, owner)
            self.assertIn('!inputs.reuse-ci', block)
            self.assertIn('--locked --no-fail-fast -- --test-threads=1', block)
        guest = job_block(lane, 'guest')
        self.assertIn('native-build-artifact.py reuse', guest)
        self.assertIn('--timeout 60', guest)
        self.assertIn('actions: read', guest)
        self.assertNotIn('issues: write', lane)
        self.assertIn('inputs.staged && inputs.reuse-ci', guest)
        self.assertIn('if: inputs.staged && !inputs.reuse-ci', guest)
        self.assertIn("reuse-ci: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}", matrix)
        self.assertIn('  pull_request:\n  merge_group:', ci)
        self.assertIn('python3 scripts/ci-change-scope.py', ci)

    def test_cli_dispatches_build_and_reuse_with_exact_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / 'event.json'
            event_path.write_text('{"number":440}', encoding='utf-8')
            for mode, method in [('build', 'build_and_package'), ('reuse', 'reuse')]:
                with self.subTest(mode=mode), patch.dict(os.environ, {'GITHUB_EVENT_PATH': str(event_path)}), \
                        patch.object(BUILD, method) as operation:
                    BUILD.main([mode, '--distro', 'ubuntu', '--image', 'ubuntu-24.04',
                                '--features', 'debian,pgp,license', '--destination', directory + '/staged'])
                    args = operation.call_args.args
                    self.assertEqual(args[:5], (Path.cwd(), 'ubuntu', 'ubuntu-24.04',
                                                'debian,pgp,license', Path(directory) / 'staged'))
                    if mode == 'reuse':
                        self.assertEqual(args[6], {'number': 440})

    def test_reuse_checks_live_attempt_and_writes_only_validated_files(self):
        for mode in ('valid', 'in-progress', 'queued', 'queued-artifact', 'waiting-artifact',
                     'changed-attempt', 'expired', 'older-attempt', 'missing'):
            expected, provenance, payload = fixture()
            data = bundle(provenance, payload)
            run = dict(id=123, run_attempt=1, repository={'full_name': 'omg-cli/omg'},
                       path='.github/workflows/ci.yml', workflow_id=42, event='pull_request',
                       head_sha='c'*40, pull_requests=[{'number': 440}],
                       run_started_at='2026-09-20T09:00:00Z', status='completed', conclusion='success')
            if mode == 'in-progress':
                # Main CI's release job waits for QEMU; requiring workflow
                # completion before admitting its early artifact would deadlock.
                run.update(status='in_progress', conclusion=None)
            if mode in ('queued-artifact', 'waiting-artifact'):
                run.update(status=mode.split('-')[0], conclusion=None)
            artifact = dict(id=9, name='native-release-debian-1', size_in_bytes=len(data), expired=False,
                            created_at='2026-09-20T09:01:00Z', digest='sha256:' + hashlib.sha256(data).hexdigest())
            if mode == 'expired':
                artifact['expired'] = True
            if mode == 'older-attempt':
                artifact['created_at'] = '2026-09-20T08:59:59Z'
            def lookup(path):
                if path.endswith('/workflows/ci.yml'):
                    return {'id': 42, 'path': '.github/workflows/ci.yml'}
                if '/ci.yml/runs?' in path:
                    candidate = dict(run, status='queued', conclusion=None, run_started_at=None) if mode == 'queued' else run
                    return {'workflow_runs': [candidate]}
                if '/artifacts?' in path:
                    return {'total_count': 0 if mode == 'missing' else 1,
                            'artifacts': [] if mode == 'missing' else [artifact]}
                if path.endswith('/runs/123'):
                    return dict(run, run_attempt=2) if mode == 'changed-attempt' else run
                self.fail('unexpected API request: ' + path)
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'Cargo.toml').write_text('[package]\nversion="1.2.3"\n')
                (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="1.95.0"\n')
                destination = root / 'staged'
                context = dict(GITHUB_REPOSITORY='omg-cli/omg', GITHUB_SHA='a'*40,
                               GITHUB_EVENT_NAME='pull_request')
                event = {'number': 440, 'pull_request': {'head': {'sha': 'c'*40}}}
                with patch.object(BUILD, 'api_json', side_effect=lookup), patch.object(BUILD, 'api', return_value=data), \
                        patch.object(BUILD, 'command_output', return_value='a'*40), patch.object(BUILD.time, 'sleep'), \
                        patch.object(BUILD.time, 'monotonic', side_effect=range(0, 10000, 100)):
                    if mode in ('valid', 'in-progress', 'queued', 'queued-artifact', 'waiting-artifact'):
                        result = BUILD.reuse(root, 'debian', expected['image'], 'debian,pgp,license', destination, context, event)
                        self.assertEqual(result, provenance)
                        self.assertEqual({path.name for path in destination.iterdir()},
                                         {provenance['archive'], provenance['archive']+'.sha256', 'native-build.json'})
                        self.assertEqual((destination / provenance['archive']).read_bytes(), payload)
                    else:
                        error_type = BUILD.ArtifactUnavailable if mode == 'missing' else ValueError
                        with self.assertRaises(error_type):
                            BUILD.reuse(root, 'debian', expected['image'], 'debian,pgp,license', destination, context, event)
                        self.assertFalse(destination.exists())

    def test_producer_run_identity_uses_api_head_but_archive_uses_checkout_sha(self):
        expected = dict(repository='omg-cli/omg', workflow_id=42, event='pull_request',
                        head_sha='c' * 40, pr_number=440)
        run = dict(id=123, run_attempt=1, repository={'full_name': 'omg-cli/omg'},
                   path='.github/workflows/ci.yml', workflow_id=42, event='pull_request',
                   head_sha='c' * 40, pull_requests=[{'number': 440}],
                   run_started_at='2026-09-20T09:00:00Z', status='in_progress', conclusion=None)
        BUILD.validate_producer_run(run, expected)
        for key, value in [('id', True), ('run_attempt', 0), ('workflow_id', 99),
                           ('path', '.github/workflows/other.yml'), ('event', 'workflow_dispatch'),
                           ('head_sha', 'a'*40), ('pull_requests', [{'number': 441}]),
                           ('repository', {'full_name': 'foreign/repo'})]:
            candidate = dict(run, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                BUILD.validate_producer_run(candidate, expected)

    def test_packager_proves_build_invocation_and_exact_pair_before_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'target/release').mkdir(parents=True)
            for name in ('omg', 'omgd'):
                (root / 'target/release' / name).write_bytes(('fixture-' + name).encode())
            for name in ('README.md', 'LICENSE'):
                (root / name).write_text(name)
            (root / 'Cargo.toml').write_text('[package]\nversion = "1.2.3"\n')
            (root / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.95.0"\n')
            context = dict(GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1',
                           GITHUB_REPOSITORY='omg-cli/omg',
                           GITHUB_WORKFLOW_REF='omg-cli/omg/.github/workflows/ci.yml@refs/heads/main')
            def output(argv):
                if argv[0] == 'git':
                    return 'a' * 40
                return 'rustc 1.95.0 (fixture)\nhost: x86_64-unknown-linux-gnu'
            with patch.object(BUILD, 'command_output', side_effect=output), patch.object(BUILD.subprocess, 'run') as run:
                provenance = BUILD.build_and_package(root, 'debian', 'debian:bookworm@sha256:' + 'b'*64,
                                                     'debian,pgp,license', root / 'output', context)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][0:4], ['cargo', 'build', '--timings', '--release'])
            self.assertEqual(run.call_args.kwargs['env']['RUSTFLAGS'], '')
            payload = (root / 'output' / provenance['archive']).read_bytes()
            data = bundle(provenance, payload)
            expected = {key: provenance[key] for key in fixture()[0]}
            self.assertEqual(BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)[0], provenance)

    def test_build_command_matches_published_recipe_and_rejects_instrumentation(self):
        for distro, features, cpu in (
            ('arch', 'arch,pgp,license', '-C target-cpu=x86-64-v2'),
            ('debian', 'debian,pgp,license', ''),
            ('ubuntu', 'debian,pgp,license', ''),
            ('fedora', 'fedora,pgp,license', ''),
        ):
            with self.subTest(distro=distro):
                argv, env = BUILD.build_command(distro, features, {'CARGO_PROFILE_DEV_LTO': 'off'})
                self.assertEqual(argv, ['cargo', 'build', '--timings', '--release',
                                        '--no-default-features', '--features', features, '--locked'])
                self.assertEqual(env['RUSTFLAGS'], cpu)
                self.assertEqual(env['CARGO_PROFILE_DEV_LTO'], 'off')
        for overrides in ({'CARGO_PROFILE_RELEASE_LTO': 'off'}, {'RUSTFLAGS': '-Cinstrument-coverage'},
                          {'CARGO_ENCODED_RUSTFLAGS': '-Zsomething'}, {'RUSTC_WRAPPER': 'unknown'},
                          {'CARGO_TARGET_DIR': '/foreign'}, {'CARGO_BUILD_TARGET_DIR': '/foreign'},
                          {'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS': '-Cinstrument-coverage'},
                          {'CARGO_BUILD_RUSTFLAGS': '-Cinstrument-coverage'}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                BUILD.build_command('debian', 'debian,pgp,license', overrides)
        with self.assertRaises(ValueError):
            BUILD.build_command('debian', 'arch,pgp,license', {})

    def test_exact_pair_recipe_and_server_digest_admitted(self):
        expected, provenance, payload = fixture()
        data = bundle(provenance, payload)
        result, files = BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)
        self.assertEqual(result, provenance)
        self.assertEqual(files[provenance['archive']], payload)

    def test_every_compatibility_dimension_is_enforced(self):
        expected, provenance, payload = fixture()
        for field in expected:
            forged = copy.deepcopy(provenance)
            forged[field] = [] if field == 'features' else 2 if field == 'run_attempt' else 'foreign'
            data = bundle(forged, payload)
            with self.subTest(field=field), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)

    def test_archive_and_each_binary_digest_cannot_be_substituted(self):
        for field in ('archive_sha256', 'omg', 'omgd'):
            expected, provenance, payload = fixture()
            if field == 'archive_sha256':
                provenance[field] = 'f' * 64
            else:
                provenance['binaries'][field] = 'f' * 64
            data = bundle(provenance, payload)
            with self.subTest(field=field), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)

    def test_recorded_compiler_and_invocation_must_match_the_recipe(self):
        for field, value in [('compiler', 'rustc 1.94.0 (foreign)\nhost: x86_64-unknown-linux-gnu'),
                             ('compiler', 'rustc 1.95.0 (foreign)\nhost: aarch64-unknown-linux-gnu'),
                             ('build_argv', ['cargo', 'build', '--profile', 'dev'])]:
            expected, provenance, payload = fixture()
            provenance[field] = value
            data = bundle(provenance, payload)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)

    def test_missing_wrong_server_digest_and_extra_members_rejected(self):
        expected, provenance, payload = fixture()
        data = bundle(provenance, payload)
        for digest in (None, 'sha256:' + 'f' * 64):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, digest, expected)
        for name in ('../escape', '/absolute', 'extra.json', 'nested/native-build.json'):
            data = bundle(provenance, payload, (name, 'extra'))
            with self.subTest(name=name), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)

    def test_archive_links_and_foreign_members_rejected_even_with_updated_hashes(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.REGTYPE):
            expected, provenance, _ = fixture()
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w:gz') as stream:
                member = tarfile.TarInfo('../escape')
                member.type = kind
                member.linkname = '/etc/shadow'
                stream.addfile(member)
            payload = buffer.getvalue()
            provenance['archive_sha256'] = hashlib.sha256(payload).hexdigest()
            data = bundle(provenance, payload)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                BUILD.validate_bundle(data, 'sha256:' + hashlib.sha256(data).hexdigest(), expected)


if __name__ == '__main__':
    unittest.main()

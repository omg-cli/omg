from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('build_comparison', ROOT / 'scripts/build-comparison.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
WINDOWS_SPEC = importlib.util.spec_from_file_location('windows_build_comparison', ROOT / 'scripts/windows-build-comparison.py')
WINDOWS = importlib.util.module_from_spec(WINDOWS_SPEC)
WINDOWS_SPEC.loader.exec_module(WINDOWS)


class ComparisonTests(unittest.TestCase):
    def source_fixture(self, root):
        source, evidence = root / 'source', root / 'evidence'
        source.mkdir()
        evidence.mkdir()
        (source / '.cargo').mkdir()
        (source / '.cargo/config.toml').write_text('[build]\njobs = 5\n')
        (source / 'Cargo.toml').write_text('[package]\nversion = "0.1.2"\n[profile.release]\nlto = "fat"\n')
        files = RUNNER.manifest(source)
        RUNNER.write_json(evidence / 'prepared.json', {'sourceSha': 'a' * 40, 'archiveSha256': 'b' * 64,
            'sourceManifestSha256': RUNNER.manifest_digest(files), 'files': files})
        RUNNER.write_json(evidence / 'receipt.json', {'status': 'prepared'})
        return source, evidence

    def fake_measure(self, argv, source, evidence, label, environment, timeout=5400):
        if argv[:2] == ['cargo', 'build']:
            messages = []
            for name in ('omg', 'omgd'):
                binary = source / 'target/release' / name
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(name.encode())
                messages.append({'reason': 'compiler-artifact', 'target': {'name': name},
                    'executable': str(binary), 'fresh': label != 'build-0'})
            text = '\n'.join(json.dumps(row) for row in messages + [{'reason': 'build-finished', 'success': True}])
        elif argv[:2] == ['cargo', 'test']:
            name = next(value for value in argv if value in RUNNER.TESTS)
            text = 'test ' + name + ' ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
        elif argv[-1] == '--version':
            text = Path(argv[0]).name + ' 0.1.2\n'
        elif argv[-1] == '--help':
            text = 'Usage: ' + Path(argv[0]).name + ' [OPTIONS]\n'
        else:
            text = '{"packages":["bash"],"count":1}'
        (evidence / (label + '.stdout')).write_text(text)
        (evidence / (label + '.stderr')).write_text('')
        return {'label': label, 'argv': argv, 'wallSeconds': 0.1, 'maximumProcessRssKiB': 1,
                'exitCode': 0, 'timedOut': False}

    def test_complete_wave_requires_both_binaries_named_tests_and_native_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            source, evidence = self.source_fixture(Path(directory))
            with patch.object(RUNNER, 'measure', self.fake_measure), \
                 patch.object(RUNNER, 'system_information', return_value={}), \
                 patch.object(RUNNER, 'native_inventory', return_value=(['bash\t1\tinstalled'], {'bash'})), \
                 redirect_stdout(io.StringIO()):
                result = RUNNER.run_wave(source, evidence, 'a' * 40)
            self.assertEqual(result['status'], 'complete')
            self.assertEqual(len(result['samples']), 17)
            self.assertEqual(len(result['tests']), 8)
            self.assertEqual(set(result['binaryHashes']), {'omg', 'omgd'})
            self.assertTrue(result['inventoryProof']['completeNamesEqual'])
            self.assertEqual(result['summary']['build']['warmN'], 3)
            WINDOWS.validate_receipt(result, {'sourceSha': 'a' * 40, 'archiveSha256': 'b' * 64,
                'sourceManifestSha256': result['sourceManifestSha256'], 'scriptSha256': result['scriptSha256']})
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                WINDOWS.validate_receipt(result, {'archiveSha256': 'c' * 64})
            result['samples'][0]['exitCode'] = 101
            with self.assertRaisesRegex(ValueError, 'failed or missing measurements'):
                WINDOWS.validate_receipt(result, {})

    def test_failed_cargo_command_leaves_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            source, evidence = self.source_fixture(Path(directory))
            def fail(*arguments):
                row = self.fake_measure(*arguments)
                row['exitCode'] = 101
                return row
            with patch.object(RUNNER, 'measure', fail), patch.object(RUNNER, 'system_information', return_value={}), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'build-0 failed'):
                    RUNNER.run_wave(source, evidence, 'a' * 40)
            result = json.loads((evidence / 'receipt.json').read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['samples'][0]['exitCode'], 101)
            self.assertNotIn('summary', result)

    def test_failed_cargo_streams_flushed_start_then_failed_end_without_completion(self):
        class Output(io.StringIO):
            def __init__(self):
                super().__init__()
                self.flushed = []
            def flush(self):
                self.flushed.append(self.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            source, evidence = self.source_fixture(Path(directory))
            output = Output()
            def fail(*arguments):
                self.assertEqual(len(output.flushed), 1)
                start = json.loads(output.flushed[0])
                self.assertEqual(start, {'event': 'phase-start', 'label': 'build-0', 'sample': 0})
                row = self.fake_measure(*arguments)
                row['exitCode'] = 101
                return row
            with patch.object(RUNNER, 'measure', fail), patch.object(RUNNER, 'system_information', return_value={}), \
                 redirect_stdout(output):
                with self.assertRaisesRegex(ValueError, 'build-0 failed'):
                    RUNNER.run_wave(source, evidence, 'a' * 40)
            events = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(events, [
                {'event': 'phase-start', 'label': 'build-0', 'sample': 0},
                {'event': 'phase-end', 'label': 'build-0', 'sample': 0, 'wallSeconds': 0.1, 'exitCode': 101}])
            self.assertEqual(len(output.flushed), 2)
            self.assertEqual(json.loads((evidence / 'receipt.json').read_text())['status'], 'failed')

    def test_successful_cargo_exit_with_zero_tests_leaves_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            source, evidence = self.source_fixture(Path(directory))
            def zero_tests(*arguments):
                row = self.fake_measure(*arguments)
                if row['label'].startswith('test-'):
                    (evidence / (row['label'] + '.stdout')).write_text('test result: ok. 0 passed; 0 failed; 0 ignored;')
                return row
            with patch.object(RUNNER, 'measure', zero_tests), patch.object(RUNNER, 'system_information', return_value={}), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'did not execute'):
                    RUNNER.run_wave(source, evidence, 'a' * 40)
            self.assertEqual(json.loads((evidence / 'receipt.json').read_text())['status'], 'failed')

    def test_zero_selected_tests_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, 'did not execute'):
            RUNNER.verify_test('test result: ok. 0 passed; 0 failed; 0 ignored;', RUNNER.TESTS[0])

    def test_another_test_cannot_substitute_for_named_test(self):
        with self.assertRaisesRegex(ValueError, 'did not execute'):
            RUNNER.verify_test('test another::test ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;', RUNNER.TESTS[0])

    def test_completed_receipt_is_invalidated_before_failed_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            (evidence / 'receipt.json').write_text('{"status":"complete"}')
            with self.assertRaises(ValueError):
                RUNNER.run_wave(evidence / 'missing-source', evidence, 'a' * 40)
            self.assertEqual(json.loads((evidence / 'receipt.json').read_text())['status'], 'failed')

    def test_profile_and_cache_overrides_are_removed(self):
        result = RUNNER.build_environment({'PATH': 'fixture', 'CARGO_PROFILE_RELEASE_LTO': 'off',
            'RUSTC_WRAPPER': 'sccache', 'CARGO_ENCODED_RUSTFLAGS': 'foreign', 'RUSTFLAGS': 'foreign',
            'CARGO_TARGET_DIR': 'foreign', 'CARGO_BUILD_TARGET': 'foreign', 'OMG_TEST_MODE': '1'})
        self.assertNotIn('CARGO_PROFILE_RELEASE_LTO', result)
        self.assertNotIn('RUSTC_WRAPPER', result)
        self.assertNotIn('CARGO_TARGET_DIR', result)
        self.assertNotIn('CARGO_BUILD_TARGET', result)
        self.assertNotIn('OMG_TEST_MODE', result)
        self.assertEqual(result['RUSTFLAGS'], '')
        self.assertEqual(result['CARGO_BUILD_JOBS'], '4')

    @unittest.skipUnless(os.name == 'nt', 'native Windows wrapper')
    def test_exited_guest_without_export_keeps_failure_disk_and_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, tools = root / '.git/state', root / '.git/tools'
            state.mkdir(parents=True)
            tools.mkdir()
            (root / 'scripts').mkdir()
            (root / 'scripts/build-comparison.py').write_text('fixture script')
            image, template = root / '.git/base.qcow2', state / 'template.qcow2'
            image.write_bytes(b'base')
            template.write_bytes(b'template')
            manifest = root / 'images.json'
            manifest.write_text(json.dumps({'images': {'ubuntu-x86_64': {'url': 'fixture', 'digest': RUNNER.digest(image)}}}))
            record = {'templateSha256': RUNNER.digest(template), 'basePath': str(image), 'baseDigest': RUNNER.digest(image),
                'preparationBootId': 'old-boot', 'provisioning': {'passed': True, 'compiledProjectTargets': False,
                    'features': RUNNER.FEATURES, 'cachedInputs': {}},
                'sanitation': {'scheduledPoweroff': True, 'credentialsRemoved': True, 'sourceAndTargetAbsent': True}}
            template.with_suffix('.json').write_text(json.dumps(record))
            guests = []
            class ExitedGuest:
                def __init__(self, arguments, run, backing, online, host):
                    self.run, self.host = run, host
                    self.vm = SimpleNamespace(poll=lambda: 1)
                    self.disk, self.preserve_disk = run / 'disk.qcow2', False
                    guests.append(self)
                def start(self):
                    self.disk.write_bytes(b'unexported failure evidence')
                    self.host['bootId'] = 'new-boot'
                    raise ValueError('owned QEMU stopped during comparison')
                def close(self):
                    if not self.preserve_disk:
                        self.disk.unlink()
            def command(argv):
                if str(argv[0]) == 'git':
                    path = Path(next(value[9:] for value in argv if isinstance(value, str) and value.startswith('--output=')))
                    with tarfile.open(path, 'w') as archive:
                        entry = tarfile.TarInfo('Cargo.toml')
                        data = b'[package]\nversion="0.1.2"\n'
                        entry.size = len(data)
                        archive.addfile(entry, io.BytesIO(data))
                    return ''
                return json.dumps({'format': 'qcow2', 'full-backing-filename': str(image)})
            args = SimpleNamespace(state=state, tools=tools, image=image, template=template,
                                   source_sha='a' * 40, memory_mib=8192)
            with patch.object(WINDOWS, 'ROOT', root), patch.object(WINDOWS.QEMU, 'MANIFEST', manifest), \
                 patch.object(WINDOWS.QEMU, 'command', command), patch.object(WINDOWS.QEMU, 'Guest', ExitedGuest), \
                 patch.object(WINDOWS.QEMU.IMAGES, 'verify', return_value={'passed': True}), \
                 redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'QEMU stopped'):
                    WINDOWS.execute(args)
            self.assertTrue(guests[0].preserve_disk)
            self.assertEqual(guests[0].disk.read_bytes(), b'unexported failure evidence')
            receipt = json.loads((guests[0].run / 'receipt.json').read_text())
            self.assertEqual(receipt['status'], 'failed')
            self.assertIn('QEMU stopped', receipt['error'])


if __name__ == '__main__':
    unittest.main()

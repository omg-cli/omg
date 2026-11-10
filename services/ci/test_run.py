import importlib.util
import hashlib
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('plain_ci', Path(__file__).with_name('run.py'))
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class NativeChecks(unittest.TestCase):
    def baked_inputs(self):
        cargo = (ROOT / 'Cargo.toml').read_bytes()
        document = RUN.tomllib.loads(cargo.decode())
        files = {name: name.encode() for name in ('omg', 'omgd', 'libtest')}
        manifest = dict(schemaVersion=1, sourceSha='a' * 40, features=RUN.FEATURES,
            profile='release', version=document['package']['version'],
            compiler='rustc 1.95.0 (fixture)\nhost: x86_64-unknown-linux-gnu',
            releaseProfile=document['profile']['release'], cargoTomlSha256=hashlib.sha256(cargo).hexdigest(),
            files={name: dict(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)) for name, data in files.items()})
        receipt = dict(accepted=True, sourceSha=manifest['sourceSha'], candidateProcessesStopped=True,
            runtimeOnly=False, buildExecutor='github-actions-image-build',
            artifactManifestSha256=RUN.digest(json.dumps(manifest, sort_keys=True).encode()),
            libtestSha256=manifest['files']['libtest']['sha256'],
            binaryHashes={name: manifest['files'][name]['sha256'] for name in ('omg', 'omgd')})
        return cargo, files, manifest, receipt

    def test_baked_runtime_rejects_tampered_source_recipe_bytes_or_unclean_build(self):
        cargo, files, manifest, receipt = self.baked_inputs()
        RUN.validate_baked('a' * 40, cargo, manifest, receipt, files,
                           json.dumps(manifest, sort_keys=True).encode())
        cases = [dict(sourceSha='b' * 40), dict(features='debian-pure'), dict(profile='dev'),
                 dict(releaseProfile={'lto': False}), dict(cargoTomlSha256='0' * 64)]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RUN.validate_baked('a' * 40, cargo, dict(manifest, **changes), receipt, files,
                                   json.dumps(manifest, sort_keys=True).encode())
        for name in files:
            with self.subTest(file=name), self.assertRaises(ValueError):
                RUN.validate_baked('a' * 40, cargo, manifest, receipt, dict(files, **{name: b'foreign'}),
                                   json.dumps(manifest, sort_keys=True).encode())
        for changes in [dict(accepted=False), dict(candidateProcessesStopped=False),
                        dict(sourceSha='b' * 40), dict(artifactManifestSha256='0' * 64)]:
            with self.subTest(receipt=changes), self.assertRaises(ValueError):
                RUN.validate_baked('a' * 40, cargo, manifest, dict(receipt, **changes), files,
                                   json.dumps(manifest, sort_keys=True).encode())

    def test_export_requires_one_successful_owning_release_libtest(self):
        row = dict(reason='compiler-artifact', manifest_path=str(RUN.SOURCE / 'Cargo.toml'),
            target=dict(name='omg_lib', kind=['lib']), profile=dict(test=True, opt_level='3'),
            features=['debian', 'pgp', 'license'], executable=str(RUN.WORK / 'target/release/deps/omg_lib-123'))
        finished = dict(reason='build-finished', success=True)
        encode = lambda rows: '\n'.join(json.dumps(item) for item in rows)
        self.assertEqual(RUN.select_libtest(encode([row, finished])), Path(row['executable']))
        for key, value in [('manifest_path', '/foreign/Cargo.toml'), ('executable', '/tmp/foreign'),
                           ('profile', dict(test=False, opt_level='3')), ('features', ['debian-pure'])]:
            broken = dict(row, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                RUN.select_libtest(encode([broken, finished]))
        for rows in [[row, row, finished], [row], [row, dict(finished, success=False)]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                RUN.select_libtest(encode(rows))

    def test_runtime_selected_tests_execute_baked_libtest_without_cargo(self):
        names = ['one::test', 'another::test']
        calls = []
        def command(argv, label):
            calls.append(argv)
            return f'test {argv[1]} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
        with patch.object(RUN, 'ORACLE', ROOT / 'scripts/build-comparison.py'):
            rows = RUN.selected_tests(command, names, Path('/opt/ci/artifacts/libtest'))
        self.assertEqual([row['name'] for row in rows], names)
        self.assertEqual(calls, [[str(Path('/opt/ci/artifacts/libtest')), name, '--exact', '--nocapture', '--test-threads=1'] for name in names])

    def test_publish_exports_actual_bytes_and_only_after_successful_cleanup(self):
        cargo, files, manifest, receipt = self.baked_inputs()
        receipt.update({key: manifest[key] for key in ('features', 'profile', 'version', 'compiler', 'releaseProfile')})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work, destination = root / 'work', root / 'artifacts'
            release = work / 'target/release'
            (release / 'deps').mkdir(parents=True)
            for name, content in files.items():
                (release / ('deps/libtest' if name == 'libtest' else name)).write_bytes(content)
            try:
                with patch.object(RUN, 'WORK', work), patch.object(RUN, 'ARTIFACTS', destination):
                    for changes in [dict(accepted=False), dict(candidateProcessesStopped=False)]:
                        with self.assertRaises(ValueError):
                            RUN.publish_artifacts(dict(receipt, **changes), release / 'deps/libtest', cargo)
                        self.assertFalse(destination.exists())
                    RUN.publish_artifacts(receipt, release / 'deps/libtest', cargo)
                published = (destination / 'manifest.json').read_bytes()
                build_receipt = json.loads((destination / 'build-receipt.json').read_bytes())
                observed = {name: (destination / name).read_bytes() for name in files}
                self.assertEqual(observed, files)
                RUN.validate_baked('a' * 40, cargo, json.loads(published), build_receipt, observed, published)
                self.assertEqual(set(path.name for path in destination.iterdir()),
                                 {'omg', 'omgd', 'libtest', 'manifest.json', 'build-receipt.json'})
            finally:
                if destination.exists():
                    destination.chmod(0o700)
                    for path in destination.iterdir():
                        path.chmod(0o600)

    @unittest.skipUnless(os.name == 'posix', 'Linux immutable image ownership and mode boundary')
    def test_baked_input_rejects_writable_file_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o755)
            cargo = root / 'Cargo.toml'
            cargo.write_bytes(b'frozen')
            with patch.object(RUN, 'CARGO', cargo):
                with self.assertRaises(ValueError):
                    RUN.immutable_bytes(cargo)
                cargo.chmod(0o444)
                if os.getuid() == 0:
                    self.assertEqual(RUN.immutable_bytes(cargo), b'frozen')
                else:
                    with self.assertRaises(ValueError):
                        RUN.immutable_bytes(cargo)
                redirected = root / 'redirect'
                redirected.symlink_to(cargo)
                with self.assertRaises(ValueError):
                    RUN.immutable_bytes(redirected)

    def test_exact_selected_test_requires_successful_exit_and_one_real_execution(self):
        name = 'package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages'
        passed = f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'
        with patch.object(RUN, 'ORACLE', ROOT / 'scripts/build-comparison.py'):
            RUN.verify_selected_test(passed, name, 0)
            for text, code in [(passed, 101), ('test result: ok. 0 passed; 0 failed; 0 ignored;', 0),
                               (passed.replace(name, 'another::test'), 0)]:
                with self.subTest(code=code, text=text), self.assertRaises(ValueError):
                    RUN.verify_selected_test(text, name, code)

    def test_candidate_environment_has_no_controller_secrets_or_profile_overrides(self):
        environment = RUN.candidate_environment()
        self.assertEqual(environment['CARGO_BUILD_JOBS'], '4')
        self.assertEqual(environment['CARGO_INCREMENTAL'], '0')
        self.assertEqual(environment['CARGO_TARGET_DIR'], '/work/target')
        self.assertFalse(any(key.startswith('CARGO_PROFILE_') for key in environment))
        self.assertNotIn('OMG_TEST_MODE', environment)
        self.assertNotIn('CLOUDFLARE_API_TOKEN', environment)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', environment)


if __name__ == '__main__':
    unittest.main()

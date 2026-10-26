"""Behavior contracts for the reviewed Fedora SQLite supply boundary."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fedora_sqlite', ROOT/'scripts/fedora-sqlite.py')
sqlite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sqlite)
REVISION = 'a'*40


class FedoraSQLiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bundle = Path(self.temp.name)
        self.policy = json.loads((ROOT/'tests/qemu-image-provenance/fedora-sqlite.json').read_text())
        self.policy['test_files']['x86_64'] = {
            'count': 2, 'sha256': hashlib.sha256(b'oserror.test\nwalrestart.test\n').hexdigest()}
        details = ''.join(name+'... Ok\n' for name, count in self.policy['required_assertions'].items() for _ in range(count))
        build = 'SQLITE_NOFILE_SOFT=1024\nExecuting(%check): /bin/sh\nTime: oserror.test 1 ms\nTime: walrestart.test 2 ms\n0 errors out of 9 tests on  Linux 64-bit\nfuzzcheck: 0 errors out of 10 tests in 1 second\n'
        files = {'rpmbuild.log': build.encode(), 'test-details.txt': details.encode(),
                 'packages.tsv': b'sqlite\t3.51.2-2.fc44\tx86_64\n',
                 'source-signature.txt': b'Header V4 RSA/SHA256 Signature, key ID 6d9f90a6: OK\n'}
        for name in sqlite.package_names(self.policy, 'x86_64'):
            files[name] = b'fixture package bytes '+name.encode()
        for name, data in files.items():
            (self.bundle/name).write_bytes(data)
        self.manifest = {
            'schema_version': 1, 'source_sha': REVISION, 'architecture': 'x86_64',
            'base_image': self.policy['base_image'], 'source_sha256': self.policy['source_sha256'],
            'patch_sha256': self.policy['patch_sha256'], 'fingerprint': self.policy['fingerprint'],
            'version': self.policy['version'], 'release': self.policy['release'],
            'rpmbuild_exit': 0, 'nofile_soft': 1024, 'library_sha256': 'd'*64,
            'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
        self.save()

    def save(self):
        (self.bundle/'manifest.json').write_text(json.dumps(self.manifest))

    @unittest.skipUnless(__import__('sys').platform.startswith('linux'), 'QEMU driver requires Linux')
    def test_fedora_guest_refuses_missing_supply_before_any_boot(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['bash', str(ROOT/'scripts/benchmark-qemu.sh'), '--distro', 'fedora',
                '--staged-dir', directory, '--evidence-dir', directory+'/evidence'],
                capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 3)
        self.assertIn('Fedora requires a verified SQLite bundle', result.stderr)

    def test_complete_same_revision_bundle_is_admitted(self):
        receipt = sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)
        self.assertEqual(receipt['source_sha'], REVISION)
        self.assertEqual(receipt['library_sha256'], 'd'*64)

    def test_every_unpatched_fedora_identity_is_refused(self):
        for release in ['1.fc44', '2.fc44']:
            with self.subTest(release=release), self.assertRaises(ValueError):
                sqlite.validate_installed({'name': 'sqlite-libs', 'version': '3.51.2',
                    'release': release, 'architecture': 'x86_64', 'library_sha256': 'd'*64}, self.manifest)

    def test_matching_version_without_matching_native_library_is_refused(self):
        record = {'name': 'sqlite-libs', 'version': '3.51.2', 'release': '2.omgci.walreset2.fc44',
                  'architecture': 'x86_64', 'library_sha256': 'd'*64}
        sqlite.validate_installed(record, self.manifest)
        for field, value in [('library_sha256', 'e'*64), ('architecture', 'aarch64'), ('name', 'other')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                sqlite.validate_installed(dict(record, **{field: value}), self.manifest)

    def test_corrupt_package_and_missing_source_package_are_refused(self):
        names = sqlite.package_names(self.policy, 'x86_64')
        (self.bundle/names[0]).write_bytes(b'corrupted package')
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)
        self.setUp()
        (self.bundle/names[2]).unlink()
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)

    def test_forged_success_cannot_hide_failed_checks_or_omitted_regression(self):
        for name, content in [('rpmbuild.log', b'Executing(%check): /bin/sh\n1 errors out of 9 tests on  Linux 64-bit\n'),
                              ('test-details.txt', b'oserror-1.1.3... Ok\n')]:
            with self.subTest(name=name):
                data = (self.bundle/name).read_bytes()
                (self.bundle/name).write_bytes(content)
                self.manifest['files'][name] = hashlib.sha256(content).hexdigest()
                self.save()
                with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)
                (self.bundle/name).write_bytes(data)
                self.manifest['files'][name] = hashlib.sha256(data).hexdigest()
                self.save()

    def test_wrong_source_revision_patch_key_or_build_result_is_refused(self):
        for field, value in [('source_sha', 'b'*40), ('source_sha256', 'e'*64), ('patch_sha256', 'e'*64),
                             ('fingerprint', 'E'*40), ('rpmbuild_exit', 1), ('nofile_soft', 65536)]:
            with self.subTest(field=field):
                original = self.manifest[field]
                self.manifest[field] = value
                self.save()
                with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)
                self.manifest[field] = original
        self.save()

    def test_reported_descriptor_limit_must_match_the_executed_build(self):
        data = (self.bundle/'rpmbuild.log').read_bytes().replace(b'SQLITE_NOFILE_SOFT=1024', b'SQLITE_NOFILE_SOFT=65536')
        (self.bundle/'rpmbuild.log').write_bytes(data)
        self.manifest['files']['rpmbuild.log'] = hashlib.sha256(data).hexdigest()
        self.save()
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)

    def test_reviewed_material_hashes_match_the_checkout_bytes(self):
        material = ROOT/'tests/qemu-image-provenance'
        for path_key, hash_key in [('patch', 'patch_sha256'), ('keyring', 'keyring_sha256')]:
            with self.subTest(material=path_key):
                self.assertEqual(hashlib.sha256((material/self.policy[path_key]).read_bytes()).hexdigest(), self.policy[hash_key])
        self.assertNotIn(b'\r', (material/self.policy['patch']).read_bytes())

    def test_supply_container_matches_the_reviewed_builder_identity(self):
        workflow = (ROOT/'.github/workflows/fedora-sqlite.yml').read_text()
        import re
        images = re.findall(r'^      image: (.+)$', workflow, re.M)
        self.assertEqual(images, [self.policy['base_image']])

    def test_omitting_any_original_test_file_is_refused_even_with_zero_errors(self):
        log = (self.bundle/'rpmbuild.log').read_bytes().replace(b'Time: oserror.test 1 ms\n', b'')
        (self.bundle/'rpmbuild.log').write_bytes(log)
        self.manifest['files']['rpmbuild.log'] = hashlib.sha256(log).hexdigest()
        self.save()
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)

    def test_boolean_build_status_and_duplicate_json_fields_are_refused(self):
        self.manifest['rpmbuild_exit'] = False
        self.save()
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)
        (self.bundle/'manifest.json').write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)

    def test_native_before_and_after_evidence_is_bound_to_exact_supplied_bytes(self):
        record = {'schema_version': 1, 'source_sha': REVISION,
            'manifest_sha256': hashlib.sha256((self.bundle/'manifest.json').read_bytes()).hexdigest(),
            'native_package_verification': True,
            'installed': {'name': 'sqlite-libs', 'version': '3.51.2', 'release': '2.omgci.walreset2.fc44',
                'architecture': 'x86_64', 'library_sha256': 'd'*64},
            'before': {'version': '3.51.2', 'release': '1.fc44'}, 'before_admitted': False,
            'package_sha256': {n: self.manifest['files'][n] for n in sqlite.package_names(self.policy, 'x86_64')}}
        for phase in ['before', 'after', 'final']:
            (self.bundle/f'fedora-sqlite-{phase}.json').write_text(json.dumps(record))
        sqlite.verify_guest_evidence(self.bundle, self.bundle, self.manifest)
        for field, value in [('source_sha', 'b'*40), ('manifest_sha256', 'e'*64), ('native_package_verification', False),
                             ('before_admitted', True), ('installed', dict(record['installed'], library_sha256='e'*64))]:
            with self.subTest(field=field):
                altered = dict(record, **{field: value})
                (self.bundle/'fedora-sqlite-before.json').write_text(json.dumps(altered))
                with self.assertRaises(ValueError): sqlite.verify_guest_evidence(self.bundle, self.bundle, self.manifest)
        (self.bundle/'fedora-sqlite-before.json').write_text(json.dumps(record))
        (self.bundle/'fedora-sqlite-after.json').unlink()
        with self.assertRaises(ValueError): sqlite.verify_guest_evidence(self.bundle, self.bundle, self.manifest)
        (self.bundle/'fedora-sqlite-after.json').write_text(json.dumps(record))
        (self.bundle/'fedora-sqlite-final.json').unlink()
        with self.assertRaises(ValueError): sqlite.verify_guest_evidence(self.bundle, self.bundle, self.manifest)

    def test_unreviewed_extra_files_are_not_copied_into_the_guest(self):
        (self.bundle/'unreviewed.py').write_text('print("unreviewed")')
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)

    def test_payload_paths_cannot_escape_the_bundle(self):
        self.manifest['files']['../outside.rpm'] = 'd'*64
        self.save()
        with self.assertRaises(ValueError): sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', REVISION)

    def test_retry_selects_latest_same_run_attempt_and_refuses_a_corrupt_latest(self):
        parent = self.bundle/'attempts'
        parent.mkdir()
        import shutil
        for attempt in [1, 2, 3]:
            dest = parent/f'fedora-sqlite-x86_64-{attempt}'
            shutil.copytree(self.bundle, dest, ignore=shutil.ignore_patterns('attempts'))
        selected = sqlite.select_bundle(parent, 'x86_64', 2)
        self.assertEqual(selected.name, 'fedora-sqlite-x86_64-2')
        (selected/'manifest.json').write_text('{}')
        with self.assertRaises(ValueError): sqlite.verify_bundle(selected, self.policy, 'x86_64', REVISION)


if __name__ == '__main__':
    unittest.main()

"""Host admission must bind APT evidence to both native binaries and probe source."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).with_name('qemu-apt-abi-evidence.py')


class AptAbiEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SOURCE.is_file(), 'independent host ABI admission is missing')
        spec = importlib.util.spec_from_file_location('apt_abi_evidence', SOURCE)
        self.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.validator)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.probe = self.root / 'probe.py'
        self.probe.write_bytes(b'trusted selected source\n')
        self.archive = self.root / 'release.tar.gz'
        self.payloads = {'omg': b'cli ELF fixture', 'omgd': b'daemon ELF fixture'}
        self.write_archive()
        release = b'ID=debian\nVERSION_ID="13"\n'
        (self.evidence / 'os-release').write_bytes(release)
        row = b'libapt-pkg.so.7.0 => /lib/x86_64-linux-gnu/libapt-pkg.so.7.0 (0x123)\n'
        binaries = {}
        for name, payload in self.payloads.items():
            (self.evidence / (name + '-loader.log')).write_bytes(row)
            binaries[name] = dict(binary_sha256=self.sha(payload),
                library_path='/lib/x86_64-linux-gnu/libapt-pkg.so.7.0',
                library_sha256='b' * 64, log_sha256=self.sha(row))
        self.receipt = dict(schema_version=1, kind='trixie-apt-abi', complete=True,
            distro='debian-trixie', arch='x86_64', ordinary_user_uid=1000,
            os_id='debian', version_id='13', os_release_sha256=self.sha(release),
            loader_sha256='d' * 64, probe_sha256=self.sha(self.probe.read_bytes()), binaries=binaries)
        self.write_receipt()

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    def write_archive(self, arch='x86_64', duplicate=False):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, payload in self.payloads.items():
                member = tarfile.TarInfo(f'omg-v0.1.0-{arch}-linux-debian-trixie/{name}')
                member.size = len(payload)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(payload))
                if duplicate and name == 'omg':
                    archive.addfile(member, io.BytesIO(payload))

    def write_receipt(self):
        (self.evidence / 'receipt.json').write_text(json.dumps(self.receipt))

    def admit(self):
        return self.validator.validate_evidence(self.evidence, self.archive, self.probe)

    def test_bound_two_binary_receipt_is_admitted(self):
        result = self.admit()
        self.assertEqual(result['native_archive_sha256'], self.sha(self.archive.read_bytes()))
        self.assertEqual(result['binaries'], self.receipt['binaries'])

    def test_foreign_receipt_identity_and_hashes_are_refused(self):
        original = copy.deepcopy(self.receipt)
        for key, value in (('schema_version', True), ('complete', 1), ('distro', 'debian'),
                           ('arch', 'aarch64'), ('ordinary_user_uid', 0),
                           ('ordinary_user_uid', True), ('version_id', '12'),
                           ('probe_sha256', 'f' * 64), ('os_release_sha256', 'f' * 64),
                           ('loader_sha256', 'unknown')):
            with self.subTest(key=key, value=value):
                self.receipt = dict(original, **{key: value})
                self.write_receipt()
                with self.assertRaises(ValueError):
                    self.admit()
        self.receipt = original
        for key, value in (('binary_sha256', 'f' * 64), ('log_sha256', 'f' * 64),
                           ('library_sha256', 'f' * 64), ('library_path', '/home/user/libapt-pkg.so.7.0')):
            with self.subTest(key=key):
                self.receipt = copy.deepcopy(original)
                self.receipt['binaries']['omgd'][key] = value
                self.write_receipt()
                with self.assertRaises(ValueError):
                    self.admit()

    def test_raw_guest_and_dependency_evidence_must_match(self):
        for name, payload in (('os-release', b'ID=debian\nVERSION_ID=12\n'),
                              ('omgd-loader.log', b'libapt-pkg.so.7.0 => not found\n'),
                              ('omg-loader.log', b'x' * 65537)):
            path = self.evidence / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(payload)
                with self.assertRaises(ValueError):
                    self.admit()
                path.write_bytes(original)

    def test_incomplete_duplicate_and_extra_receipt_keys_are_refused(self):
        original = copy.deepcopy(self.receipt)
        for binaries in ({}, {'omg': original['binaries']['omg']},
                         dict(original['binaries'], other=original['binaries']['omg'])):
            self.receipt = dict(original, binaries=binaries)
            self.write_receipt()
            with self.assertRaises(ValueError):
                self.admit()
        self.receipt = dict(original, unexpected=True)
        self.write_receipt()
        with self.assertRaises(ValueError):
            self.admit()
        (self.evidence / 'receipt.json').write_text('{"complete":true,"complete":true}')
        with self.assertRaises(ValueError):
            self.admit()

    def test_native_archive_pair_must_be_unique_and_x86_64(self):
        for arch, duplicate in (('aarch64', False), ('x86_64', True)):
            with self.subTest(arch=arch, duplicate=duplicate):
                self.write_archive(arch, duplicate)
                with self.assertRaises(ValueError):
                    self.admit()
        self.write_archive()
        self.payloads['omgd'] = b'foreign daemon'
        self.write_archive()
        with self.assertRaises(ValueError):
            self.admit()

    def test_symlink_and_unexpected_evidence_files_are_refused(self):
        path = self.evidence / 'omg-loader.log'
        outside = self.root / 'outside.log'
        outside.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError:
            self.skipTest('platform cannot create symlinks')
        with self.assertRaises(ValueError):
            self.admit()
        path.unlink()
        path.write_bytes(outside.read_bytes())
        (self.evidence / 'private-key').write_bytes(b'private')
        with self.assertRaises(ValueError):
            self.admit()


if __name__ == '__main__':
    unittest.main()

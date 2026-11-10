#!/usr/bin/env python3
"""Exercise Windows QEMU source and evidence boundaries without a VM."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_qemu', ROOT / 'scripts/windows-qemu.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
SMOKE_TESTS = {
    'arch': [
        'package_managers::pacman_db::db::tests::parse_sync_db_handles_gzip_and_zstd_after_magic_probe',
        'package_managers::pacman_db::db::tests::malformed_sync_package_does_not_hide_valid_repository_entries',
    ],
    'debian': [
        'package_managers::debian_db::db::tests::parse_packages_file_sync_reads_valid_packages',
        'package_managers::debian_db::db::tests::installed_status_accepts_held_packages_but_not_partial_states',
    ],
    'fedora': [
        'package_managers::dnf::tests::installed_details_preserve_canonical_names_and_native_versions',
        'package_managers::dnf::tests::installed_details_preserve_order_and_distinct_native_reasons',
    ],
}
FEATURES = {
    'arch': 'arch,pgp,license', 'debian': 'debian,pgp,license',
    'debian-trixie': 'debian,pgp,license', 'ubuntu': 'debian,pgp,license',
    'fedora': 'fedora,pgp,license',
}


class SourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.git/native-whpx-20261110/test-scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='windows-qemu-', dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.repo = self.work / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'core.autocrlf', 'false')
        files = {
            'Cargo.toml': '[package]\nname = "fixture"\nversion = "0.1.0"\n',
            'Cargo.lock': 'version = 4\n',
            'rust-toolchain.toml': '[toolchain]\nchannel = "1.95.0"\n',
            '.cargo/config.toml': '[build]\njobs = 2\n',
            'scripts/windows-qemu-guest.sh': '#!/bin/bash\nset -eu\n',
            'src/lib.rs': 'pub fn value() -> u8 { 1 }\n',
            '.gitignore': 'ignored-secret\n',
        }
        for name, content in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8', newline='\n')
        self.git('add', '.')
        self.git('update-index', '--chmod=+x', 'scripts/windows-qemu-guest.sh')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + str(self.work / 'no-hooks'),
                 'commit', '-qm', 'fixture')

    def git(self, *arguments):
        return subprocess.check_output(['git', '-C', str(self.repo), *arguments], text=True, encoding='utf-8').strip()

    def snapshot(self, name='source.tar.gz'):
        archive = self.work / name
        return RUNNER.snapshot_source(archive, root=self.repo), archive

    def test_snapshot_transfers_dirty_and_untracked_bytes_with_executable_mode(self):
        clean, _ = self.snapshot('clean.tar.gz')
        self.assertFalse(clean['dirty'])
        (self.repo / 'src/lib.rs').write_text('pub fn value() -> u8 { 2 }\n', encoding='utf-8', newline='\n')
        (self.repo / 'src/new.rs').write_text('pub const NEW: bool = true;\n', encoding='utf-8', newline='\n')
        (self.repo / 'ignored-secret').write_text('must not enter the guest', encoding='utf-8')
        source, archive = self.snapshot()
        self.assertTrue(source['dirty'])
        self.assertEqual(source['head'], clean['head'])
        self.assertEqual(source['archiveSha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
        with tarfile.open(archive, 'r:gz') as bundle:
            self.assertEqual(bundle.extractfile('src/lib.rs').read(), b'pub fn value() -> u8 { 2 }\n')
            self.assertEqual(bundle.extractfile('src/new.rs').read(), b'pub const NEW: bool = true;\n')
            self.assertEqual(bundle.getmember('scripts/windows-qemu-guest.sh').mode, 0o755)
            self.assertNotIn('ignored-secret', bundle.getnames())
            self.assertTrue(all(not name.startswith('.git/') for name in bundle.getnames()))
            self.assertEqual(set(source['files']), set(bundle.getnames()))
        self.assertNotEqual(source['archiveSha256'], clean['archiveSha256'])

    def test_missing_required_input_is_not_a_successful_snapshot(self):
        (self.repo / 'Cargo.lock').unlink()
        with self.assertRaisesRegex(ValueError, 'required Rust inputs'):
            self.snapshot()

    def test_owner_and_snapshot_reject_path_escape_and_directory_link(self):
        with self.assertRaisesRegex(ValueError, 'escapes its owner'):
            RUNNER.owned(self.repo / '../outside', self.repo)
        with self.assertRaisesRegex(ValueError, 'escapes its owner'):
            RUNNER.owned(self.repo, self.repo)
        real = self.repo / 'real'
        real.mkdir()
        (real / 'data.rs').write_text('fixture', encoding='utf-8')
        link = self.repo / 'shortcut'
        try:
            os.symlink(real, link, target_is_directory=True)
        except OSError:
            if os.name != 'nt':
                raise
            subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(link), str(real)],
                           check=True, capture_output=True)
        try:
            with self.assertRaisesRegex(ValueError, 'reparse or symlink'):
                self.snapshot()
        finally:
            if link.is_symlink():
                link.unlink()
            else:
                os.rmdir(link)
        self.assertEqual((real / 'data.rs').read_text(encoding='utf-8'), 'fixture')

    def test_template_identity_tracks_dependencies_and_preserves_ordinary_edits(self):
        original, _ = self.snapshot('original.tar.gz')
        image = 'a' * 64
        key = RUNNER.template_key(original, 'ubuntu', image)
        (self.repo / 'src/lib.rs').write_text('pub fn value() -> u8 { 9 }\n', encoding='utf-8')
        edited, _ = self.snapshot('edited.tar.gz')
        self.assertNotEqual(original['files']['src/lib.rs'], edited['files']['src/lib.rs'])
        self.assertEqual(RUNNER.template_key(edited, 'ubuntu', image), key)
        for name in ('Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml',
                     '.cargo/config.toml', 'scripts/windows-qemu-guest.sh'):
            with self.subTest(input=name):
                path = self.repo / name
                before = path.read_bytes()
                path.write_bytes(before + b'\n# changed dependency input\n')
                changed, _ = self.snapshot('dependency.tar.gz')
                self.assertNotEqual(RUNNER.template_key(changed, 'ubuntu', image), key)
                path.write_bytes(before)
        self.assertNotEqual(RUNNER.template_key(edited, 'fedora', image), key)
        self.assertNotEqual(RUNNER.template_key(edited, 'ubuntu', 'b' * 64), key)


    def test_frozen_recipe_uses_snapshot_and_rejects_changed_recipe_or_expected_hash(self):
        from io import BytesIO

        source, archive = self.snapshot()
        recipe = 'scripts/windows-qemu-guest.sh'
        original = (self.repo / recipe).read_bytes()
        (self.repo / recipe).write_bytes(b'#!/bin/bash\nexit 19\n')
        frozen = self.work / 'guest-recipe.sh'
        RUNNER.freeze_recipe(archive, source, frozen)
        self.assertEqual(frozen.read_bytes(), original)
        self.assertNotEqual(frozen.read_bytes(), (self.repo / recipe).read_bytes())
        changed_archive = self.work / 'changed.tar.gz'
        with tarfile.open(changed_archive, 'w:gz') as bundle:
            data = b'#!/bin/bash\nexit 23\n'
            entry = tarfile.TarInfo(recipe)
            entry.size = len(data)
            bundle.addfile(entry, BytesIO(data))
        wrong_hash = copy.deepcopy(source)
        wrong_hash['files'][recipe] = '0' * 64
        for label, candidate, identity in [('archive', changed_archive, source),
                                            ('expected-hash', archive, wrong_hash)]:
            with self.subTest(tampered=label):
                destination = self.work / (label + '.sh')
                with self.assertRaisesRegex(ValueError, 'guest recipe identity changed'):
                    RUNNER.freeze_recipe(candidate, identity, destination)
                self.assertFalse(destination.exists())
        self.assertEqual(frozen.read_bytes(), original)


class BuildReceiptTests(unittest.TestCase):
    def valid(self, distro='ubuntu'):
        backend = 'debian' if distro in ('debian', 'debian-trixie', 'ubuntu') else distro
        request = {'distro': distro, 'sourceArchiveSha256': 'a' * 64,
                   'bootId': '05caed3b-e9ab-4e4a-93c6-5d7f656f0c3e',
                   'features': FEATURES[distro], 'rustVersion': '1.95.0', 'packageVersion': '0.1.224'}
        result = {name: request[name] for name in ('distro', 'sourceArchiveSha256', 'bootId', 'features')}
        result.update(passed=True, stage='built', profile='dev', toolchain='1.95.0',
                      compiler='rustc 1.95.0 (59807616e 2026-04-14)\nhost: x86_64-unknown-linux-gnu\n',
                      binaryHashes={'omg': 'b' * 64, 'omgd': 'c' * 64},
                      binaryexecution=[{'binary': name, 'version': name + ' 0.1.224',
                                        'versionExit': 0, 'helpExit': 0} for name in ('omg', 'omgd')],
                      inventoryproof={'nativeExplicitCount': 3, 'completeNamesEqual': True,
                                      'nativeStateUnchanged': True},
                      tests=[{'name': name, 'passed': 1, 'failed': 0, 'ignored': 0}
                             for name in SMOKE_TESTS[backend]])
        return result, request

    def test_actual_requested_positive_evidence_is_accepted_for_each_distro(self):
        for distro in FEATURES:
            with self.subTest(distro=distro):
                result, request = self.valid(distro)
                RUNNER.verify_build(result, request)

    def test_foreign_source_guest_features_profile_and_compiler_are_rejected(self):
        values = {'sourceArchiveSha256': 'd' * 64, 'bootId': 'other-boot', 'distro': 'arch',
                  'features': 'debian-pure', 'profile': 'release', 'toolchain': '1.94.0',
                  'compiler': 'rustc 1.95.0 (fixture)\nhost: x86_64-pc-windows-msvc\n',
                  'stage': 'provisioned', 'passed': False}
        for name, value in values.items():
            with self.subTest(field=name):
                result, request = self.valid()
                result[name] = value
                with self.assertRaises(ValueError):
                    RUNNER.verify_build(result, request)

    def test_zero_duplicate_ignored_failed_and_unrequested_tests_are_rejected(self):
        mutations = [[], [{'name': 'invented', 'passed': 1, 'failed': 0, 'ignored': 0}]]
        base, _ = self.valid()
        for field, value in [('passed', 0), ('failed', 1), ('ignored', 1), ('name', 'other::test')]:
            tests = copy.deepcopy(base['tests'])
            tests[0][field] = value
            mutations.append(tests)
        mutations.append([copy.deepcopy(base['tests'][0]), copy.deepcopy(base['tests'][0])])
        for index, tests in enumerate(mutations):
            with self.subTest(case=index):
                result, request = self.valid()
                result['tests'] = tests
                with self.assertRaisesRegex(ValueError, 'named tests'):
                    RUNNER.verify_build(result, request)

    def test_missing_binaries_failed_execution_and_native_inventory_drift_are_rejected(self):
        mutations = [
            ('binaryHashes', {'omg': 'b' * 64}),
            ('binaryHashes', {'omg': 'b' * 64, 'omgd': 'not-a-digest'}),
            ('binaryexecution', []),
            ('binaryexecution', [{'binary': 'omg', 'version': 'omg 0.1.224', 'versionExit': 0, 'helpExit': 0}] * 2),
            ('inventoryproof', {'nativeExplicitCount': 0, 'completeNamesEqual': True, 'nativeStateUnchanged': True}),
            ('inventoryproof', {'nativeExplicitCount': 3, 'completeNamesEqual': False, 'nativeStateUnchanged': True}),
            ('inventoryproof', {'nativeExplicitCount': 3, 'completeNamesEqual': True, 'nativeStateUnchanged': False}),
        ]
        base, _ = self.valid()
        for field, value in [('versionExit', 1), ('helpExit', 1), ('version', 'omg 0.0.0')]:
            execution = copy.deepcopy(base['binaryexecution'])
            execution[0][field] = value
            mutations.append(('binaryexecution', execution))
        for index, (field, value) in enumerate(mutations):
            with self.subTest(case=index):
                result, request = self.valid()
                result[field] = value
                with self.assertRaises(ValueError):
                    RUNNER.verify_build(result, request)


class MemoryAdmissionTests(unittest.TestCase):
    def test_commit_headroom_admits_guest_without_requiring_unused_physical_capacity(self):
        from unittest.mock import patch

        memory = {'availablePhysicalBytes': 2 * 1024**3,
                  'availableCommitBytes': 18 * 1024**3, 'physicalLoadPercent': 94}
        with patch.object(RUNNER, 'memory_status', return_value=memory):
            self.assertEqual(RUNNER.memory_guard(4096), memory)

    def test_acute_physical_pressure_and_insufficient_commit_refuse_guest(self):
        from unittest.mock import patch

        cases = [
            ({'availablePhysicalBytes': 511 * 1024**2,
              'availableCommitBytes': 18 * 1024**3, 'physicalLoadPercent': 99}, 'acute memory pressure'),
            ({'availablePhysicalBytes': 2 * 1024**3,
              'availableCommitBytes': 6 * 1024**3 - 1, 'physicalLoadPercent': 94}, 'commit headroom'),
        ]
        for memory, error in cases:
            with self.subTest(refusal=error), patch.object(RUNNER, 'memory_status', return_value=memory):
                with self.assertRaisesRegex(ValueError, error):
                    RUNNER.memory_guard(4096)


if __name__ == '__main__':
    unittest.main()

"""Exercise release collection with complete and invalid APT6/APT7 bundles."""
import hashlib
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest

from test_ci_gates import job_block
from test_release_workflow_boundaries import BASH, step_script

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ('x86_64-linux-arch', 'x86_64-linux-debian',
             'x86_64-linux-debian-trixie', 'x86_64-linux-ubuntu',
             'x86_64-linux-fedora', 'aarch64-darwin')


class ReleaseCollection(unittest.TestCase):
    def test_resync_rejects_wrong_platform_even_when_counts_match(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        script = step_script(workflow, 'Download and verify published release')
        validation = script.split('--dir release\n', 1)[1].split('for archive in', 1)[0]
        for substituted in (False, True):
            with self.subTest(substituted=substituted), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'release').mkdir()
                (root / 'scripts').mkdir()
                shutil.copy(ROOT / 'scripts/collect-release-artifacts.sh', root / 'scripts')
                for platform in PLATFORMS:
                    if substituted and platform.endswith('trixie'):
                        platform = 'unsupported-platform'
                    name = f'omg-v1.2.3-{platform}.tar.gz'
                    payload = platform.encode()
                    (root / 'release' / name).write_bytes(payload)
                    (root / 'release' / (name + '.sha256')).write_text(
                        f'{hashlib.sha256(payload).hexdigest()}  {name}\n')
                (root / 'release/omg-v1.2.3.cdx.json').write_text('{"bomFormat":"CycloneDX"}')
                result = subprocess.run([BASH, '-eu', '-c', validation], cwd=root,
                                        env=dict(os.environ, VERSION='1.2.3'),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, not substituted, result.stdout + result.stderr)

    def test_published_resync_requires_six_archive_checksum_pairs(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        script = step_script(workflow, 'Download and verify published release')
        start = script.index('if (( ${#archives[@]}')
        end = script.index('\nfi', start) + len('\nfi')
        guard = script[start:end]
        for archives, checksums, accepted in ((6, 6, True), (5, 5, False),
                                              (6, 5, False), (7, 7, False)):
            with self.subTest(archives=archives, checksums=checksums):
                command = ('archives=(' + 'x ' * archives + ')\n'
                           'checksums=(' + 'x ' * checksums + ')\n' + guard)
                result = subprocess.run([BASH, '-eu', '-c', command],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_publication_requires_apt_smoke_and_preserves_failure(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        block = job_block(workflow, 'smoke-apt')
        self.assertIn('smoke-apt', job_block(workflow, 'release').split('steps:', 1)[0])
        self.assertIn('name: ${{ matrix.artifact }}', block)
        self.assertIn('if: always()', block)
        script = step_script(block, 'Exercise staged APT release')
        for distro, abi in [('debian', '6'), ('ubuntu', '6'), ('debian', '7'), ('ubuntu', '7')]:
            for outcome in (0, 19):
                with self.subTest(distro=distro, abi=abi, outcome=outcome), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'scripts').mkdir()
                    (root / 'Cargo.toml').write_text('version = "1.2.3"\n')
                    probe = root / 'scripts/release-smoke.sh'
                    probe.write_text('#!/bin/bash\nset -eu\n'
                                     'printf "%s\\n" "$@" > args.txt\nexit "$PROBE_EXIT"\n')
                    probe.chmod(0o755)
                    result = subprocess.run([BASH, '-eu', '-c', script], cwd=root,
                                            env=dict(os.environ, DISTRO=distro, APT_ABI=abi,
                                                     PROBE_EXIT=str(outcome)), capture_output=True, text=True)
                    self.assertEqual(result.returncode, outcome, result.stderr)
                    self.assertEqual((root / 'args.txt').read_text().splitlines(),
                                     ['--release', 'v1.2.3', '--staged-dir', 'staged-release',
                                      '--distro', distro, '--apt-abi', abi,
                                      '--evidence-dir', 'apt-smoke-evidence'])

    def test_release_package_step_emits_both_distinct_apt_pairs(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        block = job_block(workflow, 'build-debian')
        self.assertIn('image: ${{ matrix.image }}', block)
        self.assertIn('name: ${{ matrix.distro }}-build', block)
        self.assertIn('DISTRO: ${{ matrix.distro }}', block)
        for distro, image in (('debian', 'bookworm'), ('debian-trixie', 'trixie')):
            self.assertIn(f'- distro: {distro}\n', block)
            self.assertIn(f'image: debian:{image}@sha256:', block)
            with self.subTest(distro=distro), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'target/release').mkdir(parents=True)
                files = {'omg': b'cli fixture', 'omgd': b'daemon fixture'}
                for name, payload in files.items():
                    (root / 'target/release' / name).write_bytes(payload)
                (root / 'Cargo.toml').write_text('version = "1.2.3"\n')
                for name in ('README.md', 'LICENSE'):
                    (root / name).write_text(name)
                result = subprocess.run([BASH, '-eu', '-c', step_script(block, 'Package')],
                                        cwd=root, env=dict(os.environ, DISTRO=distro,
                                                          CARGO_HOME='/nonexistent'),
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                package = f'omg-v1.2.3-x86_64-linux-{distro}'
                archive = root / (package + '.tar.gz')
                with tarfile.open(archive) as bundle:
                    for name, payload in files.items():
                        self.assertEqual(bundle.extractfile(f'{package}/{name}').read(), payload)
                self.assertEqual((root / (archive.name + '.sha256')).read_text(),
                                 f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')

    def test_complete_bundle_and_invalid_variants(self):
        for case in ('complete', 'missing-trixie', 'duplicate-trixie',
                     'corrupt-trixie', 'unexpected'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifacts = root / 'artifacts'
                artifacts.mkdir()
                for platform in PLATFORMS:
                    if case == 'missing-trixie' and platform.endswith('trixie'):
                        continue
                    name = f'omg-v1.2.3-{platform}.tar.gz'
                    payload = platform.encode()
                    (artifacts / name).write_bytes(payload)
                    (artifacts / (name + '.sha256')).write_text(
                        f'{hashlib.sha256(payload).hexdigest()}  {name}\n')
                trixie = 'omg-v1.2.3-x86_64-linux-debian-trixie.tar.gz'
                if case == 'duplicate-trixie':
                    (artifacts / 'duplicate').mkdir()
                    (artifacts / 'duplicate' / trixie).write_bytes(b'duplicate')
                if case == 'corrupt-trixie':
                    (artifacts / trixie).write_bytes(b'corrupted')
                if case == 'unexpected':
                    (artifacts / 'unexpected.tar.gz').write_bytes(b'unexpected')
                (artifacts / 'omg-v1.2.3.cdx.json').write_text(
                    '{"bomFormat":"CycloneDX"}')
                destination = root / 'release'
                result = subprocess.run(
                    [BASH, str(ROOT / 'scripts/collect-release-artifacts.sh'),
                     '1.2.3', str(artifacts), str(destination)],
                    capture_output=True, text=True, timeout=15)
                if case == 'complete':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(list(destination.iterdir())), 13)
                    for source in artifacts.iterdir():
                        self.assertEqual((destination / source.name).read_bytes(),
                                         source.read_bytes())
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    diagnostic = ('checksum mismatch' if case == 'corrupt-trixie'
                                  else 'exact platform allowlist')
                    self.assertIn(diagnostic, result.stderr)


if __name__ == '__main__':
    unittest.main()

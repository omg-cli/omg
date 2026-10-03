import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('prepare_release', Path(__file__).with_name('prepare-qemu-release.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseContractTests(unittest.TestCase):
    def test_published_trixie_archive_preserves_attestation_and_tag_contract(self):
        data = (release.HEADER + '\nrelease-case\t[]\tread\t0\tpass\t-\thermetic\t-\t-\t-\n').encode()
        revision = 'a' * 40
        blob = {'encoding': 'base64', 'size': len(data), 'content': base64.b64encode(data).decode()}
        for verified in (True, False):
            with self.subTest(verified=verified), tempfile.TemporaryDirectory() as tmp:
                destination = Path(tmp)
                outcomes = [None, None if verified else subprocess.CalledProcessError(1, 'verify')]
                with patch.object(release, 'api', side_effect=[{'sha': revision}, blob, {'sha': revision}]), patch.object(release.subprocess, 'run', side_effect=outcomes) as calls:
                    if verified:
                        release.prepare('v0.1.224', 'debian-trixie', destination)
                        self.assertEqual((destination / 'cases.tsv').read_bytes(), data)
                        provenance = json.loads((destination / 'inventory-provenance.json').read_text())
                        self.assertEqual(provenance['inventory_revision'], revision)
                        self.assertTrue(provenance['artifact_attestation_verified'])
                    else:
                        with self.assertRaises(subprocess.CalledProcessError):
                            release.prepare('v0.1.224', 'debian-trixie', destination)
                        self.assertFalse((destination / 'cases.tsv').exists())
                        self.assertFalse((destination / 'inventory-provenance.json').exists())
                archive = 'omg-v0.1.224-x86_64-linux-debian-trixie.tar.gz'
                self.assertIn(archive, calls.call_args_list[0].args[0])
                self.assertIn(archive + '.sha256', calls.call_args_list[0].args[0])
                self.assertEqual(calls.call_args_list[1].args[0], [
                    'gh', 'attestation', 'verify', str(destination / archive),
                    '--repo', 'omg-cli/omg', '--source-digest', revision,
                    '--source-ref', 'refs/tags/v0.1.224',
                    '--signer-workflow', 'omg-cli/omg/.github/workflows/release.yml',
                ])
                self.assertTrue(calls.call_args_list[1].kwargs['check'])

    def test_installer_uses_same_release_signer_cutover(self):
        bash = os.environ.get('OMG_TEST_BASH') or (shutil.which('bash') if os.name != 'nt' else None)
        if not bash:
            self.skipTest('native Bash required')
        installer = Path(__file__).parents[1].joinpath('install.sh').read_text(encoding='utf-8')
        definitions = '\n'.join(re.search(r'^' + name + r'\(\) \{.*?^\}', installer, re.M | re.S)[0]
                                for name in ('validate_bare_version', 'validate_version_tag', 'release_signer_repo'))
        cases = {'v0.1.220': 'PyRo1121/omg', 'v0.1.221': 'PyRo1121/omg',
                 'v0.1.222': 'omg-cli/omg', 'v0.1.222-rc.1': 'omg-cli/omg',
                 'v0.2.0': 'omg-cli/omg', 'v1.0.0': 'omg-cli/omg',
                 'v01.1.221': None, 'v0.1.221/other': None, '0.1.221': None}
        for tag, expected in cases.items():
            with self.subTest(tag=tag):
                result = subprocess.run([bash, '-c', definitions + '\nrelease_signer_repo "$1"', 'test', tag],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if expected else 1)
                self.assertEqual(result.stdout.strip(), expected or '')

    def test_organization_release_requires_organization_signer(self):
        data = (release.HEADER + '\n').encode()
        blob = {'encoding': 'base64', 'size': len(data), 'content': base64.b64encode(data).decode()}
        with tempfile.TemporaryDirectory() as tmp, patch.object(release, 'api', side_effect=[{'sha': 'a' * 40}, blob, {'sha': 'a' * 40}]), patch.object(release.subprocess, 'run') as calls:
            release.prepare('v0.1.222', 'ubuntu', Path(tmp))
            verify = calls.call_args_list[1].args[0]
            self.assertEqual(verify[verify.index('--repo') + 1], 'omg-cli/omg')
            self.assertEqual(verify[verify.index('--signer-workflow') + 1], 'omg-cli/omg/.github/workflows/release.yml')

    def test_contract_is_pinned_to_resolved_release_not_main(self):
        data = (release.HEADER + '\nold-case\t[]\tread\t0\tpass\t-\thermetic\t-\t-\t-\n').encode()
        revision = 'a' * 40
        blob = {'encoding': 'base64', 'size': len(data), 'content': base64.b64encode(data).decode()}
        with tempfile.TemporaryDirectory() as tmp, patch.object(release, 'api', side_effect=[{'sha': revision}, blob, {'sha': revision}]) as api, patch.object(release.subprocess, 'run') as download:
            destination = Path(tmp)
            release.prepare('v0.1.220', 'arch', destination)
            self.assertEqual(api.call_args_list[1].args[0], f'contents/tests/cli_behavior_inventory.tsv?ref={revision}')
            self.assertEqual((destination / 'cases.tsv').read_bytes(), data)
            self.assertEqual(json.loads((destination / 'inventory-provenance.json').read_text())['inventory_revision'], revision)
            self.assertIn('omg-v0.1.220-x86_64-linux-arch.tar.gz', download.call_args_list[0].args[0])
            verify = download.call_args_list[1]
            self.assertEqual(verify.args[0], [
                'gh', 'attestation', 'verify',
                str(destination / 'omg-v0.1.220-x86_64-linux-arch.tar.gz'),
                '--repo', 'PyRo1121/omg',
                '--source-digest', revision,
                '--source-ref', 'refs/tags/v0.1.220',
                '--signer-workflow', 'PyRo1121/omg/.github/workflows/release.yml',
            ])
            self.assertTrue(verify.kwargs['check'])
            self.assertLessEqual(verify.kwargs['timeout'], 180)

    def test_invalid_attestation_does_not_publish_a_usable_contract(self):
        data = (release.HEADER + '\n').encode()
        blob = {'encoding': 'base64', 'size': len(data), 'content': base64.b64encode(data).decode()}
        with tempfile.TemporaryDirectory() as tmp, patch.object(release, 'api', side_effect=[{'sha': 'a' * 40}, blob, {'sha': 'a' * 40}]), patch.object(release.subprocess, 'run', side_effect=[None, subprocess.CalledProcessError(1, 'verify')]):
            with self.assertRaises(subprocess.CalledProcessError):
                release.prepare('v0.1.220', 'arch', Path(tmp))
            self.assertFalse((Path(tmp) / 'cases.tsv').exists())
            self.assertFalse((Path(tmp) / 'inventory-provenance.json').exists())

    def test_bad_inventory_cannot_fall_back_to_current_contract(self):
        for blob in ({'encoding': 'none', 'size': 2}, {'encoding': 'base64', 'size': 1048577},
                     {'encoding': 'base64', 'size': 3, 'content': 'YmFk'}):
            with self.subTest(blob=blob), tempfile.TemporaryDirectory() as tmp, patch.object(release, 'api', side_effect=[{'sha': 'a' * 40}, blob]), patch.object(release.subprocess, 'run') as download:
                with self.assertRaises(ValueError):
                    release.prepare('v0.1.220', 'debian', Path(tmp))
                download.assert_not_called()
                self.assertFalse((Path(tmp) / 'cases.tsv').exists())

    def test_moving_tag_does_not_publish_contract(self):
        data = (release.HEADER + '\n').encode()
        blob = {'encoding': 'base64', 'size': len(data), 'content': base64.b64encode(data).decode()}
        with tempfile.TemporaryDirectory() as tmp, patch.object(release, 'api', side_effect=[{'sha': 'a' * 40}, blob, {'sha': 'b' * 40}]), patch.object(release.subprocess, 'run'):
            with self.assertRaisesRegex(ValueError, 'moved'):
                release.prepare('v0.1.220', 'ubuntu', Path(tmp))
            self.assertFalse((Path(tmp) / 'cases.tsv').exists())

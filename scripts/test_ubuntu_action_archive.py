"""Pinned pre-checkout actions must survive the repository archive policy."""
import io
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = '.github/actions/ubuntu-apt/'


def members(revision, worktree=False):
    command = ['git', '-C', str(ROOT), 'archive', '--format=tar']
    if worktree:
        command.append('--worktree-attributes')
    command += [revision, ACTION.rstrip('/')]
    data = subprocess.check_output(command, timeout=30)
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            return {row.name: archive.extractfile(row).read() for row in archive.getmembers() if row.isfile()}
    except tarfile.ReadError:
        return {}


class UbuntuActionArchive(unittest.TestCase):
    def test_current_archive_includes_both_action_entrypoints(self):
        exported = members('HEAD', worktree=True)
        self.assertEqual(set(exported), {ACTION+'action.yml', ACTION+'setup.sh'})
        for name, data in exported.items():
            self.assertEqual(data, (ROOT/name).read_bytes())

    @unittest.skipUnless(os.name == 'posix', 'APT archive setup uses POSIX shell tools')
    def test_configures_the_signed_archive_for_a_multimirror_runner_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os_release = root / 'os-release'
            os_release.write_text('ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n')
            sources = root / 'ubuntu.sources'
            sources.write_text(
                'Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt https://archive.ubuntu.com/ubuntu/\n'
                'Suites: noble noble-updates noble-security noble-backports\n'
                'Components: main restricted universe multiverse\n'
                'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n'
            )
            (root / 'ca-certs').write_bytes(b'fixture CA')
            (root / 'archive-keyring.gpg').write_bytes(b'fixture keyring')
            tools = root / 'tools'
            tools.mkdir()
            calls = root / 'apt-calls'
            apt = tools / 'apt-get'
            apt.write_text('#!/bin/sh\nprintf "%s\n" "$@" >> "$APT_CALLS"\n')
            apt.chmod(0o755)
            sudo = tools / 'sudo'
            sudo.write_text('#!/bin/sh\ntest "$1" = -n || exit 90\nshift\nexec "$@"\n')
            sudo.chmod(0o755)
            script = (ROOT / ACTION / 'setup.sh').read_text(encoding='utf-8')
            for variable, fixture in (
                ('os_release', os_release),
                ('source_file', sources),
                ('ca_bundle', root / 'ca-certs'),
                ('keyring', root / 'archive-keyring.gpg'),
            ):
                script = re.sub(rf'(?m)^{variable}=.*$', f'{variable}={shlex.quote(str(fixture))}', script, count=1)
            result = subprocess.run(
                [shutil.which('bash'), '-c', script],
                env=dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}", APT_CALLS=str(calls)),
                capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            configured = sources.read_text()
            self.assertIn('URIs: https://mirrors.edge.kernel.org/ubuntu/', configured)
            self.assertIn('Suites: noble noble-updates noble-security noble-backports', configured)
            self.assertIn('Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg', configured)
            self.assertNotIn('Trusted: yes', configured)
            self.assertEqual(calls.read_text().splitlines()[-1], 'update')
            self.assertIn('APT::Update::Error-Mode=any', calls.read_text())

            prior_calls = calls.read_bytes()
            unsafe = configured + 'Trusted: yes\n'
            sources.write_text(unsafe)
            rejected = subprocess.run(
                [shutil.which('bash'), '-c', script],
                env=dict(os.environ, PATH=f"{tools}{os.pathsep}{os.environ['PATH']}", APT_CALLS=str(calls)),
                capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('source definition failed validation', rejected.stderr)
            self.assertEqual(sources.read_text(), unsafe)
            self.assertEqual(calls.read_bytes(), prior_calls)

    def test_exact_precheckout_pin_exports_the_executed_action(self):
        workflow = (ROOT/'.github/workflows/ci.yml').read_text(encoding='utf-8')
        pins = re.findall(r'omg-cli/omg/\.github/actions/ubuntu-apt@([a-f0-9]{40})', workflow)
        self.assertEqual(len(pins), 1)
        exported = members(pins[0])
        self.assertEqual(set(exported), {ACTION+'action.yml', ACTION+'setup.sh'})
        for name, data in exported.items():
            original = subprocess.check_output(['git','-C',str(ROOT),'show',pins[0]+':'+name], timeout=30)
            self.assertEqual(data, original)


if __name__ == '__main__':
    unittest.main()

"""Execute installer routing against the same filesystem cases as Rust self-update."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / 'tests/fixtures/apt-release-selection.json').read_text())


class AptReleaseSelection(unittest.TestCase):
    def test_installer_selects_available_native_abi_or_refuses(self):
        for distro in ('debian', 'ubuntu'):
            for case in CASES:
                with self.subTest(distro=distro, case=case['name']), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    lib = root / 'usr/lib/x86_64-linux-gnu'
                    lib.mkdir(parents=True)
                    for major, kind in case['libraries'].items():
                        path = lib / ('libapt-pkg.so.' + major)
                        if kind == 'file':
                            path.write_bytes(b'library fixture')
                        elif kind == 'directory':
                            path.mkdir()
                        elif kind in ('symlink', 'dangling'):
                            target = path.with_name(path.name + '.0')
                            if kind == 'symlink':
                                target.write_bytes(b'library fixture')
                            path.symlink_to(target.name)
                        else:
                            self.fail('unknown fixture kind: ' + kind)
                    functions = root / 'functions.sh'
                    functions.write_text((ROOT / 'install.sh').read_text().rsplit('\n', 2)[0] + '\n')
                    result = subprocess.run(
                        ['bash', '-c', 'source "$1"; trap - EXIT; select_artifact v1.2.3 linux "$2" "$3" "$4"',
                         'bash', str(functions), distro, case['arch'], str(root)],
                        capture_output=True, text=True, timeout=10)
                    if case['suffix'] is None:
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertEqual(result.stdout, '')
                        self.assertIn('No compatible native APT release', result.stderr)
                    else:
                        suffix = distro if case['suffix'] == 'legacy' else case['suffix']
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout.strip(), f'omg-v1.2.3-x86_64-linux-{suffix}.tar.gz')

    def test_installer_refuses_unpublished_linux_architectures(self):
        for distro in ('arch', 'fedora', 'unknown'):
            with self.subTest(distro=distro), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                functions = root / 'functions.sh'
                functions.write_text((ROOT / 'install.sh').read_text().rsplit('\n', 2)[0] + '\n')
                result = subprocess.run(
                    ['bash', '-c', 'source "$1"; trap - EXIT; select_artifact v1.2.3 linux "$2" aarch64 "$3"',
                     'bash', str(functions), distro, str(root)],
                    capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(result.stdout, '')
                self.assertIn('No published OMG Linux artifact', result.stderr)


if __name__ == '__main__':
    unittest.main()

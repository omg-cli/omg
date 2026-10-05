"""Require distinct Trixie identity and resolved APT 7 loader evidence."""
import importlib.util
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('qemu-apt-abi.py')


class AptAbiTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SOURCE.is_file(), 'the guest APT ABI probe is missing')
        spec = importlib.util.spec_from_file_location('apt_abi', SOURCE)
        self.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.probe)

    @unittest.skipUnless(sys.platform == 'linux', 'controller staging requires POSIX Bash')
    def test_actual_controller_stages_the_same_probe_bytes(self):
        root = SOURCE.parent.parent
        source = (root / 'scripts/benchmark-qemu.sh').read_text()
        begin = source.index('cp "$here/qemu-daemon-check.sh"')
        end = source.index('cat > "$work/guest-check.sh"', begin)
        with tempfile.TemporaryDirectory() as directory:
            import os
            result = self.probe.subprocess.run(['bash', '-e', '-c', source[begin:end]],
                env=dict(os.environ, here=str(root / 'scripts'), work=directory),
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = Path(directory) / SOURCE.name
            self.assertTrue(staged.is_file(), 'the real controller did not stage the ABI probe')
            self.assertEqual(staged.read_bytes(), SOURCE.read_bytes())

    @unittest.skipUnless(sys.platform == 'linux', 'controller ordering requires POSIX Bash')
    def test_guest_refusal_prevents_both_product_entrypoints(self):
        import io
        import os
        import tarfile
        source = (SOURCE.parent / 'benchmark-qemu.sh').read_text()
        begin = source.index("printf '%s  release.tar.gz\\n'")
        end = source.index('case "$distro" in', begin)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / 'release.tar.gz'
            with tarfile.open(archive, 'w:gz') as release:
                for name in ('omg', 'omgd'):
                    payload = f'#!/bin/sh\nprintf "{name}\\n" >> "$HOME/executed"\nprintf "{name}0.1.0\\n"\n'.encode()
                    member = tarfile.TarInfo(f'omg-v0.1.0-x86_64-linux-debian-trixie/{name}')
                    member.mode, member.size = 0o755, len(payload)
                    release.addfile(member, io.BytesIO(payload))
            (root / SOURCE.name).write_text('import os,sys\nfrom pathlib import Path\n'
                'Path(os.environ["HOME"], "probe-ran").write_text("yes")\n'
                'sys.exit(int(os.environ["PROBE_STATUS"]))\n')
            environment = dict(os.environ, HOME=directory, distro='debian-trixie',
                tag='v0.1.0', guest_arch='x86_64', digest=hashlib.sha256(archive.read_bytes()).hexdigest())
            for status in ('120', '0'):
                with self.subTest(probe_status=status):
                    result = self.probe.subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', source[begin:end]],
                        cwd=root, env=dict(environment, PROBE_STATUS=status),
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, int(status), result.stderr)
                    self.assertTrue((root / 'probe-ran').is_file())
                    executed = root / 'executed'
                    if status == '120':
                        self.assertFalse(executed.exists(), 'a refused ABI must prevent both entrypoints')
                    else:
                        self.assertEqual(executed.read_text().splitlines(), ['omg', 'omgd'])

    @unittest.skipUnless(sys.platform == 'linux', 'controller admission requires POSIX Bash')
    def test_host_controller_refuses_failed_archive_bound_admission(self):
        import os
        source = (SOURCE.parent / 'benchmark-qemu.sh').read_text()
        marker = 'if [[ "$rc" == 0 && "$distro" == debian-trixie ]]; then'
        self.assertTrue(marker in source, 'the host never admits archive-bound ABI evidence')
        begin = source.index(marker)
        end = source.index('\nfi', begin) + len('\nfi')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / 'python3'
            stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\nexit "$VALIDATION_STATUS"\n')
            stub.chmod(0o755)
            environment = dict(os.environ, PATH=directory + ':' + os.environ['PATH'],
                rc='0', distro='debian-trixie', here=str(SOURCE.parent),
                work=directory, archive='release.tar.gz', CAPTURE=str(root / 'arguments'))
            for status in ('0', '120'):
                with self.subTest(validator_status=status):
                    result = self.probe.subprocess.run(['bash', '-e', '-c', source[begin:end]],
                        env=dict(environment, VALIDATION_STATUS=status),
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0 if status == '0' else 1, result.stderr)
                    self.assertEqual((root / 'arguments').read_text().splitlines(), [
                        str(SOURCE.parent / 'qemu-apt-abi-evidence.py'), '--evidence-dir',
                        directory + '/guest/evidence/apt-abi', '--archive', directory + '/release/release.tar.gz',
                        '--probe', str(SOURCE)])

    def test_only_debian_13_x86_guest_identity_is_admitted(self):
        self.probe.validate_guest('debian-trixie', 'x86_64', {'ID': 'debian', 'VERSION_ID': '13'})
        for distro, arch, release in (
            ('debian', 'x86_64', {'ID': 'debian', 'VERSION_ID': '13'}),
            ('debian-trixie', 'aarch64', {'ID': 'debian', 'VERSION_ID': '13'}),
            ('debian-trixie', 'x86_64', {'ID': 'debian', 'VERSION_ID': '12'}),
            ('debian-trixie', 'x86_64', {'ID': 'ubuntu', 'VERSION_ID': '13'}),
            ('debian-trixie', 'x86_64', {'ID': 'debian'}),
        ):
            with self.subTest(distro=distro, arch=arch, release=release), self.assertRaises(ValueError):
                self.probe.validate_guest(distro, arch, release)

    def test_requires_one_resolved_native_apt_7_library(self):
        row = 'libapt-pkg.so.7.0 => /lib/x86_64-linux-gnu/libapt-pkg.so.7.0 (0x00007ff123)\n'
        self.assertEqual(self.probe.resolved_apt_library(row), '/lib/x86_64-linux-gnu/libapt-pkg.so.7.0')
        for report in ('', row.replace('7.0', '6.0'), row + row,
                       row + 'libssl.so.3 => not found\n',
                       row.replace('/lib/x86_64-linux-gnu/', '/home/bench/'),
                       row.replace('(0x00007ff123)', '(unknown)'),
                       row + row.replace('7.0', '6.0')):
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.probe.resolved_apt_library(report)

    def test_os_release_parser_rejects_duplicate_identity(self):
        self.assertEqual(self.probe.release_values('ID=debian\nVERSION_ID="13"\n'),
                         {'ID': 'debian', 'VERSION_ID': '13'})
        with self.assertRaises(ValueError):
            self.probe.release_values('ID=debian\nID=ubuntu\nVERSION_ID=13\n')

    def probe_fixture(self, *, library_hashes=('b' * 64, 'b' * 64), failed=None, oversized=False, inspect_output=None):
        original_read = Path.read_bytes
        original_digest = self.probe.digest_file
        original_run = self.probe.subprocess.run
        libraries = iter(library_hashes)
        release = b'ID=debian\nVERSION_ID=13\n'
        row = b'libapt-pkg.so.7.0 => /lib/x86_64-linux-gnu/libapt-pkg.so.7.0 (0x123)\n'

        def read(path):
            return release if str(path) == '/etc/os-release' else original_read(path)

        def digest(path):
            if path == self.probe.LOADER:
                return 'd' * 64
            if str(path) == '/lib/x86_64-linux-gnu/libapt-pkg.so.7.0':
                return next(libraries)
            return original_digest(path)

        def run(argv, **kwargs):
            self.assertEqual(argv[:2], [str(self.probe.LOADER), '--list'])
            self.assertEqual(kwargs['timeout'], 15)
            self.assertFalse(any(key.startswith('LD_') for key in kwargs['env']))
            with patch('resource.setrlimit') as limit:
                kwargs['preexec_fn']()
                self.assertEqual(limit.call_args.args[1], (65536, 65536))
            if oversized:
                return original_run([sys.executable, '-c',
                    'import os; os.write(1, b"x" * 65536); os.write(1, b"y" * 65536)'], **kwargs)
            kwargs['stdout'].write(row)
            return SimpleNamespace(returncode=int(Path(argv[2]).name == failed))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binaries = {}
            for name in ('omg', 'omgd'):
                binary = root / name
                binary.write_text('#!/bin/sh\necho ' + name + '\n')
                binary.chmod(0o755)
                binaries[name] = binary
            output = root / 'evidence'
            with patch.object(Path, 'read_bytes', read), patch.object(self.probe, 'digest_file', digest), \
                    patch.object(self.probe.os, 'geteuid', return_value=1000), \
                    patch.object(self.probe.platform, 'machine', return_value='x86_64'), \
                    patch.object(self.probe.subprocess, 'run', side_effect=run), \
                    patch.dict(self.probe.os.environ, {'LD_PRELOAD': '/fixture/untrusted.so'}):
                try:
                    receipt = self.probe.probe('debian-trixie', 'x86_64', binaries, output)
                    error = None
                except ValueError as failure:
                    receipt, error = None, str(failure)
            files = {path.name: path.read_bytes() for path in output.iterdir()}
            if inspect_output is not None:
                inspect_output(output)
            return receipt, error, files

    @unittest.skipUnless(sys.platform == 'linux', 'evidence copy permissions require POSIX')
    def test_complete_evidence_is_readable_after_controller_copy(self):
        import os
        import shutil
        import stat

        def inspect(output):
            copied = output.parent / 'controller-copy'
            shutil.copytree(output, copied)
            self.assertEqual(stat.S_IMODE(copied.stat().st_mode), 0o755,
                             'root-owned SCP copies must be traversable by the ordinary host validator')
            for name in ('receipt.json', 'os-release', 'omg-loader.log', 'omgd-loader.log'):
                self.assertEqual(stat.S_IMODE((copied / name).stat().st_mode), 0o644,
                                 'public ABI diagnostics must be readable after UID ownership changes')
        previous = os.umask(0o077)
        try:
            receipt, error, _ = self.probe_fixture(inspect_output=inspect)
        finally:
            os.umask(previous)
        self.assertIsNone(error)
        self.assertTrue(receipt['complete'])

    @unittest.skipUnless(sys.platform == 'linux', 'evidence publication requires POSIX')
    def test_incomplete_evidence_keeps_private_permissions(self):
        import os
        import stat

        def inspect(output):
            self.assertFalse((output / 'receipt.json').exists())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir()))
        previous = os.umask(0o077)
        try:
            receipt, error, _ = self.probe_fixture(failed='omgd', inspect_output=inspect)
        finally:
            os.umask(previous)
        self.assertIsNone(receipt)
        self.assertIsNotNone(error)

    @unittest.skipUnless(sys.platform == 'linux', 'guest probe requires Linux resource limits')
    def test_probe_binds_both_binaries_and_preserves_raw_resolution(self):
        receipt, error, files = self.probe_fixture()
        self.assertIsNone(error)
        self.assertTrue(receipt['complete'])
        self.assertEqual(set(receipt['binaries']), {'omg', 'omgd'})
        self.assertNotEqual(receipt['binaries']['omg']['binary_sha256'], receipt['binaries']['omgd']['binary_sha256'])
        for name in ('omg', 'omgd'):
            self.assertEqual(receipt['binaries'][name]['log_sha256'],
                             hashlib.sha256(files[name + '-loader.log']).hexdigest())
        self.assertIn('receipt.json', files)

    @unittest.skipUnless(sys.platform == 'linux', 'guest probe requires Linux resource limits')
    def test_failed_daemon_resolution_retains_logs_without_complete_receipt(self):
        receipt, error, files = self.probe_fixture(failed='omgd')
        self.assertIsNone(receipt)
        self.assertIsNotNone(error)
        self.assertIn('omg-loader.log', files)
        self.assertIn('omgd-loader.log', files)
        self.assertNotIn('receipt.json', files)

    @unittest.skipUnless(sys.platform == 'linux', 'guest probe requires Linux resource limits')
    def test_library_change_between_binaries_cannot_admit_one_abi_receipt(self):
        receipt, error, files = self.probe_fixture(library_hashes=('b' * 64, 'c' * 64))
        self.assertIsNone(receipt)
        self.assertIsNotNone(error)
        self.assertNotIn('receipt.json', files)

    @unittest.skipUnless(sys.platform == 'linux', 'guest probe requires Linux resource limits')
    def test_real_child_cannot_grow_the_dependency_log_past_64_kib(self):
        receipt, error, files = self.probe_fixture(oversized=True)
        self.assertIsNone(receipt)
        self.assertIsNotNone(error)
        self.assertEqual(len(files['omg-loader.log']), 65536)
        self.assertNotIn('receipt.json', files)


if __name__ == '__main__':
    unittest.main()

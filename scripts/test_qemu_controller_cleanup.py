"""Docker integration checks, explicitly enabled with QEMU_CLEANUP_TEST_IMAGE."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name('build-qemu-controller.sh')


class ControllerCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('QEMU_CLEANUP_TEST_IMAGE'):
            raise unittest.SkipTest('requires explicit retained Docker builder image')

    def setUp(self):
        self.assertNotEqual(os.getuid(), 0, 'exercise the ordinary build actor')
        self.image = os.environ['QEMU_CLEANUP_TEST_IMAGE']
        subprocess.run(['docker', 'image', 'inspect', self.image], check=True,
                       stdout=subprocess.DEVNULL, timeout=10)
        self.parent = Path(tempfile.mkdtemp(prefix='omg-cleanup-test-', dir='/var/tmp'))
        self.parent_identity = (self.parent.stat().st_dev, self.parent.stat().st_ino)
        self.scratch = self.parent / 'scratch'
        self.scratch.mkdir()
        self.identity = f'{self.scratch.stat().st_dev}:{self.scratch.stat().st_ino}'
        self.foreign = self.parent / 'foreign'
        self.foreign.write_bytes(b'foreign sibling must remain unchanged\n')
        self.foreign.chmod(0o640)
        self.foreign_before = self.foreign.stat()
        self.container = 'omg-cleanup-fixture-' + self.parent.name

    def command(self, argv):
        return subprocess.run(argv, capture_output=True, text=True, timeout=90)

    def root_fixture(self):
        result = self.command(['docker', 'create', '--name', self.container,
            '--network', 'none', '--read-only', '--mount',
            f'type=bind,src={self.scratch},dst=/scratch', self.image, 'sh', '-c',
            'mkdir -p /scratch/nested/deeper; printf "owned root bytes\\n" > '
            '/scratch/nested/deeper/data; chmod 700 /scratch/nested /scratch/nested/deeper; '
            'chmod 600 /scratch/nested/deeper/data'])
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command(['docker', 'start', '--attach', self.container])
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command(['docker', 'run', '--rm', '--network', 'none',
            '--read-only', '--mount', f'type=bind,src={self.scratch},dst=/scratch',
            self.image, 'stat', '-c', '%u:%g:%a', '/scratch/nested/deeper/data'])
        self.assertEqual(result.stdout.strip(), '0:0:600', result.stderr)

    def cleanup(self, identity=None, incoming_status=0, owned=True, builder=None):
        match = re.search(r'^cleanup\(\) \{\n.*?^\}\n', SCRIPT.read_text(), re.M | re.S)
        self.assertIsNotNone(match)
        environment = dict(os.environ, scratch=str(self.scratch),
            scratch_identity=identity or self.identity, owned=str(owned).lower(),
            record_owned='false', container=self.container,
            builder=builder or self.image, runtime_record=self.container + '-record',
            host_uid=str(os.getuid()), host_gid=str(os.getgid()))
        shell = ('set -euo pipefail\n' + match.group() +
                 '\ntrap cleanup EXIT\nexit ' + str(incoming_status) + '\n')
        result = subprocess.run(['bash', '-c', shell], env=environment,
                                capture_output=True, text=True, timeout=90)
        print(json.dumps({'case': self.id(), 'exit': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr,
            'scratch_exists': self.scratch.exists(), 'incoming_status': incoming_status}))
        return result

    def assert_foreign_unchanged(self):
        self.assertEqual(self.foreign.read_bytes(), b'foreign sibling must remain unchanged\n')
        after = self.foreign.stat()
        self.assertEqual((after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                          after.st_mode, after.st_size, after.st_mtime_ns),
                         (self.foreign_before.st_dev, self.foreign_before.st_ino,
                          self.foreign_before.st_uid, self.foreign_before.st_gid,
                          self.foreign_before.st_mode, self.foreign_before.st_size,
                          self.foreign_before.st_mtime_ns))

    def tearDown(self):
        self.assertEqual(self.parent.resolve(), self.parent)
        self.assertEqual((self.parent.stat().st_dev, self.parent.stat().st_ino), self.parent_identity)
        self.command(['docker', 'rm', '--force', self.container])
        if self.scratch.is_symlink():
            self.scratch.unlink()
        elif self.scratch.exists():
            self.assertEqual(f'{self.scratch.stat().st_dev}:{self.scratch.stat().st_ino}', self.identity)
            result = self.command(['docker', 'run', '--rm', '--network', 'none',
                '--read-only', '--mount', f'type=bind,src={self.scratch},dst=/scratch',
                self.image, 'chown', '-hR', f'{os.getuid()}:{os.getgid()}', '/scratch'])
            self.assertEqual(result.returncode, 0, result.stderr)
        shutil.rmtree(self.parent)

    def test_root_owned_nested_scratch_retires_without_touching_foreign_sibling(self):
        self.root_fixture()
        result = self.cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.scratch.exists())
        self.assert_foreign_unchanged()

    def test_identity_mismatch_refuses_before_touching_either_tree(self):
        self.root_fixture()
        result = self.cleanup(identity='0:0')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertTrue(self.scratch.exists())
        result = self.command(['docker', 'inspect', '--format', '{{.State.Status}}', self.container])
        self.assertEqual(result.stdout.strip(), 'exited', result.stderr)
        self.assert_foreign_unchanged()

    def test_early_empty_scratch_retires_without_builder_and_preserves_command_failure(self):
        result = self.cleanup(incoming_status=37, owned=False, builder='missing-image.invalid')
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertFalse(self.scratch.exists())
        self.assert_foreign_unchanged()

    def test_root_owned_retirement_preserves_original_command_failure(self):
        self.root_fixture()
        result = self.cleanup(incoming_status=37)
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertFalse(self.scratch.exists())
        self.assert_foreign_unchanged()

    def test_failed_ownership_repair_fails_normal_build_and_keeps_scratch(self):
        self.root_fixture()
        result = self.cleanup(builder='sha256:' + '0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.scratch.exists())
        self.assert_foreign_unchanged()

    def test_symlink_scratch_refuses_without_touching_foreign_bytes(self):
        self.scratch.rmdir()
        self.scratch.symlink_to(self.foreign)
        result = self.cleanup(owned=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertTrue(self.scratch.is_symlink())
        self.assert_foreign_unchanged()


if __name__ == '__main__':
    unittest.main()

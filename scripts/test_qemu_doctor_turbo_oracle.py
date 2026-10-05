"""Real kernel file-capability controls, separate from hosted product execution."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('qemu-doctor-turbo-oracle.py')
SPEC = importlib.util.spec_from_file_location('doctor_capability_oracle', SCRIPT)
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class CapabilityOracleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'submitted-omg'
        self.source.write_text('#!/bin/bash\nexit 0\n')
        self.source.chmod(0o700)
        self.before = V.state(self.source)
        V.prepare(self.source, self.root)
        self.target = self.root / 'doctor-turbo-private/omg'
        self.output = self.root / 'stdout.log'
        self.output.write_text('No file capabilities remain (or none were set)\n'
                               'No permanent privileges granted to any binary\n')

    def setcap(self, value):
        subprocess.run(['/usr/bin/sudo', '-n', '--', V.trusted_setcap(),
                        value, str(self.target)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)

    def test_real_removal_positive_preserves_original(self):
        self.assertIsNotNone(V.capability(self.target))
        self.setcap('-r')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            V.verify(self.source, self.root, self.output)
        self.assertIn('"capabilities_removed": true', output.getvalue())
        self.assertEqual(V.state(self.source), self.before)

    def test_success_message_without_real_removal_refuses(self):
        with self.assertRaisesRegex(ValueError, 'retained a capability'):
            V.verify(self.source, self.root, self.output)

    def test_empty_set_is_not_removed_xattr(self):
        self.setcap('=')
        self.assertIsNotNone(V.capability(self.target))
        with self.assertRaisesRegex(ValueError, 'retained a capability'):
            V.verify(self.source, self.root, self.output)

    def test_changed_copy_refuses_even_when_write_clears_capabilities(self):
        self.target.write_text('#!/bin/bash\nexit 1\n')
        with self.assertRaisesRegex(ValueError, 'bytes or mode changed'):
            V.verify(self.source, self.root, self.output)

    def test_changed_original_refuses(self):
        self.source.write_text('#!/bin/bash\nexit 2\n')
        with self.assertRaisesRegex(ValueError, 'original executable state changed'):
            V.verify(self.source, self.root, self.output)

    def test_missing_matching_product_result_refuses(self):
        self.setcap('-r')
        self.output.write_text('setcap failed but command returned success\n')
        with self.assertRaisesRegex(ValueError, 'matching capability-cleanup result'):
            V.verify(self.source, self.root, self.output)

    def test_linked_private_directory_refuses_without_touching_original(self):
        private = self.target.parent
        saved = self.root / 'saved'
        private.rename(saved)
        private.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'owned and regular'):
            V.owned_directory(self.root)
        self.assertEqual(V.state(self.source), self.before)


if __name__ == '__main__':
    unittest.main()

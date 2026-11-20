"""Exercise the Docker install fixture guards without installing host packages."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('docker_install_fixture',
                                             Path(__file__).with_name('docker-install-fixture.py'))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


@unittest.skipIf(os.name == 'nt', 'Actual no-controlling-terminal behavior requires POSIX')
class DockerInstallFixture(unittest.TestCase):
    @staticmethod
    def command(yes=True, status=1, unrelated=False):
        program = '''import os,sys
assert not os.isatty(0)
assert sys.stdin.read() == ''
try:
    terminal = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
except OSError as error:
    assert error.errno == 6, error
else:
    os.close(terminal)
    raise AssertionError('A no-TTY control inherited a controlling terminal')
'''
        if unrelated:
            program += "print('Network request failed')\n"
        elif yes:
            program += ("print('SECURITY WARNING: advisory coverage for the selected transaction is unknown.')\n"
                        "print('Security review requires an attended controlling terminal; --yes cannot accept advisory risk or unknown coverage')\n")
        else:
            program += "print('Use --yes for non-interactive package installation')\n"
        program += f'raise SystemExit({status})\n'
        return [sys.executable, '-c', program] + (['-y'] if yes else [])

    def test_real_detached_children_prove_both_denials_and_unchanged_native_database(self):
        before = (b'base 1-1\n', [('base/desc', 'original')])
        for yes in (False, True):
            with self.subTest(yes=yes), patch.object(FIXTURE, 'native_state', return_value=before):
                FIXTURE.deny_unattended(self.command(yes), before)

    def test_success_or_unrelated_failure_cannot_be_credited_as_security_refusal(self):
        for command, message in [(self.command(status=0), 'unexpectedly succeeded'),
                                 (self.command(unrelated=True), 'missing security consent'),
                                 (self.command(yes=False, unrelated=True), 'missing mutation consent')]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                FIXTURE.deny_unattended(command, 'before')

    def test_correct_refusal_cannot_hide_native_database_mutation(self):
        with patch.object(FIXTURE, 'native_state', return_value='changed'), self.assertRaisesRegex(ValueError, 'changed the native'):
            FIXTURE.deny_unattended(self.command(), 'before')


if __name__ == '__main__':
    unittest.main()

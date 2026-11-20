"""Exercise the nextest installer's owned process group lifecycle."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('install-nextest-macos.py'))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


@unittest.skipUnless(os.name == 'posix', 'Requires POSIX process groups')
class InstallerProcessTests(unittest.TestCase):
    def test_kqueue_without_context_manager_is_closed_and_latches_exit(self):
        queue = Mock()
        queue.control.side_effect = [[], [], [object()]]
        with patch.multiple(INSTALLER.select, create=True, kqueue=Mock(return_value=queue),
                            kevent=Mock(), KQ_FILTER_PROC=1, KQ_EV_ADD=2, KQ_EV_ONESHOT=4,
                            KQ_NOTE_EXIT=8):
            with INSTALLER.observe_leader(123) as observe:
                self.assertFalse(observe())
                self.assertTrue(observe())
                self.assertTrue(observe())
        self.assertEqual(queue.control.call_count, 3)
        queue.close.assert_called_once_with()

    def test_finished_leader_is_reaped_after_group_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = INSTALLER.Commands(root / 'receipts')
            for code in (0, 7):
                result, _, _ = commands.run(str(code), [sys.executable, '-c', f'raise SystemExit({code})'],
                                            10, root)
                self.assertEqual(result, code)
                self.assertFalse(commands.rows[-1]['group_remaining_at_cleanup'])
                self.assertTrue(commands.rows[-1]['group_gone_after_cleanup'])

    def test_descendant_after_leader_exit_is_terminated_and_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = INSTALLER.Commands(root / 'receipts')
            child = "import subprocess; subprocess.Popen(['/bin/sleep', '30'])"
            with self.assertRaisesRegex(INSTALLER.AdmissionError, 'unfinished descendants'):
                commands.run('descendant', [sys.executable, '-c', child], 10, root)
            row = commands.rows[-1]
            self.assertTrue(row['group_remaining_at_cleanup'])
            self.assertTrue(row['group_term_sent'])
            self.assertTrue(row['group_gone_after_cleanup'])

    def test_permission_error_on_owned_group_is_a_fatal_cleanup_error(self):
        process = Mock(pid=123)
        row = {}
        with patch.object(INSTALLER, 'group_has_descendants', return_value=True), \
                patch.object(INSTALLER.os, 'killpg', side_effect=PermissionError):
            with self.assertRaisesRegex(INSTALLER.AdmissionError, 'could not signal'):
                INSTALLER.finish_group(process, row, lambda: True)
        self.assertNotIn('group_gone_after_cleanup', row)
        process.wait.assert_not_called()

    def test_deadline_terminates_a_live_leader(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = INSTALLER.Commands(root / 'receipts')
            with self.assertRaisesRegex(INSTALLER.AdmissionError, 'elapsed deadline'):
                commands.run('deadline', ['/bin/sleep', '30'], 0.1, root)
            self.assertTrue(commands.rows[-1]['group_gone_after_cleanup'])


if __name__ == '__main__':
    unittest.main()

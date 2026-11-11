"""Pinned pre-checkout actions must survive the repository archive policy."""
import io
from pathlib import Path
import re
import subprocess
import tarfile
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

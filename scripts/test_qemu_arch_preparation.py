"""Execute the launcher's Arch preparation arm without privileged package changes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'guest shell contracts require POSIX bash')
class ArchPreparationEvidence(unittest.TestCase):
    def prepare(self, package_exit):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        marker = 'native=(pacman -Qi tree); version_cmd=(pacman -Q tree)'
        end = source.index(marker) + len(marker)
        start = source.rindex('arch)', 0, end) + len('arch)')
        arm = source[start:end]
        self.assertIn('sudo -n pacman -Syu --noconfirm', arm)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'evidence').mkdir()
            tools = root / 'bin'
            tools.mkdir()
            sudo = tools / 'sudo'
            sudo.write_text(
                '#!/bin/bash\n'
                '[[ "$*" == "-n pacman -Syu --noconfirm" ]] || exit 97\n'
                'printf "fixture linux package upgrade\\n"\n'
                'printf "fixture package hook diagnostic\\n" >&2\n'
                'exit "$FIXTURE_PACKAGE_STATUS"\n', encoding='utf-8')
            sudo.chmod(0o700)
            env = os.environ.copy()
            env.update(PATH=str(tools) + os.pathsep + env['PATH'],
                       FIXTURE_PACKAGE_STATUS=str(package_exit))
            result = subprocess.run(['bash', '-c', arm], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=5)
            log = root / 'evidence/arch-system-upgrade.txt'
            return result, log.read_text(encoding='utf-8') if log.exists() else None

    def test_successful_upgrade_retains_package_and_hook_output(self):
        result, log = self.prepare(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(log, 'successful upgrade transaction was discarded')
        self.assertIn('fixture linux package upgrade', log)
        self.assertIn('fixture package hook diagnostic', log)

    def test_failed_upgrade_retains_output_and_preserves_harness_failure(self):
        result, log = self.prepare(7)
        self.assertEqual(result.returncode, 120, result.stderr)
        self.assertIsNotNone(log, 'failed upgrade transaction was discarded')
        self.assertIn('fixture linux package upgrade', log)
        self.assertIn('fixture package hook diagnostic', log)


if __name__ == '__main__':
    unittest.main()

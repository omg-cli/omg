"""Execute the launcher's Arch preparation arm without privileged package changes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'guest shell contracts require POSIX bash')
class ArchPreparationEvidence(unittest.TestCase):
    def prepare(self, attempts):
        result, log, _ = self.run_attempts([(attempts, "fixture package hook diagnostic")])
        return result, log

    def run_attempts(self, attempts):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        marker = 'native=(pacman -Qi tree); version_cmd=(pacman -Q tree)'
        end = source.index(marker) + len(marker)
        start = source.rindex('arch)', 0, end) + len('arch)')
        arm = source[start:end]
        helpers = ''
        if 'arch_system_upgrade() {' in source:
            helper_start = source.index('arch_system_upgrade() {')
            helper_end = source.index('\nfedora_makecache_class() {', helper_start)
            helpers = source[helper_start:helper_end]
        script = 'set -euo pipefail\nsleep() { :; }\n' + helpers + '\n' + arm
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'evidence').mkdir()
            tools = root / 'bin'
            tools.mkdir()
            for number, (code, diagnostic) in enumerate(attempts, 1):
                (root / f'status-{number}').write_text(str(code))
                (root / f'diagnostic-{number}').write_text(diagnostic + '\n')
            sudo = tools / 'sudo'
            sudo.write_text(
                '#!/bin/bash\n'
                '[[ "$*" == "-n pacman -Syu --noconfirm" ]] || exit 97\n'
                'printf "fixture linux package upgrade\\n"\n'
                'attempts=0\n'
                '[[ ! -f attempts ]] || read -r attempts < attempts\n'
                'attempts=$((attempts+1))\n'
                'printf "%s\\n" "$attempts" > attempts\n'
                'cat "diagnostic-$attempts" >&2\n'
                'exit "$(cat "status-$attempts")"\n', encoding='utf-8')
            sudo.chmod(0o700)
            env = os.environ.copy()
            env.update(PATH=str(tools) + os.pathsep + env['PATH'])
            result = subprocess.run(['bash', '-c', script], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=5)
            log = root / 'evidence/arch-system-upgrade.txt'
            evidence = {item.name: item.read_text() for item in (root / 'evidence').iterdir()}
            return result, evidence.get(log.name), evidence

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


    def test_arch_retries_a_mirror_dns_timeout_and_preserves_both_attempts(self):
        diagnostic = ("error: failed retrieving file 'core.db' from fastly.mirror.pkgbuild.com"
                      " : Resolving timed out after 10000 milliseconds\n"
                      "error: failed to synchronize all databases (failed to retrieve some files)")
        result, log, evidence = self.run_attempts([(1, diagnostic), (0, 'upgrade complete')])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('upgrade complete', log)
        self.assertIn(diagnostic, evidence['arch-system-upgrade-1.txt'])
        self.assertIn('upgrade complete', evidence['arch-system-upgrade-2.txt'])

    def test_arch_persistent_dns_failure_is_bounded(self):
        diagnostic = ("error: failed retrieving file 'core.db' from geo.mirror.pkgbuild.com"
                      " : Resolving timed out after 10001 milliseconds")
        result, log, evidence = self.run_attempts([(1, diagnostic), (1, diagnostic)])
        self.assertEqual(result.returncode, 120, result.stderr)
        self.assertIn(diagnostic, log)
        self.assertIn(diagnostic, evidence['arch-system-upgrade-2.txt'])
        self.assertNotIn('arch-system-upgrade-3.txt', evidence)

    def test_arch_signature_failure_is_never_retried_even_with_a_dns_error(self):
        diagnostic = ("error: failed retrieving file 'core.db' from geo.mirror.pkgbuild.com"
                      " : Resolving timed out after 10001 milliseconds\n"
                      "error: omaview: signature from reviewer is unknown trust")
        result, log, evidence = self.run_attempts([(1, diagnostic), (0, 'unexpected recovery')])
        self.assertEqual(result.returncode, 120, result.stderr)
        self.assertIn(diagnostic, log)
        self.assertNotIn('arch-system-upgrade-2.txt', evidence)


if __name__ == '__main__':
    unittest.main()

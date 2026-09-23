"""Exercise the controller package gate, including missing/version-query failures."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'


class QemuControllerFloorTests(unittest.TestCase):
    def run_gate(self, query_status=0, comparator_status=0, version='1:10.0.11+ds-0+deb13u1', package='qemu-system-x86'):
        gate = (ROOT / 'scripts/check-qemu-controller.sh').read_text(encoding='utf-8')
        prefix = '''dpkg-query() { printf '%s' "$FIXTURE_VERSION"; return "$QUERY_STATUS"; }
dpkg() { [[ "$1" == --compare-versions && "$3" == ge && "$4" == '1:10.0.11+ds-0+deb13u1' ]] || return 99; return "$COMPARATOR_STATUS"; }
'''
        return subprocess.run([BASH, '-c', prefix + gate, '_', package],
            env=dict(os.environ, FIXTURE_VERSION=version, QUERY_STATUS=str(query_status),
                     COMPARATOR_STATUS=str(comparator_status)), capture_output=True, text=True, timeout=10)

    def test_rejects_missing_old_or_invalid_package_evidence(self):
        for kwargs in ({'query_status': 1}, {'comparator_status': 1},
                       {'comparator_status': 127}, {'version': ''},
                       {'version': '1:10.0.11\nforged'}, {'package': 'other'}):
            with self.subTest(kwargs=kwargs):
                self.assertNotEqual(self.run_gate(**kwargs).returncode, 0)
        for package in ('qemu-system-x86', 'qemu-system-arm'):
            result = self.run_gate(package=package)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(result.stdout.splitlines()), 3)
            self.assertIn('qemu-system-common=', result.stdout)
            self.assertIn('qemu-utils=', result.stdout)

    @unittest.skipUnless(shutil.which('dpkg'), 'Debian version comparison runs in Linux CI')
    def test_real_debian_version_ordering(self):
        gate = (ROOT / 'scripts/check-qemu-controller.sh').read_text(encoding='utf-8')
        prefix = 'dpkg-query() { printf "%s" "$FIXTURE_VERSION"; }\n'
        for version, expected in [('1:7.2+dfsg-7+deb12u18', False),
                                  ('1:10.0.2+ds-2+deb13u1', False),
                                  ('1:10.0.11+ds-0+deb13u1', True),
                                  ('1:10.0.13+ds-0+deb13u1', True)]:
            with self.subTest(version=version):
                result = subprocess.run([BASH, '-c', prefix + gate, '_', 'qemu-system-x86'],
                    env=dict(os.environ, FIXTURE_VERSION=version), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_controller_checks_before_image_parsing_and_boot(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        check = source.index('bash /work/check-qemu-controller.sh')
        self.assertLess(check, source.index('qemu-img info base.qcow2'))
        self.assertNotIn('controller_image=debian:bookworm', source)
        self.assertEqual(source.count('controller_image_x86_64=debian:trixie@sha256:'), 1)
        self.assertEqual(source.count('controller_image_aarch64=debian:trixie@sha256:'), 1)


if __name__ == '__main__':
    unittest.main()

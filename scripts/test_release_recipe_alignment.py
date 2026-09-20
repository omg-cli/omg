"""Execute the staging build command and compare its CPU baseline to release."""
import os
from pathlib import Path
import subprocess
import textwrap
import unittest

from test_ci_gates import job_block
from test_native_build_artifact import BUILD

ROOT = Path(__file__).resolve().parents[1]


class ReleaseRecipeAlignment(unittest.TestCase):
    def test_ci_release_cpu_baseline_matches_arch_and_generic_distros(self):
        ci = job_block((ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8'), 'linux-matrix')
        block = ci.split('      - name: Build release\n', 1)[1].split('\n      - name:', 1)[0]
        # Container jobs default to sh; this recipe uses Bash conditional syntax.
        self.assertIn('        shell: bash\n', block)
        raw = block.split('        run: ', 1)[1]
        command = textwrap.dedent(raw[2:]) if raw.startswith('|\n') else raw.strip()
        for distro, cpu in (('arch', '-C target-cpu=x86-64-v2'), ('debian', ''), ('fedora', ''), ('debian-trixie', '')):
            features = 'debian,pgp,license' if distro == 'debian-trixie' else distro + ',pgp,license'
            script = "cargo() { printf 'cargo %s\\n' \"$*\"; }\npython3() { printf 'python3 %s\\n' \"$*\"; }\n" + command
            bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
            result = subprocess.run([bash, '-eu', '-c', script], text=True, capture_output=True, check=True,
                                    env=dict(os.environ, DISTRO=distro, RUSTFLAGS='', BUILD_FEATURES=features,
                                             BUILD_IMAGE='fixture-image', RUNNER_TEMP='/fixture-temp'), timeout=10)
            with self.subTest(distro=distro):
                if distro == 'debian-trixie':
                    self.assertEqual(result.stdout.strip(),
                                     'cargo build --release --no-default-features --features ' + features + ' --locked')
                else:
                    self.assertEqual(result.stdout.strip(), 'python3 scripts/native-build-artifact.py build --distro '
                                     + distro + ' --image fixture-image --features ' + features
                                     + ' --destination /fixture-temp/native-release')
                    _, environment = BUILD.build_command(distro, features, {})
                    self.assertEqual(environment['RUSTFLAGS'], cpu)

    def test_staged_cpu_baseline_matches_each_published_distro(self):
        lane = (ROOT / '.github/workflows/qemu-lane.yml').read_text(encoding='utf-8')
        block = lane.split('      - name: Build\n', 1)[1]
        command = textwrap.dedent(block.split('        run: |\n', 1)[1].split('\n      - name:', 1)[0])
        for distro, features, cpu in (
            ('arch', 'arch,pgp,license', '-C target-cpu=x86-64-v2'),
            ('debian', 'debian,pgp,license', ''),
            ('fedora', 'fedora,pgp,license', ''),
        ):
            with self.subTest(distro=distro):
                release = job_block((ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8'), 'build-' + distro)
                if cpu:
                    self.assertIn('export RUSTFLAGS="' + cpu + '"', release)
                else:
                    self.assertNotIn('RUSTFLAGS', release)
                script = command.replace('${{ inputs.features }}', features)
                script = "cargo() { printf '%s\\n' \"${RUSTFLAGS-}\" \"$*\"; }\n" + script
                bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
                result = subprocess.run([bash, '-eu', '-c', script], text=True,
                                        capture_output=True, check=True,
                                        env=dict(os.environ, DISTRO=distro, RUSTFLAGS=''), timeout=10)
                lines = result.stdout.splitlines()
                self.assertEqual(lines[0], cpu)
                self.assertEqual(lines[1], 'build --timings --release --no-default-features --features '
                                 + features + ' --locked')


if __name__ == '__main__':
    unittest.main()

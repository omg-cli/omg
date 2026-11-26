"""Execute the staging build command and compare its CPU baseline to release."""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

from test_ci_gates import job_block
from test_native_build_artifact import BUILD

ROOT = Path(__file__).resolve().parents[1]


class ReleaseRecipeAlignment(unittest.TestCase):
    def test_native_tests_run_before_release_builds(self):
        ci = job_block((ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8'), 'linux-matrix')
        for preparation in ('Install nextest', 'Verify nextest', 'Prepare genuine Node activation fixture'):
            self.assertLess(ci.index('      - name: ' + preparation + '\n'),
                            ci.index('      - name: Run unit tests\n'))
        for build in ('Build release', 'Build Ubuntu 26.04 validation binary'):
            self.assertLess(ci.index('      - name: Run unit tests\n'),
                            ci.index('      - name: ' + build + '\n'))

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
                self.assertEqual(result.stdout.strip(), 'python3 scripts/native-build-artifact.py build --distro '
                                 + distro + ' --image fixture-image --features ' + features
                                 + ' --destination /fixture-temp/native-release')
                _, environment = BUILD.build_command(distro, features, {})
                self.assertEqual(environment['RUSTFLAGS'], cpu)

    def test_staged_unit_failure_evidence_uses_the_uploaded_workspace_path(self):
        for filename in ('qemu-lane.yml', 'qemu-matrix.yml'):
            with self.subTest(workflow=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                workspace = root / 'workspace'
                workspace.mkdir()
                container_temp = root / 'container-temp'
                container_temp.mkdir()
                host_temp = root / 'host-temp'
                host_temp.mkdir()
                workflow = (ROOT / '.github/workflows' / filename).read_text(encoding='utf-8')
                unit_step = workflow.split('- name: Run library and binary unit tests (including omgd)\n', 1)[1]
                command = unit_step.split('run: ', 1)[1].splitlines()[0]
                command = command.replace('${{ inputs.features }}', 'fedora,pgp,license')
                command = command.replace('${{ matrix.features }}', 'fedora,pgp,license')
                artifact = unit_step.split('- name: Preserve compiler timings\n', 1)[1]
                paths = artifact.split('path: |\n', 1)[1].split('retention-days:', 1)[0].splitlines()
                bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
                script = ("""python3() {
                    while [[ "$1" != --output ]]; do shift; done
                    shift
                    mkdir -p "$1"
                    printf 'failed unit test\\n' > "$1/run.stderr.log"
                    return 1
                }
                """ + command)
                result = subprocess.run(
                    [bash, '-eu', '-c', script], cwd=workspace,
                    env=dict(os.environ, RUNNER_TEMP=container_temp.as_posix()),
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, '')
                report = 'run.stderr.log'
                emitted = list(root.rglob(report))
                self.assertEqual(len(emitted), 1)
                uploaded = [workspace / path.strip().replace('${{ runner.temp }}', host_temp.as_posix()) / report
                            for path in paths if path.strip()]
                self.assertIn(emitted[0], uploaded)
                self.assertEqual(emitted[0].read_text(encoding='utf-8'), 'failed unit test\n')

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

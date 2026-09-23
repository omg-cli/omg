"""Contracts for explicit local TCG execution in the QEMU harness."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
BASH = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "bash"


class QemuAccelerationTests(unittest.TestCase):
    def test_help_exposes_explicit_tcg_opt_in(self):
        result = subprocess.run(
            [BASH, str(ROOT / "scripts/benchmark-qemu.sh"), "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--allow-tcg", result.stdout)
        self.assertIn("correctness audit", result.stdout)
        self.assertIn("not valid benchmark evidence", result.stdout)

    def test_tcg_changes_the_real_launch_and_keeps_kvm_as_default(self):
        source = (ROOT / "scripts/benchmark-qemu.sh").read_text(encoding="utf-8")
        self.assertIn('[[ "$allow_tcg" == false ]] || args+=(--allow-tcg)', source)
        self.assertIn('qemu_accel=tcg', source)
        self.assertIn('qemu_cpu=cortex-a72', source)
        self.assertIn('x86_64) qemu_cpu=max', source)
        self.assertIn('qemu_accel=kvm', source)
        self.assertIn('qemu_cpu=host', source)
        self.assertIn('-machine "$6" -accel "$accel" -cpu "$8"', source)
        self.assertIn('accel=tcg,thread=multi', source)
        self.assertIn('-device virtio-net-pci,netdev=n,romfile=', source)
        self.assertNotIn('-machine "$6,accel=kvm" -cpu host', source)

    def test_cross_arch_tcg_uses_a_native_controller(self):
        source = (ROOT / "scripts/benchmark-qemu.sh").read_text(encoding="utf-8")
        self.assertIn('if [[ "$qemu_accel" == tcg && "$host_arch" != "$arch" ]]', source)
        self.assertIn('controller_image=$controller_image_tcg', source)

    def test_tcg_deadlines_are_explicit_and_leave_kvm_defaults_unchanged(self):
        runner = (ROOT / "scripts/benchmark-qemu.sh").read_text(encoding="utf-8")
        daemon = (ROOT / "scripts/qemu-daemon-check.sh").read_text(encoding="utf-8")
        self.assertIn("boot_timeout=700", runner)
        self.assertIn("guest_timeout=600", runner)
        self.assertIn("boot_timeout=1800", runner)
        self.assertIn("guest_timeout=2400", runner)
        self.assertIn("kvm) daemon_timeout=240 ;; tcg) daemon_timeout=900", runner)
        self.assertIn('OMG_QEMU_ACCEL="$accel" timeout', runner)
        self.assertIn("kvm) readiness_attempts=30", daemon)
        self.assertIn("tcg) readiness_attempts=300", daemon)

    @unittest.skipUnless(os.name == "posix" and os.uname().machine == "x86_64",
                         "cross-architecture TCG preflight needs an x86_64 Linux host")
    def test_tcg_refuses_benchmark_evidence_before_starting_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [BASH, str(ROOT / "scripts/benchmark-qemu.sh"),
                 "--distro", "ubuntu", "--arch", "aarch64", "--allow-tcg",
                 "--benchmark", "--evidence-dir", directory],
                capture_output=True, text=True, timeout=10, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TCG is correctness-only", result.stderr)
            self.assertNotIn("docker:", result.stderr)


if __name__ == "__main__":
    unittest.main()

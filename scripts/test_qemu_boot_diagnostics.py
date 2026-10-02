"""Run the observer against native proc/socket state; no guest success is claimed."""
from pathlib import Path
import os
import signal
import socket
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("qemu-boot-diagnostics.sh")


class BootDiagnostics(unittest.TestCase):
    def observe(self, directory):
        result = subprocess.run(["timeout", "--kill-after=2s", "3s", "bash", str(SCRIPT), str(directory)],
                                capture_output=True, text=True, timeout=6, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_missing_process_and_startup_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.observe(directory)
        self.assertIn("qemu_pid=unavailable", output)
        self.assertIn("qemu_process_status=unavailable", output)
        self.assertIn("qemu_startup=unavailable", output)
        self.assertIn("controller_memory_events:", output)

    def test_live_child_status_and_dead_child_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            pidfile = Path(directory) / "qemu.pid"
            child = subprocess.Popen(["sleep", "30"])
            try:
                pidfile.write_text(f"{child.pid}\n")
                live = self.observe(directory)
                self.assertIn(f"qemu_pid={child.pid}", live)
                self.assertRegex(live, rf"(?m)^Pid:\s+{child.pid}$")
                self.assertRegex(live, rf"(?m)^PPid:\s+{os.getpid()}$")
                # Kernel proc documentation defines D as a live uninterruptible wait:
                # https://docs.kernel.org/filesystems/proc.html#process-specific-subdirectories
                self.assertRegex(live, r"(?m)^State:\s+[RSD] \(")
                self.assertNotIn("qemu_process_status=unavailable", live)
                self.assertIsNone(child.poll(), "the observer must not signal the child")
            finally:
                child.terminate()
                child.wait(timeout=5)
            dead = self.observe(directory)
            self.assertIn("qemu_process_status=unavailable", dead)

    def test_stopped_child_state_is_preserved_without_resuming_it(self):
        with tempfile.TemporaryDirectory() as directory:
            child = subprocess.Popen(['sleep', '30'])
            try:
                os.kill(child.pid, signal.SIGSTOP)
                stopped_pid, status = os.waitpid(child.pid, os.WUNTRACED)
                self.assertEqual(stopped_pid, child.pid)
                self.assertTrue(os.WIFSTOPPED(status))
                (Path(directory) / 'qemu.pid').write_text(f'{child.pid}\n')
                output = self.observe(directory)
                self.assertRegex(output, rf'(?m)^Pid:\s+{child.pid}$')
                self.assertRegex(output, r'(?m)^State:\s+T \(stopped\)$')
                native_status = Path(f'/proc/{child.pid}/status').read_text()
                self.assertRegex(native_status, r'(?m)^State:\s+T \(stopped\)$')
                self.assertIsNone(child.poll())
            finally:
                os.kill(child.pid, signal.SIGCONT)
                child.terminate()
                child.wait(timeout=5)

    def test_real_listener_port_is_observed(self):
        with socket.socket() as listener, tempfile.TemporaryDirectory() as directory:
            listener.bind(("127.0.0.1", 2222))
            listener.listen()
            output = self.observe(directory)
            self.assertRegex(output, r"listener=0100007F:08AE inode=\d+")

    def test_startup_tail_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "qemu-startup.log").write_text("x" * 20000 + "failure-reason\n")
            output = self.observe(directory)
            tail = output.split("qemu_startup_tail:\n", 1)[1]
            self.assertEqual(len(tail.encode()), 8192)
            self.assertTrue(tail.endswith("failure-reason\n"))

    def test_pid_and_startup_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private").write_text("private-content\n")
            (root / "qemu.pid").symlink_to(root / "private")
            (root / "qemu-startup.log").symlink_to(root / "private")
            output = self.observe(directory)
            self.assertNotIn("private-content", output)
            self.assertIn("qemu_pid=unavailable", output)
            self.assertIn("qemu_startup=unavailable", output)

    def test_clone_observation_preserves_the_failed_boot_exit(self):
        transaction = SCRIPT.with_name("qemu-transactions.sh").read_text()
        function = "start_clone() {" + transaction.split("start_clone() {", 1)[1].split("\nfreeze_base() {", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boot = root / "failed-boot.sh"
            boot.write_text("printf launch-failed > qemu-startup.log\nexit 7\n")
            function = function.replace("/work/boot.sh", str(boot))
            function = function.replace("bash /work/qemu-boot-diagnostics.sh", f'bash "{SCRIPT}" "{root}"')
            command = 'set -euo pipefail\nclone_boot_timeout=3\nboot_args=(bios ssh)\n' + function
            command += '\nstart_clone disk vars serial.log clone.log\n'
            result = subprocess.run(["bash", "-c", command], cwd=root, capture_output=True, text=True, timeout=6, check=False)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertIn("launch-failed", (root / "clone.diagnostics.log").read_text())
            self.assertEqual((root / "clone.qemu-startup.log").read_text(), "launch-failed")


if __name__ == "__main__":
    unittest.main()

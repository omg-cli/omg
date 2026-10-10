"""Execute the production process-status gate against unsafe QEMU identities."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'


class QemuProcessIsolationTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'production nohup launch requires POSIX executable paths')
    def test_launch_disables_legacy_vapic_only_for_x86_and_preserves_guest_devices(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        launch = 'firmware=()' + source.split('firmware=()', 1)[1].split('\n# Launch from the controller', 1)[0]
        for machine in ('q35', 'q35,sata=off', 'virt'):
            for firmware in ('bios', 'uefi'):
                with self.subTest(machine=machine, firmware=firmware), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    recorder = root / 'record-qemu'
                    recorder.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARG_FILE"\n')
                    recorder.chmod(0o755)
                    (root / 'vars.fd').write_bytes(b'firmware-fixture')
                    script = ('set -euo pipefail\ninitial=false\nvm_vars=vars.fd\n'
                              'vm_disk=disk.qcow2\nvm_serial=serial.log\n' + launch + '\nwait\n')
                    result = subprocess.run(
                        [BASH, '-c', script, 'launch', firmware, 'sshd', 'code.fd', 'vars.fd',
                         str(recorder), machine, 'kvm', 'host'], cwd=root,
                        env={**os.environ, 'ARG_FILE': str(root / 'arguments')},
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    arguments = (root / 'arguments').read_text().splitlines()
                    self.assertEqual(arguments.count('apic-common.vapic=false'), 0 if machine == 'virt' else 1)
                    if machine != 'virt':
                        self.assertEqual(arguments[arguments.index('-global') + 1], 'apic-common.vapic=false')
                    else:
                        self.assertNotIn('-global', arguments)
                    for retained in ('user=65534:65534', 'on,obsolete=deny,spawn=deny,resourcecontrol=deny',
                                     'file:serial.log', 'file=disk.qcow2,if=virtio,format=qcow2',
                                     'file=seed.img,if=virtio,format=raw', 'virtio-net-pci,netdev=n,romfile='):
                        self.assertIn(retained, arguments)
                    self.assertEqual('if=pflash,format=raw,file=vars.fd' in arguments, firmware == 'uefi')

    def test_machine_selection_disables_unused_x86_sata_without_changing_arm(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        function = 'pins_for() {' + source.split('pins_for() {', 1)[1].split('\n# Lifecycle case ids', 1)[0]
        for distro, arch in [('arch', 'x86_64'), ('debian', 'x86_64'),
                             ('debian-trixie', 'x86_64'), ('ubuntu', 'x86_64'),
                             ('fedora', 'x86_64'), ('debian', 'aarch64'),
                             ('ubuntu', 'aarch64'), ('fedora', 'aarch64')]:
            with self.subTest(distro=distro, arch=arch):
                command = ('set -euo pipefail\ncontroller_image_x86_64=x86\n'
                           'controller_image_aarch64=arm\n' + function
                           + '\npins_for "$1" "$2"\nprintf "%s\\n" "$qemu_machine"\n')
                result = subprocess.run([BASH, '-c', command, 'machine-selection', distro, arch],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'q35,sata=off' if arch == 'x86_64' else 'virt')

    def test_launch_uses_supported_privilege_drop_without_root_fallback(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        self.assertIn('-run-with user=65534:65534', source)
        self.assertNotIn('-runas ', source)
        self.assertIn('-sandbox on,obsolete=deny,spawn=deny,resourcecontrol=deny', source)

    def test_process_gate_rejects_root_capabilities_and_missing_restrictions(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        script = source.split('qemu_pid=$(<qemu.pid)', 1)[1].split('opts=(', 1)[0]
        script = script[script.index("awk '"):script.index("printf 'QEMU isolation verified")]
        script = script.replace('"/proc/$qemu_pid/status"', '"$STATUS_FILE"')
        safe = ('Uid:\t65534\t65534\t65534\t65534\n'
                'Gid:\t65534\t65534\t65534\t65534\n'
                'CapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n')
        cases = [safe, '', safe.replace('65534', '0', 1),
                 safe.replace('CapEff:\t0000000000000000', 'CapEff:\t0000000000000001'),
                 safe.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'),
                 safe.replace('Seccomp:\t2', 'Seccomp:\t0'),
                 safe.replace('Gid:\t65534', 'Gid:\t0')]
        for index, status in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'status'
                path.write_text(status)
                result = subprocess.run([BASH, '-c', script],
                                        env=dict(os.environ, STATUS_FILE=str(path)),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, index == 0, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'SSH timeout regression needs POSIX timeout and process signals')
    def test_guest_readiness_probe_cannot_hang_on_an_ssh_banner(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        self.assertIn('probe_timeout=$(( remaining - SSH_KILL_GRACE ))', source)
        self.assertIn('after=$(timeout --kill-after="${SSH_KILL_GRACE}s" "${probe_timeout}s" ssh', source)
        start = source.index('wait_ssh() {')
        end = source.index('\nwait_ssh\n', start)
        function = source[start:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ssh = root / 'ssh'
            ssh.write_text('#!/usr/bin/env bash\nsleep 5\n', encoding='utf-8')
            ssh.chmod(0o755)
            (root / 'qemu.pid').write_text(str(os.getpid()))
            (root / 'serial.log').write_text('Booting Fedora Linux\n', encoding='utf-8')
            result = subprocess.run(
                [BASH, '-c', 'opts=(); vm_serial=serial.log; SSH_WAIT_BUDGET=3; '
                 'SSH_ATTEMPT_TIMEOUT=1; SSH_KILL_GRACE=1; SSH_RETRY_DELAY=1; '
                 + function + '\nwait_ssh'],
                cwd=root, env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH']),
                capture_output=True, text=True, timeout=4)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('SSH readiness timed out after 3 seconds', result.stderr)
            self.assertIn('kernel_banner_seen=no', result.stderr)
            self.assertIn('Booting Fedora Linux', result.stderr)


if __name__ == '__main__':
    unittest.main()

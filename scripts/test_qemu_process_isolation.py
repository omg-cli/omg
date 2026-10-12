"""Execute the production process-status gate against unsafe QEMU identities."""
import os
import json
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

    @unittest.skipIf(os.name == 'nt', 'launch fixture requires POSIX executable scripts')
    def test_headless_launch_preserves_default_vga_serial_and_network(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        launch = 'nohup "$5"' + source.split('nohup "$5"', 1)[1].split('# Launch from the controller', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'qemu-fixture'
            executable.write_text('#!/usr/bin/env python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n')
            executable.chmod(0o755)
            for machine in ('q35', 'virt'):
                with self.subTest(machine=machine):
                    command = ('set -- bios vars code firmware "$1" "$2" tcg max; '
                               'accel=tcg; firmware=(); vm_serial=serial.log; vm_disk=disk.qcow2; '
                               + launch + '\nwait $!\n')
                    result = subprocess.run([BASH, '-c', command, '_', str(executable), machine],
                                            cwd=root, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    arguments = json.loads((root / 'qemu-startup.log').read_text())
                    self.assertNotIn('-vga', arguments)
                    self.assertEqual(arguments[arguments.index('-display') + 1], 'none')
                    self.assertEqual(arguments[arguments.index('-serial') + 1], 'file:serial.log')
                    self.assertIn('virtio-net-pci,netdev=n,romfile=', arguments)
                    self.assertIn('user=65534:65534', arguments)
                    self.assertIn('on,obsolete=deny,spawn=deny,resourcecontrol=deny', arguments)

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
            self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=124(?:\s|$)')
            self.assertIn('kernel_banner_seen=no', result.stderr)
            self.assertIn('Booting Fedora Linux', result.stderr)



_METADATA_FAULT_SHIM = r'''
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys

result = subprocess.run([sys.executable, *sys.argv[1:]], input=sys.stdin.buffer.read())
if sys.argv[2] == 'capture' and result.returncode == 0:
    target = os.environ.get('OMG_SSH_LAST_PROBE_RECORD', 'ssh-last-probe.json')
    counter = Path('metadata-capture-count')
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    fault = os.environ['OMG_METADATA_FAULT']
    if fault.startswith('boolean') or count == 1:
        if not target:
            raise RuntimeError('required metadata fault injection has no record target')
        path = Path(target)
        record = json.loads(path.read_text())
        if record['exit'] != 0 or record['helper_exit'] != 0:
            raise RuntimeError('genuine successful capture prerequisite')
        if os.environ['OMG_METADATA_FAULT'] == 'boolean':
            record.update(attempt=True, exit=False, helper_exit=False)
        elif fault.startswith('boolean-'):
            field = {'boolean-attempt': 'attempt', 'boolean-exit': 'exit',
                     'boolean-helper-exit': 'helper_exit'}[fault]
            record[field] = True if field == 'attempt' else False
        else:
            first = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
            record['started_utc'] = first.isoformat()
            record['ended_utc'] = (first + datetime.timedelta(milliseconds=record['elapsed_ms'])).isoformat()
        path.write_text(json.dumps(record))
sys.exit(result.returncode)
'''

class QemuReadinessDiagnosticTests(unittest.TestCase):
    def run_readiness(self, program, before='', budget=3, attempt_timeout=1, setup='', repeat=1):
        import signal
        import time
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        start = source.index('wait_ssh() {')
        function = source[start:source.index('\nwait_ssh\n', start)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'ssh'
            executable.write_text('#!/usr/bin/env bash\n' + program + '\n', encoding='utf-8')
            executable.chmod(0o755)
            (root / 'qemu.pid').write_text(str(os.getpid()))
            (root / 'serial.log').write_text('fixture-serial\n', encoding='utf-8')
            (root / 'qemu-startup.log').write_bytes(b'')
            command = ('set -euo pipefail\nopts=(); vm_serial=serial.log; '
                       f'SSH_WAIT_BUDGET={budget}; SSH_ATTEMPT_TIMEOUT={attempt_timeout}; '
                       'SSH_KILL_GRACE=1; SSH_RETRY_DELAY=1;\n' + setup + '\n' + function
                       + '\nwait_ssh "$1"\n' * repeat)
            started = time.monotonic()
            process = subprocess.Popen([BASH, '-c', command, 'readiness', before], cwd=root,
                                       env=dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                                                LC_ALL='C'), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=budget + 2)
                elapsed = time.monotonic() - started
                descendants = []
                if (root / 'descendant.pid').is_file():
                    pid = int((root / 'descendant.pid').read_text())
                    stat = Path(f'/proc/{pid}/stat')
                    if stat.is_file():
                        state = stat.read_text().rsplit(') ', 1)[1].split()[0]
                        if state != 'Z':
                            descendants.append(pid)
                return subprocess.CompletedProcess(process.args, process.returncode,
                                                   stdout.decode(errors='replace'), stderr.decode(errors='replace')), elapsed, descendants
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

    def test_readiness_refusal_retains_last_status_and_literal_stderr(self):
        result, elapsed, children = self.run_readiness('printf "fixture-refused\\n" >&2; exit 255')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture-refused', result.stderr)
        self.assertIn('SSH last probe: mode=initial', result.stderr)
        self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=255(?:\s|$)')
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_readiness_timeout_retains124_and_literal_stderr(self):
        result, elapsed, children = self.run_readiness('printf "fixture-banner-stall\\n" >&2; sleep 30')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture-banner-stall', result.stderr)
        self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=124(?:\s|$)')
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_readiness_initial_success_retains_zero_status(self):
        result, elapsed, children = self.run_readiness('printf "fixture-ready\\n" >&2; exit 0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SSH last probe: mode=initial attempt=1 exit=0', result.stderr)
        self.assertIn('boot_id=not-applicable', result.stderr)
        self.assertIn('fixture-ready', result.stderr)
        self.assertLess(elapsed, 2)
        self.assertEqual(children, [])

    def test_readiness_reboot_retries_same_id_until_changed(self):
        program = ('count=0; [[ ! -f count ]] || read -r count < count; '
                   'count=$((count + 1)); printf "%s\\n" "$count" > count; '
                   'if ((count == 1)); then printf "old-boot-id\\n"; '
                   'else printf "new-boot-id\\n"; fi')
        result, elapsed, children = self.run_readiness(program, before='old-boot-id')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('reboot verified: old-boot-id -> new-boot-id', result.stdout)
        self.assertIn('SSH last probe: mode=reboot attempt=2 exit=0', result.stderr)
        self.assertIn('boot_id=changed', result.stderr)
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertLess(elapsed, 3)
        self.assertEqual(children, [])

    def test_readiness_stderr_tail_is_bounded_and_truncation_is_visible(self):
        result, elapsed, children = self.run_readiness(
            'printf "%06000d" 0 >&2; printf "fixture-tail\\n" >&2; exit 255')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture-tail', result.stderr)
        self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=255(?:\s|$)')
        self.assertIn('stderr_truncated=yes', result.stderr)
        self.assertIn('stderr_bytes=4096', result.stderr)
        self.assertLessEqual(len(result.stderr.encode()), 8192)
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_readiness_inherited_stderr_pipe_cannot_leak_or_extend_wait(self):
        result, elapsed, children = self.run_readiness(
            'sleep 30 >&2 & printf "%s\\n" "$!" > descendant.pid; '
            'printf "fixture-descendant\\n" >&2; exit 255')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture-descendant', result.stderr)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [], 'diagnostic drain left a live descendant')


    def test_readiness_capture_failure_preserves_original_exit(self):
        for status, outcome in [(255, 1), (0, 0)]:
            with self.subTest(status=status):
                program = ('record=${OMG_SSH_LAST_PROBE_RECORD:-}; '
                           '[[ -n "$record" ]] || exit 77; '
                           'if [[ -f "$record" ]]; then '
                           'rm -- "$record" && mkdir -- "$record" || exit 77; '
                           'else [[ -d "$record" ]] || exit 77; fi; '
                           f'printf "capture-storage-denied-complete-{status}\\n"; exit {status}')
                result, _, children = self.run_readiness(program)
                self.assertEqual(result.returncode, outcome, result.stderr)
                completions = result.stdout.splitlines().count(f'capture-storage-denied-complete-{status}')
                self.assertGreaterEqual(completions, 1)
                if status == 0:
                    self.assertEqual(completions, 1)
                self.assertRegex(result.stderr, rf'(?:^|\s)helper_exit={status}(?:\s|$)')
                self.assertIn('capture_complete=no', result.stderr)
                self.assertIn('capture_state=unavailable', result.stderr)
                self.assertIn('stderr_bytes=0', result.stderr)
                self.assertEqual(children, [])


    def test_readiness_stderr_exact_boundary_and_binary_bytes(self):
        for size, truncated in [(4096, 'no'), (4097, 'yes')]:
            with self.subTest(size=size):
                program = f"python3 -c 'import os;os.write(2,b\"\\x00\"*{size})'; exit 255"
                result, _, children = self.run_readiness(program)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('stderr_bytes=4096', result.stderr)
                self.assertIn(f'stderr_truncated={truncated}', result.stderr)
                self.assertEqual(result.stderr.count('\x00'), 4096)
                self.assertEqual(children, [])



    def test_readiness_emit_failure_does_not_change_probe_outcome(self):
        setup = ('python3() { if [[ "$2" == emit ]]; then return 77; '
                 'else command python3 "$@"; fi; }')
        for status, outcome in [(0, 0), (255, 1)]:
            with self.subTest(status=status):
                result, _, children = self.run_readiness(f'exit {status}', setup=setup)
                self.assertEqual(result.returncode, outcome, result.stderr)
                self.assertEqual(children, [])



    def test_readiness_invalid_record_cannot_change_success(self):
        setup = ('python3() { command python3 "$@"; local rc=$?; '
                 'if [[ "$2" == capture ]]; then '
                 "command python3 -c 'import json,os; p=os.environ.get(\"OMG_SSH_LAST_PROBE_RECORD\",\"\"); "
                 'assert p, "required invalid-record injection has no target"; '
                 'r=json.load(open(p)); '
                 'assert type(r["exit"]) is int and r["exit"]==0 and r["helper_exit"]==0 '
                 'and r["status_state"]=="observed", "genuine successful capture prerequisite"; '
                 'r["observed_bytes"]="invalid"; '
                 "json.dump(r,open(p,\"w\"))' || return 77; fi; return \"$rc\"; }")
        result, _, children = self.run_readiness(
            'printf "invalid-record-producer-complete\\n"; exit 0', setup=setup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines().count('invalid-record-producer-complete'), 1)
        self.assertRegex(result.stderr, r'(?:^|\s)helper_exit=0(?:\s|$)')
        self.assertIn('capture_state=invalid', result.stderr)
        self.assertIn('capture_complete=no', result.stderr)
        self.assertIn('stderr_bytes=0', result.stderr)
        self.assertEqual(children, [])


    def test_readiness_qemu_exit_emits_previous_probe_once(self):
        result, _, children = self.run_readiness(
            'printf "2147483647\\n" > qemu.pid; printf "fixture-before-qemu-exit\\n" >&2; exit 255')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('QEMU exited before SSH became ready', result.stderr)
        self.assertIn('fixture-before-qemu-exit', result.stderr)
        self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=255(?:\s|$)')
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertEqual(children, [])

    def test_readiness_kill_grace_retains_actual137(self):
        result, elapsed, children = self.run_readiness(
            'trap "" TERM; printf "fixture-ignores-term\\n" >&2; while :; do sleep 1; done',
            budget=4)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture-ignores-term', result.stderr)
        self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=137(?:\s|$)')
        self.assertLess(elapsed, 6)
        self.assertEqual(children, [])



    def test_readiness_near_deadline_preserves_last_actual_probe(self):
        result, elapsed, children = self.run_readiness(
            'printf "fixture-near-deadline\\n" >&2; sleep 30', budget=2)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('fixture-near-deadline', result.stderr)
        self.assertRegex(result.stderr, r'(?m)^SSH last probe:[^\n]*\sexit=124(?:\s|$)')
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertLess(elapsed, 4)
        self.assertEqual(children, [])


    def _metadata_fault_setup(self, kind):
        return ('cat >metadata-fault.py <<\'METADATA_FAULT\'\n'
                + _METADATA_FAULT_SHIM + '\nMETADATA_FAULT\n'
                + f'export OMG_METADATA_FAULT={kind};\n'
                + 'python3() { command python3 metadata-fault.py "$@"; }')

    def test_boolean_record_aliases_are_rejected_without_changing_success(self):
        result, elapsed, children = self.run_readiness(
            'printf "fixture-boolean-current\\n" >&2; printf "boolean-producer-complete\\n"; exit 0',
            setup=self._metadata_fault_setup('boolean'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines().count('boolean-producer-complete'), 1)
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertIn('helper_exit=0', result.stderr)
        self.assertIn('capture_state=invalid', result.stderr)
        self.assertIn('capture_complete=no', result.stderr)
        self.assertIn('stderr_bytes=0', result.stderr)
        self.assertNotIn('fixture-boolean-current', result.stderr)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_matching_stale_record_is_not_attributed_to_a_new_wait(self):
        program = ('count=0; [[ ! -f ssh-count ]] || read -r count < ssh-count; '
                   'count=$((count + 1)); printf "%s\\n" "$count" > ssh-count; '
                   'if ((count == 1)); then printf "fixture-prior-wait\\n" >&2; '
                   'printf "stale-first-producer-complete\\n"; exit 0; '
                   'else chmod 0400 "${OMG_SSH_LAST_PROBE_RECORD:-ssh-last-probe.json}"; '
                   'printf "fixture-current-wait\\n" >&2; '
                   'printf "stale-second-producer-complete\\n"; exit 0; fi')
        result, elapsed, children = self.run_readiness(
            program, setup=self._metadata_fault_setup('stale'), repeat=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines().count('stale-first-producer-complete'), 1)
        self.assertEqual(result.stdout.splitlines().count('stale-second-producer-complete'), 1)
        segments = result.stderr.split('SSH last probe:')
        self.assertEqual(len(segments), 3)
        self.assertIn('fixture-prior-wait', segments[1])
        self.assertIn('capture_state=complete', segments[1])
        self.assertRegex(segments[1], r'(?:^|\s)exit=0(?:\s|$)')
        self.assertIn('helper_exit=0', segments[1])
        self.assertIn('2000-01-01T00:00:00+00:00', segments[1])
        self.assertIn('helper_exit=0', segments[2])
        self.assertNotIn('fixture-prior-wait', segments[2])
        self.assertNotIn('2000-01-01T', segments[2])
        if 'capture_state=complete' in segments[2] or 'capture_state=partial' in segments[2]:
            self.assertIn('fixture-current-wait', segments[2])
            self.assertRegex(segments[2], r'(?:^|\s)exit=0(?:\s|$)')
        else:
            self.assertTrue('capture_state=invalid' in segments[2]
                            or 'capture_state=unavailable' in segments[2], segments[2])
            self.assertNotIn('fixture-current-wait', segments[2])
            self.assertIn('capture_complete=no', segments[2])
            self.assertIn('stderr_bytes=0', segments[2])
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])



    def _assert_single_boolean_alias_rejected(self, field):
        marker = f'boolean-{field}-producer-complete'
        result, elapsed, children = self.run_readiness(
            f'printf "fixture-single-boolean-current\n" >&2; printf "{marker}\n"; exit 0',
            setup=self._metadata_fault_setup(f'boolean-{field}'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines().count(marker), 1)
        self.assertEqual(result.stderr.count('SSH last probe:'), 1)
        self.assertRegex(result.stderr, r'(?:^|\s)helper_exit=0(?:\s|$)')
        self.assertIn('capture_state=invalid', result.stderr)
        self.assertIn('capture_complete=no', result.stderr)
        self.assertIn('stderr_bytes=0', result.stderr)
        self.assertNotIn('fixture-single-boolean-current', result.stderr)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_boolean_attempt_alias_is_rejected_independently(self):
        self._assert_single_boolean_alias_rejected('attempt')

    def test_boolean_actual_exit_alias_is_rejected_independently(self):
        self._assert_single_boolean_alias_rejected('exit')

    def test_boolean_helper_exit_alias_is_rejected_independently(self):
        self._assert_single_boolean_alias_rejected('helper-exit')

    def _assert_allocator_refusal_preserves_probe_outcome(self, status):
        allocator = r"""cat >mktemp <<'ALLOCATOR'
#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f allocator-count ]] || read -r count < allocator-count
count=$((count + 1))
printf '%s\n' "$count" > allocator-count
if ((count == 1)); then exec /usr/bin/mktemp "$@"; fi
exit 73
ALLOCATOR
chmod 0755 mktemp
"""
        program = ('count=0; [[ ! -f ssh-count ]] || read -r count < ssh-count; '
                   'count=$((count + 1)); printf "%s\\n" "$count" > ssh-count; '
                   'if ((count == 1)); then printf "fixture-prior-allocation\\n" >&2; '
                   'printf "allocator-first-producer-complete\\n"; exit 0; fi; '
                   'allocation_count=0; [[ ! -f allocator-count ]] || read -r allocation_count < allocator-count; '
                   'if ((allocation_count == 2)); then printf "allocator-refusal-observed\\n"; fi; '
                   'printf "fixture-current-after-refusal\\n" >&2; '
                   f'printf "allocator-second-producer-complete-{status}\\n"; exit {status}')
        result, elapsed, children = self.run_readiness(
            program, setup=self._metadata_fault_setup('allocator') + '\n' + allocator, repeat=2)
        self.assertEqual(result.returncode, 0 if status == 0 else 1, result.stderr)
        self.assertEqual(result.stdout.splitlines().count('allocator-first-producer-complete'), 1)
        completion_count = result.stdout.splitlines().count(f'allocator-second-producer-complete-{status}')
        self.assertGreaterEqual(completion_count, 1)
        if status == 0:
            self.assertEqual(completion_count, 1)
        segments = result.stderr.split('SSH last probe:')
        self.assertEqual(len(segments), 3)
        self.assertIn('capture_state=complete', segments[1])
        self.assertRegex(segments[1], r'(?:^|\s)exit=0(?:\s|$)')
        self.assertRegex(segments[1], r'(?:^|\s)helper_exit=0(?:\s|$)')
        self.assertIn('fixture-prior-allocation', segments[1])
        self.assertIn('2000-01-01T00:00:00+00:00', segments[1])
        self.assertEqual(result.stdout.splitlines().count('allocator-refusal-observed'), completion_count)
        self.assertRegex(segments[2], rf'(?:^|\s)helper_exit={status}(?:\s|$)')
        self.assertIn('capture_state=unavailable', segments[2])
        self.assertIn('capture_complete=no', segments[2])
        self.assertIn('stderr_bytes=0', segments[2])
        self.assertNotIn('fixture-prior-allocation', segments[2])
        self.assertNotIn('fixture-current-after-refusal', segments[2])
        self.assertNotIn('2000-01-01T', segments[2])
        self.assertLess(elapsed, 7)
        self.assertEqual(children, [])

    def test_allocator_refusal_preserves_genuine_success(self):
        self._assert_allocator_refusal_preserves_probe_outcome(0)

    def test_allocator_refusal_preserves_genuine_refusal(self):
        self._assert_allocator_refusal_preserves_probe_outcome(255)



    def _record_boundary_setup(self, allocation='normal', retirement='normal', restore=False):
        setup = f'export FIXTURE_ALLOCATION={allocation} FIXTURE_RETIREMENT={retirement};\n'
        setup += r"""cat >mktemp <<'ALLOCATOR'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$FIXTURE_ALLOCATION" == partial || "$FIXTURE_ALLOCATION" == timed ]]; then
  sentinel=./ssh-last-probe.Partial1
  : > "$sentinel"
  chmod 0600 "$sentinel"
  printf '%s\n' "$sentinel"
  if [[ "$FIXTURE_ALLOCATION" == timed ]]; then
    printf 'timed-allocator-started\n' >&2
    sleep 30
  fi
  exit 73
fi
path=$(/usr/bin/mktemp "$@")
[[ -n "$path" && -f "$path" && ! -L "$path" ]] || exit 77
printf '%s\n' "$path" > fixture-owned-path
if [[ "$FIXTURE_ALLOCATION" == zero-attempt ]]; then printf '2147483647\n' > qemu.pid; fi
printf '%s\n' "$path"
ALLOCATOR
cat >rm <<'RETIREMENT'
#!/usr/bin/env bash
set -euo pipefail
[[ -f fixture-owned-path ]] || exit 77
read -r expected < fixture-owned-path
target=${@: -1}
[[ -n "$expected" && "$target" == "$expected" && "${OMG_SSH_LAST_PROBE_RECORD:-}" == "$expected" ]] || exit 77
[[ -f "$target" && ! -L "$target" ]] || exit 77
if [[ "$FIXTURE_RETIREMENT" == refuse ]]; then
  printf 'owned-record-retirement-refused\n'
  [[ -f "$target" ]] && printf 'owned-record-present-after-refusal\n'
  exit 73
fi
/usr/bin/rm "$@"
[[ ! -e "$target" ]] || exit 77
printf 'owned-record-retired-before-fixture-cleanup\n'
RETIREMENT
chmod 0755 mktemp rm
"""
        if allocation in ('partial', 'timed'):
            setup += ("trap '[[ -f ./ssh-last-probe.Partial1 && ! -s ./ssh-last-probe.Partial1 ]] "
                      "&& printf \"partial-output-sentinel-untouched-at-exit\\n\"' EXIT\n")
        if restore:
            setup += ("export OMG_SSH_LAST_PROBE_RECORD=caller-record-context; "
                      "trap '[[ \"${OMG_SSH_LAST_PROBE_RECORD:-}\" == caller-record-context ]] "
                      "&& printf \"caller-export-restored-at-exit\\n\"' EXIT\n")
        return setup

    def test_timed_allocator_preserves_deadline_without_fabricating_probe(self):
        result, elapsed, children = self.run_readiness(
            '[[ -z "${OMG_SSH_LAST_PROBE_RECORD:-}" ]] || exit 77; '
            'printf "timed-allocation-producer-complete\\n"; exit 0',
            setup=self._record_boundary_setup(allocation='timed'))
        self.assertIn('timed-allocator-started', result.stderr)
        self.assertEqual(result.stdout.splitlines().count('partial-output-sentinel-untouched-at-exit'), 1)
        completions = result.stdout.splitlines().count('timed-allocation-producer-complete')
        self.assertIn(completions, (0, 1))
        self.assertEqual(result.returncode, 0 if completions else 1, result.stderr)
        if completions:
            self.assertEqual(result.stderr.count('SSH last probe:'), 1)
            self.assertRegex(result.stderr, r'(?:^|\s)helper_exit=0(?:\s|$)')
            self.assertIn('capture_state=unavailable', result.stderr)
        else:
            self.assertNotIn('SSH last probe:', result.stderr)
            self.assertIn('SSH readiness timed out', result.stderr)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_failed_allocator_partial_output_grants_no_path_authority(self):
        result, elapsed, children = self.run_readiness(
            '[[ -z "${OMG_SSH_LAST_PROBE_RECORD:-}" && -f ./ssh-last-probe.Partial1 ]] || exit 77; '
            'printf "partial-output-producer-complete\\n"; exit 0',
            setup=self._record_boundary_setup(allocation='partial'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines().count('partial-output-producer-complete'), 1)
        self.assertEqual(result.stdout.splitlines().count('partial-output-sentinel-untouched-at-exit'), 1)
        self.assertRegex(result.stderr, r'(?:^|\s)helper_exit=0(?:\s|$)')
        self.assertIn('capture_state=unavailable', result.stderr)
        self.assertIn('stderr_bytes=0', result.stderr)
        self.assertNotIn('owned-record-retired', result.stdout)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_successful_allocator_zero_attempt_retires_exact_owned_file(self):
        result, elapsed, children = self.run_readiness(
            'printf "unexpected-zero-attempt-producer\\n"; exit 0',
            setup=self._record_boundary_setup(allocation='zero-attempt'))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('QEMU exited before SSH became ready', result.stderr)
        self.assertNotIn('SSH last probe:', result.stderr)
        self.assertNotIn('unexpected-zero-attempt-producer', result.stdout)
        self.assertEqual(result.stdout.splitlines().count('owned-record-retired-before-fixture-cleanup'), 1)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def _assert_record_retirement_and_context(self, status, retirement='normal', restore=False):
        program = ('[[ -n "${OMG_SSH_LAST_PROBE_RECORD:-}" '
                   '&& "$OMG_SSH_LAST_PROBE_RECORD" != caller-record-context '
                   '&& -f "$OMG_SSH_LAST_PROBE_RECORD" ]] || exit 77; '
                   'printf "fixture-owned-record-current\\n" >&2; '
                   f'printf "owned-record-producer-complete-{status}\\n"; exit {status}')
        result, elapsed, children = self.run_readiness(
            program, setup=self._record_boundary_setup(retirement=retirement, restore=restore))
        self.assertEqual(result.returncode, 0 if status == 0 else 1, result.stderr)
        completions = result.stdout.splitlines().count(f'owned-record-producer-complete-{status}')
        self.assertGreaterEqual(completions, 1)
        if status == 0:
            self.assertEqual(completions, 1)
        self.assertRegex(result.stderr, rf'(?:^|\s)exit={status}(?:\s|$)')
        self.assertRegex(result.stderr, rf'(?:^|\s)helper_exit={status}(?:\s|$)')
        self.assertIn('fixture-owned-record-current', result.stderr)
        self.assertIn('capture_state=complete', result.stderr)
        if retirement == 'normal':
            self.assertEqual(result.stdout.splitlines().count('owned-record-retired-before-fixture-cleanup'), 1)
            self.assertNotIn('owned-record-retirement-refused', result.stdout)
        else:
            self.assertEqual(result.stdout.splitlines().count('owned-record-retirement-refused'), 1)
            self.assertEqual(result.stdout.splitlines().count('owned-record-present-after-refusal'), 1)
            self.assertNotIn('owned-record-retired-before-fixture-cleanup', result.stdout)
        if restore:
            self.assertEqual(result.stdout.splitlines().count('caller-export-restored-at-exit'), 1)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_owned_record_retirement_preserves_success(self):
        self._assert_record_retirement_and_context(0)

    def test_owned_record_retirement_preserves_refusal(self):
        self._assert_record_retirement_and_context(255)

    def test_record_retirement_refusal_preserves_success(self):
        self._assert_record_retirement_and_context(0, retirement='refuse')

    def test_record_retirement_refusal_preserves_probe_refusal(self):
        self._assert_record_retirement_and_context(255, retirement='refuse')

    def test_exported_caller_record_context_is_restored_after_success(self):
        self._assert_record_retirement_and_context(0, restore=True)

    def test_exported_caller_record_context_is_restored_after_refusal(self):
        self._assert_record_retirement_and_context(255, restore=True)

    def test_genuine_ssh125_remains_an_observed_producer_status(self):
        result, elapsed, children = self.run_readiness(
            'printf "fixture-real-ssh125\\n" >&2; printf "real-ssh125-complete\\n"; exit 125')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertGreaterEqual(result.stdout.splitlines().count('real-ssh125-complete'), 1)
        self.assertRegex(result.stderr, r'(?:^|\s)exit=125(?:\s|$)')
        self.assertRegex(result.stderr, r'(?:^|\s)helper_exit=125(?:\s|$)')
        self.assertIn('capture_error=none', result.stderr)
        self.assertIn('capture_state=complete', result.stderr)
        self.assertIn('fixture-real-ssh125', result.stderr)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])

    def test_record_only_unavailable125_representation_is_distinct_from_observed125(self):
        shim = r"""import json,os,subprocess,sys
from pathlib import Path
result=subprocess.run([sys.executable,*sys.argv[1:]],input=sys.stdin.buffer.read())
if sys.argv[2]=='capture':
    if result.returncode!=125:
        raise RuntimeError('real125 capture prerequisite')
    target=os.environ.get('OMG_SSH_LAST_PROBE_RECORD','')
    if not target:
        raise RuntimeError('unavailable representation injection has no target')
    path=Path(target)
    record=json.loads(path.read_text())
    if (type(record['exit']) is not int or record['exit']!=125
            or record['helper_exit']!=125 or record['status_state']!='observed'):
        raise RuntimeError('real observed125 record prerequisite')
    record.update(exit=None,status_state='unavailable',capture_error='producer-status-unavailable')
    path.write_text(json.dumps(record))
    print('record-only-unavailable125-injected',file=sys.stderr)
sys.exit(result.returncode)
"""
        setup = ("cat >unavailable-status.py <<'UNAVAILABLE_STATUS'\n" + shim
                 + "\nUNAVAILABLE_STATUS\npython3() { command python3 unavailable-status.py \"$@\"; }")
        result, elapsed, children = self.run_readiness(
            'printf "fixture-represented-ssh125\\n" >&2; '
            'printf "represented-real-ssh125-complete\\n"; exit 125', setup=setup)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertGreaterEqual(result.stdout.splitlines().count('represented-real-ssh125-complete'), 1)
        self.assertIn('record-only-unavailable125-injected', result.stderr)
        self.assertRegex(result.stderr, r'(?:^|\s)exit=unavailable(?:\s|$)')
        self.assertRegex(result.stderr, r'(?:^|\s)helper_exit=125(?:\s|$)')
        self.assertIn('capture_error=producer-status-unavailable', result.stderr)
        self.assertIn('capture_state=complete', result.stderr)
        self.assertIn('fixture-represented-ssh125', result.stderr)
        self.assertLess(elapsed, 5)
        self.assertEqual(children, [])


if __name__ == '__main__':
    unittest.main()

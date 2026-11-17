"""The native coverage job must execute its supplemental CLI producer."""

import importlib.util
import hashlib
import io
import json
import os
import re
import select
import signal
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BASH = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
SPEC = importlib.util.spec_from_file_location('native_cli_coverage',
                                             ROOT / 'scripts/native-cli-coverage.py')
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)

UNKNOWN_SPEC = importlib.util.spec_from_file_location(
    'attend_unknown_fixture', ROOT / 'scripts/attend-unknown-fixture.py')
UNKNOWN = importlib.util.module_from_spec(UNKNOWN_SPEC)
UNKNOWN_SPEC.loader.exec_module(UNKNOWN)


class UnknownFixtureTerminal(unittest.TestCase):
    @staticmethod
    def prompt(digest='a' * 64):
        return (b'SECURITY WARNING: advisory coverage for the selected transaction is unknown.\n'
                b'No clean security result was established.\nPackage: fixture 1-1\n'
                + f'Type accept {digest} within 60 seconds to continue (default: cancel): '.encode())

    def test_only_complete_fresh_unknown_prompts_receive_exact_answers(self):
        first = self.prompt()
        offset, answers = UNKNOWN.review_answers(first[:-1], 0)
        self.assertEqual((offset, answers), (0, []))
        offset, answers = UNKNOWN.review_answers(first, offset)
        self.assertEqual(answers, [b'accept ' + b'a' * 64 + b'\n'])
        self.assertEqual(UNKNOWN.review_answers(first, offset), (offset, []))
        second = first + b'accepted\n' + self.prompt('b' * 64)
        end, answers = UNKNOWN.review_answers(second, offset)
        self.assertEqual(end, len(second))
        self.assertEqual(answers, [b'accept ' + b'b' * 64 + b'\n'])

    def test_fixture_never_accepts_a_disclosed_finding_or_unidentified_prompt(self):
        for prefix in [b'', b'SECURITY WARNING: the selected transaction has disclosed advisory findings.\n',
                       self.prompt().split(b'Type accept', 1)[0]
                       + b'SECURITY WARNING: the selected transaction has disclosed advisory findings.\n']:
            prompt = prefix + b'Type accept' + self.prompt().split(b'Type accept', 1)[1]
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, 'Unknown-only'):
                UNKNOWN.review_answers(prompt, 0)
        with self.assertRaisesRegex(ValueError, 'Unknown-only'):
            UNKNOWN.review_answers(self.prompt() + b'Type accept' + self.prompt().split(b'Type accept', 1)[1], 0)

    @unittest.skipIf(os.name == 'nt', 'Actual controlling-terminal behavior requires POSIX')
    def test_real_terminal_accepts_each_unknown_digest_and_records_the_decisions(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'review.json'
            program = ('import os,sys\n'
                       'assert os.isatty(0) and os.tcgetpgrp(0)==os.getpgrp()\n'
                       'for digest in ["a"*64,"b"*64]:\n'
                       ' print("SECURITY WARNING: advisory coverage for the selected transaction is unknown.")\n'
                       ' print("Package: owned-fixture 1-1")\n'
                       ' print("Type accept "+digest+" within 60 seconds to continue (default: cancel): ",end="",flush=True)\n'
                       ' assert sys.stdin.readline()=="accept "+digest+"\\n"\n'
                       'print("all exact reviews accepted")\n')
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/attend-unknown-fixture.py'),
                                     '--timeout', '3', '--receipt', str(receipt), '--',
                                     sys.executable, '-c', program], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(b'all exact reviews accepted', result.stdout)
            self.assertEqual(json.loads(receipt.read_text()),
                             dict(reviews=['a' * 64, 'b' * 64], cli_exit_code=0))

    @unittest.skipIf(os.name == 'nt', 'Actual controlling-terminal behavior requires POSIX')
    def test_real_terminal_refuses_disclosed_findings_and_reaps_timed_out_children(self):
        for finding in [True, False]:
            with self.subTest(finding=finding), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                receipt = root / 'review.json'
                child_pid = root / 'child.pid'
                program = ('import os,sys,time\n'
                           f'open({str(child_pid)!r},"w").write(str(os.getpid()))\n'
                           + ('print("SECURITY WARNING: the selected transaction has disclosed advisory findings.")\n'
                              'print("Type accept "+"c"*64+" within 60 seconds to continue (default: cancel): ",end="",flush=True)\n'
                              if finding else 'print("no complete review prompt",flush=True)\n')
                           + 'time.sleep(30)\n')
                result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/attend-unknown-fixture.py'),
                                         '--timeout', '0.5', '--receipt', str(receipt), '--',
                                         sys.executable, '-c', program], capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'Unknown-only' if finding else b'owned deadline', result.stderr)
                self.assertFalse(receipt.exists())
                pid = int(child_pid.read_text())
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)


@unittest.skipIf(os.name == 'nt', 'Native identity ownership requires POSIX metadata')
class MachineIdentityFixture(unittest.TestCase):
    def test_private_identity_and_restored_source_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            source = owner / 'system-machine-id'
            source.write_text('original guest identity\n')
            original = PRODUCER.sha(source)
            data = owner / 'data'
            data.mkdir(mode=0o700)
            identity = data / 'machine-id'
            value = '123e4567-e89b-42d3-a456-426614174000'
            identity.write_text(value)
            identity.chmod(0o600)
            uid, gid = (os.getuid(), os.getgid()) if os.getuid() else (65534, 65534)
            if os.getuid() == 0:
                os.chown(data, uid, gid)
                os.chown(identity, uid, gid)
            def verify():
                return PRODUCER.verify_machine_identity_fixture(owner, source, original, uid, gid)
            receipt = verify()
            self.assertEqual(receipt['status'], 'PASS_NATIVE_MACHINE_IDENTITY_FALLBACK')
            self.assertEqual(receipt['persisted_sha256'], hashlib.sha256(value.encode()).hexdigest())
            self.assertEqual((receipt['uid'], receipt['gid']), (uid, gid))
            identity.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                verify()
            identity.chmod(0o600)
            data.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'directory'):
                verify()
            data.chmod(0o700)
            link = data / 'extra-link'
            os.link(identity, link)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                verify()
            link.unlink()
            identity.write_text(value.replace('42d3', '12d3'))
            with self.assertRaisesRegex(ValueError, 'canonical'):
                verify()
            identity.write_text(value)
            source.write_text('source was not restored\n')
            with self.assertRaisesRegex(ValueError, 'not restored'):
                verify()

    def test_identity_symlink_and_root_identity_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            source = owner / 'system-machine-id'
            source.write_text('guest identity\n')
            data = owner / 'data'
            data.mkdir(mode=0o700)
            target = owner / 'outside-identity'
            target.write_text('123e4567-e89b-42d3-a456-426614174000')
            target.chmod(0o600)
            (data / 'machine-id').symlink_to(target)
            uid, gid = (os.getuid(), os.getgid()) if os.getuid() else (65534, 65534)
            if os.getuid() == 0:
                os.chown(data, uid, gid)
            with self.assertRaisesRegex(ValueError, 'metadata'):
                PRODUCER.verify_machine_identity_fixture(owner, source, PRODUCER.sha(source), uid, gid)
            with self.assertRaisesRegex(ValueError, 'ordinary'):
                PRODUCER.verify_machine_identity_fixture(owner, source, PRODUCER.sha(source), 0, 0)


class HostedProducer(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'Requires an owned Linux controlling terminal')
    def test_fresh_terminal_answers_the_current_native_consent_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / 'fixture-cli'
            digest = 'c' * 64
            cli.write_text('#!' + sys.executable + '\nimport signal,sys\n'
                           'signal.alarm(2)\n'
                           f'print("Full prepared batch SHA-256: {digest}")\n'
                           f'print("Type accept {digest} within 60 seconds to continue (default: cancel): ", end="", flush=True)\n'
                           f'sys.exit(0 if sys.stdin.readline() == "accept {digest}\\n" else 1)\n')
            cli.chmod(0o755)
            case = next(case for case in PRODUCER.FRESH_ADMISSION_CASES if case.name == 'archive-accept')
            state = {}
            result = PRODUCER.fresh_admission_terminal(cli, [], dict(os.environ), case, root,
                                                       state, os.getuid(), os.getgid())
            self.assertTrue(result['prompt_seen'], 'the current production prompt must be answered')
            self.assertEqual(result['exit_code'], 0, result['output'])

    @unittest.skipUnless(sys.platform == 'linux', 'The producer executes in a Linux guest')
    def test_guest_script_preserves_the_command_exit_status(self):
        PRODUCER.run_guest_script('exit 0', timeout=1)
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            PRODUCER.run_guest_script('exit 17', timeout=1)
        self.assertEqual(failure.exception.returncode, 17)

    @unittest.skipUnless(sys.platform == 'linux', 'Requires Linux process descriptors')
    def test_guest_timeout_kills_owned_descendants_without_killing_unrelated_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'descendant.pid'
            unrelated = subprocess.Popen(['sleep', '60'], start_new_session=True)
            popen = subprocess.Popen
            descendant = None

            def capture(*args, **kwargs):
                nonlocal descendant
                process = popen(*args, **kwargs)
                deadline = time.monotonic() + 2
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not marker.exists():
                    process.kill()
                    process.wait()
                    self.fail('the owned descendant did not start')
                descendant = os.pidfd_open(int(marker.read_text()))
                return process

            try:
                with patch.object(PRODUCER.subprocess, 'Popen', side_effect=capture):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        PRODUCER.run_guest_script(
                            'sleep 60 & printf "%s" "$!" > ' + shlex.quote(str(marker)) + '; wait',
                            timeout=0.1)
                self.assertTrue(select.select([descendant], [], [], 2)[0],
                                'the timed-out producer left a live descendant holding its output')
                self.assertIsNone(unrelated.poll(), 'unrelated process must survive producer cleanup')
            finally:
                if descendant is not None:
                    if not select.select([descendant], [], [], 0)[0]:
                        signal.pidfd_send_signal(descendant, signal.SIGKILL)
                    os.close(descendant)
                unrelated.terminate()
                unrelated.wait(timeout=3)

    def test_generated_fresh_stage_receipt_block_executes_without_template_corruption(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        first = script.index("python3 - <<'OMG_FRESH_STAGE_")
        last = script.index('\nstage=native-preflight-isolation', first)
        block = script[first:last]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'fresh-admission.json').write_text(json.dumps({'profile_stages': ['fresh-one', 'fresh-two']}))
            block = block.replace('/evidence/cli/', str(root) + '/')
            result = subprocess.run([BASH, '-euo', 'pipefail', '-c', block],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'process-checks.tsv').read_text(), 'fresh-one\t0\nfresh-two\t0\n')
            self.assertEqual(result.stderr, '')

    def test_generated_cli_identity_preserves_literal_template_words(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        compiled = '/workspace/RECEIPT/ARTIFACTS/SELECTION/COMPILED_CLI/NATIVE_PREFLIGHT_TEST/@@ARTIFACTS@@/omg'
        script = PRODUCER.guest_script(artifacts, compiled)
        first = script.index("printf '%s' ")
        marker = ' > /omg-extra-bin/cli-receipt.json'
        last = script.index(marker, first) + len(marker)
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / 'identity.json'
            block = script[first:last].replace('/omg-extra-bin/cli-receipt.json', shlex.quote(str(receipt)))
            result = subprocess.run([BASH, '-euo', 'pipefail', '-c', block],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(receipt.read_text()),
                             dict(original=compiled, copy='/omg-extra-bin/cli', sha256='a' * 64))

    @unittest.skipIf(os.name == 'nt', 'Native cloud-init preparation requires POSIX Bash')
    def test_native_dependencies_are_queued_before_the_existing_boot_reboot(self):
        driver = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        bootstrap = driver[driver.index('cp "$here/qemu-boot-budget.sh"'):driver.index('cat > "$work/boot.sh"')]
        boot = driver.split("<<'BOOT'\n", 1)[1].split('\nBOOT\n', 1)[0]
        seed = boot[boot.index('{\n  # Guest identity'):boot.index('\nchmod 600 user-data')]
        seed = seed.replace('/work/native-cli', '"$work/native-cli"')
        for native in (False, True):
            with self.subTest(native=native), tempfile.TemporaryDirectory() as directory:
                owner = Path(directory)
                inputs = owner / 'inputs'
                (inputs / 'bin').mkdir(parents=True)
                (inputs / 'native-cli-manifest.json').write_text('{}\n')
                (owner / 'client-key.pub').write_text('ssh-ed25519 fixture-client\n')
                (owner / 'guest-host-key').write_text('fixture-private-key\n')
                (owner / 'guest-host-key.pub').write_text('ssh-ed25519 fixture-host\n')
                prefix = 'set -euo pipefail\nwork=$PWD\nhere=$PRODUCER_DIRECTORY\nnative_cli_coverage_dir=$NATIVE_INPUTS\n'
                result = subprocess.run([BASH, '-c', prefix + bootstrap + seed], cwd=owner,
                                        env=dict(os.environ, PRODUCER_DIRECTORY=str(ROOT / 'scripts'),
                                                 NATIVE_INPUTS=str(inputs) if native else ''),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                document = (owner / 'user-data').read_text()
                if not native:
                    self.assertNotIn('\nruncmd:\n', document)
                    continue
                self.assertIn('\nruncmd:\n', document,
                              'Native dependency upgrades must finish during cloud-init before the existing reboot')
                commands = [json.loads(line.strip()[2:]) for line in document.split('\nruncmd:\n', 1)[1].splitlines()
                            if line.strip().startswith('- ')]
                self.assertEqual(commands, [['pacman', '-Syu', '--noconfirm', '--needed',
                                            'python', 'sudo', 'bubblewrap', 'fakeroot', 'debugedit',
                                            'git', 'make', 'jq', 'diffutils', 'gnupg', 'openssl',
                                            'iproute2', 'util-linux']])

    @unittest.skipUnless(sys.platform == 'linux', 'Native QMP identity requires Linux peer credentials')
    def test_poweroff_ssh_disconnect_preserves_producer_status_after_observed_guest_shutdown(self):
        import threading
        import time

        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        body = source.split("printf '[native-coverage] requesting clean poweroff\\n'", 1)[1].split('\nNATIVE_COVERAGE', 1)[0]
        server_code = r'''
import json,socket,sys,time
from pathlib import Path
path,trigger,event=sys.argv[1:]
with socket.socket(socket.AF_UNIX) as server:
    server.bind(path);server.listen(1)
    with server.accept()[0] as peer:
        stream=peer.makefile('rwb',buffering=0)
        stream.write(b'{"QMP":{"version":{}}}\r\n')
        line=stream.readline()
        if not line: sys.exit(0)
        command=json.loads(line)
        stream.write((json.dumps({'return':{},'id':command['id']})+'\r\n').encode())
        deadline=time.monotonic()+5
        while not Path(trigger).exists():
            assert time.monotonic()<deadline
            time.sleep(0.01)
        if event != 'null':
            stream.write((json.dumps({'event':'SHUTDOWN','data':json.loads(event)})+'\r\n').encode())
'''
        guest_shutdown = {'guest': True, 'reason': 'guest-shutdown'}
        cases = [
            (0, 0, guest_shutdown, False, True),
            (0, 255, guest_shutdown, False, True),
            (17, 255, guest_shutdown, False, True),
            (0, 1, guest_shutdown, False, False),
            (0, 255, {'guest': False, 'reason': 'host-signal'}, False, False),
            (0, 255, {'guest': True, 'reason': 'guest-reset'}, False, False),
            (0, 255, None, False, False),
            (0, 255, guest_shutdown, True, False),
        ]
        for producer_status, ssh_status, event, wrong_peer, accepted in cases:
            with self.subTest(producer_status=producer_status, ssh_status=ssh_status,
                              event=event, wrong_peer=wrong_peer), tempfile.TemporaryDirectory() as directory:
                owner = Path(directory)
                (owner / 'guest').mkdir()
                (owner / 'native-cli').mkdir()
                (owner / 'native-cli/native-cli-coverage.py').write_bytes((ROOT / 'scripts/native-cli-coverage.py').read_bytes())
                trigger = owner / 'shutdown-request'
                monitor = owner / 'guest/native-qmp.sock'
                server = subprocess.Popen([sys.executable, '-c', server_code, str(monitor), str(trigger), json.dumps(event)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                reaper = threading.Thread(target=server.wait)
                reaper.start()
                try:
                    deadline = time.monotonic() + 5
                    while not monitor.exists():
                        self.assertLess(time.monotonic(), deadline, 'owned protocol peer did not start')
                        time.sleep(0.01)
                    (owner / 'guest/qemu.pid').write_text(str(server.pid + int(wrong_peer)))
                    ssh = owner / 'ssh'
                    ssh.write_text('#!/usr/bin/env python3\nimport os\nfrom pathlib import Path\n'
                                   'Path(os.environ["SHUTDOWN_TRIGGER"]).touch()\nraise SystemExit(int(os.environ["SSH_RESULT"]))\n')
                    ssh.chmod(0o755)
                    script = 'set -euo pipefail\nopts=(); status=' + str(producer_status) + '\n' + body.replace('/work/', str(owner) + '/')
                    result = subprocess.run([BASH, '-c', script],
                        env=dict(os.environ, PATH=str(owner) + os.pathsep + os.environ['PATH'],
                                 SHUTDOWN_TRIGGER=str(trigger), SSH_RESULT=str(ssh_status)),
                        capture_output=True, text=True, timeout=10)
                finally:
                    if server.poll() is None:
                        server.terminate()
                    reaper.join(timeout=5)
                    server.stderr.close()
                if accepted:
                    self.assertEqual(result.returncode, producer_status, result.stdout + result.stderr)
                    receipt = json.loads((owner / 'native-poweroff.json').read_text())
                    self.assertEqual(receipt['shutdown'], guest_shutdown)
                    self.assertTrue(receipt['process_gone'])
                    self.assertEqual(receipt['qmp_peer_pid'], server.pid)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertNotIn('PASS_GUEST_POWEROFF', (owner / 'native-poweroff.json').read_text())
                    if wrong_peer:
                        self.assertFalse(trigger.exists(), 'Poweroff must not run against another monitor process')

    def test_native_migration_state_requires_exact_packages_payloads_and_install_intents(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            database = owner / 'db'
            (database / 'local').mkdir(parents=True)
            (owner / 'cache').mkdir()
            packages = {}
            for name in ('fixture-app', 'xorg-xrandr', 'hp-omnibook-3-audio'):
                payload = (name + ': upgraded\n').encode()
                packages[name] = dict(reason=0, payload_path='usr/share/fixture/' + name,
                                      after_sha256=hashlib.sha256(payload).hexdigest())
                if name != 'hp-omnibook-3-audio':
                    PRODUCER.fixture_local_package(owner / 'root', database, name, '3-1',
                                                   packages[name]['payload_path'], payload, 0)
            (owner / 'data-receipt.json').write_text(json.dumps(dict(
                initial_packages={'fixture-app': packages['fixture-app']},
                migration_packages={name: packages[name] for name in ('xorg-xrandr', 'hp-omnibook-3-audio')})))
            (owner / 'cache/unrelated.txt').write_text('must survive pruning\n')
            (owner / 'outside-cache.txt').write_text('must survive symlink escape\n')
            (owner / 'cache/escape.pkg.tar.gz').symlink_to(owner / 'outside-cache.txt')
            for version in ('1-1', '2-1'):
                for suffix in ('', '.sig'):
                    (owner / f'cache/omg-coverage-app-{version}-any.pkg.tar.gz{suffix}').write_bytes(b'cached')
            state = PRODUCER.verify_signed_fixture(owner, phase='migrated-unmatched')
            self.assertEqual(set(state['packages']), {'fixture-app', 'xorg-xrandr'})
            with self.assertRaisesRegex(ValueError, 'inventory differs'):
                PRODUCER.verify_signed_fixture(owner, phase='migrated')
            PRODUCER.fixture_local_package(owner / 'root', database, 'hp-omnibook-3-audio', '3-1',
                                           packages['hp-omnibook-3-audio']['payload_path'],
                                           b'hp-omnibook-3-audio: upgraded\n', 0)
            with self.assertRaisesRegex(ValueError, 'Non-matching hardware'):
                PRODUCER.verify_signed_fixture(owner, phase='migrated-unmatched')
            state = PRODUCER.verify_signed_fixture(owner, phase='migrated')
            self.assertEqual(set(state['packages']), set(packages))
            description = database / 'local/hp-omnibook-3-audio-3-1/desc'
            description.write_text(description.read_text().replace('%REASON%\n0', '%REASON%\n1'))
            with self.assertRaisesRegex(ValueError, 'install intent'):
                PRODUCER.verify_signed_fixture(owner, phase='migrated')

    def test_interrupted_update_requires_exact_partial_native_state(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            database = owner / 'db'
            (database / 'local').mkdir(parents=True)
            (owner / 'cache').mkdir()
            payload = b'original payload\n'
            PRODUCER.fixture_local_package(owner / 'root', database, 'fixture-app', '1-1',
                                           'usr/share/fixture/value', payload, 0)
            PRODUCER.fixture_local_package(owner / 'root', database, 'omg-coverage-dead-dep', '1-1',
                                           'usr/share/fixture/orphan', b'orphan\n', 1)
            (owner / 'data-receipt.json').write_text(json.dumps(dict(
                initial_database_sha256=PRODUCER.fixture_tree_hashes(database / 'local'),
                initial_payload_sha256=PRODUCER.fixture_tree_hashes(owner / 'root'), initial_packages={
                'fixture-app': dict(reason=0, payload_path='usr/share/fixture/value',
                                    before_sha256=hashlib.sha256(payload).hexdigest(),
                                    after_sha256=hashlib.sha256(b'updated\n').hexdigest())})))
            (owner / 'cache/unrelated.txt').write_text('must survive pruning\n')
            (owner / 'outside-cache.txt').write_text('must survive symlink escape\n')
            (owner / 'cache/escape.pkg.tar.gz').symlink_to(owner / 'outside-cache.txt')
            for version in ('1-1', '2-1'):
                (owner / f'cache/omg-coverage-app-{version}-any.pkg.tar.gz').write_bytes(b'cached')
                (owner / f'cache/omg-coverage-app-{version}-any.pkg.tar.gz.sig').write_bytes(b'signature')
            state = PRODUCER.verify_signed_fixture(owner, phase='cache-pruned')
            self.assertEqual(state['status'], 'PASS_NATIVE_CACHE_PRUNED_STATE')
            original = owner / 'root/usr/share/fixture/value'
            original.write_bytes(b'unexpected write')
            with self.assertRaisesRegex(ValueError, 'payload differs'):
                PRODUCER.verify_signed_fixture(owner, phase='cache-pruned')
            original.write_bytes(payload)
            (owner / 'db/db.lck').write_text('leaked')
            with self.assertRaisesRegex(ValueError, 'database lock'):
                PRODUCER.verify_signed_fixture(owner, phase='cache-pruned')

    def test_cancellation_cases_keep_unrelated_processes_and_native_state(self):
        for stage, control in [('omarchy-interrupted', 'interrupt'),
                               ('omarchy-output-closed', 'output-closed'),
                               ('omarchy-terminal-closed', 'terminal-closed')]:
            self.assertIn(stage, PRODUCER.OMARCHY_CASES,
                          'Native coverage omits cancellation or output-disconnection behavior')
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertEqual(case.control, control)
            self.assertEqual(case.native_phase, 'cache-pruned')
            self.assertEqual(case.exit_status, 1)

    def test_normal_arch_readonly_updates_are_required_after_vendor_scenarios(self):
        for stage in ('arch-dry-run', 'arch-check'):
            self.assertIn(stage, PRODUCER.PROCESS_STAGES)
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('ID=arch', script)
        self.assertIn('transcript_unchanged=yes', script)

    @unittest.skipIf(os.name == 'nt', 'QEMU transport preflight requires POSIX Bash')
    def test_native_coverage_transport_reaches_preflight_with_bound_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            inputs = owner / 'inputs'
            binaries = inputs / 'bin'
            binaries.mkdir(parents=True)
            artifacts = {}
            for role in PRODUCER.ROLES:
                executable = binaries / role
                executable.write_bytes(b'preflight-only fixture, never executed\n')
                executable.chmod(0o755)
                artifacts[role] = dict(path='/compiled/' + role, bytes=executable.stat().st_size,
                                       sha256=hashlib.sha256(executable.read_bytes()).hexdigest())
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
            manifest = dict(source_commit=commit,
                            producer_sha256=PRODUCER.sha(ROOT / 'scripts/native-cli-coverage.py'),
                            unknown_driver_sha256=PRODUCER.sha(ROOT / 'scripts/attend-unknown-fixture.py'),
                            artifacts=artifacts)
            (inputs / 'native-cli-manifest.json').write_text(json.dumps(manifest))
            fake_tools = owner / 'tools'
            fake_tools.mkdir()
            docker = fake_tools / 'docker'
            docker.write_text('#!/bin/sh\nprintf "%s\n" "$*" >> "$FAKE_DOCKER_LOG"\nexit 7\n')
            docker.chmod(0o755)
            staged = owner / 'staged'
            staged.mkdir()
            calls = owner / 'docker-calls'
            environment = dict(os.environ, PATH=str(fake_tools) + os.pathsep + os.environ['PATH'],
                               OMG_QEMU_ALLOW_NO_KVM='1', FAKE_DOCKER_LOG=str(calls))
            benchmark = os.environ.get('OMG_NATIVE_BENCHMARK_UNDER_TEST', str(ROOT / 'scripts/benchmark-qemu.sh'))
            args = [BASH, benchmark, '--distro', 'arch', '--arch', 'x86_64', '--release', 'v0.1.224',
                    '--staged-dir', str(staged), '--native-cli-coverage-dir', str(inputs),
                    '--evidence-dir', str(owner / 'evidence')]
            result = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertTrue(calls.is_file(), 'Closed native transport was not admitted to its Docker preflight')
            self.assertEqual(calls.read_text(), 'version --format {{.Server.Version}}\n')
            reports = list((owner / 'evidence').glob('run-*/results.json'))
            self.assertEqual(len(reports), 1)
            self.assertEqual(json.loads(reports[0].read_text())[0]['case_id'], 'qemu-arch-native-cli-coverage')
            calls.unlink()
            (binaries / 'cli').write_bytes(b'tampered')
            refused = subprocess.run(args, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(refused.returncode, 0)
            self.assertFalse(calls.exists(), 'Unbound executable bytes reached Docker')

    @unittest.skipIf(os.name == 'nt', 'Controller launch uses POSIX Bash')
    def test_native_controller_reaps_exited_qemu_without_changing_other_modes(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        launch = source[source.index('controller_work=$work\n'):
                        source.index('if [[ "$restrict_egress" == true ]]; then', source.index('controller_work=$work\n'))]
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            docker = owner / 'docker'
            docker.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
                              'if sys.argv[1] == "run":\n'
                              ' with open(os.environ["CAPTURE"], "w") as f: json.dump(sys.argv[2:],f)\n'
                              ' print("unit-controller")\n'
                              'elif sys.argv[1] == "inspect":\n'
                              ' print(json.dumps([dict(Type="bind", Source=os.environ["WORK"], Destination=os.environ["WORK"], RW=True)]))\n')
            docker.chmod(0o755)
            capture = owner / 'launch.json'
            for native in ('/admitted-fixture', ''):
                prefix = 'work="$WORK"; here="$PRODUCER_DIRECTORY"; controller=unit-controller; controller_image=fixture; docker_device_args=(); native_cli_coverage_dir="$NATIVE";\n'
                result = subprocess.run([BASH, '-euo', 'pipefail', '-c', prefix + launch],
                                        env=dict(os.environ, PATH=str(owner) + os.pathsep + os.environ['PATH'],
                                                 WORK=str(owner), PRODUCER_DIRECTORY=str(ROOT / 'scripts'),
                                                 CAPTURE=str(capture), NATIVE=native),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual('--init' in json.loads(capture.read_text()), bool(native),
                                 'The native controller must reap QEMU after clean poweroff')

    def test_signed_fixture_package_has_native_signature_preflight_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = PRODUCER.fixture_package(Path(directory), 'fixture-app', '3-1',
                                               'usr/share/fixture/value', b'updated', ('fixture-dep>=1-1',))
            with tarfile.open(archive) as package:
                metadata = package.extractfile('.PKGINFO').read().decode()
                self.assertIn('packager = ', metadata)
                self.assertIn('depend = fixture-dep>=1-1\n', metadata)
                self.assertEqual(package.extractfile('usr/share/fixture/value').read(), b'updated')
                self.assertIsNotNone(package.getmember('.MTREE'))

    def test_guest_archive_transport_extracts_only_bounded_regular_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            archive = owner / 'returned.tar'
            with tarfile.open(archive, 'w') as tar:
                member = tarfile.TarInfo('cli/real.log')
                value = b'actual captured evidence\n'
                member.size = len(value)
                tar.addfile(member, io.BytesIO(value))
            destination = owner / 'evidence'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                     'unpack', '--archive', str(archive), '--directory', str(destination)],
                                    text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((destination / 'cli/real.log').read_bytes(), value)
            self.assertFalse((destination / 'cli/real.log').is_symlink())

    def test_guest_archive_transport_refuses_escape_links_devices_and_duplicates(self):
        cases = [('../escape', tarfile.REGTYPE, ''), ('/absolute', tarfile.REGTYPE, ''),
                 ('cli/link', tarfile.SYMTYPE, '../../escape'),
                 ('cli/hard', tarfile.LNKTYPE, 'cli/real.log'), ('cli/fifo', tarfile.FIFOTYPE, '')]
        with tempfile.TemporaryDirectory() as directory:
            owner = Path(directory)
            sentinel = owner / 'escape'
            sentinel.write_bytes(b'unchanged')
            for index, (name, kind, target) in enumerate(cases):
                archive = owner / ('bad-' + str(index) + '.tar')
                with tarfile.open(archive, 'w') as tar:
                    member = tarfile.TarInfo(name)
                    member.type, member.linkname = kind, target
                    tar.addfile(member)
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                         'unpack', '--archive', str(archive),
                                         '--directory', str(owner / ('evidence-' + str(index)))],
                                        text=True, capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertEqual(sentinel.read_bytes(), b'unchanged')
            archive = owner / 'duplicate.tar'
            with tarfile.open(archive, 'w') as tar:
                for _ in range(2):
                    tar.addfile(tarfile.TarInfo('same'))
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                     'unpack', '--archive', str(archive), '--directory', str(owner / 'duplicate')],
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)

    def test_controller_mapping_uses_the_most_specific_writable_bind(self):
        mounts = [
            {'Type': 'bind', 'Source': '/home/runner/work', 'Destination': '/__w', 'RW': True},
            {'Type': 'bind', 'Source': '/runner/temp', 'Destination': '/__w/_temp', 'RW': True},
        ]
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                 'controller-path', '--path', '/__w/_temp/owned-native/run-one'],
                                input=json.dumps(mounts), text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '/runner/temp/owned-native/run-one\n')

    def test_controller_mapping_refuses_unmapped_ambiguous_or_unsafe_paths(self):
        writable = {'Type': 'bind', 'Source': '/runner/temp', 'Destination': '/__w/_temp', 'RW': True}
        cases = [
            ('/__w/_temporary/run', [writable]),
            ('/__w/_temp/../outside', [writable]),
            ('/__w/_temp/run,other', [writable]),
            ('/__w/_temp/run', [dict(writable, RW=False)]),
            ('/__w/_temp/run', [dict(writable, Type='volume')]),
            ('/__w/_temp/run', [writable, dict(writable, Source='/different')]),
            ('/__w/_temp/run', [dict(writable, Source='relative')]),
        ]
        for path, mounts in cases:
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/native-cli-coverage.py'),
                                     'controller-path', '--path', path], input=json.dumps(mounts),
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0, path)
            self.assertFalse(result.stdout, 'Refused mount mappings must not produce a usable host path')

    def test_native_image_installs_supplemental_runtime_dependencies(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        image = workflow.split("docker build --tag omg-coverage-sandbox - <<'DOCKERFILE'", 1)[1]
        image = image.split('DOCKERFILE', 1)[0]
        install = next(line.strip() for line in image.splitlines() if line.strip().startswith('RUN pacman '))
        packages = set(shlex.split(install.split('&&', 1)[0]))
        required = {'git', 'make', 'jq', 'diffutils', 'openssl', 'iproute2'}
        self.assertFalse(required - packages,
                         'Native supplemental fixtures lack runtime packages: ' + ', '.join(sorted(required - packages)))

    @unittest.skipIf(os.name == 'nt', 'Native prerequisite shell requires POSIX Bash')
    def test_native_runtime_preflight_reports_all_missing_commands_and_refuses(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        line = next(line for line in script.splitlines() if 'prerequisites.txt' in line)
        args = shlex.split(line)
        self.assertEqual(args[:3], ['ordinary', 'bash', '-c'])
        loop = args[3]
        self.assertIn('git make jq cmp', loop)
        missing = ['omg-fixture-missing-tool-a', 'omg-fixture-missing-tool-b']
        for tools, expected in [('true printf', 0), ('true ' + missing[0] + ' printf ' + missing[1], 1)]:
            result = subprocess.run([BASH, '-euo', 'pipefail', '-c', loop.replace('git make jq cmp', tools)],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ['true', 'printf'])
            if expected:
                for tool in missing:
                    self.assertIn('Missing native fixture command: ' + tool, result.stderr)

    def test_private_loopback_fixture_has_required_network_capability(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        native = workflow.split('      - name: Cover sandbox descendant cancellation\n', 1)[1]
        create = native.split('container=$(docker create ', 1)[1].split("/bin/bash -euo pipefail -c '", 1)[0]
        self.assertIn('--cap-add NET_ADMIN', create,
                      'Private network namespace cannot raise loopback without NET_ADMIN')
        self.assertIn('--network none', create)

    @unittest.skipIf(os.name == 'nt', 'Native provider fixture reads POSIX host databases')
    def test_omarchy_offline_provider_files_preserve_hosts_and_confine_dns(self):
        script = PRODUCER.omarchy_guest_script()
        block = script.split("<<'OMG_OMARCHY_OFFLINE_ADVISORY'\n", 1)[1].split('\nOMG_OMARCHY_OFFLINE_ADVISORY', 1)[0]
        original_hosts = Path('/etc/hosts').read_bytes()
        original_nss = Path('/etc/nsswitch.conf').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-', directory], input=block, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            root = Path(directory)
            self.assertEqual((root / 'advisory-hosts').read_text().splitlines()[-1],
                             '127.0.0.1 omg-advisories.latham.workers.dev')
            self.assertTrue((root / 'advisory-hosts').read_bytes().startswith(original_hosts.rstrip()))
            nss_lines = (root / 'advisory-nss').read_text().splitlines()
            self.assertEqual([line for line in nss_lines if line.startswith('hosts:')], ['hosts: files'])
        self.assertEqual(Path('/etc/hosts').read_bytes(), original_hosts)
        self.assertEqual(Path('/etc/nsswitch.conf').read_bytes(), original_nss)

    @unittest.skipIf(os.name == 'nt', 'Native fixture runner requires POSIX Bash')
    def test_advisory_consent_runner_counts_profiles_and_refuses_missing_evidence(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        native = workflow.split('      - name: Cover sandbox descendant cancellation\n', 1)[1]
        function = 'run_case() {' + native.split('run_case() {', 1)[1].split('\n              cases=(', 1)[0]
        name = 'package_managers::alpm_ops::tests::native_advisory_consent_installs_only_the_accepted_transaction'
        case_id = name.replace('::', '_')
        groups = ('finding', 'unavailable', 'unmapped')
        for missing, stale in [(None, None), *((group, None) for group in groups),
                               *((None, group) for group in groups)]:
            with self.subTest(missing=missing, stale=stale), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'bin').mkdir()
                (root / 'evidence').mkdir()
                (root / 'profiles').mkdir()
                (root / 'evidence/registry.txt').write_text(name + ': test\n')
                calls = root / 'calls.txt'
                if stale:
                    (root / 'profiles' / f'omg-fixture-{case_id}-{stale}-stale-1-1.profraw').write_text('old profile')
                fake = root / 'bin/python3'
                fake.write_text('#!/bin/bash\nset -euo pipefail\n'
                                'test "$1" = /advisory-fixture/test-arch-advisory-consent.py\n'
                                'test "$2" = --unit\n'
                                'test "$6" = --profiles\ntest "$8" = --coverage\n'
                                'printf "%s\\n" "${9}" >> "$CALLS"\n'
                                'if test "${9}" != "$MISSING"; then\n'
                                '  printf profile > "${7}/omg-fixture-$CASE_ID-${9}-accept-1-1.profraw"\n'
                                'fi\n'
                                + 'printf \'{"passed":8}\\n\'\n')
                fake.chmod(0o755)
                script = 'set -euo pipefail\n' + function + '\nrun_case ' + shlex.quote(name)
                result = subprocess.run([BASH, '-c', script], capture_output=True, text=True,
                                        env=os.environ | {'PATH': str(root / 'bin') + os.pathsep + os.environ['PATH'],
                                            'fixture_evidence': str(root / 'evidence'), 'fixture_profiles': str(root / 'profiles'),
                                            'fixture_binary': '/fixture', 'CASE_ID': case_id, 'CALLS': str(calls),
                                            'MISSING': missing or ''})
                self.assertEqual(result.returncode == 0, not missing and not stale, result.stdout + result.stderr)
                expected = groups[:groups.index(missing) + 1] if missing else (
                    groups[:groups.index(stale)] if stale else groups)
                self.assertEqual(calls.read_text().splitlines() if calls.exists() else [], list(expected))
                passed = root / 'evidence/passed.tsv'
                if not missing and not stale:
                    self.assertEqual(passed.read_text(), name + '\t3\n')
                else:
                    self.assertFalse(passed.exists(), 'Missing profiles must not be reported as a passed native fixture')

    def test_supplemental_cli_execution_precedes_the_state_mount(self):
        workflow = (ROOT / '.github/workflows/coverage.yml').read_text()
        native = workflow.split('      - name: Cover sandbox descendant cancellation\n', 1)[1]
        native = native.split('\n      - name:', 1)[0]
        self.assertIn('python3 scripts/native-cli-coverage.py prepare', native,
                      'Hosted native coverage omits the protected supplemental CLI producer')
        self.assertIn('--native-cli-coverage-dir', native)
        self.assertNotIn('python /native-cli-coverage.py run', native)
        self.assertIn('python3 scripts/native-cli-coverage.py verify', native)
        self.assertLess(native.index('--native-cli-coverage-dir'),
                        native.index('docker start --attach'))

    def test_missing_runtime_directory_keeps_the_lock_private(self):
        names = {'omarchy-runtime-fallback', 'omarchy-runtime-foreign-lock'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys(),
                        'Native coverage omits session runtime fallback and foreign lock refusal')
        self.assertEqual(PRODUCER.OMARCHY_CASES['omarchy-runtime-fallback'].lock_location, 'temporary')
        self.assertEqual(PRODUCER.OMARCHY_CASES['omarchy-runtime-foreign-lock'].lock_location, 'foreign')
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('runtime_environment=()', script)
        self.assertIn('coordination_lock=/tmp/omarchy-update.lock', script)
        self.assertIn('flock --nonblock 9 9< \"$coordination_lock\"', script)
        self.assertIn('foreign fallback lock was preserved', script)

    def test_authorization_refresh_cases_require_real_sudo_audit_records(self):
        names = {'omarchy-authorization-refresh', 'omarchy-authorization-denied'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys(),
                        'The real authorization keeper is never exercised past its interval')
        for stage in names:
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertEqual(case.scene, 'authorization-hold')
            self.assertIn(case.authorization, ('refresh', 'denied'))
            self.assertEqual(case.native_phase, 'complete')
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('omarchy-update-dev:authorization-hold) sleep 65', script)
        self.assertIn("producer['authorization_audit']", script)
        self.assertIn('!/usr/bin/true', script)

    def test_missing_reboot_helper_is_required_after_a_completed_native_update(self):
        self.assertIn('omarchy-reboot-helper-missing', PRODUCER.OMARCHY_CASES)
        case = PRODUCER.OMARCHY_CASES['omarchy-reboot-helper-missing']
        self.assertEqual(case.exit_status, 1)
        self.assertEqual(case.absent_helper, 'omarchy-system')
        self.assertEqual(case.reboot_answer, 'y')
        self.assertEqual(case.native_phase, 'complete')
        self.assertNotIn('omarchy-system\treboot', case.helpers)

    def test_current_kernel_update_requires_signed_ownership_without_reboot(self):
        self.assertTrue('omarchy-current-kernel' in PRODUCER.OMARCHY_CASES, 'Missing current-kernel update scenario')
        case = PRODUCER.OMARCHY_CASES['omarchy-current-kernel']
        self.assertEqual(case.exit_status, 0)
        self.assertEqual(case.native_phase, 'complete')
        self.assertIsNone(case.reboot_answer)
        self.assertIn('--current-kernel', PRODUCER.omarchy_guest_script())

    def test_attended_reboot_cases_require_prompt_and_terminal_receipts(self):
        names = {'omarchy-reboot-decline', 'omarchy-reboot-accept', 'omarchy-reboot-failure'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys(),
                        'Native coverage does not exercise the attended reboot prompt')
        for stage in names:
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertIn(case.reboot_answer, ('y', 'n'))
            self.assertEqual(case.native_phase, 'complete')
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('pty.fork()', script)
        self.assertIn('signal.SIGWINCH', script)
        self.assertIn("b'Reboot now?'", script)

    def test_declared_optional_and_required_helper_cases_execute_the_real_cli(self):
        required = {'omarchy-snapshot-missing', 'omarchy-snapshot-unsupported',
                    'omarchy-required-helper-missing'}
        self.assertTrue(required <= PRODUCER.OMARCHY_CASES.keys(),
                        'Native lifecycle coverage omits missing/unsupported helper scenarios')
        script = PRODUCER.omarchy_guest_script()
        stages = script.split('for stage in ', 1)[1].split('; do', 1)[0].split()
        self.assertEqual(stages, list(PRODUCER.OMARCHY_CASES),
                         'Every declared scenario must execute once in declaration order')
        for stage in required:
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertIn(stage + ')', script)
            self.assertIn('OMARCHY_FIXTURE_SCENE="$scene"', script)
            if case.absent_helper:
                self.assertIn(case.absent_helper, script)

    def test_generated_omarchy_cases_use_the_real_cli_in_a_private_namespace(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        self.assertIn("OMG_OMARCHY_NAMESPACE", script)
        self.assertIn('ID=omarchy', script)
        self.assertIn('mount --bind "$fixture/release" /etc/os-release', script)
        self.assertIn('omarchy-success', script)
        self.assertIn('omarchy-vendor-failure', script)
        self.assertIn('omarchy-migration-refusal', script)
        self.assertIn('test -u /usr/bin/sudo', script)
        self.assertNotIn('mount --bind "$fixture/sudo"', script)
        self.assertIn('exec /omg-extra-bin/cli update', script)

    @unittest.skipIf(os.name == 'nt', 'Guest sentinel scripts require POSIX Bash')
    def test_package_helper_sentinels_refuse_instead_of_faking_success(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'bin').mkdir()
            trace = root / 'helpers.tsv'
            environment = dict(os.environ, OMARCHY_PATH=str(root),
                               OMARCHY_FIXTURE_CASE='omarchy-success', OMARCHY_HELPER_TRACE=str(trace))
            for name in ('omarchy-update-pkg-prune', 'omarchy-update-keyring',
                         'omarchy-update-system-pkgs', 'omarchy-update-orphan-pkgs',
                         'pacman', 'pacman-key', 'paccache', 'yay', 'aura', 'paru'):
                program = root / 'bin' / name
                program.write_text(helper)
                program.chmod(0o755)
                result = subprocess.run([str(program)], env=environment, text=True,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 99,
                                 name + ' must refuse with the package sentinel status: ' + result.stderr)
                self.assertEqual(trace.read_text().splitlines()[-1], name,
                                 'Forbidden execution must leave a real invocation record')

    @unittest.skipIf(os.name == 'nt', 'Guest lifecycle helpers require POSIX Bash')
    def test_lifecycle_helper_refusals_have_real_exit_statuses(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'bin').mkdir()
            for name, scene, arguments, expected in [
                    ('omarchy-snapshot', 'snapshot-unsupported', [], 127),
                    ('omarchy-system', 'reboot-failure', [], 7),
                    ('omarchy-update-requires-free-space', 'preflight-failure', [], 7),
                    ('omarchy-update-confirm', 'confirmation-failure', [], 2),
                    ('omarchy-update-dev', 'development-failure', [], 7),
                    ('omarchy-update-stay-awake', 'inhibitor-start-failure', ['start'], 7),
                    ('omarchy-update-stay-awake', 'inhibitor-stop-failure', ['stop'], 7)]:
                program = root / 'bin' / name
                program.write_text(helper)
                result = subprocess.run([BASH, str(program), *arguments],
                    env=dict(os.environ, OMARCHY_PATH=str(root), OMARCHY_FIXTURE_SCENE=scene,
                             OMARCHY_FIXTURE_CASE='inert-lifecycle-control',
                             OMARCHY_HELPER_TRACE=str(root / 'helpers.tsv')),
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_inert_omarchy_helpers_record_arguments_and_reject_external_aur(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'bin').mkdir()
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-success',
                       OMARCHY_HELPER_TRACE=str(trace), OMARCHY_PATH=str(root))
            for name, args, source, status in (
                    ('omarchy-update-dev', [], helper, 0),
                    ('omarchy-shell', ['-q', 'omarchy.system-update', 'clear'], helper, 0),
                    ('yay', ['-Sua'], helper, 99)):
                path = root / 'bin' / name
                path.write_text(source)
                result = subprocess.run([BASH, str(path), *args], env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, status, result.stderr)
            self.assertEqual(trace.read_text().splitlines(), [
                'omarchy-update-dev', 'omarchy-shell\t-q\tomarchy.system-update\tclear',
                'yay\t-Sua'])

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_inert_omarchy_helper_rejects_mismatched_runtime_before_trace(self):
        script = PRODUCER.omarchy_guest_script()
        helper = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            checkout = root / 'checkout'
            (checkout / 'bin').mkdir(parents=True)
            other = root / 'other-checkout'
            other.mkdir()
            path = checkout / 'bin/omarchy-update-dev'
            path.write_text(helper)
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-success',
                       OMARCHY_HELPER_TRACE=str(trace), OMARCHY_PATH=str(checkout))
            accepted = subprocess.run([BASH, str(path)], env=env, text=True, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(trace.read_text(), 'omarchy-update-dev\n')
            trace.unlink()
            env['OMARCHY_PATH'] = str(other)
            refused = subprocess.run([BASH, str(path)], env=env, text=True, capture_output=True)
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertIn('OMARCHY_PATH does not match this Omarchy command.', refused.stderr)
            self.assertFalse(trace.exists(), 'Rejected runtime must not execute a stage')

    @unittest.skipIf(os.name == 'nt', 'Inert guest helper scripts require POSIX Bash')
    def test_foreign_optional_helper_marks_execution_before_source_guard(self):
        script = PRODUCER.omarchy_guest_script()
        stage = script.split("<<'OMG_INERT_OMARCHY_STAGE'\n", 1)[1].split('\nOMG_INERT_OMARCHY_STAGE', 1)[0]
        prefix = script.split("<<'OMG_FOREIGN_OMARCHY_STAGE_PREFIX'\n", 1)[1].split(
            '\nOMG_FOREIGN_OMARCHY_STAGE_PREFIX', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'installed').mkdir()
            (root / 'foreign/bin').mkdir(parents=True)
            helper = root / 'foreign/bin/omarchy-snapshot'
            helper.write_text(prefix + '\n' + stage.split('\n', 1)[1])
            trace = root / 'helpers.tsv'
            env = dict(os.environ, OMARCHY_FIXTURE_CASE='omarchy-optional-failures',
                       OMARCHY_HELPER_TRACE=str(trace), OMARCHY_PATH=str(root / 'installed'))
            result = subprocess.run([BASH, str(helper), 'create'], env=env,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('OMARCHY_PATH does not match this Omarchy command.', result.stderr)
            self.assertEqual(Path(str(trace) + '.unexpected').read_text(),
                             'foreign helper executed: ' + str(helper) + '\n')
            self.assertFalse(trace.exists(), 'Foreign helper must fail before normal stage trace')

    @unittest.skipIf(os.name == 'nt', 'Native sync archive fixture requires POSIX tar')
    def test_omarchy_fixture_database_uses_supported_compression(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = PRODUCER.fixture_package(Path(directory), 'fixture', '1-1',
                                               'usr/share/fixture/value', b'data')
            with tarfile.open(archive, 'r:gz') as package:
                self.assertEqual(package.extractfile('usr/share/fixture/value').read(), b'data')


    def test_generated_guest_program_is_one_valid_bash_program(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        result = subprocess.run([BASH, '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('unshare --mount --net --fork', script)
        self.assertIn('test "$(id -u)" -ne 0', script)
        self.assertIn('test "$(id -u)" = 0', script)
        self.assertNotIn('systemd-detect-virt', script)


def fresh_admission_receipt():
    rows = []
    for case in PRODUCER.FRESH_ADMISSION_CASES:
        prompt = case.interaction not in ('none', 'noninteractive')
        fetched = case.interaction == 'accept' or case.name.startswith('repository-')
        before = {'installed-1-1/desc': 'd' * 64}
        after = dict(before)
        payload = {'usr/share/installed.txt': 'e' * 64}
        changed = dict(payload)
        if case.commits:
            if case.name.startswith('repository-'):
                after['omg-coverage-app-3-1/desc'] = 'f' * 64
                changed['usr/share/omg-coverage/omg-coverage-app.txt'] = hashlib.sha256(
                    b'omg-coverage-app: upgraded3\n').hexdigest()
            else:
                after['omg-fresh-archive-1-1/desc'] = 'f' * 64
                changed['usr/share/omg-fresh-archive.txt'] = hashlib.sha256(b'approved inert archive\n').hexdigest()
        rows.append(dict(name=case.name, expected_commit=case.commits, status='PASS',
            exit_code=0 if case.commits else 1, stopped_signal=None, transaction_lock_remains=False,
            prompt_seen=prompt, foreground_moved=case.interaction == 'foreground-loss',
            elapsed_seconds=60 if case.interaction == 'timeout' else 1,
            output=('Arch advisory applicability is UNKNOWN\n' if prompt else '') + case.diagnostic,
            requests=[dict(path='/v1/arch/advisories', prompt_seen=prompt)] if fetched else [],
            server_errors=[], database_before=before, database_after=after,
            payload_before=payload, payload_after=changed))
    return dict(status='PASS', cli_sha256='a' * 64, cases=rows,
        selected=[row['name'] for row in rows], complete_matrix=True,
        profile_stages=['fresh-' + row['name'] for row in rows],
        real_guest_database_unchanged=True, coverage_acceptance=False)


def evidence_fixture(root):
    evidence, profiles = root / 'evidence', root / 'profiles'
    evidence.mkdir()
    profiles.mkdir()
    artifacts = {role: dict(path='/build/' + role, sha256='a' * 64, bytes=16)
                 for role in PRODUCER.ROLES}
    (evidence / 'all-stages-pass.txt').write_text('PASS\n')
    (evidence / 'fresh-admission.json').write_text(json.dumps(fresh_admission_receipt()))
    rows = ['\t'.join(row) for row in PRODUCER.CASES]
    (evidence / 'expected-tests.tsv').write_text('\n'.join(rows) + '\n')
    (evidence / 'passed.tsv').write_text('\n'.join(row + '\tPASS' for row in rows) + '\n')
    (evidence / 'process-checks.tsv').write_text('\n'.join(stage + '\t0' for stage in PRODUCER.PROCESS_STAGES) + '\n')
    for name in ('db-before.txt', 'db-after.txt'):
        (evidence / name).write_text('unchanged private guest DB\n')
    (evidence / 'identity.txt').write_text('actual_id=arch ordinary_uid=65534 root_uid=0\n')
    (evidence / 'cli-elevation-denied-exit.txt').write_text('1\n')
    (evidence / 'cli-elevation-denied-identity.txt').write_text(
        'actual_uid=65534 operation=clean-cache authentication=denied\n')
    (evidence / 'cli-elevation-denied.log').write_text(
        'Privilege elevation failed (--yes flag prevents password prompt)\n')
    (evidence / 'cli-authorization-denied-exit.txt').write_text('1\n')
    (evidence / 'cli-authorization-denied-identity.txt').write_text(
        'actual_uid=65534 operation=clean-cache authorization=denied\n')
    (evidence / 'cli-authorization-denied.log').write_text(
        "nobody is not allowed to execute '/omg-extra-bin/cli __omg_elevated clean --cache --yes' as root\n")
    (evidence / 'cli-fresh-mock-refused-exit.txt').write_text('1\n')
    (evidence / 'cli-fresh-mock-refused-identity.txt').write_text(
        'actual_uid=65534 test_mode=1 backend=mock fresh_snapshot=refused mock_state_created=no\n')
    (evidence / 'cli-fresh-mock-refused.log').write_text(
        '[fresh-mock-refusal] uid=65534 test_mode=1\n'
        'FreshSnapshot requires the private native prepared admission owner\n')
    (evidence / 'artifacts.sha256').write_text(''.join(
        f"{a['sha256']}  /omg-extra-bin/{r}\n" for r, a in artifacts.items()))
    for role in PRODUCER.ROLES:
        (evidence / f'abi-{role}.txt').write_text('all dependencies present\n')
    for role, harness in PRODUCER.HARNESSES.items():
        names = harness.tests
        (evidence / f'registry-{role}.txt').write_text(''.join(name + ': test\n' for name in names))
    for stage in PRODUCER.STAGES:
        (profiles / f'omg-extra-{stage}-123-100_0.profraw').write_bytes(bytes.fromhex('8172666f72706cff') + b'fixture')
    (profiles / 'omg-extra-native-preflight-isolation-124-100_0.profraw').write_bytes(
        bytes.fromhex('8172666f72706cff') + b'fixture')
    (evidence / 'native-preflight-isolation.log').write_text(
        '[native-preflight-isolation] uid=65534 test_mode=absent\n'
        'test result: ok. 1 passed; 0 failed; 0 ignored;\n')
    for stage, role, name in PRODUCER.CASES:
        log = f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
        if role in ('cli-unit', 'lib-unit'):
            log += '[extra-root-test] uid=0\n'
            if role == 'lib-unit':
                log += (f"[omg-unprivileged-fixture] test={name} parent_uid=0 executable_sha256={artifacts[role]['sha256']}\n"
                        f"[omg-unprivileged-fixture-child] test={name} uid=65534 executable_sha256={artifacts[role]['sha256']}\n"
                        f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n')
                (profiles / f'omg-extra-{stage}-124-100_0.profraw').write_bytes(bytes.fromhex('8172666f72706cff') + b'fixture')
        elif role == 'coverage11':
            log += '[native-machine-identity] uid=65534 system_source_bytes=0 test_mode=absent\n'
            (evidence / f'{stage}-identity.json').write_text(json.dumps(dict(
                status='PASS_NATIVE_MACHINE_IDENTITY_FALLBACK', uid=65534, gid=65534,
                file_mode=0o600, directory_mode=0o700, persisted_bytes=36, uuid_version=4,
                persisted_sha256='a' * 64, original_source_sha256='b' * 64,
                system_source_restored=True)))
        else:
            log += '[native-arch-fixture] uid=65534 actual_id=arch\n'
            (profiles / f'omg-extra-{stage}-124-200_0.profraw').write_bytes(bytes.fromhex('8172666f72706cff') + b'fixture')
        if role == 'comprehensive':
            log += '[native-inventory-coverage] unavailable_rows=0;\n'
        (evidence / f'{stage}.log').write_text(log)
    (evidence / 'inventory').mkdir()
    (evidence / 'inventory/index.tsv').write_text('header\n' + ''.join(
        f'{name}\tcli\targs\t0\t0\tnone\tavailable\n'
        for name in ('why', 'why-reverse', 'size', 'size-tree', 'blame')))
    (evidence / 'daemon.log').write_text('[extra-daemon] startup_socket=ready uid=65534\n'
                                       '[extra-daemon] sigterm_exit=0 socket_removed=yes\n')
    for stage, case in PRODUCER.OMARCHY_CASES.items():
        status, helpers = case.exit_status, case.helpers
        (evidence / f'{stage}-exit.txt').write_text(f'{status}\n')
        (evidence / f'{stage}-helpers.tsv').write_text(''.join(row + '\n' for row in helpers))
        if helpers:
            (evidence / f'{stage}-coordination.txt').write_text(
                'released private lock; owned transcript mode=600\n')
            (evidence / f'{stage}-transcript.log').write_text('OMG Omarchy update started\nOMG Omarchy update finished: exit status: 0\n')
        (evidence / f'{stage}-native-state.json').write_text(json.dumps(dict(status=PRODUCER.NATIVE_PHASES[case.native_phase])))
        if case.scene in ('migration-inventory-error', 'migration-directory-untrusted'):
            (evidence / f'{stage}-migrations.txt').write_text(f'boundary_control={case.scene} completion_markers=0\n')
        elif stage == 'omarchy-native-migrations-script-failure':
            (evidence / f'{stage}-migrations.txt').write_text('failed_configuration=before completion_markers=0\n')
        elif stage.startswith('omarchy-native-migrations'):
            (evidence / f'{stage}-migrations.txt').write_text(
                'ordered_configuration=before,after recognized_native_migrations=2 completion_markers=4\n')
        if stage == 'omarchy-current-kernel':
            path = 'usr/lib/modules/fixture/modules.builtin'
            (evidence / f'{stage}-native-state.json').write_text(json.dumps(dict(
                status=PRODUCER.NATIVE_PHASES[case.native_phase],
                running_kernel_modules=dict(path=path, sha256='a' * 64),
                packages={'omg-coverage-kernel': dict(payload_path=path)})))
        if case.control:
            (evidence / f'{stage}-control.json').write_text(json.dumps(dict(
                mode=case.control, ready_observed=True, cli_exit_code=1, unrelated_pid=600,
                unrelated_survived=True, owned_processes_gone=True,
                owned_processes=[dict(pid=700, start='1000', group=700, uid=65534),
                                 dict(pid=701, start='1001', group=700, uid=65534)])))
            if case.control == 'terminal-closed':
                (evidence / f'{stage}-transcript.log').write_text(
                    'OMG Omarchy update started\nError: Omarchy update interrupted\n'
                    'OMG Omarchy update finished: exit status: 1\n')
        if case.lock_location == 'foreign':
            (evidence / f'{stage}-layout.txt').write_text(
                'foreign fallback lock was preserved; transcript unchanged\n')
        if case.authorization:
            authorization_log = evidence / f'{stage}-authorization.log'
            authorization_log.write_text(
                'Nov 13 23:59:30 : nobody : USER=root ;\n    COMMAND=/usr/bin/true\n'
                + 'Nov 14 00:00:30 : nobody : '
                + ('command not allowed ; ' if case.authorization == 'denied' else '')
                + 'USER=root ;\n    COMMAND=/usr/bin/true\n')
            (evidence / f'{stage}-authorization.json').write_text(json.dumps(dict(
                initial_authorizations=1, refresh_count=1, refresh_after_seconds=60,
                denied=case.authorization == 'denied', log_uid=0,
                log_sha256=PRODUCER.sha(authorization_log))))
        if case.reboot_answer:
            (evidence / f'{stage}-interaction.json').write_text(json.dumps(dict(
                prompt_observed=True, answer=case.reboot_answer, resize_sent=1,
                cli_exit_code=case.exit_status)))
        if case.native_phase not in ('initial', 'cache-pruned') and not case.control:
            (evidence / f'{stage}-unknown.json').write_text(json.dumps(dict(
                reviews=['a' * 64], cli_exit_code=case.exit_status)))
        if case.absent_helper:
            (evidence / f'{stage}-layout.txt').write_text(
                'absent helper restored after genuine CLI execution\n')
        if stage == 'omarchy-optional-failures':
            (evidence / f'{stage}-layout.txt').write_text(
                'foreign optional helpers never executed; original helpers restored\n')
        log = {
            'omarchy-success': '| System is up to date',
            'omarchy-native-migrations': '| System is up to date\nNative Omarchy migration-xrandr completed\nNative Omarchy migration-omnibook-audio completed',
            'omarchy-native-migrations-unmatched': '| System is up to date\nNative Omarchy migration-xrandr completed',
            'omarchy-native-migrations-notification-error': '| System is up to date\nNative Omarchy migration-xrandr completed\nNative Omarchy migration-omnibook-audio completed\nCannot dismiss the Omarchy migration notification:',
            'omarchy-native-migrations-notification-missing': '| System is up to date\nNative Omarchy migration-xrandr completed\nNative Omarchy migration-omnibook-audio completed',
            'omarchy-native-migrations-installed-audio': '| System is up to date\nNative Omarchy migration-xrandr completed',
            'omarchy-native-migrations-script-failure': '0000000000.sh failed: exit status: 7',
            'omarchy-native-migrations-inventory-error': 'Cannot inspect pending Omarchy migrations',
            'omarchy-native-migrations-directory-untrusted': 'Selected Omarchy runtime directory is not root-controlled',
            'omarchy-current-kernel': '| System is up to date',
            'omarchy-runtime-unset': 'caller_runtime_hint=unset\n| System is up to date',
            'omarchy-interrupted': 'Omarchy update interrupted',
            'omarchy-output-closed': 'Update output disconnected',
            'omarchy-runtime-fallback': '| System is up to date',
            'omarchy-runtime-foreign-lock': 'Omarchy coordination file must be single-link',
            'omarchy-authorization-refresh': '| System is up to date',
            'omarchy-authorization-denied': '| System is up to date\nOmarchy update authorization refresh stopped',
            'omarchy-reboot-decline': '| System is up to date\nReboot now?',
            'omarchy-reboot-accept': '| System is up to date\nReboot now?',
            'omarchy-reboot-failure': '| System is up to date\nReboot now?\nOmarchy reboot failed',
            'omarchy-reboot-helper-missing': '| System is up to date\nReboot now?\nNo root-controlled system executable found for omarchy-system',
            'omarchy-snapshot-missing': '| System is up to date',
            'omarchy-snapshot-unsupported': '| System is up to date',
            'omarchy-required-helper-missing': 'Omarchy update did not complete: omarchy-update-dev',
            'omarchy-optional-failures': '| System is up to date\n! Continuing without a snapshot\n! Some mise tools could not be updated',
            'omarchy-vendor-failure': 'Omarchy update did not complete',
            'omarchy-declined': 'declined',
            'omarchy-migration-refusal': 'external package helper',
            'omarchy-migration-helper-tabs': 'external package helper',
            'omarchy-migration-helper-quoted': 'external package helper',
            'omarchy-migration-helper-bare': 'external package helper',
            'omarchy-migration-helper-substitution': 'external package helper',
            'omarchy-unsupported-mode': 'complete update lifecycle',
            'omarchy-unsupported-turbo-mode': 'complete update lifecycle',
            'omarchy-invalid-transport': 'Incomplete Omarchy update transport',
        }.get(stage, '')
        if case.failure_command:
            log = f'Omarchy stage {case.failure_command} did not complete: exit status: {case.failure_status}'
            if case.native_phase == 'complete':
                log += '\nSystem is up to date\nOmarchy cleanup failed'
        if case.native_phase not in ('initial', 'cache-pruned') and not case.control:
            log += '\n' + UnknownFixtureTerminal.prompt().decode()
        (evidence / f'{stage}.log').write_text(log)
    for stage in PRODUCER.ARCH_READONLY_STAGES:
        (evidence / f'{stage}.log').write_text('System is up to date\n')
        (evidence / f'{stage}-isolation.txt').write_text(
            'actual_id=arch ordinary_uid=65534 vendor_helpers=0 transcript_unchanged=yes\n')
        (evidence / f'{stage}-native-state.json').write_text(json.dumps(dict(status='PASS_SIGNED_NATIVE_STATE')))
    return evidence, profiles, artifacts


class SupplementalEvidence(unittest.TestCase):
    def test_native_unknown_decisions_require_nonempty_exact_prompt_fingerprints(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            path = evidence / 'omarchy-success-unknown.json'
            original = path.read_text()
            for receipt in [dict(reviews=[], cli_exit_code=0),
                            dict(reviews=['b' * 64], cli_exit_code=0),
                            dict(reviews=['a' * 64], cli_exit_code=1),
                            dict(reviews=['a' * 64], cli_exit_code=0, ignored=True)]:
                path.write_text(json.dumps(receipt))
                with self.subTest(receipt=receipt), self.assertRaisesRegex(ValueError, 'Unknown decisions'):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            path.write_text(original)
            log = evidence / 'omarchy-success.log'
            log.write_text('System is up to date\n')
            with self.assertRaisesRegex(ValueError, 'Unknown decisions'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_debug_backend_cannot_claim_fresh_native_admission(self):
        stage = 'cli-fresh-mock-refused'
        self.assertIn(stage, PRODUCER.PROCESS_STAGES,
                      'Fresh admission must also refuse the debug backend through the real CLI')
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            mutations = {
                f'{stage}-exit.txt': '0\n',
                f'{stage}-identity.txt': 'actual_uid=0 test_mode=1 backend=mock fresh_snapshot=refused mock_state_created=no\n',
                f'{stage}.log': 'Failed to query advisory provider\n',
            }
            for name, value in mutations.items():
                path = evidence / name
                original = path.read_text()
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'fresh mock'):
                    path.write_text(value)
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                path.write_text(original)

    def test_public_machine_identity_fallback_requires_native_private_persistence(self):
        self.assertIn('coverage11', PRODUCER.HARNESSES,
                      'The public machine identity consumer must exercise the native fallback')
        self.assertEqual(PRODUCER.HARNESSES['coverage11'].tests,
                         ('machine_id_is_stable_sixteen_lowercase_hex',))
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            stage = next(stage for stage, role, _ in PRODUCER.CASES if role == 'coverage11')
            path = evidence / f'{stage}-identity.json'
            original = json.loads(path.read_text())
            for key, value in [('uid', 0), ('file_mode', 0o644), ('directory_mode', 0o755),
                               ('system_source_restored', False), ('persisted_bytes', 0)]:
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'machine identity'):
                    path.write_text(json.dumps(dict(original, **{key: value})))
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            path.write_text(json.dumps(original))
            log = evidence / f'{stage}.log'
            log.write_text(log.read_text().replace('system_source_bytes=0', 'system_source_bytes=33'))
            with self.assertRaisesRegex(ValueError, 'machine identity'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_root_policy_ui_fixture_requires_an_unprivileged_child_witness(self):
        role = 'lib-unit'
        name = 'cli::tui::ui::tests::security_tab_tracks_configured_policy_and_reports_invalid_policy'
        self.assertIn(role, PRODUCER.HARNESSES,
                      'Native coverage must verify the policy fixture from an actual root harness')
        self.assertIn(name, PRODUCER.HARNESSES[role].tests)
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            stage = next(stage for stage, selected_role, test in PRODUCER.CASES
                         if selected_role == role and test == name)
            path = evidence / f'{stage}.log'
            original = path.read_text()
            mutations = {
                'missing-child': original.replace('[omg-unprivileged-fixture-child]', '[missing-child]'),
                'root-child': original.replace('uid=65534 executable_sha256=', 'uid=0 executable_sha256='),
                'wrong-artifact': original.replace('executable_sha256=' + 'a' * 64,
                                                   'executable_sha256=' + 'c' * 64),
                'missing-parent': original.replace('parent_uid=0', 'parent_uid=65534'),
                'extra-execution': original + 'test result: ok. 1 passed; 0 failed; 0 ignored;\n',
            }
            for mutation, value in mutations.items():
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    path.write_text(value)
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            path.write_text(original)
            next(profiles.glob(f'omg-extra-{stage}-124-*.profraw')).unlink()
            with self.assertRaisesRegex(ValueError, 'child profiles'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_turbo_scope_refusal_has_its_own_native_case_and_diagnostic(self):
        stage = 'omarchy-unsupported-turbo-mode'
        self.assertIn(stage, PRODUCER.OMARCHY_CASES,
                      'Turbo must independently refuse an incomplete Omarchy update')
        case = PRODUCER.OMARCHY_CASES[stage]
        self.assertEqual(case.exit_status, 1)
        self.assertEqual(case.helpers, ())
        self.assertIn(stage + ') args=(--turbo)', PRODUCER.omarchy_guest_script())
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            (evidence / f'{stage}.log').write_text('unrelated refusal\n')
            with self.assertRaisesRegex(ValueError, 'Unsupported Omarchy scope'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_elevation_refusal_requires_identity_exit_diagnostic_and_cli_profiles(self):
        stage = 'cli-elevation-denied'
        self.assertIn(stage, PRODUCER.PROCESS_STAGES,
                      'Native coverage must exercise a genuine denied CLI elevation')
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            changes = {
                f'{stage}-exit.txt': '0\n',
                f'{stage}-identity.txt': 'actual_uid=0 operation=clean-cache authorization=denied\n',
                f'{stage}.log': 'unrelated command failed\n',
            }
            for name, value in changes.items():
                path = evidence / name
                original = path.read_text()
                path.write_text(value)
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'elevation'):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                path.write_text(original)
            original = next(profiles.glob(f'omg-extra-{stage}-*.profraw'))
            original.rename(profiles / f'omg-extra-{stage}-123-999_0.profraw')
            with self.assertRaisesRegex(ValueError, 'elevation'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_payload_authorization_refusal_is_distinct_from_authentication(self):
        stage = 'cli-authorization-denied'
        self.assertIn(stage, PRODUCER.PROCESS_STAGES,
                      'Credential validation cannot substitute for command authorization')
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            path = evidence / f'{stage}.log'
            path.write_text('Privilege elevation failed (--yes flag prevents password prompt)\n')
            with self.assertRaisesRegex(ValueError, 'authorization'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_unset_runtime_hint_completes_native_update_and_requires_a_witness(self):
        stage = 'omarchy-runtime-unset'
        self.assertIn(stage, PRODUCER.OMARCHY_CASES,
                      'Native updates must also exercise trusted discovery without OMARCHY_PATH')
        case = PRODUCER.OMARCHY_CASES[stage]
        self.assertEqual((case.exit_status, case.native_phase), (0, 'complete'))
        self.assertEqual(case.helpers, PRODUCER.OMARCHY_PREFIX + PRODUCER.OMARCHY_SUFFIX)
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            log = evidence / f'{stage}.log'
            log.write_text('System is up to date\n' + UnknownFixtureTerminal.prompt().decode())
            with self.assertRaisesRegex(ValueError, 'runtime hint'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    @unittest.skipIf(os.name == 'nt', 'Native caller environment requires POSIX Bash')
    def test_native_runtime_environment_preserves_and_omits_the_hint_by_case(self):
        self.assertIn('omarchy-runtime-unset', PRODUCER.OMARCHY_CASES,
                      'Missing native unset-hint scenario')
        script = PRODUCER.omarchy_guest_script()
        start = script.index('  omarchy_environment=(')
        end = script.index('  runtime_environment=(', start)
        environment_setup = script[start:end]
        with tempfile.TemporaryDirectory() as directory:
            for stage, expected in [('omarchy-success', str(Path(directory) / 'checkout')),
                                    ('omarchy-runtime-unset', None)]:
                with self.subTest(stage=stage):
                    command = environment_setup + '\nenv -i "${omarchy_environment[@]}" ' + shlex.quote(sys.executable)
                    command += ' -c ' + shlex.quote('import json,os;print(json.dumps(os.environ.get("OMARCHY_PATH")))')
                    result = subprocess.run([BASH, '-euo', 'pipefail', '-c', command],
                                            env=dict(os.environ, stage=stage, case_dir=directory),
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout), expected)

    def test_current_kernel_requires_ownership_evidence_and_no_reboot_reason(self):
        self.assertTrue('omarchy-current-kernel' in PRODUCER.OMARCHY_CASES, 'Missing current-kernel update scenario')
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            state = evidence / 'omarchy-current-kernel-native-state.json'
            original = state.read_text()
            value = json.loads(original)
            value.pop('running_kernel_modules')
            state.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'Current kernel'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            value = json.loads(original)
            path = 'usr/lib/modules/../modules.builtin'
            value['running_kernel_modules']['path'] = path
            value['packages']['omg-coverage-kernel']['payload_path'] = path
            state.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'Current kernel'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            state.write_text(original)
            (evidence / 'omarchy-current-kernel.log').write_text(
                'System is up to date\nRun omarchy-system reboot when ready.\n'
                + UnknownFixtureTerminal.prompt().decode())
            with self.assertRaisesRegex(ValueError, 'Current kernel'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_missing_reboot_helper_requires_the_actual_refusal_diagnostic(self):
        self.assertIn('omarchy-reboot-helper-missing', PRODUCER.OMARCHY_CASES)
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            (evidence / 'omarchy-reboot-helper-missing.log').write_text(
                'System is up to date\nReboot now?\n' + UnknownFixtureTerminal.prompt().decode())
            with self.assertRaisesRegex(ValueError, 'Missing reboot helper'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_authorization_audit_requires_initial_success_and_one_real_interval(self):
        initial = 'Nov 13 23:59:30 : nobody : USER=root ;\n    COMMAND=/usr/bin/true\n'
        refresh = 'Nov 14 00:00:30 : nobody : USER=root ;\n    COMMAND=/usr/bin/true\n'
        observation = PRODUCER.authorization_audit(initial + refresh)
        self.assertEqual(observation, dict(initial_authorizations=1, refresh_count=1,
                                          refresh_after_seconds=60, denied=False))
        denied = ('Nov 14 00:00:30 : nobody : command not allowed ; PWD=/home/bench ;\n'
                  '    USER=root ; COMMAND=/usr/bin/true\n')
        self.assertEqual(PRODUCER.authorization_audit(initial + denied),
                         dict(initial_authorizations=1, refresh_count=1,
                              refresh_after_seconds=60, denied=True))
        for text in (initial, initial + refresh + refresh,
                     initial + refresh.replace('/usr/bin/true', '/usr/bin/true-extra'),
                     initial + refresh.replace('00:00:30', '23:59:31'),
                     initial.replace('nobody', 'root') + refresh,
                     initial.replace('USER=root', 'USER=nobody') + refresh,
                     initial.replace('USER=root', 'command not allowed ; USER=root') + refresh):
            with self.subTest(text=text), self.assertRaises(ValueError):
                PRODUCER.authorization_audit(text)

    def test_complete_observed_selection_and_processes_have_a_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            files = PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            receipt = json.loads((evidence / 'verification.json').read_text())
            self.assertEqual(len(receipt['tests']), 22)
            self.assertEqual(len(receipt['process_checks']), 72)
            self.assertEqual(len(receipt['fresh_admission']), 20)
            self.assertEqual(len(files), len(receipt['profiles']))

    def test_forged_omarchy_helper_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            (evidence / 'omarchy-success-helpers.tsv').write_text('yay\t-Sua\n')
            with self.assertRaises(ValueError):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            self.assertFalse((evidence / 'verification.json').exists())

    def test_incomplete_or_misleading_guest_evidence_is_refused(self):
        mutations = {
            'missing-stage': lambda e, p: (p / 'omg-extra-daemon-123-100_0.profraw').unlink(),
            'missing-child': lambda e, p: (p / 'omg-extra-test-01-123-100_0.profraw').unlink(),
            'bad-raw-magic': lambda e, p: (p / 'omg-extra-daemon-123-100_0.profraw').write_bytes(b'wrong'),
            'empty-profile': lambda e, p: (p / 'omg-extra-daemon-123-100_0.profraw').write_bytes(b''),
            'skip-marker': lambda e, p: (e / 'test-01.log').write_text((e / 'test-01.log').read_text() + '[omg-skip]\n'),
            'zero-tests': lambda e, p: (e / 'test-01.log').write_text('test result: ok. 0 passed; 0 failed; 0 ignored;\n'),
            'changed-db': lambda e, p: (e / 'db-after.txt').write_text('changed'),
            'no-daemon-cleanup': lambda e, p: (e / 'daemon.log').write_text('[extra-daemon] startup_socket=ready uid=65534'),
            'duplicate-result': lambda e, p: (e / 'passed.tsv').write_text((e / 'passed.tsv').read_text() * 2),
            'missing-process': lambda e, p: (e / 'process-checks.tsv').write_text('cli-q\t0\n'),
            'fresh-missing-receipt': lambda e, p: (e / 'fresh-admission.json').unlink(),
            'fresh-incomplete-receipt': lambda e, p: (e / 'fresh-admission.json').write_text('{}'),
            'native-preflight-not-executed': lambda e, p: (e / 'native-preflight-isolation.log').write_text(
                '[native-preflight-isolation] uid=65534 test_mode=absent\n'
                'test result: ok. 0 passed; 0 failed; 1 ignored;\n'),
            'native-preflight-no-worker': lambda e, p: (p / 'omg-extra-native-preflight-isolation-124-100_0.profraw').unlink(),
            'fresh-wrong-cli-profile': lambda e, p: (p / 'omg-extra-fresh-archive-accept-123-100_0.profraw').rename(
                p / 'omg-extra-fresh-archive-accept-123-200_0.profraw'),
            'wrong-artifact': lambda e, p: (e / 'artifacts.sha256').write_text('different'),
            'llvm-warning': lambda e, p: (e / 'cli-q.log').write_text('LLVM Profile Warning: write failed'),
            'omarchy-failed-status': lambda e, p: (e / 'omarchy-success-exit.txt').write_text('1\n'),
            'omarchy-skipped-aur': lambda e, p: (e / 'omarchy-success.log').write_text('only vendor commands ran'),
            'omarchy-false-transcript': lambda e, p: (e / 'omarchy-success-transcript.log').write_text('fake output'),
            'omarchy-no-update-result': lambda e, p: (e / 'omarchy-success.log').write_text('No update result was emitted'),
            'omarchy-foreign-helper-executed': lambda e, p: (e / 'omarchy-optional-failures-layout.txt').write_text('foreign helper executed'),
            'omarchy-hidden-optional-warnings': lambda e, p: (e / 'omarchy-optional-failures.log').write_text('| System is up to date'),
            'omarchy-old-logger': lambda e, p: (e / 'omarchy-success-transcript.log').write_text('Script started on fixture\nScript done on fixture\n'),
            'omarchy-no-cleanup': lambda e, p: (e / 'omarchy-success-coordination.txt').write_text('lock still held'),
            'omarchy-no-refusal': lambda e, p: (e / 'omarchy-migration-refusal.log').write_text('failed for another reason'),
            'cancelled-but-stage-survived': lambda e, p: (e / 'omarchy-interrupted-control.json').write_text('{}'),
            'normal-arch-crossed-vendor-boundary': lambda e, p: (e / 'arch-check-isolation.txt').write_text('vendor_helpers=1'),
            'normal-arch-mutated-packages': lambda e, p: (e / 'arch-dry-run-native-state.json').write_text('{"status":"PASS_NATIVE_INITIAL_STATE"}'),
            'normal-arch-used-vendor-runtime': lambda e, p: (e / 'arch-check.log').write_text('System is up to date\nOmarchy runtime selected'),
            'cancelled-before-package-state-check': lambda e, p: (e / 'omarchy-interrupted-native-state.json').write_text('{"status":"PASS_SIGNED_NATIVE_STATE"}'),
            'foreign-fallback-was-overwritten': lambda e, p: (e / 'omarchy-runtime-foreign-lock-layout.txt').write_text('overwritten'),
            'foreign-fallback-no-ownership-diagnostic': lambda e, p: (e / 'omarchy-runtime-foreign-lock.log').write_text('failed for another reason'),
            'no-real-authorization-refresh': lambda e, p: (e / 'omarchy-authorization-refresh-authorization.json').write_text('{}'),
            'authorization-log-changed': lambda e, p: (e / 'omarchy-authorization-refresh-authorization.log').write_text('different'),
            'authorization-refusal-hidden': lambda e, p: (e / 'omarchy-authorization-denied.log').write_text('System is up to date'),
            'no-attended-reboot-prompt': lambda e, p: (e / 'omarchy-reboot-accept-interaction.json').write_text('{}'),
            'reboot-failure-hidden': lambda e, p: (e / 'omarchy-reboot-failure.log').write_text('System is up to date\nReboot now?'),
            'missing-helper-not-restored': lambda e, p: (e / 'omarchy-snapshot-missing-layout.txt').write_text('still absent'),
            'unsupported-snapshot-skips-native': lambda e, p: (e / 'omarchy-snapshot-unsupported-native-state.json').write_text('{"status":"UNCOMMITTED"}'),
            'required-helper-false-success': lambda e, p: (e / 'omarchy-required-helper-missing-exit.txt').write_text('0\n'),
            'omarchy-wrong-cli': lambda e, p: (p / 'omg-extra-omarchy-success-123-100_0.profraw').rename(
                p / 'omg-extra-omarchy-success-123-200_0.profraw'),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                evidence, profiles, artifacts = evidence_fixture(Path(directory))
                mutate(evidence, profiles)
                with self.assertRaises(ValueError):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                self.assertFalse((evidence / 'verification.json').exists())


class ArtifactAdmission(unittest.TestCase):
    def make_target(self, root):
        deps = root / 'debug/deps'
        deps.mkdir(parents=True)
        paths = ['debug/omg', 'debug/omgd'] + [f'debug/deps/{prefix}-' + '1' * 16
                 for prefix in (harness.binary for harness in PRODUCER.HARNESSES.values())]
        for name in paths:
            path = root / name
            path.write_bytes(name.encode())
            path.chmod(0o755)
        os.link(root / 'debug/omg', deps / ('omg-' + '2' * 16))

    def test_every_registered_harness_is_required(self):
        for role, harness in PRODUCER.HARNESSES.items():
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_target(root)
                (root / 'debug/deps' / (harness.binary + '-' + '1' * 16)).unlink()
                with patch.object(PRODUCER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 0, '__llvm_covmap __llvm_prf_cnts')):
                    with self.assertRaisesRegex(ValueError, re.escape(role)):
                        PRODUCER.prepare(root, 'b' * 40)

    def test_cli_unit_selection_excludes_the_normal_cli_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_target(root)
            with patch.object(PRODUCER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, '__llvm_covmap __llvm_prf_cnts')):
                manifest = PRODUCER.prepare(root, 'b' * 40)
            self.assertEqual(manifest['artifacts']['cli-unit']['path'],
                             str(root / 'debug/deps' / ('omg-' + '1' * 16)))

    def test_stale_second_test_harness_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_target(root)
            extra = root / 'debug/deps' / ('omg-' + '3' * 16)
            extra.write_bytes(b'stale harness')
            extra.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'exactly one instrumented harness for cli-unit'):
                PRODUCER.prepare(root, 'b' * 40)

    def test_manifest_refuses_changed_producer_source_or_incomplete_artifacts(self):
        for scenario in ('complete', 'wrong-producer', 'wrong-unknown-driver', 'missing-artifact', 'invalid-commit', 'invalid-size'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.make_target(root)
                with patch.object(PRODUCER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                        [], 0, '__llvm_covmap __llvm_prf_cnts')):
                    manifest = PRODUCER.prepare(root, 'b' * 40)
                if scenario == 'wrong-producer':
                    manifest['producer_sha256'] = '0' * 64
                elif scenario == 'wrong-unknown-driver':
                    manifest['unknown_driver_sha256'] = '0' * 64
                elif scenario == 'missing-artifact':
                    del manifest['artifacts']['cli-unit']
                elif scenario == 'invalid-commit':
                    manifest['source_commit'] = 'main'
                elif scenario == 'invalid-size':
                    manifest['artifacts']['cli-unit']['bytes'] = False
                path = root / 'manifest.json'
                path.write_text(json.dumps(manifest))
                if scenario == 'complete':
                    self.assertEqual(PRODUCER.read_manifest(path), manifest)
                else:
                    with self.assertRaises(ValueError):
                        PRODUCER.read_manifest(path)


class FreshAdmissionFixture(unittest.TestCase):
    def test_native_migration_case_requires_package_and_completion_evidence(self):
        stage = 'omarchy-native-migrations'
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            receipt = evidence / f'{stage}-migrations.txt'
            receipt.write_text('ordered_configuration=before,after recognized_native_migrations=2 completion_markers=3\n')
            with self.assertRaisesRegex(ValueError, 'migration completion'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            receipt.write_text('ordered_configuration=before,after recognized_native_migrations=2 completion_markers=4\n')
            log = evidence / f'{stage}.log'
            log.write_text(log.read_text().replace('Native Omarchy migration-xrandr completed', ''))
            with self.assertRaisesRegex(ValueError, 'migration package operations'):
                PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)

    def test_native_migration_failure_cases_are_mandatory_and_cannot_forge_completion(self):
        required = {'omarchy-native-migrations-notification-error',
                    'omarchy-native-migrations-notification-missing',
                    'omarchy-native-migrations-script-failure',
                    'omarchy-native-migrations-installed-audio'}
        self.assertTrue(required <= PRODUCER.OMARCHY_CASES.keys())
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            for filename, original, replacement, diagnostic in (
                    ('omarchy-native-migrations-notification-error.log',
                     'Cannot dismiss the Omarchy migration notification:', '', 'notification'),
                    ('omarchy-native-migrations-script-failure-migrations.txt',
                     'completion_markers=0', 'completion_markers=1', 'completion marker'),
                    ('omarchy-native-migrations-installed-audio.log',
                     'Native Omarchy migration-xrandr completed',
                     'Native Omarchy migration-xrandr completed\nNative Omarchy migration-omnibook-audio completed',
                     'unnecessary package transaction')):
                path = evidence / filename
                contents = path.read_text()
                self.assertIn(original, contents)
                path.write_text(contents.replace(original, replacement))
                with self.assertRaisesRegex(ValueError, diagnostic):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                path.write_text(contents)

    def test_helper_spacing_refusals_are_mandatory_before_any_native_phase(self):
        cases = ('omarchy-migration-helper-tabs', 'omarchy-migration-helper-quoted',
                 'omarchy-migration-helper-bare', 'omarchy-migration-helper-substitution')
        for stage in cases:
            self.assertIn(stage, PRODUCER.OMARCHY_CASES)
            case = PRODUCER.OMARCHY_CASES[stage]
            self.assertEqual((case.exit_status, case.helpers, case.native_phase), (1, (), 'initial'))
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            for stage in cases:
                path = evidence / f'{stage}.log'
                old = path.read_text()
                path.write_text('an unrelated failure\n')
                with self.assertRaisesRegex(ValueError, 'native package migration refusal'):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                path.write_text(old)

    def test_native_migration_boundary_refusals_require_actual_control_and_no_markers(self):
        names = {'omarchy-native-migrations-inventory-error',
                 'omarchy-native-migrations-directory-untrusted'}
        self.assertTrue(names <= PRODUCER.OMARCHY_CASES.keys())
        for name in names:
            case = PRODUCER.OMARCHY_CASES[name]
            self.assertEqual(case.exit_status, 1)
            self.assertEqual(case.native_phase, 'repository-upgraded')
        with tempfile.TemporaryDirectory() as directory:
            evidence, profiles, artifacts = evidence_fixture(Path(directory))
            PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
            for name in names:
                path = evidence / f'{name}-migrations.txt'
                data = path.read_text()
                path.write_text(data.replace('completion_markers=0', 'completion_markers=1'))
                with self.assertRaisesRegex(ValueError, 'boundary'):
                    PRODUCER.validate_evidence(evidence, profiles, artifacts, 'b' * 40)
                path.write_text(data)

    def test_native_migrations_are_a_required_signed_full_update_case(self):
        case = PRODUCER.OMARCHY_CASES['omarchy-native-migrations']
        self.assertEqual(case.exit_status, 0)
        self.assertEqual(case.native_phase, 'migrated')
        self.assertNotIn('omarchy-migrate', case.helpers)
        self.assertIn('omarchy-hw-match\tOmniBook 3 Laptop', case.helpers)
        self.assertIn('omarchy-state\tset\treboot-required', case.helpers)
        script = PRODUCER.omarchy_guest_script()
        self.assertIn('--native-migrations', script)
        self.assertIn('1794518371.sh', script)
        self.assertIn('1794675791.sh', script)

    def test_daemon_scope_and_lifecycle_open_errors_are_mandatory_root_receivers(self):
        for name in (
                'cli::tea::status_model::tests::daemon_load_executes_status_request_and_preserves_reported_scope',
                'package_managers::aur::utils::tests::lifecycle_lock_initial_open_errors_preserve_path_and_io_cause'):
            self.assertIn(name, PRODUCER.HARNESSES['lib-unit'].tests)

    def test_native_remediation_dry_run_is_a_mandatory_ipc_fixture(self):
        name = 'native_audit_fix_dry_runs_preserve_unknown_scope_and_inert_advisory_text'
        self.assertIn(name, PRODUCER.HARNESSES['ipc'].tests)
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        self.assertIn('"$name" --exact --include-ignored --nocapture', script)

    def test_native_preflight_is_mandatory_even_when_ordinary_runs_ignore_it(self):
        name = 'cli::packages::install::arch::tests::native_fresh_snapshot_preflight_defers_evidence_but_enforces_source_policy'
        self.assertIn(name, PRODUCER.HARNESSES['lib-unit'].tests)
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        self.assertIn('"$name" --exact --include-ignored --nocapture', script)
        self.assertIn('native-preflight-isolation', PRODUCER.PROCESS_STAGES)

    def test_generated_guest_program_requires_all_native_admission_profiles(self):
        artifacts = {role: {'sha256': 'a' * 64} for role in PRODUCER.ROLES}
        script = PRODUCER.guest_script(artifacts, '/workspace/target/debug/omg')
        self.assertIn('fresh-admission-fixture --owner /opt/omg-coverage-fresh-ci', script)
        self.assertIn('--cli /omg-extra-bin/cli --profiles /profiles', script)
        for case in PRODUCER.FRESH_ADMISSION_CASES:
            self.assertIn('fresh-' + case.name, PRODUCER.PROCESS_STAGES)

    def test_native_admission_evidence_requires_matching_cli_and_complete_behavior(self):
        value = fresh_admission_receipt()
        PRODUCER.validate_fresh_admission(value, 'a' * 64)
        mutations = {
            'missing-case': lambda r: r['cases'].pop(),
            'reordered-case': lambda r: r['cases'].reverse(),
            'partial': lambda r: r.update(complete_matrix=False),
            'foreign-cli': lambda r: r.update(cli_sha256='b' * 64),
            'database-changed': lambda r: r.update(real_guest_database_unchanged=False),
            'missing-profile': lambda r: r['profile_stages'].pop(),
            'stopped': lambda r: r['cases'][7].update(stopped_signal=21),
            'held-lock': lambda r: r['cases'][7].update(transaction_lock_remains=True),
            'panic': lambda r: r['cases'][1].update(exit_code=101),
            'no-prompt': lambda r: r['cases'][0].update(prompt_seen=False),
            'wrong-refusal': lambda r: r['cases'][1].update(output='unrelated error'),
            'empty-database': lambda r: r['cases'][1].update(database_before={}, database_after={}),
            'refusal-mutated-payload': lambda r: r['cases'][1]['payload_after'].update(escape='c' * 64),
            'background-not-exercised': lambda r: r['cases'][7].update(foreground_moved=False),
            'short-timeout': lambda r: r['cases'][9].update(elapsed_seconds=1),
            'server-error': lambda r: r['cases'][0].update(server_errors=['failure']),
            'early-fetch': lambda r: r['cases'][0]['requests'][0].update(prompt_seen=False),
            'missing-fetch': lambda r: r['cases'][0].update(requests=[]),
            'wrong-committed-bytes': lambda r: r['cases'][0]['payload_after'].update(
                {'usr/share/omg-fresh-archive.txt': 'c' * 64}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = fresh_admission_receipt()
                mutate(value)
                with self.assertRaises(ValueError):
                    PRODUCER.validate_fresh_admission(value, 'a' * 64)

    def test_matrix_covers_attended_refusal_and_precommit_authority_changes(self):
        cases = PRODUCER.FRESH_ADMISSION_CASES
        by_name = {case.name: case for case in cases}
        self.assertEqual(len(by_name), len(cases))
        self.assertTrue({'archive-accept', 'archive-noninteractive', 'archive-decline',
                         'archive-eof', 'archive-foreground-loss', 'archive-interrupt',
                         'archive-terminal-disconnect', 'archive-policy-changed',
                         'archive-profile-changed', 'archive-staged-bytes-changed',
                         'archive-source-replaced', 'archive-identity-changed',
                         'archive-stale-evidence', 'archive-minimum-verified',
                         'repository-accept', 'repository-stale-evidence',
                         'archive-long-input', 'archive-timeout', 'archive-batch-limit'} <= by_name.keys())
        self.assertEqual({case.name for case in cases if case.commits},
                         {'archive-accept', 'archive-source-replaced', 'repository-accept'})
        self.assertTrue(all(case.diagnostic for case in cases if not case.commits))

    def test_snapshot_fixture_preserves_digest_and_explicit_staleness(self):
        fresh = json.loads(PRODUCER.fresh_admission_snapshot('fresh', 1_800_000_000))
        self.assertEqual(fresh['source_url'], 'https://security.archlinux.org/issues/all.json')
        self.assertEqual(fresh['payload_sha256'], hashlib.sha256(fresh['payload_json'].encode()).hexdigest())
        issues = json.loads(fresh['payload_json'])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['packages'], ['omg-unrelated-fixture'])
        self.assertEqual(issues[0]['status'], 'Fixed')
        self.assertTrue(fresh['complete'])
        stale = json.loads(PRODUCER.fresh_admission_snapshot('stale', 1_800_000_000))
        self.assertLess(stale['checked_at'], fresh['checked_at'])
        self.assertEqual(stale['payload_sha256'], fresh['payload_sha256'])
        with self.assertRaisesRegex(ValueError, 'snapshot mode'):
            PRODUCER.fresh_admission_snapshot('unrecognized', 1_800_000_000)

    def test_native_matrix_refuses_an_ordinary_process_before_creating_fixtures(self):
        with patch.object(PRODUCER.os, 'geteuid', return_value=1000), \
             patch.object(PRODUCER.Path, 'mkdir', side_effect=AssertionError('fixture created before admission')):
            with self.assertRaisesRegex(RuntimeError, 'Guest root'):
                PRODUCER.run_fresh_admission_fixture(Path('/opt/omg-coverage-fresh-test'), Path('/unused'))


if __name__ == '__main__':
    unittest.main()

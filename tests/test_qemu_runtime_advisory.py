"""Exercise the QEMU consent driver with a real controlling terminal."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
import shlex
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("qemu_runtime_consent", ROOT / "scripts/qemu-runtime-advisory-oracle.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class RuntimeConsentTests(unittest.TestCase):
    def command(self, root, *, known=True, url=True, findings=1, hang=False, native=False):
        script = root / "fixture.py"
        details = ('SECURITY WARNING: the selected transaction has disclosed advisory findings.\n' if known else 'SECURITY WARNING: advisory coverage for the selected transaction is unknown.\n')
        details += ('Package: ["tree","2.2.1-1",{"kind":"unknown"},"x86_64",null,[]]\n' if native else 'Package: ["node","24.21.0","x86_64"]\n')
        details += 'CVE-2026-12345\n' if known else 'Coverage gap: controlled incomplete fixture\n'
        if url: details += 'https://www.cve.org/CVERecord?id=CVE-2026-12345\n'
        if findings > 1:
            details += ''.join(f'CVE-2026-{12345+index}\nhttps://www.cve.org/CVERecord?id=CVE-2026-{12345+index}\n' for index in range(1, findings))
        script.write_text('import os,sys\n' + f'details={details!r}\n' + '''
try: tty = os.open('/dev/tty', os.O_RDWR)
except OSError:
    print(details + 'Security review requires an attended controlling terminal', file=sys.stderr)
    raise SystemExit(7)
os.write(tty, (details + '\\nType accept ' + 'a'*64 + ' within 60 seconds to continue (default: cancel): ').encode())
answer = b''
while not answer.endswith(b'\\n'): answer += os.read(tty, 128)
if answer.strip() != ('accept ' + 'a'*64).encode(): raise SystemExit(8)
open('accepted.marker','w').write('accepted')
print('runtime-install-complete')
''')
        if hang:
            script.write_text(script.read_text().replace("os.write(tty,", "import time; time.sleep(30)\nos.write(tty,"))
        return [sys.executable, str(script)]

    def test_known_and_unknown_reviews_require_actual_terminal_acceptance(self):
        for known in (True, False):
            with self.subTest(known=known), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                command = self.command(root, known=known)
                old = Path.cwd()
                try:
                    os.chdir(root)
                    code, transcript, receipt = driver.run_install(command, 'node', '24.21.0', 5, root)
                finally: os.chdir(old)
                self.assertEqual(code, 0, transcript.decode(errors='replace'))
                self.assertTrue((root / 'accepted.marker').exists())
                self.assertEqual(receipt['denied_exit_code'], 7)
                self.assertEqual(receipt['accepted_review'], 'a' * 64)
                self.assertIn(b'runtime-install-complete', transcript)

    def test_driver_never_accepts_a_warning_without_a_public_source_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaisesRegex(ValueError, 'public HTTPS'):
                    driver.run_install(self.command(root, url=False), 'node', '24.21.0', 5, root)
            finally: os.chdir(old)
            self.assertFalse((root / 'accepted.marker').exists())

    def test_large_review_keeps_every_disclosed_identifier_and_link_in_the_terminal_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); old = Path.cwd()
            try:
                os.chdir(root)
                code, transcript, receipt = driver.run_install(self.command(root, findings=197), 'node', '24.21.0', 5, root)
            finally: os.chdir(old)
            self.assertEqual(code, 0)
            for index in range(197):
                self.assertIn(f'https://www.cve.org/CVERecord?id=CVE-2026-{12345+index}'.encode(), transcript)
            self.assertEqual(receipt['accepted_review'], 'a' * 64)

    def test_terminal_timeout_is_fatal_and_reaps_its_owned_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); old = Path.cwd(); started = time.monotonic()
            try:
                os.chdir(root)
                with self.assertRaisesRegex(ValueError, 'row deadline'):
                    driver.run_install(self.command(root, hang=True), 'node', '24.21.0', 0.3, root)
            finally: os.chdir(old)
            self.assertLess(time.monotonic() - started, 2)
            self.assertFalse((root / 'accepted.marker').exists())

    def test_accounting_accept_only_runs_the_original_cli_command_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = self.command(root)
            script = Path(command[1])
            script.write_text("with open('attempts.log','a') as attempts: attempts.write('attempt\\n')\n" + script.read_text())
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                     '--runtime', 'node', '--version', '24.21.0', '--timeout', '5',
                                     '--accept-only', '--', *command], cwd=root, capture_output=True,
                                    start_new_session=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual((root / 'attempts.log').read_text().splitlines(), ['attempt'])
            self.assertTrue((root / 'accepted.marker').exists())
            receipt = json.loads(result.stdout.split(b'OMG_QEMU_RUNTIME_CONSENT=')[1])
            self.assertIsNone(receipt['denied_exit_code'])
            self.assertIsNone(receipt['denied_current_unchanged'])

    def test_native_known_and_unknown_acceptance_runs_each_original_command_once(self):
        for known in (True, False):
            with self.subTest(known=known), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                command = self.command(root, known=known, native=True)
                script = Path(command[1])
                script.write_text("with open('attempts.log','a') as attempts: attempts.write('attempt\\n')\n" + script.read_text())
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                         '--native', '--timeout', '5', '--accept-only', '--require-review',
                                         '--', *command], cwd=root, capture_output=True,
                                        start_new_session=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                self.assertEqual((root / 'attempts.log').read_text().splitlines(), ['attempt'])
                self.assertTrue((root / 'accepted.marker').exists())
                receipt = json.loads(result.stdout.split(b'OMG_QEMU_NATIVE_CONSENT=')[1])
                self.assertEqual(receipt['accepted_review'], 'a' * 64)
                self.assertEqual(receipt['accepted_reviews'], ['a' * 64])

    def test_native_no_terminal_refuses_and_never_mutates_the_prior_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'prior').write_bytes(b'prior native package')
            result = subprocess.run(self.command(root, known=False, native=True), cwd=root,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    start_new_session=True, timeout=5)
            self.assertEqual(result.returncode, 7)
            self.assertIn(b'Coverage gap:', result.stderr)
            self.assertIn(b'https://', result.stderr)
            self.assertFalse((root / 'accepted.marker').exists())
            self.assertEqual((root / 'prior').read_bytes(), b'prior native package')

    def test_native_denial_control_records_one_actual_refused_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = self.command(root, known=False, native=True)
            script = Path(command[1])
            script.write_text("with open('attempts.log','a') as attempts: attempts.write('attempt\\n')\n" + script.read_text())
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                     '--native', '--deny-only', '--timeout', '5', '--', *command],
                                    cwd=root, capture_output=True, start_new_session=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual((root / 'attempts.log').read_text().splitlines(), ['attempt'])
            self.assertFalse((root / 'accepted.marker').exists())
            receipt = json.loads(result.stdout.split(b'OMG_QEMU_NATIVE_CONSENT=')[1])
            self.assertEqual(receipt['denied_exit_code'], 7)
            self.assertIsNone(receipt['accepted_review'])

    def test_native_rejects_missing_identity_or_https_before_acceptance(self):
        for fault in ('identity', 'url'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                command = self.command(root, native=True, url=fault != 'url')
                if fault == 'identity':
                    script = Path(command[1])
                    script.write_text(script.read_text().replace('Package: [', 'Missing: ['))
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                         '--native', '--timeout', '5', '--accept-only', '--require-review',
                                         '--', *command], cwd=root, capture_output=True,
                                        start_new_session=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'accepted.marker').exists())

    def test_native_unknown_review_accepts_a_public_https_homepage_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            command=self.command(root,native=True,known=False)
            script=Path(command[1])
            script.write_text(script.read_text().replace('https://www.cve.org/CVERecord?id=CVE-2026-12345','https://www.cve.org/'))
            result=subprocess.run([sys.executable,str(ROOT/'scripts/qemu-runtime-advisory-oracle.py'),'--native','--accept-only','--require-review','--timeout','5','--',*command],cwd=root,capture_output=True,start_new_session=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            self.assertTrue((root/'accepted.marker').exists())

    def test_native_clean_success_can_run_without_inventing_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'clean.py'
            script.write_text("open('attempts.log','a').write('attempt\\n')\nprint('native-clean-complete')\n")
            command = [sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                       '--native', '--timeout', '5', '--accept-only', '--', sys.executable, str(script)]
            result = subprocess.run(command, cwd=root, capture_output=True, start_new_session=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual((root / 'attempts.log').read_text().splitlines(), ['attempt'])
            receipt = json.loads(result.stdout.split(b'OMG_QEMU_NATIVE_CONSENT=')[1])
            self.assertIsNone(receipt['accepted_review'])
            self.assertEqual(receipt['accepted_reviews'], [])

    def test_named_privilege_launcher_uses_path_and_not_a_same_named_working_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = self.command(root, native=True, known=False)
            search = root / 'commands'
            search.mkdir()
            launcher = search / 'sudo'
            launcher.write_text('#!' + sys.executable + '\n' +
                                "import os,sys\nassert sys.argv[1] == '-n'\n" +
                                "open('launcher.log','a').write('path-launcher\\n')\n" +
                                'os.execv(sys.argv[2], sys.argv[2:])\n')
            launcher.chmod(0o755)
            shadow = root / 'sudo'
            shadow.write_text('#!/bin/sh\nprintf wrong-working-directory-launcher\\n\nexit 42\n')
            shadow.chmod(0o755)
            environment = os.environ | {'PATH': str(search) + os.pathsep + os.environ.get('PATH', '')}
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                     '--native', '--accept-only', '--require-review', '--timeout', '5',
                                     '--', 'sudo', '-n', *command], cwd=root, env=environment,
                                    capture_output=True, start_new_session=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual((root / 'launcher.log').read_text().splitlines(), ['path-launcher'])
            self.assertTrue((root / 'accepted.marker').exists())
            self.assertNotIn(b'wrong-working-directory-launcher', result.stdout)

    def test_missing_path_command_refuses_before_any_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                     '--native', '--accept-only', '--timeout', '5', '--',
                                     'omg-missing-launcher-fixture'], cwd=root,
                                    capture_output=True, start_new_session=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'command executable was not found in PATH', result.stderr)
            self.assertFalse((root / 'accepted.marker').exists())

    def test_explicit_relative_launcher_keeps_its_path_without_a_path_search(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / 'owned-command'
            launcher.write_text('#!' + sys.executable + '\n' +
                                "open('attempts.log','a').write('relative-launcher\\n')\n")
            launcher.chmod(0o755)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                     '--native', '--accept-only', '--timeout', '5', '--',
                                     './owned-command'], cwd=root, env=os.environ | {'PATH': ''},
                                    capture_output=True, start_new_session=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual((root / 'attempts.log').read_text().splitlines(), ['relative-launcher'])

    def test_nonexecutable_path_entry_never_becomes_a_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            launcher = root / 'omg-inert-launcher-fixture'
            launcher.write_text('#!/bin/sh\ntouch should-not-run\n')
            launcher.chmod(0o644)
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/qemu-runtime-advisory-oracle.py'),
                                     '--native', '--accept-only', '--timeout', '5', '--', launcher.name],
                                    cwd=root, env=os.environ | {'PATH': str(root)}, capture_output=True,
                                    start_new_session=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'command executable was not found in PATH', result.stderr)
            self.assertFalse((root / 'should-not-run').exists())

    def test_actual_transaction_recipe_keeps_one_original_install_after_exact_review(self):
        source = (ROOT / 'benchmark-hyperfine.sh').read_text()
        begin = source.index('        if [[ "$GUEST_TOOL" == omg ]]; then')
        end = source.index('        command_json "$transaction_label"', begin)
        for distro in ('debian', 'fedora'):
            with self.subTest(distro=distro), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                command = self.command(root, native=True, known=False)
                executable = Path(command[1])
                executable.write_text('#!' + sys.executable + '\n' +
                                      "with open('attempts.log','a') as attempts: attempts.write('attempt\\n')\n" +
                                      executable.read_text())
                executable.chmod(0o755)
                shutil.copyfile(ROOT / 'scripts/qemu-runtime-advisory-oracle.py', root / 'qemu-runtime-advisory-oracle.py')
                recipe = ('set -euo pipefail\nGUEST_TOOL=omg\nGUEST_TRANSACTION=install\n'
                          + f'distro={shlex.quote(distro)}\nREPO_ROOT={shlex.quote(str(root))}\n'
                          + f'OMG={shlex.quote(str(executable))}\nprivileged=()\n'
                          + source[begin:end] + '\n"${transaction[@]}"\n')
                result = subprocess.run(['bash', '-c', recipe], cwd=root, capture_output=True,
                                        start_new_session=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                self.assertEqual((root / 'attempts.log').read_text().splitlines(), ['attempt'])
                self.assertTrue((root / 'accepted.marker').exists())


if __name__ == '__main__': unittest.main()

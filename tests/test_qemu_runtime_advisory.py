"""Exercise the QEMU consent driver with a real controlling terminal."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("qemu_runtime_consent", ROOT / "scripts/qemu-runtime-advisory-oracle.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class RuntimeConsentTests(unittest.TestCase):
    def command(self, root, *, known=True, url=True, findings=1, hang=False):
        script = root / "fixture.py"
        details = ('SECURITY WARNING: the selected transaction has disclosed advisory findings.\n' if known else 'SECURITY WARNING: advisory coverage for the selected transaction is unknown.\n')
        details += 'Package: ["node","24.21.0","x86_64"]\n'
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


if __name__ == '__main__': unittest.main()

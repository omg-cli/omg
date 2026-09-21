"""Guard all-distro daemon packaging and the actual host receipt gate."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
BASH = os.environ.get('OMG_TEST_BASH') or ('C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash')


class DaemonContractTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'guest dependency setup requires POSIX bash')
    def test_guest_query_tools_are_installed_with_benchmarks_disabled(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        setup = source.split('guest_tools=(jq)', 1)[1].split('timeout --kill-after=5s 240s', 1)[0]
        setup = 'guest_tools=(jq)' + setup
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            for benchmark in ('true', 'false'):
                with self.subTest(distro=distro, benchmark=benchmark):
                    result = subprocess.run(
                        [BASH, '-euc', 'sudo() { printf "%s\\n" "$@"; };\n' + setup],
                        env=dict(os.environ, distro=distro, benchmark=benchmark),
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = result.stdout.splitlines()
                    self.assertEqual(args.count('jq'), 1)
                    self.assertEqual(args.count('hyperfine'), int(benchmark == 'true'))

    def test_query_parity_receipt_is_mandatory(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        gate = source.split('  daemon_receipt=', 1)[1].split('\nfi\n', 1)[0]
        self.assertIn('.query_parity == true', gate)

    @unittest.skipIf(os.name == 'nt', 'native query oracle requires POSIX jq')
    def test_query_oracle_rejects_wrong_names_counts_duplicates_and_extra_json(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN EXPLICIT QUERY ORACLE')
        end = source.index('# END EXPLICIT QUERY ORACLE', begin)
        function = source[begin:end]
        good = {'expected': '["bash","git"]',
                'listing': '{"packages":["git","bash"],"count":2}',
                'count': '2', 'shortcut': '2', 'jsoncount': '{"count":2}'}
        cases = [(good, True)]
        for key, value in [('listing', '{"packages":["bash","wrong"],"count":2}'),
                           ('listing', '{"packages":["bash","git","git"],"count":2}'),
                           ('listing', '{"packages":["bash","git"],"count":3}'),
                           ('count', '3'), ('shortcut', '3'), ('jsoncount', '{"count":"2"}'),
                           ('count', '0\n2'), ('listing', '{}\n' + good['listing'])]:
            cases.append((dict(good, **{key: value}), False))
        for files, passed in cases:
            with self.subTest(files=files), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, content in files.items():
                    (root / name).write_text(content)
                result = subprocess.run([BASH, '-c', function + '\ncheck_explicit_query_outputs expected listing count shortcut jsoncount'],
                                        cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    def test_shell_startup_does_not_skip_this_users_ipc_check_for_another_process(self):
        source = (ROOT / 'src/cli/init.rs').read_text(encoding='utf-8')
        command = re.search(r'const DAEMON_SHELL_START: &str = "([^"]+)";', source).group(1)
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'launcher-called'
            # A name-only process lookup finds an unrelated daemon. Startup
            # must still ask OMG to check the current user's own socket.
            script = 'pgrep() { return 0; }; omg() { printf "%s" "$1" > "$MARKER"; };\n'
            result = subprocess.run([BASH, '-euc', script + command + '\nwait'],
                                    env=dict(os.environ, MARKER=marker.as_posix()),
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(marker.exists(), 'unrelated process suppressed daemon startup')
            self.assertEqual(marker.read_text(), 'daemon')

    def test_release_and_staged_archives_ship_matching_daemon(self):
        for name in ('release.yml', 'qemu-matrix.yml', 'qemu-lane.yml'):
            text = (ROOT / '.github/workflows' / name).read_text(encoding='utf-8')
            destinations = re.findall(r'cp target/release/omg ("[^\n]*(?:linux|darwin)[^\n]*")', text)
            self.assertTrue(destinations, name)
            for destination in destinations:
                self.assertIn('cp target/release/omgd ' + destination, text, (name, destination))

    def test_receipt_rejects_missing_false_and_wrong_type_fields(self):
        if not shutil.which('jq'):
            self.skipTest('jq required')
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        gate = source.split('  daemon_receipt=', 1)[1].split('\nfi\n', 1)[0]
        gate = 'daemon_receipt=' + gate
        good = dict(schema_version=1, direct=True, foreground=True, ipc=True,
                    singleton=True, shutdown=True, restart=True, query_parity=True, sigint=True)
        cases = [(good, True), (None, False)]
        for key in good:
            missing = dict(good)
            del missing[key]
            cases.append((missing, False))
            wrong = dict(good, **{key: 'true'})
            cases.append((wrong, False))
            cases.append((dict(good, **{key: False}), False))
        serialized = [(None if receipt is None else json.dumps(receipt), expected)
                      for receipt, expected in cases]
        serialized += [('{}\n' + json.dumps(good), False),
                       (json.dumps(good) + '\n' + json.dumps(good), False)]
        for receipt, expected in serialized:
            with self.subTest(receipt=receipt), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = root / 'guest/evidence'
                evidence.mkdir(parents=True)
                if receipt is not None:
                    (evidence / 'daemon-lifecycle.json').write_text(receipt)
                result = subprocess.run([BASH, '-euc', gate], env=dict(os.environ, work=root.as_posix()),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_lifecycle_is_unconditional_and_receipt_is_exported(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        guest = source.split("<<'GUEST'", 1)[1].split('\nGUEST', 1)[0]
        probe = 'timeout --kill-after=5s 240s bash "$HOME/qemu-daemon-check.sh"'
        self.assertIn(probe, guest)
        self.assertLess(guest.index(probe), guest.index('if [[ "$benchmark" == true ]]'))
        export = (ROOT / 'scripts/export-qemu-evidence.py').read_text(encoding='utf-8')
        self.assertIn('"daemon-lifecycle.json"', export)


if __name__ == '__main__':
    unittest.main()

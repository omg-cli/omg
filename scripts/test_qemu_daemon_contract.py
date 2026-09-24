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
    @unittest.skipIf(os.name == 'nt', 'guest failure diagnostics require POSIX bash')
    def test_silent_probe_failure_reports_its_line_and_exit(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        trap = next(line for line in source.splitlines()
                    if line.startswith("trap 'status=$?;") and line.endswith(" ERR"))
        result = subprocess.run(
            [BASH, '-Eeuo', 'pipefail', '-c', trap + '\nfalse'],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertRegex(result.stderr, r'daemon lifecycle probe failed at line [0-9]+ \(exit 1\)')

    @unittest.skipIf(os.name == 'nt', 'guest fault oracle requires POSIX bash')
    def test_backend_refusal_requires_product_exit_cause_and_no_success_output(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        function = source.split('# BEGIN BACKEND FAULT ORACLE', 1)[-1].split('# END BACKEND FAULT ORACLE', 1)[0]
        diagnostic = 'Error: Could not load DNF install reasons: dnf repoquery --userinstalled failed: omg-injected-dnf-reason-failure\n'
        for code, stdout, stderr, passed in (
            (1, '', diagnostic, True),
            (0, '{"explicit_packages":0}\n', '', False),
            (1, '{"explicit_packages":0}\n', diagnostic, False),
            (1, '', 'permission denied\n', False),
            (127, '', diagnostic, False),
            (124, '', diagnostic, False),
        ):
            with self.subTest(code=code, stdout=stdout, stderr=stderr), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'stdout').write_text(stdout)
                (root / 'stderr').write_text(stderr)
                result = subprocess.run([BASH, '-c', function + '\ncheck_backend_refusal "$1" stdout stderr', '_', str(code)],
                                        cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'guest dependency setup requires POSIX bash')
    def test_guest_query_tools_are_installed_with_benchmarks_disabled(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        setup = source.split('guest_tools=(jq)', 1)[1].split("printf 'daemon lifecycle start", 1)[0]
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

    @unittest.skipIf(os.name == 'nt', 'native query diagnostics require POSIX jq')
    def test_query_mismatch_reports_bounded_native_and_omg_set_differences(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN EXPLICIT QUERY ORACLE')
        end = source.index('# END EXPLICIT QUERY ORACLE', begin)
        function = source[begin:end]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'expected').write_text('["bash","native-only"]')
            (root / 'listing').write_text('{"packages":["bash","omg-only","omg-only"],"count":3}')
            result = subprocess.run(
                [BASH, '-c', function + '\nreport_explicit_query_difference expected listing fixture'],
                cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('fixture native_count=2 omg_count=3', result.stderr)
            self.assertIn('native_only=["native-only"]', result.stderr)
            self.assertIn('omg_only=["omg-only"]', result.stderr)
            self.assertIn('omg_duplicates=["omg-only"]', result.stderr)

    @unittest.skipIf(os.name == 'nt', 'package query oracle requires POSIX jq')
    def test_daemon_and_direct_package_queries_must_agree_on_a_real_installed_name(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        self.assertIn('# BEGIN PACKAGE QUERY ORACLE', source)
        begin = source.index('# BEGIN PACKAGE QUERY ORACLE')
        end = source.index('# END PACKAGE QUERY ORACLE', begin)
        function = source[begin:end]
        search = [{'name': 'bash', 'version': '5.3', 'description': 'Shell', 'source': 'Official'}]
        info = {'name': 'bash', 'version': '5.3', 'description': 'Shell', 'installed': True}
        cases = [(search, info, search, info, True)]
        cases += [
            ([], info, search, info, False),
            (search, dict(info, version='wrong'), search, info, False),
            (search, info, search, dict(info, installed=False), False),
            (search + search, info, search, info, False),
            ([dict(search[0], source='AUR')], info, search, info, False),
            (search, info, [dict(search[0], description='')], info, False),
            (search, info, search, {'name': 'other', **{key: value for key, value in info.items() if key != 'name'}}, False),
        ]
        for daemon_search, daemon_info, direct_search, direct_info, passed in cases:
            with self.subTest(daemon_search=daemon_search, daemon_info=daemon_info,
                              direct_search=direct_search, direct_info=direct_info), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, value in [('daemon-search', daemon_search), ('daemon-info', daemon_info),
                                    ('direct-search', direct_search), ('direct-info', direct_info)]:
                    (root / name).write_text(json.dumps(value))
                result = subprocess.run(
                    [BASH, '-c', function + '\ncheck_package_query_outputs bash daemon-search daemon-info direct-search direct-info'],
                    cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'text info oracle requires POSIX bash')
    def test_text_info_requires_true_native_installation_in_both_modes(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        self.assertIn('# BEGIN TEXT INFO ORACLE', source)
        function = source.split('# BEGIN TEXT INFO ORACLE', 1)[1].split('# END TEXT INFO ORACLE', 1)[0]
        good = '\n  | Info\n    bash\n          Name: bash\n     Installed: yes\n'
        for daemon, direct, passed in [(good, good, True),
                                       (good.replace('yes', 'no'), good, False),
                                       (good, good.replace('yes', 'no'), False),
                                       (good.replace('Name: bash', 'Name: wrong'), good, False)]:
            with self.subTest(daemon=daemon, direct=direct), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'daemon').write_text(daemon)
                (root / 'direct').write_text(direct)
                result = subprocess.run([BASH, '-c', function + '\ncheck_text_info_outputs bash daemon direct'],
                                        cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'daemon IPC counters require POSIX bash')
    def test_package_ipc_oracle_rejects_native_fallback_and_unrelated_requests(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        function = source.split('# BEGIN PACKAGE IPC ORACLE', 1)[1].split('# END PACKAGE IPC ORACLE', 1)[0]
        before = 'omg_search_requests_total 4\nomg_info_requests_total 8\n'
        cases = [
            ('omg_search_requests_total 5\nomg_info_requests_total 8\n', 1, 0, True),
            ('omg_search_requests_total 4\nomg_info_requests_total 9\n', 0, 1, True),
            ('omg_search_requests_total 4\nomg_info_requests_total 8\n', 1, 0, False),
            ('omg_search_requests_total 5\nomg_info_requests_total 8\n', 0, 1, False),
            ('omg_search_requests_total 5\nomg_info_requests_total 9\n', 1, 0, False),
            ('omg_search_requests_total 5\nomg_info_requests_total 9\n', 0, 1, False),
            ('omg_search_requests_total 5\n', 1, 0, False),
            ('omg_search_requests_total 5\nomg_search_requests_total 5\nomg_info_requests_total 8\n', 1, 0, False),
        ]
        for after, expected_search, expected_info, passed in cases:
            with self.subTest(after=after, search=expected_search, info=expected_info), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'before').write_text(before)
                (root / 'after').write_text(after)
                result = subprocess.run(
                    [BASH, '-c', function + f'\ncheck_package_ipc_delta before after {expected_search} {expected_info}'],
                    cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'daemon JSON provenance oracle requires POSIX bash')
    def test_daemon_info_provenance_rejects_native_fallback_after_ipc_attempt(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        function = source.split('# BEGIN INFO PROVENANCE ORACLE', 1)[1].split('# END INFO PROVENANCE ORACLE', 1)[0]
        native = {'name': 'bash', 'version': '1', 'description': 'shell', 'installed': True}
        fedora_native = {**native, 'source': 'Official'}
        daemon = {**native, 'source': 'Official', 'repo': 'core', 'download_size': 0}
        for daemon_output, native_output, passed in [
            (daemon, native, True),
            (daemon, fedora_native, True),
            (native, native, False),
            (fedora_native, fedora_native, False),
            (daemon, daemon, False),
            ({**daemon, 'source': 'AUR'}, native, False),
        ]:
            with self.subTest(daemon=daemon_output, native=native_output), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'daemon.json').write_text(json.dumps(daemon_output))
                (root / 'native.json').write_text(json.dumps(native_output))
                result = subprocess.run(
                    [BASH, '-c', function + '\ncheck_daemon_info_provenance daemon.json native.json'],
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
                    singleton=True, shutdown=True, restart=True, query_parity=True, sigint=True,
                    cleanup=True, backend_faults=['dnf-reason-refusal'])
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
                result = subprocess.run([BASH, '-euc', gate], env=dict(os.environ, work=root.as_posix(), distro='fedora'),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'guest cleanup requires POSIX bash')
    def test_daemon_cleanup_removes_owned_state_and_rejects_incomplete_removal(self):
        source = (ROOT / 'scripts/qemu-daemon-check.sh').read_text(encoding='utf-8')
        cleanup = 'cleanup() {' + source.split('cleanup() {', 1)[1].split('\ntrap cleanup EXIT', 1)[0]
        for fault in ('none', 'error', 'noop'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / 'state'
                state.mkdir()
                (state / 'fixture').write_text('owned state')
                shadow = '' if fault == 'none' else 'rm() { return ' + ('17' if fault == 'error' else '0') + '; };\n'
                result = subprocess.run([BASH, '-c', shadow + cleanup + '\ntrap cleanup EXIT\nexit 0'],
                                        env=dict(os.environ, state=str(state), daemon_pid='', launcher_pid=''),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0 if fault == 'none' else 1, result.stderr)
                self.assertEqual(state.exists(), fault != 'none')
                if fault != 'none':
                    self.assertIn('daemon fixture cleanup failed', result.stderr)

    def test_lifecycle_is_unconditional_and_receipt_is_exported(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        guest = source.split("<<'GUEST'", 1)[1].split('\nGUEST', 1)[0]
        probe = 'OMG_QEMU_ACCEL="$accel" timeout --kill-after=5s "$daemon_timeout" bash "$HOME/qemu-daemon-check.sh"'
        self.assertIn(probe, guest)
        self.assertLess(guest.index(probe), guest.index('if [[ "$benchmark" == true ]]'))
        export = (ROOT / 'scripts/export-qemu-evidence.py').read_text(encoding='utf-8')
        self.assertIn('"daemon-lifecycle.json"', export)

    @unittest.skipIf(os.name == 'nt', 'guest regression requires POSIX bash')
    def test_fedora_advisory_shutdown_failure_blocks_guest(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text(encoding='utf-8')
        probe = source.split('# BEGIN ADVISORY SHUTDOWN REGRESSION\n', 1)[1].split(
            '# END ADVISORY SHUTDOWN REGRESSION', 1)[0]
        for distro, outcome in [('fedora', 0), ('fedora', 19), ('arch', 19)]:
            with self.subTest(distro=distro, outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'evidence').mkdir()
                script = 'sudo() { printf "advisory regression invoked\\n"; return "$OUTCOME"; };\n' + probe
                result = subprocess.run([BASH, '-euo', 'pipefail', '-c', script],
                                        env=dict(os.environ, HOME=str(root), distro=distro,
                                                 bin='/fixture/omg', OUTCOME=str(outcome)),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, outcome if distro == 'fedora' else 0)
                log = root / 'evidence/daemon-advisory-shutdown.log'
                self.assertEqual(log.exists(), distro == 'fedora')
                if log.exists():
                    self.assertIn('advisory regression invoked', log.read_text())
                    self.assertIn('advisory regression invoked', result.stdout)


if __name__ == '__main__':
    unittest.main()

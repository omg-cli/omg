"""Exercise the exact guest output oracle with plausible false-green products."""
import os
import hashlib
import json
import re
import runpy
import shlex
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]



@unittest.skipIf(os.name == 'nt', 'native preview assertions require POSIX bash')
class NativeRemovalContracts(unittest.TestCase):
    def test_trixie_doctor_backend_reference_preserves_os_and_lane_identity(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN DOCTOR BACKEND ORACLE')
        end = source.index('# END DOCTOR BACKEND ORACLE', begin)
        command = source[begin:end] + '\ncheck_doctor_native_backend "$1" "$2" "$3"\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / 'os-release'
            output = root / 'doctor.out'
            healthy = ('  Debian/Ubuntu detected (apt backend)\n'
                       '  Found dependency: apt-get\n'
                       '  Found dependency: sudo\n'
                       '  dpkg package database (/var/lib/dpkg/status)\n'
                       '  APT package indexes (/var/lib/apt/lists)\n')
            output.write_text(healthy, encoding='utf-8')
            cases = (
                ('ID=debian\nVERSION_ID=13\n', 0),
                ('ID="debian"\nVERSION_ID="13"\n', 0),
                ("ID='debian'\nVERSION_ID='13'\n", 0),
                ('ID=debian\nVERSION_ID=12\n', 2),
                ('ID=ubuntu\nVERSION_ID=13\n', 2),
                ('ID=debian\n', 2),
                ('ID=debian\nID=debian\nVERSION_ID=13\n', 2),
                ('ID=debian\nVERSION_ID=13\nVERSION_ID=13\n', 2),
            )
            for identity, expected in cases:
                with self.subTest(identity=identity):
                    release.write_text(identity, encoding='utf-8')
                    result = subprocess.run(
                        [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'), '-c',
                         command, '_', 'debian-trixie', str(output), str(release)],
                        cwd=root, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stderr)
            release.write_text('ID=debian\nVERSION_ID=13\n', encoding='utf-8')
            output.write_text(healthy.replace('  Found dependency: apt-get\n', ''),
                              encoding='utf-8')
            result = subprocess.run(
                [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'), '-c',
                 command, '_', 'debian-trixie', str(output), str(release)],
                cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1,
                             'Trixie OS identity must retain trusted apt-get validation')

    def test_trixie_connectivity_setup_requires_debian_13(self):
        source = (ROOT / 'scripts/qemu-doctor-connectivity-check.sh').read_text(encoding='utf-8')
        marker = '[[ -d "$evidence" ]] || setup_fail \'evidence directory unavailable\''
        self.assertIn(marker, source)
        prefix = source.split(marker, 1)[0] + marker
        for release, code in (('ID=debian\nVERSION_ID=13\n', 0),
                              ('ID=debian\nVERSION_ID=12\n', 120),
                              ('ID=ubuntu\nVERSION_ID=13\n', 120)):
            with self.subTest(release=release), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os_release = root / 'os-release'
                os_release.write_text(release)
                (root / 'qemu-doctor-connectivity-fixture.py').symlink_to(ROOT / 'scripts/qemu-doctor-connectivity-fixture.py')
                binary = root / 'omg'
                binary.write_text('#!/bin/sh\nexit 99\n')
                binary.chmod(0o755)
                script = root / 'setup.sh'
                script.write_text(prefix.replace('/etc/os-release', str(os_release)) + '\n')
                result = subprocess.run(['bash', str(script), str(binary), 'debian-trixie', str(root)],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stderr)

    def test_trixie_native_version_and_identity_require_installed_apt_records(self):
        provider = 'dpkg-query() { printf "%s" "$QUERY_OUT"; }\n'
        for record, expected, code in (
            ('install ok installed\t1.2-3\n', '1.2-3', 0),
            ('deinstall ok config-files\t1.2-3\n', '', 0),
        ):
            with self.subTest(record=record):
                result = subprocess.run(['bash', '-c', provider + self.functions() +
                    '\nnative_installed_version debian-trixie tree', '_'],
                    env=dict(os.environ, QUERY_OUT=record), capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)
        identity = subprocess.run(['bash', '-c', self.functions() +
            '\nnative_installed_identity debian-trixie tree'], capture_output=True, text=True, timeout=10)
        self.assertEqual(identity.returncode, 0, identity.stderr)
        self.assertEqual(identity.stdout.strip(), 'tree')

    def test_trixie_transaction_invokes_exact_native_apt_operations(self):
        source = (ROOT / 'scripts/qemu-transactions.sh').read_text(encoding='utf-8')
        function = source[source.index('native_change() {'):source.index('capture_repository_state() {')]
        for operation in ('install', 'remove'):
            with self.subTest(operation=operation):
                result = subprocess.run(['bash', '-c',
                    'distro=debian-trixie\nremote_argv() { printf "%s\\n" "$@"; }\n' +
                    function + '\nnative_change "$1"', '_', operation],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ['sudo', '-n', 'env',
                    'DEBIAN_FRONTEND=noninteractive', 'apt-get', operation, '-y', 'tree'])

    @staticmethod
    def functions():
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        return source[source.index('native_installed_version() {'):
                      source.index('prepare_native_apt_orphan() {')]

    def test_removal_preview_requires_exact_native_identity_version_and_multiplicity(self):
        header = 'The following packages would be removed:\n'
        footer = 'No changes made (dry run)\n'
        cases = [
            ('bash', '5.3.9-3.fc44', '  ✗ bash 5.3.9-3.fc44\n', True),
            ('bash.x86_64', '5.3.9-3.fc44', '  ✗ bash.x86_64 5.3.9-3.fc44\n', True),
            ('bash.x86_64', '2:5.3.9-3.fc44', '  ✗ bash.x86_64 2:5.3.9-3.fc44\n', True),
            ('bash.x86_64', '5.3.9-3.fc44', '  ✗ bash 5.3.9-3.fc44\n', False),
            ('bash.x86_64', '5.3.9-3.fc44', '  ✗ bash.i686 5.3.9-3.fc44\n', False),
            ('bash.x86_64', '5.3.9-3.fc44', '  ✗ bash.x86_64 5.3.8-3.fc44\n', False),
            ('bash.x86_64', '2:5.3.9-3.fc44', '  ✗ bash.x86_64 5.3.9-3.fc44\n', False),
            ('bash', '5.3.9-3.fc44', '  ✗ bash 5.3.9-3.fc44\n' * 2, False),
            ('bash.x86_64', '5.3.9-3.fc44', '', False),
            ('bash.x86_64', '5.3.9-3.fc44', '  ✗ bash.x86_64 5.3.9-3.fc44 extra\n', False),
        ]
        for identity, version, rows, passed in cases:
            with self.subTest(identity=identity, version=version, rows=rows), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / 'preview').write_text(header + rows + footer, encoding='utf-8')
                result = subprocess.run(['bash', '-c', self.functions() +
                                         '\ncheck_native_remove_preview preview "$1" "$2"',
                                         '_', version, identity], cwd=directory,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    def test_arch_removal_rows_require_the_exact_size_format(self):
        header = 'The following requested packages would be removed:\n'
        footer = 'No changes made (dry run)\n'
        cases = [
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (0.47 MB)\n', True),
            ('arch', 'bash', '5.3.20-1', '  ✗ bash 5.3.20-1 (9.59 MB)\n', True),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (0.47 MB) extra\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (unknown MB)\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (-0.47 MB)\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (0.4 MB)\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (0.47 GB)\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (0.47 MB\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.1-1 (0.47 MB)\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq-tools 1.8.2-1 (0.47 MB)\n', False),
            ('arch', 'jq', '1.8.2-1', '  ✗ jq 1.8.2-1 (0.47 MB)\n' * 2, False),
            ('fedora', 'jq.x86_64', '1.8.1-3.fc44',
             '  ✗ jq.x86_64 1.8.1-3.fc44 (0.47 MB)\n', False),
        ]
        for distro, identity, version, rows, passed in cases:
            with self.subTest(distro=distro, rows=rows), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / 'preview').write_text(header + rows + footer, encoding='utf-8')
                result = subprocess.run(['bash', '-c', self.functions() +
                                         '\ncheck_native_remove_preview preview "$1" "$2" "$3"',
                                         '_', version, identity, distro], cwd=directory,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, passed, result.stderr)

    def test_native_identity_rejects_inexact_or_multiple_rpm_records(self):
        provider = r"""
rpm() { printf '%s' "$IDENTITY_OUT"; return "$RPM_EXIT"; }
"""
        cases = [('fedora', 'jq\tx86_64\n', 0, 0, 'jq.x86_64'),
                 ('fedora', 'jq\tnoarch\n', 0, 0, 'jq.noarch'),
                 ('arch', '', 0, 0, 'jq'), ('debian', '', 0, 0, 'jq'),
                 ('ubuntu', '', 0, 0, 'jq'),
                 ('fedora', '', 0, 1, ''),
                 ('fedora', 'jq\tx86_64\njq\ti686\n', 0, 1, ''),
                 ('fedora', 'bash\tx86_64\n', 0, 1, ''),
                 ('fedora', 'jq\tx86_64 \n', 0, 1, ''),
                 ('fedora', 'jq\tx86_64\n', 17, 17, '')]
        for distro, output, native_exit, exit_code, expected in cases:
            with self.subTest(distro=distro, output=output, native_exit=native_exit):
                result = subprocess.run(['bash', '-c', provider + self.functions() +
                                         '\nnative_installed_identity "$1" jq', '_', distro],
                                        env=dict(os.environ, IDENTITY_OUT=output, RPM_EXIT=str(native_exit)),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_fedora_installed_version_retains_nonzero_epoch_and_rejects_bad_records(self):
        provider = r"""
rpm() {
  case "$*" in
    *EPOCHNUM*) printf '%s\t%s\t%s\n' "$EPOCH" "$VERSION" "$RELEASE" ;;
    *) printf '%s-%s\n' "$VERSION" "$RELEASE" ;;
  esac
  return "$RPM_EXIT"
}
"""
        cases = [('0', '5.3.9', '3.fc44', 0, 0, '5.3.9-3.fc44'),
                 ('2', '5.3.9', '3.fc44', 0, 0, '2:5.3.9-3.fc44'),
                 ('bad', '5.3.9', '3.fc44', 0, 1, ''),
                 ('0', '', '3.fc44', 0, 1, ''),
                 ('0', '5.3.9\n5.3.8', '3.fc44', 0, 1, ''),
                 ('0', '5.3.9', '3.fc44', 17, 17, '')]
        for epoch, version, release, native_exit, exit_code, expected in cases:
            with self.subTest(epoch=epoch, version=version, native_exit=native_exit):
                result = subprocess.run(['bash', '-c', provider + self.functions() +
                                         '\nnative_installed_version fedora bash'],
                                        env=dict(os.environ, EPOCH=epoch, VERSION=version,
                                                 RELEASE=release, RPM_EXIT=str(native_exit)),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)



@unittest.skipIf(os.name == 'nt', 'Row transport requires POSIX bash')
class RowTransportContracts(unittest.TestCase):
    @staticmethod
    def receiver(size, digest):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        functions = source[source.index('# BEGIN ROW PROGRAM RECEIVER'):
                           source.index('# END ROW PROGRAM RECEIVER')]
        result = subprocess.run(['bash', '-c', functions + '\nrow_program_receiver "$1" "$2"',
                                 '_', str(size), digest], capture_output=True, timeout=10)
        return result

    def execute(self, program, stream=None, *, digest=None):
        receiver = self.receiver(len(program), digest or hashlib.sha256(program).hexdigest())
        self.assertEqual(receiver.returncode, 0, receiver.stderr)
        self.assertLess(len(receiver.stdout), 4096)
        return subprocess.run(['bash', '-c', receiver.stdout.decode()],
                              input=program if stream is None else stream,
                              env=dict(os.environ, qemu_row_payload='inherited-export', LC_ALL='C.UTF-8'),
                              capture_output=True, timeout=10)

    def test_verified_long_program_keeps_bytes_eof_environment_and_exit_behavior(self):
        body = '''set -eu
test "$#" -eq 0
test "$LC_ALL" = C.UTF-8
! env | grep '^qemu_row_payload='
if IFS= read -r input; then exit 73; fi
printf 'unicode: →\\n'
trap 'printf "exit-trap\\n"' EXIT
'''
        for size in (154274, 1048576):
            program = body.encode() + b'#' + b'x' * (size - len(body.encode()) - 3) + b'\n\n'
            with self.subTest(size=size):
                result = self.execute(program)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, 'unicode: →\nexit-trap\n'.encode())
        program = b'set -eu\ntrap \'printf "exit-trap\\n"\' EXIT\nfalse\nprintf forbidden\n\n'
        result = self.execute(program)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, b'exit-trap\n')
        result = self.execute(b'set -eu\ntrap \'printf "exit-trap\\n"\' EXIT\nexit 23\n\n')
        self.assertEqual((result.returncode, result.stdout), (23, b'exit-trap\n'))

    def test_unverified_or_oversized_stream_cannot_reach_the_program(self):
        program = b'printf executed\n' + b'#' + b'x' * 140000 + b'\n\n'
        for label, stream, digest in (
            ('truncated', program[:-1], None), ('extra', program + b'\n', None),
            ('wrong bytes', program.replace(b'executed', b'mutated!'), None),
            ('wrong digest', program, '0' * 64), ('empty', b'', None),
            ('embedded NUL', program[:20] + b'\0' + program[20:], None),
            ('over limit', program + b'x' * 1048577, None),
        ):
            with self.subTest(label=label):
                result = self.execute(program, stream, digest=digest)
                self.assertEqual(result.returncode, 122, result.stderr)
                self.assertEqual(result.stdout, b'')
        for size, digest in ((0, '0' * 64), (1048577, '0' * 64),
                             ('1; printf executed', '0' * 64), (1, 'invalid')):
            with self.subTest(size=size, digest=digest):
                result = self.receiver(size, digest)
                self.assertEqual(result.returncode, 120, result.stderr)
                self.assertEqual(result.stdout, b'')


class OutputContracts(unittest.TestCase):
    def test_run_watch_row_uses_bounded_source_edit_and_receipt(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        row = next(line for line in inventory.splitlines() if line.startswith('run-watch\t'))
        self.assertEqual(row.split('\t')[8], 'watch-task-rerun')
        product = '''[[ "$1:$2:$3" == run:--watch:smoke && -f src/watch-trigger.txt ]] || exit 70
make -s smoke || exit 71
printf 'Watching for changes...\\n'
while [[ $(cat src/watch-trigger.txt) != 'changed once' ]]; do sleep .02; done
printf 'File changed, re-running\\n'
make -s smoke || exit 71
trap 'exit 130' INT
while :; do sleep .05; done
'''
        result, evidence, logs = self.run_inventory(
            product, [row], tiers='container', row_timeout=30,
            home_files={'qemu-run-watch-check.py':
                        (ROOT / 'scripts/qemu-run-watch-check.py').read_bytes()})
        self.assertEqual(result.returncode, 0, f'{result.stdout}\n{result.stderr}\n{logs}')
        self.assertEqual(evidence[0]['result'], 'PASS', logs)

    def test_golden_path_oracle_rejects_false_success_and_stale_state(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        oracle = source[source.index('check_golden_path_state() {'):
                        source.index('check_product_output() {')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config'
            config.mkdir()
            store = config / 'golden-paths.toml'
            output = root / 'output.log'

            def check(assertion, contents, message):
                if contents is None:
                    store.unlink(missing_ok=True)
                else:
                    store.write_text(contents, encoding='utf-8')
                output.write_text(message, encoding='utf-8')
                return subprocess.run(
                    ['bash', '-c', oracle + '\n'
                     + 'export OMG_CONFIG_DIR="$PWD/config"\n'
                     + 'check_golden_path_state "$1" output.log', '_', assertion],
                    cwd=root, capture_output=True, text=True)

            template = ('[[templates]]\nname = "smoke"\ncreated_at = 1700000000\n'
                        'packages = []\n[templates.runtimes]\n')
            good = {
                'golden-path-created': "Golden path 'smoke' created!\n",
                'golden-path-listed': '1 custom template(s)\nsmoke - runtimes: [], packages: 0\n',
                'golden-path-deleted': "Deleted template 'smoke'\n",
            }
            for assertion, message in good.items():
                state = 'templates = []\n' if assertion == 'golden-path-deleted' else template
                with self.subTest(assertion=assertion):
                    self.assertEqual(check(assertion, state, message).returncode, 0)
                    self.assertNotEqual(check(assertion, None, message).returncode, 0)
                    self.assertNotEqual(check(assertion, state, '').returncode, 0)
            for state in (
                template.replace('"smoke"', '"wrong"'),
                template.replace('1700000000', '0'),
                template + template,
                template.replace('packages = []', 'packages = ["curl"]'),
                'templates = []\n',
            ):
                with self.subTest(state=state):
                    self.assertNotEqual(check('golden-path-created', state,
                                              good['golden-path-created']).returncode, 0)
            self.assertNotEqual(check('golden-path-deleted', template,
                                      good['golden-path-deleted']).returncode, 0)
            self.assertNotEqual(check('golden-path-listed', template,
                                      'No custom templates\n').returncode, 0)
            flagged = (template + '[[templates]]\nname = "flagged"\ncreated_at = 1700000001\n'
                       'packages = ["ripgrep"]\n[templates.runtimes]\n'
                       'node = "20"\npython = "3.12"\n')
            receipt = "Golden path 'flagged' created!\nNode: 20\nPython: 3.12\nPackages: ripgrep\n"
            self.assertEqual(check('golden-path-flags', flagged, receipt).returncode, 0)
            for broken in (flagged.replace('node = "20"', 'node = "22"'),
                           flagged.replace('packages = ["ripgrep"]', 'packages = []'),
                           template):
                self.assertNotEqual(check('golden-path-flags', broken, receipt).returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_tree_install_remove_rows_reject_collateral_package_and_reason_changes(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith(('release-package-install-tree\t',
                                    'release-package-remove-tree\t'))]
        self.assertEqual(len(rows), 2)
        native = {
            'sudo': '''[[ "$1" != -n ]] || shift
case "$1:$2" in
  pacman:-R|dpkg:--purge|rpm:-e)
    [[ "${@: -1}" == tree ]] || exit 70
    rm -f "$HOME/tree-state" "$OMG_QEMU_TEST_TREE_BINARY" \
      "$HOME/base-arch" "$HOME/base-epoch" "$HOME/base-dnf-arch" ;;
  *) exit 70 ;;
esac
''',
            'pacman': '''case "$1" in
  -Qq)
    if [[ "${2:-}" == tree ]]; then [[ -f "$HOME/tree-state" ]] && printf 'tree\n';
    else printf 'base\n'; [[ ! -f "$HOME/tree-state" ]] || printf 'tree\n'; fi ;;
  -Q)
    printf 'base %s\n' "$(cat "$HOME/base-state" 2>/dev/null || printf 1.0)"
    if [[ -f "$HOME/tree-state" ]]; then printf 'tree 2.0\n'; fi ;;
  -Qqe)
    if [[ ! -f "$HOME/base-auto" ]]; then printf 'base\n'; fi
    if [[ -f "$HOME/tree-state" ]]; then printf 'tree\n'; fi ;;
  *) exit 70 ;;
esac
''',
            'dpkg-query': '''if [[ "$*" == *'${Version}'* ]]; then
  if [[ "$*" == *'${Architecture}'* ]]; then
    printf 'base\t%s\tinstall ok installed\t%s\n' \
      "$(cat "$HOME/base-state" 2>/dev/null || printf 1.0)" \
      "$(cat "$HOME/base-arch" 2>/dev/null || printf amd64)"
    if [[ -f "$HOME/tree-state" ]]; then printf 'tree\t2.0\tinstall ok installed\tamd64\n'; fi
  else
    printf 'base\t%s\tinstall ok installed\n' "$(cat "$HOME/base-state" 2>/dev/null || printf 1.0)"
    if [[ -f "$HOME/tree-state" ]]; then printf 'tree\t2.0\tinstall ok installed\n'; fi
  fi
else
  printf 'base\tinstall ok installed\n'
  if [[ -f "$HOME/tree-state" ]]; then printf 'tree\tinstall ok installed\n'; fi
fi
''',
            'apt-mark': '''[[ "$1" == showmanual ]] || exit 70
if [[ ! -f "$HOME/base-auto" ]]; then printf 'base\n'; fi
if [[ -f "$HOME/tree-state" ]]; then printf 'tree\n'; fi
''',
            'rpm': '''case "$1:$2" in
  -qa:--qf)
    if [[ "$3" == *VERSION* ]]; then
      if [[ "$3" == *EPOCHNUM* && "$3" == *ARCH* ]]; then
        printf 'base\t%s\t%s\t1\t%s\n' \
          "$(cat "$HOME/base-epoch" 2>/dev/null || printf 0)" \
          "$(cat "$HOME/base-state" 2>/dev/null || printf 1.0)" \
          "$(cat "$HOME/base-arch" 2>/dev/null || printf x86_64)"
        if [[ -f "$HOME/tree-state" ]]; then printf 'tree\t0\t2.0\t1\tx86_64\n'; fi
      else
        printf 'base\t%s-1\n' "$(cat "$HOME/base-state" 2>/dev/null || printf 1.0)"
        if [[ -f "$HOME/tree-state" ]]; then printf 'tree\t2.0-1\n'; fi
      fi
    else
      printf 'base\n'
      if [[ -f "$HOME/tree-state" ]]; then printf 'tree\n'; fi
    fi ;;
  -q:tree) [[ -f "$HOME/tree-state" ]] ;;
  *) exit 70 ;;
esac
''',
            'dnf': '''printf 'base\t'
if [[ "$*" == *'%{arch}'* ]]; then
  printf '%s\t' "$(cat "$HOME/base-dnf-arch" 2>/dev/null || printf x86_64)"
fi
if [[ -f "$HOME/base-auto" ]]; then printf 'dependency\n'; else printf 'user\n'; fi
if [[ -f "$HOME/tree-state" ]]; then
  if [[ "$*" == *'%{arch}'* ]]; then printf 'tree\tx86_64\tuser\n'; else printf 'tree\tuser\n'; fi
fi
''',
        }
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            for mutation in ('none', 'install-package', 'install-reason',
                             'remove-package', 'remove-reason'):
                with self.subTest(distro=distro, mutation=mutation):
                    action, _, kind = mutation.partition('-')
                    product = '''case "$1" in
  install)
    printf 2.0 > "$HOME/tree-state"
    printf '#!/bin/sh\\necho tree 2.0\\n' > "$OMG_QEMU_TEST_TREE_BINARY"
    chmod 755 "$OMG_QEMU_TEST_TREE_BINARY" ;;
  remove)
    rm -f "$HOME/tree-state" "$OMG_QEMU_TEST_TREE_BINARY" ;;
  *) exit 70 ;;
esac
'''
                    if mutation != 'none':
                        product += (f'if [[ "$1" == {action} ]]; then '
                                    + ('printf 9.0 > "$HOME/base-state"'
                                       if kind == 'package' else ': > "$HOME/base-auto"')
                                    + '; fi\n')
                    result, evidence, logs = self.run_inventory(
                        product, rows, native_commands=native, distro=distro,
                        tiers='container', allow_mutations=True, fake_tree_binary=True)
                    verdicts = [item['result'] for item in evidence]
                    expected = (['PASS', 'PASS'] if mutation == 'none' else
                                ['FAIL', 'PASS'] if action == 'install' else
                                ['PASS', 'FAIL'])
                    self.assertEqual(verdicts, expected, logs)
                    self.assertEqual(result.returncode, int(mutation != 'none'), result.stderr)
        for distro, marker, value in (
            ('debian', 'base-arch', 'arm64'),
            ('ubuntu', 'base-arch', 'arm64'),
            ('fedora', 'base-arch', 'aarch64'),
            ('fedora', 'base-epoch', '1'),
            ('fedora', 'base-dnf-arch', 'aarch64'),
        ):
            with self.subTest(distro=distro, marker=marker):
                product = f'''[[ "$1" == install ]] || exit 70
printf 2.0 > "$HOME/tree-state"
printf '#!/bin/sh\\necho tree 2.0\\n' > "$OMG_QEMU_TEST_TREE_BINARY"
chmod 755 "$OMG_QEMU_TEST_TREE_BINARY"
printf %s {shlex.quote(value)} > "$HOME/{marker}"
'''
                result, evidence, logs = self.run_inventory(
                    product, [rows[0]], native_commands=native, distro=distro,
                    tiers='container', allow_mutations=True, fake_tree_binary=True)
                self.assertEqual(evidence[0]['result'], 'FAIL', logs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('state changed outside tree',
                              logs['release-package-install-tree.log'])
        blocked, evidence, logs = self.run_inventory(
            'exit 70\n', [rows[0]], native_commands=native, distro='debian',
            tiers='container', allow_mutations=True, fake_tree_binary=True,
            home_files={'tree-state': b'2.0', 'tree-binary': b'preexisting'})
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertNotEqual(blocked.returncode, 0)
        failed_after_snapshot = dict(native)
        failed_after_snapshot['dpkg-query'] = native['dpkg-query'].replace(
            "if [[ \"$*\" == *'${Version}'* ]]; then",
            "if [[ \"$*\" == *'${Version}'* ]]; then\n"
            '  if [[ -f "$HOME/fail-next-snapshot" ]]; then\n'
            '    rm -f "$HOME/fail-next-snapshot"\n'
            '    exit 70\n'
            '  fi')
        after_snapshot, evidence, logs = self.run_inventory(
            '''[[ "$1" == install ]] || exit 70
printf 2.0 > "$HOME/tree-state"
printf '#!/bin/sh\\necho tree 2.0\\n' > "$OMG_QEMU_TEST_TREE_BINARY"
chmod 755 "$OMG_QEMU_TEST_TREE_BINARY"
: > "$HOME/fail-next-snapshot"
''', [rows[0]], native_commands=failed_after_snapshot, distro='debian',
            tiers='container', allow_mutations=True, fake_tree_binary=True)
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
        self.assertNotEqual(after_snapshot.returncode, 0)
        self.assertIn('native package after-state is unavailable',
                      logs['release-package-install-tree.log'])
        failed_cleanup = dict(native, sudo='exit 71\n')
        cleanup, evidence, logs = self.run_inventory(
            '''[[ "$1" == install ]] || exit 70
printf 2.0 > "$HOME/tree-state"
printf '#!/bin/sh\\necho tree 2.0\\n' > "$OMG_QEMU_TEST_TREE_BINARY"
chmod 755 "$OMG_QEMU_TEST_TREE_BINARY"
''', [rows[0]], native_commands=failed_cleanup, distro='debian',
            tiers='container', allow_mutations=True, fake_tree_binary=True)
        self.assertEqual(evidence[0]['result'], 'HARNESS_ERROR', logs)
        self.assertNotEqual(cleanup.returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'APT rollback oracle requires POSIX jq')
    def test_apt_rollback_requires_unique_native_history_and_tree_only_delta(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        functions = source[source.index('apt_tree_removal_id() {'):
                           source.index('check_apt_update_delta() {')]
        removal = {'id': '12345678-1234-1234-1234-123456789abc',
                   'transaction_type': 'Remove', 'success': True,
                   'changes': [{'name': 'tree', 'old_version': '2.0',
                                'new_version': None, 'source': 'apt'}]}
        restore = {'id': '87654321-1234-1234-1234-123456789abc',
                   'transaction_type': 'Install', 'success': True,
                   'changes': [{'name': 'tree', 'old_version': None,
                                'new_version': '2.0', 'source': 'rollback'}]}
        with tempfile.TemporaryDirectory() as directory:
            history = Path(directory) / 'history.json'

            def check(entries, command):
                history.write_text(json.dumps(entries), encoding='utf-8')
                return subprocess.run(
                    [shutil.which('bash'), '-c', functions + '\n' + command,
                     '_', str(history)], capture_output=True, text=True)

            selected = check([removal], 'apt_tree_removal_id "$1" 2.0')
            self.assertEqual(selected.returncode, 0, selected.stderr)
            self.assertEqual(selected.stdout.strip(), removal['id'])
            for entries in ([], [removal, removal],
                            [dict(removal, success=False)],
                            [dict(removal, changes=[dict(removal['changes'][0],
                                                         old_version='1.0')])],
                            [dict(removal, changes=[dict(removal['changes'][0],
                                                         source='local')])]):
                with self.subTest(entries=entries):
                    self.assertNotEqual(
                        check(entries, 'apt_tree_removal_id "$1" 2.0').returncode, 0)
            self.assertEqual(
                check([removal, restore], 'check_apt_tree_restoration "$1" 2.0').returncode, 0)
            for entries in ([removal], [dict(restore, changes=[dict(restore['changes'][0],
                                                                   new_version='9.0')])],
                            [restore, restore]):
                with self.subTest(restore_entries=entries):
                    self.assertNotEqual(
                        check(entries, 'check_apt_tree_restoration "$1" 2.0').returncode, 0)

            baseline = 'installed packages\nbase\t1.0\tinstall ok installed\ninstall reasons\nbase'
            tree = ('installed packages\nbase\t1.0\tinstall ok installed\n'
                    'tree\t2.0\tinstall ok installed\ninstall reasons\nbase\ntree')
            unrelated = tree.replace('base\t1.0', 'base\t2.0')
            reason_changed = tree.replace('install reasons\nbase\ntree',
                                          'install reasons\ntree')
            for after, expected in ((tree, 0), (unrelated, 1), (reason_changed, 1)):
                with self.subTest(after=after):
                    result = subprocess.run(
                        [shutil.which('bash'), '-c',
                         functions + '\ncheck_apt_tree_only_delta "$1" "$2"',
                         '_', baseline, after], capture_output=True, text=True)
                    self.assertEqual(result.returncode, expected, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_container_run_detached_requires_exact_fake_engine_argv(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith('container-run-detached-argv\t')]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].split('\t')[8], 'container-run-argv')
        run = ('podman run --detach --name smoke -w /tmp/omg-smoke -e SMOKE=1 '
               '-v "$(dirname "$OMG_QEMU_ENGINE_CAPTURE"):/tmp/omg-smoke" '
               '-- debian:bookworm sh -c "printf smoke"\n')
        base = ('[[ "$1:$2" == container:run ]] || exit 95\n'
                'podman --version >/dev/null\n' + run)
        variants = (
            ('correct', base, 'PASS'),
            ('no engine call', 'echo fake-container-id\n', 'FAIL'),
            ('missing detach', base.replace('run --detach', 'run'), 'FAIL'),
            ('unexpected remove', base.replace('run --detach', 'run --detach --rm'), 'FAIL'),
            ('unexpected tty', base.replace('run --detach', 'run --detach -it'), 'FAIL'),
            ('wrong name', base.replace('--name smoke', '--name other'), 'FAIL'),
            ('wrong env', base.replace('SMOKE=1', 'SMOKE=0'), 'FAIL'),
            ('wrong mount', base.replace(':/tmp/omg-smoke', ':/tmp/wrong'), 'FAIL'),
            ('wrong workdir', base.replace('-w /tmp/omg-smoke', '-w /tmp/wrong'), 'FAIL'),
            ('wrong image', base.replace('debian:bookworm', 'ubuntu:24.04'), 'FAIL'),
            ('wrong command', base.replace('printf smoke', 'printf wrong'), 'FAIL'),
            ('duplicate run', base + run, 'FAIL'),
        )
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            for label, product, expected in variants:
                with self.subTest(distro=distro, variant=label):
                    result, evidence, logs = self.run_inventory(product, rows, distro=distro)
                    self.assertEqual(evidence[0]['result'], expected, logs)
                    self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    def test_container_shell_and_build_require_exact_fake_engine_argv(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        for case, operation, correct, faults in (
            ('container-shell-argv', 'shell',
             'podman run --rm -it --name "$(basename "$PWD")-dev" -w /tmp '
             '-e TERM=xterm-256color -e SMOKE=1 -v "$PWD:/app" '
             '-v "$PWD:/tmp/omg-smoke" -- debian:bookworm /bin/bash\n',
             ('--rm ', '-it ', 'SMOKE=1', ':/app', 'debian:bookworm', '/bin/bash')),
            ('container-build-argv', 'build',
             'podman build -f Dockerfile -t smoke:latest --no-cache '
             '--build-arg SMOKE=1 --target dev -- "$PWD"\n',
             ('-f Dockerfile ', '-t smoke:latest ', '--no-cache ',
              '--build-arg SMOKE=1 ', '--target dev ', '"$PWD"')),
        ):
            rows = [line for line in inventory.splitlines()
                    if line.startswith(case + '\t')]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].split('\t')[8], case)
            prefix = (f'[[ "$1:$2" == container:{operation} ]] || exit 95\n'
                      'podman --version >/dev/null\n')
            variants = [('correct', prefix + correct, 'PASS'),
                        ('no engine call', 'echo claimed-success\n', 'FAIL'),
                        ('duplicate engine call', prefix + correct + correct, 'FAIL')]
            for omitted in faults:
                self.assertIn(omitted, correct)
                variants.append((f'omit {omitted}', prefix + correct.replace(omitted, '', 1), 'FAIL'))
            for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
                for label, product, expected in variants:
                    with self.subTest(case=case, distro=distro, variant=label):
                        result, evidence, logs = self.run_inventory(product, rows, distro=distro)
                        self.assertEqual(evidence[0]['result'], expected, logs)
                        self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_diff_rows_require_the_requested_missing_lockfile_diagnostic(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith(('diff\t', 'diff-from\t'))]
        self.assertEqual(len(rows), 2)
        for row in rows:
            case = row.split('\t')[0]
            with self.subTest(case=case):
                self.assertEqual(row.split('\t')[8], 'local:' + case)
                for diagnostic, expected in (
                    ('unrelated failure', 'FAIL'),
                    ('Failed to inspect lockfile other.lock', 'FAIL'),
                    ('Failed to inspect lockfile missing.lock', 'PASS'),
                ):
                    with self.subTest(diagnostic=diagnostic):
                        product = f'printf "%s\\n" {shlex.quote(diagnostic)} >&2\nexit 1\n'
                        result, evidence, logs = self.run_inventory(product, [row])
                        self.assertEqual(evidence[0]['result'], expected, logs)
                        self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_workspace_init_and_add_require_persisted_workspace_state(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith(('workspace-init\t', 'workspace-add\t'))]
        self.assertEqual(len(rows), 2)
        self.assertEqual([row.split('\t')[8] for row in rows],
                         ['workspace-init-state', 'workspace-add-state'])
        # Retain the historical metadata oracle's mutants as well as the full
        # current workspace-state fixture exercised below.
        rows = [row.replace('workspace-init-state', 'workspace-initialized')
                   .replace('workspace-add-state', 'workspace-project-added') for row in rows]
        initialize = ('if [[ "$2" == init ]]; then\n'
                      '  printf \'name = "smoke"\\ncreated_at = "2026-09-27T00:00:00Z"\\n\' > omg-workspace.toml\n'
                      'fi\n')
        add = ('if [[ "$2" == add ]]; then\n'
               '  printf \'[projects.fixture]\\npath = "."\\n\' >> omg-workspace.toml\n'
               'fi\n')
        for product, expected in (
            (':\n', ['FAIL', 'BLOCKED']),
            ('echo "Created omg-workspace.toml"\n', ['FAIL', 'BLOCKED']),
            (initialize.replace('name = "smoke"', 'name = "wrong"') + add, ['FAIL', 'BLOCKED']),
            (initialize, ['PASS', 'FAIL']),
            (initialize + add, ['PASS', 'PASS']),
        ):
            with self.subTest(expected=expected):
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], expected, logs)
                self.assertEqual(result.returncode, int(expected != ['PASS', 'PASS']), result.stderr)

    def test_workspace_list_and_remove_reject_false_green_results(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith(('workspace-init\t', 'workspace-add\t',
                                    'workspace-list\t', 'workspace-remove\t'))]
        self.assertEqual(len(rows), 4)
        self.assertEqual([row.split('\t')[8] for row in rows[-2:]],
                         ['workspace-list-state', 'workspace-remove-state'])
        rows = [row.replace('workspace-init-state', 'workspace-initialized')
                   .replace('workspace-add-state', 'workspace-project-added')
                   .replace('workspace-list-state', 'workspace-project-listed')
                   .replace('workspace-remove-state', 'workspace-project-removed') for row in rows]
        product = '''case "$2" in
  init) printf 'name = "smoke"\\ncreated_at = "2026-09-27T00:00:00Z"\\n' > omg-workspace.toml ;;
  add) printf '[projects.fixture]\\npath = "."\\n' >> omg-workspace.toml ;;
  list) printf 'OMG Workspace: smoke\\n  1. fixture → .\\n' ;;
  remove) sed -i '/^\\[projects.fixture\\]/,$d' omg-workspace.toml
          printf "✓ Removed project 'fixture'\\n" ;;
esac
'''
        for label, altered, expected in (
            ('correct', product, ['PASS'] * 4),
            ('list silent', product.replace("list) printf 'OMG Workspace: smoke\\n  1. fixture → .\\n' ;;",
                                            'list) : ;;'), ['PASS', 'PASS', 'FAIL', 'PASS']),
            ('list wrong project', product.replace('1. fixture → .', '1. other → .'),
             ['PASS', 'PASS', 'FAIL', 'PASS']),
            ('list invented extra project', product.replace('1. fixture → .\\n',
                                                            '1. fixture → .\\n  2. other → .\\n'),
             ['PASS', 'PASS', 'FAIL', 'PASS']),
            ('remove silent', product.replace("remove) sed -i '/^\\[projects.fixture\\]/,$d' omg-workspace.toml",
                                              'remove) :'), ['PASS', 'PASS', 'PASS', 'FAIL']),
            ('remove wrong report', product.replace("Removed project 'fixture'", "Removed project 'other'"),
             ['PASS', 'PASS', 'PASS', 'FAIL']),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(altered, rows)
                self.assertEqual([row['result'] for row in evidence], expected, logs)
                self.assertEqual(result.returncode, int('FAIL' in expected), result.stderr)

    def test_container_init_requires_scaffold_and_final_secret_exclusions(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        row = next(line for line in inventory.splitlines() if line.startswith('container-init\t'))
        self.assertEqual(row.split('\t')[8], 'container-init-scaffold')
        product = '''if [[ "$1:$2:$3:$4" != container:init:--base:debian:bookworm ]]; then exit 9; fi
cat > Dockerfile.omg <<'DOCKERFILE'
FROM debian:bookworm

RUN apt-get update && apt-get install -y \\
    curl wget git build-essential ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
CMD ["/bin/bash"]
DOCKERFILE
for ignore in .dockerignore Dockerfile.omg.dockerignore .containerignore; do
cat >> "$ignore" <<'IGNORE'
# added by omg container init
.git
.env
.env.*
!.env.example
*.pem
*.key
id_rsa*
.omg/
IGNORE
done
printf '  ✓ Created Dockerfile.omg\\n│ Base image: debian:bookworm │\\n'
'''
        for label, altered, expected in (
            ('correct', product, 'PASS'),
            ('missing Dockerfile', product.replace('cat > Dockerfile.omg', 'cat > ignored'), 'FAIL'),
            ('wrong base', product.replace('FROM debian:bookworm', 'FROM ubuntu:24.04'), 'FAIL'),
            ('missing build dependencies', product.replace('curl wget git build-essential ca-certificates',
                                                           'curl wget git'), 'FAIL'),
            ('missing root protection', product.replace(
                'for ignore in .dockerignore Dockerfile.omg.dockerignore .containerignore; do',
                'for ignore in Dockerfile.omg.dockerignore .containerignore; do'), 'FAIL'),
            ('missing BuildKit protection', product.replace(
                'for ignore in .dockerignore Dockerfile.omg.dockerignore .containerignore; do',
                'for ignore in .dockerignore .containerignore; do'), 'FAIL'),
            ('missing Podman protection', product.replace(
                'for ignore in .dockerignore Dockerfile.omg.dockerignore .containerignore; do',
                'for ignore in .dockerignore Dockerfile.omg.dockerignore; do'), 'FAIL'),
            ('late exception', product + "printf '!*.key\\n' >> .dockerignore\n", 'FAIL'),
            ('late override exception', product + "printf '!*.key\\n' >> Dockerfile.omg.dockerignore\n", 'FAIL'),
            ('lost user negations', product + "sed -i '1,2d' .containerignore\n", 'FAIL'),
            ('extra build command', product.replace('WORKDIR /app', 'RUN echo unexpected\nWORKDIR /app'), 'FAIL'),
            ('silent output', product.replace("printf '  ✓ Created Dockerfile.omg\\n│ Base image: debian:bookworm │\\n'",
                                               ':'), 'FAIL'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(altered, [row])
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_arch_update_rows_require_bounded_native_fixture_receipt(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith(('update-fast\t', 'update-turbo\t'))]
        product = (
            '[[ "$1" == update && "$3" == --yes ]] || exit 9\n'
            'case "$2" in\n'
            '  --fast) printf "Fast System Update\\nSynced\\nUpgraded 1 package\\n" ;;\n'
            '  --turbo) printf "TURBO System Update\\ncached, no sync\\nUpgraded 1 package\\n" ;;\n'
            '  *) exit 9 ;;\n'
            'esac\n'
        )
        sudo = '[[ "$1" != -n ]] || shift\nexec "$@"\n'
        for row in rows:
            mode = row.split('\t', 1)[0].removeprefix('update-')
            for after_marker in (True, False):
                with self.subTest(mode=mode, after_marker=after_marker):
                    fixture = (
                        '#!/usr/bin/env bash\n'
                        'mode=$1; binary=$2\n'
                        'printf "OMG_QEMU_UPDATE_FIXTURE:before:%s:1\\n" "$mode"\n'
                        '"$binary" update "--$mode" --yes\n'
                    )
                    if after_marker:
                        fixture += 'printf "OMG_QEMU_UPDATE_FIXTURE:after:%s:2:native-upgrade\\n" "$mode"\n'
                    result, evidence, logs = self.run_inventory(
                        product, [row], distro='arch', tiers='container',
                        allow_mutations=True, native_commands={'sudo': sudo},
                        home_files={'qemu-arch-update-fixture.sh': fixture.encode()})
                    self.assertEqual(evidence[0]['result'], 'PASS' if after_marker else 'FAIL', logs)
                    self.assertEqual(result.returncode, 0 if after_marker else 1, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_apt_fast_and_turbo_require_a_native_version_upgrade(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if line.startswith(('update-fast\t', 'update-turbo\t'))]
        self.assertEqual(len(rows), 2)
        fast_row = next(row for row in rows if row.startswith('update-fast\t'))
        pin_dir = Path(tempfile.mkdtemp(prefix='omg-qemu-apt-pin-test-'))
        self.addCleanup(shutil.rmtree, pin_dir)
        pin = pin_dir / 'omg-qemu-tree.pref'
        quoted_pin = shlex.quote(str(pin))
        native = {
            'sudo': f'''[[ "$1" != -n ]] || shift
pin={quoted_pin}
target=/etc/apt/preferences.d/omg-qemu-tree.pref
case "$1" in
  dpkg) exec "$@" ;;
  test)
    [[ "${{@: -1}}" == "$target" ]] || exit 70
    case "$2:$3" in
      '!:-e') [[ ! -e "$pin" ]] ;;
      '!:-L') [[ ! -L "$pin" ]] ;;
      *) exit 70 ;;
    esac ;;
  install)
    [[ "$2:$3:$4:$5:$6:$7" == '-o:root:-g:root:-m:0644' && "${{@: -1}}" == "$target" ]] || exit 70
    /usr/bin/install -m 0644 "${{@: -2:1}}" "$pin" ;;
  stat)
    [[ "${{@: -1}}" == "$target" && -f "$pin" ]] || exit 70
    printf '0:0:644\\n' ;;
  rm)
    [[ "$2:$3:$4" == "-f:--:$target" ]] || exit 70
    /usr/bin/rm -f -- "$pin" ;;
  *) exit 70 ;;
esac
''',
            'dpkg-deb': '''case "$1" in
  --raw-extract) mkdir -p "$3/DEBIAN"; printf 'Package: tree\\nVersion: 2.0\\n' > "$3/DEBIAN/control" ;;
  --build) : > "$3" ;;
  *) exit 70 ;;
esac
''',
            'dpkg': '''case "$1" in
  --install) printf 0.0.1 > "$HOME/tree-state" ;;
  --purge) rm -f "$HOME/tree-state" ;;
  --compare-versions) [[ "$2" == 2.0 && "$3" == gt && "$4" == 0.0.1 ]] ;;
  *) exit 70 ;;
esac
''',
            'dpkg-query': '''if [[ "$*" == *'${Package}'* && "$*" == *'${Version}'* ]]; then
  printf 'base\\tinstall ok installed\\t%s\\n' "$(cat "$HOME/base-state" 2>/dev/null || printf 1.0)"
  if [[ -f "$HOME/tree-state" ]]; then printf 'tree\\tinstall ok installed\\t%s\\n' "$(cat "$HOME/tree-state")"; fi
elif [[ "$*" == *'${Package}'* ]]; then
  printf 'base\\tinstall ok installed\\n'
  if [[ -f "$HOME/tree-state" ]]; then printf 'tree\\tinstall ok installed\\n'; fi
elif [[ -f "$HOME/tree-state" ]]; then
  printf 'install ok installed\\t%s\\n' "$(cat "$HOME/tree-state")"
else
  exit 1
fi
''',
            'apt-mark': '''[[ "$1" == showmanual ]] || exit 70
if [[ ! -f "$HOME/base-auto" ]]; then printf 'base\\n'; fi
if [[ -f "$HOME/tree-state" ]]; then printf 'tree\\n'; fi
''',
            'apt-cache': 'printf "tree:\\n  Candidate: 2.0\\n"\n',
            'apt-get': f'''[[ "$1" == -s && "$2" == upgrade ]] || exit 70
pin={quoted_pin}
[[ -f "$pin" ]] || exit 71
grep -Fxq 'Package: tree:any' "$pin" || exit 72
grep -Fxq 'Package: *:any' "$pin" || exit 72
grep -Fxq 'Pin: release *' "$pin" || exit 72
grep -Fxq 'Pin-Priority: -1' "$pin" || exit 72
printf 'Inst tree [0.0.1] (2.0 local)\\n'
''',
        }
        for row in rows:
            case = row.split('\t')[0]
            mode = case.removeprefix('update-')
            title = 'Fast System Update\nSynced\n' if mode == 'fast' else 'TURBO System Update\nTurbo upgrade\n'
            for version, expected in (('0.0.1', 'FAIL'), ('9.9', 'FAIL'), ('2.0', 'PASS')):
                with self.subTest(case=case, version=version):
                    product = (f'[[ -f {quoted_pin} ]] || exit 73\n'
                               f'printf %s {shlex.quote(title + "Upgraded 1 packages\n")}\n'
                               f'printf %s {shlex.quote(version)} > "$HOME/tree-state"\n')
                    result, evidence, logs = self.run_inventory(
                        product, [row], native_commands=native,
                        home_files={'tree_fixture.deb': b'fixture'},
                        distro='debian', tiers='container', allow_mutations=True)
                    self.assertEqual(evidence[0]['result'], expected, logs)
                    self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)
                    self.assertFalse(pin.exists(), 'APT pin survived a completed row')
        message = 'Fast System Update\nSynced\nUpgraded 1 packages\n'
        product = (f'[[ -f {quoted_pin} ]] || exit 73\n'
                   f'printf %s {shlex.quote(message)}\n'
                   'printf 2.0 > "$HOME/tree-state"\n'
                   'printf 2.0 > "$HOME/base-state"\n')
        result, evidence, logs = self.run_inventory(
            product, [fast_row], native_commands=native,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
        self.assertIn('APT update changed installed packages other than tree', logs['update-fast.log'])
        self.assertFalse(pin.exists(), 'extra-package rejection leaked the pin')
        result, evidence, logs = self.run_inventory(
            f'[[ -f {quoted_pin} ]] || exit 73\n'
            'printf "Fast System Update\\nSynced\\nUpgraded 1 package\\n"\n'
            'printf 2.0 > "$HOME/tree-state"\n'
            ': > "$HOME/base-auto"\n',
            [fast_row], native_commands=native,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
        self.assertIn('install reasons', logs['update-fast.log'])
        self.assertFalse(pin.exists(), 'reason-change rejection leaked the pin')
        # A pre-existing native tree is a setup conflict, never this fixture's
        # package to purge. The host may independently have /usr/bin/tree.
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'baseline-purged'
            guarded = dict(native)
            guarded['dpkg'] = native['dpkg'].replace(
                '--purge) rm -f "$HOME/tree-state" ;;',
                f'--purge) : > {shlex.quote(str(marker))}; rm -f "$HOME/tree-state" ;;')
            result, evidence, logs = self.run_inventory(
                ':\n', [rows[0]], native_commands=guarded,
                home_files={'tree_fixture.deb': b'fixture', 'tree-state': b'2.0'},
                distro='debian', tiers='container', allow_mutations=True)
            self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
            self.assertFalse(marker.exists(), 'setup failure purged the pre-existing package')
            self.assertFalse(pin.exists(), 'setup conflict installed an APT pin')
        failing_simulation = dict(native)
        failing_simulation['apt-get'] = native['apt-get'] + 'exit 43\n'
        result, evidence, logs = self.run_inventory(
            ':\n', [rows[0]], native_commands=failing_simulation,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertFalse(pin.exists(), 'APT simulation failure leaked the pin')
        extra_upgrade = dict(native)
        extra_upgrade['apt-get'] = native['apt-get'] + "printf 'Inst openssl [1.0] (2.0 local)\\n'\n"
        result, evidence, logs = self.run_inventory(
            'exit 74\n', [rows[0]], native_commands=extra_upgrade,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertFalse(pin.exists(), 'unrelated-upgrade refusal leaked the pin')
        partial_install = dict(native)
        partial_install['sudo'] = native['sudo'].replace(
            '/usr/bin/install -m 0644 "${@: -2:1}" "$pin" ;;',
            '/usr/bin/install -m 0644 "${@: -2:1}" "$pin"; exit 75 ;;')
        result, evidence, logs = self.run_inventory(
            'exit 74\n', [rows[0]], native_commands=partial_install,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertFalse(pin.exists(), 'partial pin installation leaked the pin')
        failed_setup_cleanup = dict(partial_install)
        failed_setup_cleanup['sudo'] = partial_install['sudo'].replace(
            '/usr/bin/rm -f -- "$pin" ;;', 'exit 76 ;;')
        result, evidence, logs = self.run_inventory(
            'exit 74\n', [fast_row], native_commands=failed_setup_cleanup,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertIn('APT setup cleanup failed', logs['update-fast.log'])
        self.assertTrue(pin.exists(), 'setup cleanup failure was not exercised')
        pin.unlink()
        pin.write_text('pre-existing policy\n', encoding='utf-8')
        result, evidence, logs = self.run_inventory(
            'exit 74\n', [rows[0]], native_commands=native,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertEqual(pin.read_text(encoding='utf-8'), 'pre-existing policy\n')
        pin.unlink()
        failed_cleanup = dict(native)
        failed_cleanup['sudo'] = native['sudo'].replace(
            '/usr/bin/rm -f -- "$pin" ;;', 'exit 76 ;;')
        result, evidence, logs = self.run_inventory(
            f'[[ -f {quoted_pin} ]] || exit 73\n'
            'printf "Fast System Update\\nSynced\\nUpgraded 1 package\\n"\n'
            'printf 2.0 > "$HOME/tree-state"\n',
            [fast_row], native_commands=failed_cleanup,
            home_files={'tree_fixture.deb': b'fixture'},
            distro='debian', tiers='container', allow_mutations=True)
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertIn('APT update fixture cleanup failed', logs['update-fast.log'])
        self.assertTrue(pin.exists(), 'cleanup failure was not exercised')
        pin.unlink()

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_invalid_runtime_uninstall_reaches_runtime_dispatch(self):
        row = next(line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
                   if line.startswith('use-uninstall\t'))
        product = '''if [[ "$*" == 'use --uninstall invalid-runtime 1.0.0' ]]; then
echo "Error: Unsupported runtime 'invalid-runtime'" >&2
else
echo 'Error: --uninstall requires a version: omg use <runtime> <version> --uninstall' >&2
fi
exit 1
'''
        result, evidence, logs = self.run_inventory(product, [row])
        self.assertEqual(evidence[0]['result'], 'PASS', f'{result.stdout}\n{result.stderr}\n{logs}')

    def test_local_audit_fixture_uses_published_v1_chain(self):
        owner = runpy.run_path(str(ROOT / 'scripts/qemu-local-oracle.py'))
        entries = owner['audit_entries']()
        # Independent SHA-256 vectors for the published ff01 domain and nine
        # u64-framed fields, including the empty metadata field. These bind the
        # actual wire format without letting the fixture verify its own hashes.
        hashes = [
            'd3df81db57ea65ffc64aa04a6e8bb82a2c9e266d16d2cc1c0e6de686d381376c',
            '817dd3e64749aebb815b77fc9a33b4e259973f623223f2ee0911824c59be5516',
            'a3234184a2fab63e94b4ecd55fa3100d62db224f5e56812fb9dac2f5fe1b3b9f',
            '5c2cbb9084fedafb5a0e794281c8611fdef6c4c55d0c9ee4ecaeacc85d938d6a',
        ]
        self.assertEqual(len(entries), len(hashes))
        for index, (entry, digest) in enumerate(zip(entries, hashes)):
            with self.subTest(index=index):
                self.assertEqual(entry.get('hash_version'), 1)
                self.assertEqual(entry['hash'], digest)
                self.assertEqual(entry['prev_hash'], 'genesis' if index == 0 else hashes[index - 1])
                self.assertNotIn('metadata', entry)
                self.assertEqual(set(entry), {'id', 'timestamp', 'event_type', 'severity', 'user',
                                             'resource', 'description', 'prev_hash', 'hash_version', 'hash'})

    @staticmethod
    def local_fixture_product():
        source = (ROOT / 'src/cli/tool.rs').read_text()
        start = source.index('const TOOL_REGISTRY:')
        records = re.findall(r'\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,?\s*\)', source[start:source.index('];', start)])
        return 'python3 - "$@" <<\'PY\'\nREGISTRY = ' + repr(records) + '\n' + r'''
import datetime, hashlib, json, os, pathlib, pwd, subprocess, time, tomllib
mutant = 'none'
before = json.loads(pathlib.Path('.qemu-local-before.json').read_text())
case = before['case']
data, config, home = (pathlib.Path(os.environ[name]) for name in ('OMG_DATA_DIR','OMG_CONFIG_DIR','HOME'))
def text(path): return pathlib.Path(path).read_text()
def save(path, value): pathlib.Path(path).write_text(value)
def golden(items):
    lines=[]
    for item in items:
        lines += ['[[templates]]', 'name = '+json.dumps(item['name']), 'created_at = '+str(item['created_at']), 'packages = '+json.dumps(item['packages']), '[templates.runtimes]']
        lines += [key+' = '+json.dumps(value) for key,value in item['runtimes'].items()]
    save(config/'golden-paths.toml','\n'.join(lines)+'\n')
missing_account='No dashboard account linked. Run `omg account link --token-stdin` to sync usage to the dashboard.'
refusals={'diff':'Failed to inspect lockfile missing.lock','diff-from':'Failed to inspect lockfile missing.lock',
    'audit-export':'Absolute paths not allowed','audit-export-flags':'Absolute paths not allowed',
    'enterprise-audit-export':'Absolute paths not allowed','rollback':'No history entries available for rollback',
    'rollback-yes':'No history entries available for rollback','env-export-missing-lock':'Failed to inspect lockfile omg.lock',
    'account-link-stdin':'Dashboard token is empty','workspace-run':"1 project(s) failed to run 'true'",
    'workspace-check':'1 project(s) need attention, 0 failed to check (of 1 total)',
    'team-compliance-export':"No compliance data is available to export to '"+str(pathlib.Path.cwd()/'compliance.json')+"'; compliance evidence requires an evaluated report"}
for name in ['team-members','team-activity','fleet-status','enterprise-reports','enterprise-reports-type','enterprise-policy-show','enterprise-policy-scope']: refusals[name]=missing_account
if case == 'metrics':
    print('Error: Daemon not running. Performance metrics require the daemon (start it with: omg daemon): Failed to connect to daemon at '+os.environ['OMG_SOCKET_PATH'],file=__import__('sys').stderr); raise SystemExit(1)
if case in refusals:
    if case == 'workspace-run': print("'omg run true' in '.' exited with code 1")
    if case == 'workspace-check': print('→ fixture\n  ⚠ needs attention')
    prefix='Failed to fetch team members for enterprise report: ' if case.startswith('enterprise-reports') else ''
    print('Error: '+prefix+refusals[case],file=__import__('sys').stderr); raise SystemExit(1)
if case == 'snapshot-list':
    rows=json.loads(text(data/'snapshots/index.json'))['snapshots']
    print('OMG Snapshots')
    for item in reversed(rows): print(item['id'],datetime.datetime.fromtimestamp(item['created_at'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M'),item['hash'][:8],item['message'])
    print(('99' if mutant=='count' else '2')+' snapshots total')
elif case in ('list','list-available','which','hook-env'):
    version='99.0.0' if mutant=='version' else '24.21.0'
    if case=='which': print('node '+version)
    elif case=='hook-env': print("export PATH='"+str(data/'versions/node'/version/'bin')+"':\"${_OMG_PATH_BASE:-$PATH}\"")
    elif case=='list': print('OMG Installed runtime versions\n  • node 22.16.0\n  • node '+version+' (active)\n  • python 3.12.14 (active)')
    else: print('OMG Installed runtime versions\n  • Node.js '+version+'\n  • Python 3.12.14')
elif case=='hooks-status':
    print('OMG Git Hooks Status\n  ● pre-commit - installed (unrecognized or modified)')
    for name in ['post-checkout','post-merge']:
        installed=pathlib.Path('.git/hooks',name).exists()
        print(('  ● ' if installed else '  ○ ')+name+' - '+('installed (OMG)' if installed else 'not installed'))
    print('Hooks directory:',pathlib.Path.cwd()/'.git/hooks')
elif case=='hooks-run':
    if mutant!='noop': subprocess.run(['.git/hooks/pre-commit'],check=True)
    print('OMG Running pre-commit hook...\n✓ Hook completed successfully')
elif case=='hook-uninstall':
    rc=home/'.bashrc'
    if mutant!='noop':
        save(home/'.bashrc.omg-backup',text(rc));save(rc,'alias keep="echo preserved"\nexport KEEP_VALUE=42\n')
    print('Shell integration removed (rc file backed up with .omg-backup)')
elif case=='workspace-diff': print('OMG Comparing workspace environments vs main\n→ fixture\n  No omg.lock file')
elif case=='config':
    print('OMG Configuration\ntelemetry.enabled = false\naur.build_concurrency = '+('99' if mutant=='count' else '3')+'\naur.enable_ccache = false\nconfig_file = '+str(config/'config.toml')+'\ndata_dir = '+str(data))
elif case=='privacy': print('OMG Privacy Settings\nTelemetry: '+('Enabled' if mutant=='count' else 'Disabled'))
elif case=='account-status': print('OMG Dashboard account\nStatus: '+('Linked' if mutant=='count' else 'Not linked'))
elif case=='account-unlink':
    if mutant!='noop': (data/'license.json').unlink()
    print('Dashboard account unlinked.\nLocal commands are unchanged.')
elif case=='team-init':
    member=pwd.getpwuid(os.getuid()).pw_name; now=int(time.time())
    team={'team_id':'smoke/team','name':'Wrong Team' if mutant=='identity' else 'Smoke Team','member_id':member,'auto_push':False}
    pathlib.Path('.omg').mkdir(exist_ok=True)
    save('.omg/team.toml','\n'.join(key+' = '+('false' if value is False else json.dumps(value)) for key,value in team.items())+'\n')
    status={'format_version':1,'config':dict(team,remote_url=None),'lock_hash':'','members':[{'id':member,'name':member,'env_hash':'','last_sync':now,'in_sync':True,'drift_summary':None}],'updated_at':now}
    save('.omg/team-status.json',json.dumps(status))
    for name in ['post-checkout','post-merge']:
        path=pathlib.Path('.git/hooks')/name;save(path,'#!/bin/sh\n# OMG Team Sync Hook\nif [ -f omg.lock ]; then\n  \"'+os.environ['OMG_QEMU_EXECUTABLE']+'\" env check 2>/dev/null || true\nfi\n');path.chmod(0o755)
    print('Team workspace initialized!\nTeam ID: smoke/team\nName: Smoke Team')
elif case=='team-roles-list':
    print('Team Roles\nAvailable roles\nadmin - Full access (push, policy, members)\nlead - Can push to team lock, manage policies\ndeveloper - Can pull, cannot push without approval\nreadonly - Can only view status')
elif case.startswith('team-golden-'):
    items=tomllib.loads(text(config/'golden-paths.toml'))['templates']
    if case=='team-golden-list':
        print('Golden Path Templates\n'+str(len(items))+' custom template(s)')
        for item in items: print(item['name']+' - runtimes: '+json.dumps(list(item['runtimes']))+', packages: '+str(len(item['packages'])))
    elif case=='team-golden-delete':
        if mutant!='noop': golden([item for item in items if item['name']!='smoke'])
        print("Deleted template 'smoke'")
    else:
        selected='flagged' if case.endswith('flags') else 'smoke'
        item={'name':selected,'created_at':int(time.time()),'packages':['ripgrep'] if selected=='flagged' else [],'runtimes':{'node':'20','python':'3.12'} if selected=='flagged' else {}}
        if mutant=='version': item['runtimes']['node']='99'
        golden([value for value in items if value['name']!=selected]+[item]);print("Golden path '"+selected+"' created!")
        if selected=='flagged': print('Node: 20\nPython: 3.12\nPackages: ripgrep')
elif case.startswith('team-compliance'):
    print('Compliance Status\nNo local data\nCompliance scoring is not computed locally; view evaluated results on the dashboard')
    if case.endswith('enforce'): print('Enforcement mode requested, but no compliance evaluation engine exists locally; nothing can be enforced yet')
elif case.startswith('tool-'):
    if case=='tool-list':
        print('OMG Installed Tools:')
        for link in sorted((data/'bin').iterdir()):
            if link.is_symlink(): print('  '+link.name+' points to -> '+os.readlink(link))
    elif case=='tool-search':
        print("Searching for 'rip'...\nFound "+('99' if mutant=='count' else '5')+" tools:")
        for name,source,description,category in REGISTRY:
            if any('rip' in value.lower() for value in (name,description,category)): print(name+' ['+category+'] via '+source.split(':')[0]+'\n'+description)
    else:
        print('OMG Tool Registry')
        for category in sorted({item[3] for item in REGISTRY}):
            rows=[item for item in REGISTRY if item[3]==category];print('  ['+category+'] ('+str(len(rows))+' tools)')
            for name,source,description,_ in rows: print('    '+name+' ('+('wrong' if mutant=='manager' else source.split(':')[0])+') - '+description)
        print('Total: 59 tools available')
elif case.startswith('audit-'):
    if case=='audit-policy': print('OMG Security Policy Status\nMinimum Grade: VERIFIED (PGP/Checksum)\nAUR Allowed: No\nPGP Required: '+('No' if mutant=='count' else 'Yes')+'\nBanned Packages: fixture-banned\nAllowed Licenses: MIT Apache-2.0')
    elif case=='audit-verify': print('Local audit chain consistency verified\nTotal: '+('99' if mutant=='count' else '4')+' entries\nValid: 4 entries\nChain: Internally consistent; not authenticated\nThis check does not prove authenticity or completeness.\nLog Path: '+str(data/'audit/audit.jsonl'))
    else:
        entries=[json.loads(line) for line in text(data/'audit/audit.jsonl').splitlines()]
        entries.reverse()
        if case=='audit-log-flags':
            selected=entries if mutant=='filter' else [entry for entry in entries if entry['severity'] in ('error','critical')][:3]
            path=pathlib.Path('audit-log-export.json');save(path,json.dumps(selected));path.chmod(0o600);print('OMG Exporting audit log to '+str(pathlib.Path.cwd()/path)+'...\n✓ Export successful')
        else:
            entries=entries if mutant=='filter' else entries[:3]
            print('OMG Security Audit Log')
            for entry in entries: print(entry['timestamp']+' ['+entry['severity'].upper()+'] PackageInstall - '+entry['description']+'\nResource: '+entry['resource'])
            print('Showing '+str(len(entries))+' of '+str(len(entries))+' entries')
elif case.startswith('history'):
    entries=list(reversed(json.loads(text(data/'history.json'))))
    if case=='history-flags' and mutant!='filter': entries=[entry for entry in entries if entry['transaction_type']=='Install' and 'pacman' in entry['changes'][0]['name'] and entry['timestamp'].startswith('2025')]
    print('OMG Transaction History ('+('filtered' if case=='history-flags' else 'last 3')+')')
    for entry in entries[:3]:
        print('✓ '+entry['timestamp']+' ['+entry['id'][:8]+'] - '+entry['transaction_type']+' (1 changes)')
        for change in entry['changes']: print('→ '+change['name']+' '+change['old_version']+' → '+change['new_version'])
elif case=='stats': print('OMG Usage Statistics\nTime Saved: 1.0min\nTotal Commands: '+('99' if mutant=='count' else '37')+'\nQueries Today: 3\nQueries This Month: 9\nMost Used Commands:\n→ search (21x)\n→ list (16x)')
elif case=='init':
    if mutant!='skipped':
        packages=before['packages']; runtimes={'node':'24.21.0','python':'3.12.14'}
        payload=''.join(name+':'+version+';' for name,version in sorted(runtimes.items()))+''.join(name+';' for name in packages)
        save('omg.lock','schema_version = 1\npackages = '+json.dumps(packages)+'\ntimestamp = '+str(int(time.time()))+'\nhash = "'+hashlib.sha256(payload.encode()).hexdigest()+'"\n[runtimes]\nnode = "24.21.0"\npython = "3.12.14"\n')
    print('OMG Setting up with defaults...\n→ Shell hook: skipped\n→ Daemon setup: skipped\n→ Capturing environment... '+('(skipped: unrelated permission denied)' if mutant=='skipped' else '✓')+'\n✓ Setup complete!')
''' + '\nPY\n'

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_local_family_contracts_accept_matching_output_and_state(self):
        rows = []
        for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()[1:]:
            fields = line.split('\t')
            if fields[8] == 'local:' + fields[0]:
                rows.append('\t'.join(fields))
        self.assertEqual(len(rows), 52)
        rows = self.rows_with_prerequisites(rows)
        result, evidence, logs = self.run_inventory(self.local_fixture_with_workspace(), rows, native_commands={'pacman': 'printf "fixture-package\\n"\n'})
        self.assertEqual([row['result'] for row in evidence], ['PASS'] * len(rows),
                         f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_local_family_contracts_reject_wrong_values_and_noop_mutations(self):
        mutations = {'snapshot-list': 'count', 'list': 'version', 'list-available': 'version',
                     'which': 'version', 'hook-env': 'version', 'hooks-run': 'noop',
                     'hook-uninstall': 'noop', 'config': 'count', 'privacy': 'count',
                     'account-status': 'count', 'account-unlink': 'noop', 'team-init': 'identity',
                     'team-golden-delete': 'noop', 'team-golden-create-flags': 'version',
                     'tool-search': 'count', 'tool-registry': 'manager', 'audit-policy': 'count',
                     'audit-verify': 'count', 'audit-log': 'filter', 'audit-log-flags': 'filter',
                     'history-flags': 'filter', 'stats': 'count', 'init': 'skipped'}
        source_rows = {line.split('\t')[0]: line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()[1:]}
        for case, mutant in mutations.items():
            with self.subTest(case=case, mutant=mutant):
                product = self.local_fixture_product().replace("case = before['case']", "case = before['case']\nmutant = " + repr(mutant) + ' if case == ' + repr(case) + " else 'none'")
                rows = self.rows_with_prerequisites([source_rows[case]])
                result, evidence, logs = self.run_inventory(self.local_fixture_with_workspace(product), rows, native_commands={'pacman': 'printf "fixture-package\\n"\n'})
                self.assertEqual([item['result'] for item in evidence], ['PASS'] * (len(rows) - 1) + ['FAIL'], f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_local_review_counterexamples_are_rejected(self):
        source_rows = {line.split('\t')[0]: line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()[1:]}
        product = self.local_fixture_product()
        comment_hooks = product + '''for name in post-checkout post-merge; do
printf '#!/bin/sh\n# OMG Team Sync Hook\n# %s env check\nexit 0\n' "$OMG_QEMU_EXECUTABLE" > ".git/hooks/$name"
done
'''
        wrong_date = product.replace("datetime.datetime.fromtimestamp(item['created_at'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')", "'1900-01-01 00:00'")
        for case, producer in [('team-init', comment_hooks), ('snapshot-list', wrong_date),
                               ('audit-log', product.replace("mutant = 'none'", "mutant = 'filter'")),
                               ('init', product.replace("mutant = 'none'", "mutant = 'skipped'"))]:
            with self.subTest(case=case):
                fields = source_rows[case].split('\t'); fields[5] = '-'
                result, evidence, logs = self.run_inventory(producer, ['\t'.join(fields)], native_commands={'pacman': 'printf "fixture-package\\n"\n'})
                self.assertEqual(evidence[0]['result'], 'FAIL', f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_flagged_golden_path_retains_declared_output_values(self):
        row = next(line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('team-golden-create-flags\t'))
        rows = self.rows_with_prerequisites([row])
        valid = self.local_fixture_product()
        for details, expected in (('Node: 20\nPython: 3.12\nPackages: ripgrep', 'PASS'),
                                  ('', 'FAIL'),
                                  ('Node: 99\nPython: 3.12\nPackages: ripgrep', 'FAIL')):
            with self.subTest(details=details), mock.patch.dict(os.environ, {
                    'remote': 'inherited-export', 'row_program': 'inherited-export'}):
                product = valid.replace("print('Node: 20\\nPython: 3.12\\nPackages: ripgrep')", 'print(' + repr(details) + ')')
                result, evidence, logs = self.run_inventory(self.local_fixture_with_workspace(product), rows)
                self.assertEqual([item['result'] for item in evidence], ['PASS'] * (len(rows) - 1) + [expected],
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_additional_local_refusals_bind_the_cause_and_artifact_boundary(self):
        ids = {'diff', 'diff-from', 'audit-export', 'audit-export-flags',
               'rollback', 'rollback-yes', 'env-export-missing-lock', 'metrics'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        self.assertEqual(len(rows), len(ids))
        valid = '''case "$1" in
diff) echo 'Error: Failed to inspect lockfile missing.lock' >&2 ;;
audit) echo 'Error: Absolute paths not allowed' >&2 ;;
rollback) echo 'Error: No history entries available for rollback' >&2 ;;
env) echo 'Error: Failed to inspect lockfile omg.lock' >&2 ;;
metrics) echo 'Error: Daemon not running. Performance metrics require the daemon (start it with: omg daemon)' >&2; echo "Failed to connect to daemon at $OMG_SOCKET_PATH" >&2 ;;
esac
exit 1
'''
        for product, expected, label in (
            ('echo unrelated permission error >&2\nexit 1\n', 'FAIL', 'wrong cause'),
            ('touch omg.lock\n' + valid, 'FAIL', 'created a forbidden lock'),
            ('mkdir -p audit-evidence\n' + valid, 'FAIL', 'wrote an export directory'),
            (valid, 'PASS', 'specific cause and preserved artifact boundary'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], [expected] * len(rows),
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_remaining_local_families_reject_generic_success_and_refusal(self):
        ids = {'snapshot-list','list','hooks-status','hooks-run','workspace-diff','hook-env','config','privacy','which',
               'audit-log','audit-verify','audit-policy','tool-list','tool-search','tool-registry','team-init',
               'team-roles-list','team-golden-create','team-golden-list','team-golden-delete','team-compliance',
               'account-status','account-unlink','history','stats','init','list-available','hook-uninstall',
               'audit-log-flags','team-golden-create-flags','team-compliance-enforce','history-flags',
               'workspace-run','workspace-check','team-members','team-activity','account-link-stdin','fleet-status',
               'enterprise-reports','enterprise-policy-show','enterprise-audit-export','team-compliance-export',
               'enterprise-reports-type','enterprise-policy-scope'}
        rows = []
        for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()[1:]:
            fields = line.split('\t')
            if fields[0] in ids:
                rows.append('\t'.join(fields))
        self.assertEqual(len(rows), len(ids))
        for row in rows:
            case, _, _, expected_code = row.split('\t')[:4]
            with self.subTest(case=case):
                # Real dependency declarations stay intact. Only the selected
                # command emits unrelated output; its parents use valid state.
                product = ('case_id=$(python3 -c "import json;print(json.load(open(\'.qemu-local-before.json\'))[\'case\'])")\n'
                           'if [[ "$case_id" == ' + shlex.quote(case) + ' ]]; then\n'
                           'echo unrelated output\necho unrelated permission error >&2\nexit ' + expected_code + '\nfi\n'
                           + self.local_fixture_product())
                selected = self.rows_with_prerequisites([row])
                result, evidence, logs = self.run_inventory(self.local_fixture_with_workspace(product), selected, native_commands={'pacman': 'printf "fixture-package\\n"\n'})
                self.assertEqual([item['result'] for item in evidence], ['PASS'] * (len(selected) - 1) + ['FAIL'],
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @staticmethod
    def rows_with_prerequisites(rows):
        source = {line.split('\t')[0]: line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()[1:]}
        selected = []
        seen = set()
        def append(row):
            fields = row.split('\t')
            if fields[0] in seen:
                return
            if fields[5] != '-':
                for parent in fields[5].split(','):
                    append(source[parent])
            seen.add(fields[0])
            selected.append(row)
        for row in rows:
            append(row)
        return selected

    def local_fixture_with_workspace(self, product=None):
        hooks = 'if [[ "$1:$2" == hooks:install ]]; then\nmkdir -p .git/hooks\n'
        for name, (content, _) in self.generated_hooks().items():
            hooks += 'printf %s ' + shlex.quote(content) + ' > .git/hooks/' + shlex.quote(name) + '\n'
        hooks += 'chmod 755 .git/hooks/pre-commit .git/hooks/post-checkout .git/hooks/post-merge\nexit 0\nfi\n'
        return (hooks + 'if [[ "$1" == workspace && ( "$2" == init || "$2" == add ) ]]; then\n'
                + self.workspace_fixture_product() + '\nexit $?\nfi\n'
                + (product if product is not None else self.local_fixture_product()))

    @staticmethod
    def workspace_fixture_product():
        return "python3 - \"$@\" <<'PY'\n" + r'''
import datetime, json, pathlib, sys, tomllib
args = sys.argv[1:]
path = pathlib.Path('omg-workspace.toml')
action = args[1]
if action == 'init':
    state = {'name': args[2], 'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'projects': {}}
else:
    state = tomllib.loads(path.read_text())
if action == 'add':
    state['projects'][args[4]] = {'path': args[2], 'depends_on': [], 'commands': {'build': 'make build', 'test': 'make test'}}
elif action == 'remove':
    del state['projects'][args[2]]
if action in ('init', 'add', 'remove'):
    lines = ['name = ' + json.dumps(state['name']), 'created_at = ' + json.dumps(state['created_at']), '[projects]']
    for name, project in state['projects'].items():
        lines += ['[projects.' + name + ']', 'path = ' + json.dumps(project['path']), 'depends_on = []', '[projects.' + name + '.commands]']
        lines += [key + ' = ' + json.dumps(value) for key, value in project['commands'].items()]
    path.write_text('\n'.join(lines) + '\n')
if action == 'init':
    print("OMG Initializing workspace 'smoke'\n✓ Created omg-workspace.toml")
elif action == 'add':
    print("✓ Added project '" + args[4] + "' (" + args[2] + ")")
elif action == 'remove':
    print("✓ Removed project 'fixture'")
elif action == 'list':
    print('OMG Workspace: smoke\n  1. fixture → .\n     commands: test, build')
elif action == 'status':
    print('OMG Workspace Status: smoke\n  Projects: 1 projects\n    ○ fixture - no omg.lock\n  ⚠ 0 healthy, 1 need attention')
''' + '\nPY\n'

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_workspace_rows_require_persisted_fixture_state(self):
        ids = {'workspace-init', 'workspace-add', 'workspace-list', 'workspace-status',
               'workspace-remove', 'workspace-readd-after-remove', 'workspace-add-second'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        self.assertEqual(len(rows), len(ids))
        for product, valid, label in (
            ('exit 0\n', False, 'silent no-op'),
            ("printf 'OMG Workspace: smoke\\n  1. fixture → .\\n'\n", False, 'forged output'),
            (self.workspace_fixture_product(), True, 'persisted state and matching output'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows)
                if valid:
                    self.assertEqual([row['result'] for row in evidence], ['PASS'] * len(rows),
                                     f'{result.stdout}\n{result.stderr}\n{logs}')
                else:
                    self.assertNotIn('PASS', [row['result'] for row in evidence],
                                     f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if valid else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_workspace_rows_reject_wrong_state_and_display(self):
        ids = {'workspace-init', 'workspace-add', 'workspace-list', 'workspace-status', 'workspace-remove'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        valid = self.workspace_fixture_product()
        for label, original, replacement, failed in (
            ('wrong project path', "'path': args[2]", "'path': 'elsewhere'", 'workspace-add'),
            ('wrong detected command', "'test': 'make test'", "'test': 'ignored'", 'workspace-add'),
            ('remove keeps project', "del state['projects'][args[2]]", 'pass', 'workspace-remove'),
            ('list names missing project', '1. fixture → .', '1. imaginary → .', 'workspace-list'),
            ('status claims healthy', '0 healthy, 1 need attention', '1 healthy, 0 need attention', 'workspace-status'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(valid.replace(original, replacement), rows)
                by_id = {row['case_id'].removeprefix('qemu-arch-'): row for row in evidence}
                self.assertEqual(by_id[failed]['result'], 'FAIL',
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_bash_completion_artifacts_must_complete_commands(self):
        ids = {'completions', 'completions-install'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        completion = (ROOT / 'src/hooks/completions/bash.sh').read_text(encoding='utf-8')
        for content, expected, label in (
            ('', 'FAIL', 'empty artifact'),
            ('# plausible completion file\ntrue\n', 'FAIL', 'valid shell with no completion'),
            (completion.replace('search s install', 'unrelated s install'), 'FAIL', 'wrong command candidates'),
            (completion, 'PASS', 'registered completion with real candidates'),
        ):
            product = ('if [[ "$*" == *--stdout* ]]; then printf %s ' + shlex.quote(content) + '; else\n'
                       'mkdir -p "$HOME/.local/share/bash-completion/completions"\n'
                       'printf %s ' + shlex.quote(content) + ' > "$HOME/.local/share/bash-completion/completions/omg"\n'
                       'echo "Installed bash completions"\nfi\n')
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], [expected] * len(rows),
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_man_generation_requires_command_documentation(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('generate-man\t'))
        count = len((ROOT / 'tests/man_page_inventory.txt').read_text(encoding='utf-8').splitlines())
        valid = '''mkdir -p "$3"
while IFS= read -r file; do
  page=${file%.1}
  printf '.TH %s 1\n.SH NAME\n%s \\- command documentation\n.SH SYNOPSIS\n%s [options]\n.SH DESCRIPTION\nDocumented command\n' "$page" "$page" "$page" > "$3/$file"
done
''' .replace('done\n', 'done < "$HOME/man_page_inventory.txt"\n') + f"printf '✓ Generated {count} man pages\\n'\n"
        for product, expected, label in (
            ('exit 0\n', 'FAIL', 'no artifacts'),
            (valid.replace('.SH SYNOPSIS', '.SH UNRELATED'), 'FAIL', 'not command reference pages'),
            (valid + 'mv "$3/omg-workspace-init.1" "$3/unrelated-init.1"\n', 'FAIL', 'missing nested command'),
            (valid.replace(f'Generated {count}', 'Generated 99'), 'FAIL', 'false page count'),
            (valid, 'PASS', 'documented root and command pages'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_dynamic_completion_returns_the_requested_env_candidate(self):
        ids = {'complete', 'complete-full'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        for output, expected in (('', 'FAIL'), ('check\n', 'FAIL'),
                                 ('capture\ncapture\n', 'FAIL'), ('capture\n', 'PASS')):
            with self.subTest(output=output):
                product = 'printf %s ' + shlex.quote(output) + '\n'
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], [expected] * len(rows),
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_ci_cache_returns_the_documented_paths_and_key(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('ci-cache\t'))
        valid = ('OMG CI Cache Paths\n  ~/.local/share/omg/\n  ~/.local/share/omg/versions/\n'
                 '  ~/.cargo/registry/\n  ~/.cargo/git/\n  ~/.npm/\n'
                 "  omg-${{ runner.os }}-${{ hashFiles('omg.lock') }}\n")
        for output, expected in (('', 'FAIL'), ('OMG CI Cache Paths\n', 'FAIL'),
                                 (valid.replace('omg.lock', 'wrong.lock'), 'FAIL'), (valid, 'PASS')):
            with self.subTest(output=output):
                result, evidence, logs = self.run_inventory('printf %s ' + shlex.quote(output) + '\n', [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_bash_hook_preserves_prompt_array_and_sigint_behavior(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('hook\t'))
        source = (ROOT / 'src/hooks/mod.rs').read_text(encoding='utf-8')
        hook = re.search(r'const BASH_HOOK: &str = r#"(.*?)"#;', source, re.S).group(1)
        for content, expected, label in (
            ('', 'FAIL', 'no hook'),
            ('# OMG Bash hook\ntrue\n', 'FAIL', 'plausible text'),
            (hook.replace('eval "$previous_int_trap"', 'trap - SIGINT'), 'FAIL', 'lost SIGINT handler'),
            (hook, 'PASS', 'registered and executed hook'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory('printf %s ' + shlex.quote(content) + '\n', [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_container_init_requires_build_recipe_and_ignore_protection(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('container-init\t'))
        ignore = ('!.env\n!secrets.key\n# added by omg container init\n.git\n.env\n.env.*\n'
                  '!.env.example\n*.pem\n*.key\nid_rsa*\n.omg/\n')
        dockerfile = ('FROM debian:bookworm\n'
                      'RUN apt-get update && apt-get install -y \\\n    curl wget git build-essential ca-certificates \\\n    && rm -rf /var/lib/apt/lists/*\n'
                      'WORKDIR /app\nCOPY . .\nCMD ["/bin/bash"]\n')
        valid = ('printf %s ' + shlex.quote(dockerfile) + ' > Dockerfile.omg\n'
                 'for file in .dockerignore Dockerfile.omg.dockerignore .containerignore; do\n'
                 '  printf %s ' + shlex.quote(ignore) + ' > "$file"\ndone\n'
                 "printf '  ✓ Created Dockerfile.omg\\nBase image: debian:bookworm\\n'\n")
        for product, expected, label in (
            ('exit 0\n', 'FAIL', 'no artifacts'),
            (valid.replace('FROM debian:bookworm', 'FROM unrelated:latest'), 'FAIL', 'wrong requested base'),
            (valid.replace('.env.*', '# omitted credential pattern'), 'FAIL', 'unprotected build context'),
            (valid.replace('!secrets.key', '# lost custom rule'), 'FAIL', 'discarded existing ignore file'),
            (valid, 'PASS', 'recipe and protected existing ignore files'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_local_refusals_require_the_specific_cause_and_preserve_fixtures(self):
        ids = {'ci-validate', 'snapshot-restore', 'snapshot-restore-yes', 'snapshot-delete',
               'use', 'use-uninstall', 'env-plan-missing-manifest'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        self.assertEqual(len(rows), len(ids))
        valid = '''case "$1" in
ci) echo "Error: No omg.lock found; run 'omg env capture' before CI validation" >&2 ;;
snapshot) echo "Error: Snapshot 'missing' not found" >&2 ;;
use) echo "Error: Unsupported runtime 'invalid-runtime'" >&2 ;;
env) echo "Error: Cannot read .omg.toml for environment planning" >&2 ;;
esac
exit 1
'''
        for product, expected, label in (
            ('echo unrelated permission error >&2\nexit 1\n', 'FAIL', 'unrelated error'),
            ('touch omg.lock\n' + valid, 'FAIL', 'creates forbidden lock'),
            ('echo changed >> Makefile\n' + valid, 'FAIL', 'changes existing fixture'),
            (valid, 'PASS', 'specific refusal without state changes'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], [expected] * len(rows),
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_daemon_status_reports_the_isolated_missing_socket(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('daemon-status\t'))
        valid = '''printf 'OMG Daemon Status\n  ✗ Daemon socket not found\n    Path: %s\n' "$OMG_SOCKET_PATH"
'''
        for product, expected, label in (
            ('exit 0\n', 'FAIL', 'silent success'),
            (valid.replace('Daemon socket not found', 'Daemon running'), 'FAIL', 'wrong socket state'),
            (valid.replace('"$OMG_SOCKET_PATH"', 'unrelated.sock'), 'FAIL', 'wrong selected socket'),
            ('touch "$OMG_SOCKET_PATH"\n' + valid, 'FAIL', 'claims absent socket after creating one'),
            (valid, 'PASS', 'missing private socket identified'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_search_queries_require_an_official_firefox_result(self):
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ('search', 'search-quiet')]
        self.assertEqual(len(rows), 2)
        for output, expected in (
            ('', 'FAIL'),
            ('  | Search\n    firefox\n', 'FAIL'),
            ('  | Search\n    firefox\n  unrelated 1.0  Official\n', 'FAIL'),
            ('  | Search\n    firefox\n  firefox 130.0  AUR\n', 'FAIL'),
            ('  | Search\n    firefox\n  firefox 130.0  Official\n', 'PASS'),
        ):
            with self.subTest(output=output):
                product = 'printf %s ' + shlex.quote(output) + '\n'
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], [expected] * len(rows),
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_run_requires_the_make_task_to_execute(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('run\t'))
        self.assertEqual(row.split('\t')[8], 'task-executed')
        for product, expected, explanation in (
            ('exit 0\n', 'FAIL', 'silent success'),
            ("printf 'smoke-task-ok\\n'\n", 'FAIL', 'forged stdout'),
            ('make smoke\n', 'PASS', 'executed task'),
        ):
            with self.subTest(explanation=explanation):
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_run_parallel_requires_two_overlapping_tasks(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('run-parallel\t'))
        self.assertEqual(row.split('\t')[8], 'parallel-tasks-executed')
        concurrent = ('make parallel-one & first=$!\n'
                      'make parallel-two & second=$!\n'
                      'wait "$first" && wait "$second"\n')
        for product, expected, explanation in (
            ('exit 0\n', 'FAIL', 'silent success'),
            ("printf 'parallel-one-ok\\nparallel-two-ok\\n'\n", 'FAIL', 'forged stdout'),
            ('make parallel-one; make parallel-two; exit 0\n', 'FAIL', 'serial execution'),
            (concurrent, 'PASS', 'overlapping execution'),
        ):
            with self.subTest(explanation=explanation):
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_run_all_requires_make_and_node_task_dispatch(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('run-all\t'))
        self.assertEqual(row.split('\t')[8], 'all-tasks-executed')
        for product, expected, explanation in (
            ('exit 0\n', 'FAIL', 'silent success'),
            ('make smoke\n', 'FAIL', 'make only'),
            ('npm run smoke\n', 'FAIL', 'npm only'),
            ('make smoke && npm run smoke\n', 'PASS', 'both ecosystems'),
        ):
            with self.subTest(explanation=explanation):
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_package_dry_runs_reject_success_without_a_preview(self):
        release = Path('/etc/os-release').read_text(encoding='utf-8')
        match = re.search(r'^ID=(\S+)$', release, re.MULTILINE)
        distro = {'arch': 'arch', 'archlinux': 'arch', 'debian': 'debian',
                  'ubuntu': 'ubuntu', 'fedora': 'fedora'}.get(match.group(1).strip('"') if match else '')
        if distro is None:
            self.skipTest('requires one supported native package database')
        ids = {'install', 'remove', 'install-flags', 'remove-flags'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        self.assertEqual(len(rows), len(ids))
        result, evidence, logs = self.run_inventory('exit 0\n', rows, distro=distro)
        self.assertEqual([row['result'] for row in evidence], ['FAIL'] * len(rows),
                         f'{result.stdout}\n{result.stderr}\n{logs}')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_package_dry_run_rejects_native_state_mutation(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('install\t'))
        native = {'pacman': 'case "$1" in\n'
                            '  -Q) if [[ -f native-state-changed ]]; then echo "pacman 8"; '
                            'else echo "pacman 7"; fi ;;\n'
                            '  -Qqe) if [[ -f native-reason-changed ]]; then echo changed; '
                            'else echo pacman; fi ;;\n'
                            '  *) exit 2 ;;\n'
                            'esac\n'}
        preview = "printf '%s\\n' '  | Install Preview' '    dry run' " \
                  "'│ pacman  ┆ 7.1 ┆ 1 MB ┆ Official │' " \
                  "'  ℹ • No changes will be made (dry run)'\n"
        result, evidence, logs = self.run_inventory(preview, [row],
                                                     distro='arch', native_commands=native)
        self.assertEqual([item['result'] for item in evidence], ['PASS'],
                         f'{result.stdout}\n{result.stderr}\n{logs}')
        result, evidence, logs = self.run_inventory('touch native-state-changed\n' + preview,
                                                     [row], distro='arch', native_commands=native)
        self.assertEqual([item['result'] for item in evidence], ['FAIL'],
                         f'{result.stdout}\n{result.stderr}\n{logs}')
        self.assertIn('dry run changed native installed-package state or reasons', logs['install.log'])
        result, evidence, logs = self.run_inventory('touch native-reason-changed\n' + preview,
                                                     [row], distro='arch', native_commands=native)
        self.assertEqual(evidence[0]['result'], 'FAIL',
                         f'{result.stdout}\n{result.stderr}\n{logs}')
        self.assertIn('dry run changed native installed-package state or reasons', logs['install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_fedora_remove_requires_the_installed_rpm_version(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('remove\t'))
        native = {'rpm': r"""
case "$1" in
  -qa) printf 'jq.x86_64\t1.8.1-3.fc44\n' ;;
  -q)
    case "$*" in
      *EPOCHNUM*) printf '0\t1.8.1\t3.fc44\n' ;;
      *ARCH*) printf 'jq\tx86_64\n' ;;
      *) printf '1.8.1-3.fc44\n' ;;
    esac ;;
  *) exit 2 ;;
esac
""", 'dnf': "printf 'jq\tUser\n'\n"}
        preview = "[[ \"$1:$2:$3\" == remove:--dry-run:jq ]] || exit 70\n" \
                  "printf '%s\n' '  | Remove Preview' '    dry run' " \
                  "'  → The following packages would be removed:' " \
                  "'    ✗ jq.x86_64 1.8.1-3.fc44' " \
                  "'    ✗ oniguruma.x86_64 6.9.10-3.fc44' " \
                  "'  ℹ No changes made (dry run)'\n"
        result, evidence, logs = self.run_inventory(preview, [row],
                                                   distro='fedora', native_commands=native)
        self.assertEqual(evidence[0]['result'], 'PASS',
                         f'{result.stdout}\n{result.stderr}\n{logs}')
        for changed in ('jq', 'jq.i686', 'jq.x86_64 0.0-1'):
            mutated = preview.replace('jq.x86_64 1.8.1-3.fc44',
                                      changed if ' ' in changed else changed + ' 1.8.1-3.fc44')
            result, evidence, logs = self.run_inventory(mutated, [row],
                                                       distro='fedora', native_commands=native)
            self.assertEqual(evidence[0]['result'], 'FAIL',
                             f'{result.stdout}\n{result.stderr}\n{logs}')
            self.assertIn('lacks the exact native installed package identity/version', logs['remove.log'])
        result, evidence, logs = self.run_inventory(
            preview.replace("'    ✗ jq.x86_64 1.8.1-3.fc44'",
                            "'    ✗ jq.x86_64 1.8.1-3.fc44' '    ✗ jq.x86_64 1.8.1-3.fc44'"),
            [row], distro='fedora', native_commands=native)
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)

    def test_recursive_remove_requires_the_backend_specific_refusal(self):
        for distro, explanation in (
            ('debian', 'Recursive removal is not supported by the Debian backend'),
            ('ubuntu', 'Recursive removal is not supported by the Debian backend'),
            ('fedora', 'Recursive removal is not supported by this package backend'),
        ):
            with self.subTest(distro=distro):
                refusal = f'Error: {explanation}\n'
                self.assertEqual(self.run_oracle(assertion='package-dry-run-recursive',
                                                code=1, stderr=refusal, distro=distro).returncode, 0)
                self.assertNotEqual(self.run_oracle(assertion='package-dry-run-recursive',
                                                   code=1, stderr='Error: arbitrary failure\n',
                                                   distro=distro).returncode, 0)
                self.assertNotEqual(self.run_oracle(assertion='package-dry-run-recursive',
                                                   code=1, stderr=refusal,
                                                   stdout='  | Remove Preview\n',
                                                   distro=distro).returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'Doctor guest oracle requires a POSIX shell')
    def test_doctor_backend_oracle_rejects_wrong_guest_and_false_health(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN DOCTOR BACKEND ORACLE')
        end = source.index('# END DOCTOR BACKEND ORACLE', begin)
        oracle = source[begin:end]
        expected = {
            'arch': ('Arch Linux detected', 'ALPM local package database (/var/lib/pacman/local, 2 packages verified)'),
            'debian': ('Debian/Ubuntu detected (apt backend)',
                       'dpkg package database (/var/lib/dpkg/status)\n  APT package indexes (/var/lib/apt/lists)'),
            'ubuntu': ('Debian/Ubuntu detected (apt backend)',
                       'dpkg package database (/var/lib/dpkg/status)\n  APT package indexes (/var/lib/apt/lists)'),
            'fedora': ('Fedora/RHEL detected (dnf backend)',
                       'RPM installed package database nonempty\n  DNF local package database healthy'),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / 'os-release'
            output = root / 'doctor.out'
            trace = root / 'doctor.exec.log'
            (root / 'bin').mkdir()
            pacman = root / 'bin/pacman'
            pacman.write_text('#!/usr/bin/env bash\ncase "$1" in -Dk) exit 0 ;; -Qq) printf "one\\ntwo\\n" ;; *) exit 17 ;; esac\n', encoding='utf-8')
            pacman.chmod(0o755)
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
            env['HOME'] = str(root)
            (root / 'qemu-doctor-index-oracle.py').write_bytes(
                (ROOT / 'scripts/qemu-doctor-index-oracle.py').read_bytes())
            for distro, (identity, health) in expected.items():
                with self.subTest(distro=distro):
                    release.write_text(f'ID={distro}\n', encoding='utf-8')
                    healthy = f'  {identity}\n'
                    if os.geteuid() != 0:
                        healthy += '  Found dependency: sudo\n'
                    if distro in ('debian', 'ubuntu'):
                        healthy += '  Found dependency: apt-get\n'
                    if health:
                        healthy += f'  {health}\n'
                    output.write_text(healthy, encoding='utf-8')
                    trace.write_text(
                        '122 execve("/usr/bin/rpm", ["/usr/bin/rpm", "-qa"], 0x7ffd) = 0\n'
                        '123 execve("/usr/bin/dnf5", ["/usr/bin/dnf5", "--cacheonly", '
                        '"--disable-repo=*", "check"], 0x7ffd /* 1 var */) = 0\n',
                        encoding='utf-8')
                    command = oracle + '\ncheck_doctor_native_backend "$1" "$2" "$3" "$4"\n'
                    def probe():
                        return subprocess.run(
                            [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'), '-c',
                             command, '_', distro, str(output), str(release), str(trace) if distro == 'fedora' else ''],
                            cwd=root, env=env, capture_output=True, text=True, timeout=10)
                    passed = probe()
                    self.assertEqual(passed.returncode, 0, passed.stderr)
                    if distro in ('debian', 'ubuntu'):
                        negative = subprocess.run(
                            [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'), '-c',
                             command.replace('"$4"\n', '"$4" false "$5"\n'), '_',
                             distro, str(output), str(release), '',
                             str(root / 'missing-index-proof.json')],
                            cwd=root, env=env, capture_output=True, text=True, timeout=10)
                        self.assertEqual(negative.returncode, 1,
                                         'healthy output without the required corrupt-index proof must fail')
                    if distro == 'arch':
                        pacman.write_text('#!/usr/bin/env bash\nexit 17\n', encoding='utf-8')
                        self.assertEqual(probe().returncode, 2)
                        pacman.write_text('#!/usr/bin/env bash\ncase "$1" in -Dk) exit 0 ;; -Qq) printf "one\\ntwo\\n" ;; *) exit 17 ;; esac\n', encoding='utf-8')
                    output.write_text(healthy + '  Found dependency: curl\n', encoding='utf-8')
                    self.assertEqual(probe().returncode, 1,
                                     'an invented curl dependency must fail the Doctor oracle')
                    output.write_text(healthy, encoding='utf-8')
                    if distro in ('debian', 'ubuntu'):
                        output.write_text(healthy.replace('  Found dependency: apt-get\n', ''), encoding='utf-8')
                        self.assertEqual(probe().returncode, 1,
                                         'APT Doctor must verify the native command')
                        output.write_text(healthy, encoding='utf-8')
                    if distro == 'fedora':
                        self.assertIn('Fedora doctor RPM execution receipt: 122 execve(', passed.stderr)
                        self.assertIn('Fedora doctor DNF execution receipt: 123 execve(', passed.stderr)
                        output.write_text(f'  {identity}\n', encoding='utf-8')
                        self.assertEqual(probe().returncode, 1, 'Fedora identity alone is not native health proof')
                        output.write_text(healthy, encoding='utf-8')
                        trace.write_text(
                            '123 execve("/usr/bin/dnf5", ["/usr/bin/dnf5", "--cacheonly", '
                            '"--disable-repo=*", "check"], 0x7ffd /* 1 var */) = 0\n',
                            encoding='utf-8')
                        self.assertEqual(probe().returncode, 1, 'Fedora health text without an RPM query is not proof')
                        trace.write_text('122 execve("/usr/bin/rpm", ["/usr/bin/rpm", "-qa"], 0x7ffd) = 0\n', encoding='utf-8')
                        self.assertEqual(probe().returncode, 1, 'Fedora health text without an offline DNF check is not proof')
                        trace.write_text('123 execve("/usr/bin/dnf5", ["/usr/bin/dnf5", "check"], 0x7ffd) = 0\n', encoding='utf-8')
                        self.assertEqual(probe().returncode, 1, 'Fedora health text without an offline DNF exec is not proof')
                        trace.write_text(
                            '122 execve("/usr/bin/rpm", ["/usr/bin/rpm", "-qa"], 0x7ffd) = 0\n'
                            '123 execve("/usr/bin/dnf5", ["/usr/bin/dnf5", "--cacheonly", '
                            '"--disable-repo=*", "check"], 0x7ffd /* 1 var */) = 0\n',
                            encoding='utf-8')
                    output.write_text('  Arch Linux detected\n' if distro != 'arch'
                                      else '  Fedora/RHEL detected (dnf backend)\n', encoding='utf-8')
                    self.assertEqual(probe().returncode, 1)
                    output.write_text(healthy.replace(health, 'backend check absent')
                                      if health else healthy + '  Arch Linux detected\n', encoding='utf-8')
                    self.assertEqual(probe().returncode, 1)
                    output.write_text(healthy, encoding='utf-8')
                    release.write_text('ID=other\n', encoding='utf-8')
                    self.assertEqual(probe().returncode, 2)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_actual_runner_requires_doctor_backend_evidence(self):
        release = Path('/etc/os-release').read_text(encoding='utf-8')
        distro = next((line.split('=', 1)[1].strip('"') for line in release.splitlines()
                       if line.startswith('ID=')), '')
        if distro not in ('arch', 'debian', 'ubuntu', 'fedora'):
            self.skipTest('not a supported Linux guest')
        rows = ['doctor\t["doctor"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tdoctor-native-backend\ttempdir-drop']
        identity = {'arch': 'Arch Linux detected',
                    'debian': 'Debian/Ubuntu detected (apt backend)',
                    'ubuntu': 'Debian/Ubuntu detected (apt backend)',
                    'fedora': 'Fedora/RHEL detected (dnf backend)'}[distro]
        health = {'arch': '  ALPM local package database (/var/lib/pacman/local, 2 packages verified)\n',
                  'debian': '  dpkg package database (/var/lib/dpkg/status)\n  APT package indexes (/var/lib/apt/lists)\n',
                  'ubuntu': '  dpkg package database (/var/lib/dpkg/status)\n  APT package indexes (/var/lib/apt/lists)\n',
                  'fedora': '  RPM installed package database nonempty\n'
                            '  DNF local package database healthy\n'}[distro]
        healthy = f'  {identity}\n{health}'
        if os.geteuid() != 0:
            healthy += '  Found dependency: sudo\n'
        if distro in ('debian', 'ubuntu'):
            healthy += '  Found dependency: apt-get\n'
        git_probe = ('if command -v git >/dev/null; then echo "  Optional tool available: git"; '
                     'else echo "  Optional tool unavailable: git (project and Git integration)"; fi\n')
        healthy_prefix = ('printf %s ' + shlex.quote(healthy) + '\n' + git_probe +
                          'if [[ "$1" == doctor ]] && [[ "' + distro + '" == arch ]]; then '
                          'if command -v makepkg >/dev/null; then echo "  Optional tool available: makepkg"; '
                          'else echo "  Optional tool unavailable: makepkg (Arch AUR builds)"; fi; fi\n')
        healthy_product = healthy_prefix + 'printf "  PATH configured correctly\\nSystem is healthy with warnings.\\n"\n'
        fault_guard = '''graph_db=${OMG_PACMAN_DB_DIR:-}
if [[ -z "$graph_db" && -n "${OMG_PACMAN_CONF:-}" ]]; then
  graph_db=$(sed -n 's/^DBPath = //p' "$OMG_PACMAN_CONF")
fi
case "$graph_db" in
  */graph-db/healthy)
    printf '  ALPM local package database (%s/local, 1 packages verified)\\nSystem is healthy with warnings.\\n' "$graph_db"
    exit 0 ;;
  */graph-db/dependency)
    printf '  ALPM native database check failed (%s/local)\\n  ALPM dependency unsatisfied: first requires omg-fixture-unavailable>=99\\n' "$graph_db"
    printf 'Error: doctor found 1 health issue(s)\\n' >&2
    exit 1 ;;
  */graph-db/conflict|*/graph-db/ownership)
    printf '  ALPM native database check failed (%s/local)\\n' "$graph_db"
    printf 'Error: doctor found 1 health issue(s)\\n' >&2
    exit 1 ;;
  */graph-db/malformed)
    printf '  ALPM local package database inconsistent (%s/local): missing files\\n' "$graph_db"
    printf 'Error: doctor found 1 health issue(s)\\n' >&2
    exit 1 ;;
  '') ;;
  *) printf '  ALPM local package database inconsistent (fixture): missing files\\n'; exit 1 ;;
esac
'''
        proxy_logic = ('if [[ "${HTTPS_PROXY:-}" == http://127.0.0.1:1 ]]; then\n'
                   '  printf "  Connectivity probes failed (controlled proxy refusal)\\n"\n'
                   '  resolved=$(command -v omg || true)\n'
                   '  if [[ -z "$resolved" ]]; then\n'
                   '    printf "  omg executable not found on PATH\\n→ Found 2 issue(s). Please review.\\n"\n'
                   '    printf "Error: doctor found 2 health issue(s)\\n" >&2\n'
                   '  elif [[ $(readlink -f "$resolved") != $(readlink -f "$0") ]]; then\n'
                   '    printf "  PATH resolves a different omg executable first: \\"%s\\"\\n→ Found 2 issue(s). Please review.\\n" "$resolved"\n'
                   '    printf "Error: doctor found 2 health issue(s)\\n" >&2\n'
                   '  else\n'
                   '    printf "  PATH configured correctly\\n→ Found 1 issue(s). Please review.\\n"\n'
                   '    printf "Error: doctor found 1 health issue(s)\\n" >&2\n'
                   '  fi\n'
                   '  exit 1\n'
                   'fi\n')
        product = fault_guard + healthy_prefix + proxy_logic + 'printf "  PATH configured correctly\\nSystem is healthy with warnings.\\n"\n'
        native = {'pacman': 'case "$1" in -Dk) exit 0 ;; -Qq) printf "one\\ntwo\\n" ;; *) exit 17 ;; esac\n'}
        if distro in ('debian', 'ubuntu'):
            # This test isolates the PATH oracle. Root QEMU mounts are an
            # external prerequisite; receipt validation remains real.
            receipt = {'schema_version': 1, 'distro': distro, 'complete': True,
                       'db_before': 'a' * 64, 'db_after': 'a' * 64,
                       'baseline_issues': 1, 'cases': {
                           name: {'exit': 1, 'issues': 1 if name == 'empty' else 2,
                                  'diagnostic': True}
                           for name in ('empty', 'corrupt-gzip', 'unreadable', 'corrupt-status')}}
            native['sudo'] = ('[[ "$1" == -n ]] || exit 120\nshift\n'
                              '[[ "$1" == unshare && "$2" == --mount && "$3" == --propagation '
                              '&& "$4" == private && "$5" == python3 '
                              '&& "$6" == "$HOME/qemu-doctor-index-oracle.py" '
                              '&& "$7" == --binary && "$9" == --distro ]] || exit 120\n'
                              'printf %s ' + shlex.quote(json.dumps(receipt)) + '\n')
        result, evidence, logs = self.run_inventory(product, rows, native_commands=native,
                                                    distro=distro, binary_name='omg')
        if distro == 'fedora':
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(evidence[0]['result'], 'FAIL')
            self.assertIn('did not execute the trusted offline DNF5', logs['doctor.log'])
        else:
            self.assertEqual(result.returncode, 0, f'{result.stderr}\n{logs}')
            self.assertEqual(evidence[0]['result'], 'PASS')
            for false_green in (
                product.replace('  omg executable not found on PATH',
                                '  PATH configured correctly'),
                product.replace('  PATH resolves a different omg executable first:',
                                '  PATH configured correctly:'),
                product.replace('Found 2 issue(s)', 'Found 1 issue(s)')
                       .replace('doctor found 2 health issue(s)',
                                'doctor found 1 health issue(s)'),
            ):
                result, evidence, logs = self.run_inventory(
                    false_green, rows, native_commands=native, distro=distro, binary_name='omg')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(evidence[0]['result'], 'FAIL', logs)
                self.assertIn('controlled Doctor PATH probe', logs['doctor.log'])
        if distro == 'arch':
            stalled = product.replace(
                'if [[ "${HTTPS_PROXY:-}" == http://127.0.0.1:1 ]]; then\n',
                'if [[ "${HTTPS_PROXY:-}" == http://127.0.0.1:1 ]]; then sleep 3; fi\n'
                'if [[ "${HTTPS_PROXY:-}" == http://127.0.0.1:1 ]]; then\n', 1)
            result, evidence, logs = self.run_inventory(
                stalled, rows, native_commands=native, distro=distro, row_timeout=1,
                binary_name='omg')
            self.assertEqual(evidence[0]['result'], 'FAIL', logs)
            self.assertEqual(evidence[0]['exit_code'], 124,
                             'a timed-out probe must retain its executor identity')
            self.assertIn('did not execute as a product run', logs['doctor.log'])
            silent_fault = healthy_product
            result, evidence, logs = self.run_inventory(silent_fault, rows,
                                                        native_commands=native, distro=distro,
                                                        binary_name='omg')
            self.assertEqual(evidence[0]['result'], 'FAIL', logs)
            self.assertIn('doctor accepted a corrupt Arch local package entry', logs['doctor.log'])
            spoofed = product.replace(git_probe, 'echo "  Optional tool available: git"\n')
            result, evidence, logs = self.run_inventory(spoofed, rows, native_commands=native,
                                                        distro=distro, binary_name='omg')
            self.assertEqual(evidence[0]['result'], 'FAIL',
                             'a fixed Git verdict must fail under the restricted PATH')
            self.assertIn('did not report absent Git/AUR tools', logs['doctor.log'])
        result, evidence, logs = self.run_inventory('printf "Doctor is healthy\\n"\n', rows,
                                                    native_commands=native, distro=distro,
                                                    binary_name='omg')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(evidence[0]['result'], 'FAIL')
        self.assertIn('doctor did not identify', logs['doctor.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_ci_init_requires_a_generated_workflow_and_advanced_security_job(self):
        rows = [
            'ci-init\t["ci","init","github"]\tisolated-write\t0\tpass\t-\t'
            'hermetic\thermetic:pass\tci-github-workflow\ttempdir-drop',
            'ci-init-advanced\t["ci","init","github","--advanced"]\tisolated-write\t0\tpass\t-\t'
            'hermetic\thermetic:pass\tci-github-workflow-advanced\ttempdir-drop',
        ]
        basic = '''mkdir -p .github/workflows
cat > .github/workflows/ci.yml <<'WORKFLOW'
name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - name: Install release
        run: |
          OMG_VERSION=v0.1.224 bash omg-install.sh
      - name: Build
        run: omg run build
      - name: Test
        run: omg run test
WORKFLOW
'''
        advanced = '''if [[ "${4:-}" == --advanced ]]; then
cat >> .github/workflows/ci.yml <<'WORKFLOW'
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Audit
        run: |
          cargo audit
          cargo cyclonedx --format json
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: rust-dependencies-sbom
WORKFLOW
fi
'''
        for product, expected in (
            (basic + advanced, ['PASS', 'PASS']),
            (basic, ['PASS', 'FAIL']),
            (basic.replace('        run: omg run test\n', '# omg run test\n') + advanced,
             ['FAIL', 'FAIL']),
            (basic + advanced.replace('          cargo audit\n', '# cargo audit\n'),
             ['PASS', 'FAIL']),
            ('echo generated\n', ['FAIL', 'FAIL']),
        ):
            with self.subTest(expected=expected):
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([row['result'] for row in evidence], expected,
                                 f'{result.stdout}\n{result.stderr}\n{logs}')
                self.assertEqual(result.returncode, int('FAIL' in expected), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_doctor_eol_requires_confined_runtime_and_both_classifications(self):
        row = ('doctor-eol\t["doctor","--eol"]\tcontrolled-error\t1\tpass\t-\t'
               'container\tarch:pass,debian:pass,ubuntu:pass,fedora:pass\tdoctor-eol-state\ttempdir-drop')
        preflight = ('[[ $(id -u) != 0 && "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 '
                     '&& -d "$OMG_DATA_DIR/versions/node/16.20.2" '
                     '&& $(readlink "$OMG_DATA_DIR/versions/node/current") == 16.20.2 '
                     '&& -d "$OMG_DATA_DIR/versions/python/3.12.14" '
                     '&& $(readlink "$OMG_DATA_DIR/versions/python/current") == 3.12.14 ]] '
                     '|| exit 70\n')
        good = ('printf "Runtime EOL Status\\n  ⚠ node 16.20.2 - EOL since 2023-09-11\\n'
                '  ✓ python 3.12.14\\n"\n')
        for output, eol_count, expected in (
            (good, 2, 'PASS'),
            (good, 1, 'FAIL'),
            (good.replace('EOL since 2023-09-11', 'healthy'), 2, 'FAIL'),
            (good.replace('  ✓ python 3.12.14\\n', ''), 2, 'FAIL'),
            ('printf "Runtime EOL Status\\n  ⚠ node 16.20.2 - EOL since 2023-09-11\\n'
             '  ⚠ python 3.12.14 - EOL since 2023-09-11\\n"\n', 2, 'FAIL'),
        ):
            with self.subTest(expected=expected, output=output, eol_count=eol_count):
                product = (preflight
                           + 'if [[ "$2" != --eol ]]; then echo "Error: doctor found 1 health issue(s)" >&2; exit 1; fi\n'
                           + output
                           + f'echo "Error: doctor found {eol_count} health issue(s)" >&2\nexit 1\n')
                result, evidence, logs = self.run_inventory(product, [row], tiers='container')
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_audit_eol_requires_private_runtime_classifications_and_issue_count(self):
        row = ('audit-eol\t["audit","eol"]\tread\t0\tpass\t-\t'
               'hermetic\thermetic:pass\taudit-eol-state\ttempdir-drop')
        preflight = ('[[ $(id -u) != 0 && "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 '
                     '&& -d "$OMG_DATA_DIR/versions/node/16.20.2" '
                     '&& $(readlink "$OMG_DATA_DIR/versions/node/current") == 16.20.2 '
                     '&& -d "$OMG_DATA_DIR/versions/python/3.12.14" '
                     '&& $(readlink "$OMG_DATA_DIR/versions/python/current") == 3.12.14 ]] '
                     '|| exit 70\n')
        good = ('  ✗ node v16.20.2 - EOL (EOL: 2023-09-11)\n'
                '  ✓ python v3.12.14 - Active (EOL: 2028-10-31)\n'
                '⚠ 1 runtime(s) need attention. Consider upgrading to supported versions.\n')
        for output, expected in (
            (good, 'PASS'),
            (good.replace('EOL (EOL: 2023-09-11)', 'Active (EOL: 2023-09-11)'), 'FAIL'),
            (good.replace('  ✓ python v3.12.14 - Active (EOL: 2028-10-31)\n', ''), 'FAIL'),
            (good.replace('1 runtime(s) need attention', '0 runtime(s) need attention'), 'FAIL'),
            (good.replace('1 runtime(s) need attention', '11 runtime(s) need attention'), 'FAIL'),
            (good + '  ✗ node v16.20.2 - EOL (EOL: 2023-09-11)\n', 'FAIL'),
        ):
            with self.subTest(expected=expected, output=output):
                product = preflight + 'printf %s ' + shlex.quote(output) + '\n'
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_doctor_network_requires_backend_probes_and_counted_failures(self):
        row = ('doctor-network\t["doctor","--network"]\tcontrolled-error\t1\tpass\t-\t'
               'container\tarch:pass,debian:pass,ubuntu:pass,fedora:pass\tdoctor-network-state\ttempdir-drop')
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            mirrors = ((('Arch Linux', 'https://archlinux.org'), ('Kernel.org', 'https://kernel.org'),
                        ('GitHub', 'https://github.com'), ('AUR', 'https://aur.archlinux.org'))
                       if distro == 'arch' else (('Kernel.org', 'https://kernel.org'),
                                                ('GitHub', 'https://github.com')))
            hosts = (('archlinux.org', 'aur.archlinux.org', 'github.com') if distro == 'arch'
                     else ('kernel.org', 'github.com'))
            mirror_lines = ''.join(f'  ✗ {name} (request failed for {url})\n' for name, url in mirrors)
            dns_lines = f'    ✓ {hosts[0]} (2 addresses)\n'
            dns_lines += ''.join(f'    ✗ {host} (resolver unavailable)\n' for host in hosts[1:])
            basic_hosts = ('archlinux.org', 'kernel.org') if distro == 'arch' else ('github.com', 'kernel.org')
            basic = (f'  Connectivity probes failed ({basic_hosts[0]}: connection error: refused; '
                     f'{basic_hosts[1]}: connection error: refused)\n\n')
            correct = basic + f'Network Diagnostics\n{mirror_lines}\n  DNS Resolution:\n{dns_lines}'
            expected_count = 1 + len(mirrors) + len(hosts) - 1
            variants = (
                (correct, expected_count, 'PASS'),
                (correct, expected_count - 1, 'FAIL'),
                (correct.replace(basic, ''), expected_count, 'FAIL'),
                (correct.replace(basic_hosts[1] + ': connection error: refused',
                                 'unknown.example: connection error: refused', 1), expected_count, 'FAIL'),
                (correct.replace(basic_hosts[1] + ': connection error: refused',
                                 basic_hosts[1] + ': healthy', 1), expected_count, 'FAIL'),
                (correct.replace(f'  ✗ {mirrors[0][0]}', f'  ✓ {mirrors[0][0]}'), expected_count, 'FAIL'),
                (correct.replace(mirrors[0][1], 'https://wrong.example'), expected_count, 'FAIL'),
                (correct.replace(f'    ✗ {hosts[-1]}', '    ✗ wrong.example'), expected_count, 'FAIL'),
            )
            for output, count, expected in variants:
                with self.subTest(distro=distro, expected=expected, count=count, output=output):
                    product = (
                        '[[ "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 ]] || exit 70\n'
                        'if [[ "$2" != --network ]]; then echo "Error: doctor found 1 health issue(s)" >&2; exit 1; fi\n'
                        + 'printf %s ' + shlex.quote(output) + '\n'
                        + f'echo "Error: doctor found {count} health issue(s)" >&2\nexit 1\n'
                    )
                    result, evidence, logs = self.run_inventory(product, [row], tiers='container', distro=distro)
                    self.assertEqual(evidence[0]['result'], expected, logs)
                    self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_audit_secrets_requires_scoped_redacted_finding(self):
        row = ('audit-secrets\t["audit","secrets","--path","project"]\tread\t0\tpass\t-\t'
               'hermetic\thermetic:pass\taudit-secret-scoped\ttempdir-drop')
        good = ('⚠ Found 1 potential secrets:\n  ● 1 MEDIUM\n'
                '  [MEDIUM] Password in project/config.txt:1\n      pass**********...7429\n')
        for output, expected in (
            (good, 'PASS'),
            ('✓ No secrets detected.\n', 'FAIL'),
            (good.replace('project/config.txt', 'outside.txt'), 'FAIL'),
            (good + '  [MEDIUM] Password in project/config.txt:1\n', 'FAIL'),
            (good + 'password=qemuSecret7429\n', 'FAIL'),
        ):
            with self.subTest(expected=expected, output=output):
                product = ('[[ -f project/config.txt && -f outside.txt ]] || exit 70\n'
                           + 'printf %s ' + shlex.quote(output) + '\n')
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_audit_secrets_critical_requires_failure_and_redaction(self):
        row = ('audit-secrets-critical\t["audit","secrets","--path","project/critical"]\t'
               'controlled-error\t1\tpass\t-\thermetic\thermetic:pass\t'
               'audit-secret-critical\ttempdir-drop')
        good = ('⚠ Found 1 potential secrets:\n  ● 1 CRITICAL\n'
                '  [CRITICAL] Private Key in project/critical/key.pem:1\n'
                '      ----**********...----\n')
        error = 'Error: Secret scan failed: 1 critical secret finding(s) require remediation'
        raw_marker = '-----BEGIN ' + 'PRIVATE KEY-----'
        for output, stderr, code, expected in (
            (good, error, 1, 'PASS'),
            (good, '', 1, 'FAIL'),
            (good, error, 0, 'FAIL'),
            (good + '  [CRITICAL] Private Key in project/critical/key.pem:1\n', error, 1, 'FAIL'),
            (good + raw_marker + '\n', error, 1, 'FAIL'),
            (good, error + '\n' + raw_marker, 1, 'FAIL'),
        ):
            with self.subTest(expected=expected, code=code, output=output):
                product = ('[[ -f project/critical/key.pem ]] || exit 70\n'
                           + 'printf %s ' + shlex.quote(output) + '\n'
                           + 'printf %s ' + shlex.quote(stderr + '\n') + ' >&2\n'
                           + f'exit {code}\n')
                result, evidence, logs = self.run_inventory(product, [row])
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'), result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_info_row_compares_version_and_source_to_native_catalog(self):
        row = ('info\t["info","pacman"]\tread\t0\tpass\t-\thermetic\thermetic:pass'
               '\tinfo-native-package\ttempdir-drop')
        references = {
            'arch': ('pacman', 'Repository : core\nVersion : 1.2-3\n', 'Official repository (core)'),
            'debian': ('apt-cache', 'pacman:\n  Candidate: 1.2-3\n', 'Official repository (apt)'),
            'ubuntu': ('apt-cache', 'pacman:\n  Candidate: 1.2-3\n', 'Official repository (apt)'),
            'fedora': ('dnf', '1.2-3\n', 'Official repository (dnf)'),
        }
        for distro, (tool, native_output, source) in references.items():
            with self.subTest(distro=distro):
                native = {tool: 'printf %s ' + shlex.quote(native_output) + '\n'}
                def product(version):
                    return 'printf %s ' + shlex.quote(
                        f'  | Info\n    pacman\n          Name: pacman\n'
                        f'       Version: {version}\n        Source: {source}\n') + '\n'
                result, evidence, _ = self.run_inventory(
                    product('1.2-3'), [row], distro=distro, native_commands=native)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(evidence[0]['result'], 'PASS')
                result, evidence, logs = self.run_inventory(
                    product('9.9-9'), [row], distro=distro, native_commands=native)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(evidence[0]['result'], 'FAIL')
                self.assertIn('info disagrees with the native', logs['info.log'])
                result, evidence, _ = self.run_inventory(
                    product('1.2-3'), [row], distro=distro,
                    native_commands={tool: 'exit 7\n'})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(evidence[0]['result'], 'BLOCKED')

    @staticmethod
    def runtime_usage_fixture(runtime):
        usage = json.dumps({'runtime_usage_counts': {runtime: 1},
                            'commands': {'runtime_switch': 1}, 'total_commands': 1})
        return ('mkdir -p "$OMG_DATA_DIR"\nchmod 700 "$OMG_DATA_DIR"\n'
                f'printf %s {shlex.quote(usage)} > "$OMG_DATA_DIR/usage.json"\n')

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_runtime_install_requires_private_persisted_usage(self):
        rows = ['runtime-node-install\t["use","node","24.21.0"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        # The fake runtime satisfies the separate execution oracle so failures
        # here must come from the state that the actual CLI failed to persist.
        node = '#!/bin/sh\ncat >/dev/null\necho OMG_NODE_RUNTIME_OK:24.21.0\n'
        product = self.runtime_usage_fixture('node')
        product += 'base="$OMG_DATA_DIR/versions/node"\nmkdir -p "$base/24.21.0/bin" "$base/24.21.0/lib/node_modules/npm/bin"\n'
        product += f'printf %s {shlex.quote(node)} > "$base/24.21.0/bin/node"\nchmod 755 "$base/24.21.0/bin/node"\n'
        product += 'ln -s 24.21.0 "$base/current"\necho fixture > "$base/24.21.0/lib/node_modules/npm/bin/npm-cli.js"\n'
        faults = {
            'missing': 'rm "$OMG_DATA_DIR/usage.json"\n',
            'invalid-json': 'echo broken > "$OMG_DATA_DIR/usage.json"\n',
            'multiple-documents': 'echo "{}" >> "$OMG_DATA_DIR/usage.json"\n',
            'writable': 'chmod 775 "$OMG_DATA_DIR"\n',
            'wrong-runtime': 'sed -i s/node/python/g "$OMG_DATA_DIR/usage.json"\n',
            'double-counted': 'sed -i s/1/2/g "$OMG_DATA_DIR/usage.json"\n',
            'command-missing': 'sed -i s/runtime_switch/other/g "$OMG_DATA_DIR/usage.json"\n',
            'none': '',
        }
        for fault, mutation in faults.items():
            with self.subTest(fault=fault):
                result, evidence, logs = self.run_inventory(product + mutation, rows)
                self.assertEqual(evidence[0]['result'], 'PASS' if fault == 'none' else 'FAIL')
                self.assertEqual(result.returncode, int(fault != 'none'))
                if fault != 'none':
                    self.assertIn('assertion failed: runtime usage', logs['runtime-node-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_runtime_uninstall_removes_only_inactive_version(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if re.match(r'^runtime-(node|python|go)-uninstall\t', line)]
        self.assertEqual(len(rows), 3)
        checks = ('[[ "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 '
                  '&& -f "$OMG_DATA_DIR/versions/$2/$3/sentinel" '
                  '&& -L "$OMG_DATA_DIR/versions/$2/current" '
                  '&& -f "$OMG_DATA_DIR/versions/$2/9.9.9/sentinel" '
                  '&& -f "$OMG_DATA_DIR/versions/other-guard/1.0.0/sentinel" '
                  '&& -L "$OMG_DATA_DIR/versions/$2/$3/external-link" ]] || exit 70\n')
        product = checks + 'rm -rf -- "$OMG_DATA_DIR/versions/$2/$3"\n'
        for row in rows:
            case = row.split('\t')[0]
            with self.subTest(case=case):
                result, evidence, logs = self.run_inventory(product, [row], tiers='container')
                self.assertEqual(evidence[0]['result'], 'PASS', logs)
                self.assertEqual(result.returncode, 0, result.stderr)
                mutations = {
                    'no-removal': checks + ':\n',
                    'sibling': product + 'rm -rf -- "$OMG_DATA_DIR/versions/$2/9.9.9"\n',
                    'active-pointer': product + 'ln -sfn /missing "$OMG_DATA_DIR/versions/$2/current"\n',
                    'external-target': checks + 'rm -rf -- "$(readlink "$OMG_DATA_DIR/versions/$2/$3/external-link")"\n' + product,
                    'other-runtime': product + 'rm -rf -- "$OMG_DATA_DIR/versions/other-guard"\n',
                }
                for fault, broken in mutations.items():
                    with self.subTest(case=case, fault=fault):
                        result, evidence, logs = self.run_inventory(broken, [row], tiers='container')
                        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertIn('assertion failed: runtime uninstall', logs[case + '.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_runtime_list_and_switch_require_exact_private_state(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        rows = [line for line in inventory.splitlines()
                if re.match(r'^runtime-(node|python|go)-(list|switch)-installed\t', line)]
        self.assertEqual(len(rows), 6)
        versions = {'node': ('24.21.0', '22.21.0'),
                    'python': ('3.12.14', '3.11.14'),
                    'go': ('1.27.1', '1.26.0')}
        for row in rows:
            case = row.split('\t')[0]
            runtime = case.split('-')[1]
            operation = case.split('-')[2]
            selected, active = versions[runtime]
            base = f'"$OMG_DATA_DIR/versions/{runtime}"'
            checks = (f'[[ "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 '
                      f'&& -f "$OMG_DATA_DIR/versions/{runtime}/{selected}/sentinel" '
                      f'&& -f "$OMG_DATA_DIR/versions/{runtime}/{active}/sentinel" '
                      f'&& -f "$OMG_DATA_DIR/versions/{runtime}/8.8.8/.omg-installing" '
                      f'&& -L "$OMG_DATA_DIR/versions/{runtime}/7.7.7" '
                      f'&& -L "$OMG_DATA_DIR/versions/{runtime}/current" ]] || exit 70\n')
            if operation == 'list':
                payload = {'runtime': runtime, 'current': active,
                           'installed': [selected, active]}
                output = 'printf %s ' + shlex.quote(json.dumps(payload)) + '\n'
                product = checks + output
                mutants = {
                    'silent': checks + ':\n',
                    'wrong-current': checks + 'printf %s ' + shlex.quote(
                        json.dumps({**payload, 'current': selected})) + '\n',
                    'missing-version': checks + 'printf %s ' + shlex.quote(
                        json.dumps({**payload, 'installed': [selected]})) + '\n',
                    'leaked-pending': checks + 'printf %s ' + shlex.quote(
                        json.dumps({**payload, 'installed': [selected, active, '8.8.8']})) + '\n',
                    'leaked-symlink': checks + 'printf %s ' + shlex.quote(
                        json.dumps({**payload, 'installed': [selected, active, '7.7.7']})) + '\n',
                    'extra-document': product + output,
                    'changed-pointer': checks + f'rm {base}/current; ln -s {base}/{selected} {base}/current\n' + output,
                    'lost-pending': checks + f'rm {base}/8.8.8/.omg-installing\n' + output,
                    'lost-external': checks + 'rm "$(dirname "$OMG_DATA_DIR")/external-runtime/sentinel"\n' + output,
                }
            else:
                switch = f'rm {base}/current; ln -s {base}/{selected} {base}/current\n'
                usage = self.runtime_usage_fixture(runtime)
                product = checks + switch + usage
                mutants = {
                    'no-switch': checks + usage,
                    'missing-usage': checks + switch,
                    'lost-active': product + f'rm -rf {base}/{active}\n',
                    'lost-pending': product + f'rm {base}/8.8.8/.omg-installing\n',
                    'lost-external': product + 'rm "$(dirname "$OMG_DATA_DIR")/external-runtime/sentinel"\n',
                }
            with self.subTest(case=case):
                result, evidence, logs = self.run_inventory(product, [row], tiers='container')
                self.assertEqual(evidence[0]['result'], 'PASS', logs)
                self.assertEqual(result.returncode, 0, result.stderr)
                for fault, broken in mutants.items():
                    with self.subTest(case=case, fault=fault):
                        result, evidence, logs = self.run_inventory(broken, [row], tiers='container')
                        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
                        self.assertEqual(result.returncode, 1, result.stderr)
                        self.assertIn('assertion failed: runtime', logs[case + '.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_config_rows_require_private_persisted_state(self):
        rows = [
            'config-set\t["config","set","telemetry.enabled","true"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\tconfig-set-persisted\ttempdir-drop',
            'config-get\t["config","get","telemetry.enabled"]\tread\t0\tpass\tconfig-set\thermetic\thermetic:pass\tconfig-get-persisted\ttempdir-drop',
            'config-list\t["config","list"]\tread\t0\tpass\tconfig-set\thermetic\thermetic:pass\tconfig-list-persisted\ttempdir-drop',
            'config-validate\t["config","validate"]\tread\t0\tpass\tconfig-set\thermetic\thermetic:pass\tconfig-validate-persisted\ttempdir-drop',
            'config-path\t["config","path"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tconfig-path-isolated\ttempdir-drop',
            'config-reset\t["config","reset","--yes"]\tisolated-write\t0\tpass\tconfig-set\thermetic\thermetic:pass\tconfig-reset-defaults\ttempdir-drop',
        ]
        product = r'''file="$OMG_CONFIG_DIR/config.toml"
case "$1:$2" in
  config:set) mkdir -p "$OMG_CONFIG_DIR"; printf 'telemetry_enabled = true\n' > "$file"; echo 'Set telemetry.enabled = true' ;;
  config:get) echo true ;;
  config:list) echo 'telemetry.enabled = true' ;;
  config:validate) echo 'Configuration is valid!' ;;
  config:path) printf '%s\n' "$file" ;;
  config:reset) cp "$file" "$file.backup"; printf 'telemetry_enabled = false\n' > "$file"; echo 'Configuration reset to defaults' ;;
  *) exit 77 ;;
esac
'''
        result, evidence, logs = self.run_inventory(product, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS'] * len(rows), logs)

        faults = (
            ("printf 'telemetry_enabled = true\\n' > \"$file\"", ':', 'config-set'),
            ("printf 'telemetry_enabled = true\\n' > \"$file\"", "printf 'telemetry_enabled = true\\ntelemetry_enabled=false\\n' > \"$file\"", 'config-set'),
            ('config:get) echo true', 'config:get) echo false', 'config-get'),
            ("config:list) echo 'telemetry.enabled = true'", "config:list) echo 'telemetry.enabled = false'", 'config-list'),
            ("config:validate) echo 'Configuration is valid!'", "config:validate) echo 'Validation skipped'", 'config-validate'),
            ("config:path) printf '%s\\n' \"$file\"", 'config:path) echo /tmp/wrong', 'config-path'),
            ("printf 'telemetry_enabled = false\\n' > \"$file\"", "printf 'telemetry_enabled = true\\n' > \"$file\"", 'config-reset'),
        )
        for old, new, case in faults:
            with self.subTest(case=case):
                self.assertIn(old, product)
                result, evidence, logs = self.run_inventory(product.replace(old, new, 1), rows)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                observed = {row['case_id'].removeprefix('qemu-arch-'): row['result'] for row in evidence}
                self.assertEqual(observed[case], 'FAIL', logs)
                self.assertIn('assertion failed: config', logs[case + '.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_privacy_rows_require_persisted_state_and_queue_purge(self):
        rows = [
            'privacy-opt-out\t["privacy","opt-out"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\tprivacy-opted-out\ttempdir-drop',
            'privacy-status\t["privacy","status"]\tread\t0\tpass\tprivacy-opt-out\thermetic\thermetic:pass\tprivacy-status-disabled\ttempdir-drop',
            'privacy-opt-in\t["privacy","opt-in"]\tisolated-write\t0\tpass\tprivacy-opt-out\thermetic\thermetic:pass\tprivacy-opted-in\ttempdir-drop',
            'privacy-status-enabled\t["privacy","status"]\tread\t0\tpass\tprivacy-opt-in\tcontainer\tarch:pass,debian:pass,ubuntu:pass,fedora:pass\tprivacy-status-enabled\ttempdir-drop',
        ]
        product = r'''file="$OMG_CONFIG_DIR/config.toml"
case "$1:$2" in
  privacy:opt-out) mkdir -p "$OMG_CONFIG_DIR"; rm "$OMG_DATA_DIR/telemetry_queue.json"; printf 'telemetry_enabled = false\n' > "$file"; echo 'Telemetry disabled locally' ;;
  privacy:status) if grep -Fxq 'telemetry_enabled = true' "$file"; then echo '  Telemetry: Enabled'; else echo '  Telemetry: Disabled'; fi ;;
  privacy:opt-in) printf 'telemetry_enabled = true\n' > "$file"; echo 'Telemetry enabled locally' ;;
  *) exit 77 ;;
esac
'''
        result, evidence, logs = self.run_inventory(product, rows, tiers='hermetic,container')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS'] * len(rows), logs)

        faults = (
            ("printf 'telemetry_enabled = false\\n' > \"$file\"", ':', 'privacy-opt-out'),
            ('rm "$OMG_DATA_DIR/telemetry_queue.json"', ':', 'privacy-opt-out'),
            ("else echo '  Telemetry: Disabled'", "else echo '  Telemetry: Enabled'", 'privacy-status'),
            ("printf 'telemetry_enabled = true\\n' > \"$file\"", ':', 'privacy-opt-in'),
            ("then echo '  Telemetry: Enabled'", "then echo '  Telemetry: Disabled'", 'privacy-status-enabled'),
        )
        for old, new, case in faults:
            with self.subTest(case=case, mutation=old):
                self.assertIn(old, product)
                result, evidence, logs = self.run_inventory(product.replace(old, new, 1), rows, tiers='hermetic,container')
                self.assertNotEqual(result.returncode, 0, result.stderr)
                observed = {row['case_id'].removeprefix('qemu-arch-'): row['result'] for row in evidence}
                self.assertEqual(observed[case], 'FAIL', logs)
                self.assertIn('assertion failed: privacy', logs[case + '.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_privacy_export_requires_private_complete_redacted_local_data(self):
        row = ('privacy-export\t["privacy","export","--output","${ROOT}/privacy.json"]'
               '\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass'
               '\tartifact:privacy.json\ttempdir-drop')
        payload = {
            'exported_at': '2026-09-26T00:00:00Z', 'scope': 'local',
            'local': {
                'usage.json': {'fixture': 'usage', 'total_commands': 7},
                'config.toml': 'telemetry_enabled = false\n',
                'license.json': {
                    'tier': 'pro', 'features': ['sbom'],
                    'customer': 'fixture@example.invalid', 'expires_at': None,
                    'validated_at': 1700000000, 'machine_id': 'fixture-machine',
                },
            },
        }
        preflight = ('[[ "$OMG_DISABLE_DAEMON" == 1 && '
                     '-f "$OMG_DATA_DIR/usage.json" && '
                     '-f "$OMG_DATA_DIR/license.json" && '
                     '-f "$OMG_CONFIG_DIR/config.toml" && '
                     '$(stat -c %a "$4") == 644 ]] || exit 70\n'
                     'jq -e \'.fixture == "usage" and .total_commands == 7\' '
                     '"$OMG_DATA_DIR/usage.json" >/dev/null || exit 70\n'
                     'jq -e \'.key == "qemu-secret-license-key" and '
                     '.token == "qemu-secret-license-token"\' '
                     '"$OMG_DATA_DIR/license.json" >/dev/null || exit 70\n'
                     'grep -Fxq "telemetry_enabled = false" '
                     '"$OMG_CONFIG_DIR/config.toml" || exit 70\n')

        def product(data, *, mode=600, write=True):
            command = preflight
            if write:
                command += 'printf "%s\\n" ' + shlex.quote(json.dumps(data)) + ' > "$4"\n'
                command += f'chmod {mode} "$4"\n'
            command += 'printf "Data exported to: %s\\n" "$4"\n'
            return command

        result, evidence, logs = self.run_inventory(product(payload), [row])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(evidence[0]['result'], 'PASS', logs)

        faults = {
            'wrong-usage': {**payload, 'local': {**payload['local'],
                'usage.json': {'fixture': 'usage', 'total_commands': 0}}},
            'missing-config': {**payload, 'local': {key: value for key, value in
                payload['local'].items() if key != 'config.toml'}},
            'leaked-license-key': {**payload, 'local': {**payload['local'],
                'license.json': {**payload['local']['license.json'], 'key': 'qemu-secret-license-key'}}},
            'wrong-scope': {**payload, 'scope': 'remote'},
            'extra-remote': {**payload, 'remote': {}},
        }
        for fault, data in faults.items():
            with self.subTest(fault=fault):
                result, evidence, logs = self.run_inventory(product(data), [row])
                self.assertEqual(evidence[0]['result'], 'FAIL', logs)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('assertion failed: privacy export', logs['privacy-export.log'])
        for fault, command in [('permissive-mode', product(payload, mode=644)),
                               ('unchanged-stale-file', product(payload, write=False))]:
            with self.subTest(fault=fault):
                result, evidence, logs = self.run_inventory(command, [row])
                self.assertEqual(evidence[0]['result'], 'FAIL', logs)
                self.assertEqual(result.returncode, 1, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_counter_rows_require_native_counts_and_block_failed_references(self):
        cases = {'ec': 'explicit-shortcut', 'tc': 'total-shortcut',
                 'oc': 'orphan-shortcut', 'uc': 'updates-shortcut'}
        native = {
            'pacman': "printf 'alpha\\nbeta\\n'\n",
            'rpm': "printf 'alpha.x86_64\\nbeta.x86_64\\n'\n",
            'dnf': "[[ \"$1\" == --cacheonly ]] || exit 19\nprintf 'alpha.x86_64\\nbeta.x86_64\\n'\n",
            'dpkg-query': "printf 'installed\\nconfig-files\\ninstalled\\n'\n",
            'apt-mark': "printf 'alpha\\nbeta\\n'\n",
            'apt-get': "[[ \"$1\" == -s && \"$2\" == autoremove ]] || exit 19\nprintf 'Reading lists...\\nRemv alpha [1.0]\\nRemv beta [2.0]\\n'\n",
            'apt': "printf 'Listing...\\nalpha/stable 2 amd64 [upgradable from: 1]\\nbeta/stable 3 amd64 [upgradable from: 2]\\n'\n",
        }
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            for command, case in cases.items():
                rows = [f'{case}\t["{command}"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tnative-count\ttempdir-drop']
                for value, verdict in [('2', 'PASS'), ('0', 'FAIL')]:
                    with self.subTest(distro=distro, command=command, value=value):
                        result, evidence, logs = self.run_inventory(
                            f'printf "{value}\\n"\n', rows, native_commands=native, distro=distro)
                        self.assertEqual(evidence[0]['result'], verdict, logs)
                        self.assertEqual(result.returncode, int(verdict == 'FAIL'), result.stderr)
                        self.assertIn(f'native counter {command} expected=2 actual={value}', logs[case + '.log'])
            explicit = ['explicit\t["explicit","--count"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tnative-count\ttempdir-drop']
            for value, verdict in [('2', 'PASS'), ('0', 'FAIL')]:
                with self.subTest(distro=distro, case='explicit', value=value):
                    result, evidence, _ = self.run_inventory(
                        f'printf "{value}\\n"\n', explicit, native_commands=native, distro=distro)
                    self.assertEqual(evidence[0]['result'], verdict)
                    self.assertEqual(result.returncode, int(verdict == 'FAIL'))
            broken = {name: 'echo native-reference-failed >&2\nexit 17\n' for name in native}
            result, evidence, logs = self.run_inventory('printf "0\\n"\n', rows,
                                                       native_commands=broken, distro=distro)
            self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('native counter reference failed', logs[case + '.log'])
        rows = ['explicit-shortcut\t["ec"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tnative-count\ttempdir-drop']
        result, evidence, logs = self.run_inventory('printf "0\\n"\n', rows,
            native_commands=dict(native, sort='exit 17\n'))
        self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
        self.assertNotEqual(result.returncode, 0)
        for output in ('02', 'two', '2\n2', '9' * 40):
            with self.subTest(malformed_output=output):
                result, evidence, _ = self.run_inventory(
                    'printf %s ' + shlex.quote(output) + '\n', rows, native_commands=native)
                self.assertEqual(evidence[0]['result'], 'FAIL')
                self.assertNotEqual(result.returncode, 0)
        for diagnostic, verdict in [('', 'PASS'), ('echo database-unavailable >&2\n', 'BLOCKED')]:
            result, evidence, _ = self.run_inventory('printf "0\\n"\n', rows,
                native_commands={'pacman': diagnostic + 'exit 1\n'})
            self.assertEqual(evidence[0]['result'], verdict)
            self.assertEqual(result.returncode, int(verdict != 'PASS'))

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_status_rows_require_distro_native_counts_instead_of_only_exit_zero(self):
        native = {
            'pacman': 'case "$1" in -Qq) printf "a\\nb\\nc\\n" ;; -Qqe) printf "a\\nb\\n" ;; -Qdtq|-Quq) printf "c\\n" ;; *) exit 17 ;; esac\n',
            'dpkg-query': 'printf "installed\\nconfig-files\\ninstalled\\ninstalled\\n"\n',
            'apt-mark': 'printf "a\\nb\\n"\n',
            'apt-get': 'printf "Remv c [1.0]\\n"\n',
            'apt': 'printf "c/stable 2 amd64 [upgradable from: 1]\\n"\n',
            'rpm': 'printf "a.x86_64\\nb.x86_64\\nc.x86_64\\n"\n',
            'dnf': 'case " $* " in *--userinstalled*) printf "a\\nb\\n" ;; *--unneeded*|*--upgrades*) printf "c\\n" ;; *) exit 17 ;; esac\n',
        }
        rows = (
            'status\t["status","--fast"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tstatus-native-fast\ttempdir-drop',
            'status-verbose\t["--verbose","status"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tstatus-native-full\ttempdir-drop',
        )
        product = (
            'printf "Status\\n\\n  3 packages installed · 2 explicit\\n"\n'
            'if [[ "$1" == status ]]; then\n'
            '  printf "  Updates and orphans not checked. Run omg status for a full check.\\n"\n'
            'else\n'
            '  printf "  Updates    1\\n  Orphans    1\\n"\n'
            'fi\n'
        )
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            with self.subTest(distro=distro, case='correct'):
                result, evidence, logs = self.run_inventory(product, rows, native_commands=native, distro=distro)
                self.assertEqual(result.returncode, 0, logs)
                self.assertEqual([item['result'] for item in evidence], ['PASS', 'PASS'])
                self.assertIn('native counter tc expected=3 actual=3', logs['status.log'])
                self.assertIn('native counter oc expected=1 actual=1', logs['status-verbose.log'])
            with self.subTest(distro=distro, case='false-green-total'):
                wrong = product.replace('3 packages installed', '4 packages installed')
                result, evidence, logs = self.run_inventory(wrong, rows, native_commands=native, distro=distro)
                self.assertEqual(result.returncode, 1, logs)
                self.assertEqual([item['result'] for item in evidence], ['FAIL', 'FAIL'])
                self.assertIn('assertion failed: status tc', logs['status.log'])
        for case, mutation in (
            ('explicit', ('2 explicit', '9 explicit')),
            ('updates', ('Updates    1', 'Updates    9')),
            ('orphans', ('Orphans    1', 'Orphans    9')),
            ('fast-marker', ('Updates and orphans not checked.', 'All checks complete.')),
        ):
            with self.subTest(case=case):
                result, evidence, _ = self.run_inventory(
                    product.replace(*mutation), rows, native_commands=native)
                self.assertEqual(result.returncode, 1)
                self.assertIn('FAIL', [item['result'] for item in evidence])
        broken = dict(native, pacman='echo native-reference-failed >&2\nexit 17\n')
        result, evidence, _ = self.run_inventory(product, rows, native_commands=broken)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([item['result'] for item in evidence], ['BLOCKED', 'BLOCKED'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_outdated_rows_compare_reported_updates_to_native_queries(self):
        native = {
            'pacman': '[[ "$1" == -Quq ]] || exit 17\nprintf "c\\n"\n',
            'apt': 'printf "c/stable 2 amd64 [upgradable from: 1]\\n"\n',
            'dnf': '[[ " $* " == *--upgrades* ]] || exit 17\nprintf "c.x86_64\\n"\n',
        }
        rows = (
            'outdated\t["outdated"]\tread\t0\tpass\t-\thermetic\thermetic:pass\toutdated-native-count\ttempdir-drop',
            'outdated-json\t["--json","outdated"]\tread\t0\tpass\t-\thermetic\thermetic:pass\toutdated-json-native-count\ttempdir-drop',
        )
        item = '{"name":"c","current_version":"1","new_version":"2"}'
        product = (
            'if [[ "$1" == --json ]]; then\n'
            f'  printf "%s\\n" \'[{item}]\'\n'
            'else\n'
            '  printf "[Available Updates] 1 packages total\\n"\n'
            'fi\n'
        )
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            with self.subTest(distro=distro, case='correct'):
                result, evidence, logs = self.run_inventory(product, rows, native_commands=native, distro=distro)
                self.assertEqual(result.returncode, 0, logs)
                self.assertEqual([item['result'] for item in evidence], ['PASS', 'PASS'])
                self.assertIn('native counter uc expected=1 actual=1', logs['outdated.log'])
            with self.subTest(distro=distro, case='false-zero'):
                wrong = product.replace('1 packages total', '2 packages total').replace(f'[{item}]', '[]')
                result, evidence, logs = self.run_inventory(wrong, rows, native_commands=native, distro=distro)
                self.assertEqual(result.returncode, 1, logs)
                self.assertEqual([item['result'] for item in evidence], ['FAIL', 'FAIL'])
        for case, mutation in (
            ('missing-version', (item, '{"name":"c","current_version":"1","new_version":""}')),
            ('no-summary', ('[Available Updates] 1 packages total', 'Updates may be available')),
            ('conflicting-zero', ('[Available Updates] 1 packages total',
                                  '[Available Updates] 1 packages total\\nEverything is up to date!')),
        ):
            with self.subTest(case=case):
                result, evidence, _ = self.run_inventory(product.replace(*mutation), rows,
                                                          native_commands=native)
                self.assertEqual(result.returncode, 1)
                self.assertIn('FAIL', [item['result'] for item in evidence])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_python_install_requires_active_executable_and_exact_version(self):
        rows = ['runtime-python-install\t["use","python","3.12.14"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        for fault in ('missing', 'inactive', 'wrong-version', 'broken', 'escaped', 'version-escaped', 'version-only', 'program-noop', 'program-failure', 'none'):
            with self.subTest(fault=fault):
                product = 'printf "Installed Python 3.12.14\\n"\n'
                if fault != 'missing':
                    version = '3.12.13' if fault == 'wrong-version' else '3.12.14'
                    script = '#!/bin/sh\n' + ('exit 1\n' if fault == 'broken' else f'printf "Python {version}\\n"\n')
                    if fault in ('program-noop', 'program-failure', 'none'):
                        # This models runner admission, not a real Python install.
                        behavior = {'program-noop': 'exit 0\n',
                                    'program-failure': 'echo missing-stdlib >&2\nexit 17\n',
                                    'none': 'printf "OMG_PYTHON_RUNTIME_OK:3.12.14\\n"\n'}[fault]
                        script = '#!/bin/sh\nif [ "$1" = --version ]; then printf "Python 3.12.14\\n"; exit 0; fi\ncat >/dev/null\n' + behavior
                    product += ': "${OMG_DATA_DIR:?isolated runtime state missing}"\nbase="$OMG_DATA_DIR/versions/python"\nmkdir -p "$base/3.12.14/bin"\n'
                    product += f'printf %s {shlex.quote(script)} > "$base/3.12.14/bin/python3"\nchmod 755 "$base/3.12.14/bin/python3"\n'
                    if fault != 'inactive':
                        product += 'ln -s 3.12.14 "$base/current"\n'
                    if fault == 'escaped':
                        product += 'mv "$base/3.12.14/bin/python3" "$OMG_DATA_DIR/external"\nln -s "$OMG_DATA_DIR/external" "$base/3.12.14/bin/python3"\n'
                    if fault == 'version-escaped':
                        product += 'mv "$base/3.12.14" "$OMG_DATA_DIR/external-version"\nln -s "$OMG_DATA_DIR/external-version" "$base/3.12.14"\n'
                result, evidence, logs = self.run_inventory(self.runtime_usage_fixture('python') + product, rows)
                self.assertEqual(result.returncode, 0 if fault == 'none' else 1, result.stderr)
                self.assertEqual(evidence[0]['result'], 'PASS' if fault == 'none' else 'FAIL')
                if fault != 'none':
                    self.assertIn('assertion failed: Python', logs['runtime-python-install.log'])
                if fault == 'program-failure':
                    self.assertIn('missing-stdlib', logs['runtime-python-install.log'])
                    self.assertIn('exit=17', logs['runtime-python-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_node_install_rejects_success_without_installed_runtime(self):
        rows = ['runtime-node-install\t["use","node","24.21.0"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        result, evidence, logs = self.run_inventory('printf "Installed Node.js 24.21.0\\n"\n', rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(evidence[0]['result'], 'FAIL')
        self.assertIn('assertion failed: Node', logs['runtime-node-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_node_install_rejects_incomplete_or_nonexecuting_runtime(self):
        rows = ['runtime-node-install\t["use","node","24.21.0"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        for fault in ('inactive', 'escaped', 'missing-npm', 'escaped-npm', 'version-only', 'noop', 'failure', 'none'):
            with self.subTest(fault=fault):
                # Successful mock models receipt admission only; real runtime
                # behavior is exercised independently with the exact oracle.
                body = {'version-only': 'echo v24.21.0\n', 'noop': 'exit 0\n',
                        'failure': 'echo npm-probe-failed >&2\nexit 17\n'}.get(fault, 'echo OMG_NODE_RUNTIME_OK:24.21.0\n')
                script = '#!/bin/sh\ncat >/dev/null\n' + body
                product = 'base="$OMG_DATA_DIR/versions/node"\nmkdir -p "$base/24.21.0/bin" "$base/24.21.0/lib/node_modules/npm/bin"\n'
                product += f'printf %s {shlex.quote(script)} > "$base/24.21.0/bin/node"\nchmod 755 "$base/24.21.0/bin/node"\n'
                if fault != 'inactive':
                    product += 'ln -s 24.21.0 "$base/current"\n'
                if fault != 'missing-npm':
                    product += 'echo fixture > "$base/24.21.0/lib/node_modules/npm/bin/npm-cli.js"\n'
                if fault in ('escaped', 'escaped-npm'):
                    target = 'bin/node' if fault == 'escaped' else 'lib/node_modules/npm/bin/npm-cli.js'
                    product += f'mv "$base/24.21.0/{target}" "$OMG_DATA_DIR/external"\nln -s "$OMG_DATA_DIR/external" "$base/24.21.0/{target}"\n'
                result, evidence, logs = self.run_inventory(self.runtime_usage_fixture('node') + product, rows)
                self.assertEqual(result.returncode, 0 if fault == 'none' else 1, result.stderr)
                self.assertEqual(evidence[0]['result'], 'PASS' if fault == 'none' else 'FAIL')
                if fault == 'failure':
                    self.assertIn('npm-probe-failed', logs['runtime-node-install.log'])
                    self.assertIn('exit=17', logs['runtime-node-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_go_install_rejects_success_without_compiler(self):
        rows = ['runtime-go-install\t["use","go","1.27.1"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        result, evidence, logs = self.run_inventory('echo Installed Go\n', rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(evidence[0]['result'], 'FAIL')
        self.assertIn('assertion failed: Go', logs['runtime-go-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_go_install_requires_build_program_and_test_effects(self):
        rows = ['runtime-go-install\t["use","go","1.27.1"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        for fault in ('inactive', 'escaped', 'version-only', 'build-noop', 'wrong-program', 'test-noop', 'test-failure', 'none'):
            with self.subTest(fault=fault):
                # Fake compiler models admission only; the actual compiler
                # runs this exact oracle separately on each supported distro.
                program = '#!/bin/sh\necho ' + ('wrong' if fault == 'wrong-program' else 'OMG_GO_RUNTIME_OK:go1.27.1') + '\n'
                build = 'exit 0' if fault == 'build-noop' else f'printf %s {shlex.quote(program)} > probe; chmod 755 probe'
                test = {'test-noop': 'echo "--- PASS: TestProbe (0.00s)"',
                        'test-failure': 'echo failing-test >&2; exit 17'}.get(fault,
                            'echo go-test-executed > test-complete; echo "--- PASS: TestProbe (0.00s)"')
                compiler = f'#!/bin/sh\ncase "$1" in\nenv) printf "%s\\ngo1.27.1\\n" "$GOROOT";;\nbuild) {build};;\ntest) {test};;\n*) exit 23;;\nesac\n'
                if fault == 'version-only':
                    compiler = '#!/bin/sh\necho go1.27.1\n'
                product = 'base="$OMG_DATA_DIR/versions/go"\nmkdir -p "$base/1.27.1/bin"\n'
                product += f'printf %s {shlex.quote(compiler)} > "$base/1.27.1/bin/go"\nchmod 755 "$base/1.27.1/bin/go"\n'
                if fault != 'inactive':
                    product += 'ln -s 1.27.1 "$base/current"\n'
                if fault == 'escaped':
                    product += 'mv "$base/1.27.1/bin/go" "$OMG_DATA_DIR/external"\nln -s "$OMG_DATA_DIR/external" "$base/1.27.1/bin/go"\n'
                result, evidence, logs = self.run_inventory(self.runtime_usage_fixture('go') + product, rows)
                self.assertEqual(result.returncode, 0 if fault == 'none' else 1, result.stderr)
                self.assertEqual(evidence[0]['result'], 'PASS' if fault == 'none' else 'FAIL')
                if fault == 'test-failure':
                    self.assertIn('exit=17', logs['runtime-go-install.log'])
                    self.assertIn('failing-test', logs['runtime-go-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_go_install_gets_a_bounded_large_archive_budget(self):
        rows = ['runtime-go-install\t["use","go","1.27.1"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        program = '#!/bin/sh\necho OMG_GO_RUNTIME_OK:go1.27.1\n'
        compiler = (
            '#!/bin/sh\ncase "$1" in\n'
            'env) printf "%s\\ngo1.27.1\\n" "$GOROOT";;\n'
            f'build) printf %s {shlex.quote(program)} > probe; chmod 755 probe;;\n'
            'test) echo go-test-executed > test-complete; echo "--- PASS: TestProbe (0.00s)";;\n'
            '*) exit 23;;\nesac\n'
        )
        product = self.runtime_usage_fixture('go')
        product += 'sleep 2\nbase="$OMG_DATA_DIR/versions/go"\nmkdir -p "$base/1.27.1/bin"\n'
        product += f'printf %s {shlex.quote(compiler)} > "$base/1.27.1/bin/go"\nchmod 755 "$base/1.27.1/bin/go"\n'
        product += 'ln -s 1.27.1 "$base/current"\n'
        result, evidence, logs = self.run_inventory(product, rows, row_timeout=1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(evidence[0]['result'], 'PASS', logs)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_python_download_outlives_generic_budget_but_failure_stays_fatal(self):
        rows = ['runtime-python-install\t["use","python","3.12.14"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        product = 'sleep 2\nprintf "download failed\\n" >&2\nexit 17\n'
        result, evidence, logs = self.run_inventory(product, rows, row_timeout=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
        self.assertEqual(evidence[0]['exit_code'], 17, logs)
        self.assertIn('download failed', logs['runtime-python-install.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_executor_timeout_names_deadline_not_product_refusal(self):
        rows = ['slow\t["slow"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        result, evidence, logs = self.run_inventory('sleep 2\n', rows, row_timeout=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
        self.assertEqual(evidence[0]['exit_code'], 124, logs)
        self.assertIn('command exceeded 1s QEMU row deadline', logs['slow.log'])
        self.assertNotIn('product refusal', logs['slow.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_system_update_transactions_outlive_the_generic_row_budget(self):
        rows = [
            'update-check\t["update","--check"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\tnone',
            'update-turbo\t["update","--turbo"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\tupdate-turbo-output\tnone',
        ]
        product = (
            'if [[ "$1" == update && "$2" == --check ]]; then sleep 2; exit 0; fi\n'
            'sleep 1\n'
            'printf "%s\\n" "TURBO System Update" "cached, no sync" "Upgraded 1 package"\n'
        )
        result, evidence, logs = self.run_inventory(product, rows, row_timeout=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(evidence[0]['case_id'], 'qemu-arch-update-check')
        self.assertEqual(evidence[0]['result'], 'FAIL', logs)
        self.assertEqual(evidence[0]['exit_code'], 124)
        self.assertEqual(evidence[1]['case_id'], 'qemu-arch-update-turbo')
        self.assertEqual(evidence[1]['result'], 'PASS', logs)

    def generated_hooks(self):
        source = (ROOT / 'src/cli/git_hooks.rs').read_text(encoding='utf-8')
        return {name: (re.search(r'const ' + constant + r': &str = r#"(.*?)"#;', source, re.S).group(1), 0o755)
                for name, constant in [('pre-commit', 'PRE_COMMIT_HOOK'),
                                       ('post-checkout', 'POST_CHECKOUT_HOOK'),
                                       ('post-merge', 'POST_MERGE_HOOK')]}

    def test_executable_noop_hooks_cannot_satisfy_behavior(self):
        hooks = self.generated_hooks()
        result = self.run_oracle(assertion='hooks-installed', hooks=hooks)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in hooks:
            with self.subTest(hook=name):
                content, mode = hooks[name]
                changed = dict(hooks)
                changed[name] = (content.splitlines()[0] + '\n' + content.splitlines()[1] + '\nexit 0\n', mode)
                result = self.run_oracle(assertion='hooks-installed', hooks=changed)
                self.assertNotEqual(result.returncode, 0, f'{name} did nothing but passed')
                self.assertIn('assertion failed:', result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_actual_runner_executes_installed_hook_contracts(self):
        rows = ['hooks\t["hooks","install"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\thooks-installed\ttempdir-drop']
        for disabled in (False, True):
            with self.subTest(disabled=disabled):
                product = 'mkdir -p .git/hooks\n'
                for name, (content, _) in self.generated_hooks().items():
                    if disabled:
                        content = '\n'.join(content.splitlines()[:2]) + '\nexit 0\n'
                    product += f'printf %s {shlex.quote(content)} > .git/hooks/{name}\nchmod 755 .git/hooks/{name}\n'
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual(result.returncode, 1 if disabled else 0, result.stderr)
                self.assertEqual(evidence[0]['result'], 'FAIL' if disabled else 'PASS')
                if disabled:
                    self.assertIn('hook notice', logs['hooks.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_force_row_requires_replacing_user_content_not_reinstalling_identical_hooks(self):
        rows = [
            'hooks-install\t["hooks","install"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\thooks-installed\ttempdir-drop',
            'hooks-install-force\t["hooks","install","--force"]\tisolated-write\t0\tpass\thooks-install\thermetic\thermetic:pass\thooks-installed\ttempdir-drop',
        ]
        for ignored in (False, True):
            with self.subTest(ignored=ignored):
                product = 'mkdir -p .git/hooks\n'
                if ignored:
                    product += 'if [[ "${3:-}" == --force ]]; then exit 0; fi\n'
                for name, (content, _) in self.generated_hooks().items():
                    product += f'printf %s {shlex.quote(content)} > .git/hooks/{name}\nchmod 755 .git/hooks/{name}\n'
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual(result.returncode, int(ignored), result.stderr)
                self.assertEqual([row['result'] for row in evidence], ['PASS', 'FAIL' if ignored else 'PASS'])
                if ignored:
                    self.assertIn('assertion failed: installed hook', logs['hooks-install-force.log'])

    def test_failure_diagnosis_precedes_long_product_output(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN ROW LOG')
        end = source.index('# END ROW LOG', begin)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'stdout').write_text('product output\n' * 100, encoding='utf-8', newline='\n')
            (root / 'stderr').write_text('assertion failed: selected task did not run\n', encoding='utf-8', newline='\n')
            result = subprocess.run(
                [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'), '-c',
                 source[begin:end] + '\nwrite_row_log row.log stdout stderr fixture FAIL', '_'],
                cwd=root, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            log = (root / 'row.log').read_text()
            self.assertIn('assertion failed: selected task did not run', '\n'.join(log.splitlines()[:12]))
            self.assertIn('case=fixture verdict=FAIL', log.splitlines()[0])
            self.assertEqual(log.count('product output'), 100)

    def test_generated_man_pages_require_real_content_and_matching_count(self):
        row = next(line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
                   if line.startswith('generate-man\t'))
        page = '.TH "omg" "1"\n.SH "NAME"\nomg\\-command\n.SH "SYNOPSIS"\nomg\n'
        pages = tuple((ROOT / 'tests/man_page_inventory.txt').read_text().splitlines())
        self.assertEqual(len(pages), 140)
        product = f'''[[ "$1" == generate-man && "$2" == --output ]] || exit 70
mkdir -p "$3"
for name in {shlex.join(pages)}; do
  printf %s {shlex.quote(page)} > "$3/$name"
done
printf 'Generated {len(pages)} man pages\\n'
'''
        for mutation, expected in (
            ('', 'PASS'),
            ('sed -i "/SYNOPSIS/d" "$3/omg-team.1"\n', 'FAIL'),
            ('rm "$3/omg-team-golden-path-create.1"\n', 'FAIL'),
            ('mv "$3/omg-audit-licenses.1" "$3/omg-unrelated.1"\n', 'FAIL'),
            ('find "$3" -type f ! -name omg.1 ! -name omg-generate-man.1 -delete\n'
             'printf "Generated 2 man pages\\n"; exit 0\n', 'FAIL'),
            ('touch "$3/omg-invented.1"\n', 'FAIL'),
            ('printf "Generated 141 man pages\\n"; exit 0\n', 'FAIL'),
        ):
            with self.subTest(mutation=mutation):
                announcement = f"printf 'Generated {len(pages)} man pages\\n'"
                command = product.replace(announcement, mutation + announcement)
                result, evidence, logs = self.run_inventory(command, [row])
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'))
        third_level = {'omg-enterprise-policy-show.1', 'omg-team-roles-list.1',
                       'omg-team-golden-path-create.1',
                       'omg-team-golden-path-delete.1',
                       'omg-team-golden-path-list.1'}
        legacy_pages = tuple(name for name in pages if name not in third_level)
        legacy_product = product.replace(shlex.join(pages), shlex.join(legacy_pages)).replace(
            f'Generated {len(pages)} man pages',
            f'Generated {len(legacy_pages)} man pages')
        result, evidence, logs = self.run_inventory(legacy_product, [row], exact_man=False)
        self.assertEqual((result.returncode, evidence[0]['result']), (0, 'PASS'), logs)
        result, evidence, logs = self.run_inventory(legacy_product, [row], exact_man=True)
        self.assertEqual((result.returncode, evidence[0]['result']), (1, 'FAIL'), logs)

    def test_absolute_path_exports_refuse_without_evidence(self):
        rows = [line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
                if line.startswith(('audit-export\t', 'audit-export-flags\t',
                                    'enterprise-audit-export\t'))]
        self.assertEqual(len(rows), 3)
        for row in rows:
            for mutation, expected in (
                ('', 'PASS'),
                ('printf "Error: unrelated failure\\n" >&2\n', 'FAIL'),
                ('mkdir -p "${@: -1}"\n', 'FAIL'),
            ):
                with self.subTest(row=row.split('\t', 1)[0], mutation=mutation):
                    product = mutation + '''if [[ "$*" == *export* ]]; then
  printf 'Error: Absolute paths not allowed\\n' >&2
  exit 1
fi
exit 70
'''
                    if mutation.startswith('printf'):
                        product = mutation + 'exit 1\n'
                    result, evidence, logs = self.run_inventory(product, [row])
                    self.assertEqual(evidence[0]['result'], expected, logs)
                    self.assertEqual(result.returncode, int(expected == 'FAIL'))

    def test_enterprise_export_requires_five_private_evidence_files(self):
        row = next(line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
                   if line.startswith('enterprise-audit-export-flags\t'))
        product = '''[[ "$1:$2:$3:$4:$5:$6:$7:$8" == enterprise:audit-export:--framework:iso27001:--period:2025-Q1:--output:./enterprise-evidence-flags ]] || exit 70
mkdir enterprise-evidence-flags
printf '%s' '{"unavailable_evidence":[{"artifact":"access-control-matrix","reason":"unavailable"}]}' > enterprise-evidence-flags/limitations.json
printf '[]' > enterprise-evidence-flags/change-log.json
printf '{}' > enterprise-evidence-flags/policy-enforcement.json
printf 'package,version,description\\nbash,1,shell\\n' > enterprise-evidence-flags/installed-packages.csv
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"bash"}]}' > enterprise-evidence-flags/sbom-inventory.json
chmod 600 enterprise-evidence-flags/*
printf 'Audit evidence exported: iso27001 2025-Q1\\n'
'''
        for mutation, expected in (
            ('', 'PASS'),
            ('rm enterprise-evidence-flags/sbom-inventory.json\n', 'FAIL'),
            ('chmod 644 enterprise-evidence-flags/limitations.json\n', 'FAIL'),
            ('printf invalid > enterprise-evidence-flags/change-log.json\n', 'FAIL'),
        ):
            with self.subTest(mutation=mutation):
                result, evidence, logs = self.run_inventory(product + mutation, [row])
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'))
        for mutation, expected in (('', 'PASS'), ('mkdir enterprise-evidence-flags\n', 'FAIL')):
            with self.subTest(distro='debian', mutation=mutation):
                product = mutation + '''printf 'Error: Installed-package export requires the Arch package backend\\n' >&2
exit 1
'''
                result, evidence, logs = self.run_inventory(product, [row], distro='debian')
                self.assertEqual(evidence[0]['result'], expected, logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'))

    def test_team_compliance_refusal_never_writes_an_unevaluated_report(self):
        rows = [line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
                if line.startswith(('team-init\t', 'team-compliance-export\t'))]
        self.assertEqual(len(rows), 2)
        for mutation, expected in (
            ('', 'PASS'),
            ('printf "Error: unrelated failure\\n" >&2; exit 1\n', 'FAIL'),
            ('printf fabricated > "$4"\n', 'FAIL'),
        ):
            with self.subTest(mutation=mutation):
                product = ('[[ "$1" == team ]] || exit 70\n'
                           'if [[ "$2" == init ]]; then\n' + self.local_fixture_product() + '\nexit $?\nfi\n'
                           '[[ "$2" == compliance && "$3" == --export ]] || exit 70\n') + mutation
                if not mutation.startswith('printf "Error: unrelated'):
                    product += '''printf "Error: No compliance data is available to export to '%s'; compliance evidence requires an evaluated report\\n" "$4" >&2
exit 1
'''
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual([item['result'] for item in evidence], ['PASS', expected], logs)
                self.assertEqual(result.returncode, int(expected == 'FAIL'))

    def test_audit_log_export_rejects_unfiltered_stale_or_nonprivate_records(self):
        row = next(line for line in (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('audit-log-flags\t'))
        self.assertEqual(row.split('\t')[8], 'local:audit-log-flags')
        # Exercise the retained richer historical six-record export contract.
        row = row.replace('local:audit-log-flags', 'audit-log-filtered-export')
        product = '''[[ "$1:$2:$3:$4:$5:$6:$7" == audit:log:--limit:3:--severity:error:--export ]] || exit 70
python3 - "$8" <<'PY'
import json, pathlib, sys
records = [json.loads(line) for line in pathlib.Path('audit-log-data/audit/audit.jsonl').read_text(encoding='utf-8').splitlines()]
output = pathlib.Path(sys.argv[1])
output.write_text(json.dumps([dict(records[i], hash_version=0) for i in (5, 4, 2)]))
output.chmod(0o600)
PY
printf 'OMG Exporting audit log to %s...\\n✓ Export successful\\n' "$8"
'''
        for mutation, expected in (
            ('', 'PASS'),
            ('rm "$8"\n', 'FAIL'),
            ('printf "[]" > "$8"\n', 'FAIL'),
            ('chmod 644 "$8"\n', 'FAIL'),
            ('cp audit-log-data/audit/audit.jsonl "$8"\n', 'FAIL'),
            ('printf changed >> audit-log-data/audit/audit.jsonl\n', 'FAIL'),
            ("python3 -c \"import json,pathlib; p=pathlib.Path('audit-log-export.json'); r=json.loads(p.read_text(encoding='utf-8')); p.write_text(json.dumps(r[::-1]))\"\n", 'FAIL'),
            ("python3 -c \"import json,pathlib; p=pathlib.Path('audit-log-export.json'); r=json.loads(p.read_text(encoding='utf-8')); r[0].pop('hash_version'); p.write_text(json.dumps(r))\"\n", 'FAIL'),
            ("python3 -c \"import json,pathlib; p=pathlib.Path('audit-log-export.json'); r=json.loads(p.read_text(encoding='utf-8')); r[0]['hash_version']=1; p.write_text(json.dumps(r))\"\n", 'FAIL'),
        ):
            with self.subTest(mutation=mutation):
                result, evidence, logs = self.run_inventory(product + mutation, [row])
                self.assertEqual((result.returncode, evidence[0]['result']),
                                 (int(expected == 'FAIL'), expected), logs)
        result, evidence, logs = self.run_inventory('exit 0\n', [row])
        self.assertEqual((result.returncode, evidence[0]['result']), (1, 'FAIL'), logs)

    def test_negative_workspace_rows_reject_unrelated_failures_and_state_changes(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
        prereqs = [line for line in inventory if line.startswith(('workspace-init\t', 'workspace-add\t'))]
        self.assertEqual(len(prereqs), 2)
        setup = ('if [[ "$2" == init || "$2" == add ]]; then\n'
                 + self.workspace_fixture_product() + '\nexit $?\nfi\n')
        products = {
            'workspace-run': '''printf "%s\\n" "→ Task 'true' not found, trying 'make true'..." "  ✗ 'omg run true' in '.' exited with code 1" '⚠ 0 succeeded, 1 failed'
printf "%s\\n" "make: *** No rule to make target 'true'.  Stop." "Error: 1 project(s) failed to run 'true'" >&2
''',
            'workspace-check': '''printf '→ fixture\\n  ⚠ needs attention\\n'
printf '%s\\n' 'Error: No omg.lock file found' 'Error: 1 project(s) need attention, 0 failed to check (of 1 total)' >&2
''',
        }
        for case, receipt in products.items():
            row = next(line for line in inventory if line.startswith(case + '\t'))
            for body, expected in (
                (receipt, 'PASS'),
                ('printf "Error: unrelated failure\\n" >&2\n', 'FAIL'),
                (receipt + 'printf changed >> omg-workspace.toml\n', 'FAIL'),
                (receipt + 'printf changed >> Makefile\n', 'FAIL'),
                (receipt + 'printf fabricated > omg.lock\n', 'FAIL'),
                (receipt.replace('1 project(s)', '2 project(s)'), 'FAIL'),
            ):
                with self.subTest(case=case, body=body):
                    result, evidence, logs = self.run_inventory(setup + body + 'exit 1\n', prereqs + [row])
                    self.assertEqual([item['result'] for item in evidence], ['PASS', 'PASS', expected], logs)
                    self.assertEqual(result.returncode, int(expected == 'FAIL'), logs)


    @unittest.skipIf(os.name == 'nt', 'Generated offline launch requires POSIX bash')
    def test_offline_preview_launch_admits_only_the_exact_fedora_dry_run(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        start = source.index('  if [[ "$network_scope" == offline ]]; then\n')
        launch = source[start:source.index('  # Bash SECONDS', start)]
        defaults = dict(distro='fedora', case='remove', safety='read',
                        assertions='package-dry-run-remove', expected_ux='pass',
                        requires='-', tier='hermetic', targets='hermetic:pass',
                        cleanup='tempdir-drop', network_scope='offline', ssh_user='fixture',
                        args_json='["remove","--dry-run","jq"]')
        variants = [('exact native preview', {}, '0:retained')]
        for key, value in (
            ('distro', 'arch'), ('distro', 'debian'), ('distro', 'ubuntu'), ('ssh_user', 'root'),
            ('case', 'other'), ('safety', 'package-mutation'),
            ('assertions', '-'), ('expected_ux', 'declared'), ('requires', 'help'),
            ('tier', 'container'), ('targets', 'fedora:pass'), ('cleanup', 'container-prune'),
            ('args_json', '["remove","jq"]'),
            ('args_json', '["remove","--dry-run","--yes","jq"]'),
            ('args_json', '["remove","--recursive","--dry-run","jq"]'),
            ('args_json', '["remove","--dry-run","bash"]'),
            ('args_json', '["remove","--dry-run","jq","other"]'),
        ):
            variants.append((key + '=' + value, {key: value}, '1:dropped'))
        variants += [('wrong expected exit', {'resolved_exit': '1'}, '1:dropped'),
                     ('prerequisite chain', {'chain_entry': 'help'}, '1:dropped'),
                     ('network row unchanged', {'network_scope': 'network'}, 'unwrapped'),
                     ('install row', {'case': 'install', 'assertions': 'package-dry-run-install',
                                      'args_json': '["install","--dry-run","pacman"]'}, '1:dropped'),
                     ('recursive removal row', {'case': 'remove-flags',
                                               'assertions': 'package-dry-run-recursive'}, '1:dropped')]
        wrappers = r"""
sudo() { [[ "$1" == -n ]] || return 90; shift; "$@"; }
unshare() { [[ "$1:$2" == --net:-- ]] || return 91; shift 2; "$@"; }
setpriv() {
  local nnp=0 bound=retained uid= gid= clear=0 inh=0 ambient=0
  while [[ "$1" != env ]]; do
    case "$1" in
      --reuid=*) uid=${1#*=} ;; --regid=*) gid=${1#*=} ;;
      --clear-groups) clear=1 ;; --no-new-privs) nnp=1 ;;
      --bounding-set=-all) bound=dropped ;; --inh-caps=-all) inh=1 ;;
      --ambient-caps=-all) ambient=1 ;; *) return 92 ;;
    esac; shift
  done
  [[ "$uid" == "$(id -u)" && "$gid" == "$(id -g)" && "$uid" != 0 && "$clear:$inh:$ambient" == 1:1:1 ]] || return 93
  export OMG_QEMU_TEST_LAUNCH="$nnp:$bound"
  "$@"
}
export -f sudo unshare setpriv
"""
        for label, changes, expected in variants:
            values = dict(defaults, **{k: v for k, v in changes.items()
                                      if k not in {'resolved_exit', 'chain_entry'}})
            assignments = '\n'.join(f'{key}={shlex.quote(value)}' for key, value in values.items())
            chain = shlex.quote(changes['chain_entry']) if 'chain_entry' in changes else ''
            setup = (assignments + '\ndeclare -A row_exit=([$case]='
                     + shlex.quote(changes.get('resolved_exit', '0')) + ')\nchain=(' + chain + ')\n')
            script = (wrappers + setup
                      + 'remote=' + shlex.quote('bash -c ' + shlex.quote(
                          'printf %s "${OMG_QEMU_TEST_LAUNCH:-unwrapped}"')) + '\n'
                      + launch + '\nbash -c "$remote"\n')
            with self.subTest(label=label):
                result = subprocess.run(['bash', '-c', script], capture_output=True,
                                        text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected, label)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX descriptors')
    def test_fedora_preview_actual_runner_keeps_native_plan_and_setup_failures(self):
        row = next(line for line in
                   (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                   if line.startswith('remove\t'))
        native = {'rpm': r"""
case "$1" in
  -qa) printf 'jq\t0\t1.8.1\t3.fc44\tx86_64\noniguruma\t0\t6.9.10\t3.fc44\tx86_64\n' ;;
  -q) case "$*" in *EPOCHNUM*) printf '0\t1.8.1\t3.fc44\n' ;; *ARCH*) printf 'jq\tx86_64\n' ;; *) exit 2 ;; esac ;;
  *) exit 2 ;;
esac
""", 'dnf': "printf 'jq x86_64 User\\noniguruma x86_64 Dependency\\n'\n",
                  'sudo': '[[ "$1" == -n ]] || exit 90\nshift\nexec "$@"\n',
                  'unshare': '[[ "$1:$2" == --net:-- ]] || exit 91\nshift 2\nexec "$@"\n',
                  'setpriv': r"""
export OMG_QEMU_TEST_NNP=0
while [[ "$1" != env ]]; do
  [[ "$1" != --no-new-privs ]] || export OMG_QEMU_TEST_NNP=1
  shift
done
exec "$@"
"""}
        captured = ('sudo: The "no new privileges" flag is set, which prevents sudo from running as root.\n'
                    'sudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.\n')
        preview = ("[[ \"$1:$2:$3\" == remove:--dry-run:jq ]] || exit 70\n"
                   + 'if [[ "$OMG_QEMU_TEST_NNP" == 1 ]]; then printf %s '
                   + shlex.quote(captured) + ' >&2; exit 1; fi\n'
                   + "printf '%s\\n' '  | Remove Preview' '    dry run' "
                   "'  → The following packages would be removed:' "
                   "'    ✗ jq.x86_64 1.8.1-3.fc44' "
                   "'    ✗ oniguruma.x86_64 6.9.10-3.fc44' '  ℹ No changes made (dry run)'\n")
        result, evidence, logs = self.run_inventory(preview, [row], distro='fedora',
                                                   native_commands=native, isolation_scope='offline')
        self.assertEqual(result.returncode, 0, f'{result.stdout}\n{result.stderr}\n{logs}')
        self.assertEqual(evidence[0]['result'], 'PASS', logs)
        self.assertIn('OMG_QEMU_RECEIPT:product:0:0', logs['remove.stdout.log'])
        for label, product, commands, expected in (
            ('native installed-state changed', 'touch native-state-changed\n' + preview,
             dict(native, rpm=native['rpm'].replace('-qa) ', '-qa) [[ ! -e native-state-changed ]] || { echo changed; exit 0; }; ')), 'FAIL'),
            ('native reasons changed', 'touch native-reason-changed\n' + preview,
             dict(native, dnf='[[ ! -e native-reason-changed ]] || { echo changed; exit 0; }\n' + native['dnf']), 'FAIL'),
            ('wrong canonical identity', preview.replace('✗ jq.x86_64', '✗ jq.i686'), native, 'FAIL'),
            ('silent product', 'exit 0\n', native, 'FAIL'),
            ('namespace setup failed', preview, dict(native, unshare='exit 73\n'), 'HARNESS_ERROR'),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, [row], distro='fedora',
                                                           native_commands=commands, isolation_scope='offline')
                self.assertEqual(result.returncode, 1, logs)
                self.assertEqual(evidence[0]['result'], expected, logs)
                if expected == 'HARNESS_ERROR':
                    self.assertNotIn('OMG_QEMU_RECEIPT:product:', logs['remove.stdout.log'])

        for column, value in ((1, '["remove","jq"]'),
                              (1, '["remove","--dry-run","--yes","jq"]'),
                              (1, '["remove","--recursive","--dry-run","jq"]'),
                              (1, '["remove","--dry-run","jq","other"]'),
                              (2, 'package-mutation'), (3, '1'), (8, '-')):
            fields = row.split('\t')
            fields[column] = value
            with self.subTest(label='invalid admission tuple', column=column, value=value):
                result, evidence, logs = self.run_inventory(preview, ['\t'.join(fields)],
                                                           distro='fedora', native_commands=native,
                                                           isolation_scope='offline', allow_mutations=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(evidence, [], logs)
                self.assertEqual(logs, {})

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX descriptors')
    def test_rollback_refusals_bind_the_backend_and_preserve_absent_history(self):
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in {'rollback', 'rollback-yes'}]
        self.assertEqual(len(rows), 2)
        empty = 'Error: No history entries available for rollback\n'
        fedora = 'Error: Package rollback is not implemented for the selected Fedora backend\n'
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            cause = fedora if distro == 'fedora' else empty
            good = 'printf %s ' + shlex.quote(cause) + ' >&2\nexit 1\n'
            with self.subTest(distro=distro):
                result, evidence, logs = self.run_inventory(good, rows, distro=distro)
                self.assertEqual(result.returncode, 0, logs)
                self.assertEqual([item['result'] for item in evidence], ['PASS', 'PASS'], logs)
        supported = 'printf %s ' + shlex.quote(empty) + ' >&2\nexit 1\n'
        for label, product in (
            ('supported stdout contamination', 'echo unrelated\n' + supported),
            ('supported stderr preamble', 'echo unrelated >&2\n' + supported),
            ('supported history created', 'printf "[]" > "$OMG_DATA_DIR/history.json"\n' + supported),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows, distro='arch')
                self.assertEqual(result.returncode, 1, logs)
                self.assertEqual([item['result'] for item in evidence], ['FAIL', 'FAIL'], logs)
        for distro in ('arch', 'debian', 'ubuntu'):
            with self.subTest(label='wrong Fedora cause', distro=distro):
                result, evidence, logs = self.run_inventory(good, rows, distro=distro)
                self.assertEqual(result.returncode, 1, logs)
                self.assertEqual([item['result'] for item in evidence], ['FAIL', 'FAIL'], logs)
        for label, product in (
            ('wrong history cause', 'printf %s ' + shlex.quote(empty) + ' >&2\nexit 1\n'),
            ('wrong backend cause', good.replace('Fedora backend', 'MacOS backend')),
            ('generic sudo refusal', 'echo "sudo: a password is required" >&2\nexit 1\n'),
            ('stdout contamination', 'echo unrelated\n' + good),
            ('stderr preamble', 'echo unrelated >&2\n' + good),
            ('incorrect success', good.replace('exit 1', 'exit 0')),
            ('incorrect refusal exit', good.replace('exit 1', 'exit 2')),
            ('created empty history', 'printf "[]" > "$OMG_DATA_DIR/history.json"\n' + good),
            ('changed unrelated fixture', 'echo changed >> "$OMG_DATA_DIR/fixture-unrelated.txt"\n' + good),
        ):
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows, distro='fedora')
                self.assertEqual(result.returncode, 1, logs)
                self.assertEqual([item['result'] for item in evidence], ['FAIL', 'FAIL'], logs)


    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX descriptors')
    def test_stream_transport_keeps_product_eof_following_rows_and_setup_refusals(self):
        rows = [case + '\t["--help"]\thelp-boundary\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop'
                for case in ('help-one', 'help-two')]
        product = '''if IFS= read -r input; then echo "product consumed stdin" >&2; exit 73; fi
[[ -z "${qemu_row_payload+x}" ]] || exit 74
printf 'Usage: fixture\\n'
'''
        for label, prefix, suffix, expected in (
            ('exact stream', '', '', 'PASS'),
            ('truncated', '', 'head -c -1 | ', 'HARNESS_ERROR'),
            ('extra bytes', '', '{ cat; printf extra; } | ', 'HARNESS_ERROR'),
            ('NUL inserted', '', '{ printf "\\0"; cat; } | ', 'HARNESS_ERROR'),
            ('setup failed', 'exit 73\n', '', 'HARNESS_ERROR'),
        ):
            ssh = prefix + 'export qemu_row_payload=inherited-export\n' + suffix + 'bash -c "${@: -1}"\n'
            with self.subTest(label=label):
                result, evidence, logs = self.run_inventory(product, rows, ssh_body=ssh)
                self.assertEqual(result.returncode, int(expected != 'PASS'), logs)
                self.assertEqual([item['result'] for item in evidence], [expected, expected], logs)
                if expected != 'PASS':
                    self.assertFalse(any('OMG_QEMU_RECEIPT:product:' in value for value in logs.values()), logs)

    def run_inventory(self, product, rows, *, native_commands=None, home_files=None, distro='arch', tiers='hermetic', row_timeout=None, allow_mutations=False, fake_tree_binary=False, exact_man=True, binary_name='product', isolation_scope=None, ssh_body=None):
        def shell_path(path):
            value = path.as_posix()
            return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('home', 'bin', 'guest'):
                (root / name).mkdir()
            guest_files = {
                'man_page_inventory.txt': (ROOT / 'tests/man_page_inventory.txt').read_bytes(),
                'qemu-enterprise-export-oracle.py':
                    (ROOT / 'scripts/qemu-enterprise-export-oracle.py').read_bytes(),
                'qemu-audit-log-oracle.py':
                    (ROOT / 'scripts/qemu-audit-log-oracle.py').read_bytes(),
                'qemu-doctor-index-oracle.py':
                    (ROOT / 'scripts/qemu-doctor-index-oracle.py').read_bytes(),
            }
            guest_files.update(home_files or {})
            for name, content in guest_files.items():
                (root / 'home' / name).write_bytes(content)
            for name, content in (native_commands or {}).items():
                tool = root / 'bin' / name
                tool.write_text('#!/usr/bin/env bash\n' + content, encoding='utf-8', newline='\n')
                tool.chmod(0o755)
            binary = root / binary_name
            # The real submitted product is an ELF executable and remains
            # launchable when its PATH is restricted. Use an absolute shell
            # interpreter for the fixture so it has that same property.
            binary.write_text('#!/bin/bash\n' + product, encoding='utf-8', newline='\n')
            binary.chmod(0o755)
            ssh = root / 'bin/ssh'
            ssh.write_text('#!/usr/bin/env bash\n' +
                           (ssh_body or 'exec bash -c "${@: -1}"\n'),
                           encoding='utf-8', newline='\n')
            ssh.chmod(0o755)
            inventory = root / 'cases.tsv'
            inventory.write_text(
                'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup\n'
                + '\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
            env = dict(os.environ, HOME=shell_path(root / 'home'),
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
                       PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
            driver = ROOT / 'scripts/qemu-inventory.sh'
            if fake_tree_binary:
                env['OMG_QEMU_TEST_TREE_BINARY'] = shell_path(root / 'home/tree-binary')
                # Substitute the native path in a private controller copy,
                # before its size/hash are computed. Keep the receiver exact;
                # changing streamed bytes would rightly fail authentication.
                fixture_scripts = root / 'scripts'
                fixture_scripts.mkdir()
                for helper in (ROOT / 'scripts').iterdir():
                    if helper.is_file() and helper.name != driver.name:
                        (fixture_scripts / helper.name).symlink_to(helper)
                fixture_driver = fixture_scripts / driver.name
                fixture_driver.write_text(driver.read_text(encoding='utf-8').replace(
                    '/usr/bin/tree', shell_path(root / 'home/tree-binary')),
                    encoding='utf-8', newline='\n')
                driver = fixture_driver
            command = [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'),
                       str(driver), '--work', str(root),
                       '--binary', shell_path(binary), '--tsv', str(inventory),
                       '--distro', distro, '--tiers', tiers, '--tag', 'fixture']
            if isolation_scope is not None:
                policy = root / 'network-policy.json'
                policy.write_text(json.dumps({
                    'inventory_sha256': hashlib.sha256(inventory.read_bytes()).hexdigest(),
                    'scopes': {row.split('\t', 1)[0]: isolation_scope for row in rows},
                }), encoding='utf-8')
                command += ['--isolate-hermetic', '--network-policy', str(policy)]
            if exact_man:
                command += ['--man-page-inventory',
                            shell_path(ROOT / 'tests/man_page_inventory.txt')]
            if row_timeout is not None:
                command += ['--row-timeout', str(row_timeout)]
            if allow_mutations:
                command.append('--allow-mutations')
            result = subprocess.run(
                command,
                env=env, capture_output=True, text=True,
                timeout=max(120, (row_timeout or 0) + 10))
            evidence = root / 'inventory/results.json'
            self.assertTrue(evidence.exists(), result.stdout + result.stderr)
            return result, json.loads(evidence.read_text()), {
                path.name: path.read_text() for path in (root / 'inventory/rows').glob('*.log')}

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_trixie_runner_selects_apt_targets_and_keeps_guest_identity(self):
        rows = ['help\t["--help"]\thelp-boundary\tarch:1,debian:0,ubuntu:0,fedora:125\tpass\t-\thermetic\tarch:pending,debian:pass,ubuntu:pass,fedora:pending\t-\ttempdir-drop']
        result, evidence, logs = self.run_inventory(
            'printf "Usage: fixture\\n"\n', rows, distro='debian-trixie')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(evidence), 1, logs)
        self.assertEqual(evidence[0]['case_id'], 'qemu-debian-trixie-help')
        self.assertEqual(evidence[0]['distro'], 'debian-trixie')
        self.assertEqual(evidence[0]['result'], 'PASS', logs)
        self.assertEqual(evidence[0]['exit_code'], 0, logs)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_actual_runner_records_not_applicable_target_without_running_product(self):
        rows = [
            'help\t["--help"]\thelp-boundary\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop',
            'apt-only\t["clean","--orphans"]\tpackage-mutation\t0\tpass\t-\tcontainer\t'
            'arch:not-applicable,debian:pass,ubuntu:pass,fedora:not-applicable\t-\tcontainer-prune',
        ]
        product = '[[ "$1" == --help ]] || exit 99\nprintf "Usage: fixture\\n"\n'
        result, evidence, _ = self.run_inventory(
            product, rows, tiers='hermetic,container', allow_mutations=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS', 'SKIPPED'])
        self.assertEqual(evidence[1]['exit_code'], -1)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_actual_runner_rejects_false_green_help_and_exports(self):
        rows = [
            'help\t["--help"]\thelp-boundary\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop',
            'export\t["export"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\tartifact:manifest.json\ttempdir-drop',
        ]
        result, evidence, logs = self.run_inventory('printf not-json > manifest.json\nprintf ok\\n\n', rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['FAIL', 'FAIL'])
        self.assertIn('assertion failed:', logs['export.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_prerequisite_diagnostic_cannot_cover_a_silent_refusal(self):
        rows = [
            'prepare\t["prepare"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop',
            'refuse\t["refuse"]\tcontrolled-error\t1\tpass\tprepare\thermetic\thermetic:pass\t-\ttempdir-drop',
        ]
        product = 'if [[ "$1" == prepare ]]; then echo preparation-diagnostic >&2; exit 0; fi\nexit 1\n'
        result, evidence, logs = self.run_inventory(product, rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS', 'FAIL'])
        self.assertIn('own stderr explanation', logs['refuse.log'])

    def test_offline_refusals_require_the_product_explanation(self):
        cases = (
            ('self-update-downgrade-refusal',
             'Error: Refusing to downgrade from 1.0.0 to 0.0.1 (use --force to override)\n'),
            ('env-share-missing-lock', 'Error: No omg.lock file found\n'),
        )
        for assertion, refusal in cases:
            with self.subTest(assertion=assertion):
                self.assertEqual(
                    self.run_oracle(safety='controlled-error', assertion=assertion,
                                    code=1, stderr=refusal).returncode,
                    0,
                )
                self.assertNotEqual(
                    self.run_oracle(safety='controlled-error', assertion=assertion,
                                    code=1, stderr='unrelated refusal\n').returncode,
                    0,
                )
                self.assertNotEqual(
                    self.run_oracle(safety='controlled-error', assertion=assertion,
                                    code=0, stderr=refusal).returncode,
                    0,
                )

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_license_rows_require_the_backend_refusal_without_an_export(self):
        ids = {'audit-licenses', 'audit-licenses-filter-policy', 'audit-licenses-export',
               'enterprise-license-scan', 'enterprise-license-scan-export'}
        rows = [line for line in
                (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8').splitlines()
                if line.split('\t', 1)[0] in ids]
        self.assertEqual(len(rows), len(ids))
        refusal = ('if [[ "$1" == audit ]]; then\n'
                   '  echo "Error: License scanning of installed packages is not available without the Arch backend" >&2\n'
                   'else\n'
                   '  echo "Error: Enterprise license scan requires the Arch package backend" >&2\n'
                   'fi\nexit 1\n')
        leaked_export = ('if [[ "$*" == *--export* ]]; then\n'
                         '  if [[ "$1" == audit ]]; then printf partial > licenses-export.csv;\n'
                         '  else printf partial > license-scan-fixture.json; fi\n'
                         'fi\n' + refusal)
        for distro in ('debian', 'ubuntu', 'fedora'):
            for label, product, rejected in (
                ('wrong cause', 'echo unrelated permission error >&2\nexit 1\n', ids),
                ('explicit refusal', refusal, set()),
                ('report despite refusal', 'echo "[]"\n' + refusal, ids),
                ('partial export', leaked_export,
                 {'audit-licenses-export', 'enterprise-license-scan-export'}),
            ):
                with self.subTest(distro=distro, label=label):
                    result, evidence, logs = self.run_inventory(product, rows, distro=distro)
                    for row in evidence:
                        case = row['case_id'].removeprefix(f'qemu-{distro}-')
                        self.assertEqual(row['result'], 'FAIL' if case in rejected else 'PASS',
                                         f'{result.stdout}\n{result.stderr}\n{logs}')
                    self.assertEqual(result.returncode, 1 if rejected else 0)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_actual_runner_executes_offline_refusals(self):
        rows = [
            'self-update-version\t["self-update","--version","0.0.1"]\tcontrolled-error\t1\tpass\t-\thermetic\thermetic:pass\tself-update-downgrade-refusal\ttempdir-drop',
            'env-share-missing-lock\t["env","share"]\tcontrolled-error\t1\tpass\t-\thermetic\thermetic:pass\tenv-share-missing-lock\ttempdir-drop',
        ]
        product = '''case "$1" in
self-update) printf 'OMG Checking for updates... (current: v0.1.224)\\n'
  printf 'Error: Refusing to downgrade from 0.1.224 to 0.0.1 (use --force to override)\\n' >&2; exit 1 ;;
env) printf 'Error: No omg.lock file found\\n' >&2; exit 1 ;;
esac
'''
        result, evidence, _ = self.run_inventory(product, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS', 'PASS'])
        result, evidence, logs = self.run_inventory(product.replace('Refusing to downgrade', 'Proceeding'), rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['FAIL', 'PASS'])
        self.assertIn('did not refuse an offline downgrade', logs['self-update-version.log'])

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_actual_runner_accepts_valid_output_and_blocks_bad_dependencies(self):
        rows = [
            'help\t["--help"]\thelp-boundary\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop',
            'export\t["export"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\tartifact:manifest.json\ttempdir-drop',
            'refuse\t["refuse"]\tcontrolled-error\t1\tpass\texport\thermetic\thermetic:pass\t-\ttempdir-drop',
        ]
        product = '''case "$1" in
--help) printf 'Usage: fixture\\n' ;;
export) printf '{"packages":[]}' > manifest.json ;;
refuse) printf 'deliberate refusal\\n' >&2; exit 1 ;;
esac
'''
        result, evidence, _ = self.run_inventory(product, rows)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS'] * 3)
        result, evidence, logs = self.run_inventory(product.replace('{"packages":[]}', 'invalid'), rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['PASS', 'FAIL', 'BLOCKED'])
        self.assertIn('regular JSON document', logs['refuse.log'])

    def run_oracle(self, safety='read', assertion='-', code=0, stdout='', stderr='', artifact=None, hooks=None, distro='arch', tree_oracle_status=None):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN PRODUCT OUTPUT ORACLE')
        end = source.index('# END PRODUCT OUTPUT ORACLE', begin)
        function = source[begin:end]
        if tree_oracle_status is not None:
            function += f'\ncheck_native_tree_state() {{ return {tree_oracle_status}; }}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'stdout').write_text(stdout, encoding='utf-8', newline='\n')
            (root / 'stderr').write_text(stderr, encoding='utf-8', newline='\n')
            if artifact is not None:
                (root / 'manifest.json').write_text(artifact, encoding='utf-8', newline='\n')
            if hooks is not None:
                (root / '.git/hooks').mkdir(parents=True)
                for name, (content, mode) in hooks.items():
                    path = root / '.git/hooks' / name
                    path.write_text(content, encoding='utf-8', newline='\n')
                    path.chmod(mode)
            result = subprocess.run(
                [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'), '-c',
                 function + '\ncheck_product_output "$@"', '_',
                 safety, assertion, str(code), 'stdout', 'stderr', distro],
                cwd=root, capture_output=True, text=True, timeout=10)
            return result

    def test_exit_zero_without_help_is_not_success(self):
        result = self.run_oracle(safety='help-boundary', stdout='ok\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('help', result.stderr)
        self.assertEqual(self.run_oracle(safety='help-boundary', stdout='Usage: omg search\n').returncode, 0)

    def test_package_rows_bind_native_state_to_success(self):
        for assertion in ('native-tree-installed', 'native-tree-absent'):
            self.assertEqual(self.run_oracle(assertion=assertion, tree_oracle_status=0).returncode, 0)
            self.assertNotEqual(self.run_oracle(assertion=assertion, tree_oracle_status=1).returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'DNF reason oracle needs a POSIX shell')
    def test_fedora_update_allows_only_the_oracle_install_reason_to_change(self):
        source = (ROOT / 'scripts/qemu-fedora-update-fixture.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN DNF REASON DELTA ORACLE')
        end = source.index('# END DNF REASON DELTA ORACLE', begin)
        function = source[begin:end]
        before = 'bash|x86_64|User\nomg-qemu-update-oracle|noarch|External\n'
        cases = (
            ('omg-qemu-update-oracle|noarch|User\nbash|x86_64|User\n', True),
            ('bash|x86_64|Dependency\nomg-qemu-update-oracle|noarch|User\n', False),
            ('omg-qemu-update-oracle|noarch|User\n', False),
            ('bash|x86_64|User\ncurl|x86_64|Dependency\nomg-qemu-update-oracle|noarch|User\n', False),
        )
        for after, accepted in cases:
            with self.subTest(after=after), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'before').write_text(before, encoding='utf-8', newline='\n')
                (root / 'after').write_text(after, encoding='utf-8', newline='\n')
                result = subprocess.run(
                    [shutil.which('bash'), '-c',
                     'package=omg-qemu-update-oracle\n' + function +
                     '\ncheck_reason_delta before after'],
                    cwd=root, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if not accepted:
                    self.assertIn('changed DNF install reasons', result.stderr)

    def test_release_search_requires_an_exact_ranked_official_result(self):
        valid = '  | Search\n    tree\n  tree 2.1.3  Official\n  tree-sitter 1.0  Official\n'
        self.assertEqual(self.run_oracle(assertion='search-official-tree-output', stdout=valid).returncode, 0)
        invalid = [
            '', 'No results found\n', '  tree 2.1.3  AUR\n',
            '  tree  Official\n', '  tree-sitter 1.0  Official\n',
            '  tree 2.1.3  AUR\n  tree 2.1.3  Official\n',
            '  tree-sitter 1.0  Official\n  tree 2.1.3  Official\n',
            '  tree 2.1.3  Official\n  tree 2.1.3  Official\n',
        ]
        for output in invalid:
            with self.subTest(output=output):
                self.assertNotEqual(
                    self.run_oracle(assertion='search-official-tree-output', stdout=output).returncode,
                    0,
                )

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_release_search_runner_rejects_successful_empty_search(self):
        row = ('release-package-search-tree\t["search","tree"]\tread\t0\tpass\t-'
               '\tcontainer\tarch:pass\tsearch-official-tree-output\tnone')
        for payload, accepted in (
            ('No results found', False),
            ('  tree 2.1.3  Official', True),
        ):
            with self.subTest(payload=payload):
                product = f'printf %s {shlex.quote(payload)}\n'
                result, evidence, logs = self.run_inventory(product, [row], tiers='container')
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual(evidence[0]['result'], 'PASS' if accepted else 'FAIL')
                if not accepted:
                    self.assertIn('search lacks a ranked official tree', logs['release-package-search-tree.log'])

    @unittest.skipIf(os.name == 'nt', 'Native package oracle fixtures require POSIX executables')
    def test_native_tree_state_requires_database_and_payload_parity(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        function = source[source.index('check_native_tree_state() {'):source.index('check_go_install() (')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / 'commands'
            commands.mkdir()
            for name in ('pacman', 'dpkg-query', 'rpm'):
                manager = commands / name
                row = 'tree\\tinstall ok installed\\n' if name == 'dpkg-query' else 'tree\\n'
                base = 'base\\tinstall ok installed\\n' if name == 'dpkg-query' else 'base\\n'
                manager.write_text('#!/bin/sh\n[ "$OMG_TEST_QUERY_STATUS" = 3 ] && exit 0\n'
                                   '[ "$OMG_TEST_QUERY_STATUS" = 0 ] || exit 2\n'
                                   f'printf "{base}"\n[ "$OMG_TEST_PRESENT" = 1 ] && printf "{row}"\nexit 0\n',
                                   encoding='utf-8')
                manager.chmod(0o755)
            tree = root / 'tree'
            tree.write_text('#!/bin/sh\n[ "$1" = --version ] && echo "tree v2"\n', encoding='utf-8')
            tree.chmod(0o755)
            for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
                for present, payload, expected, query_status, accepted in (
                    ('0', False, 'absent', '0', True), ('0', False, 'installed', '0', False),
                    ('1', True, 'installed', '0', True), ('1', True, 'absent', '0', False),
                    ('1', False, 'installed', '0', False), ('0', True, 'absent', '0', False),
                    ('0', False, 'absent', '2', False), ('1', True, 'installed', '2', False),
                    ('0', False, 'absent', '3', False)):
                    with self.subTest(distro=distro, present=present, payload=payload,
                                      expected=expected, query_status=query_status):
                        if not payload:
                            tree.unlink(missing_ok=True)
                        elif not tree.exists():
                            tree.write_text('#!/bin/sh\n[ "$1" = --version ] && echo "tree v2"\n', encoding='utf-8')
                            tree.chmod(0o755)
                        environment = dict(os.environ, OMG_TEST_PRESENT=present,
                                           OMG_TEST_QUERY_STATUS=query_status,
                                           PATH=str(commands) + os.pathsep + os.environ['PATH'])
                        result = subprocess.run(
                            [shutil.which('bash'), '-c', function + '\ncheck_native_tree_state "$@"',
                             '_', distro, expected, str(tree)],
                            env=environment, capture_output=True, text=True, timeout=10)
                        self.assertEqual(result.returncode == 0, accepted, result.stderr)

    @unittest.skipIf(os.name == 'nt', 'Native APT oracle needs POSIX executables')
    def test_apt_orphan_oracle_rejects_claims_without_native_removal(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        functions = source[source.index('check_native_tree_state() {'):source.index('check_go_install() (')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / 'commands'
            commands.mkdir()
            query = commands / 'dpkg-query'
            query.write_text(
                '#!/usr/bin/env bash\n'
                'printf "apt\\tinstall ok installed\\n"\n'
                'if [[ "$OMG_TEST_BASELINE_CHANGED" != 1 ]]; then '
                'printf "bash\\tinstall ok installed\\n"; fi\n'
                'if [[ "$OMG_TEST_TREE_PRESENT" == 1 && $# == 2 ]]; then '
                'printf "tree\\tinstall ok installed\\n"; fi\n',
                encoding='utf-8')
            query.chmod(0o755)
            (root / 'baseline-packages.tsv').write_text(
                'apt\tinstall ok installed\nbash\tinstall ok installed\n')
            for tree_present, baseline_changed, report, accepted in (
                ('0', '0', 'Removed 1 orphan package\n', True),
                ('1', '0', 'Removed 1 orphan package\n', False),
                ('0', '1', 'Removed 1 orphan package\n', False),
                ('0', '0', 'Cleanup complete\n', False),
                ('0', '0', 'Removed 0 orphan packages\n', False),
            ):
                with self.subTest(tree_present=tree_present, baseline_changed=baseline_changed,
                                  report=report):
                    (root / 'output').write_text(report)
                    env = dict(os.environ, OMG_TEST_TREE_PRESENT=tree_present,
                               OMG_TEST_BASELINE_CHANGED=baseline_changed,
                               PATH=str(commands) + os.pathsep + os.environ['PATH'])
                    result = subprocess.run(
                        [shutil.which('bash'), '-c', functions +
                         '\ncheck_native_apt_orphan_removed debian output missing-tree'],
                        cwd=root, env=env, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_offline_sbom_requires_advisory_source_failure(self):
        prefix = 'Error: Failed to generate system SBOM: Failed to generate a complete security SBOM: '
        for message in ('Failed to query native security advisories', 'Failed to scan package pkg for vulnerabilities: Failed to query the OSV vulnerability database'):
            self.assertEqual(self.run_oracle(assertion='sbom-source-failure', code=1, stderr=prefix + message).returncode, 0)
        for message in ('unsupported backend', 'daemon is not running', 'failed to parse mock state'):
            self.assertNotEqual(self.run_oracle(assertion='sbom-source-failure', code=1, stderr=prefix + message).returncode, 0)
        self.assertNotEqual(self.run_oracle(assertion='sbom-source-failure', code=0).returncode, 0)

    def test_expected_refusal_requires_its_own_diagnostic(self):
        self.assertNotEqual(self.run_oracle(code=1, stderr=' \n\t').returncode, 0)
        self.assertEqual(self.run_oracle(code=1, stderr='unknown runtime\n').returncode, 0)

    def test_offline_audit_requires_source_failure_without_false_clean_output(self):
        diagnostics = [
            'Error: Failed to scan package pkg for vulnerabilities: Failed to query the OSV vulnerability database\n',
            'Error: Failed to query native security advisories\n',
        ]
        for diagnostic in diagnostics:
            self.assertEqual(self.run_oracle(assertion='audit-source-failure', code=1, stderr=diagnostic).returncode, 0)
            self.assertNotEqual(self.run_oracle(assertion='audit-source-failure', code=0, stderr=diagnostic).returncode, 0)
            self.assertNotEqual(self.run_oracle(assertion='audit-source-failure', code=1, stderr=diagnostic, stdout='No vulnerabilities found!').returncode, 0)
        for diagnostic in ['unknown runtime', 'Daemon not running', 'Error: OSV has no configured ecosystem for the running package backend']:
            self.assertNotEqual(self.run_oracle(assertion='audit-source-failure', code=1, stderr=diagnostic).returncode, 0)

    def test_auto_fix_refusal_matches_backend_before_scanning(self):
        source_error = 'Error: Failed to query native security advisories\n'
        unsupported = 'Error: Vulnerability auto-fix is not available without the Arch backend; upgrade the affected packages manually\n'
        self.assertEqual(self.run_oracle(assertion='audit-fix-refusal', code=1, stderr=source_error, distro='arch').returncode, 0)
        self.assertNotEqual(self.run_oracle(assertion='audit-fix-refusal', code=1, stderr=unsupported, distro='arch').returncode, 0)
        for distro in ('debian', 'ubuntu', 'fedora'):
            with self.subTest(distro=distro):
                self.assertEqual(self.run_oracle(assertion='audit-fix-refusal', code=1, stderr=unsupported, distro=distro).returncode, 0)
                self.assertNotEqual(self.run_oracle(assertion='audit-fix-refusal', code=0, stderr=unsupported, distro=distro).returncode, 0)
                self.assertNotEqual(self.run_oracle(assertion='audit-fix-refusal', code=1, stderr=source_error, distro=distro).returncode, 0)
                self.assertNotEqual(self.run_oracle(assertion='audit-fix-refusal', code=1, stderr=unsupported, stdout='Scanning for fixable vulnerabilities\n', distro=distro).returncode, 0)

    def test_panic_cannot_hide_behind_success_or_expected_failure(self):
        for code in (0, 1):
            for output in ('stdout', 'stderr'):
                with self.subTest(code=code, output=output):
                    result = self.run_oracle(code=code, **{output: 'thread main panicked at bug.rs:1\n'})
                    self.assertNotEqual(result.returncode, 0)

    def test_artifact_requires_one_valid_json_document(self):
        for content in (None, '', 'not JSON', '{}\n{}'):
            with self.subTest(content=content):
                self.assertNotEqual(self.run_oracle(assertion='artifact:manifest.json', artifact=content).returncode, 0)
        self.assertEqual(self.run_oracle(assertion='artifact:manifest.json', artifact='{"packages":[]}').returncode, 0)

    def test_json_stdout_rejects_noise_and_multiple_documents(self):
        for content in ('', 'ok', '{}\n{}', 'notice\n{}'):
            self.assertNotEqual(self.run_oracle(assertion='json-stdout', stdout=content).returncode, 0)
        self.assertEqual(self.run_oracle(assertion='json-stdout', stdout='{"packages":[]}').returncode, 0)

    def test_official_search_limit_checks_actual_results(self):
        valid = ('\n  | Search\n    git-\n'
                 '  git-absorb 0.9.0-2  Official\n'
                 '  git-annex 10.20260901-7  Official\n'
                 '  git-branchless 0.11.1-2  Official\n'
                 '  (+173 more packages...)\n')
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        row = next(line for line in inventory.splitlines() if line.startswith('search-flags\t'))
        self.assertEqual(row.split('\t')[8], 'search-official-limit-three')
        self.assertEqual(row.split('\t')[6:8], ['container', 'arch:pass,debian:pass,ubuntu:pass,fedora:pass'])
        args = json.loads(row.split('\t')[1])
        self.assertEqual(args, ['search', '--detailed', '--no-aur', '--limit', '3', 'git-'])
        self.assertEqual(self.run_oracle(assertion='search-official-limit-three', stdout=valid).returncode, 0)
        fedora = valid.replace('  git-branchless 0.11.1-2  Official\n',
                               '  git-all 2.55.0-1.fc44  Official\n')
        self.assertEqual(self.run_oracle(assertion='search-official-limit-three', stdout=fedora).returncode, 0)
        for output in (
            '',
            '  | Search\n    git-\n',
            valid.replace('    git-\n', '    chrome\n'),
            valid.replace('  git-absorb 0.9.0-2  Official\n', '  git-absorb 0.9.0-2  AUR\n'),
            valid.replace('  git-absorb 0.9.0-2  Official\n', '  git-absorb 0.9.0-2  Official\n' * 4),
            ('\n  | Search\n    git-\n' + '  git-absorb 0.9.0-2  Official\n' * 3
             + '  (+1 more packages...)\n'),
            valid.replace('  git-absorb 0.9.0-2  Official\n', '  unrelated 0.9.0-2  Official\n'),
            valid + 'unrelated warning hidden after results\n',
            valid.replace('  git-annex 10.20260901-7  Official\n', ''),
            valid.replace('  (+173 more packages...)\n', ''),
            valid.replace('  (+173 more packages...)\n', '  (+0 more packages...)\n'),
            '\n  | Search\n    git-\n  git-absorb 0.9.0-2  Official\n',
        ):
            with self.subTest(output=output):
                self.assertNotEqual(self.run_oracle(assertion='search-official-limit-three', stdout=output).returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_search_oracle_rejects_false_green_product_in_actual_runner(self):
        inventory = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text(encoding='utf-8')
        row = next(line for line in inventory.splitlines() if line.startswith('search-flags\t'))
        valid = ('printf "\\n  | Search\\n    git-\\n'
                 '  git-absorb 0.9.0-2  Official\\n'
                 '  git-annex 10.20260901-7  Official\\n'
                 '  git-branchless 0.11.1-2  Official\\n'
                 '  (+173 more packages...)\\n"\n')
        invalid = 'printf "\\n  | Search\\n    git-\\n  git-absorb 0.9.0-2  Official\\n"\n'
        for product, expected in ((valid, 'PASS'), (invalid, 'FAIL')):
            with self.subTest(expected=expected):
                result, evidence, logs = self.run_inventory(product, [row], tiers='container')
                self.assertEqual(evidence[0]['result'], expected, result.stderr)
                self.assertEqual(result.returncode, 0 if expected == 'PASS' else 1)
                if expected == 'FAIL':
                    self.assertIn('three results and a positive remainder', logs['search-flags.log'])

    def test_workspace_filter_requires_selected_task_once_and_excludes_other_task(self):
        for output in ('', 'nested-smoke-task-ok\n',
                       'smoke-task-ok\nsmoke-task-ok\n',
                       'smoke-task-ok\nnested-smoke-task-ok\n'):
            with self.subTest(output=output):
                self.assertNotEqual(self.run_oracle(assertion='workspace-filtered-output', stdout=output).returncode, 0)
        self.assertEqual(self.run_oracle(assertion='workspace-filtered-output', stdout='smoke-task-ok\n').returncode, 0)

    def test_hook_state_rejects_missing_invalid_or_leftover_hooks(self):
        hooks = self.generated_hooks()
        self.assertNotEqual(self.run_oracle(assertion='hooks-installed', hooks={}).returncode, 0)
        self.assertEqual(self.run_oracle(assertion='hooks-installed', hooks=hooks).returncode, 0)
        for replacement in ('#!/bin/sh\nexit 0\n', '#!/bin/sh\n# OMG Pre-commit Hook\nif\n'):
            changed = dict(hooks, **{'pre-commit': (replacement, 0o755)})
            self.assertNotEqual(self.run_oracle(assertion='hooks-installed', hooks=changed).returncode, 0)
        self.assertNotEqual(self.run_oracle(assertion='hooks-absent', hooks=hooks).returncode, 0)
        self.assertEqual(self.run_oracle(assertion='hooks-absent', hooks={}).returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'Windows does not model POSIX executable bits')
    def test_hook_state_rejects_nonexecutable_hooks(self):
        hooks = {name: (f'#!/bin/sh\n# OMG {label} Hook\nexit 0\n', 0o644)
                 for name, label in [('pre-commit', 'Pre-commit'), ('post-checkout', 'Post-checkout'), ('post-merge', 'Post-merge')]}
        self.assertNotEqual(self.run_oracle(assertion='hooks-installed', hooks=hooks).returncode, 0)

    def test_workspace_all_requires_both_tasks_once_without_order_assumption(self):
        for output in ('', 'smoke-task-ok\n', 'nested-smoke-task-ok\n',
                       'smoke-task-ok\nnested-smoke-task-ok\nsmoke-task-ok\n'):
            with self.subTest(output=output):
                self.assertNotEqual(self.run_oracle(assertion='workspace-all-output', stdout=output).returncode, 0)
        for output in ('smoke-task-ok\nnested-smoke-task-ok\n', 'nested-smoke-task-ok\nsmoke-task-ok\n'):
            self.assertEqual(self.run_oracle(assertion='workspace-all-output', stdout=output).returncode, 0)

    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX jq process-substitution descriptors')
    def test_inventory_routes_workspace_assertions_instead_of_accepting_exit_zero(self):
        rows = [
            'filtered\t["both"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tworkspace-filtered-output\ttempdir-drop',
            'all\t["both"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tworkspace-all-output\ttempdir-drop',
            'missing\t["one"]\tread\t0\tpass\t-\thermetic\thermetic:pass\tworkspace-all-output\ttempdir-drop',
        ]
        product = 'printf "smoke-task-ok\\n"\nif [[ "$1" == both ]]; then printf "nested-smoke-task-ok\\n"; fi\n'
        result, evidence, _ = self.run_inventory(product, rows)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([row['result'] for row in evidence], ['FAIL', 'PASS', 'FAIL'])


if __name__ == '__main__':
    unittest.main()

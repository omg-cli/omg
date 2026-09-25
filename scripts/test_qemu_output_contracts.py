"""Exercise the exact guest output oracle with plausible false-green products."""
import os
import json
import re
import shlex
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OutputContracts(unittest.TestCase):
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
                rows = [f'{case}\t["{command}"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
                for value, verdict in [('2', 'PASS'), ('0', 'FAIL')]:
                    with self.subTest(distro=distro, command=command, value=value):
                        result, evidence, logs = self.run_inventory(
                            f'printf "{value}\\n"\n', rows, native_commands=native, distro=distro)
                        self.assertEqual(evidence[0]['result'], verdict, logs)
                        self.assertEqual(result.returncode, int(verdict == 'FAIL'), result.stderr)
                        self.assertIn(f'native counter {command} expected=2 actual={value}', logs[case + '.log'])
            broken = {name: 'echo native-reference-failed >&2\nexit 17\n' for name in native}
            result, evidence, logs = self.run_inventory('printf "0\\n"\n', rows,
                                                       native_commands=broken, distro=distro)
            self.assertEqual(evidence[0]['result'], 'BLOCKED', logs)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('native counter reference failed', logs[case + '.log'])
        rows = ['explicit-shortcut\t["ec"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
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

    def run_inventory(self, product, rows, *, native_commands=None, distro='arch', tiers='hermetic', row_timeout=None):
        def shell_path(path):
            value = path.as_posix()
            return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('home', 'bin', 'guest'):
                (root / name).mkdir()
            for name, content in (native_commands or {}).items():
                tool = root / 'bin' / name
                tool.write_text('#!/usr/bin/env bash\n' + content, encoding='utf-8', newline='\n')
                tool.chmod(0o755)
            binary = root / 'product'
            binary.write_text('#!/usr/bin/env bash\n' + product, encoding='utf-8', newline='\n')
            binary.chmod(0o755)
            ssh = root / 'bin/ssh'
            ssh.write_text('#!/usr/bin/env bash\nexec bash -c "${@: -1}"\n', encoding='utf-8', newline='\n')
            ssh.chmod(0o755)
            inventory = root / 'cases.tsv'
            inventory.write_text(
                'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup\n'
                + '\n'.join(rows) + '\n', encoding='utf-8', newline='\n')
            env = dict(os.environ, HOME=shell_path(root / 'home'),
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1',
                       PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'])
            command = [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'),
                       str(ROOT / 'scripts/qemu-inventory.sh'), '--work', str(root),
                       '--binary', shell_path(binary), '--tsv', str(inventory),
                       '--distro', distro, '--tiers', tiers, '--tag', 'fixture']
            if row_timeout is not None:
                command += ['--row-timeout', str(row_timeout)]
            result = subprocess.run(
                command,
                env=env, capture_output=True, text=True, timeout=30)
            evidence = root / 'inventory/results.json'
            self.assertTrue(evidence.exists(), result.stdout + result.stderr)
            return result, json.loads(evidence.read_text()), {
                path.name: path.read_text() for path in (root / 'inventory/rows').glob('*.log')}

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

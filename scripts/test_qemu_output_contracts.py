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
    @unittest.skipIf(os.name == 'nt', 'Full runner needs POSIX shell descriptors')
    def test_python_install_requires_active_executable_and_exact_version(self):
        rows = ['runtime-python-install\t["use","python","3.12.14"]\tisolated-write\t0\tpass\t-\thermetic\thermetic:pass\t-\ttempdir-drop']
        for fault in ('missing', 'inactive', 'wrong-version', 'broken', 'escaped', 'version-escaped', 'none'):
            with self.subTest(fault=fault):
                product = 'printf "Installed Python 3.12.14\\n"\n'
                if fault != 'missing':
                    version = '3.12.13' if fault == 'wrong-version' else '3.12.14'
                    script = '#!/bin/sh\n' + ('exit 1\n' if fault == 'broken' else f'printf "Python {version}\\n"\n')
                    product += ': "${OMG_DATA_DIR:?isolated runtime state missing}"\nbase="$OMG_DATA_DIR/versions/python"\nmkdir -p "$base/3.12.14/bin"\n'
                    product += f'printf %s {shlex.quote(script)} > "$base/3.12.14/bin/python3"\nchmod 755 "$base/3.12.14/bin/python3"\n'
                    if fault != 'inactive':
                        product += 'ln -s 3.12.14 "$base/current"\n'
                    if fault == 'escaped':
                        product += 'mv "$base/3.12.14/bin/python3" "$OMG_DATA_DIR/external"\nln -s "$OMG_DATA_DIR/external" "$base/3.12.14/bin/python3"\n'
                    if fault == 'version-escaped':
                        product += 'mv "$base/3.12.14" "$OMG_DATA_DIR/external-version"\nln -s "$OMG_DATA_DIR/external-version" "$base/3.12.14"\n'
                result, evidence, logs = self.run_inventory(product, rows)
                self.assertEqual(result.returncode, 0 if fault == 'none' else 1, result.stderr)
                self.assertEqual(evidence[0]['result'], 'PASS' if fault == 'none' else 'FAIL')
                if fault != 'none':
                    self.assertIn('assertion failed: Python', logs['runtime-python-install.log'])

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

    def run_inventory(self, product, rows):
        def shell_path(path):
            value = path.as_posix()
            return '/' + value[0].lower() + value[2:] if os.name == 'nt' else value

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('home', 'bin', 'guest'):
                (root / name).mkdir()
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
            result = subprocess.run(
                [os.environ.get('OMG_TEST_BASH') or shutil.which('bash'),
                 str(ROOT / 'scripts/qemu-inventory.sh'), '--work', str(root),
                 '--binary', shell_path(binary), '--tsv', str(inventory),
                 '--distro', 'arch', '--tiers', 'hermetic', '--tag', 'fixture'],
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

    def run_oracle(self, safety='read', assertion='-', code=0, stdout='', stderr='', artifact=None, hooks=None):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        begin = source.index('# BEGIN PRODUCT OUTPUT ORACLE')
        end = source.index('# END PRODUCT OUTPUT ORACLE', begin)
        function = source[begin:end]
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
                 safety, assertion, str(code), 'stdout', 'stderr'],
                cwd=root, capture_output=True, text=True, timeout=10)
            return result

    def test_exit_zero_without_help_is_not_success(self):
        result = self.run_oracle(safety='help-boundary', stdout='ok\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('help', result.stderr)
        self.assertEqual(self.run_oracle(safety='help-boundary', stdout='Usage: omg search\n').returncode, 0)

    def test_expected_refusal_requires_its_own_diagnostic(self):
        self.assertNotEqual(self.run_oracle(code=1, stderr=' \n\t').returncode, 0)
        self.assertEqual(self.run_oracle(code=1, stderr='unknown runtime\n').returncode, 0)

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

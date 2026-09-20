"""Exercise the exact guest output oracle with plausible false-green products."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OutputContracts(unittest.TestCase):
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

    def run_oracle(self, safety='read', assertion='-', code=0, stdout='', stderr='', artifact=None):
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


if __name__ == '__main__':
    unittest.main()

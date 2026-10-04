"""Keep historical guest profiles explicit and bind new profiles to run source."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
import subprocess
import tempfile
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('profile_reporter', Path(__file__).with_name('report-qemu-workflow.py'))
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)
FOUR = ('arch', 'debian', 'ubuntu', 'fedora')
FIVE = ('arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora')


def workflow(distros):
    return ('          distros=\'' + json.dumps(list(distros)) + '\'\n').encode()


class GuestProfileTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'transaction projection requires Bash and jq')
    def test_trixie_transaction_projection_keeps_complete_native_and_product_trials(self):
        helper = Path(__file__).with_name('qa-evidence-lib.sh')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = []
            bases = {'install': 'a' * 64, 'remove': 'b' * 64}
            for number, (operation, tool) in enumerate(((op, tool) for op in bases for tool in ('native', 'omg')), 1):
                digit = str(number)
                rows.append(dict(id=f'{operation}-{tool}-001', operation=operation, tool=tool,
                    round=1, result='PASS', exit_code=0,
                    boot_id=digit * 8 + '-' + digit * 4 + '-4' + digit * 3 + '-8' + digit * 3 + '-' + digit * 12,
                    base_sha256=bases[operation]))
            summary = dict(schema_version=2, kind='transaction-suite', distro='debian-trixie',
                complete=True, phase='complete', samples_per_tool=1, expected_trials=4, bases=bases, results=rows)
            (root / 'results.json').write_text(json.dumps(rows))
            (root / 'summary.json').write_text(json.dumps(summary))
            for complete in (True, False):
                with self.subTest(complete=complete):
                    (root / 'summary.json').write_text(json.dumps(dict(summary, complete=complete)))
                    result = subprocess.run(['bash', '-e', '-c', 'source "$1"; qa_transaction_rows "$2"',
                        'fixture', str(helper), str(root / 'results.json')], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, complete, result.stderr)
                    if complete:
                        actual = json.loads(result.stdout)
                        self.assertEqual(len(actual), 4)
                        self.assertEqual({row['distro'] for row in actual}, {'debian-trixie'})

    @unittest.skipUnless(os.name == 'posix', 'shared evidence validation requires Bash and jq')
    def test_shared_issue_and_sentry_projection_accepts_trixie_but_not_foreign_guests(self):
        helper = Path(__file__).with_name('qa-evidence-lib.sh')
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'results.json'
            for distro in ('debian-trixie', 'foreign'):
                with self.subTest(distro=distro):
                    evidence.write_text(json.dumps([dict(case_id=f'qemu-{distro}-lifecycle',
                        distro=distro, result='HARNESS_ERROR', exit_code=120, elapsed_seconds=1)]))
                    result = subprocess.run(['bash', '-e', '-c', 'source "$1"; qa_result_rows "$2"',
                        'fixture', str(helper), str(evidence)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, distro == 'debian-trixie', result.stderr)
                    if result.returncode == 0:
                        self.assertEqual(json.loads(result.stdout)[0]['distro'], distro)

    def test_historical_four_and_new_five_are_explicit_profiles(self):
        for distros in (FOUR, FIVE):
            with self.subTest(distros=distros):
                self.assertEqual(REPORT.required_guest_distros(workflow(distros)), distros)

    def test_missing_ambiguous_partial_or_unknown_profiles_fail_closed(self):
        for source in (b'', workflow(FIVE) * 2, workflow(FOUR[:-1]),
                       workflow(FIVE + ('evil',)), workflow(FIVE + ('debian-trixie',)),
                       workflow(tuple(reversed(FIVE)))):
            with self.subTest(source=source), self.assertRaises(ValueError):
                REPORT.required_guest_distros(source)

    def test_profile_fetch_is_bound_to_immutable_source_and_git_blob(self):
        source = workflow(FIVE)
        blob = hashlib.sha1(b'blob ' + str(len(source)).encode() + b'\0' + source).hexdigest()
        response = dict(type='file', path='.github/workflows/qemu-matrix.yml', encoding='base64',
                        size=len(source), sha=blob, content=base64.b64encode(source).decode())
        with patch.object(REPORT, 'api', return_value=json.dumps(response).encode()) as api:
            self.assertEqual(REPORT.run_guest_profile('owner/repo', 'a' * 40), FIVE)
        api.assert_called_once_with('repos/owner/repo/contents/.github/workflows/qemu-matrix.yml?ref=' + 'a' * 40)
        for field, value in (('sha', '0' * 40), ('size', len(source) + 1),
                             ('path', 'foreign.yml'), ('type', 'symlink'), ('encoding', 'none')):
            with self.subTest(field=field), patch.object(REPORT, 'api', return_value=json.dumps(dict(response, **{field: value})).encode()), self.assertRaises(ValueError):
                REPORT.run_guest_profile('owner/repo', 'a' * 40)

    def test_trixie_failure_and_artifact_preserve_actual_identity(self):
        self.assertEqual(REPORT.artifact_guest_identity('qemu-evidence-debian-trixie'), ('debian-trixie', 'x86_64'))
        self.assertIsNone(REPORT.artifact_guest_identity('qemu-arm-evidence-debian-trixie'))
        jobs = [dict(name='QEMU behavioral verification / Distro lane (debian-trixie) / QEMU guest (debian-trixie)', conclusion='failure')]
        rows = REPORT.failed_guest_receipts(jobs)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['distro'], rows[0]['arch']), ('debian-trixie', 'x86_64'))
        self.assertEqual(REPORT.workflow_receipt(jobs, 'failure')['distro'], 'debian-trixie')
        cases = REPORT.canonical_case_ids({'inventories': {'digest': {'cases': [{'id': 'search'}]}}})
        self.assertIn('qemu-debian-trixie-search', cases)
        self.assertNotIn('qemu-debian-trixie-aarch64-lifecycle', cases)


if __name__ == '__main__':
    unittest.main()

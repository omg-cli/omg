"""Execute helper ownership boundaries without running the repository suites."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile


SUBJECT = Path(__file__).with_name('workflow-helpers.py')
EXPLICIT = (
    'test_benchmark_records.py', 'test_terminal_update_notice.py',
    'test_audit_repair_shell.py', 'test_changelog_workflow_security.py',
    'test_ci_config_path_security.py', 'test_container_path_security.py',
    'test_daemon_path_security.py', 'test_shell_backup_safety.py',
)


def subject():
    spec = importlib.util.spec_from_file_location('workflow_helpers_subject', SUBJECT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HelperExecutionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'tests').mkdir()
        self.body = 'import unittest\nclass Checks(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n'
        for name in EXPLICIT:
            (self.root / 'tests' / name).write_text(self.body)
        (self.root / 'tests/test_qemu_fixture.py').write_text(self.body)
        (self.root / 'scripts/test_helper_fixture.py').write_text(self.body)

    def run_cli(self, *arguments):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('GITHUB_')}
        return subprocess.run([sys.executable, '-B', str(SUBJECT), 'run', '--root', str(self.root),
                               *arguments], capture_output=True, text=True, timeout=25, env=environment)

    def test_two_real_shards_execute_exact_disjoint_complete_identity_union(self):
        receipts = []
        for shard in (0, 1):
            output = self.root / f'out-{shard}'
            result = self.run_cli('--shard', str(shard), '--shards', '2', '--output', str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            receipts.append(json.loads((output / 'receipt.json').read_text()))
        self.assertEqual(receipts[0]['discovered'], receipts[1]['discovered'])
        selected = [row for receipt in receipts for row in receipt['selected']]
        self.assertEqual(sorted(selected), receipts[0]['discovered'])
        self.assertEqual(len(selected), len(set(selected)))
        for receipt in receipts:
            self.assertEqual(sorted(row['id'] for row in receipt['executed']), receipt['selected'])
            self.assertTrue(all(row['status'] == 'passed' and row['elapsed_seconds'] >= 0
                                for row in receipt['executed']))
            self.assertTrue(receipt['complete'])

    def test_module_can_import_helpers_through_the_repository_namespace(self):
        (self.root / 'scripts/support.py').write_text('VALUE = 42\n')
        (self.root / 'scripts/test_helper_fixture.py').write_text(
            'from scripts.support import VALUE\n' + self.body)
        result = self.run_cli('--output', str(self.root / 'namespace'))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    @unittest.skipUnless(sys.platform == 'linux', 'real Linux UID permission boundary')
    def test_module_scratch_allows_explicit_fixture_access_but_keeps_private_content_denied(self):
        prefix = [] if os.geteuid() == 0 else ['sudo', '-n']
        if not shutil.which('setpriv') or (prefix and subprocess.run(
                [*prefix, 'true'], capture_output=True, timeout=5).returncode):
            self.skipTest('real UID transition requires root or passwordless sudo and setpriv')
        code = '''import os,subprocess,sys,tempfile
from pathlib import Path
scratch=Path(os.environ['TMPDIR'])
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory);root.chmod(0o755)
 public=root/'readable';public.write_text('readable');public.chmod(0o644)
 private=root/'private';private.write_text('secret');private.chmod(0o600)
 hidden=root/'hidden';hidden.mkdir(mode=0o700)
 nested=hidden/'file';nested.write_text('secret');nested.chmod(0o644)
 probe="""from pathlib import Path
import sys
assert Path(sys.argv[1]).read_text()=='readable'
for path in sys.argv[2:4]:
 try:Path(path).read_text()
 except PermissionError:pass
 else:raise AssertionError('private fixture became readable')
scratch=Path(sys.argv[4])
try:list(scratch.iterdir())
except PermissionError:pass
else:raise AssertionError('scratch became listable')
try:(scratch/'unowned').write_text('unowned')
except PermissionError:pass
else:raise AssertionError('scratch became writable')
"""
 subprocess.run(PREFIX+['setpriv','--reuid=65534','--regid=65534','--clear-groups',sys.executable,'-c',probe,str(public),str(private),str(nested),str(scratch)],check=True)
 assert scratch.stat().st_mode & 0o777 == 0o711
'''.replace('PREFIX', repr(prefix))
        result = subject().child_process(self.root, [], dict(os.environ), time.monotonic() + 10,
                                         self.root / 'permissions.log', [sys.executable, '-B', '-c', code])
        self.assertEqual(result, 0, (self.root / 'permissions.log').read_text())

    def test_real_failure_preserves_failed_identity_and_nonzero_exit(self):
        (self.root / 'scripts/test_helper_fixture.py').write_text(self.body.replace('True)', 'False)'))
        output = self.root / 'failed'
        result = self.run_cli('--output', str(output))
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads((output / 'receipt.json').read_text())
        self.assertFalse(receipt['success'])
        self.assertTrue(any(row['status'] == 'failed' for row in receipt['executed']))

    def test_real_timeout_is_not_a_successful_empty_module(self):
        (self.root / 'scripts/test_helper_fixture.py').write_text(
            'import unittest,time\nclass Checks(unittest.TestCase):\n'
            ' def test_hang(self): time.sleep(30)\n')
        output = self.root / 'timeout'
        result = self.run_cli('--output', str(output), '--timeout', '1')
        self.assertNotEqual(result.returncode, 0)
        receipt = json.loads((output / 'receipt.json').read_text())
        self.assertFalse(receipt['success'])
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['failure_kind'], 'timeout')

    def test_import_discovery_obeys_the_same_absolute_deadline(self):
        (self.root / 'scripts/test_helper_fixture.py').write_text(
            'import time\nfrom pathlib import Path\ntime.sleep(2)\n'
            'Path("unbounded-import").write_text("not cancelled")\n' + self.body)
        result = self.run_cli('--output', str(self.root / 'import-timeout'), '--timeout', '.1')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'unbounded-import').exists())

    def test_discovery_error_and_empty_module_fail_before_passing_receipt(self):
        for body in ('raise RuntimeError("discovery failed")\n', 'import unittest\n'):
            with self.subTest(body=body):
                (self.root / 'scripts/test_helper_fixture.py').write_text(body)
                result = self.run_cli('--output', str(self.root / ('bad-' + hashlib.sha256(body.encode()).hexdigest())))
                self.assertNotEqual(result.returncode, 0)

    def test_duplicate_selected_test_ids_are_rejected(self):
        module = subject()
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)] * 2)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            module.test_identities(suite)

    def test_strict_receipt_rejects_missing_duplicate_failed_and_foreign_work(self):
        module = subject()
        manifest = module.discover(self.root)
        receipt = module.empty_receipt(self.root, manifest, 0, 1, {}, False)
        receipt.update(complete=True, success=True,
                       executed=[dict(id=name, status='passed', elapsed_seconds=0.01)
                                 for name in receipt['selected']])
        module.validate_execution(receipt, manifest)
        for mutate in (
            lambda row: row['executed'].pop(),
            lambda row: row['executed'].append(row['executed'][0]),
            lambda row: row['executed'][0].update(status='failed'),
            lambda row: row['executed'][0].update(id='foreign'),
            lambda row: row.update(selected=[]),
            lambda row: row.update(complete=False),
        ):
            bad = copy.deepcopy(receipt); mutate(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                module.validate_execution(bad, manifest)

    def test_class_setup_error_is_a_real_failure_not_a_recording_crash(self):
        (self.root / 'scripts/test_helper_fixture.py').write_text(
            'import unittest\nclass Checks(unittest.TestCase):\n'
            ' @classmethod\n def setUpClass(cls): raise RuntimeError("setup exploded")\n'
            ' def test_never(self): pass\n')
        output = self.root / 'class-error'
        result = self.run_cli('--output', str(output))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('setup exploded', result.stdout)
        self.assertNotIn('KeyError', result.stdout)

    def test_subtest_skip_and_failure_preserve_parent_identity(self):
        (self.root / 'scripts/test_helper_fixture.py').write_text(
            'import unittest\nclass Checks(unittest.TestCase):\n'
            ' def test_subtests(self):\n'
            '  with self.subTest(case="skip"): self.skipTest("known fixture")\n'
            '  with self.subTest(case="fail"): self.assertEqual(1,2)\n')
        result = self.run_cli('--output', str(self.root / 'subtests'))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('KeyError', result.stdout)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process group ownership')
    def test_completed_module_stops_term_ignoring_descendant_and_preserves_result(self):
        for succeeds in (True, False):
            with self.subTest(succeeds=succeeds):
                marker = self.root / 'completed-descendant'
                marker.unlink(missing_ok=True)
                child = ('import os,signal,time;from pathlib import Path;'
                         'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                         'Path("completed-descendant").write_text(str(os.getpid()));time.sleep(60)')
                (self.root / 'scripts/test_helper_fixture.py').write_text(
                    'import unittest,subprocess,sys,time\nfrom pathlib import Path\n'
                    'class Checks(unittest.TestCase):\n def test_spawn(self):\n'
                    f'  subprocess.Popen([sys.executable,"-c",{child!r}])\n'
                    '  deadline=time.monotonic()+5\n'
                    '  while not Path("completed-descendant").exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                    '  self.assertTrue(Path("completed-descendant").exists())\n'
                    f'  self.assertTrue({succeeds!r})\n')
                output = self.root / ('completed-pass' if succeeds else 'completed-fail')
                result = self.run_cli('--output', str(output))
                self.assertTrue(marker.exists(), result.stderr + result.stdout)
                descendant = int(marker.read_text())
                try:
                    status = Path('/proc') / str(descendant) / 'stat'
                    deadline = time.monotonic() + 2
                    while status.exists() and status.read_text().split()[2] not in ('Z', 'X') and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(not status.exists() or status.read_text().split()[2] in ('Z', 'X'),
                                    'completed module left a running descendant')
                finally:
                    try:
                        os.kill(descendant, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.assertEqual(result.returncode == 0, succeeds, result.stderr + result.stdout)
                self.assertEqual(json.loads((output / 'receipt.json').read_text())['success'], succeeds)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process group ownership')
    def test_signal_cancellation_stops_the_owned_module_descendant(self):
        (self.root / 'scripts/test_helper_fixture.py').write_text(
            'import unittest,subprocess,sys,time\nfrom pathlib import Path\n'
            'class Checks(unittest.TestCase):\n def test_wait(self):\n'
            '  child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"])\n'
            '  Path("descendant-pid").write_text(str(child.pid))\n  time.sleep(60)\n')
        output = self.root / 'cancelled'
        environment = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
        process = subprocess.Popen([sys.executable, '-B', str(SUBJECT), 'run', '--root', str(self.root),
                                    '--output', str(output)], env=environment,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        marker = self.root / 'descendant-pid'
        deadline = time.monotonic() + 10
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        self.assertTrue(marker.exists(), 'module child never started')
        descendant = int(marker.read_text())
        process.send_signal(signal.SIGTERM)
        self.assertNotEqual(process.wait(timeout=15), 0)
        status = Path('/proc') / str(descendant) / 'stat'
        self.assertTrue(not status.exists() or status.read_text().split()[2] in ('Z', 'X'))
        self.assertFalse(json.loads((output / 'receipt.json').read_text())['success'])

    def test_worker_commands_have_separate_complete_results_not_python_test_ids(self):
        module = subject(); original = module.child_process; commands = []
        def execute(root, arguments, environment, deadline, log_path, argv=None):
            if argv is None:
                return original(root, arguments, environment, deadline, log_path)
            commands.append(argv); log_path.write_text('controlled command execution\n'); return 0
        with patch.object(module, 'child_process', side_effect=execute):
            receipt = module.run_shard(self.root, self.root / 'worker', environment={}, worker_checks=True)
        self.assertEqual(len(commands), 4)
        module.validate_auxiliary(receipt['auxiliary'])
        self.assertEqual(len(receipt['discovered']), len(receipt['executed']))
        self.assertFalse(any(name.startswith('ci-artifacts-') for name in receipt['discovered']))
        for mutate in (lambda rows: rows.pop(), lambda rows: rows.append(rows[0]),
                       lambda rows: rows[0].update(exit_code=1), lambda rows: rows[0].update(complete=False)):
            bad = copy.deepcopy(receipt['auxiliary']); mutate(bad)
            with self.assertRaises(ValueError):
                module.validate_auxiliary(bad)

    def test_privileged_proof_requires_actual_root_unskipped_exact_source(self):
        module = subject()
        manifest = [dict(path='scripts/test_qemu_health.py', sha256='a' * 64,
                         identities=[module.PRIVILEGED_ID])]
        context = dict(source_sha='a' * 40, tree_sha='b' * 40, source_clean=True,
                       python=dict(version=[3, 12, 3]))
        proof = dict(schema_version=1, kind='workflow-helper-privileged', context=context,
                     started_at='2026-11-11T00:01:00Z', completed_at='2026-11-11T00:01:01Z',
                     identities=[module.PRIVILEGED_ID], module_sha256='a' * 64,
                     runner_sha256=module.digest(SUBJECT.read_bytes()),
                     actor=dict(uid=0, platform='linux', python=[3, 12, 3]),
                     executed=[dict(id=module.PRIVILEGED_ID, status='passed', elapsed_seconds=.1)])
        module.validate_privileged(proof, manifest, context)
        for mutate in (lambda row: row['actor'].update(uid=1001),
                       lambda row: row['executed'][0].update(status='skipped'),
                       lambda row: row['context'].update(source_sha='c' * 40),
                       lambda row: row.update(identities=[])):
            bad = copy.deepcopy(proof); mutate(bad)
            with self.assertRaises(ValueError):
                module.validate_privileged(bad, manifest, context)


class HelperAdmissionTests(unittest.TestCase):
    def setUp(self):
        HelperExecutionTests.setUp(self)
        self.module = subject()
        self.sha, self.tree, self.repository = 'a' * 40, 'b' * 40, 'owner/repo'
        self.run = dict(id=10, head_sha=self.sha, event='push', head_branch='main',
                        workflow_id=20, path=self.module.WORKFLOW, run_attempt=1,
                        repository=dict(full_name=self.repository), status='in_progress',
                        run_started_at='2026-11-11T00:00:00Z')
        self.manifest = self.module.discover(self.root)
        self.jobs, self.artifacts, self.archives = [], [], {}
        for shard in range(2):
            job = dict(id=30 + shard, name=f'Workflow helpers ({shard}/2)', run_id=10,
                       head_sha=self.sha, run_attempt=1, status='completed', conclusion='success',
                       started_at='2026-11-11T00:01:00Z', completed_at='2026-11-11T00:02:00Z',
                       labels=['ubuntu-24.04'])
            self.jobs.append(job)
            receipt = self.module.empty_receipt(self.root, self.manifest, shard, 2, {}, shard == 0)
            receipt.update(complete=True, success=True,
                           executed=[dict(id=name, status='passed', elapsed_seconds=.01)
                                     for name in receipt['selected']])
            receipt['context'].update(repository=self.repository, source_sha=self.sha, tree_sha=self.tree,
                                      source_clean=True, api_head_sha=self.sha, run_id='10', run_attempt=1,
                                      event='push', ref='refs/heads/main', platform='linux', uid=1001,
                                      workflow_ref=self.repository + '/' + self.module.WORKFLOW + '@refs/heads/main',
                                      python=dict(implementation='CPython', version=[3, 12, 9]))
            self.bundle(shard, receipt)
        self.latest_jobs = self.jobs

    def bundle(self, shard, receipt, *, extra=False):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('receipt.json', json.dumps(receipt))
            if extra:
                archive.writestr('extra', 'unadmitted')
        content = buffer.getvalue()
        artifact = dict(id=40 + shard, name=f'workflow-helpers-10-1-{shard}-of-2',
                        size_in_bytes=len(content), digest='sha256:' + hashlib.sha256(content).hexdigest(),
                        expired=False, created_at='2026-11-11T00:01:30Z',
                        workflow_run=dict(id=10, head_sha=self.sha))
        self.archives[shard] = (receipt, content)
        if len(self.artifacts) > shard:
            self.artifacts[shard] = artifact
        else:
            self.artifacts.append(artifact)

    def api(self):
        parent = self
        class API:
            def listing(self, endpoint, field):
                if field == 'jobs':
                    return copy.deepcopy(parent.latest_jobs if '/attempts/2/' in endpoint else parent.jobs)
                if field == 'artifacts':
                    return copy.deepcopy(parent.artifacts)
                raise AssertionError(endpoint)
            def request(self, endpoint, binary=False):
                if binary:
                    number = int(endpoint.split('/artifacts/')[1].split('/')[0]) - 40
                    return parent.archives[number][1]
                if endpoint.endswith('/attempts/1'):
                    prior = dict(parent.run, run_attempt=1, run_started_at='2026-11-11T00:00:00Z')
                    return copy.deepcopy(prior)
                if endpoint.endswith('/actions/runs/10'):
                    return copy.deepcopy(parent.run)
                raise AssertionError(endpoint)
        return API()

    def admit(self):
        with patch.object(self.module.subprocess, 'check_output', return_value=self.tree):
            return self.module.admit_pair(self.api(), self.root, self.repository, self.run, self.sha)

    def git_output(self, arguments, **kwargs):
        if 'status' in arguments:
            return ''
        return self.tree if arguments[-1] == 'HEAD^{tree}' else self.sha

    def test_successful_owners_can_be_consumed_before_whole_ci_finishes(self):
        receipt = self.admit()
        self.assertTrue(receipt['success'])
        self.assertEqual([row['producer_job'] for row in receipt['producers']], [30, 31])

    def test_latest_failed_or_incomplete_owner_never_uses_old_green_proof(self):
        for status, conclusion in [('completed', 'failure'), ('in_progress', None), ('completed', 'cancelled')]:
            with self.subTest(status=status, conclusion=conclusion):
                self.jobs[0].update(status=status, conclusion=conclusion)
                with self.assertRaises(ValueError):
                    self.admit()

    def test_carried_relabelled_attempt_uses_original_execution_artifact(self):
        self.run.update(run_attempt=2, run_started_at='2026-11-11T00:03:00Z')
        self.latest_jobs = [dict(job, id=100 + index, run_attempt=2) for index, job in enumerate(self.jobs)]
        receipt = self.admit()
        self.assertEqual([row['producer_attempt'] for row in receipt['producers']], [1, 1])
        self.assertEqual([row['producer_job'] for row in receipt['producers']], [30, 31])

    def test_changed_carried_execution_interval_is_rejected(self):
        self.run.update(run_attempt=2, run_started_at='2026-11-11T00:03:00Z')
        self.latest_jobs = [dict(job, id=100 + index, run_attempt=2) for index, job in enumerate(self.jobs)]
        self.latest_jobs[0]['completed_at'] = '2026-11-11T00:02:01Z'
        with self.assertRaisesRegex(ValueError, 'execution changed'):
            self.admit()

    def test_archive_digest_size_owner_interval_and_extra_members_are_closed(self):
        for field, value in [('digest', 'sha256:' + '0' * 64), ('size_in_bytes', 1),
                             ('expired', True), ('created_at', '2026-11-11T00:02:01Z')]:
            original = self.artifacts[0][field]
            with self.subTest(field=field):
                self.artifacts[0][field] = value
                with self.assertRaises(ValueError):
                    self.admit()
                self.artifacts[0][field] = original
        self.bundle(0, self.archives[0][0], extra=True)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.admit()

    def test_receipt_context_static_ownership_and_execution_tamper_are_rejected(self):
        original = copy.deepcopy(self.archives[0][0])
        for mutate in (lambda row: row['context'].update(source_sha='c' * 40),
                       lambda row: row['context'].update(tree_sha='c' * 40),
                       lambda row: row['context'].update(source_clean=False),
                       lambda row: row['context'].update(uid=0),
                       lambda row: row.update(static_complete=False),
                       lambda row: row['executed'].pop()):
            bad = copy.deepcopy(original); mutate(bad); self.bundle(0, bad)
            with self.subTest(receipt=bad), self.assertRaises(ValueError):
                self.admit()
        self.bundle(0, original)

    def test_attempt_change_during_download_is_rejected(self):
        api = self.api(); request = api.request
        def response(endpoint, binary=False):
            row = request(endpoint, binary)
            if endpoint.endswith('/actions/runs/10'):
                row['run_attempt'] = 2
            return row
        api.request = response
        with patch.object(self.module.subprocess, 'check_output', return_value=self.tree):
            with self.assertRaisesRegex(ValueError, 'attempt changed'):
                self.module.admit_pair(api, self.root, self.repository, self.run, self.sha)

    def test_complete_listing_pages_and_duplicate_ids_fail_closed(self):
        api = self.module.GitHub(99999999999)
        pages = [dict(total_count=101, jobs=[dict(id=i) for i in range(1, 101)]),
                 dict(total_count=101, jobs=[dict(id=101)])]
        with patch.object(api, 'request', side_effect=pages):
            self.assertEqual(len(api.listing('jobs', 'jobs')), 101)
        pages[1]['jobs'][0]['id'] = 1
        with patch.object(api, 'request', side_effect=pages), self.assertRaisesRegex(ValueError, 'duplicate'):
            api.listing('jobs', 'jobs')

    def outer_api(self, runs):
        api = self.api(); request, listing = api.request, api.listing
        api.deadline = time.monotonic() + 20
        def response(endpoint, binary=False):
            if endpoint.endswith('/actions/workflows/ci.yml'):
                return dict(path=self.module.WORKFLOW, id=20)
            return request(endpoint, binary)
        def listings(endpoint, field):
            return copy.deepcopy(runs) if field == 'workflow_runs' else listing(endpoint, field)
        api.request, api.listing = response, listings
        return api

    def test_scheduled_absence_is_the_only_explicit_standalone_fallback(self):
        environment = dict(GITHUB_REPOSITORY=self.repository, GITHUB_SHA=self.sha, GITHUB_EVENT_NAME='schedule')
        with patch.object(self.module, 'GitHub', return_value=self.outer_api([])), \
                patch.object(self.module.subprocess, 'check_output', side_effect=self.git_output):
            with self.assertRaises(self.module.NoProducer):
                self.module.admit(self.root, environment, 20)
        self.jobs[0]['conclusion'] = 'failure'
        with patch.object(self.module, 'GitHub', return_value=self.outer_api([self.run])), \
                patch.object(self.module.subprocess, 'check_output', side_effect=self.git_output):
            with self.assertRaisesRegex(ValueError, 'latest helper owner failed'):
                self.module.admit(self.root, environment, 20)

    def test_push_consumer_uses_completed_shards_without_waiting_for_whole_run(self):
        environment = dict(GITHUB_REPOSITORY=self.repository, GITHUB_SHA=self.sha, GITHUB_EVENT_NAME='push')
        with patch.object(self.module, 'GitHub', return_value=self.outer_api([self.run])), \
                patch.object(self.module.subprocess, 'check_output', side_effect=self.git_output):
            receipt = self.module.admit(self.root, environment, 20)
        self.assertTrue(receipt['success'])

    def test_metadata_retry_reuses_native_transport_and_does_not_retry_rate_limits(self):
        api = self.module.GitHub(time.monotonic() + 20)
        def request(arguments, *, stdout, check, timeout):
            calls.append(timeout)
            status = responses.pop(0)
            stdout.write(f'HTTP/2.0 {status} response\ncontent-type: application/json\n\n{{"ok":true}}'.encode())
            if status != 200:
                raise subprocess.CalledProcessError(1, arguments)
        calls, responses = [], [502, 200]
        with patch.object(self.module.subprocess, 'run', side_effect=request), patch.object(self.module.time, 'sleep'):
            self.assertEqual(api.request('fixture'), {'ok': True})
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(0 < timeout <= 20 for timeout in calls))
        calls, responses = [], [429]
        with patch.object(self.module.subprocess, 'run', side_effect=request):
            with self.assertRaises(subprocess.CalledProcessError):
                api.request('fixture')
        self.assertEqual(len(calls), 1)

    def test_current_pr_run_binds_api_head_and_actual_merge_source_separately(self):
        event = self.root / 'event.json'
        event.write_text(json.dumps(dict(pull_request=dict(head=dict(sha='c' * 40)))))
        self.run.update(head_sha='c' * 40, event='pull_request', head_branch='feature')
        for job in self.jobs:
            job['head_sha'] = 'c' * 40
        for shard in range(2):
            receipt = copy.deepcopy(self.archives[shard][0])
            receipt['context'].update(api_head_sha='c' * 40, event='pull_request', ref='refs/pull/7/merge',
                                      workflow_ref=self.repository + '/' + self.module.WORKFLOW + '@refs/pull/7/merge')
            self.bundle(shard, receipt)
            self.artifacts[shard]['workflow_run']['head_sha'] = 'c' * 40
        environment = dict(GITHUB_REPOSITORY=self.repository, GITHUB_SHA=self.sha, GITHUB_EVENT_NAME='pull_request',
                           GITHUB_REF='refs/pull/7/merge', GITHUB_HEAD_REF='feature', GITHUB_RUN_ID='10',
                           GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_PATH=str(event),
                           GITHUB_WORKFLOW_REF=self.repository + '/' + self.module.WORKFLOW + '@refs/pull/7/merge')
        with patch.object(self.module, 'GitHub', return_value=self.outer_api([self.run])), \
                patch.object(self.module.subprocess, 'check_output', side_effect=self.git_output):
            proof = self.module.admit(self.root, environment, 20, current_run=True)
        self.assertEqual(proof['source_sha'], self.sha)
        environment['GITHUB_RUN_ATTEMPT'] = '2'
        with patch.object(self.module, 'GitHub', return_value=self.outer_api([self.run])), \
                patch.object(self.module.subprocess, 'check_output', side_effect=self.git_output):
            with self.assertRaisesRegex(ValueError, 'consumer attempt changed'):
                self.module.admit(self.root, environment, 20, current_run=True)

    def test_dirty_consumer_cannot_claim_clean_remote_source_proof(self):
        environment = dict(GITHUB_REPOSITORY=self.repository, GITHUB_SHA=self.sha, GITHUB_EVENT_NAME='push')
        def dirty(arguments, **kwargs):
            return ' M source.py\n' if 'status' in arguments else self.git_output(arguments, **kwargs)
        with patch.object(self.module, 'GitHub', return_value=self.outer_api([self.run])), \
                patch.object(self.module.subprocess, 'check_output', side_effect=dirty):
            with self.assertRaisesRegex(ValueError, 'dirty or mismatched'):
                self.module.admit(self.root, environment, 20)


if __name__ == '__main__':
    unittest.main()

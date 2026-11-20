import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest import mock

import test_fedora_sqlite as fixtures

SPEC = importlib.util.spec_from_file_location('sqlite_baseline', fixtures.ROOT/'scripts/fedora-sqlite-baseline.py')
cache = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cache)
BUILT = 1700000000
INSTALLED = [{'name': 'gcc', 'evr': '0:16-1.fc44', 'arch': 'x86_64',
              'immutable_header_sha256': 'c'*64, 'signature_sha256': 'd'*64, 'signers': 'Key ID 6d9f90a6'}]


class BaselineTests(unittest.TestCase):
    save = fixtures.FedoraSQLiteTests.save

    def setUp(self):
        fixtures.FedoraSQLiteTests.setUp(self)
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.work = Path(scratch.name)
        self.metadata = dict(schema_version=1, architecture='x86_64', source_sha=fixtures.REVISION,
            built_at=BUILT, run_id='41', run_attempt=1, recipe_sha256='b'*64,
            inventory_sha256=cache.sha(cache.canonical(INSTALLED)),
            manifest_sha256=fixtures.sqlite.digest(self.bundle/'manifest.json'))

    def artifact(self, metadata=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            for path in self.bundle.iterdir():
                archive.add(path, arcname='bundle/'+path.name)
            for name, value in (('baseline.json', metadata or self.metadata), ('inventory.json', INSTALLED)):
                data = cache.canonical(value)
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return output.getvalue()

    def restore(self, metadata=None, tamper=False):
        archive, proof = self.artifact(metadata), b'fixture local Sigstore bundle'
        pointer = dict(archive_sha256=cache.sha(archive), proof_sha256=cache.sha(proof),
                       generation=[BUILT, 41, 1])
        keys = []
        def fetch(key, path, limit):
            keys.append(key)
            data = cache.canonical(pointer) if key.endswith('latest.json') else proof if key.endswith('.sigstore.json') else archive
            path.write_bytes(data+b'tamper' if tamper and key.endswith('.tar') else data)
        destination, diagnostics = self.work/'supply', self.work/'diagnostics'
        destination.mkdir()
        diagnostics.mkdir()
        with mock.patch.dict(os.environ, GITHUB_RUN_ID='91', GITHUB_RUN_ATTEMPT='2'), \
                mock.patch.object(cache, 'recipe', return_value='b'*64), \
                mock.patch.object(cache, 'fetch', side_effect=fetch), \
                mock.patch.object(cache, 'verify_attestation', return_value=BUILT+1) as verify, \
                mock.patch.object(cache.time, 'time', return_value=BUILT+30):
            cache.restore(destination, self.policy, 'x86_64', 'e'*40, INSTALLED, diagnostics)
            self.assertEqual(verify.call_count, 1)
        return destination, keys

    def test_cached_build_a_consumed_by_b_keeps_original_truth_and_all_guest_bindings(self):
        original = (self.bundle/'manifest.json').read_bytes()
        destination, keys = self.restore()
        self.assertEqual((destination/'manifest.json').read_bytes(), original)
        admission = json.loads((destination/'admission.json').read_bytes())
        self.assertEqual((admission['build_source_sha'], admission['consumer_sha']),
                         (fixtures.REVISION, 'e'*40))
        self.assertTrue(all(key.startswith(cache.prefix('x86_64', 'b'*64, self.metadata['inventory_sha256'])) for key in keys))
        context = dict(run_id='91', run_attempt=2,
                       admission_sha256=fixtures.sqlite.digest(destination/'admission.json'))
        with mock.patch.object(cache.time, 'time', return_value=BUILT+30):
            manifest = fixtures.sqlite.verify_bundle(destination, self.policy, 'x86_64', 'e'*40, context)
            binding = fixtures.sqlite.admission_binding(destination, manifest, 'e'*40, context)
            record = dict(schema_version=1, source_sha='e'*40, **binding,
                manifest_sha256=fixtures.sqlite.digest(destination/'manifest.json'),
                native_package_verification=True, installed=dict(name='sqlite-libs', version=manifest['version'],
                    release=manifest['release'], architecture='x86_64', library_sha256=manifest['library_sha256']),
                before=dict(version='3.51.2', release='1.fc44'), before_admitted=False,
                package_sha256={name: manifest['files'][name] for name in fixtures.sqlite.package_names(self.policy, 'x86_64')})
            for phase in ('before', 'after', 'final'):
                (self.work/f'fedora-sqlite-{phase}.json').write_bytes(cache.canonical(record))
            fixtures.sqlite.verify_guest_evidence(self.work, destination, manifest, 'e'*40, context)
            for changed in (dict(context, run_attempt=1), dict(context, admission_sha256='f'*64)):
                with self.assertRaises(ValueError):
                    fixtures.sqlite.verify_bundle(destination, self.policy, 'x86_64', 'e'*40, changed)
            altered = dict(record, admission_sha256='f'*64)
            (self.work/'fedora-sqlite-final.json').write_bytes(cache.canonical(altered))
            with self.assertRaises(ValueError):
                fixtures.sqlite.verify_guest_evidence(self.work, destination, manifest, 'e'*40, context)

    def test_tampered_transport_changed_recipe_and_wrong_architecture_refuse_admission(self):
        for mode in ('tampered', 'recipe', 'arch'):
            with self.subTest(mode=mode):
                for path in (self.work/'supply', self.work/'diagnostics'):
                    if path.exists():
                        import shutil
                        shutil.rmtree(path)
                metadata = dict(self.metadata)
                if mode == 'recipe':
                    metadata['recipe_sha256'] = 'f'*64
                if mode == 'arch':
                    metadata['architecture'] = 'aarch64'
                with self.assertRaises(ValueError):
                    self.restore(metadata, tamper=mode == 'tampered')
                self.assertEqual(list((self.work/'supply').iterdir()), [])

    def test_same_run_partial_rerun_revalidates_owner_bytes_age_and_recipe(self):
        import zipfile
        destination, _ = self.restore()
        original = (destination/'manifest.json').read_bytes()
        previous = (destination/'admission.json').read_bytes()
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, 'w') as archive:
            for path in destination.iterdir():
                archive.writestr('fedora-sqlite-x86_64-2/'+path.name, path.read_bytes())
        payload = raw.getvalue()
        artifact = dict(id=71, name='fedora-sqlite-x86_64-2', expired=False,
            size_in_bytes=len(payload), digest='sha256:'+cache.sha(payload),
            created_at='2023-11-14T22:13:25Z')
        event = self.work/'event.json'
        event.write_text('{}')
        mode = 'valid'
        current_reads = 0
        def api(path):
            nonlocal current_reads
            base = dict(id=91, repository={'id':1133413326}, head_sha='e'*40,
                event='push', path='.github/workflows/ci.yml', run_attempt=3,
                run_started_at='2023-11-14T22:13:40Z')
            if path.endswith('/artifacts?per_page=100'):
                return dict(total_count=1, artifacts=[artifact])
            if '/jobs?' in path:
                current = '/attempts/3/' in path
                job = dict(id=56 if current else 55, name='Fedora SQLite supply / SQLite full RPM check (x86_64)',
                    run_id=91, run_attempt=3 if current else 2, head_sha='e'*40,
                    status='completed', conclusion='failure' if mode == 'failed' else 'success',
                    started_at='2023-11-14T22:13:41Z' if current and mode == 'rerun' else '2023-11-14T22:13:23Z',
                    completed_at='2023-11-14T22:13:30Z')
                if current:
                    if mode == 'latest-failed': job['conclusion'] = 'failure'
                    if mode == 'latest-cancelled': job['conclusion'] = 'cancelled'
                    if mode == 'latest-pending': job['status'] = 'in_progress'
                    if mode == 'latest-invalid-id': job['id'] = 0
                    if mode == 'latest-string-id': job['id'] = '56'
                    if mode == 'latest-bool-id': job['id'] = True
                    if mode == 'latest-interval': job['completed_at'] = '2023-11-14T22:13:31Z'
                return dict(total_count=1, jobs=[job])
            if path.endswith('/attempts/2'):
                base.update(run_attempt=2, run_started_at='2023-11-14T22:13:22Z')
            if path.endswith('/runs/91'):
                current_reads += 1
                if mode == 'attempt-race' and current_reads > 1:
                    base['run_attempt'] = 4
            return base
        for mode in ('valid', 'foreign-run', 'foreign-source', 'expired', 'recipe', 'failed', 'rerun', 'attempt-race',
                     'latest-failed', 'latest-cancelled', 'latest-pending', 'latest-invalid-id',
                     'latest-string-id', 'latest-bool-id', 'latest-interval'):
            (destination/'admission.json').write_bytes(previous)
            current_reads = 0
            context = dict(run_id='92' if mode == 'foreign-run' else '91', run_attempt=3)
            now = BUILT+86401 if mode == 'expired' else BUILT+30
            with self.subTest(mode=mode), mock.patch.dict(os.environ,
                    GITHUB_EVENT_PATH=str(event), GITHUB_EVENT_NAME='push'), \
                    mock.patch.dict(cache.NATIVE, api_json=api), \
                    mock.patch.object(cache, 'recipe', return_value='f'*64 if mode == 'recipe' else 'b'*64), \
                    mock.patch.object(cache, 'verify_attestation', return_value=BUILT+1), \
                    mock.patch.object(cache, 'download_carried_artifact',
                                      side_effect=lambda item, path: path.write_bytes(payload)), \
                    mock.patch.object(cache.time, 'time', return_value=now):
                if mode == 'valid':
                    self.assertEqual(cache.readmit(destination, self.policy, 'x86_64', 'e'*40, context),
                                     'carried-supply')
                    current = json.loads((destination/'admission.json').read_bytes())
                    self.assertEqual((current['consumer_run_attempt'], current['supply_run_attempt']), (3,2))
                    self.assertEqual((current['built_at'], current['build_source_sha']), (BUILT,fixtures.REVISION))
                else:
                    with self.assertRaises(ValueError):
                        cache.readmit(destination, self.policy, 'x86_64',
                                      'f'*40 if mode == 'foreign-source' else 'e'*40, context)
                    self.assertEqual((destination/'admission.json').read_bytes(), previous)
                self.assertEqual((destination/'manifest.json').read_bytes(), original)

    def test_actual_build_age_has_no_publication_or_future_extension(self):
        for now in (BUILT-1, BUILT+86401):
            with self.subTest(now=now), self.assertRaises(ValueError):
                cache.fresh(self.metadata, now)
        cache.fresh(self.metadata, BUILT+86400)
        with self.assertRaises(ValueError):
            cache.fresh(dict(self.metadata, built_at=True), BUILT)

    def test_legacy_same_source_remains_valid_and_cross_source_requires_admission(self):
        fixtures.sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', fixtures.REVISION)
        with self.assertRaises(ValueError):
            fixtures.sqlite.verify_bundle(self.bundle, self.policy, 'x86_64', 'e'*40)

    def test_installed_inventory_changes_when_signed_immutable_header_changes(self):
        def output(header, signed=None):
            return ('gcc\t0:16-1.fc44\tx86_64\t'+header+
                    '\tRSA/SHA256, Key ID 6d9f90a6;\t(none)\tc2ln\t(none)\t'+
                    (signed or cache.sha(bytes.fromhex(header)))+'\n').encode()
        first = cache.package_inventory(output('aabb'*16))
        second = cache.package_inventory(output('aabc'*16))
        self.assertEqual(first[0]['evr'], second[0]['evr'])
        self.assertNotEqual(cache.sha(cache.canonical(first)), cache.sha(cache.canonical(second)))
        for data in (output('aabb'), output('aabb'*16, 'f'*64), b'invalid header'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                cache.package_inventory(data)

    def test_verified_certificate_requires_immutable_owner_workflow_source_and_trusted_time(self):
        archive, proof, report = self.work/'archive', self.work/'proof', self.work/'verification.json'
        archive.write_bytes(b'archive')
        proof.write_bytes(b'proof')
        cert = dict(issuer='https://token.actions.githubusercontent.com',
            sourceRepositoryURI='https://github.com/omg-cli/omg', sourceRepositoryIdentifier='1133413326',
            sourceRepositoryOwnerIdentifier='329545359', sourceRepositoryRef='refs/heads/main',
            sourceRepositoryDigest=fixtures.REVISION,
            buildSignerURI='https://github.com/'+cache.WORKFLOW+'@refs/heads/main',
            buildSignerDigest=fixtures.REVISION, runnerEnvironment='github-hosted',
            runInvocationURI='https://github.com/omg-cli/omg/actions/runs/41/attempts/1')
        result = dict(signature=dict(certificate=cert),
            verifiedTimestamps=[dict(type='Tlog', timestamp=datetime.datetime.fromtimestamp(BUILT+1, datetime.UTC).isoformat())],
            statement=dict(predicateType='https://slsa.dev/provenance/v1',
                subject=[dict(name='sqlite-baseline.tar', digest=dict(sha256=cache.SQLITE['digest'](archive)))]))
        cases = [(None, None), ('sourceRepositoryIdentifier', '999'), ('sourceRepositoryOwnerIdentifier', '999'),
                 ('buildSignerURI', 'https://github.com/evil/worker@refs/heads/main'),
                 ('sourceRepositoryRef', 'refs/heads/other'), ('sourceRepositoryDigest', 'f'*40),
                 ('runnerEnvironment', 'self-hosted'), ('runInvocationURI', 'https://github.com/omg-cli/omg/actions/runs/41/attempts/2'),
                 ('__timestamp__', dict(type='Tlog', timestamp=datetime.datetime.fromtimestamp(BUILT-1, datetime.UTC).isoformat())),
                 ('__timestamp__', dict(type='Tlog', timestamp=datetime.datetime.fromtimestamp(BUILT+31, datetime.UTC).isoformat())),
                 ('__timestamp__', dict(type='TimestampAuthority', timestamp=datetime.datetime.fromtimestamp(BUILT+1, datetime.UTC).isoformat()))]
        for key, value in cases:
            candidate = copy.deepcopy(result)
            if key == '__timestamp__':
                candidate['verifiedTimestamps'] = [value]
            elif key:
                candidate['signature']['certificate'][key] = value
            def verify(command, **options):
                self.assertIn('--bundle', command)
                self.assertIn('--source-digest', command)
                self.assertIn('--deny-self-hosted-runners', command)
                options['stdout'].write(json.dumps([{'verificationResult': candidate}]).encode())
            with self.subTest(key=key), mock.patch.object(cache.subprocess, 'run', side_effect=verify), \
                    mock.patch.object(cache.time, 'time', return_value=BUILT+30):
                if key:
                    with self.assertRaises(ValueError):
                        cache.verify_attestation(archive, proof, self.metadata, report)
                else:
                    cache.verify_attestation(archive, proof, self.metadata, report)

    def test_untrusted_publisher_context_is_rejected_before_remote_or_file_operations(self):
        trusted = dict(GITHUB_REPOSITORY='omg-cli/omg', GITHUB_REPOSITORY_ID='1133413326',
            GITHUB_REPOSITORY_OWNER_ID='329545359', GITHUB_REF='refs/heads/main',
            GITHUB_EVENT_NAME='push', GITHUB_WORKFLOW_REF='omg-cli/omg/.github/workflows/ci.yml@refs/heads/main')
        for key, value in (('GITHUB_EVENT_NAME','pull_request'), ('GITHUB_REF','refs/pull/1/merge'),
                ('GITHUB_REPOSITORY_ID','999'), ('GITHUB_REPOSITORY_OWNER_ID','999'),
                ('GITHUB_WORKFLOW_REF','omg-cli/omg/.github/workflows/ci.yml@refs/heads/main-other')):
            with self.subTest(key=key), mock.patch.dict(os.environ, dict(trusted, **{key:value})), \
                    mock.patch.object(cache, 'r2') as remote, self.assertRaises(ValueError):
                cache.publish(self.work/'does-not-exist', self.work/'no-proof', 'x86_64')
            remote.assert_not_called()

    def test_publication_reuses_the_one_cold_build_and_retains_existing_proof(self):
        from test_ci_gates import job_block
        workflow = (fixtures.ROOT/'.github/workflows/fedora-sqlite.yml').read_text()
        publisher = (fixtures.ROOT/'.github/workflows/fedora-sqlite-publish.yml').read_text()
        build, publish = job_block(workflow,'build'), job_block(publisher,'publish')
        self.assertEqual(workflow.count('python3 scripts/fedora-sqlite.py '), 1)
        self.assertNotIn('id-token: write', workflow)
        self.assertNotIn('attestations: write', workflow)
        self.assertNotIn('AWS_SECRET_ACCESS_KEY', workflow)
        self.assertIn("github.ref == 'refs/heads/main'", publish)
        self.assertIn('artifact-ids: ${{ inputs.artifact-id }}', publish)
        self.assertIn('--artifact-digest "$SUPPLY_ARTIFACT_DIGEST"', publish)
        self.assertNotIn('rpmbuild', publish)
        self.assertNotIn('fedora-sqlite.py build', publish)
        self.assertIn('attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8', publish)
        self.assertFalse((fixtures.ROOT/'.github/workflows/fedora-sqlite-baseline.yml').exists())

    def test_optional_publication_records_early_failures_without_weakening_required_supply(self):
        import subprocess
        import sys
        import textwrap
        from test_ci_gates import job_block
        workflow = (fixtures.ROOT/'.github/workflows/fedora-sqlite-publish.yml').read_text()
        required = (fixtures.ROOT/'.github/workflows/fedora-sqlite.yml').read_text()
        self.assertIn('    continue-on-error: true', job_block(workflow,'publish'))
        self.assertNotIn('continue-on-error:', job_block(required,'build'))
        code = workflow.split("          python3 - <<'PY'\n",1)[1].split('          PY\n',1)[0]
        code = textwrap.dedent(code)
        for failed in ('checkout','download','none'):
            stages = dict(CHECKOUT_RESULT='success',DOWNLOAD_RESULT='success',PACKAGE_RESULT='success',
                          ATTEST_RESULT='success',PUBLICATION='success')
            if failed != 'none':
                stages[failed.upper()+'_RESULT'] = 'failure'
                stages.update(PACKAGE_RESULT='skipped',ATTEST_RESULT='skipped',PUBLICATION='skipped')
                if failed == 'checkout': stages['DOWNLOAD_RESULT']='skipped'
            target = self.work/('status-'+failed)
            result = subprocess.run([sys.executable,'-B','-c',code],capture_output=True,text=True,timeout=10,
                env=dict(os.environ,**stages,RUNNER_TEMP=str(target),GITHUB_SHA=fixtures.REVISION,
                    GITHUB_RUN_ID='41',GITHUB_RUN_ATTEMPT='1',SUPPLY_ARTIFACT_ID='71',
                    SUPPLY_ARTIFACT_DIGEST='d'*64,AWS_SECRET_ACCESS_KEY='must-not-be-recorded'))
            self.assertEqual(result.returncode,0,result.stderr)
            raw = (target/'sqlite-publication/publication-status.json').read_text()
            receipt = json.loads(raw)
            self.assertEqual(receipt['disposition'],'published' if failed=='none' else 'degraded')
            self.assertIs(receipt['tests_executed_by_publisher'],False)
            self.assertNotIn('must-not-be-recorded',raw)
            self.assertEqual((receipt['source_sha'],receipt['run_id'],receipt['run_attempt']),
                             (fixtures.REVISION,'41',1))

    def test_publisher_packages_only_the_digest_verified_original_cold_artifact(self):
        import shutil
        import zipfile
        source = self.work/'producer/fedora-sqlite-x86_64-1'
        source.parent.mkdir()
        shutil.copytree(self.bundle, source)
        manifest = dict(self.manifest, built_at=BUILT)
        (source/'manifest.json').write_bytes(cache.canonical(manifest))
        diagnostics = source.parent/'diagnostics'/source.name
        diagnostics.mkdir(parents=True)
        metadata = dict(source_sha=fixtures.REVISION, run_id='41', run_attempt=1, built_at=BUILT)
        (diagnostics/'build-finished.json').write_bytes(cache.canonical(metadata))
        inventory = cache.canonical(INSTALLED)
        (diagnostics/'inventory.json').write_bytes(inventory)
        policy = self.work/'policy.json'
        policy.write_bytes(cache.canonical(self.policy))
        raw = io.BytesIO()
        with zipfile.ZipFile(raw,'w') as archive:
            for path in [*source.iterdir(), *diagnostics.iterdir()]:
                archive.writestr(path.relative_to(source.parent).as_posix(), path.read_bytes())
        payload = raw.getvalue()
        artifact = dict(id=71, name=source.name, digest='sha256:'+cache.sha(payload),
            size_in_bytes=len(payload), expired=False, workflow_run=dict(id=41,head_sha=fixtures.REVISION))
        for mode in ('valid','wrong-digest','changed-local-inventory'):
            (diagnostics/'inventory.json').write_bytes(inventory if mode != 'changed-local-inventory' else b'changed')
            with self.subTest(mode=mode), mock.patch.dict(os.environ,GITHUB_RUN_ID='41',GITHUB_RUN_ATTEMPT='1'), \
                    mock.patch.dict(cache.SQLITE, DEFAULT_POLICY=policy), \
                    mock.patch.dict(cache.NATIVE, api_json=mock.Mock(return_value=artifact)), \
                    mock.patch.object(cache, 'bounded_output', return_value=payload), \
                    mock.patch.object(cache.time,'time',return_value=BUILT+30):
                if mode == 'valid':
                    result = cache.pack(source,self.work/mode,'x86_64',fixtures.REVISION,'71',cache.sha(payload))
                    self.assertEqual(result['built_at'],BUILT)
                    self.assertEqual((source/'manifest.json').read_bytes(),cache.canonical(manifest))
                else:
                    with self.assertRaises(ValueError):
                        cache.pack(source,self.work/mode,'x86_64',fixtures.REVISION,'71',
                                   'f'*64 if mode == 'wrong-digest' else cache.sha(payload))

    def test_old_publication_cannot_replace_newer_pointer_and_race_is_conditional(self):
        publication = self.work/'publication'
        publication.mkdir()
        (publication/'baseline.json').write_bytes(cache.canonical(self.metadata))
        (publication/'sqlite-baseline.tar').write_bytes(b'archive')
        proof = self.work/'proof'
        proof.write_bytes(b'proof')
        environment = dict(GITHUB_REPOSITORY='omg-cli/omg', GITHUB_REPOSITORY_ID='1133413326',
            GITHUB_REPOSITORY_OWNER_ID='329545359', GITHUB_REF='refs/heads/main', GITHUB_EVENT_NAME='schedule',
            GITHUB_WORKFLOW_REF='omg-cli/omg/.github/workflows/ci.yml@refs/heads/main', GITHUB_SHA=fixtures.REVISION,
            GITHUB_RUN_ID='41', GITHUB_RUN_ATTEMPT='1')
        for previous, expected_pointer in (([BUILT+1, 42, 1], False), ([BUILT-1, 40, 1], True)):
            calls = []
            def r2(key, method, output, body=None, condition=None):
                calls.append((key, method, condition))
                if key.endswith('latest.json') and method == 'GET':
                    output.write_bytes(cache.canonical({'generation': previous}))
                    return 200, 'etag: "old"\r\n'
                return (412 if key.endswith('latest.json') else 200), ''
            with self.subTest(previous=previous), mock.patch.dict(os.environ, environment), \
                    mock.patch.object(cache, 'verify_attestation'), mock.patch.object(cache, 'r2', side_effect=r2), \
                    mock.patch.object(cache.time, 'time', return_value=BUILT+30):
                cache.publish(publication, proof, 'x86_64')
            self.assertEqual([method for _, method, _ in calls[:3]], ['PUT', 'PUT', 'GET'])
            self.assertEqual(len(calls), 4 if expected_pointer else 3)
            if expected_pointer:
                self.assertEqual(calls[-1][2], 'If-Match: "old"')
        self.assertEqual(json.loads((publication/'baseline.json').read_text())['built_at'], BUILT)


if __name__ == '__main__':
    unittest.main()

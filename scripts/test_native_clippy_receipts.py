"""Verify Clippy execution evidence after native build ownership is consolidated."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from test_native_readiness import NATIVE, SOURCE

PLATFORMS=('arch','debian','debian-trixie','fedora','ubuntu-2604')

class NativeClippyReceipts(unittest.TestCase):
    def sample(self,root):
        run=dict(id=123,run_attempt=1,repository={'full_name':'omg-cli/omg'},path='.github/workflows/ci.yml',
                 workflow_id=42,event='push',head_sha=SOURCE,created_at='2026-11-11T00:00:00Z',
                 run_started_at='2026-11-11T00:00:00Z',status='in_progress',conclusion=None)
        event=root/'event.json';event.write_text('{}')
        env=dict(os.environ,GITHUB_REPOSITORY='omg-cli/omg',GITHUB_SHA=SOURCE,GITHUB_RUN_ID='123',
                 GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='push',GITHUB_EVENT_PATH=str(event),
                 NATIVE_CLIPPY_OUTCOME='success')
        receipts={}
        with patch.dict(os.environ,env,clear=True),patch.object(NATIVE,'command_output',return_value=SOURCE):
            for platform in PLATFORMS:
                output=root/platform
                features=NATIVE.FEATURES.get(platform,NATIVE.FEATURES['ubuntu'])
                NATIVE.main(['clippy-record','--platform',platform,'--image','image@sha256:'+'b'*64,
                             '--features',features,'--destination',str(output)])
                receipts[platform]=json.loads((output/'native-clippy.json').read_text())
        return run,env,receipts

    def verify(self,root,run,env,receipts,mode=None):
        original_run = dict(run, status='completed', conclusion='failure')
        if mode in ('carried', 'reran-owner'):
            run = dict(run, run_attempt=2, run_started_at='2026-11-11T01:00:00Z')
            env = dict(env, GITHUB_RUN_ATTEMPT='2')
        payloads={};artifacts=[]
        for i,(platform,receipt) in enumerate(receipts.items()):
            receipt=copy.deepcopy(receipt)
            if platform=='arch':
                if mode=='failed':receipt['outcome']='failure'
                if mode=='wrong-source':receipt['source_sha']='c'*40
                if mode=='wrong-command':receipt['argv'].append('--no-deps')
                if mode=='wrong-workflow':receipt['workflow_sha256']='0'*64
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w') as archive:
                archive.writestr('native-clippy.json',json.dumps(receipt))
                if mode=='extra-member' and platform=='arch':archive.writestr('extra.json','{}')
            data=buffer.getvalue();payloads[str(10+i)]=data
            artifacts.append(dict(id=10+i,name=f'native-clippy-{platform}-1',size_in_bytes=len(data),
                                  expired=False,created_at='2026-11-11T00:01:00Z',
                                  digest='sha256:'+hashlib.sha256(data).hexdigest()))
        if mode=='bad-digest':artifacts[0]['digest']='sha256:'+'0'*64
        if mode=='missing':artifacts.pop()
        def api(path):
            if path.endswith('/actions/workflows/ci.yml'):return dict(id=42,path='.github/workflows/ci.yml')
            if path.endswith('/runs/123'):return run
            if '/artifacts?' in path:return dict(total_count=len(artifacts),artifacts=artifacts)
            if path.endswith('/attempts/1'):
                return original_run
            if '/jobs?' in path:
                current = '/attempts/2/' in path
                jobs = [dict(id=100+i, name=f'Linux ({platform})', run_id=123,
                             run_attempt=2 if current else 1, head_sha=SOURCE,
                             status='completed', conclusion='success',
                             started_at='2026-11-11T00:00:30Z', completed_at='2026-11-11T00:02:00Z')
                        for i, platform in enumerate(PLATFORMS)]
                if mode == 'reran-owner' and current:
                    jobs.append(dict(jobs[0], id=999, conclusion='failure',
                                     started_at='2026-11-11T01:00:30Z',
                                     completed_at='2026-11-11T01:02:00Z'))
                return dict(total_count=len(jobs), jobs=jobs)
            self.fail('unexpected metadata '+path)
        def download(path,*args,**kwargs):return payloads[path.split('/')[-2]]
        with patch.dict(os.environ,env,clear=True),patch.object(NATIVE,'command_output',return_value=SOURCE), \
             patch.object(NATIVE,'api_json',side_effect=api),patch.object(NATIVE,'api',side_effect=download):
            NATIVE.main(['clippy-verify','--destination',str(root/'summary')])
        return json.loads((root/'summary/native-clippy-summary.json').read_text())

    def test_record_and_verify_requires_exactly_five_successful_current_recipes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);run,env,receipts=self.sample(root)
            summary=self.verify(root,run,env,receipts)
            self.assertEqual(set(summary['platforms']),set(PLATFORMS))
            self.assertEqual(summary['source_sha'],SOURCE)
            self.assertEqual({p['receipt']['outcome'] for p in summary['platforms'].values()},{'success'})

    def test_failed_incomplete_foreign_or_modified_proof_cannot_pass(self):
        for mode in ('failed','wrong-source','wrong-command','wrong-workflow','extra-member','bad-digest','missing'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);run,env,receipts=self.sample(root)
                with self.assertRaises(ValueError):self.verify(root,run,env,receipts,mode)
                self.assertFalse((root/'summary/native-clippy-summary.json').exists())

    def test_partial_rerun_keeps_original_successful_owner_and_rejects_new_failed_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, env, receipts = self.sample(root)
            summary = self.verify(root, run, env, receipts, 'carried')
            self.assertEqual(summary['run_attempt'], 2)
            self.assertEqual({entry['producer_attempt'] for entry in summary['platforms'].values()}, {1})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, env, receipts = self.sample(root)
            with self.assertRaises(NATIVE.ArtifactUnavailable):
                self.verify(root, run, env, receipts, 'reran-owner')

    def test_manual_current_run_clippy_is_admitted_but_native_reuse_stays_automatic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, env, receipts = self.sample(root)
            run['event'] = env['GITHUB_EVENT_NAME'] = 'workflow_dispatch'
            summary = self.verify(root, run, env, receipts)
            self.assertEqual(summary['source_sha'], SOURCE)
            with patch.object(NATIVE, 'command_output', return_value=SOURCE):
                with self.assertRaisesRegex(ValueError, 'automatic source runs'):
                    NATIVE.find_native_artifact(root, 'arch', env, {})

    def test_pr_api_head_and_executed_merge_source_stay_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run, env, receipts = self.sample(root)
            run.update(event='pull_request', head_sha='c'*40, pull_requests=[dict(number=440)])
            env['GITHUB_EVENT_NAME'] = 'pull_request'
            (root/'event.json').write_text(json.dumps(dict(number=440, pull_request=dict(head=dict(sha='c'*40)))))
            summary = self.verify(root, run, env, receipts)
            self.assertEqual(summary['source_sha'], SOURCE)
            self.assertNotEqual(summary['source_sha'], run['head_sha'])

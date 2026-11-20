"""Native metadata readiness keeps current-byte admission in its consumers."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('native_readiness', Path(__file__).with_name('native-build-artifact.py'))
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
SOURCE = 'a' * 40


class NativeReadiness(unittest.TestCase):
    def state(self):
        run = dict(id=123, run_attempt=1, repository={'full_name': 'omg-cli/omg'},
                   path='.github/workflows/ci.yml', workflow_id=42, event='push', head_sha=SOURCE,
                   created_at='2026-11-11T00:00:00Z', run_started_at='2026-11-11T00:00:00Z',
                   status='in_progress', conclusion=None)
        artifacts = [dict(id=10+i, name=f'native-release-{name}-1', size_in_bytes=17,
                          expired=False, created_at='2026-11-11T00:01:00Z',
                          digest='sha256:'+'b'*64) for i,name in enumerate(NATIVE.FEATURES)]
        return run, artifacts

    def invoke(self, root, run, artifacts, *, jobs=None, artifact_reads=None, seconds=None):
        event = root/'event.json'
        event.write_text('{}')
        context = dict(os.environ, GITHUB_REPOSITORY='omg-cli/omg', GITHUB_SHA=SOURCE,
                       GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME='push',
                       GITHUB_EVENT_PATH=str(event))
        reads = []
        snapshots = iter(artifact_reads) if artifact_reads is not None else None
        def api(path):
            reads.append(path)
            if path.endswith('/actions/workflows/ci.yml'):
                return dict(id=42, path='.github/workflows/ci.yml')
            if path.endswith('/runs/123'):
                return copy.deepcopy(run)
            if '/artifacts?' in path:
                selected = next(snapshots) if snapshots is not None else artifacts
                return dict(total_count=len(selected), artifacts=copy.deepcopy(selected))
            if '/jobs?' in path:
                selected = jobs or []
                return dict(total_count=len(selected), jobs=selected)
            self.fail('unexpected API path '+path)
        output = root/'ready'
        with patch.dict(os.environ, context, clear=True), patch.object(NATIVE, 'api_json', side_effect=api), \
                patch.object(NATIVE, 'command_output', return_value=SOURCE), \
                patch.object(NATIVE.time, 'sleep') as sleep:
            if seconds is None:
                NATIVE.main(['ready','--destination',str(output),'--timeout','120'])
            else:
                with patch.object(NATIVE.time, 'monotonic', side_effect=seconds):
                    NATIVE.main(['ready','--destination',str(output),'--timeout','120'])
        return json.loads((output/'native-ready.json').read_text()), reads, sleep

    def test_current_inprogress_run_releases_all_five_without_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.state()
            receipt, reads, sleep = self.invoke(Path(tmp), run, artifacts)
            self.assertEqual(receipt['source_sha'], SOURCE)
            self.assertEqual((receipt['run_id'],receipt['run_attempt']),('123',1))
            self.assertEqual(set(receipt['artifacts']),set(NATIVE.FEATURES))
            self.assertEqual({v['id'] for v in receipt['artifacts'].values()},set(range(10,15)))
            self.assertFalse(any('/zip' in path or '/runs?' in path for path in reads))
            sleep.assert_not_called()

    def test_pending_snapshot_is_checked_again_under_one_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.state()
            receipt, _, sleep = self.invoke(Path(tmp),run,artifacts,artifact_reads=[artifacts[:-1],artifacts])
            self.assertEqual(len(receipt['artifacts']),5)
            sleep.assert_called_once()

    def test_invalid_identity_duplicate_or_expired_artifact_fails(self):
        for mutation in ('attempt','source','foreign-run','duplicate','expired'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                run, artifacts = self.state()
                if mutation=='attempt':run['run_attempt']=2
                if mutation=='source':run['head_sha']='c'*40
                if mutation=='foreign-run':run['id']=456
                if mutation=='duplicate':artifacts.append(dict(artifacts[0]))
                if mutation=='expired':artifacts[0]['expired']=True
                with self.assertRaises(ValueError):self.invoke(Path(tmp),run,artifacts)
                self.assertFalse((Path(tmp)/'ready/native-ready.json').exists())

    def test_failed_owner_without_artifact_stops_before_aggregate_can_finish(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.state()
            jobs=[dict(name='Linux ('+list(NATIVE.FEATURES)[-1]+')',status='completed',conclusion='failure',
                       run_id=123,head_sha=SOURCE)]
            with self.assertRaisesRegex(NATIVE.ArtifactUnavailable,'owner'):
                self.invoke(Path(tmp),run,artifacts[:-1],jobs=jobs)
            self.assertFalse((Path(tmp)/'ready/native-ready.json').exists())

    def test_late_success_cannot_bypass_the_common_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            run, artifacts = self.state()
            with self.assertRaisesRegex(NATIVE.ArtifactUnavailable,'deadline'):
                self.invoke(Path(tmp),run,artifacts,seconds=[0,1,121,122])
            self.assertFalse((Path(tmp)/'ready/native-ready.json').exists())

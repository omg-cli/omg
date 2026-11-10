import copy
import hashlib
from pathlib import Path
import runpy
import unittest
from courier import validate


class EvidenceChecks(unittest.TestCase):
    def test_native_receipt_requires_both_built_binary_hashes(self):
        identity = {'sourceSha': 'a' * 40, 'runId': '10', 'attempt': 1}
        image = 'sha256:' + 'b' * 64
        logs = {'stdout': b'', 'stderr': b''}
        names = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts/build-comparison.py'))['TESTS']
        report = {'accepted': True, 'sourceSha': identity['sourceSha'], 'profile': 'release',
                  'features': 'debian,pgp,license', 'binaryHashes': {'omg': 'c' * 64, 'omgd': 'd' * 64},
                  'tests': [{'name': name, 'stdout': f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;'} for name in names],
                  'inventory': {'completeNamesEqual': True, 'nativeStateUnchanged': True,
                                'beforeSha256': 'e' * 64, 'afterSha256': 'e' * 64},
                  'daemon': {'accepted': True, 'source_sha': identity['sourceSha'], 'native_candidate_count': 25000,
                             'info_requests_delta': 2, 'shutdown_returncode': 0, 'socket_absent_after_shutdown': True,
                             'native_state_unchanged': {}, 'native_state_after_shutdown': {},
                             'omg_sha256': 'c' * 64, 'omgd_sha256': 'd' * 64}}
        receipt = {'schemaVersion': 1, 'input': identity, 'mode': 'run', 'imageDigest': image,
                   'accepted': True, 'exitCode': 0, 'containerDestroyed': True, 'error': None,
                   'report': report, 'logs': {name: {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()} for name in logs}}
        validate(receipt, identity, image, 'run', logs)
        for hashes in ({}, {'omg': 'c' * 64}):
            changed = copy.deepcopy(receipt)
            changed['report']['binaryHashes'] = hashes
            with self.subTest(hashes=hashes), self.assertRaises(ValueError):
                validate(changed, identity, image, 'run', logs)

    def test_success_requires_exact_identity_logs_and_confirmed_cleanup(self):
        identity = {'sourceSha': 'a' * 40, 'runId': '10', 'attempt': 1}
        image = 'sha256:' + 'b' * 64
        logs = {'stdout': b'proof', 'stderr': b''}
        receipt = {'schemaVersion': 1, 'input': identity, 'mode': 'canary', 'imageDigest': image,
                   'accepted': True, 'exitCode': 0, 'containerDestroyed': True, 'error': None,
                   'report': {'accepted': True, 'ubuntu': '24.04', 'uid': 10001, 'gid': 10001,
                              'effectiveCapabilities': 0, 'rootWriteDenied': True},
                   'logs': {name: {'bytes': len(data),
                       'sha256': hashlib.sha256(data).hexdigest()} for name, data in logs.items()}}
        validate(receipt, identity, image, 'canary', logs)
        for key, value in [('accepted', False), ('exitCode', 1), ('containerDestroyed', False),
                           ('imageDigest', 'sha256:' + 'c' * 64), ('input', dict(identity, attempt=2))]:
            changed = copy.deepcopy(receipt)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate(changed, identity, image, 'canary', logs)
        with self.assertRaises(ValueError):
            validate(receipt, identity, image, 'canary', dict(logs, stdout=b'forged'))
        with self.assertRaises(ValueError):
            validate(dict(receipt, report={'accepted': True}), identity, image, 'canary', logs)
        for status in ('errored', 'terminated', 'failed'):
            with self.subTest(status=status), self.assertRaises(ValueError):
                validate(receipt, identity, image, 'canary', logs, status)


if __name__ == '__main__':
    unittest.main()

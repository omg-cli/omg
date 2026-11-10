"""Submit one immutable CI job and verify its private evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import time
import urllib.error
import urllib.request

LIMIT = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(evidence, identity, image, mode, logs, workflow_status='complete'):
    require(evidence.get('schemaVersion') == 1 and evidence.get('input') == identity,
            'receipt identity mismatch')
    require(evidence.get('imageDigest') == image and evidence.get('mode') == mode,
            'receipt image or recipe mismatch')
    for stream, content in logs.items():
        row = evidence['logs'][stream]
        require(row['bytes'] == len(content) and row['sha256'] == hashlib.sha256(content).hexdigest(),
                'log digest mismatch: ' + stream)
    require(evidence.get('accepted') is True and evidence.get('exitCode') == 0 and
            evidence.get('containerDestroyed') is True and evidence.get('error') is None,
            'hosted job failed or cleanup was not confirmed')
    require(workflow_status in ('complete', 'completed'), 'Workflow did not complete successfully')
    report = evidence['report']
    require(isinstance(report, dict) and report.get('accepted') is True, 'missing accepted report')
    if mode == 'canary':
        require(report.get('ubuntu') == '24.04' and report.get('uid') == report.get('gid') == 10001 and
                report.get('effectiveCapabilities') == 0 and report.get('rootWriteDenied') is True,
                'native permission canary proof is incomplete')
    else:
        require(report.get('sourceSha') == identity['sourceSha'] and report.get('profile') == 'release' and
                report.get('features') == 'debian,pgp,license', 'native recipe mismatch')
        oracle = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts/build-comparison.py'))
        require([row['name'] for row in report['tests']] == list(oracle['TESTS']), 'selected tests differ')
        for row in report['tests']:
            oracle['verify_test'](row['stdout'], row['name'])
        inventory, daemon = report['inventory'], report['daemon']
        require(inventory['completeNamesEqual'] is True and inventory['nativeStateUnchanged'] is True and
                inventory['beforeSha256'] == inventory['afterSha256'], 'native inventory was not verified')
        require(daemon['accepted'] is True and daemon['source_sha'] == identity['sourceSha'] and
                daemon['native_candidate_count'] >= 25000 and daemon['info_requests_delta'] == 2 and
                daemon['shutdown_returncode'] == 0 and daemon['socket_absent_after_shutdown'] is True and
                daemon['native_state_unchanged'] == daemon['native_state_after_shutdown'], 'daemon proof failed')
        require(set(report['binaryHashes']) == {'omg', 'omgd'}, 'both binary identities are required')
        for name, digest in report['binaryHashes'].items():
            require(re.fullmatch('[a-f0-9]{64}', digest) and daemon[name + '_sha256'] == digest,
                    'daemon binary identity mismatch')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        raise ValueError('CI endpoint redirected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('canary', 'run'), required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--image-digest', required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    require(re.fullmatch('[a-f0-9]{40}', args.source_sha), 'invalid source SHA')
    require(re.fullmatch('sha256:[a-f0-9]{64}', args.image_digest), 'invalid image digest')
    identity = {'sourceSha': args.source_sha, 'runId': os.environ['GITHUB_RUN_ID'],
                'attempt': int(os.environ['GITHUB_RUN_ATTEMPT'])}
    token = os.environ['OMG_NATIVE_CI_TOKEN']
    require(len(token) >= 32 and '\n' not in token, 'missing dedicated CI token')
    endpoint = 'https://omg-native-ci.latham.workers.dev'
    opener = urllib.request.build_opener(NoRedirect)
    def request(path, method='GET', payload=None):
        require(path.startswith('/runs') or path == '/canary', 'invalid API path')
        req = urllib.request.Request(endpoint + path, method=method,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                     'User-Agent': 'omg-ci-courier/1'})
        with opener.open(req, timeout=60) as response:
            content = response.read(LIMIT + 1)
        require(len(content) <= LIMIT, 'API response exceeds output budget')
        return content
    args.evidence_dir.mkdir(parents=True, exist_ok=False)
    job = json.loads(request('/canary' if args.mode == 'canary' else '/runs', 'POST', identity))
    require(isinstance(job.get('id'), str) and re.fullmatch('[a-zA-Z0-9_-]{1,100}', job['id']), 'invalid job ID')
    path = '/runs/' + job['id']
    (args.evidence_dir / 'submitted.json').write_text(json.dumps(job, indent=2))
    accepted = False
    try:
        deadline = time.monotonic() + (300 if args.mode == 'canary' else 2500)
        while True:
            status = json.loads(request(path))
            (args.evidence_dir / 'status.json').write_text(json.dumps(status, indent=2))
            state = status.get('status')
            print('Cloudflare CI status: ' + str(state), flush=True)
            if state in ('complete', 'completed', 'errored', 'terminated', 'failed'):
                break
            require(time.monotonic() < deadline, 'GitHub polling deadline exceeded')
            time.sleep(15)
        evidence = json.loads(request(path + '/evidence'))
        (args.evidence_dir / 'receipt.json').write_text(json.dumps(evidence, indent=2))
        logs = {}
        for stream in ('stdout', 'stderr'):
            logs[stream] = request(path + '/logs/' + stream)
            (args.evidence_dir / stream).write_bytes(logs[stream])
        validate(evidence, identity, args.image_digest, args.mode, logs, state)
        accepted = True
        print('Cloudflare CI accepted; exact-source evidence and container cleanup verified.', flush=True)
    finally:
        if not accepted:
            try:
                request(path + '/cancel', 'POST', {})
            except (OSError, ValueError) as error:
                print('Cleanup request failed; server deadline remains active: ' + str(error), flush=True)


if __name__ == '__main__':
    main()

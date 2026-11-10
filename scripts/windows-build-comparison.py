#!/usr/bin/env python3
"""Run the shared Rust comparison in an owned Windows WHPX Ubuntu guest."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import uuid

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


QEMU = module('comparison_qemu', ROOT / 'scripts/windows-qemu.py')
BENCH = module('comparison_workload', ROOT / 'scripts/build-comparison.py')


def archive_identity(archive):
    with tarfile.open(archive, 'r:') as incoming:
        files = {entry.name: hashlib.sha256(incoming.extractfile(entry).read()).hexdigest()
                 for entry in incoming.getmembers() if entry.isfile()}
    return {'archiveSha256': QEMU.digest(archive), 'sourceManifestSha256': BENCH.manifest_digest(files), 'files': files}


def validate_receipt(result, expected):
    QEMU.require(result.get('status') == 'complete', 'guest comparison did not complete')
    for key, value in expected.items():
        QEMU.require(result.get(key) == value, 'comparison identity mismatch: ' + key)
    QEMU.require(result.get('profile') == 'release' and result.get('features') == BENCH.FEATURES and
                 result.get('jobs') == 4, 'comparison build recipe mismatch')
    samples = result.get('samples', [])
    QEMU.require(len(samples) == 17 and all(row.get('exitCode') == 0 and row.get('timedOut') is False and
                 isinstance(row.get('wallSeconds'), (int, float)) and row['wallSeconds'] >= 0 and
                 isinstance(row.get('maximumProcessRssKiB'), (int, float)) and row['maximumProcessRssKiB'] > 0
                 for row in samples), 'comparison has failed or missing measurements')
    required = {'build-' + str(sample) for sample in range(4)} | {
        f'test-{sample}-{index}' for sample in range(4) for index in range(2)} | {
        name + option for name in ('omg', 'omgd') for option in ('--version', '--help')} | {'native-inventory'}
    QEMU.require({row.get('label') for row in samples} == required, 'comparison measurements are incomplete')
    tests = result.get('tests', [])
    QEMU.require(len(tests) == 8 and {(row.get('name'), row.get('sample')) for row in tests} ==
                 {(name, sample) for name in BENCH.TESTS for sample in range(4)} and
                 all(row.get('passed') == 1 and row.get('failed') == 0 and row.get('ignored') == 0 for row in tests),
                 'required named tests did not execute')
    QEMU.require(set(result.get('binaryHashes', {})) == {'omg', 'omgd'} and
                 all(re.fullmatch('[a-f0-9]{64}', value) for value in result['binaryHashes'].values()),
                 'release binary hashes missing')
    inventory = result.get('inventoryProof', {})
    QEMU.require(inventory.get('completeNamesEqual') is True and inventory.get('nativeStateUnchanged') is True and
                 type(inventory.get('nativeExplicitCount')) is int and inventory['nativeExplicitCount'] > 0,
                 'native package inventory was not verified')


def execute(args):
    QEMU.require(os.name == 'nt', 'this runner requires native Windows')
    QEMU.require(re.fullmatch('[a-f0-9]{40}', args.source_sha), 'source SHA must be a full commit ID')
    args.state = QEMU.owned(args.state, ROOT / '.git')
    args.state.mkdir(parents=True, exist_ok=True)
    QEMU.require(args.state.drive.upper() == 'C:', 'guest data must stay on C:')
    args.tools = QEMU.owned(args.tools, ROOT / '.git')
    args.image = QEMU.owned(args.image, ROOT / '.git')
    args.template = QEMU.owned(args.template, args.state)
    args.distro = 'ubuntu'
    metadata = args.template.parent / 'metadata.json' if args.template.name == 'disk.qcow2' else args.template.with_suffix('.json')
    record = json.loads(metadata.read_text(encoding='utf-8'))
    QEMU.require(record['templateSha256'] == QEMU.digest(args.template), 'sealed template digest mismatch')
    QEMU.require(record['basePath'] == str(args.image) and record['baseDigest'] == QEMU.digest(args.image),
                 'sealed template backing image mismatch')
    QEMU.require(record['provisioning']['passed'] is True and
                 record['provisioning']['compiledProjectTargets'] is False and
                 record['provisioning']['features'] == BENCH.FEATURES and
                 all(record['sanitation'].get(key) is True for key in
                     ('scheduledPoweroff', 'credentialsRemoved', 'sourceAndTargetAbsent')), 'template is not clean and sealed')
    info = json.loads(QEMU.command([args.tools / 'ucrt64/bin/qemu-img.exe', 'info', '--output=json', args.template]))
    QEMU.require(info.get('format') == 'qcow2' and
                 Path(info.get('full-backing-filename', info.get('backing-filename', ''))).resolve() == args.image.resolve(),
                 'template uses an unexpected backing chain')
    run = args.state / ('comparison-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    run.mkdir()
    archive = run / 'source.tar'
    QEMU.command(['git', '-C', ROOT, 'archive', '--format=tar', '--output=' + str(archive), args.source_sha])
    identity = archive_identity(archive)
    for name, value in record['provisioning']['cachedInputs'].items():
        QEMU.require(identity['files'].get(name) == value, 'prefetched template inputs differ: ' + name)
    script = ROOT / 'scripts/build-comparison.py'
    expected = {key: identity[key] for key in ('archiveSha256', 'sourceManifestSha256')}
    expected.update(sourceSha=args.source_sha, scriptSha256=QEMU.digest(script))
    host = {'status': 'running', 'sourceSha': args.source_sha, 'templateSha256': record['templateSha256'],
            'sourceManifestSha256': identity['sourceManifestSha256'], 'guestMemoryMiB': args.memory_mib,
            'guestCpuCount': 4, 'jobs': 4, 'expectedGuest': expected}
    guest, succeeded = QEMU.Guest(args, run, args.template, False, host), False
    try:
        entry = json.loads(QEMU.MANIFEST.read_text(encoding='utf-8'))['images']['ubuntu-x86_64']
        original = os.environ.copy()
        os.environ['PATH'] = str(args.tools / 'usr/bin') + os.pathsep + original['PATH']
        try:
            host['image'] = QEMU.IMAGES.verify(QEMU.MANIFEST, 'ubuntu-x86_64', entry['url'], entry['digest'],
                                                args.image, str(args.tools / 'usr/bin/gpgv.exe'))
        finally:
            os.environ.clear()
            os.environ.update(original)
        guest.start()
        QEMU.require(host['bootId'] != record['preparationBootId'], 'prepared boot identity was reused')
        guest.transfer(archive, '/home/bench/source.tar')
        guest.transfer(script, '/home/bench/build-comparison.py')
        options = shlex.join(['--source', '/home/bench/source', '--evidence', '/home/bench/comparison/evidence',
                              '--source-sha', args.source_sha])
        guest.shell('export PATH=/home/bench/.cargo/bin:$PATH\n'
                    'python3 /home/bench/build-comparison.py prepare ' + options + ' --archive /home/bench/source.tar\n'
                    'python3 /home/bench/build-comparison.py run ' + options + '\n', 'comparison', 18000)
        guest.transfer(run / 'guest-receipt.json', '/home/bench/comparison/evidence/receipt.json', download=True)
        result = json.loads((run / 'guest-receipt.json').read_text(encoding='utf-8'))
        validate_receipt(result, expected)
        host['guest'] = result
        succeeded = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        host['error'] = str(error)
        raise
    finally:
        try:
            if host.get('bootId') and guest.vm and guest.vm.poll() is None:
                try:
                    guest.shell('test -d /home/bench/comparison/evidence\n'
                                'tar -czf /home/bench/comparison-evidence.tar.gz -C /home/bench/comparison evidence\n',
                                'collect-comparison', 120)
                    guest.transfer(run / 'evidence.tar.gz', '/home/bench/comparison-evidence.tar.gz', download=True)
                    guest.transfer(run / 'guest-receipt.json', '/home/bench/comparison/evidence/receipt.json', download=True)
                    host['evidenceArchiveSha256'] = QEMU.digest(run / 'evidence.tar.gz')
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    guest.preserve_disk = True
                    host['collectionError'] = str(error)
                    succeeded = False
                guest.poweroff()
            QEMU.require(QEMU.digest(args.template) == record['templateSha256'] and
                         QEMU.digest(args.image) == record['baseDigest'], 'immutable guest backing changed')
        finally:
            try:
                if not host.get('evidenceArchiveSha256'):
                    guest.preserve_disk = True
                guest.close()
            finally:
                host['status'] = 'complete' if succeeded and sys.exc_info()[0] is None else 'failed'
                QEMU.write_json(run / 'receipt.json', host)
                print(json.dumps({'status': host['status'], 'receipt': str(run / 'receipt.json')}), flush=True)
    QEMU.require(host['status'] == 'complete', 'comparison evidence collection did not complete')
    return host


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', required=True, type=Path)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--template', required=True, type=Path)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--state', type=Path, default=ROOT / '.git/native-whpx-20261110/state')
    parser.add_argument('--memory-mib', type=int, choices=(4096, 6144, 8192), default=4096)
    args = parser.parse_args(argv)
    try:
        execute(args)
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Windows comparison failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

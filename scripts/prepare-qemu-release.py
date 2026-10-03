#!/usr/bin/env python3
"""Download release assets and their versioned CLI contract before guest execution."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess

REPOSITORY = 'omg-cli/omg'
HEADER = 'case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup'


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}'], timeout=60))


def prepare(tag, distro, destination):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('Invalid release tag')
    signer = ('PyRo1121/omg' if tuple(map(int, tag[1:].split('.'))) <= (0, 1, 221)
              else REPOSITORY)
    if distro not in ('arch', 'debian', 'debian-trixie', 'ubuntu', 'fedora'):
        raise ValueError('Unsupported published distro')
    revision = api(f'commits/{tag}')['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Invalid release commit')
    blob = api(f'contents/tests/cli_behavior_inventory.tsv?ref={revision}')
    if blob.get('encoding') != 'base64' or not 0 < blob.get('size', 0) <= 1048576:
        raise ValueError('Missing or oversized release inventory')
    data = base64.b64decode(''.join(blob['content'].split()), validate=True)
    if len(data) != blob['size'] or data.decode('utf-8').splitlines()[0] != HEADER:
        raise ValueError('Invalid release inventory')
    destination.mkdir(parents=True, exist_ok=True)
    archive = f'omg-{tag}-x86_64-linux-{distro}.tar.gz'
    subprocess.run(['gh', 'release', 'download', tag, '--repo', REPOSITORY,
                    '--pattern', archive, '--pattern', archive + '.sha256',
                    '--dir', str(destination)], check=True, timeout=180)
    if api(f'commits/{tag}')['sha'] != revision:
        raise ValueError('Release tag moved during download')
    # A checksum beside an archive shares its release trust boundary. Require
    # signed build provenance for the exact repository, tag, commit and workflow
    # before publishing the inventory that authorizes guest execution.
    subprocess.run([
        'gh', 'attestation', 'verify', str(destination / archive),
        '--repo', signer,
        '--source-digest', revision,
        '--source-ref', f'refs/tags/{tag}',
        '--signer-workflow', f'{signer}/.github/workflows/release.yml',
    ], check=True, timeout=180)
    (destination / 'cases.tsv').write_bytes(data)
    (destination / 'inventory-provenance.json').write_text(json.dumps({
        'artifact_tag': tag, 'inventory_revision': revision,
        'inventory_sha256': hashlib.sha256(data).hexdigest(),
        'artifact_attestation_verified': True,
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--distro', required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.tag, args.distro, args.destination)

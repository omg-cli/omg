#!/usr/bin/env python3
"""Bounded admission of a native build from an independently identified CI run.

Server artifact digests and the expected run/recipe are supplied by the caller.
An adjacent checksum or self-reported provenance alone never authorizes reuse.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile

MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
FEATURES = {'arch': 'arch,pgp,license', 'debian': 'debian,pgp,license',
            'debian-trixie': 'debian,pgp,license',
            'ubuntu': 'debian,pgp,license', 'fedora': 'fedora,pgp,license'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate provenance key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('nonfinite provenance number: ' + value)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def build_command(distro, features, environment):
    require(distro in FEATURES and features == FEATURES[distro], 'unsupported native recipe')
    flags = '-C target-cpu=x86-64-v2' if distro == 'arch' else ''
    require(not any(key.startswith('CARGO_PROFILE_RELEASE_') for key in environment),
            'release profile override cannot be reused')
    require(environment.get('RUSTFLAGS', '') in ('', flags), 'foreign compiler flags')
    for key in ('CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                'CARGO_BUILD_TARGET', 'RUSTC', 'CARGO_BUILD_RUSTC', 'CARGO_TARGET_DIR',
                'CARGO_BUILD_TARGET_DIR', 'CARGO_BUILD_RUSTFLAGS',
                'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS'):
        require(not environment.get(key), 'foreign build override: ' + key)
    env = dict(environment, RUSTFLAGS=flags, CARGO_INCREMENTAL='0')
    return ['cargo', 'build', '--timings', '--release', '--no-default-features',
            '--features', features, '--locked'], env


def command_output(argv):
    return subprocess.check_output(argv, text=True, encoding='utf-8').strip()


def build_and_package(root, distro, image, features, destination, context):
    argv, environment = build_command(distro, features, context)
    require((distro == 'ubuntu' and image == 'ubuntu-24.04') or
            re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', image), 'unpinned native build image')
    source = command_output(['git', '-C', str(root), 'rev-parse', 'HEAD'])
    require(re.fullmatch('[a-f0-9]{40}', source) and source == context['GITHUB_SHA'], 'checkout identity mismatch')
    repository = context['GITHUB_REPOSITORY']
    require(context['GITHUB_WORKFLOW_REF'].startswith(repository + '/.github/workflows/ci.yml@'),
            'native reuse producer must be CI')
    version = tomllib.loads((root / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version']
    require(isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version), 'invalid release version')
    channel = tomllib.loads((root / 'rust-toolchain.toml').read_text(encoding='utf-8'))['toolchain']['channel']
    compiler = command_output(['rustc', '-vV'])
    require(compiler.startswith('rustc ' + channel + ' ') and
            'host: x86_64-unknown-linux-gnu' in compiler.splitlines(), 'native compiler identity mismatch')
    run_attempt = int(context['GITHUB_RUN_ATTEMPT'])
    require(run_attempt > 0 and re.fullmatch('[0-9]+', context['GITHUB_RUN_ID']), 'invalid producer run')
    subprocess.run(argv, env=environment, cwd=root, check=True)
    destination.mkdir(parents=True, exist_ok=False)
    base = 'omg-v' + version + '-x86_64-linux-' + distro
    archive = destination / (base + '.tar.gz')
    binaries = {}
    with tarfile.open(archive, 'w:gz') as tar:
        for name in ('omg', 'omgd', 'README.md', 'LICENSE'):
            path = root / 'target/release' / name if name in ('omg', 'omgd') else root / name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_DOWNLOAD,
                    'missing or invalid release input')
            data = path.read_bytes()
            entry = tarfile.TarInfo(base + '/' + name)
            entry.size = len(data)
            entry.mode = 0o755 if name in ('omg', 'omgd') else 0o644
            tar.addfile(entry, io.BytesIO(data))
            if name in ('omg', 'omgd'):
                binaries[name] = sha256(data)
    require(archive.stat().st_size <= MAX_DOWNLOAD, 'native archive exceeds download limit')
    digest = sha256(archive.read_bytes())
    (destination / (archive.name + '.sha256')).write_text(digest + '  ' + archive.name + '\n', encoding='utf-8')
    provenance = {
        'schema_version': 1, 'repository': repository, 'source_sha': source,
        'run_id': context['GITHUB_RUN_ID'], 'run_attempt': run_attempt,
        'workflow_path': '.github/workflows/ci.yml', 'distro': distro, 'image': image,
        'features': sorted(features.split(',')), 'target': 'x86_64-unknown-linux-gnu',
        'profile': 'release', 'instrumentation': 'none',
        'cpu': 'x86-64-v2' if distro == 'arch' else 'generic',
        'toolchain': channel, 'compiler': compiler, 'build_argv': argv,
        'version': version, 'archive': archive.name, 'archive_sha256': digest, 'binaries': binaries,
    }
    (destination / 'native-build.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    return provenance


def validate_producer_run(run, expected):
    require(isinstance(run, dict) and type(run.get('id')) is int and run['id'] > 0
            and type(run.get('run_attempt')) is int and run['run_attempt'] > 0, 'invalid producer run identity')
    require(run.get('repository', {}).get('full_name') == expected['repository']
            and run.get('path') == '.github/workflows/ci.yml', 'foreign producer workflow')
    for key in ('workflow_id', 'event', 'head_sha'):
        require(type(run.get(key)) is type(expected[key]) and run.get(key) == expected[key],
                'producer mismatch: ' + key)
    if expected['event'] == 'pull_request':
        require(any(row.get('number') == expected['pr_number'] for row in run.get('pull_requests', [])),
                'producer belongs to a different pull request')
    waiting = run.get('status') in ('queued', 'requested', 'waiting', 'pending')
    require((waiting and run.get('run_started_at') is None) or
            (isinstance(run.get('run_started_at'), str) and
             re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', run['run_started_at'])), 'invalid producer timestamp')
    require(run.get('conclusion') not in ('cancelled', 'timed_out', 'action_required', 'stale'),
            'producer was cancelled or did not complete normally')


def api(path, limit=1024 * 1024):
    with tempfile.TemporaryFile() as output:
        subprocess.run(['gh', 'api', path], stdout=output, check=True, timeout=90)
        require(output.tell() <= limit, 'GitHub response exceeds limit')
        output.seek(0)
        return output.read(limit + 1)


def api_json(path):
    return json.loads(api(path), object_pairs_hook=unique_object, parse_constant=reject_constant)


class ArtifactUnavailable(ValueError):
    """Scheduling absence; each guest must still enforce full admission."""


def find_native_artifact(root, distro, context, event, timeout=1500):
    require(distro in FEATURES, 'unsupported native owner')
    repository = context['GITHUB_REPOSITORY']
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid repository')
    source = context['GITHUB_SHA']
    require(re.fullmatch('[a-f0-9]{40}', source), 'invalid checkout SHA')
    require(command_output(['git', '-C', str(root), 'rev-parse', 'HEAD']) == source, 'checkout identity mismatch')
    event_name = context['GITHUB_EVENT_NAME']
    require(event_name in ('push', 'pull_request'), 'reuse only applies to automatic source runs')
    head = event['pull_request']['head']['sha'] if event_name == 'pull_request' else source
    require(re.fullmatch('[a-f0-9]{40}', head), 'invalid API head SHA')
    workflow = api_json('repos/' + repository + '/actions/workflows/ci.yml')
    require(workflow.get('path') == '.github/workflows/ci.yml' and type(workflow.get('id')) is int,
            'invalid CI workflow identity')
    expected_run = dict(repository=repository, workflow_id=workflow['id'], event=event_name,
                        head_sha=head, pr_number=event.get('number'))
    started, delay, selected_id = time.monotonic(), 5, None
    while time.monotonic() - started < timeout:
        run = None
        if selected_id is None:
            listing = api_json(f'repos/{repository}/actions/workflows/ci.yml/runs?event={event_name}&head_sha={head}&per_page=20')
            candidates = listing.get('workflow_runs')
            require(isinstance(candidates, list) and len(candidates) <= 20, 'invalid CI run listing')
            for candidate in candidates:
                if event_name == 'pull_request' and not any(row.get('number') == event.get('number')
                                                            for row in candidate.get('pull_requests', [])):
                    continue
                validate_producer_run(candidate, expected_run)
                run, selected_id = candidate, candidate['id']
                print(f'Waiting for native CI artifact from run {selected_id}', flush=True)
                break
        else:
            run = api_json(f'repos/{repository}/actions/runs/{selected_id}')
            validate_producer_run(run, expected_run)
        # Aggregate scheduling status does not establish artifact availability.
        # A started attempt may already have uploaded a native lane's output
        # while another job is waiting. Keep timestamp and byte admission intact.
        if run and run.get('run_started_at') is not None:
            attempt = run['run_attempt']
            listing = api_json(f'repos/{repository}/actions/runs/{selected_id}/artifacts?per_page=100')
            require(type(listing.get('total_count')) is int and listing['total_count'] <= 100,
                    'excessive producer artifact list')
            artifacts = [row for row in listing['artifacts']
                         if row.get('name') == f'native-release-{distro}-{attempt}']
            print(f'Native artifact lookup: run={selected_id} attempt={attempt} '
                  f'status={run.get("status")} distro={distro} matches={len(artifacts)}', flush=True)
            require(len(artifacts) <= 1, 'ambiguous native artifact')
            if artifacts:
                artifact = artifacts[0]
                require(type(artifact.get('id')) is int and artifact['id'] > 0
                        and type(artifact.get('size_in_bytes')) is int
                        and 0 < artifact['size_in_bytes'] <= MAX_DOWNLOAD
                        and artifact.get('expired') is False
                        and isinstance(artifact.get('created_at'), str)
                        and artifact['created_at'] >= run['run_started_at'], 'stale or invalid native artifact')
                return artifact, run, expected_run
            if run.get('status') == 'completed':
                raise ArtifactUnavailable('CI finished without the required native artifact')
        time.sleep(delay)
        delay = min(30, delay * 1.5)
    raise ArtifactUnavailable('CI native artifact did not become available before the deadline')


def reuse(root, distro, image, features, destination, context, event, timeout=1500):
    build_command(distro, features, {})
    started = time.monotonic()
    artifact, run, expected_run = find_native_artifact(root, distro, context, event, timeout)
    repository, selected_id, attempt = expected_run['repository'], run['id'], run['run_attempt']
    expected = {
        'repository': repository, 'source_sha': context['GITHUB_SHA'], 'run_id': str(selected_id),
        'run_attempt': attempt, 'workflow_path': '.github/workflows/ci.yml',
        'distro': distro, 'image': image, 'features': sorted(features.split(',')),
        'target': 'x86_64-unknown-linux-gnu', 'profile': 'release', 'instrumentation': 'none',
        'cpu': 'x86-64-v2' if distro == 'arch' else 'generic',
        'toolchain': tomllib.loads((root / 'rust-toolchain.toml').read_text(encoding='utf-8'))['toolchain']['channel'],
        'version': tomllib.loads((root / 'Cargo.toml').read_text(encoding='utf-8'))['package']['version'],
    }
    content = api(f'repos/{repository}/actions/artifacts/{artifact["id"]}/zip', MAX_DOWNLOAD)
    provenance, files = validate_bundle(content, artifact.get('digest'), expected)
    refreshed = api_json(f'repos/{repository}/actions/runs/{selected_id}')
    validate_producer_run(refreshed, expected_run)
    require(refreshed['id'] == selected_id and refreshed['run_attempt'] == attempt,
            'producer attempt changed during download')
    destination.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (destination / name).write_bytes(data)
    (destination / 'native-build.json').write_text(json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    print(f'Verified native CI artifact {artifact["id"]}; waited {time.monotonic() - started:.1f}s', flush=True)
    return provenance


def validate_bundle(content, server_digest, expected):
    require(isinstance(content, bytes) and len(content) <= MAX_DOWNLOAD, 'artifact download exceeds limit')
    require(isinstance(server_digest, str) and server_digest == 'sha256:' + sha256(content),
            'GitHub artifact digest missing or mismatched')
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            require(len(members) == 3 and len({item.filename for item in members}) == 3,
                    'duplicate or extra artifact members')
            require(sum(item.file_size for item in members) <= MAX_EXPANDED, 'artifact expansion exceeds limit')
            for item in members:
                mode = item.external_attr >> 16
                require(not item.is_dir() and not stat.S_ISLNK(mode) and not item.flag_bits & 1
                        and '/' not in item.filename and '\\' not in item.filename
                        and item.file_size <= MAX_DOWNLOAD, 'unsafe artifact member')
            manifest = archive.getinfo('native-build.json')
            require(manifest.file_size <= 65536, 'oversized build provenance')
            provenance = json.loads(archive.read(manifest), object_pairs_hook=unique_object,
                                    parse_constant=reject_constant)
            require(isinstance(provenance, dict) and type(provenance.get('schema_version')) is int
                    and provenance['schema_version'] == 1, 'invalid build provenance schema')
            for field, value in expected.items():
                actual = provenance.get(field)
                if field == 'features':
                    require(isinstance(actual, list) and all(isinstance(item, str) for item in actual)
                            and len(actual) == len(set(actual)) and set(actual) == set(value),
                            'build feature mismatch')
                else:
                    require(type(actual) is type(value) and actual == value, 'build identity mismatch: ' + field)
            require(isinstance(provenance.get('distro'), str) and provenance['distro'] in FEATURES,
                    'invalid distro')
            compiler = provenance.get('compiler')
            require(isinstance(compiler, str) and isinstance(provenance.get('toolchain'), str)
                    and compiler.startswith('rustc ' + provenance['toolchain'] + ' ')
                    and 'host: x86_64-unknown-linux-gnu' in compiler.splitlines(),
                    'recorded compiler does not match native recipe')
            argv, _ = build_command(provenance['distro'], FEATURES[provenance['distro']], {})
            require(provenance.get('build_argv') == argv, 'recorded build invocation mismatch')
            version = provenance.get('version')
            require(isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version), 'invalid version')
            base = 'omg-v' + version + '-x86_64-linux-' + provenance['distro']
            name = base + '.tar.gz'
            require(provenance.get('archive') == name, 'foreign archive name')
            require({item.filename for item in members} == {'native-build.json', name, name + '.sha256'},
                    'unexpected artifact content')
            payload = archive.read(name)
            require(provenance.get('archive_sha256') == sha256(payload), 'archive checksum mismatch')
            checksum = archive.getinfo(name + '.sha256')
            require(checksum.file_size <= 1024, 'oversized checksum')
            checksum_bytes = archive.read(checksum)
            require(checksum_bytes == (sha256(payload) + '  ' + name + '\n').encode(), 'invalid adjacent checksum')
            binaries = provenance.get('binaries')
            require(isinstance(binaries, dict) and set(binaries) == {'omg', 'omgd'}
                    and all(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value)
                            for value in binaries.values()), 'invalid binary pair identity')
            seen, expanded = set(), 0
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r|gz') as tar:
                for index, item in enumerate(tar):
                    require(index < 5 and item.name not in seen, 'duplicate or excessive tar members')
                    seen.add(item.name)
                    if item.isdir():
                        require(item.name.rstrip('/') == base, 'foreign tar directory')
                        continue
                    expected_files = {base + '/' + leaf for leaf in ('omg', 'omgd', 'README.md', 'LICENSE')}
                    require(item.name in expected_files and item.isreg() and not item.issparse()
                            and not item.mode & 0o6000, 'unsafe release archive member')
                    expanded += item.size
                    require(0 <= item.size <= MAX_DOWNLOAD and expanded <= MAX_EXPANDED, 'release expansion exceeds limit')
                    leaf = item.name.split('/')[-1]
                    stream = tar.extractfile(item)
                    require(stream is not None, 'missing release member')
                    digest = hashlib.sha256()
                    with stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(block)
                    if leaf in binaries:
                        require(item.mode & 0o111 and digest.hexdigest() == binaries[leaf], 'binary digest or mode mismatch')
                require({base + '/' + leaf for leaf in ('omg', 'omgd', 'README.md', 'LICENSE')} <= seen,
                        'incomplete release archive')
            return provenance, {name: payload, name + '.sha256': checksum_bytes}
    except (KeyError, UnicodeError, json.JSONDecodeError, tarfile.TarError, zipfile.BadZipFile) as error:
        raise ValueError('invalid native build archive') from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('build', 'reuse'))
    parser.add_argument('--distro', choices=tuple(FEATURES))
    parser.add_argument('--image')
    parser.add_argument('--features')
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--timeout', type=int, default=1500)
    args = parser.parse_args(argv)
    require(1 <= args.timeout <= 1500, 'invalid native wait deadline')
    if not all((args.distro, args.image, args.features, args.destination)):
        parser.error('build/reuse require --distro, --image, --features and --destination')
    parameters = (Path.cwd(), args.distro, args.image, args.features,
                  args.destination, dict(os.environ))
    if args.mode == 'build':
        build_and_package(*parameters)
    else:
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
        reuse(*parameters, event, timeout=args.timeout)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print('Native build admission failed: ' + str(error), file=sys.stderr)
        sys.exit(1)

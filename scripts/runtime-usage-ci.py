#!/usr/bin/env python3
"""Admit this CI attempt's Ubuntu binary and run private runtime accounting."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import tomllib

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('native_build_artifact', ROOT / 'scripts/native-build-artifact.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
require = native.require


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def identity(context):
    repository = context['GITHUB_REPOSITORY']
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid repository')
    require(re.fullmatch(r'[a-f0-9]{40}', context['GITHUB_SHA']), 'invalid source identity')
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        require(re.fullmatch(r'[1-9][0-9]*', context[key]), 'invalid run identity')
    event_name = context['GITHUB_EVENT_NAME']
    require(event_name in ('push', 'pull_request', 'workflow_dispatch', 'merge_group'),
            'unsupported CI event')
    event_path = Path(context['GITHUB_EVENT_PATH'])
    require(event_path.is_file() and event_path.stat().st_size <= 8 * 1024 * 1024,
            'missing or excessive trusted event payload')
    event = json.loads(event_path.read_text())
    require(event.get('repository', {}).get('full_name') == repository, 'foreign event repository')
    result = dict(repository=repository, source=context['GITHUB_SHA'], event=event_name,
                  api_head=context['GITHUB_SHA'], run=int(context['GITHUB_RUN_ID']),
                  attempt=int(context['GITHUB_RUN_ATTEMPT']))
    if event_name == 'pull_request':
        number = event.get('number')
        require(type(number) is int and number > 0
                and context['GITHUB_REF'] == f'refs/pull/{number}/merge', 'foreign PR merge ref')
        pr = event['pull_request']
        head, base = pr['head'], pr['base']
        require(base['repo']['full_name'] == repository, 'foreign PR base repository')
        for side in (head, base):
            require(re.fullmatch('[a-f0-9]{40}', side['sha'])
                    and isinstance(side['ref'], str) and 0 < len(side['ref']) <= 256
                    and type(side['repo']['id']) is int and side['repo']['id'] > 0,
                    'invalid PR source identity')
        result.update(api_head=head['sha'], pr=dict(number=number, head_sha=head['sha'],
                      base_sha=base['sha'], head_ref=head['ref'], base_ref=base['ref'],
                      head_repository_id=head['repo']['id'], base_repository_id=base['repo']['id']))
    elif event_name == 'push':
        require(event.get('after') == result['source'], 'push event source mismatch')
    elif event_name == 'merge_group':
        require(event.get('merge_group', {}).get('head_sha') == result['source']
                and event['merge_group'].get('head_ref') == context['GITHUB_REF'],
                'merge-group source mismatch')
    return result


def initialize(state, context):
    require(os.getuid() == os.geteuid() and os.getuid() != 0, 'requires an ordinary user')
    parent = Path(context['RUNNER_TEMP']).resolve(strict=True)
    expected = 'runtime-usage-' + context['GITHUB_RUN_ID'] + '-' + context['GITHUB_RUN_ATTEMPT']
    require(state.is_absolute() and state.parent == parent and state.name == expected,
            'state must be the exact current-run private directory')
    require(parent.stat().st_uid == os.getuid(), 'foreign state parent')
    state.mkdir(mode=0o700, exist_ok=False)
    for name in ('bin', 'home', 'tmp', 'evidence'):
        (state / name).mkdir(mode=0o700)
    value = dict(identity(context), uid=os.getuid(), path=str(state), inode=state.stat().st_ino)
    write_json(state / 'ownership.json', value)


def checked_state(state, context):
    require(state.is_absolute() and not state.is_symlink() and state.resolve(strict=True) == state,
            'redirected state directory')
    info = state.stat()
    require(os.getuid() == os.geteuid() != 0 and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'state must remain private and owned')
    marker = state / 'ownership.json'
    require(marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == os.getuid(),
            'missing owned state marker')
    value = json.loads(marker.read_text())
    expected = dict(identity(context), uid=os.getuid(), path=str(state), inode=info.st_ino)
    require(value == expected, 'state identity changed')
    require(state.parent == Path(context['RUNNER_TEMP']).resolve(strict=True)
            and state.name == 'runtime-usage-' + str(value['run']) + '-' + str(value['attempt']),
            'state escaped the current-run directory')
    for name in ('bin', 'home', 'tmp', 'evidence'):
        child = state / name
        require(child.is_dir() and not child.is_symlink() and child.resolve() == child
                and child.stat().st_uid == os.getuid()
                and stat.S_IMODE(child.stat().st_mode) == 0o700, 'redirected or foreign state child')
    return value


def validate_run(run, expected):
    require(type(run.get('id')) is int and run['id'] == expected['run']
            and type(run.get('run_attempt')) is int and run['run_attempt'] == expected['attempt'],
            'foreign or superseded run attempt')
    require(run.get('repository', {}).get('full_name') == expected['repository']
            and run.get('path') == '.github/workflows/ci.yml'
            and run.get('head_sha') == expected['api_head']
            and run.get('event') == expected['event'], 'foreign producer source, event or workflow')
    require(run.get('status') in ('queued', 'in_progress', 'completed')
            and run.get('conclusion') in (None, 'success'), 'producer run did not complete normally')
    if expected['event'] == 'pull_request':
        pr = expected['pr']
        rows = [row for row in run.get('pull_requests', []) if row.get('number') == pr['number']]
        require(len(rows) == 1, 'producer belongs to another PR')
        # Association SHAs follow live branch updates; the triggering event,
        # immutable run head and exact tested merge parents bind source bytes.
        for side in ('head', 'base'):
            actual = rows[0].get(side, {})
            require(actual.get('ref') == pr[side + '_ref']
                    and actual.get('repo', {}).get('id') == pr[side + '_repository_id'],
                    'producer PR ' + side + ' association changed')


def validate_commit(commit, expected, checkout_tree):
    require(commit.get('sha') == expected['source']
            and re.fullmatch('[a-f0-9]{40}', checkout_tree)
            and commit.get('tree', {}).get('sha') == checkout_tree, 'consumer commit tree mismatch')
    if expected['event'] == 'pull_request':
        require([parent.get('sha') for parent in commit.get('parents', [])]
                == [expected['pr']['base_sha'], expected['pr']['head_sha']],
                'tested merge does not link the exact PR base and head')


def select_artifact(artifacts, jobs, expected):
    owners = [job for job in jobs if job.get('name') == 'Linux (ubuntu)']
    require(len(owners) == 1 and owners[0].get('status') == 'completed'
            and owners[0].get('conclusion') == 'success'
            and owners[0].get('head_sha') == expected['api_head']
            and owners[0].get('run_id') == expected['run']
            and owners[0].get('run_attempt') == expected['attempt'], 'Ubuntu producer did not succeed')
    name = 'native-release-ubuntu-' + str(expected['attempt'])
    selected = [artifact for artifact in artifacts if artifact.get('name') == name]
    require(len(selected) == 1, 'missing or ambiguous current-attempt Ubuntu artifact')
    artifact = selected[0]
    require(artifact.get('expired') is False and type(artifact.get('id')) is int and artifact['id'] > 0,
            'expired or invalid artifact')
    require(type(artifact.get('size_in_bytes')) is int
            and 0 < artifact['size_in_bytes'] <= native.MAX_DOWNLOAD, 'artifact size outside bound')
    owner = artifact.get('workflow_run', {})
    require(owner.get('id') == expected['run'] and owner.get('head_sha') == expected['api_head'],
            'artifact belongs to another run or source')
    return artifact


def fetch_pages(path, key):
    result = []
    for page in range(1, 11):
        response = native.api_json(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
        rows = response.get(key)
        require(isinstance(rows, list) and len(rows) <= 100, 'invalid API page')
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise ValueError('API pagination exceeds bound')


def admit(state, context):
    expected = checked_state(state, context)
    require(native.command_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']) == expected['source'],
            'consumer checkout source mismatch')
    path = 'repos/' + expected['repository'] + '/actions/runs/' + str(expected['run'])
    run = native.api_json(path)
    validate_run(run, expected)
    commit = native.api_json('repos/' + expected['repository'] + '/git/commits/' + expected['source'])
    checkout_tree = native.command_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD^{tree}'])
    # Retain public source facts before refusal, not the event payload or env.
    source_identity = {key: expected[key] for key in
                       ('repository', 'source', 'api_head', 'event', 'run', 'attempt')}
    if expected['event'] == 'pull_request':
        source_identity['pr'] = expected['pr']
    write_json(state / 'evidence/source-identity.json',
               dict(expected=source_identity, checkout_tree=checkout_tree,
                    observed=dict(source=commit.get('sha'), tree=commit.get('tree', {}).get('sha'),
                                  parents=[parent.get('sha') for parent in commit.get('parents', [])])))
    validate_commit(commit, expected, checkout_tree)
    jobs = fetch_pages(path + '/attempts/' + str(expected['attempt']) + '/jobs', 'jobs')
    artifacts = fetch_pages(path + '/artifacts', 'artifacts')
    artifact = select_artifact(artifacts, jobs, expected)
    recipe = dict(repository=expected['repository'], source_sha=expected['source'],
                  run_id=str(expected['run']), run_attempt=expected['attempt'],
                  workflow_path='.github/workflows/ci.yml', distro='ubuntu', image='ubuntu-24.04',
                  features=['debian', 'license', 'pgp'], target='x86_64-unknown-linux-gnu',
                  profile='release', instrumentation='none', cpu='generic',
                  toolchain=tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())['toolchain']['channel'],
                  version=tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version'])
    content = native.download_artifact('repos/' + expected['repository']
                                       + '/actions/artifacts/' + str(artifact['id']) + '/zip')
    provenance, files = native.validate_bundle(content, artifact.get('digest'), recipe)
    refreshed = native.api_json(path)
    validate_run(refreshed, expected)
    payload = files[provenance['archive']]
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
        for name in ('omg', 'omgd'):
            member = provenance['archive'].removesuffix('.tar.gz') + '/' + name
            stream = archive.extractfile(member)
            require(stream is not None, 'missing admitted binary')
            with stream:
                data = stream.read(native.MAX_DOWNLOAD + 1)
            require(len(data) <= native.MAX_DOWNLOAD
                    and native.sha256(data) == provenance['binaries'][name], 'binary identity changed')
            destination = state / 'bin' / name
            with destination.open('xb') as output:
                output.write(data)
            destination.chmod(0o700)
    write_json(state / 'evidence/admission.json', dict(artifact=artifact, producer=run,
               refreshedProducer=refreshed, expected=recipe, provenance=provenance,
               apiZIP_SHA256=native.sha256(content), sourceCommit=commit, checkoutTree=checkout_tree))


def product_environment(state):
    return dict(PATH='/usr/bin:/bin', HOME=str(state / 'home'), TMPDIR=str(state / 'tmp'),
                LANG='C.UTF-8', LC_ALL='C.UTF-8')


def collect(state):
    homes = list((state / 'home').glob('omg-runtime-usage.*'))
    require(len(homes) <= 1, 'ambiguous runtime evidence')
    if not homes:
        return {}
    home = homes[0]
    require(not home.is_symlink() and home.resolve().parent == (state / 'home').resolve()
            and home.stat().st_uid == os.getuid(), 'foreign runtime evidence')
    counters = {}
    for mode in ('0', '1'):
        output = state / 'evidence' / mode
        output.mkdir(mode=0o700, exist_ok=True)
        for name in ('use-1.stdout', 'use-1.stderr', 'use-2.stdout', 'use-2.stderr'):
            source = home / mode / name
            if source.exists():
                require(source.is_file() and not source.is_symlink(), 'unsafe command evidence')
                shutil.copyfile(source, output / name)
        usage = home / mode / 'data/usage.json'
        if usage.exists():
            require(usage.is_file() and not usage.is_symlink(), 'unsafe usage evidence')
            counters[mode] = json.loads(usage.read_text())
            shutil.copyfile(usage, output / 'usage.json')
            counters[mode]['dataDirectoryMode'] = stat.S_IMODE(usage.parent.stat().st_mode)
            node = home / mode / 'data/versions/node/current/bin/node'
            if node.exists():
                counters[mode]['installedNodeSHA256'] = digest(node)
    return counters


def run(state, context):
    owner = checked_state(state, context)
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release['ID'].strip('"') == 'ubuntu' and release['VERSION_ID'].strip('"') == '24.04',
            'requires ordinary Ubuntu 24.04')
    admission = json.loads((state / 'evidence/admission.json').read_text())
    validate_run(admission['refreshedProducer'], owner)
    require(admission['provenance']['source_sha'] == owner['source']
            and admission['provenance']['run_id'] == str(owner['run'])
            and admission['provenance']['run_attempt'] == owner['attempt'],
            'recorded artifact is not this run attempt')
    binary = state / 'bin/omg'
    expected = admission['provenance']['binaries']['omg']
    require(binary.is_file() and not binary.is_symlink() and binary.stat().st_uid == os.getuid()
            and stat.S_IMODE(binary.stat().st_mode) == 0o700 and digest(binary) == expected,
            'admitted binary changed')
    script = ROOT / 'scripts/test-runtime-usage.sh'
    before = digest(script)
    environment = product_environment(state)
    start = time.monotonic()
    result = dict(actualUID=os.getuid(), osRelease=release, environment=environment,
                  CLI_SHA256_before=expected, scriptSHA256_before=before, runBoundSeconds=770)
    try:
        linkage = subprocess.run(['ldd', str(binary)], env=environment, capture_output=True, text=True, timeout=10)
        (state / 'evidence/linkage.stdout').write_text(linkage.stdout)
        (state / 'evidence/linkage.stderr').write_text(linkage.stderr)
        require(linkage.returncode == 0 and 'not found' not in linkage.stdout
                and 'libapt-pkg.so.6.0' in linkage.stdout, 'native linkage admission failed')
        with (state / 'evidence/script.stdout').open('wb') as out, (state / 'evidence/script.stderr').open('wb') as err:
            process = subprocess.Popen(['bash', str(script), str(binary)], env=environment,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            try:
                result['exit'] = process.wait(timeout=770)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                raise TimeoutError('runtime accounting process group exceeded 770 seconds')
        require(result['exit'] == 0, 'runtime accounting regression failed')
        output = (state / 'evidence/script.stdout').read_text()
        for mode in ('0', '1'):
            require(output.count('PASS: fresh runtime usage with telemetry=' + mode) == 1,
                    'missing positive telemetry-mode receipt')
        result['verdict'] = 'PASS'
    finally:
        result['telemetryCounters'] = collect(state)
        result.update(CLI_SHA256_after=digest(binary), scriptSHA256_after=digest(script),
                      elapsedSeconds=time.monotonic() - start)
        write_json(state / 'evidence/result.json', result)
        require(result['CLI_SHA256_after'] == expected and result['scriptSHA256_after'] == before,
                'regression inputs changed during execution')


def cleanup(state, context):
    checked_state(state, context)
    shutil.rmtree(state)
    require(not state.exists() and not state.is_symlink(), 'owned state cleanup failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'admit', 'run', 'cleanup'))
    parser.add_argument('--state', required=True, type=Path)
    args = parser.parse_args()
    try:
        {'init': initialize, 'admit': admit, 'run': run, 'cleanup': cleanup}[args.command](args.state, os.environ)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if args.command not in ('init', 'cleanup'):
            checked_state(args.state, os.environ)
            write_json(args.state / 'evidence' / (args.command + '-failure.json'),
                       dict(errorType=type(error).__name__, error=str(error)))
        raise


if __name__ == '__main__':
    main()

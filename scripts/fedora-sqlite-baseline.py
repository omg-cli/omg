#!/usr/bin/env python3
"""Reuse and publish the bounded, attested Fedora SQLite dependency baseline."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SQLITE = runpy.run_path(str(ROOT/'scripts/fedora-sqlite.py'))
NATIVE = runpy.run_path(str(ROOT/'scripts/native-build-artifact.py'))
ORIGIN = 'https://omg-ci-artifacts.latham.workers.dev'
PREFIX = 'dependencies/sqlite-v1/'
WORKFLOW = 'omg-cli/omg/.github/workflows/fedora-sqlite-publish.yml'
LIMIT = 160 * 1024 * 1024
RECIPE_FILES = ('scripts/fedora-sqlite.py', 'scripts/fedora-sqlite-baseline.py',
    '.github/workflows/fedora-sqlite.yml', '.github/workflows/fedora-sqlite-publish.yml',
    'scripts/native-build-artifact.py',
    'tests/qemu-image-provenance/fedora-sqlite.json',
    'tests/qemu-image-provenance/fedora.gpg',
    'tests/qemu-image-provenance/sqlite-3.51.2-wal-reset.patch')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def output_limit(limit):
    if os.name != 'posix':
        return {}
    import resource
    return {'preexec_fn': lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))}


def recipe(arch):
    require(arch in ('x86_64', 'aarch64'), 'unsupported baseline architecture')
    return sha(canonical({'architecture': arch,
        'files': {name: SQLITE['digest'](ROOT/name) for name in RECIPE_FILES}}))


def bounded_output(arguments, limit, timeout=20):
    with tempfile.TemporaryFile() as output:
        subprocess.run(arguments, check=True, stdout=output, timeout=timeout,
            env=dict(os.environ, LANG='C.UTF-8', TZ='UTC'), **output_limit(limit))
        output.seek(0)
        data = output.read(limit+1)
    require(0 < len(data) <= limit, 'native metadata output exceeds bound')
    return data


def package_inventory(raw):
    rows = []
    for line in raw.decode().splitlines():
        fields = line.split('\t')
        require(len(fields) == 9, 'invalid installed RPM header inventory')
        name, evr, arch, header, modern_signer, old_signer, modern, old, signed_digest = fields
        require(re.fullmatch('(?:[a-fA-F0-9]{2}){17,}', header), 'missing original immutable RPM header')
        header_bytes = bytes.fromhex(header)
        signers = sorted(set(re.findall(r'key id ([a-f0-9]{8,40})', modern_signer+'|'+old_signer, re.I)))
        if name != 'gpg-pubkey':
            require(re.fullmatch('[a-f0-9]{64}', signed_digest) and signed_digest in
                    (sha(header_bytes), sha(b'\x8e\xad\xe8\x01\0\0\0\0'+header_bytes)),
                    'installed immutable RPM image does not match signed header digest')
            require(signers and (modern != '(none)' or old != '(none)'),
                    'installed dependency lacks recorded package signature')
        rows.append({'name': name, 'evr': evr, 'arch': arch,
                     'immutable_header_sha256': sha(header_bytes), 'signed_header_sha256': signed_digest,
                     'signature_sha256': sha((modern+'|'+old).encode()),
                     'signers': [value.lower() for value in signers]})
    rows.sort(key=lambda row: (row['name'], row['evr'], row['arch']))
    require(rows and len({(row['name'], row['evr'], row['arch']) for row in rows}) == len(rows),
            'duplicate installed RPM identity')
    return rows


def inventory(diagnostics=None):
    query = ('%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{HEADERIMMUTABLE}\t'
             '[%{OPENPGP:pgpsig};]\t%{RSAHEADER:pgpsig}\t[%{OPENPGP}]\t%{RSAHEADER}\t%{SHA256HEADER}\n')
    raw = bounded_output(['rpm', '-qa', '--qf', query], LIMIT)
    if diagnostics is not None:
        sample = []
        for line in raw.decode().splitlines()[:3]:
            values = line.split('\t')
            sample.append(dict(fields=len(values), package=values[0][:80],
                header_hex_length=len(values[3]) if len(values) > 3 else 0,
                signed_header_sha256=values[8][:64] if len(values) > 8 else None))
        (diagnostics/'inventory-probe.json').write_bytes(canonical(sample))
    rows = package_inventory(raw)
    repositories = [Path('/etc/dnf/dnf.conf'), *sorted(Path('/etc/yum.repos.d').glob('*.repo'))]
    require(len(repositories) > 1, 'authenticated repository configuration is missing')
    paths = bounded_output(['rpm', '-qa', '--qf', '[%{FILENAMES}\n]'], LIMIT).decode().splitlines()
    abi = {}
    for name in sorted(set(paths)):
        path = Path(name)
        if '.so' not in path.name or not name.startswith(('/usr/lib/', '/usr/lib64/')):
            continue
        require(path.exists(), 'installed runtime ABI file is missing')
        target = path.resolve()
        require(str(target).startswith(('/usr/lib/', '/usr/lib64/')), 'foreign runtime ABI target')
        if target.is_file():
            abi[name] = SQLITE['digest'](target)
    require(abi, 'runtime ABI inventory is empty')
    result = dict(schema_version=1, packages=rows,
                  repositories={str(path): SQLITE['digest'](path) for path in repositories}, abi=abi)
    require(len(canonical(result)) <= 4*1024*1024, 'installed inventory exceeds metadata bound')
    return result


def fresh(metadata, now=None):
    now = time.time() if now is None else now
    require(type(metadata.get('built_at')) is int and 0 <= now-metadata['built_at'] <= 86400,
            'actual SQLite build is expired or in the future')


def prefix(arch, recipe_sha, inventory_sha):
    require(arch in ('x86_64', 'aarch64') and
            all(re.fullmatch('[a-f0-9]{64}', value) for value in (recipe_sha, inventory_sha)),
            'invalid baseline object identity')
    return PREFIX+arch+'/'+recipe_sha+'/'+inventory_sha+'/'


def fetch(key, output, limit):
    require(valid_key(key), 'foreign baseline object')
    subprocess.run(['curl', '--fail', '--silent', '--show-error', '--proto', '=https',
                    '--connect-timeout', '10', '--max-time', '30', '--max-filesize', str(limit),
                    '--output', str(output), ORIGIN+'/'+key], check=True, timeout=35)
    require(not output.is_symlink() and 0 < output.stat().st_size <= limit, 'oversized baseline response')


def verify_attestation(archive, proof, metadata, output):
    source = metadata.get('source_sha', '')
    require(re.fullmatch('[a-f0-9]{40}', source), 'invalid baseline build source')
    with output.open('wb') as stream, output.with_suffix('.stderr').open('wb') as errors:
        subprocess.run(['gh', 'attestation', 'verify', str(archive), '--bundle', str(proof),
            '--repo', 'omg-cli/omg', '--source-ref', 'refs/heads/main', '--source-digest', source,
            '--signer-digest', source, '--signer-workflow', WORKFLOW,
            '--deny-self-hosted-runners', '--format', 'json'],
            check=True, stdout=stream, stderr=errors, timeout=90, **output_limit(1024*1024))
    require(output.stat().st_size <= 1024*1024, 'oversized attestation verification result')
    verified = json.loads(output.read_text(), object_pairs_hook=SQLITE['unique'])
    require(isinstance(verified, list) and len(verified) == 1, 'ambiguous baseline attestation')
    result = verified[0]['verificationResult']
    certificate = result['signature']['certificate']
    expected = {
        'issuer': 'https://token.actions.githubusercontent.com',
        'sourceRepositoryURI': 'https://github.com/omg-cli/omg',
        'sourceRepositoryIdentifier': '1133413326',
        'sourceRepositoryOwnerIdentifier': '329545359',
        'sourceRepositoryRef': 'refs/heads/main', 'sourceRepositoryDigest': source,
        'buildSignerURI': 'https://github.com/'+WORKFLOW+'@refs/heads/main',
        'buildSignerDigest': source, 'runnerEnvironment': 'github-hosted',
        'runInvocationURI': 'https://github.com/omg-cli/omg/actions/runs/'+metadata['run_id']+
                            '/attempts/'+str(metadata['run_attempt'])}
    require(all(certificate.get(key) == value for key, value in expected.items()),
            'baseline verified certificate identity differs')
    timestamps = result['verifiedTimestamps']
    require(isinstance(timestamps, list) and timestamps
            and all(isinstance(row, dict) and row.get('type') == 'Tlog' for row in timestamps),
            'missing trusted transparency-log time')
    signing_times = [datetime.datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00')).timestamp() for row in timestamps]
    require(all(metadata['built_at'] <= value <= time.time() for value in signing_times),
            'baseline build time exceeds trusted signing time')
    statement = result['statement']
    require(statement.get('predicateType') == 'https://slsa.dev/provenance/v1' and
            statement.get('subject') == [{'name': 'sqlite-baseline.tar',
                'digest': {'sha256': SQLITE['digest'](archive)}}], 'attested archive subject differs')
    return int(min(signing_times))


def unpack(archive, destination, policy, arch):
    names = set(SQLITE['package_names'](policy, arch)) | {
        'manifest.json', 'rpmbuild.log', 'test-details.txt', 'packages.tsv', 'source-signature.txt'}
    allowed = {'bundle/'+name for name in names} | {'baseline.json', 'inventory.json'}
    with tarfile.open(archive, 'r:') as bundle:
        seen, total = set(), 0
        for member in bundle:
            require(member.name in allowed and member.name not in seen,
                    'baseline archive file set rejected')
            seen.add(member.name)
            total += member.size
            require(member.isfile() and not member.issparse() and 0 < member.size <= LIMIT and total <= LIMIT,
                    'linked or oversized baseline member')
            path = destination/member.name
            path.parent.mkdir(parents=True, exist_ok=True)
            content = bundle.extractfile(member).read(member.size+1)
            require(len(content) == member.size, 'truncated baseline member')
            path.write_bytes(content)
        require(seen == allowed, 'baseline archive is incomplete')
    return SQLITE['document'](destination/'baseline.json')


def restore(destination, policy, arch, revision, installed, diagnostics):
    identity = {'run_id': os.environ.get('GITHUB_RUN_ID'),
                'run_attempt': int(os.environ.get('GITHUB_RUN_ATTEMPT', '0'))}
    require(re.fullmatch('[1-9][0-9]{0,19}', identity['run_id'] or '') and identity['run_attempt'] > 0,
            'reuse requires current GitHub consumer identity')
    recipe_sha, inventory_sha = recipe(arch), sha(canonical(installed))
    key = prefix(arch, recipe_sha, inventory_sha)
    work = diagnostics/'cache'
    work.mkdir()
    fetch(key+'latest.json', work/'pointer.json', 65536)
    pointer = SQLITE['document'](work/'pointer.json')
    for field in ('archive_sha256', 'proof_sha256'):
        require(re.fullmatch('[a-f0-9]{64}', pointer.get(field, '')), 'invalid pointer digest')
    archive, proof = work/'sqlite-baseline.tar', work/'proof.json'
    fetch(key+pointer['archive_sha256']+'.tar', archive, LIMIT)
    fetch(key+pointer['archive_sha256']+'.sigstore.json', proof, 1024*1024)
    require(SQLITE['digest'](archive) == pointer['archive_sha256'] and
            SQLITE['digest'](proof) == pointer['proof_sha256'], 'baseline transport digest differs')
    with tempfile.TemporaryDirectory(prefix='sqlite-admitted-', dir=destination.parent) as temporary:
        stage = Path(temporary)
        metadata = unpack(archive, stage, policy, arch)
        fresh(metadata)
        require(type(metadata.get('schema_version')) is int and metadata['schema_version'] == 1
                and metadata.get('architecture') == arch
                and metadata.get('recipe_sha256') == recipe_sha
                and metadata.get('inventory_sha256') == inventory_sha
                and SQLITE['digest'](stage/'inventory.json') == inventory_sha,
                'baseline recipe or actual dependency inventory differs')
        require(pointer.get('generation') == [metadata['built_at'], int(metadata['run_id']), metadata['run_attempt']],
                'baseline pointer generation differs')
        signed_at = verify_attestation(archive, proof, metadata, work/'verification.json')
        manifest = SQLITE['verify_bundle'](stage/'bundle', policy, arch, metadata['source_sha'])
        require(metadata.get('manifest_sha256') == SQLITE['digest'](stage/'bundle/manifest.json'),
                'baseline original manifest digest differs')
        admission = dict(schema_version=1, consumer_sha=revision,
            consumer_run_id=identity['run_id'], consumer_run_attempt=identity['run_attempt'],
            build_run_id=metadata['run_id'], build_run_attempt=metadata['run_attempt'],
            build_source_sha=manifest['source_sha'], manifest_sha256=metadata['manifest_sha256'],
            packages_sha256=manifest['files']['packages.tsv'], recipe_sha256=recipe_sha,
            inventory_sha256=inventory_sha, archive_sha256=pointer['archive_sha256'],
            proof_sha256=pointer['proof_sha256'], built_at=metadata['built_at'],
            verified_tlog_at=signed_at, disposition='cache-hit')
        shutil.copyfile(archive, stage/'bundle/baseline.tar')
        shutil.copyfile(proof, stage/'bundle/baseline.sigstore.json')
        (stage/'bundle/admission.json').write_bytes(canonical(admission))
        identity['admission_sha256'] = SQLITE['digest'](stage/'bundle/admission.json')
        SQLITE['verify_bundle'](stage/'bundle', policy, arch, revision, identity)
        require(not list(destination.iterdir()), 'reuse destination is not empty')
        destination.rmdir()
        try:
            (stage/'bundle').rename(destination)
        except OSError:
            destination.mkdir(exist_ok=True)
            raise
    return True


def carried_owner(admission, arch, context):
    repository = 'omg-cli/omg'
    run_id, attempt = context['run_id'], context['run_attempt']
    origin = admission.get('supply_run_attempt', admission['consumer_run_attempt'])
    require(admission['consumer_run_id'] == run_id and type(origin) is int and 0 < origin < attempt,
            'carried supply belongs to a foreign run or attempt')
    api = NATIVE['api_json']
    base = f'repos/{repository}/actions/runs/{run_id}'
    run = api(base)
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    head = event['pull_request']['head']['sha'] if os.environ['GITHUB_EVENT_NAME'] == 'pull_request' else context['source_sha']
    require(run.get('id') == int(run_id) and run.get('run_attempt') == attempt
            and run.get('repository', {}).get('id') == 1133413326
            and run.get('head_sha') == head and run.get('event') == os.environ['GITHUB_EVENT_NAME']
            and run.get('path') in ('.github/workflows/ci.yml', '.github/workflows/qemu-matrix.yml')
            and run.get('conclusion') not in ('cancelled', 'timed_out', 'action_required', 'stale')
            and isinstance(run.get('run_started_at'), str), 'carried supply run identity differs')
    suffix = '/ SQLite full RPM check ('+arch+')'
    owner = None
    for number in range(origin, attempt+1):
        metadata = api(base+'/attempts/'+str(number))
        require(metadata.get('id') == int(run_id) and metadata.get('run_attempt') == number
                and metadata.get('head_sha') == head and isinstance(metadata.get('run_started_at'), str),
                'carried supply attempt differs')
        listing = api(base+'/attempts/'+str(number)+'/jobs?per_page=100')
        require(type(listing.get('total_count')) is int and isinstance(listing.get('jobs'), list)
                and len(listing['jobs']) == listing['total_count'] <= 100, 'incomplete supply owner listing')
        owners = [job for job in listing['jobs'] if job.get('name', '').endswith(suffix)]
        require(len(owners) == 1, 'ambiguous or missing supply owner')
        job = owners[0]
        require(isinstance(job.get('started_at'), str), 'supply owner start is unavailable')
        if number == origin:
            require(type(job.get('id')) is int and job['id'] > 0
                    and job.get('status') == 'completed' and job.get('conclusion') == 'success'
                    and job.get('run_id') == int(run_id) and job.get('run_attempt') == number
                    and job.get('head_sha') == head and isinstance(job.get('completed_at'), str)
                    and metadata['run_started_at'] <= job['started_at'] <= job['completed_at']
                    < run['run_started_at'], 'carried supply owner did not succeed')
            owner = job
        else:
            require(job['started_at'] < metadata['run_started_at'],
                    'newer supply owner reran; old supply cannot be carried')
            require(job.get('status') == 'completed' and job.get('conclusion') == 'success'
                    and type(job.get('id')) is int and job['id'] > 0
                    and job.get('run_id') == int(run_id)
                    and job.get('head_sha') == head
                    and (job['started_at'], job.get('completed_at')) ==
                        (owner['started_at'], owner['completed_at']),
                    'later carried supply owner failed, changed or is incomplete')
    listing = api(base+'/artifacts?per_page=100')
    require(type(listing.get('total_count')) is int and isinstance(listing.get('artifacts'), list)
            and len(listing['artifacts']) == listing['total_count'] <= 100, 'incomplete supply artifacts')
    artifacts = [row for row in listing['artifacts']
                 if row.get('name') == f'fedora-sqlite-{arch}-{origin}']
    require(len(artifacts) == 1, 'ambiguous carried supply artifact')
    artifact = artifacts[0]
    require(type(artifact.get('id')) is int and artifact['id'] > 0 and artifact.get('expired') is False
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= 3*LIMIT
            and re.fullmatch('sha256:[a-f0-9]{64}', artifact.get('digest', ''))
            and isinstance(artifact.get('created_at'), str)
            and owner['started_at'] <= artifact['created_at'] <= owner['completed_at'],
            'carried supply artifact lacks an exact successful owner')
    return artifact, origin


def download_carried_artifact(artifact, output):
    require(type(artifact.get('id')) is int and artifact['id'] > 0
            and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= 3*LIMIT
            and re.fullmatch('sha256:[a-f0-9]{64}', artifact.get('digest', '')),
            'invalid bounded source artifact identity')
    arguments = ['gh', 'api', f'repos/omg-cli/omg/actions/artifacts/{artifact["id"]}/zip']
    data = bounded_output(arguments, 3*LIMIT, timeout=90)
    require(len(data) == artifact['size_in_bytes'] and 'sha256:'+sha(data) == artifact['digest'],
            'carried supply archive digest differs')
    output.write_bytes(data)


def verify_zip_files(archive_path, directory, origin, arch, extra=None):
    prefix_name = f'fedora-sqlite-{arch}-{origin}/'
    expected = {prefix_name+path.name: path for path in directory.iterdir()}
    expected.update(extra or {})
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        require(len(members) <= 256 and len({item.filename for item in members}) == len(members)
                and sum(item.file_size for item in members) <= 3*LIMIT, 'oversized supply ZIP')
        for item in members:
            require(not item.is_dir() and not (item.external_attr >> 16) & 0o170000 == 0o120000
                    and not item.flag_bits & 1 and item.file_size <= LIMIT
                    and not any(part in ('', '.', '..') for part in item.filename.split('/'))
                    and re.fullmatch(r'[A-Za-z0-9_./-]+', item.filename)
                    and (item.filename.startswith(prefix_name) or item.filename.startswith('diagnostics/')),
                    'unsafe supply ZIP member')
        require({item.filename for item in members if item.filename.startswith(prefix_name)} ==
                {name for name in expected if name.startswith(prefix_name)}, 'supply ZIP member set differs')
        for name, path in expected.items():
            with archive.open(name) as stream:
                require(hashlib.file_digest(stream, 'sha256').hexdigest() == SQLITE['digest'](path),
                        'local supply differs from immutable GitHub artifact')


def readmit(directory, policy, arch, revision, context):
    manifest = SQLITE['document'](directory/'manifest.json')
    if not (directory/'admission.json').exists():
        SQLITE['verify_bundle'](directory, policy, arch, revision)
        return 'same-source-cold'
    old = SQLITE['document'](directory/'admission.json')
    require(old.get('consumer_sha') == revision and old.get('consumer_run_id') == context['run_id']
            and type(old.get('consumer_run_attempt')) is int and old['consumer_run_attempt'] <= context['run_attempt'],
            'carried supply belongs to a foreign source, run or attempt')
    previous = dict(run_id=old['consumer_run_id'], run_attempt=old['consumer_run_attempt'],
                    admission_sha256=SQLITE['digest'](directory/'admission.json'))
    SQLITE['verify_bundle'](directory, policy, arch, revision, previous)
    with tempfile.TemporaryDirectory(prefix='sqlite-readmit-', dir=directory.parent) as temporary:
        work = Path(temporary)
        metadata = unpack(directory/'baseline.tar', work, policy, arch)
        fresh(metadata)
        require(metadata.get('recipe_sha256') == recipe(arch)
                and metadata.get('run_id') == old['build_run_id']
                and metadata.get('run_attempt') == old['build_run_attempt']
                and metadata.get('built_at') == old['built_at']
                and metadata.get('inventory_sha256') == old['inventory_sha256']
                and SQLITE['digest'](work/'inventory.json') == old['inventory_sha256']
                and metadata.get('manifest_sha256') == SQLITE['digest'](directory/'manifest.json')
                and (work/'bundle/manifest.json').read_bytes() == (directory/'manifest.json').read_bytes(),
                'carried supply recipe, inventory or original manifest differs')
        SQLITE['verify_bundle'](work/'bundle', policy, arch, metadata['source_sha'])
        signed_at = verify_attestation(directory/'baseline.tar', directory/'baseline.sigstore.json',
                                       metadata, work/'verification.json')
        if old['consumer_run_attempt'] < context['run_attempt']:
            artifact, origin = carried_owner(old, arch, dict(context, source_sha=revision))
            download_carried_artifact(artifact, work/'supply.zip')
            verify_zip_files(work/'supply.zip', directory, origin, arch)
            refreshed = NATIVE['api_json']('repos/omg-cli/omg/actions/runs/'+context['run_id'])
            require(refreshed.get('id') == int(context['run_id'])
                    and refreshed.get('run_attempt') == context['run_attempt'],
                    'consumer attempt changed during carried supply admission')
            old.update(supply_run_attempt=origin, supply_artifact_id=artifact['id'],
                       supply_artifact_digest=artifact['digest'], disposition='carried-supply')
        fresh(metadata)
        old.update(consumer_run_attempt=context['run_attempt'], verified_tlog_at=signed_at)
        temporary_admission = work/'admission.json'
        temporary_admission.write_bytes(canonical(old))
        os.replace(temporary_admission, directory/'admission.json')
    return old['disposition']


def pack(directory, output, arch, revision, artifact_id, artifact_digest):
    policy = SQLITE['document'](SQLITE['DEFAULT_POLICY'])
    manifest = SQLITE['verify_bundle'](directory, policy, arch, revision)
    require(not (directory/'admission.json').exists(), 'publisher requires a fresh full RPM build')
    diagnostics = directory.parent/'diagnostics'/directory.name
    metadata = SQLITE['document'](diagnostics/'build-finished.json')
    fresh(metadata)
    require(manifest.get('built_at') == metadata['built_at'] and metadata['source_sha'] == revision
            and re.fullmatch('[1-9][0-9]{0,19}', metadata['run_id'])
            and type(metadata['run_attempt']) is int and metadata['run_attempt'] > 0,
            'fresh build identity is missing')
    require(metadata['run_id'] == os.environ.get('GITHUB_RUN_ID')
            and metadata['run_attempt'] == int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')),
            'publisher cannot relabel an earlier build attempt')
    require(re.fullmatch('[1-9][0-9]{0,19}', artifact_id or '')
            and re.fullmatch('[a-f0-9]{64}', artifact_digest or ''), 'exact source artifact identity is required')
    artifact = NATIVE['api_json']('repos/omg-cli/omg/actions/artifacts/'+artifact_id)
    require(artifact.get('id') == int(artifact_id) and artifact.get('expired') is False
            and artifact.get('name') == directory.name
            and artifact.get('digest') == 'sha256:'+artifact_digest
            and artifact.get('workflow_run', {}).get('id') == int(metadata['run_id'])
            and artifact.get('workflow_run', {}).get('head_sha') == revision,
            'source artifact is not this original successful build')
    with tempfile.TemporaryDirectory(prefix='sqlite-publisher-input-') as temporary:
        archive_path = Path(temporary)/'source.zip'
        download_carried_artifact(artifact, archive_path)
        verify_zip_files(archive_path, directory, metadata['run_attempt'], arch, {
            'diagnostics/'+directory.name+'/'+name: diagnostics/name
            for name in ('inventory.json', 'build-finished.json')})
    installed = (diagnostics/'inventory.json').read_bytes()
    require(0 < len(installed) <= 4*1024*1024, 'missing strong installed header inventory')
    metadata.update(schema_version=1, architecture=arch, recipe_sha256=recipe(arch),
        inventory_sha256=sha(installed), manifest_sha256=SQLITE['digest'](directory/'manifest.json'))
    output.mkdir(parents=True, exist_ok=False)
    (output/'baseline.json').write_bytes(canonical(metadata))
    with tarfile.open(output/'sqlite-baseline.tar', 'w') as archive:
        for path in sorted(directory.iterdir()):
            archive.add(path, arcname='bundle/'+path.name, recursive=False)
        archive.add(output/'baseline.json', arcname='baseline.json', recursive=False)
        archive.add(diagnostics/'inventory.json', arcname='inventory.json', recursive=False)
    require((output/'sqlite-baseline.tar').stat().st_size <= LIMIT, 'baseline archive exceeds bound')
    return metadata


def valid_key(key):
    return re.fullmatch(PREFIX+r'(?:x86_64|aarch64)/[a-f0-9]{64}/[a-f0-9]{64}/'
                        r'(?:latest\.json|[a-f0-9]{64}\.(?:tar|sigstore\.json))', key) is not None


def r2(key, method, output, body=None, condition=None):
    require(valid_key(key) and method in ('GET', 'PUT'), 'foreign R2 publication key or method')
    account = os.environ.get('OMG_R2_CACHE_ACCOUNT_ID', '')
    access, secret = os.environ.get('AWS_ACCESS_KEY_ID', ''), os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    require(re.fullmatch('[a-f0-9]{32}', account) and
            all(re.fullmatch('[A-Za-z0-9/+_=.-]+', value) for value in (access, secret)),
            'missing trusted R2 publisher credentials')
    headers = output.with_suffix('.headers')
    response_limit = 65536 if method == 'PUT' or key.endswith('latest.json') else 1024*1024 if key.endswith('.sigstore.json') else LIMIT
    command = ['curl', '--silent', '--show-error', '--proto', '=https', '--connect-timeout', '10',
        '--max-time', '60', '--max-filesize', str(response_limit), '--aws-sigv4', 'aws:amz:auto:s3',
        '--config', '-', '--request', method, '--dump-header', str(headers), '--output', str(output),
        '--write-out', '%{http_code}']
    if condition:
        command += ['--header', condition]
    if body:
        command += ['--data-binary', '@'+str(body)]
    command += ['https://'+account+'.r2.cloudflarestorage.com/omg-ci-compiler-cache/'+key]
    result = subprocess.run(command, input='user = '+json.dumps(access+':'+secret)+'\n',
                            text=True, capture_output=True, check=True, timeout=65)
    require(re.fullmatch('[0-9]{3}', result.stdout), 'invalid R2 HTTP response')
    require(headers.stat().st_size <= 65536 and output.stat().st_size <= response_limit,
            'oversized R2 response')
    return int(result.stdout), headers.read_text()


def publish(directory, proof, arch):
    require(os.environ.get('GITHUB_REPOSITORY') == 'omg-cli/omg'
            and os.environ.get('GITHUB_REPOSITORY_ID') == '1133413326'
            and os.environ.get('GITHUB_REPOSITORY_OWNER_ID') == '329545359'
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') in ('push', 'schedule', 'workflow_dispatch')
            and os.environ.get('GITHUB_WORKFLOW_REF') == 'omg-cli/omg/.github/workflows/ci.yml@refs/heads/main',
            'publication requires the trusted main baseline publisher')
    metadata = SQLITE['document'](directory/'baseline.json')
    require(metadata['source_sha'] == os.environ.get('GITHUB_SHA') and
            metadata['run_id'] == os.environ.get('GITHUB_RUN_ID') and
            metadata['run_attempt'] == int(os.environ.get('GITHUB_RUN_ATTEMPT', '0')),
            'publication differs from the actual build run')
    fresh(metadata)
    archive = directory/'sqlite-baseline.tar'
    require(0 < proof.stat().st_size <= 1024*1024, 'attestation bundle exceeds bound')
    verify_attestation(archive, proof, metadata, directory/'verification.json')
    archive_sha, proof_sha = SQLITE['digest'](archive), SQLITE['digest'](proof)
    key = prefix(arch, metadata['recipe_sha256'], metadata['inventory_sha256'])
    generation = [metadata['built_at'], int(metadata['run_id']), metadata['run_attempt']]
    for path, suffix in ((archive, '.tar'), (proof, '.sigstore.json')):
        status, _ = r2(key+archive_sha+suffix, 'PUT', directory/'put-response', path, 'If-None-Match: *')
        if status == 412:
            status, _ = r2(key+archive_sha+suffix, 'GET', directory/'existing')
            require(status == 200 and SQLITE['digest'](directory/'existing') == SQLITE['digest'](path),
                    'immutable baseline object differs')
        else:
            require(status == 200, 'immutable baseline object upload failed')
    status, headers = r2(key+'latest.json', 'GET', directory/'current.json')
    require(status in (200, 404), 'baseline pointer read failed')
    condition = 'If-None-Match: *'
    if status == 200:
        previous = SQLITE['document'](directory/'current.json')
        require(isinstance(previous.get('generation'), list) and len(previous['generation']) == 3
                and all(type(value) is int for value in previous['generation']), 'invalid existing pointer generation')
        if previous['generation'] >= generation:
            print('Current baseline publication already supersedes this build')
            return
        etags = re.findall(r'^etag:\s*("[^"\r\n]+")\s*$', headers, re.I | re.M)
        require(len(etags) == 1, 'missing pointer CAS ETag')
        condition = 'If-Match: '+etags[0]
    fresh(metadata)
    (directory/'next.json').write_bytes(canonical({'archive_sha256': archive_sha,
        'proof_sha256': proof_sha, 'generation': generation}))
    status, _ = r2(key+'latest.json', 'PUT', directory/'pointer-response', directory/'next.json', condition)
    require(status in (200, 412), 'baseline pointer publication failed')
    print('Baseline pointer advanced' if status == 200 else 'Concurrent publisher won the pointer CAS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('pack', 'publish', 'admit'))
    parser.add_argument('directory', type=Path)
    parser.add_argument('--arch', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--revision', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--proof', type=Path)
    parser.add_argument('--policy', type=Path, default=SQLITE['DEFAULT_POLICY'])
    parser.add_argument('--artifact-id')
    parser.add_argument('--artifact-digest')
    parser.add_argument('--run-id', default=os.environ.get('GITHUB_RUN_ID'))
    parser.add_argument('--run-attempt', type=int, default=os.environ.get('GITHUB_RUN_ATTEMPT'))
    args = parser.parse_args()
    try:
        if args.action == 'admit':
            if os.name == 'posix':
                def expired(signum, frame):
                    raise TimeoutError('consumer re-admission deadline exhausted')
                signal.signal(signal.SIGALRM, expired)
                signal.alarm(300)
            require(re.fullmatch('[1-9][0-9]{0,19}', args.run_id or '') and type(args.run_attempt) is int
                    and args.run_attempt > 0, 'current consumer identity is required')
            print(readmit(args.directory, SQLITE['document'](args.policy), args.arch,
                          args.revision, dict(run_id=args.run_id, run_attempt=args.run_attempt)))
        elif args.action == 'pack':
            require(args.output is not None, 'archive output is required')
            pack(args.directory, args.output, args.arch, args.revision, args.artifact_id, args.artifact_digest)
        else:
            require(args.proof is not None, 'local attestation bundle is required')
            publish(args.directory, args.proof, args.arch)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        parser.exit(1, 'SQLite baseline failed: '+type(error).__name__+'\n')

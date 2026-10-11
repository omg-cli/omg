"""Observe Rustup metadata without invoking proxies or modifying toolchains."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

STAGES = ('before_minimal', 'after_minimal', 'after_components', 'before_first_proxy')


def stable(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise OSError(f'not a regular metadata file: {path}')
    if before.st_size > 1024 * 1024:
        raise OSError(f'metadata exceeds limit: {path}')
    with path.open('rb') as stream:
        data = stream.read(1024 * 1024 + 1)
        opened = os.fstat(stream.fileno())
    after = path.lstat()
    if stable(before) != stable(opened) or stable(before) != stable(after) or len(data) > 1024 * 1024:
        raise OSError(f'metadata changed during read: {path}')
    return {'text': data.decode('utf-8'), 'sha256': hashlib.sha256(data).hexdigest()}


def destination(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'present': False}
    value = dict(present=True, uid=info.st_uid, gid=info.st_gid,
                 mode=oct(stat.S_IMODE(info.st_mode)), size=info.st_size,
                 inode=info.st_ino, device=info.st_dev, mtime_ns=info.st_mtime_ns,
                 ctime_ns=info.st_ctime_ns, symlink=stat.S_ISLNK(info.st_mode),
                 regular=stat.S_ISREG(info.st_mode))
    if value['symlink']:
        value['link_target'] = os.readlink(path)
    elif value['regular']:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            for data in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(data)
        if stable(info) != stable(opened) or stable(info) != stable(path.lstat()):
            raise OSError(f'destination changed during read: {path}')
        value['sha256'] = digest.hexdigest()
    return value


def classify(data):
    registered = set(data['components']['components']['text'].splitlines())
    fmt = {name for name in registered if name.startswith('rustfmt-preview-')}
    result = {}
    for name in ('cargo-fmt', 'rustfmt'):
        value = data['bins'][name]
        owners = [key.removeprefix('manifest-') for key, item in data['components'].items()
                  if key.startswith('manifest-') and f'file:bin/{name}' in item['text'].splitlines()]
        expected = sorted(set(owners) & fmt)
        if value.get('symlink'):
            state = 'symlink_destination_requires_investigation'
        elif value['present'] and not value['regular']:
            state = 'nonregular_destination_requires_investigation'
        elif value['present'] and not expected:
            state = 'destination_without_registered_rustfmt_owner'
        elif fmt and (not value['present'] or not expected):
            state = 'registered_rustfmt_metadata_incomplete'
        elif value['present']:
            state = 'destination_and_registered_owner_consistent'
        else:
            state = 'rustfmt_not_installed_destination_absent'
        result[name] = dict(state=state, declared_owners=owners, registered_rustfmt_owners=expected)
    return result


def snapshot(toolchain):
    toolchain = Path(toolchain)
    result = dict(toolchain=str(toolchain), state='diagnostic_error', errors=[], components={}, bins={})
    try:
        try:
            info = toolchain.lstat()
        except FileNotFoundError:
            return dict(toolchain=str(toolchain), state='toolchain_absent')
        if not stat.S_ISDIR(info.st_mode):
            raise OSError('toolchain is not a real directory')
        for directory in (toolchain/'lib', toolchain/'lib/rustlib', toolchain/'bin'):
            if not stat.S_ISDIR(directory.lstat().st_mode):
                raise OSError(f'not a real directory: {directory}')
        metadata = toolchain/'lib/rustlib'
        result['components']['components'] = read_regular(metadata/'components')
        names = result['components']['components']['text'].splitlines()
        if any(not re.fullmatch(r'[A-Za-z0-9_.-]+', name) for name in names) or len(names) != len(set(names)):
            raise ValueError('malformed or duplicate component name')
        for path in sorted(metadata.glob('manifest-*')):
            item = read_regular(path)
            if any(not line.startswith(('file:', 'dir:')) for line in item['text'].splitlines()):
                raise ValueError(f'malformed component manifest: {path.name}')
            result['components'][path.name] = item
        if any('manifest-'+name not in result['components'] for name in names):
            raise ValueError('registered component manifest is missing')
        for name in ('cargo-fmt', 'rustfmt', 'rustc'):
            result['bins'][name] = destination(toolchain/'bin'/name)
        result['classification'] = classify(result)
        result['state'] = 'observed'
    except (OSError, ValueError, UnicodeError) as error:
        result['errors'].append(f'{type(error).__name__}: {error}')
    return result


def envelope():
    cargo_home = Path(os.environ.get('CARGO_HOME') or str(Path.home()/'.cargo'))
    try:
        rustup = destination(cargo_home/'bin/rustup')
    except OSError as error:
        rustup = dict(state='diagnostic_error', error=f'{type(error).__name__}: {error}')
    return dict(schema=1, captured_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                declared_bootstrap_versions=dict(rustup='1.28.2', toolchain='1.95.0'),
                rustup_binary_path=str(cargo_home/'bin/rustup'), rustup_binary=rustup,
                version_qualification='Declared recipe versions; binary metadata and hashes observed, no version command invoked.',
                actor=dict(uid=os.getuid(), gid=os.getgid()),
                declared_context={key: os.environ.get(key) for key in
                    ('GITHUB_SHA', 'GITHUB_REF', 'GITHUB_REPOSITORY', 'GITHUB_WORKFLOW_SHA',
                     'GITHUB_WORKFLOW_REF', 'GITHUB_EVENT_NAME', 'GITHUB_RUN_ID',
                     'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'DIAGNOSTIC_IMAGE', 'DIAGNOSTIC_PLATFORM')},
                environment={key: os.environ.get(key) for key in ('HOME', 'RUSTUP_HOME', 'CARGO_HOME')})


def write_once(out, name, data):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    path = out/name
    with path.open('x', encoding='utf-8') as stream:
        json.dump(data, stream, indent=2)
        stream.write('\n')
    return path


def capture(toolchain, stage, out):
    if stage not in STAGES:
        raise ValueError('unknown diagnostic stage')
    data = envelope()
    data.update(stage=stage, snapshot=snapshot(toolchain))
    return write_once(out, stage+'.json', data)


def join(repo, out):
    repo = Path(repo)
    canonical = repo/'scripts/ci-rustup-diagnostics.py'
    staged = Path(__file__).read_bytes()
    data = envelope()
    try:
        if staged != canonical.read_bytes():
            raise ValueError('staged/canonical helper bytes differ')
        data['actual_checkout'] = {
            key: subprocess.check_output(['git', '-c', f'safe.directory={repo}', 'rev-parse', ref],
                                         cwd=repo, text=True, timeout=10).strip()
            for key, ref in (('head', 'HEAD'), ('tree', 'HEAD^{tree}'))}
        declared = os.environ.get('GITHUB_SHA', '')
        if not re.fullmatch(r'[0-9a-f]{40}', declared):
            raise ValueError('declared event GITHUB_SHA is missing or malformed')
        if data['actual_checkout']['head'] != declared:
            raise ValueError('actual checkout HEAD differs from declared event GITHUB_SHA')
        data['state'] = 'verified_checkout_and_helper'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        data.update(state='staging_error', error=f'{type(error).__name__}: {error}')
    write_once(out, 'source-join.json', data)
    return data['state'] == 'verified_checkout_and_helper'


def summary(out):
    data = envelope()
    data['stages'] = {stage: 'recorded' if (Path(out)/(stage+'.json')).is_file() else 'not_reached'
                      for stage in STAGES}
    write_once(out, 'stage-status.json', data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=('capture', 'join', 'summary'))
    parser.add_argument('--toolchain')
    parser.add_argument('--stage', choices=STAGES)
    parser.add_argument('--repo')
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    if args.operation == 'capture':
        if not args.toolchain or not args.stage:
            parser.error('capture requires --toolchain and --stage')
        capture(args.toolchain, args.stage, args.out)
    elif args.operation == 'join':
        if not args.repo:
            parser.error('join requires --repo')
        return 0 if join(args.repo, args.out) else 1
    else:
        summary(args.out)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

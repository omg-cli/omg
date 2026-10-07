#!/usr/bin/env python3
"""Verify a same-source Docker save archive as data before loading it."""
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

MAX_ARCHIVE = 3 * 1024**3
MAX_LAYER = 1024**3
MAX_MEMBERS = 256
MAX_JSON = 1024**2


def digest(stream, limit):
    value = hashlib.sha256()
    size = 0
    while block := stream.read(1024**2):
        size += len(block)
        if size > limit:
            raise ValueError('image bytes exceed their bound')
        value.update(block)
    return value.hexdigest(), size


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate image JSON key')
        result[key] = value
    return result


def read_json(bundle, members, name):
    entry = members.get(name)
    if entry is None or not entry.isfile() or entry.size > MAX_JSON:
        raise ValueError('missing or oversized image JSON')
    with bundle.extractfile(entry) as stream:
        raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise ValueError('image JSON exceeds its byte bound')
    return json.loads(raw, object_pairs_hook=unique_object)


def verify_archive(path, archive_sha, config_sha, architecture, source_sha, base_digest, qemu_package):
    for value, width in ((archive_sha, 64), (config_sha, 64), (source_sha, 40)):
        if not re.fullmatch(r'[0-9a-f]{' + str(width) + '}', value):
            raise ValueError('invalid expected image identity')
    if architecture not in ('amd64', 'arm64') or not re.fullmatch(r'sha256:[0-9a-f]{64}', base_digest):
        raise ValueError('invalid expected platform or base digest')
    if qemu_package != {'amd64': 'qemu-system-x86', 'arm64': 'qemu-system-arm'}[architecture]:
        raise ValueError('QEMU package differs from native platform')
    path = Path(path)
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= MAX_ARCHIVE:
        raise ValueError('invalid image archive file')
    with path.open('rb') as stream:
        actual, size = digest(stream, MAX_ARCHIVE)
    if actual != archive_sha:
        raise ValueError('image archive digest mismatch')
    with tarfile.open(path, 'r:') as bundle:
        members = {}
        for entry in bundle:
            name = PurePosixPath(entry.name)
            if (len(members) >= MAX_MEMBERS or entry.name in members or name.is_absolute()
                    or '..' in name.parts or '\\' in entry.name or len(entry.name) > 512
                    or not (entry.isfile() or entry.isdir()) or not 0 <= entry.size <= MAX_ARCHIVE):
                raise ValueError('unsafe or excessive image archive members')
            members[entry.name] = entry
        manifest = read_json(bundle, members, 'manifest.json')
        if not isinstance(manifest, list) or len(manifest) != 1:
            raise ValueError('exactly one image manifest is required')
        item = manifest[0]
        if not isinstance(item, dict) or not isinstance(item.get('Config'), str):
            raise ValueError('invalid image manifest')
        config_entry = members.get(item['Config'])
        if config_entry is None or not config_entry.isfile() or config_entry.size > MAX_JSON:
            raise ValueError('missing or oversized image config')
        with bundle.extractfile(config_entry) as stream:
            actual_config, _ = digest(stream, MAX_JSON)
        if actual_config != config_sha:
            raise ValueError('image config digest mismatch')
        config = read_json(bundle, members, item['Config'])
        if not isinstance(config, dict) or config.get('architecture') != architecture or config.get('os') != 'linux':
            raise ValueError('image platform mismatch')
        settings = config.get('config')
        if not isinstance(settings, dict) or not isinstance(settings.get('Labels'), dict):
            raise ValueError('missing image controller labels')
        labels = settings['Labels']
        if (labels.get('org.opencontainers.image.revision') != source_sha
                or labels.get('org.opencontainers.image.base.digest') != base_digest
                or labels.get('org.omg.controller.qemu-package') != qemu_package):
            raise ValueError('image source or controller labels mismatch')
        layers = item.get('Layers')
        rootfs = config.get('rootfs')
        if not isinstance(rootfs, dict):
            raise ValueError('invalid image rootfs')
        diff_ids = rootfs.get('diff_ids')
        if (rootfs.get('type') != 'layers' or not isinstance(layers, list)
                or not 0 < len(layers) <= 32 or not all(isinstance(name, str) for name in layers)
                or len(set(layers)) != len(layers) or not isinstance(diff_ids, list)
                or len(diff_ids) != len(layers)
                or not all(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)
                           for value in diff_ids)):
            raise ValueError('invalid image layer identities')
        layer_records = []
        expanded_total = 0
        for name, expected in zip(layers, diff_ids):
            entry = members.get(name)
            if entry is None or not entry.isfile():
                raise ValueError('missing image layer')
            with bundle.extractfile(entry) as stream:
                magic = stream.read(4)
                stream.seek(0)
                if magic.startswith(b'\x1f\x8b'):
                    with gzip.GzipFile(fileobj=stream) as expanded:
                        layer_sha, expanded_size = digest(expanded, MAX_LAYER)
                elif magic == b'\x28\xb5\x2f\xfd':
                    raise ValueError('zstd image layer requires a reviewed bounded decoder')
                else:
                    layer_sha, expanded_size = digest(stream, MAX_LAYER)
            if expected != 'sha256:' + layer_sha:
                raise ValueError('image layer diffID mismatch')
            expanded_total += expanded_size
            if expanded_total > MAX_ARCHIVE:
                raise ValueError('expanded image exceeds its total bound')
            layer_records.append(dict(diff_id=expected, expanded_bytes=expanded_size, stored_bytes=entry.size))
    return dict(archive_sha256=actual, archive_bytes=size, config_sha256=actual_config,
                architecture=architecture, source_sha=source_sha, base_digest=base_digest,
                layers=layer_records, expanded_bytes=expanded_total)

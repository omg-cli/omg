#!/usr/bin/env python3
"""Exercise image admission against actual saved archive bytes."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    'controller_image', Path(__file__).with_name('qemu-controller-image.py'))
IMAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMAGE)
SOURCE = 'a' * 40
BASE = 'sha256:' + 'b' * 64


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ImageAdmission(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.archive = Path(self.directory.name) / 'image.tar'
        self.layer = b'actual independent layer payload\n' * 100
        self.config = {
            'architecture': 'amd64', 'os': 'linux',
            'config': {'Labels': {
                'org.opencontainers.image.revision': SOURCE,
                'org.opencontainers.image.base.digest': BASE,
                'org.omg.controller.qemu-package': 'qemu-system-x86'}},
            'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + sha(self.layer)]}}

    def write_archive(self, *, compressed=False, layer=None, extra=()):
        config = json.dumps(self.config).encode()
        self.config_sha = sha(config)
        manifest = json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode()
        content = self.layer if layer is None else layer
        if compressed:
            content = gzip.compress(content)
        with tarfile.open(self.archive, 'w') as bundle:
            for name, data in [('manifest.json', manifest), ('config.json', config),
                               ('layer.tar', content), *extra]:
                entry = tarfile.TarInfo(name)
                if isinstance(data, bytes):
                    entry.size = len(data)
                    bundle.addfile(entry, io.BytesIO(data))
                else:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = data
                    bundle.addfile(entry)
        self.archive_sha = sha(self.archive.read_bytes())

    def verify(self, **changes):
        args = dict(path=self.archive, archive_sha=self.archive_sha,
                    config_sha=self.config_sha, architecture='amd64',
                    source_sha=SOURCE, base_digest=BASE, qemu_package='qemu-system-x86')
        args.update(changes)
        return IMAGE.verify_archive(**args)

    def test_plain_and_gzip_layers_preserve_actual_expanded_identity(self):
        for compressed in (False, True):
            with self.subTest(compressed=compressed):
                self.write_archive(compressed=compressed)
                record = self.verify()
                self.assertEqual(record['expanded_bytes'], len(self.layer))
                self.assertEqual(record['layers'][0]['diff_id'], 'sha256:' + sha(self.layer))

    def test_archive_and_config_must_match_trusted_external_digests(self):
        self.write_archive()
        with self.assertRaisesRegex(ValueError, 'archive digest mismatch'):
            self.verify(archive_sha='0' * 64)
        with self.assertRaisesRegex(ValueError, 'config digest mismatch'):
            self.verify(config_sha='0' * 64)

    def test_layer_tampering_is_refused_even_with_recomputed_outer_digest(self):
        self.write_archive(layer=b'changed payload')
        with self.assertRaisesRegex(ValueError, 'diffID mismatch'):
            self.verify()

    def test_platform_source_and_base_are_independent_requirements(self):
        self.write_archive()
        for changes, message in [
            ({'architecture': 'arm64', 'qemu_package': 'qemu-system-arm'}, 'platform mismatch'),
            ({'source_sha': 'c' * 40}, 'source or controller labels mismatch'),
            ({'base_digest': 'sha256:' + 'd' * 64}, 'source or controller labels mismatch')]:
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, message):
                self.verify(**changes)

    def test_duplicate_traversal_and_link_members_are_refused_without_extraction(self):
        for extra in [[('layer.tar', b'duplicate')], [('../escaped', b'data')],
                      [('/absolute', b'data')], [('linked', '/etc/passwd')]]:
            with self.subTest(extra=extra):
                self.write_archive(extra=extra)
                with self.assertRaisesRegex(ValueError, 'unsafe or excessive'):
                    self.verify()
        self.assertEqual(list(Path(self.directory.name).iterdir()), [self.archive])

    def test_compressed_expansion_and_member_count_are_bounded(self):
        self.write_archive(compressed=True)
        with patch.object(IMAGE, 'MAX_LAYER', len(self.layer) - 1):
            with self.assertRaisesRegex(ValueError, 'bytes exceed'):
                self.verify()
        with patch.object(IMAGE, 'MAX_MEMBERS', 2):
            with self.assertRaisesRegex(ValueError, 'unsafe or excessive'):
                self.verify()

    def test_malformed_config_shapes_are_explicit_refusals(self):
        for key, value in [('config', []), ('rootfs', None)]:
            with self.subTest(key=key):
                previous = self.config[key]
                self.config[key] = value
                self.write_archive()
                with self.assertRaises(ValueError):
                    self.verify()
                self.config[key] = previous

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate image JSON key'):
            json.loads('{"architecture":"amd64","architecture":"arm64"}',
                       object_pairs_hook=IMAGE.unique_object)


if __name__ == '__main__':
    unittest.main()

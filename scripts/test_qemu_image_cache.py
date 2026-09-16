import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('image_cache', Path(__file__).with_name('qemu-image-cache.py'))
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class ImageCacheTests(unittest.TestCase):
    def test_verified_copy_for_both_pin_algorithms(self):
        for algorithm in ('sha256', 'sha512'):
            with self.subTest(algorithm=algorithm), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source, destination = root / 'source', root / 'cache/image'
                data = b'pinned image' * 100000
                source.write_bytes(data)
                cache.verified_copy(source, destination, algorithm, hashlib.new(algorithm, data).hexdigest())
                self.assertEqual(destination.read_bytes(), data)

    def test_corruption_does_not_replace_destination_or_leave_partial_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'source', root / 'destination'
            source.write_bytes(b'corrupted')
            destination.write_bytes(b'previous')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                cache.verified_copy(source, destination, 'sha256', '0' * 64)
            self.assertEqual(destination.read_bytes(), b'previous')
            self.assertEqual(set(root.iterdir()), {source, destination})

    def test_missing_file_is_not_a_hit(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                cache.verified_copy(Path(directory) / 'missing', Path(directory) / 'out', 'sha256', '0' * 64)

    def test_invalid_digest_rejected_before_copy(self):
        with self.assertRaises(ValueError):
            cache.verified_copy('missing', 'unused', 'sha256', '../invalid')

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'data')
            link = root / 'link'
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest('symlink privileges unavailable')
            with self.assertRaises(ValueError):
                cache.verified_copy(link, root / 'out', 'sha256', hashlib.sha256(b'data').hexdigest())


if __name__ == '__main__':
    unittest.main()

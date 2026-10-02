import hashlib
import fcntl
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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


class ImageCacheBudgetTests(unittest.TestCase):
    def image(self, root, data, label='source'):
        source = root / label
        source.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        return source, root / 'cache' / ('sha256-' + digest + '.qcow2'), digest

    def publish(self, source, destination, digest, budget):
        return cache.publish_cache(source, destination, 'sha256', digest, budget)

    def test_exact_budget_and_both_algorithms(self):
        for algorithm in ('sha256', 'sha512'):
            with self.subTest(algorithm=algorithm), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = b'12345678'
                source = root / 'source'
                source.write_bytes(data)
                digest = hashlib.new(algorithm, data).hexdigest()
                destination = root / 'cache' / (algorithm + '-' + digest + '.qcow2')
                cache.publish_cache(source, destination, algorithm, digest, len(data))
                self.assertEqual(destination.read_bytes(), data)
                self.assertEqual(set(destination.parent.iterdir()),
                                 {destination, destination.parent / '.image-cache.lock'})

    def test_unknown_files_and_inflight_bytes_count_without_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            destination.parent.mkdir()
            unknown = destination.parent / 'user-owned.qcow2'
            unknown.write_bytes(b'12345')
            with self.assertRaises(cache.CacheQuotaExceeded):
                self.publish(source, destination, digest, 8)
            self.assertEqual(unknown.read_bytes(), b'12345')
            self.assertFalse(destination.exists())
            self.assertEqual(set(destination.parent.iterdir()),
                             {unknown, destination.parent / '.image-cache.lock'})

    def test_replacement_requires_room_for_old_file_and_full_temporary_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            destination.parent.mkdir()
            destination.write_bytes(b'old!')
            with self.assertRaises(cache.CacheQuotaExceeded):
                self.publish(source, destination, digest, 7)
            self.assertEqual(destination.read_bytes(), b'old!')
            self.publish(source, destination, digest, 8)
            self.assertEqual(destination.read_bytes(), b'1234')

    def test_orphan_temporary_file_counts_without_automatic_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            destination.parent.mkdir()
            orphan = destination.parent / '.image-cache-tmp-abandoned'
            orphan.write_bytes(b'1234')
            with self.assertRaises(cache.CacheQuotaExceeded):
                self.publish(source, destination, digest, 7)
            self.assertEqual(orphan.read_bytes(), b'1234')
            self.assertFalse(destination.exists())

    def test_digest_and_source_failures_are_not_quota_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            source.write_bytes(b'broken')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                self.publish(source, destination, digest, 0)
            with self.assertRaises(FileNotFoundError):
                self.publish(root / 'missing', destination, digest, 0)
            self.assertFalse(destination.exists())

    def test_wrong_filename_and_unsafe_cache_entries_are_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            with self.assertRaises(ValueError):
                self.publish(source, destination.with_name('unowned'), digest, 100)
            destination.parent.mkdir(exist_ok=True)
            outside = root / 'outside'
            outside.write_bytes(b'preserve')
            destination.symlink_to(outside)
            with self.assertRaises(ValueError):
                self.publish(source, destination, digest, 0)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(outside.read_bytes(), b'preserve')
            destination.unlink()
            (destination.parent / 'nested').mkdir()
            with self.assertRaises(ValueError):
                self.publish(source, destination, digest, 100)

    def test_symlink_directory_and_lock_are_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            actual = root / 'actual'
            actual.mkdir()
            destination.parent.symlink_to(actual, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                self.publish(source, destination, digest, 100)
            self.assertEqual(list(actual.iterdir()), [])
            destination.parent.unlink()
            destination.parent.mkdir()
            outside = root / 'outside'
            outside.write_bytes(b'preserve')
            (destination.parent / '.image-cache.lock').symlink_to(outside)
            with self.assertRaises((OSError, ValueError)):
                self.publish(source, destination, digest, 100)
            self.assertEqual(outside.read_bytes(), b'preserve')
            self.assertFalse(destination.exists())

    def test_concurrent_writers_cannot_exceed_cumulative_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jobs = []
            for number in range(2):
                data = bytes([number]) * (1024 * 1024)
                source, destination, digest = self.image(root, data, 'source' + str(number))
                jobs.append(subprocess.Popen(
                    [sys.executable, str(Path(cache.__file__)), str(source), str(destination),
                     '--algorithm', 'sha256', '--digest', digest, '--cache-write',
                     '--cache-budget-bytes', str(len(data))],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
            results = [job.communicate(timeout=20) for job in jobs]
            self.assertEqual(sorted(job.returncode for job in jobs), [0, 4], results)
            images = list((root / 'cache').glob('*.qcow2'))
            self.assertEqual(len(images), 1)
            self.assertEqual(images[0].stat().st_size, 1024 * 1024)
            self.assertFalse(list((root / 'cache').glob('.image-cache-tmp-*')))


    def test_source_change_while_waiting_for_writer_lock_is_fatal_before_quota(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            real_flock = cache.fcntl.flock

            def alter_source(lock_fd, operation):
                source.write_bytes(b'changed')
                real_flock(lock_fd, operation)

            with mock.patch.object(cache.fcntl, 'flock', side_effect=alter_source):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    self.publish(source, destination, digest, 0)
            self.assertFalse(destination.exists())

    def test_writer_waits_for_existing_local_lock_before_creating_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            destination.parent.mkdir()
            with (destination.parent / '.image-cache.lock').open('w') as locked:
                fcntl.flock(locked.fileno(), fcntl.LOCK_EX)
                job = subprocess.Popen(
                    [sys.executable, str(Path(cache.__file__)), str(source), str(destination),
                     '--algorithm', 'sha256', '--digest', digest, '--cache-write',
                     '--cache-budget-bytes', '4'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        job.communicate(timeout=0.2)
                    self.assertFalse(destination.exists())
                    self.assertFalse(list(destination.parent.glob('.image-cache-tmp-*')))
                finally:
                    fcntl.flock(locked.fileno(), fcntl.LOCK_UN)
                    output = job.communicate(timeout=10)
                self.assertEqual(job.returncode, 0, output)
                self.assertEqual(destination.read_bytes(), b'1234')

    def test_cli_default_budget_is_four_gib_without_reading_unknown_sparse_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            destination.parent.mkdir()
            unknown = destination.parent / 'preserved-user-file'
            with unknown.open('wb') as outgoing:
                outgoing.truncate(4 * 1024 * 1024 * 1024)
            result = subprocess.run(
                [sys.executable, str(Path(cache.__file__)), str(source), str(destination),
                 '--algorithm', 'sha256', '--digest', digest, '--cache-write'],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 4, result.stderr)
            self.assertIn('4294967296', result.stderr)
            self.assertEqual(unknown.stat().st_size, 4 * 1024 * 1024 * 1024)
            self.assertFalse(destination.exists())

    def test_read_remains_digest_verified_without_write_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination, digest = self.image(root, b'1234')
            destination.parent.mkdir()
            destination.write_bytes(b'1234')
            output = root / 'private-base'
            cache.verified_copy(destination, output, 'sha256', digest)
            self.assertEqual(output.read_bytes(), b'1234')
            destination.write_bytes(b'broken')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                cache.verified_copy(destination, output, 'sha256', digest)
            self.assertEqual(output.read_bytes(), b'1234')


class ImageCacheDriverTests(unittest.TestCase):
    def run_block(self, root, *, corrupt=False, status=None):
        driver = Path(__file__).with_name('benchmark-qemu.sh').read_text(encoding='utf-8')
        block = driver[driver.index('# A cache hit is only a transport optimization:'):
                       driver.index('timeout 30 docker exec -w /work/guest')]
        private = root / 'guest'
        private.mkdir()
        data = b'verified private boot image'
        (private / 'base.qcow2').write_bytes(b'broken' if corrupt else data)
        policy = root / 'policy'
        policy.write_text('pinned', encoding='utf-8')
        (root / 'qemu-image-cache.py').write_bytes(Path(cache.__file__).read_bytes())
        verifier = root / 'verify-qemu-image.py'
        verifier.write_text(
            'import hashlib, pathlib, sys\n'
            'a = sys.argv\n'
            'p = pathlib.Path(a[a.index("--image") + 1])\n'
            'assert hashlib.sha256(p.read_bytes()).hexdigest() == a[a.index("--digest") + 1]\n'
            'print("policy verified")\n', encoding='utf-8')
        setup = r'''
timeout() { shift; "$@"; }
docker() {
  [[ "$1" == exec && "$2" == fixture ]]
  shift 2
  [[ "$1" == bash && "$2" == -c ]]
  script=${3//\/work\/guest/$work\/guest}
  shift 3
  bash -c "$script" "$@"
}
'''
        if status is not None:
            setup += ('python3() { if [[ "$*" == *--cache-write* ]]; then return ' +
                      str(status) + '; else command python3 "$@"; fi; }\n')
        result = subprocess.run(
            ['/bin/bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', setup + block],
            env=dict(os.environ, work=str(root), here=str(root), image_cache=str(root / 'cache'),
                     image_cache_budget_bytes='0', hash_tool='sha256sum',
                     image_hash=hashlib.sha256(data).hexdigest(), image_url='https://invalid.local/image',
                     controller='fixture', distro='fedora', arch='x86_64', image_policy=str(policy)),
            capture_output=True, text=True, timeout=15)
        return result, private / 'base.qcow2'

    def test_quota_only_bypasses_optional_write_after_private_digest_and_before_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, base = self.run_block(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(base.read_bytes(), b'verified private boot image')
            self.assertIn('cache write bypassed', (root / 'image-cache.log').read_text())
            self.assertIn('OK', (root / 'image-setup.log').read_text())
            self.assertEqual((root / 'image-provenance.json').read_text().strip(), 'policy verified')
            self.assertFalse(list((root / 'cache').glob('*.qcow2')))

    def test_private_digest_failure_cannot_be_hidden_by_optional_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, _ = self.run_block(root, corrupt=True, status=4)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'image-provenance.json').exists())
            self.assertNotIn('cache write bypassed', (root / 'image-cache.log').read_text())

    def test_non_quota_write_failure_and_timeout_remain_fatal(self):
        for status in (1, 2, 124, 137):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                result, _ = self.run_block(root, status=status)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertFalse((root / 'image-provenance.json').exists())


    def test_all_distro_recursion_forwards_the_explicit_cache_budget(self):
        driver = Path(__file__).with_name('benchmark-qemu.sh').read_text(encoding='utf-8')
        block = driver[driver.index('  args=(--release "$tag" --arch "$arch")'):
                       driver.index('  jq -n --arg source "$source_kind" --arg suffix "$case_suffix"')]
        script = block + 'printf "%s\\n" "${args[@]}"'
        environment = dict(os.environ, tag='v1.2.3', arch='x86_64', image_cache='/cache',
                           image_cache_budget_bytes='17', staged_dir='', release_dir='',
                           inventory_file='', inventory_policy='', image_policy='', benchmark='false',
                           transaction_samples='0', inventory_tiers='', inventory_mutations='false',
                           inventory_isolation='false', storage_faults='false', restrict_egress='false',
                           allow_tcg='false')
        result = subprocess.run(['/bin/bash', '-euo', 'pipefail', '-c', script],
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['--release', 'v1.2.3', '--arch', 'x86_64',
                                                     '--image-cache', '/cache',
                                                     '--image-cache-budget-bytes', '17'])

    def test_invalid_budget_rejected_before_controller_or_guest(self):
        driver = Path(__file__).with_name('benchmark-qemu.sh')
        for value in ('-1', '1.5', 'text', ''):
            with self.subTest(value=value):
                result = subprocess.run(['/bin/bash', str(driver), '--image-cache-budget-bytes', value,
                                         '--print-pins'], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == '__main__':
    unittest.main()

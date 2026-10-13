"""Proposed real root-owned POSIX tempfile tests of the complete provenance module."""
import gzip
import hashlib
import json
import os
import copy
from pathlib import Path
import tempfile
import tomllib
import unittest
import provenance


def header(name, kind=b'0', size=0, mode=0o644, magic=b'ustar\x0000', link=b''):
    block = bytearray(512)
    encoded = name.encode('utf-8')
    if len(encoded) > 100:
        raise ValueError('fixture header name exceeds literal name field')
    block[:len(encoded)] = encoded
    for start, end, value in [(100,108,mode),(108,116,0),(116,124,0),(124,136,size),(136,148,1)]:
        block[start:end] = format(value, 'o').rjust(end-start-1, '0').encode() + b'\0'
    block[148:156] = b' ' * 8
    block[156:157] = kind
    block[157:157+len(link)] = link
    block[257:265] = magic
    block[148:156] = format(sum(block), 'o').rjust(6, '0').encode() + b'\0 '
    return bytes(block)


def archive_payload(entries, terminator=True):
    payload = b''
    for name, kind, content in entries:
        payload += header(name, kind, len(content)) + content + b'\0' * ((-len(content)) % 512)
    return payload + (b'\0' * 1024 if terminator else b'')


class RegistryArchiveIntegrityContract(unittest.TestCase):
    fixture_root = None

    def setUp(self):
        root = type(self).fixture_root
        if root is None:
            raise RuntimeError('ADMISSION_HOLD: reviewed fresh root-owned POSIX fixture root required')
        if os.name != 'posix' or os.getuid() != 0:
            raise RuntimeError('ADMISSION_HOLD: root registry integrity fixture identity required')
        self.temp = tempfile.TemporaryDirectory(prefix='registry-integrity-', dir=root)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.archive = self.base/'cache'/'fixture-registry'/'proof-1.0.0.crate'
        self.source = self.base/'src'/'fixture-registry'/'proof-1.0.0'
        self.archive.parent.mkdir(parents=True)
        (self.source/'src').mkdir(parents=True)
        (self.source/'empty').mkdir()
        (self.source/'Cargo.toml').write_bytes(b'[package]\nname="proof"\nversion="1.0.0"\n')
        (self.source/'src/lib.rs').write_bytes(b'pub const PROOF: u8 = 7;\n')
        (self.source/'.cargo-ok').write_bytes(b'{"v":1}')
        self.entries = [('proof-1.0.0/Cargo.toml',b'0',(self.source/'Cargo.toml').read_bytes()),
                        ('proof-1.0.0/src/lib.rs',b'0',(self.source/'src/lib.rs').read_bytes()),
                        ('proof-1.0.0/empty/',b'5',b'')]
        self.write_archive(archive_payload(self.entries))

    def write_archive(self, payload, checksum=None):
        raw = gzip.compress(payload, mtime=0)
        self.archive.write_bytes(raw)
        self.package = {'name':'proof','version':'1.0.0',
                        'source':'registry+https://github.com/rust-lang/crates.io-index',
                        'checksum':checksum if checksum is not None else hashlib.sha256(raw).hexdigest()}

    def verify(self):
        return provenance.verify_registry_archive(self.archive,self.source,self.package)

    def refusal(self, reason, **expected):
        with self.assertRaises(provenance.RegistryIntegrityHold) as caught:
            self.verify()
        prefix = 'REGISTRY_INTEGRITY_HOLD: ' + reason + ' '
        text = str(caught.exception)
        self.assertTrue(text.startswith(prefix), text)
        context = json.loads(text[len(prefix):])
        for key, value in expected.items():
            self.assertEqual(context[key], value)

    def test_literal_valid_archive_has_exact_existing_files_and_dirs(self):
        result = self.verify()
        self.assertEqual(result['archive_sha256'],self.package['checksum'])
        self.assertEqual(set(result['tree']),{'','Cargo.toml','src','src/lib.rs','empty','.cargo-ok'})
        self.assertEqual([(p,r['bytes'],r['sha256']) for p,r in result['tree'].items() if r['kind']=='file'],
                         [(p,len(data),hashlib.sha256(data).hexdigest()) for p,data in [('.cargo-ok',b'{"v":1}'),('Cargo.toml',b'[package]\nname="proof"\nversion="1.0.0"\n'),('src/lib.rs',b'pub const PROOF: u8 = 7;\n')]])

    def test_gnu_regular_header_and_actual_mode_mtime_differences_are_accepted(self):
        blocks = b''
        for name,kind,content in self.entries:
            blocks += header(name,kind,len(content),mode=0o755,magic=b'ustar  \x00') + content + b'\0' *((-len(content))%512)
        self.write_archive(blocks+b'\0'*1024)
        os.chmod(self.source/'src/lib.rs',0o600)
        os.utime(self.source/'src/lib.rs',(99,99))
        self.assertEqual(self.verify()['tree']['src/lib.rs']['sha256'],hashlib.sha256(b'pub const PROOF: u8 = 7;\n').hexdigest())

    def test_same_length_source_byte_change_is_refused(self):
        (self.source/'src/lib.rs').write_bytes(b'pub const PROOF: u8 = 8;\n')
        self.refusal('archive file bytes',package='proof-1.0.0',path='src/lib.rs')

    def test_missing_source_file_is_refused(self):
        (self.source/'src/lib.rs').unlink()
        self.refusal('exact tree inventory',package='proof-1.0.0',missing=['src/lib.rs'],unexpected=[])

    def test_unexpected_source_file_is_refused(self):
        (self.source/'unowned-extra.rs').write_bytes(b'pub const EXTRA: u8 = 1;\n')
        self.refusal('exact tree inventory',package='proof-1.0.0',missing=[],unexpected=['unowned-extra.rs'])

    def test_unexpected_empty_directory_is_refused(self):
        (self.source/'unowned-empty').mkdir()
        self.refusal('exact tree inventory',package='proof-1.0.0',missing=[],unexpected=['unowned-empty'])

    def test_generated_marker_literal_bytes_are_required(self):
        (self.source/'.cargo-ok').write_bytes(b'{"v":2}')
        self.refusal('archive file bytes',package='proof-1.0.0',path='.cargo-ok')

    def test_archive_checksum_mismatch_is_refused(self):
        self.package['checksum']='0'*64
        self.refusal('Cargo.lock archive checksum',package='proof-1.0.0',archive=str(self.archive))

    def test_wrong_package_prefix_is_refused_after_authenticating_crafted_bytes(self):
        self.write_archive(archive_payload([('decoy-1.0.0/Cargo.toml',b'0',b'decoy')]))
        self.refusal('package prefix',path='decoy-1.0.0/Cargo.toml',expected='proof-1.0.0')

    def test_dot_and_parent_path_aliases_are_refused(self):
        for name in ('proof-1.0.0/./src/lib.rs','proof-1.0.0/../outside'):
            with self.subTest(path=name):
                self.write_archive(archive_payload([(name,b'0',b'x')]))
                self.refusal('empty/dot/parent path',path=name)

    def test_duplicate_archive_path_is_refused(self):
        self.write_archive(archive_payload(self.entries+[self.entries[1]]))
        self.refusal('duplicate archive path',package='proof-1.0.0',path='src/lib.rs')

    def test_file_used_as_ancestor_is_refused(self):
        self.write_archive(archive_payload([('proof-1.0.0/src',b'0',b'x'),('proof-1.0.0/src/lib.rs',b'0',b'y')]))
        self.refusal('file used as ancestor',package='proof-1.0.0',path='src')

    def test_links_sparse_and_extension_headers_are_explicitly_unsupported(self):
        for kind in (b'1',b'2',b'S',b'x',b'g',b'L',b'K',b'3',b'6'):
            with self.subTest(type=kind.hex()):
                self.write_archive(archive_payload([('proof-1.0.0/link',kind,b'')]))
                self.refusal('archive entry type unsupported',package='proof-1.0.0',type_hex=kind.hex())

    def test_archived_cargo_markers_are_skipped_without_creating_directories(self):
        extras=[('proof-1.0.0/.cargo-ok',b'0',b'not the generated marker'),
                ('proof-1.0.0/unmaterialized/.cargo-ok',b'0',b'ignored nested marker'),
                ('proof-1.0.0/also-unmaterialized/.cargo-ok/',b'5',b'')]
        self.write_archive(archive_payload(self.entries+extras))
        result=self.verify()
        self.assertEqual(set(result['tree']),{'','Cargo.toml','src','src/lib.rs','empty','.cargo-ok'})
        self.assertEqual([(r['path'],r['bytes'],r['sha256']) for r in result['ignored_archive_cargo_ok_entries']],
                         [(name.removeprefix('proof-1.0.0/').rstrip('/'),len(data),hashlib.sha256(data).hexdigest()) for name,kind,data in extras])

    def test_compressed_archive_physical_size_is_bounded(self):
        with self.archive.open('r+b') as archive:
            archive.truncate(provenance.COMPRESSED_LIMIT+1)
        self.refusal('file size bound',path=str(self.archive),bytes=provenance.COMPRESSED_LIMIT+1,ceiling=provenance.COMPRESSED_LIMIT)

    def test_actual_tree_bytes_are_bounded_before_reading_all_files(self):
        for index in range(5):
            with (self.source/('large-'+str(index))).open('wb') as file:
                file.truncate(provenance.FILE_LIMIT)
        with self.assertRaises(provenance.RegistryIntegrityHold) as caught:
            self.verify()
        prefix='REGISTRY_INTEGRITY_HOLD: actual tree byte bound '
        self.assertTrue(str(caught.exception).startswith(prefix),str(caught.exception))
        context=json.loads(str(caught.exception)[len(prefix):])
        self.assertIn(context['path'],['large-'+str(index) for index in range(5)])
        self.assertGreater(context['bytes'],provenance.EXPANDED_LIMIT)
        self.assertEqual(context['aggregate'],context['bytes'])

    def test_header_checksum_corruption_is_refused_with_bound_archive_checksum(self):
        payload=bytearray(archive_payload(self.entries))
        payload[100]^=1
        self.write_archive(bytes(payload))
        self.refusal('tar header checksum',package='proof-1.0.0',ordinal=1)

    def test_declared_file_bound_refuses_before_payload_read(self):
        payload=header('proof-1.0.0/large',size=provenance.FILE_LIMIT+1)+b'\0'*1024
        self.write_archive(payload)
        self.refusal('archive file bound',package='proof-1.0.0',path='large',bytes=provenance.FILE_LIMIT+1)

    def test_truncated_tar_refuses_specific_missing_terminator(self):
        self.write_archive(archive_payload(self.entries,terminator=False))
        self.refusal('truncated tar stream',remaining=512)

    def test_nonzero_trailing_decompressed_bytes_are_refused(self):
        self.write_archive(archive_payload(self.entries)+b'UNEXPECTED_TRAILING_PAYLOAD')
        self.refusal('nonzero trailing tar stream',package='proof-1.0.0')

    def test_actual_source_symlink_is_refused_without_following_target(self):
        file=self.source/'src/lib.rs';file.unlink();file.symlink_to(self.source/'Cargo.toml')
        self.refusal('actual tree link unsupported',path='src/lib.rs')

    def test_actual_source_hardlink_is_refused(self):
        os.link(self.source/'src/lib.rs',self.base/'hardlink-outside-source')
        self.refusal('actual hardlinked file unsupported',path=str(self.source/'src/lib.rs'),links=2)

    def postrun_snapshot(self):
        verified=self.verify()
        roots=[self.source.parent,self.archive.parent]
        hash_file=lambda path,ceiling=512*1024**2: provenance.file_observation(path,ceiling)['sha256']
        snapshot={'roots':{str(root):provenance.collect_tree(root,hash_file) for root in roots},
                  'locked_registry_checksums':[{'verification':verified}]}
        return snapshot,roots,hash_file

    def test_unchanged_real_postrun_tree_is_accepted(self):
        snapshot,roots,hash_file=self.postrun_snapshot()
        self.assertEqual(snapshot['locked_registry_checksums'][0]['verification']['tree']['src/lib.rs']['sha256'],
                         hashlib.sha256(b'pub const PROOF: u8 = 7;\n').hexdigest())
        self.assertIsNone(provenance.verify(snapshot,roots,hash_file))

    def test_postrun_empty_directory_addition_is_refused(self):
        snapshot,roots,hash_file=self.postrun_snapshot()
        (self.source/'postrun-empty').mkdir()
        with self.assertRaises(provenance.RegistryIntegrityHold) as caught:
            provenance.verify(snapshot,roots,hash_file)
        prefix='REGISTRY_INTEGRITY_HOLD: exact tree inventory '
        self.assertTrue(str(caught.exception).startswith(prefix),str(caught.exception))
        self.assertEqual(json.loads(str(caught.exception)[len(prefix):]),
                         {'package':'proof-1.0.0','missing':[],'unexpected':['postrun-empty']})

    def test_postrun_file_byte_drift_hits_preserved_full_root_check(self):
        snapshot,roots,hash_file=self.postrun_snapshot()
        (self.source/'src/lib.rs').write_bytes(b'pub const PROOF: u8 = 8;\n')
        with self.assertRaisesRegex(AssertionError,'^provider/dependency closure changed$'):
            provenance.verify(snapshot,roots,hash_file)

    def test_physical_headers_including_skipped_bookkeeping_are_bounded(self):
        with self.archive.open('wb') as raw:
            with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as gz:
                gz.write(archive_payload(self.entries,terminator=False))
                for index in range(provenance.HEADER_LIMIT-len(self.entries)+1):
                    gz.write(header('proof-1.0.0/skipped'+str(index)+'/.cargo-ok'))
                gz.write(b'\0'*1024)
        self.package['checksum']=hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.refusal('physical header bound',package='proof-1.0.0',ordinal=provenance.HEADER_LIMIT+1)

    def write_zero_tail(self, total):
        payload=archive_payload(self.entries)
        with self.archive.open('wb') as raw:
            with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as gz:
                gz.write(payload)
                remaining=total-len(payload)
                while remaining:
                    amount=min(remaining,provenance.READ_CHUNK)
                    gz.write(b'\0'*amount)
                    remaining-=amount
        self.package['checksum']=hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_actual_decompression_including_zero_trailer_is_bounded(self):
        self.write_zero_tail(provenance.EXPANDED_LIMIT+provenance.READ_CHUNK)
        self.refusal('actual expanded stream bound')

    def test_aggregate_counts_genuine_scans_across_archives(self):
        self.write_zero_tail(provenance.EXPANDED_LIMIT)
        budget={'expanded':0}
        for index in range(provenance.AGGREGATE_LIMIT//provenance.EXPANDED_LIMIT):
            result=provenance.verify_registry_archive(self.archive,self.source,self.package,budget)
            self.assertEqual(result['expanded_bytes'],provenance.EXPANDED_LIMIT)
            self.assertEqual(budget['expanded'],(index+1)*provenance.EXPANDED_LIMIT)
        with self.assertRaises(provenance.RegistryIntegrityHold) as caught:
            provenance.verify_registry_archive(self.archive,self.source,self.package,budget)
        prefix='REGISTRY_INTEGRITY_HOLD: actual expanded stream bound '
        self.assertTrue(str(caught.exception).startswith(prefix))
        context=json.loads(str(caught.exception)[len(prefix):])
        self.assertEqual(context,{'expanded':512,'aggregate':provenance.AGGREGATE_LIMIT+512})


class RegistryActiveClosureContract(unittest.TestCase):
    context = None

    def setUp(self):
        context=type(self).context
        if context is None:
            raise RuntimeError('ADMISSION_HOLD: genuine owned itoa Cargo metadata, baseline and lock context required')
        metadata_path,baseline=context
        self.baseline=Path(baseline)
        if hashlib.sha256((self.baseline/'Cargo.lock').read_bytes()).hexdigest()!='e0707b92546ce332a3732c0ae1465745fcc91f40a5b236ac7b3a36b9f87d6581':
            raise RuntimeError('ADMISSION_HOLD: unchanged genuine fixture lock required')
        self.metadata=json.loads(Path(metadata_path).read_bytes())
        self.lock=tomllib.loads((self.baseline/'Cargo.lock').read_text())
        self.assertEqual(len(self.metadata['packages']),2)
        self.assertEqual({r['name'] for r in self.metadata['packages']},{'omg-provenance-contract','itoa'})

    def active(self):
        return provenance.active_locked_registry(self.metadata,self.lock,self.baseline)

    def refusal(self, reason, **expected):
        with self.assertRaises(provenance.RegistryIntegrityHold) as caught:
            self.active()
        prefix='REGISTRY_INTEGRITY_HOLD: '+reason+' '
        self.assertTrue(str(caught.exception).startswith(prefix),str(caught.exception))
        context=json.loads(str(caught.exception)[len(prefix):])
        for key,value in expected.items():
            self.assertEqual(context[key],value)

    def test_real_two_package_graph_joins_exact_lock_and_checksum(self):
        active,closure=self.active()
        self.assertEqual([(p['name'],p['version'],p['checksum']) for p in active],
                         [('itoa','1.0.17','92ecc6618181def0457392ccd0ee51198e065e016d1d527a7ac1b6dc7c1f09d2')])
        self.assertEqual((closure['active_packages'],closure['active_registry'],closure['active_local'],closure['inactive_lock_packages']),(2,1,1,0))

    def test_inactive_git_lock_entry_is_qualified_not_active(self):
        self.lock['package'].append({'name':'inactive-arch-control','version':'0.1.0','source':'git+https://example.invalid/arch#'+'a'*40})
        active,closure=self.active()
        self.assertEqual(len(active),1)
        self.assertEqual(closure['inactive_lock_tuples'],[['inactive-arch-control','0.1.0','git+https://example.invalid/arch#'+'a'*40]])
        self.assertTrue(closure['inactive_sources_not_integrity_verified'])

    def test_duplicate_metadata_id_is_refused(self):
        self.metadata['packages'].append(copy.deepcopy(self.metadata['packages'][0]))
        self.refusal('metadata duplicate/missing IDs')

    def test_unknown_dependency_id_is_refused(self):
        root=self.metadata['resolve']['root']
        node=next(n for n in self.metadata['resolve']['nodes'] if n['id']==root)
        node['dependencies'].append('unknown-dependency-id')
        node['deps'].append({'name':'unknown','pkg':'unknown-dependency-id','dep_kinds':[]})
        self.refusal('unknown dependency ID',id='unknown-dependency-id')

    def test_dependency_id_representations_must_agree(self):
        root=self.metadata['resolve']['root']
        node=next(n for n in self.metadata['resolve']['nodes'] if n['id']==root)
        node['deps']=[]
        self.refusal('dependency ID representations',id=root)

    def test_active_git_source_refuses_after_exact_tuple_join(self):
        package=next(p for p in self.metadata['packages'] if p['name']=='itoa')
        package['source']='git+https://example.invalid/active#'+'b'*40
        locked=next(p for p in self.lock['package'] if p['name']=='itoa')
        locked['source']=package['source']
        self.refusal('active source kind/registry unsupported',id=package['id'],source=package['source'])

    def test_missing_active_lock_tuple_is_refused(self):
        package=next(p for p in self.metadata['packages'] if p['name']=='itoa')
        self.lock['package']=[p for p in self.lock['package'] if p['name']!='itoa']
        self.refusal('active graph exact lock join',id=package['id'])

    def test_missing_active_checksum_is_refused(self):
        package=next(p for p in self.metadata['packages'] if p['name']=='itoa')
        next(p for p in self.lock['package'] if p['name']=='itoa').pop('checksum')
        self.refusal('locked registry checksum',id=package['id'])

"""Real provider observations and bounded locked registry archive/tree integrity."""
import gzip, hashlib, json, os, stat, tomllib, zlib
from pathlib import Path

COMPRESSED_LIMIT = 256 * 1024**2
EXPANDED_LIMIT = 1024**3
FILE_LIMIT = 256 * 1024**2
HEADER_LIMIT = 65536
NODE_LIMIT = 65536
PATH_LIMIT = 4096
AGGREGATE_LIMIT = 8 * 1024**3
READ_CHUNK = 128 * 1024


class RegistryIntegrityHold(RuntimeError):
    """Unsupported format, source drift, integrity mismatch or resource refusal."""


def demand(value, reason, **context):
    if not value:
        raise RegistryIntegrityHold('REGISTRY_INTEGRITY_HOLD: ' + reason + ' ' + json.dumps(context, sort_keys=True))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def protected(path, directory=False):
    info = path.lstat()
    demand(not stat.S_ISLNK(info.st_mode), 'symlink node unsupported', path=str(path))
    demand(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
           'unexpected node type', path=str(path), mode=info.st_mode)
    demand(info.st_uid == 0 and not info.st_mode & 0o022,
           'node ownership/mode', path=str(path), uid=info.st_uid, mode=info.st_mode)
    if not directory:
        demand(info.st_nlink == 1, 'actual hardlinked file unsupported', path=str(path), links=info.st_nlink)
    return info


def protected_ancestors(path):
    return [(str(parent), identity(protected(parent, directory=True)))
            for parent in reversed(path.parents)]


def unchanged_ancestors(rows):
    for path, expected in rows:
        demand(identity(protected(Path(path), directory=True)) == expected,
               'ancestor drift', path=path)


def file_observation(path, ceiling=FILE_LIMIT):
    ancestors = protected_ancestors(path)
    before = protected(path)
    demand(before.st_size <= ceiling, 'file size bound', path=str(path), bytes=before.st_size, ceiling=ceiling)
    demand(hasattr(os, 'O_NOFOLLOW'), 'O_NOFOLLOW unavailable', path=str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    size = 0
    try:
        demand(identity(os.fstat(fd)) == identity(before), 'opened file identity', path=str(path))
        while True:
            block = os.read(fd, READ_CHUNK)
            if not block:
                break
            size += len(block)
            demand(size <= ceiling, 'file grew beyond bound', path=str(path), bytes=size)
            digest.update(block)
        demand(size == before.st_size and identity(os.fstat(fd)) == identity(before),
               'file changed while reading', path=str(path))
    finally:
        os.close(fd)
    demand(identity(protected(path)) == identity(before), 'file path drift', path=str(path))
    unchanged_ancestors(ancestors)
    return {'bytes': size, 'sha256': digest.hexdigest(), 'identity': list(identity(before))}


def path_components(name, prefix, is_directory, ordinal):
    demand(len(name.encode('utf-8')) <= PATH_LIMIT, 'path size bound', ordinal=ordinal, path=name)
    demand(not any(ord(c) < 32 or ord(c) == 127 for c in name), 'control path', ordinal=ordinal, path=name)
    demand('\\' not in name and ':' not in name and not name.startswith('/'),
           'absolute/alias path', ordinal=ordinal, path=name)
    if is_directory and name.endswith('/'):
        name = name[:-1]
    components = name.split('/')
    demand(all(c and c not in ('.', '..') for c in components),
           'empty/dot/parent path', ordinal=ordinal, path=name)
    demand(components[0] == prefix, 'package prefix', ordinal=ordinal, path=name, expected=prefix)
    demand(len(components) > 1 or is_directory, 'top-level package is not directory', ordinal=ordinal, path=name)
    return '/'.join(components[1:])


def tar_text(field, label, ordinal):
    raw, separator, padding = field.partition(b'\0')
    demand(not separator or not any(padding), 'embedded NUL path alias', field=label, ordinal=ordinal)
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise RegistryIntegrityHold('REGISTRY_INTEGRITY_HOLD: non-UTF8 tar path ' + str(ordinal)) from error


def octal(field, label, ordinal):
    trimmed = field.strip(b'\0 ')
    demand(all(48 <= c <= 55 for c in trimmed), 'non-octal/base256 field unsupported', field=label, ordinal=ordinal)
    return int(trimmed or b'0', 8)


class ExpandedReader:
    def __init__(self, stream, budget):
        self.stream = stream
        self.budget = budget
        self.total = 0

    def read(self, amount):
        demand(0 < amount <= READ_CHUNK, 'internal read bound', amount=amount)
        block = self.stream.read(amount)
        self.total += len(block)
        self.budget['expanded'] += len(block)
        demand(self.total <= EXPANDED_LIMIT and self.budget['expanded'] <= AGGREGATE_LIMIT,
               'actual expanded stream bound', expanded=self.total, aggregate=self.budget['expanded'])
        return block

    def exact(self, amount):
        chunks = []
        remaining = amount
        while remaining:
            block = self.read(min(remaining, READ_CHUNK))
            demand(block, 'truncated tar stream', remaining=remaining)
            chunks.append(block)
            remaining -= len(block)
        return b''.join(chunks)


def actual_tree(root, budget=None):
    rows = {}
    directories = []
    pending = [('', root)]
    total_bytes = 0
    if budget is None:
        budget = {'tree_read_bytes': 0}
    budget.setdefault('tree_read_bytes', 0)
    while pending:
        relative, directory = pending.pop()
        before = identity(protected(directory, directory=True))
        directories.append((str(directory), before))
        rows[relative] = {'kind': 'directory', 'identity': list(before)}
        with os.scandir(directory) as entries:
            for entry in entries:
                key = relative + '/' + entry.name if relative else entry.name
                demand(len(key.encode('utf-8')) <= PATH_LIMIT and '\\' not in key and ':' not in key
                       and not any(ord(c) < 32 or ord(c) == 127 for c in key), 'actual path unsupported', path=key)
                info = entry.stat(follow_symlinks=False)
                demand(not stat.S_ISLNK(info.st_mode), 'actual tree link unsupported', path=key)
                demand(key not in rows and len(rows) + len(pending) < NODE_LIMIT, 'actual node bound/duplicate', path=key)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((key, Path(entry.path)))
                else:
                    total_bytes += info.st_size
                    budget['tree_read_bytes'] += info.st_size
                    demand(total_bytes <= EXPANDED_LIMIT and budget['tree_read_bytes'] <= 2 * AGGREGATE_LIMIT,
                           'actual tree byte bound', path=key, bytes=total_bytes, aggregate=budget['tree_read_bytes'])
                    observation = file_observation(Path(entry.path), 1024 if key == '.cargo-ok' else FILE_LIMIT)
                    rows[key] = dict(observation, kind='file')
        demand(identity(protected(directory, directory=True)) == before, 'directory changed during scan', path=str(directory))
    unchanged_ancestors(directories)
    return dict(sorted(rows.items()))


def verify_registry_archive(archive, source, package, budget=None):
    """Read a checksum-authenticated tar.gz and compare an existing tree; never extract."""
    if budget is None:
        budget = {'expanded': 0}
    name, version, checksum = package['name'], package['version'], package['checksum']
    prefix = name + '-' + version
    demand(archive.parent.name == source.parent.name, 'registry namespace mismatch', package=prefix)
    demand(source.name == prefix and archive.name == prefix + '.crate', 'registry pair name', package=prefix)
    protected(source, directory=True)
    initial_tree = actual_tree(source, budget)
    archive_before = file_observation(archive, COMPRESSED_LIMIT)
    demand(archive_before['sha256'] == checksum, 'Cargo.lock archive checksum', package=prefix, archive=str(archive))
    expected = {'': {'kind': 'directory'}}
    explicit = set()
    ignored_bookkeeping = []
    ordinal = 0
    ancestors = protected_ancestors(archive)
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        demand(list(identity(os.fstat(fd))) == archive_before['identity'], 'archive opened identity', package=prefix)
        with os.fdopen(fd, 'rb', closefd=False) as raw:
            with gzip.GzipFile(fileobj=raw, mode='rb') as gz:
                reader = ExpandedReader(gz, budget)
                while True:
                    header = reader.exact(512)
                    ordinal += 1
                    demand(ordinal <= HEADER_LIMIT, 'physical header bound', package=prefix, ordinal=ordinal)
                    if header == b'\0' * 512:
                        demand(reader.exact(512) == b'\0' * 512, 'missing second tar terminator', package=prefix)
                        while True:
                            tail = reader.read(READ_CHUNK)
                            if not tail:
                                break
                            demand(not any(tail), 'nonzero trailing tar stream', package=prefix)
                        break
                    checksum_value = octal(header[148:156], 'checksum', ordinal)
                    demand(sum(header[:148]) + 8 * 32 + sum(header[156:]) == checksum_value,
                           'tar header checksum', package=prefix, ordinal=ordinal)
                    kind = header[156:157]
                    demand(kind in (b'0', b'\0', b'5'), 'archive entry type unsupported',
                           package=prefix, ordinal=ordinal, type_hex=kind.hex())
                    demand(not any(header[157:257]), 'link target on nonlink entry unsupported', package=prefix, ordinal=ordinal)
                    magic = header[257:265]
                    demand(magic in (b'ustar\x0000', b'ustar  \x00', b'\0' * 8),
                           'tar header dialect unsupported', package=prefix, ordinal=ordinal, magic_hex=magic.hex())
                    if magic == b'ustar  \x00':
                        demand(not any(header[386:495]), 'GNU sparse metadata unsupported', package=prefix, ordinal=ordinal)
                    rawname = tar_text(header[:100], 'name', ordinal)
                    if magic == b'ustar\x0000':
                        pref = tar_text(header[345:500], 'prefix', ordinal)
                        if pref:
                            rawname = pref + '/' + rawname
                    rel = path_components(rawname, prefix, kind == b'5', ordinal)
                    demand(rel not in explicit, 'duplicate archive path', package=prefix, ordinal=ordinal, path=rel)
                    explicit.add(rel)
                    size = octal(header[124:136], 'size', ordinal)
                    mode = octal(header[100:108], 'mode', ordinal)
                    demand(size <= FILE_LIMIT, 'archive file bound', package=prefix, ordinal=ordinal, path=rel, bytes=size)
                    if rel.split('/')[-1] == '.cargo-ok':
                        demand(kind != b'5' or size == 0, 'directory bookkeeping size', package=prefix, path=rel)
                        digest = hashlib.sha256()
                        remaining = size
                        while remaining:
                            block = reader.read(min(remaining, READ_CHUNK))
                            demand(block, 'truncated bookkeeping payload', package=prefix, path=rel)
                            digest.update(block)
                            remaining -= len(block)
                        padding = (-size) % 512
                        if padding:
                            demand(not any(reader.exact(padding)), 'nonzero bookkeeping padding unsupported', package=prefix, path=rel)
                        ignored_bookkeeping.append({'path': rel, 'ordinal': ordinal, 'type_hex': kind.hex(),
                                                    'bytes': size, 'sha256': digest.hexdigest(),
                                                    'Cargo1_95_behavior': 'skipped before unpack; no implied directory materialized'})
                        continue
                    for parent in list(Path(rel).parents)[:-1] if rel else []:
                        parent_key = parent.as_posix()
                        if parent_key == '.':
                            parent_key = ''
                        demand(parent_key not in expected or expected[parent_key]['kind'] == 'directory',
                               'file used as ancestor', package=prefix, path=parent_key)
                        expected.setdefault(parent_key, {'kind': 'directory'})
                    if kind == b'5':
                        demand(size == 0 and (rel not in expected or expected[rel]['kind'] == 'directory'),
                               'directory size/type collision', package=prefix, path=rel)
                        expected[rel] = {'kind': 'directory'}
                    else:
                        demand(rel not in expected, 'file/directory collision', package=prefix, path=rel)
                        digest = hashlib.sha256()
                        remaining = size
                        while remaining:
                            block = reader.read(min(remaining, READ_CHUNK))
                            demand(block, 'truncated file payload', package=prefix, path=rel)
                            digest.update(block)
                            remaining -= len(block)
                        expected[rel] = {'kind': 'file', 'bytes': size, 'sha256': digest.hexdigest(), 'archive_mode': mode}
                        padding = (-size) % 512
                        if padding:
                            demand(not any(reader.exact(padding)), 'nonzero file padding unsupported', package=prefix, path=rel)
                    demand(len(expected) <= NODE_LIMIT, 'archive effective node bound', package=prefix)
                expanded = reader.total
        demand(list(identity(os.fstat(fd))) == archive_before['identity'], 'archive changed during parse', package=prefix)
    except (OSError, EOFError, zlib.error) as error:
        raise RegistryIntegrityHold('REGISTRY_INTEGRITY_HOLD: compressed/tar I/O ' + prefix + ' ' + str(error)) from error
    finally:
        os.close(fd)
    expected['.cargo-ok'] = {'kind': 'file', 'bytes': 7, 'sha256': hashlib.sha256(b'{"v":1}').hexdigest()}
    tree = actual_tree(source, budget)
    demand(tree == initial_tree, 'source changed during verification', package=prefix)
    demand(set(tree) == set(expected), 'exact tree inventory', package=prefix,
           missing=sorted(set(expected) - set(tree)), unexpected=sorted(set(tree) - set(expected)))
    for rel, row in expected.items():
        demand(tree[rel]['kind'] == row['kind'], 'tree node type', package=prefix, path=rel)
        if row['kind'] == 'file':
            demand(tree[rel]['bytes'] == row['bytes'] and tree[rel]['sha256'] == row['sha256'],
                   'archive file bytes', package=prefix, path=rel)
    demand(file_observation(archive, COMPRESSED_LIMIT) == archive_before, 'archive path/content drift', package=prefix)
    unchanged_ancestors(ancestors)
    return {'name': name, 'version': version, 'source': package['source'], 'archive': str(archive),
            'source_directory': str(source), 'archive_sha256': checksum, 'archive_identity': archive_before,
            'tree': tree, 'expanded_bytes': expanded, 'physical_headers': ordinal,
            'ignored_archive_cargo_ok_entries': ignored_bookkeeping,
            'supported_domain': 'ordinary regular/directory V7/USTAR/GNU headers; extensions/links/sparse refuse',
            'bounds_are_proposed_runtime_admission_pending': True}


def active_locked_registry(metadata, lock, baseline):
    packages = metadata['packages']
    nodes = metadata['resolve']['nodes']
    by_id = {p['id']: p for p in packages}
    by_node = {n['id']: n for n in nodes}
    demand(len(by_id) == len(packages) and len(by_node) == len(nodes) and set(by_id) == set(by_node), 'metadata duplicate/missing IDs')
    root = metadata['resolve']['root']
    demand(root in by_id and metadata['workspace_default_members'] == [root], 'owning default root')
    demand(by_id[root]['source'] is None and Path(by_id[root]['manifest_path']).resolve() == (baseline/'Cargo.toml').resolve(), 'owning local manifest root')
    demand({'fedora', 'pgp', 'license'} <= set(by_node[root]['features']), 'owning feature selection')
    seen = set()
    pending = [root]
    while pending:
        node_id = pending.pop()
        if node_id in seen:
            continue
        demand(node_id in by_node, 'unknown dependency ID', id=node_id)
        seen.add(node_id)
        node = by_node[node_id]
        dependencies = node['dependencies']
        typed = [dep['pkg'] for dep in node['deps']]
        demand(len(dependencies) == len(set(dependencies)) and set(dependencies) == set(typed), 'dependency ID representations', id=node_id)
        pending.extend(dependencies)
    demand(seen == set(by_id), 'metadata packages outside owning graph')
    lock_rows = lock['package']
    lock_map = {(r['name'], r['version'], r.get('source')): r for r in lock_rows}
    demand(len(lock_map) == len(lock_rows), 'duplicate lock tuple')
    active = []
    active_keys = set()
    joins = []
    for node_id in sorted(seen):
        p = by_id[node_id]
        key = (p['name'], p['version'], p['source'])
        demand(key in lock_map and key not in active_keys, 'active graph exact lock join', id=node_id)
        active_keys.add(key)
        locked = lock_map[key]
        if p['source'] is None:
            demand(node_id == root, 'additional local source unsupported', id=node_id)
        else:
            demand(p['source'] == 'registry+https://github.com/rust-lang/crates.io-index', 'active source kind/registry unsupported', id=node_id, source=p['source'])
            checksum = locked.get('checksum')
            demand(isinstance(checksum, str) and len(checksum) == 64 and all(c in '0123456789abcdef' for c in checksum), 'locked registry checksum', id=node_id)
            active.append(locked)
        joins.append({'id': node_id, 'name': p['name'], 'version': p['version'], 'source': p['source'],
                      'checksum': locked.get('checksum'), 'features': by_node[node_id]['features']})
    inactive = [r for r in lock_rows if (r['name'], r['version'], r.get('source')) not in active_keys]
    return active, {'owning_root': root, 'active_packages': len(seen), 'active_registry': len(active),
                    'active_local': 1, 'lock_packages': len(lock_rows), 'inactive_lock_packages': len(inactive),
                    'active_joins': joins, 'inactive_lock_tuples': [list((r['name'], r['version'], r.get('source'))) for r in inactive],
                    'inactive_sources_not_integrity_verified': True}


def collect_tree(root,hash_file):
    rows=[]
    for p in sorted(root.rglob('*')):
        info=p.lstat()
        if p.is_symlink():
            target=p.resolve(strict=True)
            if target.is_dir():
                rows.append({'path':str(p),'link':os.readlink(p),'realpath':str(target),'kind':'directory_symlink','target_files':'covered only when separately under a captured root; external target retains attribution hold'})
                continue
            require=target.stat(); assert require.st_uid==0 and not require.st_mode&0o022
            rows.append({'path':str(p),'link':os.readlink(p),'realpath':str(target),'sha256':hash_file(target,512*1024**2),'bytes':target.stat().st_size})
        else:
            if p.is_dir(): continue
            assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
            rows.append({'path':str(p),'realpath':str(p),'sha256':hash_file(p,512*1024**2),'bytes':info.st_size})
    return rows


def snapshot(out,provider,baseline,execute,env,hash_file,write):
    destination=out/'evidence/provider'; destination.mkdir()
    observations={}
    commands=[('rustc-verbose',[str(provider/'rustc'),'-vV']),('rustc-sysroot',[str(provider/'rustc'),'--print','sysroot']),('native-nevra',['/usr/bin/rpm','-qa','--qf','%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n']),('locked-fetch',[str(provider/'cargo'),'fetch','--locked','--manifest-path',str(baseline/'Cargo.toml')]),('cargo-metadata',[str(provider/'cargo'),'metadata','--locked','--offline','--no-default-features','--features','fedora,pgp,license','--filter-platform','x86_64-unknown-linux-gnu','--format-version','1','--manifest-path',str(baseline/'Cargo.toml')])]
    for name,argv in commands:
        code,stdout,stderr=execute(argv,baseline,env,destination/name,1200 if name=='locked-fetch' else 60)
        assert code==0
        observations[name]={'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest()}
        if name=='rustc-verbose': assert b'release: 1.95.0\n' in stdout and b'host: x86_64-unknown-linux-gnu\n' in stdout
        if name=='rustc-sysroot': assert Path(stdout.decode().strip()).resolve()==provider.parent.resolve()
        if name=='cargo-metadata': observations['metadata']=json.loads(stdout)
    lock_before = file_observation(baseline/'Cargo.lock')
    lock=tomllib.loads((baseline/'Cargo.lock').read_text())
    registry=Path(env['CARGO_HOME'])/'registry'
    active, closure = active_locked_registry(observations['metadata'], lock, baseline)
    checksum_rows=[]
    budget={'expanded': 0}
    for package in active:
        crate_name=package['name']+'-'+package['version']
        archives=list((registry/'cache').glob('*/'+crate_name+'.crate'))
        sources=list((registry/'src').glob('*/'+crate_name))
        demand(len(archives)==len(sources)==1, 'registry archive/source pair ambiguity', package=crate_name)
        verified=verify_registry_archive(archives[0],sources[0],package,budget)
        checksum_rows.append({'name':package['name'],'version':package['version'],
                              'archive_sha256':verified['archive_sha256'],'verification':verified})
    demand(file_observation(baseline/'Cargo.lock') == lock_before, 'Cargo.lock changed during snapshot')
    roots=[provider.parent,Path('/usr/lib64'),Path('/usr/include'),Path('/usr/bin'),registry/'src',registry/'cache']
    rows={str(root):collect_tree(root,hash_file) for root in roots}
    result={'status':'REAL_PROVIDER_CAPTURE_REQUIRES_INDEPENDENT_POSTRUN_ADMISSION','commands':observations,'cargo_lock_sha256':hash_file(baseline/'Cargo.lock'),'locked_registry_checksums':checksum_rows,'roots':rows,'closure_scope':'entire pinned Rust toolchain and native bin/lib64/header trees; actual installed NEVRA; active locked registry archive/tree integrity and all fetched Cargo sources/archives. Dynamic loader/plugin resolution outside these trees remains explicit attribution hold.',
            'active_lock_closure':closure,'registry_expanded_bytes':budget['expanded'],
            'archive_bounds_scope':'New conservative format/scan bounds require independent real compatibility/resource admission; exceeding or unsupported archives is HOLD, not integrity acceptance.'}
    write(destination/'provenance.json',result)
    return result,roots


def verify(snapshot,roots,hash_file):
    assert snapshot['roots']=={str(root):collect_tree(root,hash_file) for root in roots},'provider/dependency closure changed'
    budget={'expanded': 0}
    for row in snapshot['locked_registry_checksums']:
        saved=row['verification']
        package={'name':saved['name'],'version':saved['version'],'source':saved['source'],'checksum':saved['archive_sha256']}
        current=verify_registry_archive(Path(saved['archive']),Path(saved['source_directory']),package,budget)
        demand(current==saved, 'postrun registry archive/tree changed', package=saved['name']+'-'+saved['version'])

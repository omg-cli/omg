"""Real provider and locked registry observations; independent artifact review still required."""
import hashlib, json, os, stat, tomllib
from pathlib import Path
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
    lock=tomllib.loads((baseline/'Cargo.lock').read_text())
    registry=Path(env['CARGO_HOME'])/'registry'
    checksum_rows=[]
    for package in lock['package']:
        if 'source' not in package: continue
        assert package['source'].startswith('registry+') and 'checksum' in package,'unsupported locked external source'
        crate_name=package['name']+'-'+package['version']
        archives=list((registry/'cache').glob('*/'+crate_name+'.crate'))
        sources=list((registry/'src').glob('*/'+crate_name))
        assert len(archives)==len(sources)==1
        archive_sha=hash_file(archives[0],256*1024**2); assert archive_sha==package['checksum']
        checksum=json.loads((sources[0]/'.cargo-checksum.json').read_bytes())
        assert checksum['package']==package['checksum']
        for name,expected in checksum['files'].items():
            p=(sources[0]/name).resolve(); assert p.is_relative_to(sources[0].resolve()) and hash_file(p,256*1024**2)==expected
        checksum_rows.append({'name':package['name'],'version':package['version'],'archive_sha256':archive_sha,'source_checksum_sha256':hash_file(sources[0]/'.cargo-checksum.json')})
    roots=[provider.parent,Path('/usr/lib64'),Path('/usr/include'),Path('/usr/bin'),registry/'src',registry/'cache']
    rows={str(root):collect_tree(root,hash_file) for root in roots}
    result={'status':'REAL_PROVIDER_CAPTURE_REQUIRES_INDEPENDENT_POSTRUN_ADMISSION','commands':observations,'cargo_lock_sha256':hash_file(baseline/'Cargo.lock'),'locked_registry_checksums':checksum_rows,'roots':rows,'closure_scope':'entire pinned Rust toolchain and native bin/lib64/header trees; actual installed NEVRA; locked fetched Cargo sources/archives. Dynamic loader/plugin resolution outside these trees remains explicit attribution hold.'}
    write(destination/'provenance.json',result)
    return result,roots
def verify(snapshot,roots,hash_file):
    assert snapshot['roots']=={str(root):collect_tree(root,hash_file) for root in roots},'provider/dependency closure changed'

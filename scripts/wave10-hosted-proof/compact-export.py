import hashlib, json, os, stat
from pathlib import Path
base=Path(os.environ['WAVE10_BASE']);dest=Path(os.environ['RUNNER_TEMP'])/('wave10-compact-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT'])
dest.mkdir(exist_ok=False)
cap=64*1024**2;limit=4*1024**2;total=0;seen=0;file_count=0;copied=[];holds=[]
stack=[(base/'context',Path('context'),0),(base/'evidence',Path('evidence'),0)]
while stack:
    root,relative,depth=stack.pop()
    if not root.exists():holds.append(str(relative)+':absent');continue
    if root.is_symlink() or not root.is_dir():holds.append(str(relative)+':not-directory');continue
    with os.scandir(root) as entries:
        for entry in entries:
            seen+=1
            if seen>1024:holds.append('entry-count-cap');stack.clear();break
            path=Path(entry.path);rel=relative/entry.name;meta=entry.stat(follow_symlinks=False)
            if len(str(rel))>512 or depth>8:holds.append(str(rel)[:512]+':path-bound');continue
            if stat.S_ISDIR(meta.st_mode):stack.append((path,rel,depth+1));continue
            file_count+=1
            if file_count>600:holds.append('file-count-cap');stack.clear();break
            allowed=path.suffix in ['.json','.jsonl','.stdout','.stderr','.log','.txt'] or (relative == Path('context') and path.name in ['runner.py','bind-runtime.py']) or path.name in ['stdout','stderr']
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or not allowed:holds.append(str(rel)+':not-allowed-data-file');continue
            if meta.st_size>limit or total+meta.st_size>cap-1048576:holds.append(str(rel)+':byte-cap');continue
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:data=stream.read(limit+1)
            if len(data)!=meta.st_size or len(data)>limit:holds.append(str(rel)+':changed-or-cap');continue
            target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            total+=len(data);copied.append({'path':str(rel),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
result={'state':'BOUNDED_COMPACT_EXPORT' if not holds else 'HOLD_PARTIAL_COMPACT_EXPORT','files':copied,'holds':holds,'raw_bytes':total,'entry_count':seen,'limit_bytes':cap,'binary_cache_target_included':False}
manifest=(json.dumps(result,indent=2)+'\n').encode()
if len(manifest)>1048576:
    holds.append('manifest-byte-cap');result={'state':'HOLD_EXPORT_MANIFEST_CAP','raw_bytes':total,'files_copied':len(copied)}
    manifest=(json.dumps(result)+'\n').encode()
(dest/'export.json').write_bytes(manifest)
print(json.dumps({'state':result['state'],'files':len(copied),'bytes':total,'holds':holds}))
if holds:raise SystemExit(1)

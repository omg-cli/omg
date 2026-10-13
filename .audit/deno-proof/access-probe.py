import json, os, sys
from pathlib import Path
assert os.getuid()>0 and os.getgid()>0 and os.getgroups()==[]
source,binary,home,tmp=map(Path,sys.argv[1:])
for p in [source,binary,home,tmp]:
    for parent in p.parents: assert os.access(parent,os.X_OK)
assert source.open('rb').read(1)
assert binary.open('rb').read(4)==b'\x7fELF'
assert os.access(binary,os.X_OK)
for p in (home,tmp):
    fixture=p/'ordinary-access-probe'
    with fixture.open('xb') as stream: stream.write(b'actual ordinary filesystem probe\n')
    assert fixture.read_bytes()==b'actual ordinary filesystem probe\n'
    fixture.unlink()
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'source':str(source),'binary':str(binary),'home':str(home),'tmp':str(tmp),'actual_read_write_traversal':True}))

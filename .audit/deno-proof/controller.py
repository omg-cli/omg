"""Future Fedora-only real Deno proof. Source preparation does not authorize execution."""
import ctypes
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKAGE))
import runtime
import provenance
PREFIX = 'runtimes::deno::tests::'
def interrupted(signum, frame):
    runtime.latch(signum, frame)

def digest(data): return hashlib.sha256(data).hexdigest()
def load(path): return json.loads(path.read_bytes())
def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
def require(value, message):
    if not value: raise RuntimeError('HARNESS_ERROR: ' + message)
def process_table():
    rows = {}
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal(): continue
        try:
            fields = (item/'stat').read_text().rsplit(')', 1)[1].split()
            uid = (item/'status').read_text().split('Uid:', 1)[1].split()[0]
        except FileNotFoundError: continue
        rows[int(item.name)] = {'pid':int(item.name),'ppid':int(fields[1]),'group':int(fields[2]),
                               'session':int(fields[3]),'start_ticks':int(fields[19]),'state':fields[0],'uid':int(uid)}
    return rows
def descendants():
    table = process_table()
    parents = {os.getpid()}
    while True:
        additions = {pid for pid, row in table.items() if row['ppid'] in parents} - parents
        if not additions: break
        parents.update(additions)
    return [table[pid] for pid in sorted(parents - {os.getpid()})]
def identity_alive(row):
    current = process_table().get(row['pid'])
    return current is not None and current['start_ticks'] == row['start_ticks']
def tree_snapshot(root):
    rows = []
    for p in sorted(root.rglob('*')):
        require(not p.is_symlink(), 'unexpected symlink in private source')
        if p.is_file(): rows.append({'path':p.relative_to(root).as_posix(),'bytes':p.stat().st_size,'sha256':runtime.digest_file(p)})
    return rows
def execute(*args, **kwargs):
    return runtime.execute(*args, **kwargs)


def tool(path):
    candidate = Path(path)
    require(candidate.is_absolute(), 'absolute direct provider required')
    resolved = candidate.resolve(strict=True)
    ancestors = []
    for item in dict.fromkeys([candidate, *candidate.parents, resolved, *resolved.parents]):
        info = item.lstat()
        require(info.st_uid == 0 and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022), 'provider ancestry ownership/mode changed')
        ancestors.append({'path':str(item),'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'uid':info.st_uid,'link':os.readlink(item) if item.is_symlink() else None})
    info = resolved.stat()
    require(stat.S_ISREG(info.st_mode) and os.access(resolved,os.X_OK), 'direct regular executable required')
    with resolved.open('rb') as stream:
        require(stream.read(4) == b'\x7fELF', 'direct ELF provider required')
    return {'candidate':str(candidate),'path':str(resolved),'sha256':runtime.digest_file(resolved,512*1024**2),'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'ancestry':ancestors}

def check_tools(records):
    for record in records: require(tool(record['candidate']) == record, 'provider changed')
def listing(binary, ids, cwd, env, output, identity):
    code, stdout, stderr = execute([str(binary),'--list','--format','terse'],cwd,env,output,30,identity)
    require(code == 0 and not stderr, 'compiler executable listing failed')
    rows = stdout.decode().splitlines()
    selected = [line[:-6] for line in rows if line.startswith(PREFIX) and line.endswith(': test')]
    require(len(selected) == len(ids) and set(selected) == set(ids), 'complete compiled Deno identity set mismatch')
    return {'binary_sha256':runtime.digest_file(binary),'selected':selected,'all_listing_sha256':digest(stdout),
            'all_compiled_entries':sum(line.endswith((': test',': benchmark')) for line in rows)}
def outcomes(stdout, stderr, ids, expected_failures, all_compiled_entries):
    text = stdout.decode() + '\n' + stderr.decode()
    matched = re.findall(r'^test (runtimes::deno::tests::\S+) \.\.\. (ok|FAILED|ignored)$',text,re.M)
    require(len(matched) == len(ids) and {n for n,s in matched} == set(ids), 'missing/duplicate named test results')
    failures = {n for n,s in matched if s == 'FAILED'}
    require(failures == set(expected_failures) and all(s in ('ok','FAILED') for n,s in matched), 'unexpected failure or skip')
    passed = len(ids)-len(failures)
    summary = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',text,re.M)
    require(len(summary) == 1 and summary[0][1:5] == (str(passed),str(len(failures)),'0','0'), 'strict summary mismatch')
    require(summary[0][0] == ('FAILED' if failures else 'ok'), 'summary status mismatch')
    require(int(summary[0][5]) == all_compiled_entries-len(ids), 'compiled filtered-out count mismatch')
    for name in expected_failures:
        # Match each real libtest failure section rather than globally finding panic text.
        header = '---- ' + name + ' stdout ----\n'
        require(text.count(header) == 1, 'missing exact failed method trace')
        section = text.split(header,1)[1].split('\n---- ',1)[0].split('\nfailures:',1)[0]
        require('assertion `left == right` failed' in section and 'left: "2.2.0"' in section and 'right: "2.2.0-rc.1"' in section, 'wrong RED assertion reason')
        require('must finish' not in section and 'must succeed' not in section, 'timeout/setup is not RED')
    return {'named_results':matched,'summary':summary[0],'expected_failures':list(expected_failures)}

def main():
    manifest = load(PACKAGE/'manifest.json')
    require(digest(Path(__file__).read_bytes()) == manifest['controller_sha256'], 'controller source changed')
    for name, expected in manifest['package_inputs'].items():
        require(digest((PACKAGE/name).read_bytes()) == expected, 'package input changed')
    admission = runtime.initialize(manifest)
    canonical = admission['manifest_sha256']
    require(os.getuid() == 0 and sys.platform == 'linux' and sys.version_info >= (3,11), 'Fedora root compiler/controller bootstrap required')
    signal.signal(signal.SIGTERM,interrupted)
    signal.signal(signal.SIGALRM,interrupted)
    signal.alarm(7800)
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0) == 0, 'subreaper unavailable')
    require(not descendants(), 'controller already owns children')
    identity = pwd.getpwnam('omg-deno-proof')
    require(identity.pw_uid > 0 and identity.pw_gid > 0, 'subjects must have nonroot UID/GID')
    out = Path(os.environ['RUNNER_TEMP'])/'deno-alias-proof'
    require(out.is_dir() and (out/'receipts').is_dir() and not (out/'receipts/evidence').exists(), 'fresh supervisor workspace required')
    evidence = out/'receipts/evidence'; evidence.mkdir()
    workspace = Path(os.environ['GITHUB_WORKSPACE'])
    provider = Path(os.environ['HOME'])/'.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin'
    records = [tool(provider/name) for name in ('cargo','rustc')]
    native_tools = [tool('/usr/bin/'+name) for name in ('git','cc','clang','pkg-config','cmake','ar','ld','python3')]
    require(shutil.disk_usage(out).free >= manifest['min_free_bytes'], 'private target resource floor unmet')
    mem = int(Path('/proc/meminfo').read_text().split('MemAvailable:',1)[1].split()[0])*1024
    require(mem >= manifest['min_available_memory_bytes'], 'memory resource floor unmet')
    base_env = {'PATH':str(provider)+':/usr/bin:/bin','HOME':str(out/'compiler-home'),'CARGO_HOME':str(out/'cargo-home'),
                'CARGO_TARGET_DIR':str(out/'target'),'RUSTC':records[1]['path'],'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0',
                'CARGO_TERM_COLOR':'never','RUST_BACKTRACE':'0','LANG':'C.UTF-8','CARGO_NET_RETRY':'2'}
    for key in ('HOME','CARGO_HOME'): Path(base_env[key]).mkdir()
    write(evidence/'prequalification.json',{'tools':records,'native_tools':native_tools,'ordinary_subject_identity':{'uid':identity.pw_uid,'gid':identity.pw_gid,'name':identity.pw_name},'environment':base_env,'available_memory':mem,'free_bytes':shutil.disk_usage(out).free,'workflow_sha':os.environ['GITHUB_SHA'],'manifest_sha256':canonical})
    versions = {}
    for record in records:
        code, raw, err = execute([record['path'],'--version'],out,base_env,evidence/('version-'+Path(record['path']).name),15)
        require(code == 0 and not err and re.search(r'\b1\.95\.0\b',raw.decode()), 'pinned Rust version mismatch')
        versions[record['path']] = raw.decode()
    write(evidence/'versions.json',versions)
    # Export actual immutable Git source objects, never borrow a dirty checkout.
    git_env = {'PATH':'/usr/bin:/bin','HOME':str(out/'compiler-home'),'LANG':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_COUNT':'0'}
    baseline = out/'baseline'; baseline.mkdir(mode=0o755)
    requested = ''.join(row['blob']+'\n' for row in manifest['closure']).encode()
    code, packed, err = execute(['/usr/bin/git','-c','safe.directory='+str(workspace),'-C',str(workspace),'cat-file','--batch'],out,git_env,evidence/'source-objects',60,capture_bytes=256*1024**2,input_bytes=requested)
    require(code == 0 and not err, 'immutable source batch failed')
    cursor = 0
    for row in manifest['closure']:
        end = packed.index(b'\n',cursor)
        blob, kind, size = packed[cursor:end].decode().split()
        require(blob == row['blob'] and kind == 'blob' and int(size) == row['bytes'], 'object header mismatch')
        cursor = end+1
        raw = packed[cursor:cursor+int(size)]; cursor += int(size)
        require(packed[cursor:cursor+1] == b'\n' and digest(raw) == row['sha256'], 'closure object mismatch')
        cursor += 1
        p = baseline/row['path']; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(raw); p.chmod(0o755 if row['mode']=='100755' else 0o644)
    require(cursor == len(packed), 'unbound source batch suffix')
    require((baseline/'src/runtimes/deno.rs').read_bytes() == (PACKAGE/'baseline.rs').read_bytes(), 'baseline Deno mismatch')
    provider_snapshot, provider_roots = provenance.snapshot(out/'receipts', provider, baseline, execute, base_env, runtime.digest_file, write)
    baseline_snapshot = tree_snapshot(baseline)
    write(evidence/'closure-snapshot.json',baseline_snapshot)
    matrix = []
    for state in manifest['states']:
        provenance.verify(provider_snapshot, provider_roots, runtime.digest_file)
        check_tools(records)
        check_tools(native_tools)
        require(tree_snapshot(baseline) == baseline_snapshot, 'baseline closure modified')
        copy = out/state['name']; shutil.copytree(baseline,copy)
        subject = copy/'src/runtimes/deno.rs'
        state_bytes = (PACKAGE/state['source']).read_bytes()
        if state['fault']:
            old, new = manifest['fault_old'].encode(), manifest['fault_new'].encode()
            require(state_bytes.count(old) == 1, 'narrow fault must match exactly once')
            state_bytes = state_bytes.replace(old,new,1)
        subject.write_bytes(state_bytes)
        require(digest(subject.read_bytes()) == state['source_sha256'], 'state source mismatch')
        before = tree_snapshot(copy)
        code, raw, err = execute([records[0]['path'],'test','--lib','--no-default-features','--features','fedora,pgp,license','--locked','--no-run','--message-format=json'],copy,base_env,evidence/(state['name']+'-compile'),900)
        require(code == 0, 'compile failure is HARNESS, never RED')
        artifacts = []
        for line in raw.splitlines():
            message = json.loads(line)
            if message.get('reason') == 'compiler-artifact' and message.get('profile',{}).get('test') and message.get('target',{}).get('name') == 'omg_lib' and message.get('executable'): artifacts.append(message)
        require(len(artifacts) == 1, 'ambiguous library compiler executable')
        executable = Path(artifacts[0]['executable']).resolve(strict=True)
        require(executable.is_relative_to(out/'target') and stat.S_ISREG(executable.stat().st_mode), 'foreign compiled executable')
        binary = out/(state['name']+'-libtest'); shutil.copyfile(executable,binary); binary.chmod(0o755)
        before_binary = runtime.digest_file(binary)
        home = out/(state['name']+'-home'); home.mkdir(mode=0o700); os.chown(home,identity.pw_uid,identity.pw_gid)
        tmp = home/'tmp'; tmp.mkdir(); os.chown(tmp,identity.pw_uid,identity.pw_gid)
        subject_env = {'PATH':'/usr/bin:/bin','HOME':str(home),'TMPDIR':str(tmp),'LANG':'C.UTF-8','RUST_BACKTRACE':'0'}
        ids = [PREFIX+n for n in state['names']]
        code, probe_out, probe_err = execute([sys.executable,'-I','-B',str(PACKAGE/'access-probe.py'),str(subject),str(binary),str(home),str(tmp)],copy,subject_env,evidence/(state['name']+'-ordinary-access'),30,identity)
        require(code == 0 and not probe_err and load(evidence/(state['name']+'-ordinary-access')/'receipt.json')['requested_uid'] == identity.pw_uid, 'ordinary access preflight failed')
        discovered = listing(binary,ids,copy,subject_env,evidence/(state['name']+'-list'),identity)
        code, stdout, stderr = execute([str(binary),PREFIX,'--test-threads=1'],copy,subject_env,evidence/(state['name']+'-run'),180,identity)
        require(code == (101 if state['failures'] else 0), 'unexpected libtest exit code')
        result = outcomes(stdout,stderr,ids,[PREFIX+n for n in state['failures']],discovered['all_compiled_entries'])
        require(tree_snapshot(copy) == before and runtime.digest_file(binary) == before_binary, 'subject source/binary changed')
        provenance.verify(provider_snapshot, provider_roots, runtime.digest_file)
        check_tools(records)
        check_tools(native_tools)
        matrix.append({'state':state['name'],'compiled_artifact':artifacts[0],'binary_sha256':before_binary,'source_snapshot':before,'listing':discovered,'outcome':result,'uid':identity.pw_uid})
        write(evidence/(state['name']+'-result.json'),matrix[-1])
        require(shutil.disk_usage(out).free >= manifest['remaining_free_bytes'], 'target footprint reserve breached')
        size = sum(p.stat().st_size for p in (out/'target').rglob('*') if p.is_file())
        require(size <= manifest['max_target_bytes'], 'private target footprint budget exceeded')
    require(runtime.CANCELLED is None, 'controller cancellation forbids observed matrix finalization')
    require([len(s['outcome']['named_results']) for s in matrix] == [13,13,15,15], 'matrix count mismatch')
    write(evidence/'acceptance.json',{'status':'REAL_DENO_MODULE_MATRIX_OBSERVED_INDEPENDENT_ADMISSION_REQUIRED','matrix':matrix,'unique_old':13,'unique_stronger':15,'method_invocations':56,'source_head':manifest['source_head'],'workflow_sha':os.environ['GITHUB_SHA'],'ordinary_uid':identity.pw_uid,'release_or_guest_credit':False})

if __name__ == '__main__':
    try: main()
    except BaseException as error:
        print('HARNESS_ERROR:',type(error).__name__,str(error),file=sys.stderr)
        raise

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


def tool(path, purpose='rust'):
    candidate = Path(path)
    context = {'candidate':str(candidate),'purpose':purpose}
    def bound_require(value, message):
        require(value, message + ': ' + json.dumps(context, sort_keys=True))
    try:
        bound_require(purpose in ('rust','native','interpreter'), 'unknown provider purpose')
        bound_require(candidate.is_absolute(), 'absolute direct provider required')
        if purpose == 'native':
            bound_require(str(candidate) in tuple('/usr/bin/'+name for name in ('git','cc','clang','pkg-config','cmake','ar','ld','python3')), 'native provider outside fixed command set')
        resolved = candidate.resolve(strict=True)
        context['resolved'] = str(resolved)
        ancestors = []
        for item in dict.fromkeys([candidate, *candidate.parents, resolved, *resolved.parents]):
            info = item.lstat()
            ancestor = {'candidate':str(candidate),'resolved':str(resolved),'path':str(item),'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'mode_octal':oct(stat.S_IMODE(info.st_mode)),'uid':info.st_uid,'gid':info.st_gid,'link':os.readlink(item) if stat.S_ISLNK(info.st_mode) else None}
            context['ancestor'] = ancestor
            bound_require(info.st_uid == 0 and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022), 'provider ancestry ownership/mode changed')
            ancestors.append(ancestor)
        info = resolved.stat()
        context['file_stat'] = {'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'mode_octal':oct(stat.S_IMODE(info.st_mode)),'uid':info.st_uid,'gid':info.st_gid}
        bound_require(stat.S_ISREG(info.st_mode) and os.access(resolved,os.X_OK), 'direct regular executable required')
        with resolved.open('rb') as stream:
            header = stream.read(256)
        context['first_bytes_hex'] = header[:32].hex()
        context['shebang_observation_hex'] = header.split(b'\n',1)[0].hex() if header.startswith(b'#!') else None
        format_record = {'kind':'ELF','first_bytes_hex':header[:4].hex()}
        if header[:4] != b'\x7fELF':
            bound_require(purpose == 'native', 'direct ELF provider required')
            bound_require(header.startswith(b'#!') and b'\n' in header, 'native provider requires ELF or bounded explicit shebang')
            line_bytes = header.split(b'\n',1)[0]
            bound_require(all(c == 9 or 32 <= c <= 126 for c in line_bytes), 'native shebang must be ASCII without control bytes')
            line = line_bytes.decode('ascii')
            parts = re.split(r'[ \t]+',line[2:].strip(' \t'),maxsplit=1)
            interpreter = parts[0]
            optional_argument = parts[1].rstrip(' \t') if len(parts) == 2 else None
            context['shebang'] = {'line':line,'interpreter':interpreter,'optional_argument':optional_argument}
            allowed = ('/bin/sh','/bin/bash','/usr/bin/sh','/usr/bin/bash','/usr/bin/python3','/usr/bin/perl')
            bound_require(interpreter in allowed, 'native shebang interpreter outside explicit absolute allowlist')
            interpreter_record = tool(interpreter, 'interpreter')
            format_record = {'kind':'SHEBANG','line_hex':line_bytes.hex(),'line':line,'interpreter':interpreter_record,'optional_argument':optional_argument,'qualification':'Kernel single optional argument; no env PATH lookup or nested script interpreter permitted.'}
        return {'candidate':str(candidate),'path':str(resolved),'purpose':purpose,'sha256':runtime.digest_file(resolved,512*1024**2),'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'ancestry':ancestors,'format':format_record}
    except (OSError, ValueError) as error:
        raise RuntimeError('HARNESS_ERROR: provider inspection failed: ' + json.dumps(context,sort_keys=True) + '; ' + type(error).__name__ + ': ' + str(error)) from error

def check_tools(records):
    for record in records:
        require(tool(record['candidate'],record['purpose']) == record, 'provider changed: ' + json.dumps({'candidate':record['candidate'],'path':record['path'],'purpose':record['purpose']},sort_keys=True))

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
    signal.alarm(2400)
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0) == 0, 'subreaper unavailable')
    require(not descendants(), 'controller already owns children')
    identity = pwd.getpwnam('omg-deno-proof')
    require(identity.pw_uid > 0 and identity.pw_gid > 0, 'subjects must have nonroot UID/GID')
    out = Path(os.environ['RUNNER_TEMP'])/'deno-alias-proof'
    require(out.is_dir() and (out/'receipts').is_dir() and not (out/'receipts/evidence').exists(), 'fresh supervisor workspace required')
    evidence = out/'receipts/evidence'; evidence.mkdir()
    workspace = Path(os.environ['GITHUB_WORKSPACE'])
    provider = Path('/opt/omg-deno-proof/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
    records = [tool(provider/name) for name in ('cargo','rustc')]
    native_tools = [tool('/usr/bin/'+name, 'native') for name in ('git','cc','clang','pkg-config','cmake','ar','ld','python3')]
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
    full_source_snapshot = tree_snapshot(baseline)
    fixture = out/'registry-contract-fixture'; fixture.mkdir(mode=0o755)
    for name in ('Cargo.toml','Cargo.lock','src/lib.rs'):
        raw=(PACKAGE/'fixture'/name).read_bytes()
        path=fixture/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
    fixture_before=tree_snapshot(fixture)
    code,raw,err=execute([records[0]['path'],'fetch','--locked','--manifest-path',str(fixture/'Cargo.toml')],out,base_env,evidence/'contract-prefetch',180)
    require(code==0,'genuine fixture prefetch failed')
    require(tree_snapshot(fixture)==fixture_before,'prefetch changed fixture source/lock')
    registry=Path(base_env['CARGO_HOME'])/'registry'
    before_registry={str(root):provenance.collect_tree(root,runtime.digest_file) for root in (registry/'src',registry/'cache')}
    import unittest
    import test_registry_snapshot_contract as contract
    contract.RegistrySnapshotContract.context=(out/'receipts',provider,fixture,execute,base_env,runtime.digest_file,write)
    method='test_locked_registry_source_without_vendor_checksum_is_accepted'
    test=contract.RegistrySnapshotContract(method)
    result=unittest.TestResult();test.run(result)
    expected='test_registry_snapshot_contract.RegistrySnapshotContract.'+method
    require(result.testsRun==1 and len(result.failures)==1 and not result.errors and not result.skipped and not result.unexpectedSuccesses,'unrelated harness error or unexpected contract success is not intended RED')
    failed,trace=result.failures[0]
    require(failed.id()==expected,'wrong failed contract identity')
    sentinel='REGISTRY_LAYOUT_CONTRACT: a locked genuine Cargo registry tree must be verified without requiring directory-source .cargo-checksum.json'
    require(trace.count('AssertionError: '+sentinel)==1,'wrong RED assertion reason')
    require(runtime.CANCELLED is None,'cancellation forbids contract finalization')
    check_tools(records);check_tools(native_tools)
    require(tree_snapshot(baseline)==full_source_snapshot,'full942 original source closure changed')
    require(tree_snapshot(fixture)==fixture_before,'contract changed fixture source/lock')
    require({str(root):provenance.collect_tree(root,runtime.digest_file) for root in (registry/'src',registry/'cache')}==before_registry,'contract changed authenticated registry bytes')
    write(evidence/'registry-contract-acceptance.json',{
        'status':'ORIGINAL_REGISTRY_LAYOUT_NAMED_ASSERTION_RED_OBSERVED_REQUIRES_INDEPENDENT_ADMISSION',
        'test_id':expected,'tests_run':result.testsRun,'failures':1,'errors':0,'skips':0,'failure_trace':trace,
        'sentinel':sentinel,'original_provenance_sha256':digest((PACKAGE/'provenance.py').read_bytes()),
        'test_source_sha256':digest((PACKAGE/'test_registry_snapshot_contract.py').read_bytes()),
        'fixture_source_before_after':fixture_before,'full_source_before_after':full_source_snapshot,
        'registry_before_after':before_registry,'workflow_sha':os.environ['GITHUB_SHA'],'source_manifest_sha256':canonical,
        'controller_uid':os.getuid(),'ordinary_uid_prequalified_only':identity.pw_uid,
        'ordinary_subject_executions':0,'Deno_matrix_credit':0,'compiler_credit':0,
        'source_head':manifest['source_head'],'retirement_admission':'Every owned runtime receipt and outer supervisor separately required'})
    print('REGISTRY_CONTRACT_EXPECTED_RED '+expected,flush=True)

if __name__ == '__main__':
    try:main()
    except BaseException as error:
        print('HARNESS_ERROR:',type(error).__name__,str(error),file=sys.stderr)
        raise

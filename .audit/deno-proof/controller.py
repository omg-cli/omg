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
            bound_require(str(candidate) in tuple('/usr/bin/'+name for name in ('git','cc','clang','pkg-config','cmake','ar','ld','python3','rpm')), 'native provider outside fixed command set')
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

def protected_namespace(path):
    observations=[]
    for item in [*reversed(path.parents),path]:
        info=item.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'protected namespace ancestor ownership/mode')
        observations.append({'path':str(item),'device':info.st_dev,'inode':info.st_ino,'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid})
    return observations

def main():
    manifest=load(PACKAGE/'manifest.json')
    require(digest(Path(__file__).read_bytes())==manifest['controller_sha256'],'controller source changed')
    for name,expected in manifest['package_inputs'].items():
        require(digest((PACKAGE/name).read_bytes())==expected,'package input changed')
    red=load(PACKAGE/'input-pins/cargo-registry-red-root-admission.json')
    require(red['root_status']=='ROOT_ADMITTED_ORIGINAL_SNAPSHOT_NAMED_ASSERTION_RED_ONLY' and red['expected_assertion_failures']==1 and red['original_helper_sha256']==manifest['package_inputs']['reference-red/provenance.py'],'authentic original RED prerequisite mismatch')
    corrected=load(PACKAGE/'input-pins/cargo-correction-root-source-review-admission.json')
    require(corrected['status']=='ROOT_ADMITTED_CORRECTION_SOURCE_REVIEW_ONLY' and corrected['execution_released'] is False,'source admission must not manufacture execution release')
    admission=runtime.initialize(manifest);canonical=admission['manifest_sha256']
    require(os.getuid()==0 and sys.platform=='linux' and sys.version_info>=(3,11),'Fedora root controller bootstrap required')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGALRM,interrupted);signal.alarm(7800)
    require(not runtime.descendants(),'preexisting children')
    identity=pwd.getpwnam('omg-deno-proof');require(identity.pw_uid>0 and identity.pw_gid>0,'ordinary account identity must exist with positive UID/GID; access is unproven')
    out=runtime.WORKSPACE;protected_root=runtime.PROTECTED_ROOT
    protected_before=protected_namespace(protected_root)
    require(out.is_dir() and (out/'receipts').is_dir() and not (out/'receipts/evidence').exists(),'fresh supervisor receipt workspace required')
    evidence=out/'receipts/evidence';evidence.mkdir()
    provider=Path('/opt/omg-deno-proof/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
    records=[tool(provider/name) for name in ('cargo','rustc')]
    native_tools=[tool('/usr/bin/'+name,'native') for name in ('git','cc','clang','pkg-config','cmake','ar','ld','python3','rpm')]
    for root in (out,protected_root):require(shutil.disk_usage(root).free>=manifest['min_free_bytes'],'initial24GiB floor unmet')
    mem=int(Path('/proc/meminfo').read_text().split('MemAvailable:',1)[1].split()[0])*1024
    require(mem>=manifest['min_available_memory_bytes'],'initial4GiB available memory unmet')
    base_env={'PATH':str(provider)+':/usr/bin:/bin','HOME':str(protected_root/'compiler-home'),'CARGO_HOME':str(protected_root/'cargo-home'),'CARGO_TARGET_DIR':str(protected_root/'target'),'TMPDIR':str(protected_root/'integrity'),'RUSTC':records[1]['path'],'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_TERM_COLOR':'never','RUST_BACKTRACE':'0','LANG':'C.UTF-8','CARGO_NET_RETRY':'2'}
    for key in ('HOME','CARGO_HOME','TMPDIR'):Path(base_env[key]).mkdir(mode=0o755)
    caps={name:(Path('/sys/fs/cgroup')/name).read_text() for name in ('memory.max','memory.swap.max','pids.max')}
    write(evidence/'prequalification.json',{'tools':records,'native_tools':native_tools,'ordinary_subject_identity':{'uid':identity.pw_uid,'gid':identity.pw_gid,'name':identity.pw_name},'ordinary_prequalified_only':True,'ordinary_identity_qualification':'Account lookup only; access-probe unselected and ordinary-user accessibility UNRUN','environment':base_env,'available_memory':mem,'roots':[{'path':str(root),'free_bytes':shutil.disk_usage(root).free} for root in (out,protected_root)],'protected_namespace_ancestry':protected_before,'actual_cgroup_values':caps,'workflow_sha':os.environ['GITHUB_SHA'],'manifest_sha256':canonical})
    versions={}
    for record in records:
        code,raw,err=execute([record['path'],'--version'],protected_root,base_env,evidence/('version-'+Path(record['path']).name),15)
        require(code==0 and not err and re.search(r'\b1\.95\.0\b',raw.decode()),'Rust version mismatch');versions[record['path']]=raw.decode()
    write(evidence/'versions.json',versions)
    workspace=Path(os.environ['GITHUB_WORKSPACE'])
    # Export actual immutable Git source objects, never borrow a dirty checkout.
    git_env = {'PATH':'/usr/bin:/bin','HOME':str(protected_root/'compiler-home'),'LANG':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_COUNT':'0'}
    baseline = protected_root/'baseline'; baseline.mkdir(mode=0o755)
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
    fixture=protected_root/'registry-contract-fixture';fixture.mkdir(mode=0o755)
    for name in ('Cargo.toml','Cargo.lock','src/lib.rs'):
        raw=(PACKAGE/'fixture'/name).read_bytes();path=fixture/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
    fixture_before=tree_snapshot(fixture)
    fixture_file_observations={name:provenance.file_observation(fixture/name) for name in ('Cargo.toml','Cargo.lock','src/lib.rs')}
    namespace_before={str(path):protected_namespace(path) for path in (fixture,Path(base_env['CARGO_HOME']),Path(base_env['TMPDIR']),baseline)}
    code,raw,err=execute([records[0]['path'],'fetch','--locked','--manifest-path',str(fixture/'Cargo.toml')],protected_root,base_env,evidence/'contract-prefetch',180)
    require(code==0,'genuine prefetch failed');require(tree_snapshot(fixture)==fixture_before,'prefetch changed fixture')
    code,raw,err=execute([records[0]['path'],'metadata','--locked','--offline','--no-default-features','--features','fedora,pgp,license','--filter-platform','x86_64-unknown-linux-gnu','--format-version','1','--manifest-path',str(fixture/'Cargo.toml')],fixture,base_env,evidence/'contract-metadata',60)
    require(code==0,'genuine metadata prerequisite failed')
    metadata=json.loads(raw);require(len(metadata['packages'])==2 and {r['name'] for r in metadata['packages']}=={'omg-provenance-contract','itoa'},'genuine two-package fixture metadata mismatch')
    registry=Path(base_env['CARGO_HOME'])/'registry'
    before_registry={str(root):provenance.collect_tree(root,runtime.digest_file) for root in (registry/'src',registry/'cache')}
    write(evidence/'suite-environment.json',base_env)
    child_env=dict(base_env)
    child_env.update({name:os.environ[name] for name in ('GITHUB_EVENT_PATH','GITHUB_EVENT_NAME','GITHUB_SHA','GITHUB_REF','GITHUB_ACTOR','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_TEMP','GITHUB_WORKSPACE')})
    code,stdout,stderr=execute([native_tools[7]['path'],'-I','-B',str(PACKAGE/'suite-child.py')],PACKAGE,child_env,evidence/'suite-child',7200,capture_bytes=64*1024**2)
    require(code==0,'full37 child failed or refused; no GREEN')
    observed=load(evidence/'suite-result.json')
    require(observed['status']=='CORRECTED_INTACT37_RAW_PASS_PENDING_ROOT_INDEPENDENT_ADMISSION','suite status mismatch')
    for name,value in {'tests_run':37,'failures':0,'errors':0,'skips':0,'expected_failures':0,'unexpected_successes':0,'controller_uid':0,'full548_credit':0,'Deno_matrix_credit':0,'compiler_credit':0}.items():require(type(observed[name]) is int and observed[name]==value,'strict suite scalar mismatch')
    require(observed['started_ids']==manifest['expected_test_ids'] and len(observed['named_results'])==37 and [r['id'] for r in observed['named_results']]==manifest['expected_test_ids'] and all(r['status']=='PASS' for r in observed['named_results']),'exact37 named PASS mismatch')
    require(len(observed['nested_observations'])==11 and [{'parent_id':r['parent_id'],'params':r['params']} for r in observed['nested_observations']]==manifest['expected_nested_observations'] and all(r['status']=='PASS' for r in observed['nested_observations']),'exact11 nested observations mismatch')
    require(observed['source_manifest_sha256']==canonical and observed['workflow_sha']==os.environ['GITHUB_SHA'] and observed['provenance_sha256']==manifest['package_inputs']['provenance.py'],'child/source/dispatch mismatch')
    require(runtime.CANCELLED is None and not runtime.descendants(),'cancellation/owned census prevents admission')
    check_tools(records);check_tools(native_tools)
    require(tree_snapshot(baseline)==full_source_snapshot and tree_snapshot(fixture)==fixture_before,'full942 or fixture source changed')
    require({name:provenance.file_observation(fixture/name) for name in ('Cargo.toml','Cargo.lock','src/lib.rs')}==fixture_file_observations,'fixture file ownership/identity changed')
    require({str(root):provenance.collect_tree(root,runtime.digest_file) for root in (registry/'src',registry/'cache')}==before_registry,'suite changed genuine registry bytes')
    namespace_after={str(path):protected_namespace(path) for path in (fixture,Path(base_env['CARGO_HOME']),Path(base_env['TMPDIR']),baseline)}
    require(namespace_after==namespace_before,'protected ancestry identity/mode changed')
    require(not list(Path(base_env['TMPDIR']).iterdir()),'integrity fixtures did not retire')
    for name,expected in manifest['package_inputs'].items():require(digest((PACKAGE/name).read_bytes())==expected,'post suite package source changed')
    receipts=[]
    for path in sorted(evidence.rglob('receipt.json')):
        row=load(path);require(row['error'] is None and row['cancelled_signal'] is None and row['direct_child_reaped'] and row['retirement']['retired'] and row['retirement']['final_owned_census']==[] and not row['raw_refused_or_truncated'],'owned receipt incomplete')
        require(row['requested_uid']==0,'this intact fixture has root subject identity only')
        receipts.append({'path':path.relative_to(evidence).as_posix(),'sha256':digest(path.read_bytes()),'argv':row['argv'],'exit':row['exit']})
    require(len(receipts)==11 and all(type(row['exit']) is int and row['exit']==0 for row in receipts),'exact11 genuine owned command observations required')
    require(runtime.monitor()['combined_logical_sizes']['evidence']<=1024**3,'complete evidence >1GiB requires reviewed sharding; no truncation')
    write(evidence/'intact37-acceptance.json',{'status':'CORRECTED_INTACT37_OBSERVED_PENDING_INDEPENDENT_ROOT_ADMISSION','suite':observed,'nested_owned_command_receipts':receipts,'genuine_command_observations':11,'corrected_provenance_sha256':manifest['package_inputs']['provenance.py'],'unchanged_positive_sha256':manifest['package_inputs']['test_registry_snapshot_contract.py'],'new_test_source_sha256':manifest['package_inputs']['test_registry_archive_integrity.py'],'fixture_source_before_after':fixture_before,'protected_fixture_file_observations_before_after':fixture_file_observations,'full942_source_before_after':full_source_snapshot,'registry_before_after':before_registry,'protected_namespace_before':namespace_before,'protected_namespace_after':namespace_after,'workflow_sha':os.environ['GITHUB_SHA'],'source_manifest_sha256':canonical,'controller_uid':0,'ordinary_uid_prequalified_only':identity.pw_uid,'ordinary_subject_executions':0,'ordinary_identity_qualification':'Account existence only; zero ordinary-user subject executions or accessibility proof','full548_credit':0,'Deno_matrix_credit':0,'compiler_credit':0,'private_fault_credit':0,'retirement_scope':'All11 owned receipts plus outer supervisor terminal receipt separately required','compressed_bound_qualification':'Static protected<=256MiB archive pre/post size/hash/identity; no during-parser raw compressed byte counter or concurrent privileged writer guarantee','physical_headers_qualification':'Entry header ordinal including first terminator; second terminator/trailer bytes charged expanded budget'})
    print('CARGO_CORRECTION_INTACT37_PENDING_ROOT_ADMISSION',flush=True)

if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('HARNESS_ERROR:',type(error).__name__,str(error),file=sys.stderr);raise

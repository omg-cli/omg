"""Outer owned controller guard; missing receipts or intact failures refuse acceptance."""
import hashlib,json,os,stat,sys
from pathlib import Path
PACKAGE=Path(__file__).resolve().parent
manifest=json.loads((PACKAGE/'manifest.json').read_bytes())
for name,expected in dict(manifest['package_inputs'],**{'controller.py':manifest['controller_sha256']}).items():
    assert hashlib.sha256((PACKAGE/name).read_bytes()).hexdigest()==expected
sys.path.insert(0,str(PACKAGE))
import runtime
admission=runtime.initialize(manifest)
assert os.getuid()==0 and sys.argv[1:]==[]
workspace=runtime.WORKSPACE
workspace.mkdir(mode=0o755)
root=runtime.PROTECTED_ROOT
assert not root.exists() and not root.is_symlink()
for parent in reversed(root.parents):
    info=parent.lstat();assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
root.mkdir(mode=0o755)
receipts=workspace/'receipts';receipts.mkdir()
logs=receipts/'supervisor';logs.mkdir()
runtime.write(logs/'dispatch-admission.json',dict(admission,protected_root=str(root),protected_root_device=root.stat().st_dev,protected_root_inode=root.stat().st_ino))
env={name:os.environ[name] for name in ('GITHUB_EVENT_PATH','GITHUB_EVENT_NAME','GITHUB_SHA','GITHUB_REF','GITHUB_ACTOR','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_TEMP','GITHUB_WORKSPACE','HOME')}
env.update(PATH='/usr/bin:/bin',LANG='C.UTF-8')
def diagnostics(error, code):
    print('DENO_PROOF_FAILURE_METADATA '+json.dumps({'workspace':str(workspace),'receipt_parent':str(receipts),'controller_exit':code,'error_type':type(error).__name__,'error':str(error)[:4096],'diagnostics_are_saved_raw_output_not_test_results':True}),flush=True)
    for channel in ('stderr','stdout'):
        path=logs/'controller'/channel
        try:
            with path.open('rb') as stream:
                size=os.fstat(stream.fileno()).st_size
                stream.seek(max(0,size-8192))
                tail=stream.read(8192)
            print('DENO_PROOF_SAVED_CHANNEL_TAIL '+json.dumps({'channel':channel,'path':str(path),'saved_bytes':size,'tail_bytes':len(tail),'tail_utf8_backslashreplace':tail.decode('utf-8','backslashreplace')}),flush=True)
        except OSError as read_error:
            print('DENO_PROOF_SAVED_CHANNEL_UNAVAILABLE '+json.dumps({'channel':channel,'path':str(path),'error_type':type(read_error).__name__,'error':str(read_error)[:4096]}),flush=True)

code=None
try:
    code,stdout,stderr=runtime.execute([sys.executable,'-I','-B',str(PACKAGE/'controller.py')],PACKAGE,env,logs/'controller',8000,capture_bytes=64*1024**2)
    assert type(code) is int and code==0
    observed=json.loads((receipts/'evidence/intact37-acceptance.json').read_bytes())
    assert type(observed) is dict and observed['status']=='CORRECTED_INTACT37_OBSERVED_PENDING_INDEPENDENT_ROOT_ADMISSION'
    for name,value in {'genuine_command_observations':11,'controller_uid':0,'ordinary_subject_executions':0,'full548_credit':0,'Deno_matrix_credit':0,'compiler_credit':0,'private_fault_credit':0}.items():assert type(observed[name]) is int and observed[name]==value
    assert type(observed['ordinary_uid_prequalified_only']) is int and observed['ordinary_uid_prequalified_only']>0
    assert observed['source_manifest_sha256']==admission['manifest_sha256'] and observed['workflow_sha']==os.environ['GITHUB_SHA']
    assert observed['corrected_provenance_sha256']==manifest['package_inputs']['provenance.py']
    suite=observed['suite'];assert type(suite) is dict
    for name,value in {'tests_run':37,'failures':0,'errors':0,'skips':0,'expected_failures':0,'unexpected_successes':0}.items():assert type(suite[name]) is int and suite[name]==value
    assert type(suite['named_results']) is list and len(suite['named_results'])==37 and [r['id'] for r in suite['named_results']]==manifest['expected_test_ids'] and all(r['status']=='PASS' for r in suite['named_results'])
    assert type(suite['nested_observations']) is list and len(suite['nested_observations'])==11 and [{'parent_id':r['parent_id'],'params':r['params']} for r in suite['nested_observations']]==manifest['expected_nested_observations'] and all(r['status']=='PASS' for r in suite['nested_observations'])
    assert len(observed['nested_owned_command_receipts'])==11 and not runtime.descendants()
    runtime.write(logs/'workspace-disposition.json',{'status':'RETAINED_PRIVATE_TWO_ROOTS_FOR_INDEPENDENT_RECEIPT_ADMISSION','workspace':str(workspace),'protected_root':str(root),'roots':[{'path':str(p),'device':p.stat().st_dev,'inode':p.stat().st_ino} for p in (workspace,root)],'owned_descendants_empty':True,'only_receipts_uploaded':True,'cleanup':'After confirmed complete artifact retention, root reviews both exact identities and bounded deletion. No automatic uncertain-path cleanup; missing retirement is HOLD.'})
except BaseException as error:
    diagnostics(error,code)
    runtime.write(logs/'workspace-disposition.json',{'status':'HARNESS_ERROR_PRIVATE_TWO_ROOTS_RETAINED','workspace':str(workspace),'protected_root':str(root),'error':str(error),'no_acceptance_from_partial_outputs':True,'cleanup':'Root exact-path review after evidence preservation; no blind retry or uncertain cleanup.'})
    raise

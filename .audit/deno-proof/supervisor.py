"""Independent outer owner for the controller and its complete descendant tree."""
import hashlib,json,os,sys
from pathlib import Path
PACKAGE=Path(__file__).resolve().parent
manifest=json.loads((PACKAGE/'manifest.json').read_bytes())
for name,expected in dict(manifest['package_inputs'],**{'controller.py':manifest['controller_sha256']}).items():
    assert hashlib.sha256((PACKAGE/name).read_bytes()).hexdigest()==expected
sys.path.insert(0,str(PACKAGE))
import runtime
admission=runtime.initialize(manifest)
workspace=runtime.WORKSPACE
workspace.mkdir(mode=0o755)
receipts=workspace/'receipts'; receipts.mkdir()
logs=receipts/'supervisor'; logs.mkdir()
runtime.write(logs/'dispatch-admission.json',admission)
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

assert sys.argv[1:]==[], 'registry contract has no alternate mode'
code=None
try:
    code,stdout,stderr=runtime.execute([sys.executable,'-I','-B',str(PACKAGE/'controller.py')],PACKAGE,env,logs/'controller',2500)
    assert type(code) is int and code==0
    observed=json.loads((receipts/'evidence/registry-contract-acceptance.json').read_bytes())
    assert type(observed) is dict
    assert observed['status']=='ORIGINAL_REGISTRY_LAYOUT_NAMED_ASSERTION_RED_OBSERVED_REQUIRES_INDEPENDENT_ADMISSION'
    for key,value in {'tests_run':1,'failures':1,'errors':0,'skips':0,'controller_uid':0,'ordinary_subject_executions':0,'Deno_matrix_credit':0,'compiler_credit':0}.items():
        assert type(observed[key]) is int and observed[key]==value
    assert type(observed['ordinary_uid_prequalified_only']) is int and observed['ordinary_uid_prequalified_only']>0
    expected='test_registry_snapshot_contract.RegistrySnapshotContract.test_locked_registry_source_without_vendor_checksum_is_accepted'
    assert observed['test_id']==expected
    assert observed['source_manifest_sha256']==admission['manifest_sha256'] and observed['workflow_sha']==os.environ['GITHUB_SHA']
    assert observed['original_provenance_sha256']==manifest['package_inputs']['provenance.py']
    assert observed['test_source_sha256']==manifest['package_inputs']['test_registry_snapshot_contract.py']
    assert observed['failure_trace'].count('AssertionError: '+observed['sentinel'])==1
    runtime.write(logs/'workspace-disposition.json',{'status':'RETAINED_PRIVATE_WORKSPACE_FOR_RECEIPT_UPLOAD','workspace':str(workspace),'device':workspace.stat().st_dev,'inode':workspace.stat().st_ino,'owned_descendants_empty':not runtime.descendants(),'source_target_fault_binaries_uploaded':False,'cleanup':'After confirmed evidence artifact upload, root reviews exact workspace identity and bounded deletion. Runner hardkill/missing retirement receipts is HOLD, not acceptance.'})
except BaseException as error:
    diagnostics(error,code)
    runtime.write(logs/'workspace-disposition.json',{'status':'HARNESS_ERROR_PRIVATE_WORKSPACE_RETAINED','workspace':str(workspace),'error':str(error),'no_acceptance_from_partial_outputs':True,'cleanup':'Root-owned exact-path review after evidence preservation; no automated deletion on uncertain ownership.'})
    raise

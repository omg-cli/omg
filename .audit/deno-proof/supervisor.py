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

assert sys.argv[1:] in ([],['--provider-contract']), 'unknown supervisor mode'
contract_mode = sys.argv[1:] == ['--provider-contract']
selected = 'provider-contract.py' if contract_mode else 'controller.py'
code=None
try:
    code,stdout,stderr=runtime.execute([sys.executable,'-I','-B',str(PACKAGE/selected)],PACKAGE,env,logs/'controller',120 if contract_mode else 8000)
    assert code==0
    if contract_mode:
        observed=json.loads((receipts/'evidence/provider-contract-acceptance.json').read_bytes())
        expected=['old-valid-script-red','native-valid-qualified','native-valid-kernel-pass','strict-rust-script-refused','malformed-script','no-lf-script','crlf-script','env-interpreter-script','unallowed-interpreter-script','optional-e-kernel-stops','optional-absent-kernel-continues','nested-script-interpreter-refused','interpreter-identity-drift-refused','native-body-drift-refused','restored-exact-identities']
        fields={'status','names','cases','ordinary_uid','owned_subject_commands','source_manifest_sha256','workflow_sha','runtime_Deno_matrix_credit','original_v6_native_identity','actual_kernel','fixture_paths','fixture_disposition'}
        assert type(observed) is dict and set(observed)==fields
        assert type(observed['status']) is str and observed['status']=='REAL_PROVIDER_FORMAT_CONTRACT_OBSERVED_INDEPENDENT_ADMISSION_REQUIRED'
        assert type(observed['names']) is list and all(type(name) is str for name in observed['names']) and observed['names']==expected
        assert len(expected)==len(set(expected))==15
        assert type(observed['cases']) is list and len(observed['cases'])==15
        assert type(observed['ordinary_uid']) is int and observed['ordinary_uid']>0
        assert type(observed['owned_subject_commands']) is int and observed['owned_subject_commands']==3
        assert type(observed['runtime_Deno_matrix_credit']) is int and observed['runtime_Deno_matrix_credit']==0
        assert type(observed['workflow_sha']) is str and observed['workflow_sha']==os.environ['GITHUB_SHA']
        assert type(observed['source_manifest_sha256']) is str and observed['source_manifest_sha256']==admission['manifest_sha256']
        assert type(observed['original_v6_native_identity']) is str and observed['original_v6_native_identity']=='UNKNOWN'
        assert type(observed['actual_kernel']) is dict and set(observed['actual_kernel'])=={'sysname','nodename','release','version','machine'}
        assert all(type(value) is str for value in observed['actual_kernel'].values())
        assert type(observed['fixture_disposition']) is str
        assert type(observed['fixture_paths']) is dict and set(observed['fixture_paths'])=={'/usr/bin/clang','/usr/bin/perl'}
        for identity in observed['fixture_paths'].values():
            assert type(identity) is dict and set(identity)=={'device','inode','uid','gid','mode'}
            assert all(type(value) is int for value in identity.values()) and identity['uid']==identity['gid']==0
        kernel_names={'native-valid-kernel-pass','optional-e-kernel-stops','optional-absent-kernel-continues'}
        kind_by_name={name:'ACTUAL_FULL_CONTROLLER_REFUSAL' for name in expected}
        kind_by_name.update({name:'ACTUAL_KERNEL_ORDINARY_EXECUTION' for name in kernel_names})
        kind_by_name.update({'native-valid-qualified':'ACTUAL_FULL_CURRENT_CONTROLLER_PROVIDER','restored-exact-identities':'ACTUAL_BEFORE_AFTER_IDENTITY_EQUALITY'})
        shape_by_kind={
            'ACTUAL_FULL_CONTROLLER_REFUSAL':{'name','kind','reason','exception','path','purpose','fixture_sha256'},
            'ACTUAL_KERNEL_ORDINARY_EXECUTION':{'name','kind','provider','stdout_sha256','stdout_hex','stderr_sha256','exit','uid','receipt_path'},
            'ACTUAL_FULL_CURRENT_CONTROLLER_PROVIDER':{'name','kind','record','old_elf_control','current_native_elf_control'},
            'ACTUAL_BEFORE_AFTER_IDENTITY_EQUALITY':{'name','kind','native','interpreter','providers','constructed'},
        }
        actual_kernel_names=[]
        actual_names=[]
        for row in observed['cases']:
            assert type(row) is dict and type(row.get('name')) is str and type(row.get('kind')) is str
            name=row['name'];kind=row['kind'];assert name in kind_by_name and kind==kind_by_name[name] and set(row)==shape_by_kind[kind]
            actual_names.append(name)
            if kind=='ACTUAL_KERNEL_ORDINARY_EXECUTION':
                assert type(row['uid']) is int and row['uid']==observed['ordinary_uid']
                assert type(row['exit']) is int and row['exit']==(1 if name=='optional-e-kernel-stops' else 0)
                assert type(row['provider']) is dict and row['provider']['candidate']=='/usr/bin/clang' and row['provider']['purpose']=='native'
                assert all(type(row[key]) is str for key in ('stdout_sha256','stdout_hex','stderr_sha256','receipt_path'))
                assert Path(row['receipt_path'])==receipts/'evidence'/name/'receipt.json'
                actual_kernel_names.append(name)
            elif kind=='ACTUAL_FULL_CONTROLLER_REFUSAL':
                assert all(type(row[key]) is str for key in ('reason','exception','path','purpose','fixture_sha256'))
            elif kind=='ACTUAL_FULL_CURRENT_CONTROLLER_PROVIDER':
                assert all(type(row[key]) is dict for key in ('record','old_elf_control','current_native_elf_control'))
            else:
                assert type(row['native']) is dict and type(row['interpreter']) is dict and type(row['providers']) is list and type(row['constructed']) is dict
                assert row['constructed']==observed['fixture_paths']
        assert actual_names==expected and len(actual_names)==len(set(actual_names))==15
        assert len(actual_kernel_names)==observed['owned_subject_commands']==3 and set(actual_kernel_names)==kernel_names
    else:
        assert (receipts/'evidence/acceptance.json').is_file()
    runtime.write(logs/'workspace-disposition.json',{'status':'RETAINED_PRIVATE_WORKSPACE_FOR_RECEIPT_UPLOAD','workspace':str(workspace),'device':workspace.stat().st_dev,'inode':workspace.stat().st_ino,'owned_descendants_empty':not runtime.descendants(),'source_target_fault_binaries_uploaded':False,'cleanup':'After confirmed evidence artifact upload, root reviews exact workspace identity and bounded deletion. Runner hardkill/missing retirement receipts is HOLD, not acceptance.'})
except BaseException as error:
    diagnostics(error,code)
    runtime.write(logs/'workspace-disposition.json',{'status':'HARNESS_ERROR_PRIVATE_WORKSPACE_RETAINED','workspace':str(workspace),'error':str(error),'no_acceptance_from_partial_outputs':True,'cleanup':'Root-owned exact-path review after evidence preservation; no automated deletion on uncertain ownership.'})
    raise

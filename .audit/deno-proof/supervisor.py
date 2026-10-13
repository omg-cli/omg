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
logs=workspace/'supervisor'; logs.mkdir()
runtime.write(logs/'dispatch-admission.json',admission)
env={name:os.environ[name] for name in ('GITHUB_EVENT_PATH','GITHUB_EVENT_NAME','GITHUB_SHA','GITHUB_REF','GITHUB_ACTOR','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_TEMP','GITHUB_WORKSPACE','HOME')}
env.update(PATH='/usr/bin:/bin',LANG='C.UTF-8')
try:
    code,stdout,stderr=runtime.execute([sys.executable,'-I','-B',str(PACKAGE/'controller.py')],PACKAGE,env,logs/'controller',8000)
    assert code==0
    assert (workspace/'evidence/acceptance.json').is_file()
    runtime.write(logs/'workspace-disposition.json',{'status':'RETAINED_PRIVATE_WORKSPACE_FOR_RECEIPT_UPLOAD','workspace':str(workspace),'device':workspace.stat().st_dev,'inode':workspace.stat().st_ino,'owned_descendants_empty':not runtime.descendants(),'source_target_fault_binaries_uploaded':False,'cleanup':'After confirmed evidence artifact upload, root reviews exact workspace identity and bounded deletion. Runner hardkill/missing retirement receipts is HOLD, not acceptance.'})
except BaseException as error:
    runtime.write(logs/'workspace-disposition.json',{'status':'HARNESS_ERROR_PRIVATE_WORKSPACE_RETAINED','workspace':str(workspace),'error':str(error),'no_acceptance_from_partial_outputs':True,'cleanup':'Root-owned exact-path review after evidence preservation; no automated deletion on uncertain ownership.'})
    raise

"""Full 37-method intact suite in a genuinely owned root child; no alternate selection."""
import hashlib,json,os,stat,sys,traceback,unittest
from pathlib import Path
PACKAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(PACKAGE))
import runtime
import provenance
import test_registry_snapshot_contract as positive
import test_registry_archive_integrity as integrity
manifest=json.loads((PACKAGE/'manifest.json').read_bytes())
for name,expected in manifest['package_inputs'].items():
    assert hashlib.sha256((PACKAGE/name).read_bytes()).hexdigest()==expected
assert hashlib.sha256((PACKAGE/'controller.py').read_bytes()).hexdigest()==manifest['controller_sha256']
admission=runtime.initialize(manifest)
assert os.getuid()==0 and sys.argv[1:]==[]
root=runtime.PROTECTED_ROOT
fixture=root/'registry-contract-fixture'
evidence=runtime.WORKSPACE/'receipts/evidence'
context=evidence/'suite-context';context.mkdir();(context/'evidence').mkdir()
provider=Path('/opt/omg-deno-proof/rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin')
env=json.loads((evidence/'suite-environment.json').read_bytes())
assert Path(env['CARGO_HOME'])==root/'cargo-home' and Path(env['HOME'])==root/'compiler-home'
assert Path(env['TMPDIR'])==root/'integrity'
for path in (fixture,root/'cargo-home',root/'integrity'):
    provenance.protected_ancestors(path);provenance.protected(path,directory=True)
positive.RegistrySnapshotContract.context=(context,provider,fixture,runtime.execute,env,runtime.digest_file,runtime.write)
integrity.RegistryArchiveIntegrityContract.fixture_root=root/'integrity'
integrity.RegistryActiveClosureContract.context=(evidence/'contract-metadata/stdout',fixture)
loader=unittest.TestLoader()
suite=unittest.TestSuite([loader.loadTestsFromTestCase(positive.RegistrySnapshotContract),loader.loadTestsFromTestCase(integrity.RegistryArchiveIntegrityContract),loader.loadTestsFromTestCase(integrity.RegistryActiveClosureContract)])
def flatten(suite):
    return [test.id() for group in suite for test in (group if isinstance(group,unittest.TestSuite) else [group])]
assert flatten(suite)==manifest['expected_test_ids'] and len(flatten(suite))==37
class StrictResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.started=[];self.named=[];self.nested=[]
    def startTest(self,test):
        self.started.append(test.id());super().startTest(test)
    def addSuccess(self,test):
        self.named.append({'id':test.id(),'status':'PASS'});super().addSuccess(test)
    def addFailure(self,test,error):
        self.named.append({'id':test.id(),'status':'FAIL','trace':''.join(traceback.format_exception(*error))});super().addFailure(test,error)
    def addError(self,test,error):
        self.named.append({'id':test.id(),'status':'ERROR','trace':''.join(traceback.format_exception(*error))});super().addError(test,error)
    def addSkip(self,test,reason):
        self.named.append({'id':test.id(),'status':'SKIP','reason':reason});super().addSkip(test,reason)
    def addSubTest(self,test,subtest,error):
        self.nested.append({'parent_id':test.id(),'params':dict(subtest.params),'id':subtest.id(),'status':'PASS' if error is None else 'FAIL','trace':None if error is None else ''.join(traceback.format_exception(*error))});super().addSubTest(test,subtest,error)
result=unittest.TextTestRunner(verbosity=2,resultclass=StrictResult).run(suite)
rows=[{'parent_id':r['parent_id'],'params':r['params']} for r in result.nested]
expected=manifest['expected_nested_observations']
valid=(result.testsRun==37 and result.started==manifest['expected_test_ids'] and [r['id'] for r in result.named]==manifest['expected_test_ids'] and all(r['status']=='PASS' for r in result.named) and len(result.named)==37 and len(result.nested)==11 and rows==expected and all(r['status']=='PASS' for r in result.nested) and not result.failures and not result.errors and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and runtime.CANCELLED is None)
for name,expected_hash in manifest['package_inputs'].items():
    assert hashlib.sha256((PACKAGE/name).read_bytes()).hexdigest()==expected_hash
runtime.write(evidence/'suite-result.json',{'status':'CORRECTED_INTACT37_RAW_PASS_PENDING_ROOT_INDEPENDENT_ADMISSION' if valid else 'CORRECTED_INTACT37_NOT_ACCEPTED','tests_run':result.testsRun,'started_ids':result.started,'named_results':result.named,'nested_observations':result.nested,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),'controller_uid':os.getuid(),'source_manifest_sha256':admission['manifest_sha256'],'workflow_sha':os.environ['GITHUB_SHA'],'provenance_sha256':manifest['package_inputs']['provenance.py'],'full548_credit':0,'Deno_matrix_credit':0,'compiler_credit':0})
sys.exit(0 if valid else 1)

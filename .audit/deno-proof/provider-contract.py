"""Future hosted real Linux provider contract. No Deno matrix credit."""
import ctypes,hashlib,importlib.util,json,os,pwd,signal,stat,sys
from pathlib import Path
PACKAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(PACKAGE))
import runtime

def require(value,message): runtime.require(value,message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    require(spec is not None and spec.loader is not None,'full controller loader absent')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def main():
    manifest=json.loads((PACKAGE/'manifest.json').read_bytes())
    inputs=dict(manifest['package_inputs'],**{'controller.py':manifest['controller_sha256']})
    def packages():
        for name,pin in inputs.items():require(sha((PACKAGE/name).read_bytes())==pin,'full package changed: '+name)
    packages();admission=runtime.initialize(manifest)
    require(os.getuid()==0 and sys.platform=='linux' and sys.version_info>=(3,11),'Linux root fixture constructor required')
    signal.alarm(90)
    out=runtime.WORKSPACE;receipts=out/'receipts';evidence=receipts/'evidence'
    require(out.is_dir() and receipts.is_dir() and not evidence.exists(),'fresh contract supervisor workspace required');evidence.mkdir()
    fs=os.statvfs(out);require(fs.f_bavail*fs.f_frsize>=manifest['min_free_bytes'],'initial free resource floor unmet')
    available=int(Path('/proc/meminfo').read_text().split('MemAvailable:',1)[1].split()[0])*1024
    require(available>=manifest['min_available_memory_bytes'],'initial memory resource floor unmet')
    require(not runtime.descendants(),'contract owns preexisting children')
    identity=pwd.getpwnam('omg-deno-proof');require(identity.pw_uid>0 and identity.pw_gid>0,'actual ordinary fixture UID required')
    current=load_module('full_current_deno_controller',PACKAGE/'controller.py')
    previous=load_module('full_previous_deno_controller',PACKAGE/'previous-controller-v6.py')
    providers=[current.tool('/bin/sh','interpreter'),current.tool(sys.executable,'interpreter'),current.tool('/usr/bin/sleep','interpreter'),current.tool('/usr/bin/git','native')]
    require(providers[0]['sha256']!=providers[1]['sha256'],'distinct actual ELF providers required for drift fixture')
    shell=Path(providers[0]['path']);python=Path(providers[1]['path'])
    require(shell.stat().st_size<=16*1024**2 and python.stat().st_size<=16*1024**2,'fixture ELF source exceeds16MiB copied-file cap')
    fixtures=[Path('/usr/bin/clang'),Path('/usr/bin/perl')]
    for path in fixtures:
        require(not path.exists() and not path.is_symlink(),'contract namespace occupied HOLD: '+str(path))
        require(path.parent.is_dir() and not path.parent.is_symlink(),'direct fixture parent required')
    native,interpreter=fixtures
    constructed={}
    def create(path,data):
        with path.open('xb') as stream:stream.write(data)
        path.chmod(0o755)
        info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755,'fixture constructor identity')
        constructed[str(path)]={'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid,'gid':info.st_gid,'mode':info.st_mode}
    def replace(path,data):
        info=path.lstat();identity_before=constructed[str(path)]
        require(stat.S_ISREG(info.st_mode) and info.st_dev==identity_before['device'] and info.st_ino==identity_before['inode'] and info.st_uid==0 and info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o755,'owned fixture path drift')
        path.write_bytes(data)
    valid=b"#!/bin/sh\nsleep 1\nprintf '%s' 'NATIVE_FIXTURE_OK'\n"
    create(native,valid);create(interpreter,shell.read_bytes())
    home=out/'contract-home';home.mkdir(mode=0o700);os.chown(home,identity.pw_uid,identity.pw_gid)
    tmp=home/'tmp';tmp.mkdir(mode=0o700);os.chown(tmp,identity.pw_uid,identity.pw_gid)
    env={'PATH':'/usr/bin:/bin','HOME':str(home),'TMPDIR':str(tmp),'LANG':'C.UTF-8'}
    checks=[]
    def note(name,record):
        require(name not in [r['name'] for r in checks],'duplicate contract case')
        checks.append(dict(record,name=name));runtime.write(evidence/(name+'.json'),checks[-1])
    def refusal(name,action,reason,path,purpose,prior=False):
        try:action()
        except RuntimeError as error:
            actual=str(error)
            require(actual=='HARNESS_ERROR: '+reason if prior else actual.startswith('HARNESS_ERROR: '+reason+': '),'wrong genuine provider refusal: '+actual)
            if not prior:
                require('"candidate": "'+str(path)+'"' in actual and '"purpose": "'+purpose+'"' in actual,'refusal lacks exact path/purpose')
            note(name,{'kind':'ACTUAL_FULL_CONTROLLER_REFUSAL','reason':reason,'exception':actual,'path':str(path),'purpose':purpose,'fixture_sha256':runtime.digest_file(path)})
        else:raise RuntimeError('HARNESS_ERROR: expected real refusal absent: '+name)
    def run(name,expected_stdout,expected_exit):
        packages();current.check_tools(providers)
        before=current.tool(native,'native')
        code,stdout,stderr=runtime.execute([str(native)],home,env,evidence/name,10,identity)
        require(stdout==expected_stdout and stderr==b'' and code==expected_exit,'literal actual fixture outcome mismatch: '+name)
        receipt=json.loads((evidence/name/'receipt.json').read_bytes())
        require(receipt['requested_uid']==identity.pw_uid and any(r['last']['pid']==receipt['pid'] and r['last']['uid']==identity.pw_uid for r in receipt['owned_pidfd_identities']),'actual ordinary UID missing')
        require(receipt['direct_child_reaped'] and receipt['retirement']['retired'] and receipt['retirement']['final_owned_census']==[] and receipt['error'] is None and not receipt['raw_refused_or_truncated'],'actual fixture retirement/capture refused')
        current.check_tools([before,*providers]);packages()
        note(name,{'kind':'ACTUAL_KERNEL_ORDINARY_EXECUTION','provider':before,'stdout_sha256':sha(stdout),'stdout_hex':stdout.hex(),'stderr_sha256':sha(stderr),'exit':code,'uid':identity.pw_uid,'receipt_path':str(evidence/name/'receipt.json')})
    refusal('old-valid-script-red',lambda:previous.tool(native),'direct ELF provider required',native,'rust',True)
    qualified=current.tool(native,'native');require(qualified['format']['kind']=='SHEBANG' and qualified['format']['interpreter']==providers[0],'native real script/interpreter qualification mismatch')
    old_elf_control=previous.tool('/usr/bin/git')
    require(old_elf_control['sha256']==providers[3]['sha256'] and providers[3]['format']['kind']=='ELF','actual original/current ELF positive control mismatch')
    note('native-valid-qualified',{'kind':'ACTUAL_FULL_CURRENT_CONTROLLER_PROVIDER','record':qualified,'old_elf_control':old_elf_control,'current_native_elf_control':providers[3]})
    run('native-valid-kernel-pass',b'NATIVE_FIXTURE_OK',0)
    refusal('strict-rust-script-refused',lambda:current.tool(native),'direct ELF provider required',native,'rust')
    negatives=[('malformed-script',b'not an executable format\n','native provider requires ELF or bounded explicit shebang'),('no-lf-script',b'#!/bin/sh'+b' '*256,'native provider requires ELF or bounded explicit shebang'),('crlf-script',b'#!/bin/sh\r\nexit 0\n','native shebang must be ASCII without control bytes'),('env-interpreter-script',b'#!/usr/bin/env sh\nexit 0\n','native shebang interpreter outside explicit absolute allowlist'),('unallowed-interpreter-script',b'#!/private/unbound\nexit 0\n','native shebang interpreter outside explicit absolute allowlist')]
    for name,data,reason in negatives:
        replace(native,data);refusal(name,lambda:current.tool(native,'native'),reason,native,'native')
    optional=b"#!/bin/sh -e\nsleep 1\nfalse\nprintf '%s' 'MUST_NOT_RUN'\n"
    replace(native,optional);record=current.tool(native,'native');require(record['format']['optional_argument']=='-e','single optional argument mismatch')
    run('optional-e-kernel-stops',b'',1)
    replace(native,optional.replace(b'#!/bin/sh -e\n',b'#!/bin/sh\n'))
    run('optional-absent-kernel-continues',b'MUST_NOT_RUN',0)
    nested=b"#!/usr/bin/perl\nsleep 1\nprintf '%s' 'NATIVE_FIXTURE_OK'\n"
    replace(native,nested);nested_record=current.tool(native,'native');require(nested_record['format']['interpreter']['sha256']==providers[0]['sha256'],'copied interpreter source attribution mismatch')
    replace(interpreter,b'#!/bin/sh\nexit 0\n')
    refusal('nested-script-interpreter-refused',lambda:current.tool(native,'native'),'direct ELF provider required',interpreter,'interpreter')
    replace(interpreter,shell.read_bytes());current.check_tools([nested_record])
    replace(interpreter,python.read_bytes())
    refusal('interpreter-identity-drift-refused',lambda:current.check_tools([nested_record]),'provider changed',native,'native')
    replace(interpreter,shell.read_bytes());current.check_tools([nested_record])
    replace(native,valid);original=current.tool(native,'native');replace(native,valid+b'# actual fixture byte drift\n')
    refusal('native-body-drift-refused',lambda:current.check_tools([original]),'provider changed',native,'native')
    replace(native,valid);current.check_tools([original,*providers]);packages()
    note('restored-exact-identities',{'kind':'ACTUAL_BEFORE_AFTER_IDENTITY_EQUALITY','native':original,'interpreter':current.tool(interpreter,'interpreter'),'providers':providers,'constructed':constructed})
    expected=['old-valid-script-red','native-valid-qualified','native-valid-kernel-pass','strict-rust-script-refused',*[n for n,d,r in negatives],'optional-e-kernel-stops','optional-absent-kernel-continues','nested-script-interpreter-refused','interpreter-identity-drift-refused','native-body-drift-refused','restored-exact-identities']
    require([r['name'] for r in checks]==expected and len(checks)==15 and runtime.CANCELLED is None and not runtime.descendants(),'contract case/count/cancellation mismatch')
    runtime.write(evidence/'provider-contract-acceptance.json',{'status':'REAL_PROVIDER_FORMAT_CONTRACT_OBSERVED_INDEPENDENT_ADMISSION_REQUIRED','names':expected,'cases':checks,'ordinary_uid':identity.pw_uid,'owned_subject_commands':3,'source_manifest_sha256':admission['manifest_sha256'],'workflow_sha':os.environ['GITHUB_SHA'],'runtime_Deno_matrix_credit':0,'original_v6_native_identity':'UNKNOWN','actual_kernel':dict(zip(('sysname','nodename','release','version','machine'),os.uname())),'fixture_paths':constructed,'fixture_disposition':'Only newly owned clang/perl in disposable contract job; no protected prior provider overwritten; container disposal after artifact receipt.'})

if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('HARNESS_ERROR:',type(error).__name__,str(error),file=sys.stderr)
        raise

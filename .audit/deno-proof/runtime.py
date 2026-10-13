"""Linux pidfd/subreaper commands with capped real pipe capture."""
import ctypes, hashlib, json, os, selectors, signal, stat, subprocess, time
from pathlib import Path
CANCELLED=None
WORKSPACE=None
PROTECTED_ROOT=None
MONITORED_ROOT_IDENTITIES={}
def require(value,message):
    if not value: raise RuntimeError('HARNESS_ERROR: '+message)
def write(path,value):
    with path.open('x',encoding='utf-8') as stream: json.dump(value,stream,indent=2); stream.write('\n')
def digest_file(path,ceiling=256*1024**2):
    require(path.stat().st_size<=ceiling,'hash input above declared ceiling')
    result=hashlib.sha256(); size=0
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''):
            size+=len(block); require(size<=ceiling,'hash input grew beyond ceiling'); result.update(block)
    return result.hexdigest()
def latch(signum,frame):
    global CANCELLED
    CANCELLED=signum
def table():
    result={}
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal(): continue
        try:
            fields=(p/'stat').read_text().rsplit(')',1)[1].split()
            uid=int((p/'status').read_text().split('Uid:',1)[1].split()[0])
        except FileNotFoundError: continue
        result[int(p.name)]={'pid':int(p.name),'ppid':int(fields[1]),'session':int(fields[3]),'start_ticks':int(fields[19]),'state':fields[0],'uid':uid}
    return result
def descendants():
    rows=table(); parents={os.getpid()}
    while True:
        added={pid for pid,r in rows.items() if r['ppid'] in parents}-parents
        if not added: break
        parents.update(added)
    return [rows[p] for p in sorted(parents-{os.getpid()})]
def own_pidfds(handles):
    for row in descendants():
        key=(row['pid'],row['start_ticks'])
        if key in handles: handles[key]['last']=row; continue
        try: fd=os.pidfd_open(row['pid'])
        except ProcessLookupError: continue
        current=table().get(row['pid'])
        if current is None or current['start_ticks']!=row['start_ticks']:
            os.close(fd); continue
        handles[key]={'fd':fd,'first':row,'last':current}
def retire(child,handles):
    deadline=time.monotonic()+20; reaped=[]; signals=[]
    while True:
        own_pidfds(handles)
        for key,item in handles.items():
            try: signal.pidfd_send_signal(item['fd'],signal.SIGKILL)
            except ProcessLookupError: continue
            signals.append({'pid':key[0],'start_ticks':key[1],'signal':'SIGKILL','atomic_pidfd':True})
        if child is not None and child.poll() is not None:
            while True:
                try:
                    pid,status=os.waitpid(-1,os.WNOHANG)
                    if pid==0: break
                    reaped.append({'pid':pid,'status':status})
                except ChildProcessError: break
        final=descendants()
        if not final: return {'signals':signals,'adopted_reaps':reaped,'final_owned_census':final,'retired':True}
        require(time.monotonic()<deadline,'owned descendants did not retire')
        time.sleep(0.02)
def monitored_root_identity(root):
    info=root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),'missing/aliased monitored root: '+str(root))
    return {'device':info.st_dev,'inode':info.st_ino}

def sizes(root,observation=None):
    result={'target':0,'cargo-home':0,'evidence':0,'integrity':0,'workspace':0}
    identity=monitored_root_identity(root)
    vanished=[]
    for p in root.rglob('*'):
        try:
            info=p.lstat()
        except FileNotFoundError as error:
            if error.filename!=str(p): raise
            require(monitored_root_identity(root)==identity,'monitored root identity changed during churn: '+str(root))
            vanished.append({'path':str(p),'relative_path':str(p.relative_to(root)),'errno':error.errno,'error_type':type(error).__name__})
            continue
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)): continue
        size=info.st_size; result['workspace']+=size
        first=p.relative_to(root).parts[0]
        if first=='receipts': first='evidence'
        if first in result and first!='workspace': result[first]+=size
    require(monitored_root_identity(root)==identity,'monitored root identity changed during sampling: '+str(root))
    if observation is not None:
        observation.update({'root_identity':identity,'disappeared_nodes':vanished,'disappeared_count':len(vanished)})
    return result

def monitor():
    roots=(WORKSPACE,PROTECTED_ROOT)
    rows=[]
    for root in roots:
        identity=monitored_root_identity(root)
        key=str(root)
        if key not in MONITORED_ROOT_IDENTITIES: MONITORED_ROOT_IDENTITIES[key]=identity
        require(MONITORED_ROOT_IDENTITIES[key]==identity,'monitored root identity changed between samples: '+str(root))
        fs=os.statvfs(root)
        observation={}
        sampled=sizes(root,observation)
        require(observation['root_identity']==identity and monitored_root_identity(root)==identity,'monitored root identity changed across monitor sample: '+str(root))
        row={'path':str(root),'device':identity['device'],'inode':identity['inode'],'free_bytes':fs.f_bavail*fs.f_frsize,'sizes':sampled,'inventory_observation':observation}
        require(row['free_bytes']>=4*1024**3,'sampled disk reserve breached')
        rows.append(row)
    totals={key:sum(r['sizes'][key] for r in rows) for key in rows[0]['sizes']}
    require(totals['target']<=16*1024**3 and totals['cargo-home']<=3*1024**3 and totals['workspace']<=22*1024**3,'sampled two-root footprint ceiling breached')
    return {'epoch':time.time(),'roots':rows,'combined_logical_sizes':totals,'qualification':'Sampled lstat regular-file logical sizes; disappeared entries are recorded; no hard quota or concurrent privileged writer guarantee.'}

def initialize(manifest):
    global WORKSPACE,PROTECTED_ROOT
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes()); inputs=event.get('inputs',{})
    canonical=hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    require(manifest['execution_release']=='ROOT_REVIEWED_RUNTIME_DISPATCH_REQUIRED','release semantics mismatch')
    require(os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and inputs.get('deno-proof-head')==os.environ['GITHUB_SHA'],'actual dispatch/head mismatch')
    require(inputs.get('deno-proof-contract')==canonical and inputs.get('deno-proof-release')=='root-reviewed','reviewed dispatch contract absent')
    require(os.environ['GITHUB_REF'].startswith('refs/heads/codex/deno-alias-proof-'),'wrong branch')
    require(event.get('sender',{}).get('login')==os.environ['GITHUB_ACTOR'],'dispatch actor mismatch')
    require(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'pidfd unavailable')
    require(Path('/sys/fs/cgroup/memory.max').read_text().strip()==str(6*1024**3),'declared container6GiB memory cap not observed')
    require(Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()=='0','declared no-swap container cap not observed')
    require(Path('/sys/fs/cgroup/pids.max').read_text().strip()=='512','declared container512process cap not observed')
    require(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0)==0,'subreaper unavailable')
    for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM): signal.signal(signum,latch)
    os.umask(0o022)
    WORKSPACE=Path(os.environ['RUNNER_TEMP'])/'deno-alias-proof'
    run=os.environ['GITHUB_RUN_ID']; attempt=os.environ['GITHUB_RUN_ATTEMPT']
    require(run.isdecimal() and attempt.isdecimal(),'invalid namespace handles')
    PROTECTED_ROOT=Path('/opt')/('omg-cargo-intact37-'+run+'-'+attempt)
    return {'manifest_sha256':canonical,'workflow_sha':os.environ['GITHUB_SHA'],'actor':os.environ['GITHUB_ACTOR'],'run_id':os.environ['GITHUB_RUN_ID'],'run_attempt':os.environ['GITHUB_RUN_ATTEMPT'],'inputs':inputs}
def execute(argv,cwd,env,output,seconds,identity=None,capture_bytes=16*1024**2,input_bytes=None):
    require(CANCELLED is None and not descendants(),'cancelled or unowned preexisting controller child')
    output.mkdir(); channels={}; selector=selectors.DefaultSelector(); handles={}
    digest={name:hashlib.sha256() for name in ('stdout','stderr')}; observed={name:0 for name in digest}
    retained=0; child=None; input_stream=None; code=None; error=None; retirement=None; samples=[]; started=time.time()
    def drop():
        if identity is not None: os.setgroups([]); os.setgid(identity.pw_gid); os.setuid(identity.pw_uid)
        os.umask(0o077)
    try:
        if input_bytes is not None: (output/'stdin').write_bytes(input_bytes); input_stream=(output/'stdin').open('rb')
        for name in digest: channels[name]=(output/name).open('xb')
        child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=input_stream or subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=drop)
        for name,pipe in [('stdout',child.stdout),('stderr',child.stderr)]:
            os.set_blocking(pipe.fileno(),False); selector.register(pipe,selectors.EVENT_READ,name)
        deadline=time.monotonic()+seconds; measure=0
        while selector.get_map() or child.poll() is None:
            require(CANCELLED is None and time.monotonic()<deadline,'cancelled/deadline')
            own_pidfds(handles)
            if time.monotonic()>=measure: samples.append(monitor()); measure=time.monotonic()+0.5
            for key,mask in selector.select(0.02):
                chunk=os.read(key.fileobj.fileno(),65536)
                if not chunk: selector.unregister(key.fileobj); key.fileobj.close(); continue
                name=key.data; observed[name]+=len(chunk); amount=min(len(chunk),max(0,capture_bytes-retained))
                channels[name].write(chunk[:amount]); digest[name].update(chunk[:amount]); retained+=amount
                require(amount==len(chunk),'retained channel hard cap reached')
        code=child.wait(timeout=5)
    except BaseException as exc: error={'type':type(exc).__name__,'message':str(exc)}
    finally:
        try: retirement=retire(child,handles)
        except BaseException as exc: error={'type':type(exc).__name__,'message':str(exc)}
        for stream in channels.values(): stream.close()
        if input_stream is not None: input_stream.close()
        selector.close()
        for pipe in (() if child is None else (child.stdout,child.stderr)):
            if pipe is not None and not pipe.closed: pipe.close()
        receipt={'argv':argv,'cwd':str(cwd),'environment':env,'pid':None if child is None else child.pid,'started_epoch':started,'ended_epoch':time.time(),'deadline_seconds':seconds,'exit':code,'requested_uid':0 if identity is None else identity.pw_uid,'owned_pidfd_identities':[dict(first=item['first'],last=item['last']) for item in handles.values()],'retirement':retirement,'direct_child_reaped':child is not None and child.returncode is not None,'resource_samples':samples,'channel_observed_bytes':observed,'hard_retained_bytes':retained,'hard_retained_ceiling':capture_bytes,'channel_sha256':{c:d.hexdigest() for c,d in digest.items()},'cancelled_signal':CANCELLED,'error':error,'raw_refused_or_truncated':error is not None}
        for item in handles.values(): os.close(item['fd'])
        write(output/'receipt.json',receipt)
    require(error is None and CANCELLED is None and retirement is not None and retirement['retired'],'command/retirement/resource/capture refusal')
    if identity is not None: require(any(item['last']['pid']==child.pid and item['last']['uid']==identity.pw_uid for item in handles.values()),'actual ordinary UID not observed')
    return code,(output/'stdout').read_bytes(),(output/'stderr').read_bytes()

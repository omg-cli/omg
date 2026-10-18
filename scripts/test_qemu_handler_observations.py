import datetime,hashlib,json,os,re,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path

HERE=Path(__file__).parent
SUBJECT=HERE / 'qemu-transactions.sh'
def bash_program():
    if os.name != 'nt':
        program = shutil.which('bash')
        if program:
            return program
    else:
        git = shutil.which('git')
        roots = [Path(git).resolve().parents[1]] if git else []
        roots += [Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git']
        for root in roots:
            for path in [root / 'bin/bash.exe', root / 'usr/bin/bash.exe']:
                if path.is_file():
                    return str(path)
    raise RuntimeError('Installed Bash is required for QEMU handler observation tests')


BASH=bash_program()
BOOT='ad377857-eacb-4854-be47-ce79d3b40a8d'
OTHER='d7fb4e63-f320-40a3-bffd-7f738276c3c4'

def shellpath(p):
 s=Path(p).as_posix()
 return '/'+s[0].lower()+s[2:] if re.match('[A-Za-z]:/',s) else s

def function(text,name):
 start=text.find(name+'() {\n')
 if start<0:return ''
 end=text.index('\n}\n',start)+3
 return text[start:end]

class DiagnosticTests(unittest.TestCase):
 def run_case(self,mode='drift',health=2,transport=0):
  with tempfile.TemporaryDirectory(prefix='issue945-',dir=HERE) as name:
   root=Path(name);trial=root/'trial';trial.mkdir()
   (root/'handler').write_bytes(b'fixture-handler-before\n')
   (root/'boot').write_text(BOOT+'\n')
   (root/'comm').write_bytes(b'systemd-shutdow\n')
   (root/'cmdline').write_bytes(b'/usr/lib/systemd/systemd-shutdown\x00poweroff\x00')
   (root/'exe').write_bytes(b'fixture-pid1-executable')
   (root/'uptime').write_bytes(b'123.45 240.00\n')
   if mode=='pid1_oversized':
    (root/'comm').write_bytes(b'x'*257)
    (root/'cmdline').write_bytes(b'x'*4097)
    (root/'exe').write_bytes(b'x'*(16*1024*1024+1))
    (root/'uptime').write_bytes(b'x'*129)
   if mode=='pid1_invalid':
    (root/'cmdline').write_bytes(b'not-nul-terminated')
    (root/'uptime').write_bytes(b'not-an-uptime')
   (root/'remote.py').write_text('''import builtins,json,os,sys
from pathlib import Path
root=Path(os.environ['FIXTURE_ROOT']); realopen=builtins.open
def fixture_open(path,*args,**kw):
 name={'/proc/sys/kernel/core_pattern':'handler','/proc/sys/kernel/random/boot_id':'boot','/proc/1/comm':'comm','/proc/1/cmdline':'cmdline','/proc/1/exe':'exe','/proc/uptime':'uptime'}.get(str(path))
 if name is None:raise AssertionError('unexpected remote path '+str(path))
 if os.environ['FIXTURE_MODE']=='read_failure' and name=='handler':raise PermissionError('controlled read failure')
 if os.environ['FIXTURE_MODE']=='pid1_unavailable' and name in ('comm','cmdline','exe','uptime'):raise PermissionError('controlled unavailable')
 return realopen(root/name,*args,**kw)
builtins.open=fixture_open
os.readlink=lambda path: '/usr/lib/systemd/systemd-shutdown' if str(path)=='/proc/1/exe' else (_ for _ in ()).throw(AssertionError('unexpected link'))
assert sys.argv[1]=='-'
sys.argv=sys.argv[1:]
exec(compile(sys.stdin.read(),'<received-remote-diagnostic>','exec'))
''')
   text=SUBJECT.read_text()
   funcs=function(text,'remote_argv')+'\n'+function(text,'handler_observation')
   hooks=[line.strip() for line in text.splitlines() if line.strip().startswith('handler_observation ')]
   before=next((h for h in hooks if 'before-measurement' in h),'')
   after=next((h for h in hooks if 'before-health' in h),'')
   script='''set -euo pipefail
trial=$1;boot_id=$2
ssh_guest() {
  if [[ "$FIXTURE_TRANSPORT" != 0 ]]; then return "$FIXTURE_TRANSPORT"; fi
  bash -c "$1"
}
timeout() { shift 2; "$@"; }
sudo() { [[ "$1" == -n ]]; shift; "$@"; }
python3() { "$FIXTURE_PYTHON" -X utf8 -I -B "$FIXTURE_ROOT/remote.py" "$@"; }
export -f timeout sudo python3
'''+funcs+'\n'+before+'''
printf 'measurement\n' >> "$trial/status"
case "$FIXTURE_MODE" in
 drift) printf 'fixture-handler-after\n' > "$FIXTURE_ROOT/handler" ;;
 boot_change) printf '%s\n' 'd7fb4e63-f320-40a3-bffd-7f738276c3c4' > "$FIXTURE_ROOT/boot" ;;
 oversized) head -c 4097 /dev/zero > "$FIXTURE_ROOT/handler" ;;
 invalid_utf8) printf '\\377' > "$FIXTURE_ROOT/handler" ;;
esac
'''+after+'''
printf 'health:%s\n' "$FIXTURE_HEALTH" >> "$trial/status"
exit "$FIXTURE_HEALTH"
'''
   path=root/'run.sh';path.write_text(script,encoding='utf-8',newline='\n')
   env=dict(os.environ,FIXTURE_ROOT=root.as_posix(),FIXTURE_MODE=mode,FIXTURE_HEALTH=str(health),FIXTURE_TRANSPORT=str(transport),FIXTURE_PYTHON=sys.executable.replace('\\','/'),MSYS_NO_PATHCONV='1')
   result=subprocess.run([str(BASH),'--noprofile','--norc',shellpath(path),shellpath(trial),BOOT],capture_output=True,timeout=15,env=env)
   log=(trial/'boot.log').read_text() if (trial/'boot.log').exists() else ''
   rows=[json.loads(s) for s in log.splitlines()]
   status=(trial/'status').read_text() if (trial/'status').exists() else ''
   record_path=os.environ.get('FIXTURE_RECORDS')
   if record_path:
    evidence=Path(record_path)
    records=json.loads(evidence.read_bytes()) if evidence.exists() else []
    records.append(dict(method=self.id(),mode=mode,requested_health_exit=health,transport=transport,actual_exit=result.returncode,records=rows,status=status,stdout=result.stdout.decode(errors='replace'),stderr=result.stderr.decode(errors='replace'),shell_sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    evidence.write_text(json.dumps(records,indent=2)+'\n')
   return result,rows,status,log

 def test_pid1_identity_is_literal_same_observation_and_false_health_remains_failure(self):
  p,rows,status,_=self.run_case('unchanged',health=2)
  self.assertEqual(p.returncode,2)
  self.assertEqual(status,'measurement\nhealth:2\n')
  for row in rows:
   self.assertEqual(row['pid1']['comm'],{'status':'OBSERVED','value':'systemd-shutdow'})
   self.assertEqual(row['pid1']['cmdline'],{'status':'OBSERVED','value':['/usr/lib/systemd/systemd-shutdown','poweroff']})
   self.assertEqual(row['pid1']['executable'],{'status':'OBSERVED','link':'/usr/lib/systemd/systemd-shutdown','bytes':23,'sha256':'c7f778671a7ece8a1a532fbb25a9fb5c2edcb295b35bed843985cb7eeeb64f86'})
   self.assertEqual(row['pid1']['uptime'],{'status':'OBSERVED','value':'123.45'})
   self.assertEqual(row['boot_id'],BOOT)

 def test_pid1_unavailable_is_explicit_and_does_not_mask_failure(self):
  p,rows,status,_=self.run_case('pid1_unavailable',health=7)
  self.assertEqual(p.returncode,7)
  for row in rows:
   self.assertEqual(row['status'],'observed')
   self.assertEqual(row['pid1'],{key:{'status':'UNKNOWN','reason':'read-error'} for key in ('comm','cmdline','executable','uptime')})
  self.assertEqual(status,'measurement\nhealth:7\n')

 def test_pid1_oversized_inputs_are_unknown_without_partial_values(self):
  p,rows,status,log=self.run_case('pid1_oversized',health=7)
  self.assertEqual(p.returncode,7)
  self.assertEqual(status,'measurement\nhealth:7\n')
  for row in rows:
   self.assertEqual(row['pid1'],{key:{'status':'UNKNOWN','reason':'oversized-input'} for key in ('comm','cmdline','executable','uptime')})
  self.assertLess(len(log.encode()),4096)

 def test_pid1_invalid_cmdline_and_uptime_are_unknown(self):
  p,rows,_,_=self.run_case('pid1_invalid')
  self.assertEqual(p.returncode,2)
  for row in rows:
   for key in ('cmdline','uptime'):
    self.assertEqual(row['pid1'][key],{'status':'UNKNOWN','reason':'invalid-or-changing-identity'})

 def test_bin_false_still_refused_by_unchanged_health_collector(self):
  import importlib.util
  from unittest.mock import patch
  spec=importlib.util.spec_from_file_location('private_qemu_health',HERE/'check-qemu-health.py')
  health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)
  with patch.object(health,'query',return_value='|/bin/false'):
   with self.assertRaisesRegex(ValueError,'unsupported kernel crash handler: bytes=11 sha256='):
    health.crash_channel_capability(BOOT)

 def test_records_actual_handler_drift_on_the_same_boot(self):
  p,rows,status,log=self.run_case()
  self.assertEqual(p.returncode,2,p.stderr.decode())
  self.assertEqual([r['phase'] for r in rows],['before-measurement','before-health'])
  self.assertEqual([(r['status'],r['boot_id'],r['bytes'],r['sha256']) for r in rows],[('observed',BOOT,22,'7e3a23e845e6eaa3493dbc92ff8ee99cf05361a2621e8bd11d7961db2fd203bb'),('observed',BOOT,21,'24198940ea297131db0f3dd07c457e9a0775001c5641515ca3f044ddb435d75d')])
  self.assertEqual(status,'measurement\nhealth:2\n')
  self.assertNotIn('fixture-handler',log)
  for row in rows:self.assertEqual(datetime.datetime.fromisoformat(row['observed_utc']).utcoffset(),datetime.timedelta())

 def test_read_failure_is_explicit_without_masking_health_failure(self):
  p,rows,status,_=self.run_case('read_failure',health=7)
  self.assertEqual(p.returncode,7)
  self.assertEqual([(r['status'],r['error']) for r in rows],[('unavailable','read-error')]*2)
  self.assertEqual(status,'measurement\nhealth:7\n')

 def test_boot_change_is_explicit(self):
  p,rows,status,_=self.run_case('boot_change')
  self.assertEqual(p.returncode,2)
  self.assertEqual([(r['status'],r['boot_id'],r['expected_boot_id']) for r in rows],[('observed',BOOT,BOOT),('unavailable',OTHER,BOOT)])
  self.assertEqual(rows[1]['error'],'boot-mismatch')

 def test_oversized_handler_has_no_partial_hash(self):
  p,rows,_,log=self.run_case('oversized')
  self.assertEqual(p.returncode,2)
  self.assertEqual(len(rows),2)
  self.assertEqual((rows[1]['status'],rows[1]['error'],rows[1]['bytes'],rows[1]['sha256']),('unavailable','oversized-input',None,None))
  self.assertLess(len(log.encode()),2048)

 def test_invalid_utf8_is_explicit(self):
  p,rows,_,_=self.run_case('invalid_utf8')
  self.assertEqual(p.returncode,2)
  self.assertEqual(len(rows),2)
  self.assertEqual((rows[1]['status'],rows[1]['error']),('unavailable','invalid-utf8'))

 def test_transport_failure_retains_original_health_failure(self):
  p,rows,status,_=self.run_case(transport=255,health=9)
  self.assertEqual(p.returncode,9)
  self.assertEqual([(r['status'],r['transport_exit']) for r in rows],[('transport-error',255)]*2)
  self.assertEqual(status,'measurement\nhealth:9\n')

 def test_observed_records_do_not_make_success_fail(self):
  p,rows,status,_=self.run_case('unchanged',health=0)
  self.assertEqual(p.returncode,0,p.stderr.decode())
  self.assertEqual([r['status'] for r in rows],['observed','observed'])
  self.assertEqual(status,'measurement\nhealth:0\n')

if __name__=='__main__':unittest.main(verbosity=2)

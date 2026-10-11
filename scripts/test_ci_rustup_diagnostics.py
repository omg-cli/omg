import hashlib,importlib.util,json,pathlib,subprocess,tempfile,unittest
C=pathlib.Path(__file__).resolve().parents[1]
def helper():
 p=C/'scripts/ci-rustup-diagnostics.py'
 spec=importlib.util.spec_from_file_location('diagnostics',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class DiagnosticsTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.tc=self.root/'toolchain'
 def fixture(self,owner=True):
  meta=self.tc/'lib/rustlib';meta.mkdir(parents=True);(self.tc/'bin').mkdir()
  (meta/'components').write_text('rustfmt-preview-x86_64-unknown-linux-gnu\n' if owner else '')
  if owner:(meta/'manifest-rustfmt-preview-x86_64-unknown-linux-gnu').write_text('file:bin/cargo-fmt\nfile:bin/rustfmt\n')
  for n in ['cargo-fmt','rustfmt']:(self.tc/'bin'/n).write_bytes(b'fixture')
 def test_absent_before_minimal_is_explicit(self):
  d=helper().snapshot(self.tc);self.assertEqual(d['state'],'toolchain_absent');self.assertNotIn('classification',d)
 def test_owned_and_unowned_destinations(self):
  self.fixture();m=helper();d=m.snapshot(self.tc);self.assertEqual(d['state'],'observed');self.assertEqual(d['classification']['cargo-fmt']['state'],'destination_and_registered_owner_consistent')
  (self.tc/'lib/rustlib/components').write_text('');d=m.snapshot(self.tc);self.assertEqual(d['classification']['cargo-fmt']['state'],'destination_without_registered_rustfmt_owner')
 def test_existing_toolchain_missing_components_is_error(self):
  self.tc.mkdir();d=helper().snapshot(self.tc);self.assertEqual(d['state'],'diagnostic_error');self.assertTrue(d['errors']);self.assertNotIn('classification',d)
 def test_missing_registered_manifest_is_error(self):
  self.fixture();(self.tc/'lib/rustlib/manifest-rustfmt-preview-x86_64-unknown-linux-gnu').unlink();d=helper().snapshot(self.tc);self.assertEqual(d['state'],'diagnostic_error');self.assertNotIn('classification',d)
 def test_symlink_and_malformed_metadata_are_errors(self):
  self.fixture();p=self.tc/'lib/rustlib/components';p.unlink();p.symlink_to(self.root/'absent');d=helper().snapshot(self.tc);self.assertEqual(d['state'],'diagnostic_error')
  p.unlink();p.write_text('bogus/component\n');d=helper().snapshot(self.tc);self.assertEqual(d['state'],'diagnostic_error')
 def test_nonregular_and_symlink_destination_not_healthy(self):
  self.fixture();p=self.tc/'bin/cargo-fmt';p.unlink();p.mkdir();d=helper().snapshot(self.tc);self.assertEqual(d['classification']['cargo-fmt']['state'],'nonregular_destination_requires_investigation')
  p.rmdir();p.symlink_to('rustfmt');d=helper().snapshot(self.tc);self.assertEqual(d['classification']['cargo-fmt']['state'],'symlink_destination_requires_investigation')
 def test_capture_append_only_error_envelope(self):
  m=helper();out=self.root/'out';self.tc.mkdir();p=m.capture(self.tc,'before_minimal',out);d=json.loads(p.read_text());self.assertEqual(d['snapshot']['state'],'diagnostic_error');self.assertIn('helper_sha256',d);self.assertEqual(d['stage'],'before_minimal')
  with self.assertRaises(FileExistsError):m.capture(self.tc,'before_minimal',out)
 def test_unstable_metadata_read_is_error(self):
  self.fixture();m=helper();original=m.read_regular
  def changing(p):
   if p.name=='components':raise OSError('changed during read')
   return original(p)
  m.read_regular=changing;d=m.snapshot(self.tc);self.assertEqual(d['state'],'diagnostic_error');self.assertIn('changed during read',str(d['errors']))
 def test_actual_read_regular_rejects_identity_change_at_open(self):
  from unittest.mock import patch
  m=helper();p=self.root/'metadata';p.write_bytes(b'registered\n')
  expected={'text':'registered\n','sha256':hashlib.sha256(b'registered\n').hexdigest()}
  self.assertEqual(m.read_regular(p),expected)
  original=pathlib.Path.open;replacement=self.root/'replacement';replacement.write_bytes(b'registered\n');before=p.stat().st_ino
  def changed(target,*args,**kwargs):
   if target==p and args and args[0]=='rb':replacement.replace(p)
   return original(target,*args,**kwargs)
  with patch.object(pathlib.Path,'open',changed):
   with self.assertRaisesRegex(OSError,'metadata changed during read'):
    m.read_regular(p)
  self.assertNotEqual(p.stat().st_ino,before)
  self.assertEqual(m.read_regular(p),expected)
 def test_owning_caller_diagnostic_write_errors_preserve_bootstrap_exit(self):
  import os
  text=(C/'.github/workflows/ci.yml').read_text()
  block=text.split('      - name: Install pinned Rust toolchain\n',1)[1].split('      - uses: actions/checkout@',1)[0]
  caller='\n'.join(line[10:] for line in block.split('        run: |\n',1)[1].splitlines())
  prefix=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all','--no-new-privs'] if os.geteuid()==0 else []
  cases=[('installer',23,False),('installer',23,True),('components',27,False),('components',27,True),('installer',0,False),('components',0,True),('preminimal',23,True),('preminimal',0,True)]
  for index,(deny_at,code,deny_status) in enumerate(cases):
   with self.subTest(deny_at=deny_at,code=code,status=deny_status),tempfile.TemporaryDirectory() as t:
    root=pathlib.Path(t);root.chmod(0o755);out=root/'diagnostics';out.mkdir();out.chmod(0o700)
    uid=65534 if prefix else os.geteuid()
    if prefix:os.chown(out,uid,uid)
    (out/'helper.py').write_bytes((C/'scripts/ci-rustup-diagnostics.py').read_bytes())
    status=out/'bootstrap-status.txt';status.write_text('');trace=root/'trace';trace.write_text('')
    for f in [status,trace]:
     if prefix:os.chown(f,uid,uid)
     f.chmod(0o600)
    fallback=out/'capture-errors.log';fallback.write_text('');fallback.chmod(0o400)
    if deny_status and deny_at!='components':status.chmod(0o400)
    def cmd(which):
     denial='chmod 500 "$RUSTUP_DIAGNOSTICS_DIR"\n' if deny_at==which else ''
     if deny_status and deny_at=='components' and which=='components':denial+='chmod 400 "$RUSTUP_DIAGNOSTICS_DIR/bootstrap-status.txt"\n'
     rc=code if (which=='installer' and deny_at in ['installer','preminimal']) or (which=='components' and deny_at=='components') else 0
     return f'printf "{which}\\n" >> "$OWNED_TRACE"\nprintf "original-{which}-stdout\\n"\nprintf "original-{which}-stderr\\n" >&2\n{denial}exit {rc}'
    if deny_at=='preminimal':out.chmod(0o500)
    env={**os.environ,'HOME':str(root/'home'),'RUSTUP_HOME':str(root/'absent'),'RUSTUP_DIAGNOSTICS_DIR':str(out),'OWNED_TRACE':str(trace),'RUSTUP_INSTALL':cmd('installer'),'RUSTUP_COMPONENTS':cmd('components')}
    try:r=subprocess.run([*prefix,'sh','-e','-c',caller],env=env,capture_output=True,text=True,timeout=10)
    finally:
     out.chmod(0o700);status.chmod(0o600)
    self.assertEqual(r.returncode,code,r.stderr)
    self.assertEqual(trace.read_text().splitlines(),['installer'] if code==23 else ['installer','components'])
    self.assertIn('diagnostic_error:',r.stderr)
    self.assertIn('original-installer-stdout',r.stdout);self.assertIn('original-installer-stderr',r.stderr)
    self.assertFalse((out/'after_components.json').exists())
 def test_real_permission_error_retains_envelope(self):
  import os
  self.fixture();self.root.chmod(0o755);p=self.tc/'lib/rustlib/components';p.chmod(0);out=self.root/'out';out.mkdir();out.chmod(0o777)
  prefix=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all','--no-new-privs'] if os.geteuid()==0 else []
  command=[*prefix,'python3','-B',str(C/'scripts/ci-rustup-diagnostics.py'),'capture','--toolchain',str(self.tc),'--stage','before_minimal','--out',str(out)]
  r=subprocess.run(command,capture_output=True,text=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);data=json.loads((out/'before_minimal.json').read_text());self.assertEqual(data['actor']['uid'],65534 if prefix else os.geteuid());self.assertEqual(data['snapshot']['state'],'diagnostic_error');self.assertIn('PermissionError',str(data['snapshot']['errors']));p.chmod(0o644)
 def test_checkout_join_actual_ids_and_mismatch(self):
  m=helper();repo=self.root/'repo';(repo/'scripts').mkdir(parents=True);p=repo/'scripts/ci-rustup-diagnostics.py';p.write_bytes((C/'scripts/ci-rustup-diagnostics.py').read_bytes());subprocess.run(['git','init','-q',str(repo)],check=True);subprocess.run(['git','add','.'],cwd=repo,check=True);subprocess.run(['git','-c','user.name=fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'],cwd=repo,check=True)
  from unittest.mock import patch
  head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
  with patch.dict('os.environ',{'GITHUB_SHA':head}):
   out=self.root/'joined';self.assertTrue(m.join(repo,out));d=json.loads((out/'source-join.json').read_text());self.assertEqual(d['actual_checkout']['head'],head);self.assertEqual(d['state'],'verified_checkout_and_helper');p.write_bytes(p.read_bytes()+b'\n');self.assertFalse(m.join(repo,self.root/'badjoin'));self.assertEqual(json.loads((self.root/'badjoin/source-join.json').read_text())['state'],'staging_error')
 def test_same_helper_wrong_declared_source_refused(self):
  from unittest.mock import patch
  m=helper();repo=self.root/'repo';(repo/'scripts').mkdir(parents=True);(repo/'scripts/ci-rustup-diagnostics.py').write_bytes((C/'scripts/ci-rustup-diagnostics.py').read_bytes());subprocess.run(['git','init','-q',str(repo)],check=True);subprocess.run(['git','add','.'],cwd=repo,check=True);subprocess.run(['git','-c','user.name=fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture'],cwd=repo,check=True)
  for i,declared in enumerate(['a'*40,'', 'not-a-commit']):
   with patch.dict('os.environ',{'GITHUB_SHA':declared}):
    out=self.root/f'refused-{i}';self.assertFalse(m.join(repo,out));d=json.loads((out/'source-join.json').read_text());self.assertEqual(d['state'],'staging_error');self.assertIn('error',d)
class WorkflowBytesTests(unittest.TestCase):
 def test_embedded_helper_and_ordering(self):
  text=(C/'.github/workflows/ci.yml').read_text();block=text.split('  linux-matrix:',1)[1].split('\n  sandbox-cancellation:',1)[0]
  embedded=block.split("<<'RUSTUP_DIAGNOSTICS_PY'\n",1)[1].split('          RUSTUP_DIAGNOSTICS_PY',1)[0]
  actual=''.join(line[10:]+'\n' for line in embedded.splitlines());canonical=(C/'scripts/ci-rustup-diagnostics.py').read_bytes()
  self.assertEqual(actual.encode(),canonical);self.assertIn(hashlib.sha256(canonical).hexdigest(),block)
  for first,second in [('Stage Rustup diagnostics','Install pinned Rust toolchain'),('Install pinned Rust toolchain','uses: actions/checkout@'),('Join Rustup diagnostic source before first proxy','Cache Rust dependencies')]:self.assertLess(block.index(first),block.index(second))
  self.assertLess(block.index('observe before_minimal'),block.index('"$RUSTUP_INSTALL"'))
  upload=block.split('      - name: Preserve Rustup diagnostics\n',1)[1].split('\n      # sccache',1)[0];self.assertIn('        if: always()\n',upload);self.assertIn('          if-no-files-found: error\n',upload)
 def test_job_environment_contexts_and_private_diagnostic_path(self):
  import re
  text=(C/'.github/workflows/ci.yml').read_text()
  allowed={'github','needs','strategy','matrix','vars','secrets','inputs'}
  # GitHub's jobs.<job_id>.env context table excludes runner and env.
  for job,body in re.findall(r'^  ([\w-]+):\n(.*?)(?=^  [\w-]+:|\Z)',text,re.M|re.S):
   env=re.search(r'^    env:\n(.*?)(?=^    \S|\Z)',body,re.M|re.S)
   if env:
    for expression in re.findall(r'\$\{\{(.*?)\}\}',env.group(1),re.S):
     roots=set(re.findall(r'\b([A-Za-z_]\w*)\s*[.\[]',expression))
     self.assertLessEqual(roots,allowed,f'{job} job env uses unavailable contexts: {roots-allowed}')
  block=text.split('  linux-matrix:',1)[1].split('\n  sandbox-cancellation:',1)[0]
  template=re.search(r'^      RUSTUP_DIAGNOSTICS_DIR: (.+)$',block,re.M).group(1)
  lanes=re.findall(r'^          - platform: (\S+)$',block,re.M)
  self.assertEqual(len(lanes),5)
  paths=[]
  for run,attempt,lane in [(run,attempt,lane) for run in ['41','42'] for attempt in ['1','2'] for lane in lanes]:
   values={'github.run_id':run,'github.run_attempt':attempt,'matrix.platform':lane}
   rendered=re.sub(r'\$\{\{\s*(.*?)\s*\}\}',lambda match:values[match.group(1)],template)
   path=pathlib.PurePosixPath(rendered)
   self.assertTrue(path.is_absolute());self.assertEqual(path.parent,pathlib.PurePosixPath('/tmp'))
   self.assertNotEqual(path.name,'');paths.append(str(path))
  self.assertEqual(len(set(paths)),len(paths),'runs, attempts and matrix lanes must not share diagnostic output')
if __name__=='__main__':unittest.main(verbosity=2)

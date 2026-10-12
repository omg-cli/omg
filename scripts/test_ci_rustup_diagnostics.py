import hashlib,importlib.util,json,os,pathlib,subprocess,tempfile,unittest
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
class BookkeepingTests(unittest.TestCase):
 setUp=DiagnosticsTests.setUp
 fixture=DiagnosticsTests.fixture
 def bookkeeping_fixture(self):
  self.fixture();meta=self.tc/'lib/rustlib'
  (meta/'multirust-config.toml').write_text('config_version = "1"\n[[components]]\npkg = "rustfmt-preview"\ntarget = "x86_64-unknown-linux-gnu"\nis_extension = false\n')
  (meta/'multirust-channel-manifest.toml').write_text('manifest-version = "2"\ndate = "2026-04-16"\n[pkg.rustfmt-preview.target.x86_64-unknown-linux-gnu]\navailable = true\n')
  return meta
 def test_actual_bookkeeping_capture_and_cofault(self):
  meta=self.bookkeeping_fixture();m=helper();d=m.snapshot(self.tc);b=d['rustup_bookkeeping']
  self.assertEqual(b['state'],'bookkeeping_observed')
  self.assertEqual(b['rustfmt_config_membership'],{'rustfmt-preview-x86_64-unknown-linux-gnu':True})
  for name in ('multirust-config.toml','multirust-channel-manifest.toml'):
   f=b['files'][name];self.assertEqual(f['state'],'captured');self.assertEqual(f['sha256'],hashlib.sha256((meta/name).read_bytes()).hexdigest());self.assertEqual(f['metadata']['size'],(meta/name).stat().st_size)
  (meta/'multirust-config.toml').write_text('config_version = "1"\ncomponents = []\n')
  d=m.snapshot(self.tc)
  self.assertEqual(d['classification']['cargo-fmt']['state'],'destination_and_registered_owner_consistent')
  self.assertEqual(d['rustup_bookkeeping']['rustfmt_config_membership'],{'rustfmt-preview-x86_64-unknown-linux-gnu':False})
  self.assertEqual(d['rustup_bookkeeping']['state'],'installer_rustfmt_not_in_config')
 def test_missing_and_legacy_are_distinct(self):
  meta=self.bookkeeping_fixture();m=helper()
  for name in ('multirust-config.toml','multirust-channel-manifest.toml'):
   path=meta/name;raw=path.read_bytes();path.unlink();b=m.snapshot(self.tc)['rustup_bookkeeping'];self.assertEqual(b['state'],'bookkeeping_file_absent');self.assertEqual(b['files'][name]['state'],'absent');path.write_bytes(raw)
  out=self.root/'summary';out.mkdir();(out/'before_minimal.json').write_text(json.dumps({'snapshot':{'components':{}}}));m.summary(out)
  self.assertEqual(json.loads((out/'stage-status.json').read_text())['bookkeeping_stages']['before_minimal'],'bookkeeping_not_collected')
 def test_malformed_duplicate_unknown_and_rename_stay_unknown(self):
  meta=self.bookkeeping_fixture();m=helper();config=meta/'multirust-config.toml';original=config.read_bytes()
  cases=[('broken [','bookkeeping_parse_error'),('config_version="9"\ncomponents=[]','bookkeeping_unknown_schema'),('config_version="1"\ncomponents=[{pkg="rustfmt-preview",target="*"}]','bookkeeping_unknown_schema'),('config_version="1"\ncomponents=[{pkg="rustfmt-preview",target="x86_64-unknown-linux-gnu"},{pkg="rustfmt-preview",target="x86_64-unknown-linux-gnu"}]','bookkeeping_unknown_schema')]
  for text,state in cases:
   with self.subTest(text=text):config.write_text(text);self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],state)
  config.write_bytes(original);manifest=meta/'multirust-channel-manifest.toml';manifest.write_text(manifest.read_text()+'\n[renames.rustfmt]\nto="missing-package"\n');self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'bookkeeping_unknown_schema')
 def test_valid_manifest_rename_preserves_canonical_membership(self):
  meta=self.bookkeeping_fixture();m=helper();manifest=meta/'multirust-channel-manifest.toml'
  manifest.write_text(manifest.read_text()+'\n[renames.rustfmt]\nto="rustfmt-preview"\n')
  b=m.snapshot(self.tc)['rustup_bookkeeping'];self.assertEqual(b['state'],'bookkeeping_observed');self.assertEqual(b['rustfmt_config_membership'],{'rustfmt-preview-x86_64-unknown-linux-gnu':True})
  (meta/'multirust-config.toml').write_text('config_version="1"\ncomponents=[]\n')
  b=m.snapshot(self.tc)['rustup_bookkeeping'];self.assertEqual(b['state'],'installer_rustfmt_not_in_config');self.assertEqual(b['rustfmt_config_membership'],{'rustfmt-preview-x86_64-unknown-linux-gnu':False})
  for invalid in ['[renames.rustfmt]\nto=17\n','[renames.rustfmt]\nto="rustfmt-preview"\nextra=true\n']:
   with self.subTest(invalid=invalid):
    manifest.write_text('manifest-version="2"\ndate="2026-04-16"\n[pkg.rustfmt-preview.target.x86_64-unknown-linux-gnu]\navailable=true\n'+invalid);self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'bookkeeping_unknown_schema')
 def test_actual_bookkeeping_read_identity_fault(self):
  from unittest.mock import patch
  meta=self.bookkeeping_fixture();m=helper();p=meta/'multirust-config.toml';replacement=self.root/'replacement';replacement.write_bytes(p.read_bytes());original=pathlib.Path.open
  def changing(target,*args,**kwargs):
   if target==p and args and args[0]=='rb' and replacement.exists():replacement.replace(p)
   return original(target,*args,**kwargs)
  with patch.object(pathlib.Path,'open',changing):
   d=m.snapshot(self.tc);self.assertEqual(d['state'],'diagnostic_error');self.assertEqual(d['rustup_bookkeeping']['state'],'diagnostic_error');self.assertIn('changed during read',str(d['rustup_bookkeeping']['files'][p.name]['error']))
  self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'bookkeeping_observed')
 def test_nonregular_symlink_and_oversize_bookkeeping_errors(self):
  meta=self.bookkeeping_fixture();m=helper();p=meta/'multirust-config.toml';raw=p.read_bytes();p.unlink();p.mkdir();self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'diagnostic_error');p.rmdir();p.symlink_to('multirust-channel-manifest.toml');self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'diagnostic_error');p.unlink();p.write_bytes(b'x'*(1024*1024+1));self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'diagnostic_error');p.write_bytes(raw);self.assertEqual(m.snapshot(self.tc)['rustup_bookkeeping']['state'],'bookkeeping_observed')
 def test_real_unreadable_bookkeeping_retains_error(self):
  import os
  meta=self.bookkeeping_fixture();self.root.chmod(0o755);p=meta/'multirust-config.toml';p.chmod(0);out=self.root/'out';out.mkdir();out.chmod(0o777)
  prefix=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all','--no-new-privs'] if os.geteuid()==0 else []
  command=[*prefix,'python3','-B',str(C/'scripts/ci-rustup-diagnostics.py'),'capture','--toolchain',str(self.tc),'--stage','before_minimal','--out',str(out)]
  try:r=subprocess.run(command,capture_output=True,text=True,timeout=10)
  finally:p.chmod(0o644)
  self.assertEqual(r.returncode,0,r.stderr);d=json.loads((out/'before_minimal.json').read_text());self.assertEqual(d['snapshot']['state'],'diagnostic_error');self.assertIn('PermissionError',d['snapshot']['rustup_bookkeeping']['files'][p.name]['error']);self.assertEqual(d['actor']['uid'],65534 if prefix else os.geteuid())
 def test_disappearance_after_observation_is_error_not_absent(self):
  from unittest.mock import patch
  meta=self.bookkeeping_fixture();m=helper();p=meta/'multirust-config.toml';original=pathlib.Path.open
  def disappearing(target,*args,**kwargs):
   if target==p and args and args[0]=='rb':p.unlink()
   return original(target,*args,**kwargs)
  with patch.object(pathlib.Path,'open',disappearing):
   b=m.snapshot(self.tc)['rustup_bookkeeping'];self.assertEqual(b['state'],'diagnostic_error');self.assertEqual(b['files'][p.name]['state'],'diagnostic_error')
 def test_bookkeeping_fault_keeps_installer_manifest_and_bins(self):
  meta=self.bookkeeping_fixture();p=meta/'multirust-config.toml';p.unlink();p.mkdir();d=helper().snapshot(self.tc)
  self.assertEqual(d['state'],'diagnostic_error');self.assertEqual(d['rustup_bookkeeping']['state'],'diagnostic_error');self.assertEqual(d['components']['manifest-rustfmt-preview-x86_64-unknown-linux-gnu']['text'],'file:bin/cargo-fmt\nfile:bin/rustfmt\n')
  self.assertTrue(d['bins']['cargo-fmt']['present']);self.assertEqual(d['bins']['cargo-fmt']['sha256'],hashlib.sha256(b'fixture').hexdigest());self.assertEqual(d['classification']['cargo-fmt']['state'],'destination_and_registered_owner_consistent')
 def test_installer_fault_keeps_bookkeeping_and_unknown_membership(self):
  meta=self.bookkeeping_fixture();p=meta/'components';p.unlink();p.mkdir();d=helper().snapshot(self.tc)
  self.assertEqual(d['state'],'diagnostic_error');b=d['rustup_bookkeeping'];self.assertEqual(b['files']['multirust-config.toml']['state'],'captured');self.assertEqual(b['config_component_pairs'],[{'pkg':'rustfmt-preview','target':'x86_64-unknown-linux-gnu'}]);self.assertEqual(b['membership_state'],'installer_components_not_observed');self.assertNotIn('rustfmt_config_membership',b);self.assertTrue(d['bins']['cargo-fmt']['present']);self.assertNotIn('classification',d)
 def test_bin_fault_keeps_other_bins_and_both_metadata_layers(self):
  from unittest.mock import patch
  self.bookkeeping_fixture();m=helper();original=m.destination
  def failed(path):
   if path.name=='cargo-fmt':raise OSError('controlled destination read fault')
   return original(path)
  with patch.object(m,'destination',failed):d=m.snapshot(self.tc)
  self.assertEqual(d['state'],'diagnostic_error');self.assertEqual(d['bins']['cargo-fmt']['state'],'diagnostic_error');self.assertTrue(d['bins']['rustfmt']['present']);self.assertEqual(d['rustup_bookkeeping']['state'],'bookkeeping_observed');self.assertIn('manifest-rustfmt-preview-x86_64-unknown-linux-gnu',d['components']);self.assertNotIn('classification',d)
 def test_actual_summary_legacy_unreached_and_malformed(self):
  m=helper();out=self.root/'out';out.mkdir();(out/'before_minimal.json').write_text(json.dumps({'snapshot':{}}));(out/'after_minimal.json').write_text('{bad');(out/'after_components.json').write_text(json.dumps({'snapshot':{'rustup_bookkeeping':{'state':'diagnostic_error'}}}));m.summary(out);d=json.loads((out/'stage-status.json').read_text())
  self.assertEqual(d['bookkeeping_stages'],{'before_minimal':'bookkeeping_not_collected','after_minimal':'diagnostic_error','after_components':'diagnostic_error','before_first_proxy':'not_reached'});self.assertIn('after_minimal',d['summary_errors'])
 def test_actual_summary_unreadable_is_error_not_unreached(self):
  import os
  self.root.chmod(0o755);out=self.root/'out';out.mkdir();out.chmod(0o777);p=out/'before_minimal.json';p.write_text(json.dumps({'snapshot':{}}));p.chmod(0)
  prefix=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--bounding-set=-all','--no-new-privs'] if os.geteuid()==0 else []
  try:r=subprocess.run([*prefix,'python3','-B',str(C/'scripts/ci-rustup-diagnostics.py'),'summary','--out',str(out)],capture_output=True,text=True,timeout=10)
  finally:p.chmod(0o644)
  self.assertEqual(r.returncode,0,r.stderr);d=json.loads((out/'stage-status.json').read_text());self.assertEqual(d['bookkeeping_stages']['before_minimal'],'diagnostic_error');self.assertIn('PermissionError',d['summary_errors']['before_minimal'])
 def test_summary_large_envelope_and_explicit_bound(self):
  m=helper();out=self.root/'out';out.mkdir();(out/'before_minimal.json').write_text(json.dumps({'snapshot':{'rustup_bookkeeping':{'state':'bookkeeping_observed'},'raw_fixture':'x'*(1024*1024)}}));(out/'after_minimal.json').write_text(json.dumps({'snapshot':{'raw_fixture':'x'*(4*1024*1024)}}));m.summary(out);d=json.loads((out/'stage-status.json').read_text());self.assertEqual(d['bookkeeping_stages']['before_minimal'],'bookkeeping_observed');self.assertEqual(d['bookkeeping_stages']['after_minimal'],'diagnostic_error');self.assertIn('metadata exceeds limit',d['summary_errors']['after_minimal'])
class WorkflowBytesTests(unittest.TestCase):
 def test_embedded_helper_and_ordering(self):
  text=(C/'.github/workflows/ci.yml').read_text();block=text.split('  linux-matrix:',1)[1].split('\n  sandbox-cancellation:',1)[0]
  embedded=block.split("<<'RUSTUP_DIAGNOSTICS_PY'\n",1)[1].split('          RUSTUP_DIAGNOSTICS_PY',1)[0]
  actual=''.join(line[10:]+'\n' for line in embedded.splitlines());canonical=(C/'scripts/ci-rustup-diagnostics.py').read_bytes()
  self.assertEqual(actual.encode(),canonical);self.assertIn(hashlib.sha256(canonical).hexdigest(),block)
  for first,second in [('Stage Rustup diagnostics','Install pinned Rust toolchain'),('Install pinned Rust toolchain','uses: actions/checkout@'),('Join Rustup diagnostic source before first proxy','Cache Rust dependencies')]:self.assertLess(block.index(first),block.index(second))
  self.assertLess(block.index('observe before_minimal'),block.index('"$RUSTUP_INSTALL"'))
  upload=block.split('      - name: Preserve Rustup diagnostics\n',1)[1].split('\n      # sccache',1)[0];self.assertIn('        if: always()\n',upload);self.assertIn('          if-no-files-found: error\n',upload)
 @unittest.skipUnless(os.name == "posix", "Linux bootstrap component shell contract")
 def test_matrix_bootstrap_installs_declared_toolchain_components(self):
  import os,re,tomllib
  required=set(tomllib.loads((C/'rust-toolchain.toml').read_text())['toolchain']['components'])
  block=(C/'.github/workflows/ci.yml').read_text().split('  linux-matrix:',1)[1].split('    container:',1)[0]
  lanes=re.findall(r'^          - platform: (\S+)\n(.*?)(?=^          - platform: |\Z)',block,re.M|re.S)
  self.assertEqual({lane for lane,_ in lanes},{'arch','debian','debian-trixie','ubuntu-2604','fedora'})
  for lane,row in lanes:
   with self.subTest(platform=lane),tempfile.TemporaryDirectory() as directory:
    home=pathlib.Path(directory);fake=home/'.cargo/bin/rustup';fake.parent.mkdir(parents=True);record=home/'arguments.json'
    fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["RECORD"]).write_text(json.dumps(sys.argv[1:]))\nsys.exit(int(os.environ.get("FAKE_EXIT","0")))\n');fake.chmod(0o755)
    match=re.search(r'^            rust_components: \|\n((?:              .*\n)+)',row,re.M);self.assertIsNotNone(match,lane)
    snippet=''.join(line[14:]+'\n' for line in match.group(1).splitlines());environment=dict(os.environ,HOME=str(home),RECORD=str(record))
    result=subprocess.run(['sh','-e','-c',snippet],env=environment,capture_output=True,text=True,timeout=5)
    self.assertEqual(result.returncode,0,result.stdout+result.stderr);arguments=json.loads(record.read_text());self.assertEqual(arguments[:2],['component','add']);self.assertLessEqual(required,set(arguments[2:]),lane+' bootstrap omits declared toolchain components')
    result=subprocess.run(['sh','-e','-c',snippet],env=dict(environment,FAKE_EXIT='42'),capture_output=True,text=True,timeout=5);self.assertEqual(result.returncode,42,'component failure must propagate')
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

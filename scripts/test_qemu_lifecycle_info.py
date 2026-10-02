"""Execute the shipped guest info boundary against independent native RPM fields."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'guest native info boundary requires POSIX shell')
class GuestInfoParityTests(unittest.TestCase):
    def run_info(self, name='tree.x86_64', version='2.2.1-4.fc44',
                 architecture='x86_64', epoch='0', query_status=0,
                 native_version='2.2.1', native_release='4.fc44', records=1):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        start = source.index('case "$distro" in\n  arch) sudo -n pacman -Syu')
        stop = source.index('\ninstalled() {', start)
        commands = source[start:stop]
        start = source.index('"$bin" info tree > evidence/omg-info.txt')
        stop = source.index('\n# Exercise both direct daemon startup', start)
        boundary = source[start:stop]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'evidence').mkdir()
            provider = root / 'bin'
            provider.mkdir()
            rpm = provider / 'rpm'
            rpm.write_text('''#!/usr/bin/python3
import os,sys
if sys.argv[1:] == ['-qi','tree']:
    print('Name: tree\\nArchitecture: '+os.environ['RPM_ARCH']+'\\nVersion: 2.2.1\\nRelease: 4.fc44')
elif sys.argv[1:3] == ['-q','--qf'] and sys.argv[-1] == 'tree':
    if int(os.environ['RPM_QUERY_STATUS']): sys.exit(int(os.environ['RPM_QUERY_STATUS']))
    values={'NAME':'tree','ARCH':os.environ['RPM_ARCH'],'EPOCHNUM':os.environ['RPM_EPOCH'],
            'VERSION':os.environ['RPM_VERSION'],'RELEASE':os.environ['RPM_RELEASE']}
    output=sys.argv[3]
    for key,value in values.items(): output=output.replace('%{'+key+'}',value)
    sys.stdout.write(output.replace('\\\\n','\\n')*int(os.environ['RPM_RECORDS']))
else: sys.exit(97)
''')
            rpm.chmod(0o755)
            cli = provider / 'omg'
            cli.write_text('#!/bin/sh\n[ "$1" = info ] && [ "$2" = tree ] || exit 98\nprintf "Name: %s\\nVersion: %s\\n" "$OMG_NAME" "$OMG_VERSION"\n')
            cli.chmod(0o755)
            script = ('set -euo pipefail\ndistro=fedora\nsudo() { return 0; }\n'
                      'bin="$1"\n' + commands + '\n' + boundary)
            env = dict(os.environ, PATH=str(provider)+':'+os.environ['PATH'], LC_ALL='C',
                       RPM_ARCH=architecture, RPM_EPOCH=epoch,
                       RPM_QUERY_STATUS=str(query_status), OMG_NAME=name, OMG_VERSION=version,
                       RPM_VERSION=native_version, RPM_RELEASE=native_release, RPM_RECORDS=str(records))
            return subprocess.run(['bash','-c',script,'_',str(cli)],cwd=root,env=env,
                                  capture_output=True,text=True,timeout=10)

    def test_qualified_native_identities_and_epochs_pass(self):
        for arch,epoch in [('x86_64','0'),('aarch64','0'),('x86_64','2')]:
            with self.subTest(architecture=arch,epoch=epoch):
                version=('' if epoch=='0' else epoch+':')+'2.2.1-4.fc44'
                result=self.run_info(name='tree.'+arch,version=version,architecture=arch,epoch=epoch)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_bare_wrong_architecture_name_and_version_are_rejected(self):
        for name,version in [('tree','2.2.1-4.fc44'),('tree.aarch64','2.2.1-4.fc44'),
                             ('other.x86_64','2.2.1-4.fc44'),('tree.x86_64','2.2.0-4.fc44')]:
            with self.subTest(name=name,version=version):
                self.assertEqual(self.run_info(name=name,version=version).returncode,1)

    def test_nonzero_epoch_must_not_be_dropped(self):
        self.assertEqual(self.run_info(epoch='2').returncode,1)

    def test_native_query_failure_remains_failure(self):
        self.assertEqual(self.run_info(query_status=17).returncode,17)

    def test_malformed_native_records_remain_failure(self):
        cases = [dict(name='tree.', architecture=''),
                 dict(version='-4.fc44', native_version=''),
                 dict(version='2.2.1-', native_release=''),
                 dict(version='invalid:2.2.1-4.fc44', epoch='invalid'),
                 dict(version='2.2.1 -4.fc44', native_version='2.2.1 '),
                 dict(name='', version='', records=0),
                 dict(name='tree.x86_64\nName: tree.x86_64',
                      version='2.2.1-4.fc44\nVersion: 0:2.2.1-4.fc44', records=2)]
        for fields in cases:
            with self.subTest(fields=fields):
                result = self.run_info(**fields)
                self.assertEqual(result.returncode,120,result.stderr)
                self.assertIn('not a single valid installed record',result.stderr)


if __name__ == '__main__':
    unittest.main()

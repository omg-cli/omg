"""Structural refusal contracts; native GPG admission is exercised in real Linux replay."""
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import subprocess
import sys

spec = importlib.util.spec_from_file_location('fedora_evidence', Path(__file__).with_name('qemu-fedora-advisory-evidence.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class FedoraEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.evidence = self.root/'evidence'; self.evidence.mkdir()
        self.archive = self.root/'native.tar.gz'; self.fixture = Path(__file__).with_name('qemu-fedora-advisory-oracle.py')
        binaries = {'omg': b'native CLI', 'omgd': b'native daemon'}
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in binaries.items():
                member = tarfile.TarInfo('omg-v0.1.224-x86_64-linux-fedora/'+name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        self.identity = {'name': 'glibc', 'epoch': '0', 'version': '2.43', 'release': '2.fc44', 'arch': 'x86_64'}
        self.native = 'glibc\t0\t2.43\t2.fc44\tx86_64\nrpm\t0\t6.0.2\t1.fc44\tx86_64\n'
        state = {'installed': self.native, 'explicit': 'rpm\n', 'reason_sha256': {'packages.toml': 'a'*64}}
        original = '[main]\ninstall_weak_deps=True\n'; self.put('native-dnf-before.conf', original)
        config_hash = hashlib.sha256(original.encode()).hexdigest()
        self.put('private-dnf.conf', '[main]\ninstall_weak_deps=True\nreposdir=/tmp/omg-fedora-advisory-qemu-616/repos\n')
        self.receipt = {'schema_version': 1, 'accepted': True, 'ordinary_user_uid': 1000,
                        'boot_id': '3fd492c0-4023-4b4b-9b8c-9c6209355920', 'isolated_vm_mount_and_network': True,
                        'scope': 'native signed metadata-only advisory lifecycle; no package upgrade/download claim',
                        'fixture_id': 'OMG-QEMU-FEDORA-616', 'expected_native_severity': 'Important',
                        'native_glibc_identity': self.identity, 'newer_advisory_nevra': 'glibc-2.43-2.fc44.omgqemu616.x86_64',
                        'native_rpm_comparison': '-1', 'key_fingerprint': 'A'*40,
                        'native_archive_sha256': hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                        'fixture_sha256': hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
                        'native_state_before': state, 'native_state_after': copy.deepcopy(state), 'native_state_unchanged': True,
                        'original_dnf_config_sha256': config_hash, 'daemon_requests_delta': 2, 'daemon_shutdown': True, 'product_results': {}}
        self.receipt.update({name+'_sha256': hashlib.sha256(data).hexdigest() for name, data in binaries.items()})
        self.put('native-query.tsv', self.native); self.put('native-version-comparison.txt', '-1\n'); self.put('os-release', 'ID=fedora\n')
        for phase in ('before', 'after'): self.put('parent-system-'+phase+'.sha256', config_hash+'  /etc/dnf/dnf.conf\n')
        self.put('fixture.repo', '[omg-qemu-616]\nname=Signed local advisory fixture\nbaseurl=file:///tmp/omg-fedora-advisory-qemu-616/repo\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nlocalpkg_gpgcheck=1\ngpgkey=file:///tmp/omg-fedora-advisory-qemu-616/fixture-key.asc\nskip_if_unavailable=false\n')
        rows = []
        for name, release, arch in [('OMG-QEMU-FEDORA-616', '2.fc44.omgqemu616', 'x86_64'), ('OMG-QEMU-FEDORA-FIXED', '2.fc44', 'x86_64'), ('OMG-QEMU-FEDORA-FOREIGN', '2.fc44.omgqemu616', 'aarch64')]:
            rows.append('<update type="security"><id>'+name+'</id><severity>Important</severity><references><reference id="CVE-OMG-QEMU-616" type="cve" href="https://example.invalid/omg-qemu-616"/></references><pkglist><collection><package name="glibc" epoch="0" version="2.43" release="'+release+'" arch="'+arch+'"/></collection></pkglist></update>')
        xml = ('<updates>'+''.join(rows)+'</updates>\n').encode(); self.put('updateinfo.xml', xml)
        compressed = gzip.compress(xml); self.put('updateinfo.xml.gz', compressed)
        self.put('repomd.xml', '<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo"><checksum type="sha256">'+hashlib.sha256(compressed).hexdigest()+'</checksum><open-checksum type="sha256">'+hashlib.sha256(xml).hexdigest()+'</open-checksum><location href="repodata/'+hashlib.sha256(xml).hexdigest()+'-updateinfo.xml.gz"/><size>'+str(len(compressed))+'</size><open-size>'+str(len(xml))+'</open-size></data></repomd>')
        self.put('native-advisory-list.stdout', json.dumps([{'name': 'OMG-QEMU-FEDORA-616', 'type': 'security', 'severity': 'Important', 'nevra': 'glibc-2.43-2.fc44.omgqemu616.x86_64'}]))
        self.put('native-advisory-info.stdout', json.dumps([{'Name': 'OMG-QEMU-FEDORA-616', 'Severity': 'Important', 'Type': 'security', 'references': [{'Id': 'CVE-OMG-QEMU-616', 'Type': 'cve', 'Url': 'https://example.invalid/omg-qemu-616'}], 'collections': {'packages': ['glibc-2.43-2.fc44.omgqemu616.x86_64']}}]))
        self.put('native-repository.stdout', json.dumps([{'id': 'omg-qemu-616', 'is_enabled': True, 'skip_if_unavailable': False, 'repo_gpgcheck': True, 'pkg_gpgcheck': True, 'available_pkgs': 0, 'pkgs': 0, 'base_url': ['file:///tmp/omg-fedora-advisory-qemu-616/repo'], 'gpg_key': ['file:///tmp/omg-fedora-advisory-qemu-616/fixture-key.asc']}]))
        output = 'Found 1 vulnerabilities (1 high severity)\n  glibc (1 issues):\n    → OMG-QEMU-FEDORA-616 - Synthetic native DNF advisory [Advisory severity: Important]\n'
        for phase in ('direct-plain', 'direct-findings', 'daemon-plain', 'daemon-findings', 'untrusted-metadata', 'daemon-before', 'daemon-after'):
            metrics = phase in ('daemon-before', 'daemon-after'); finding = phase.endswith('findings')
            self.receipt['product_results'][phase] = {'argv': ['metrics'] if metrics else ['audit', 'scan']+(['--fail-on-findings'] if finding else []), 'exit_code': int(finding or phase=='untrusted-metadata')}
            self.put(phase+'.stdout', ('omg_security_audit_requests_total '+str(2 if phase=='daemon-after' else 0)+'\n') if metrics else '' if phase=='untrusted-metadata' else output)
            self.put(phase+'.stderr', 'Error: Failed to query native security advisories: Bad PGP signature\n' if phase=='untrusted-metadata' else 'Error: Vulnerability scan found 1 finding(s)\n' if finding else '')
        common = ['dnf', '--setopt=cachedir=/tmp/omg-fedora-advisory-qemu-616/user/cache/dnf-security', '--setopt=system_cachedir=/tmp/omg-fedora-advisory-qemu-616/user/cache/dnf-security', '--setopt=cacheonly=none', '--setopt=*.skip_if_unavailable=false']
        self.commands = {label: {'argv': argv, 'exit_code': 0} for label, argv in {
            'native-advisory-list': common+['--refresh', 'advisory', 'list', '--available', '--security', '--json'],
            'native-advisory-info': common+['--cacheonly', 'advisory', 'info', '--available', '--security', '--json'],
            'native-repository': common+['--cacheonly', 'repo', 'info', '--enabled', '--json'],
            'dnf-key-admission': common+['--refresh', '-y', 'makecache'],
            'dnf-default-key-admission': ['dnf', '--setopt=*.skip_if_unavailable=false', '--refresh', '-y', 'makecache'],
            'private-config': ['mount', '--bind', '/tmp/omg-fedora-advisory-qemu-616/dnf.conf', '/etc/dnf/dnf.conf'],
            'modifyrepo': ['modifyrepo_c', '--compress-type', 'gz', '--mdtype', 'updateinfo', '/tmp/omg-fedora-advisory-qemu-616/updateinfo.xml', '/tmp/omg-fedora-advisory-qemu-616/repo/repodata'],
            'verify': ['gpg', '--verify', '/tmp/omg-fedora-advisory-qemu-616/repo/repodata/repomd.xml.asc', '/tmp/omg-fedora-advisory-qemu-616/repo/repodata/repomd.xml'],
        }.items()}
        self.put('excluded-dnf.conf', '[main]\ninstall_weak_deps=True\nreposdir=/tmp/omg-fedora-advisory-qemu-616/repos\nexcludepkgs=glibc*\n')
        self.receipt['excluded_installed_advisory_scope'] = True
        self.put('native-excluded-default-list.stdout', '[]\n')
        for suffix in ('list', 'info'):
            self.put('native-excluded-override-'+suffix+'.stdout',
                     (self.evidence/('native-advisory-'+suffix+'.stdout')).read_bytes())
        for label, arguments in {
            'native-excluded-default-list': ['--cacheonly', 'advisory', 'list', '--available', '--security', '--json'],
            'native-excluded-override-list': ['--setopt=disable_excludes=*', '--cacheonly', 'advisory', 'list', '--available', '--security', '--json'],
            'native-excluded-override-info': ['--setopt=disable_excludes=*', '--cacheonly', 'advisory', 'info', '--available', '--security', '--json'],
        }.items():
            self.commands[label] = {'argv': common+arguments, 'exit_code': 0}
        self.put('commands.json', json.dumps(self.commands))
        self.write()

    def put(self, name, value):
        (self.evidence/name).write_bytes(value if isinstance(value, bytes) else value.encode())

    def write(self):
        self.put('receipt.json', json.dumps(self.receipt))

    def check(self):
        return checker.validate_structure(self.evidence, self.archive, self.fixture)

    def test_complete_native_advisory_structure_is_consistent(self):
        try: admitted = self.check()
        except ValueError as error: self.fail('complete native metadata must replay: '+str(error))
        self.assertEqual(admitted, self.receipt)

    def test_missing_excluded_installed_package_controls_are_refused(self):
        # Native installed-package advisories must stay visible even when
        # ordinary package selection excludes their package name.
        for filename in ('excluded-dnf.conf', 'native-excluded-default-list.stdout',
                         'native-excluded-override-list.stdout', 'native-excluded-override-info.stdout'):
            path = self.evidence/filename
            saved = path.read_bytes()
            path.unlink()
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.check()
            path.write_bytes(saved)

    def test_exclusion_controls_must_prove_hidden_then_visible_installed_advisory(self):
        for filename, replacement in (
            ('excluded-dnf.conf', '[main]\nexcludepkgs=unrelated\n'),
            ('native-excluded-default-list.stdout', (self.evidence/'native-advisory-list.stdout').read_bytes()),
            ('native-excluded-override-list.stdout', '[]'),
            ('native-excluded-override-info.stdout', '[]'),
        ):
            path = self.evidence/filename
            saved = path.read_bytes()
            self.put(filename, replacement)
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.check()
            path.write_bytes(saved)
        self.receipt['excluded_installed_advisory_scope'] = False
        self.write()
        with self.assertRaises(ValueError):
            self.check()

    def test_optimized_python_rejects_false_clean_native_results(self):
        script = '''import importlib.util, sys
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location("oracle", sys.argv[1])
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
valid = "Found 1 vulnerabilities (1 high severity)\\n  glibc (1 issues):\\n    → OMG-QEMU-FEDORA-616 - Synthetic [Advisory severity: Important]\\n"
oracle.verify_native_result(SimpleNamespace(returncode=0, stdout=valid, stderr=""))
print("valid")
for result, fail in [(SimpleNamespace(returncode=0, stdout="No vulnerabilities found", stderr=""), False),
                     (SimpleNamespace(returncode=1, stdout=valid, stderr=""), True),
                     (SimpleNamespace(returncode=7, stdout=valid, stderr=""), False)]:
    try:
        oracle.verify_native_result(result, fail)
    except (AssertionError, ValueError):
        print("rejected")
    else:
        print("accepted invalid")
'''
        oracle = Path(__file__).with_name("qemu-fedora-advisory-oracle.py")
        for flags in ([], ["-O"]):
            with self.subTest(flags=flags):
                result = subprocess.run([sys.executable, *flags, "-c", script, str(oracle)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "valid\nrejected\nrejected\nrejected\n")

    def test_wrong_source_state_identity_severity_and_counters_are_refused(self):
        original = copy.deepcopy(self.receipt)
        for key, value in {'accepted': False, 'ordinary_user_uid': 0, 'native_archive_sha256': 'f'*64, 'fixture_sha256': 'f'*64,
                           'omgd_sha256': 'f'*64, 'native_state_after': {}, 'native_state_unchanged': False, 'daemon_requests_delta': 0,
                           'original_dnf_config_sha256': 'f'*64, 'expected_native_severity': 'Critical', 'native_rpm_comparison': '0', 'daemon_shutdown': False}.items():
            self.receipt = dict(original, **{key: value}); self.write()
            with self.subTest(key=key), self.assertRaises(ValueError): self.check()

    def test_native_selection_signature_settings_and_raw_findings_cannot_disagree(self):
        for name, replacement in [('native-advisory-list.stdout', '[]'), ('native-advisory-info.stdout', '[]'),
                                  ('native-repository.stdout', '[]'), ('fixture.repo', '[omg-qemu-616]\nrepo_gpgcheck=0\n'),
                                  ('daemon-findings.stdout', 'No vulnerabilities found\n'), ('daemon-findings.stderr', ''),
                                  ('untrusted-metadata.stderr', ''), ('private-dnf.conf', '[main]\ninstall_weak_deps=False\n'),
                                  ('native-query.tsv', self.native.replace('2.43', '2.42'))]:
            original = (self.evidence/name).read_bytes(); self.put(name, replacement)
            with self.subTest(name=name), self.assertRaises(ValueError): self.check()
            self.put(name, original)

    def test_native_command_failures_and_incomplete_records_are_refused(self):
        for label in self.commands:
            changed = copy.deepcopy(self.commands); changed[label]['exit_code'] = 1
            self.put('commands.json', json.dumps(changed))
            with self.subTest(label=label), self.assertRaises(ValueError): self.check()
        self.put('commands.json', '{}')
        with self.assertRaises(ValueError): self.check()

    def test_native_metadata_compression_recipe_must_match_replayed_gzip(self):
        changed = copy.deepcopy(self.commands)
        changed['modifyrepo']['argv'] = [arg for arg in changed['modifyrepo']['argv'] if arg not in ('--compress-type', 'gz')]
        self.put('commands.json', json.dumps(changed))
        with self.assertRaises(ValueError): self.check()

    def test_unsigned_or_corrupt_updateinfo_and_unsafe_paths_are_refused(self):
        for name, replacement in [('updateinfo.xml.gz', b'corrupt'), ('updateinfo.xml', b'<updates/>'),
                                  ('repomd.xml', b'<repomd/>'), ('parent-system-after.sha256', b'f'*64+b'  /etc/dnf/dnf.conf\n')]:
            original = (self.evidence/name).read_bytes(); self.put(name, replacement)
            with self.subTest(name=name), self.assertRaises(ValueError): self.check()
            self.put(name, original)
        self.receipt['native_state_before']['reason_sha256']['../secret']='b'*64
        self.receipt['native_state_after']=copy.deepcopy(self.receipt['native_state_before']);self.write()
        with self.assertRaises(ValueError): self.check()


if __name__ == '__main__':
    unittest.main()

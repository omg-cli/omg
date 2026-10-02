from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LiveDoctorTests(unittest.TestCase):
    def probe(self, fault=None, distro='debian'):
        oracle = ROOT / 'scripts/qemu-doctor-live-oracle.py'
        self.assertTrue(oracle.is_file(), 'the live-network report oracle is missing')
        names = [('Kernel.org', 'https://kernel.org'), ('GitHub', 'https://github.com')]
        hosts = ['kernel.org', 'github.com']
        basic = 'github.com'
        if distro == 'arch':
            names = [('Arch Linux', 'https://archlinux.org'), *names, ('AUR', 'https://aur.archlinux.org')]
            hosts = ['archlinux.org', 'aur.archlinux.org', 'github.com']
            basic = 'archlinux.org'
        prefix = f'  Internet connectivity ({basic} reachable)\n  PATH resolves a different omg executable first: "/fixture/path-shadow/omg"\n'
        mirrors = [f'  ✓ {name} (15 ms)\n' for name, _ in names]
        dns = [f'    ✓ {host} (2 addresses)\n' for host in hosts]
        count = 1
        if fault == 'mixed-failures':
            mirrors[-1] = f'  ✗ {names[-1][0]} (request failed for {names[-1][1]}/)\n'
            dns[-1] = f'    ✗ {hosts[-1]} (resolver unavailable)\n'
            count += 2
        if fault == 'wrong-target': mirrors[0] = mirrors[0].replace(names[0][0], 'Wrong mirror')
        if fault == 'duplicate': mirrors.append(mirrors[0])
        if fault == 'zero-addresses': dns[0] = dns[0].replace('2 addresses', '0 addresses')
        if fault == 'no-http-positive':
            mirrors = [f'  ✗ {name} (timeout)\n' for name, _ in names]
            count += len(names)
        if fault == 'no-dns-positive':
            dns = [f'    ✗ {host} (resolver unavailable)\n' for host in hosts]
            count += len(hosts)
        if fault == 'no-path-fault': prefix = prefix.splitlines(keepends=True)[0]
        report = prefix + 'Network Diagnostics\n' + ''.join(mirrors) + '\n  DNS Resolution:\n' + ''.join(dns)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for name, data in [('baseline.out', prefix), ('baseline.err', 'Error: doctor found 1 health issue(s)\n'),
                               ('network.out', report), ('network.err', f'Error: doctor found {count + (fault == "wrong-count")} health issue(s)\n')]:
                (work / name).write_text(data, encoding='utf-8')
            result = subprocess.run([sys.executable, str(oracle), '--distro', distro, '--baseline-exit', '1',
                                     '--exit', '1', '--baseline-out', str(work / 'baseline.out'),
                                     '--baseline-err', str(work / 'baseline.err'), '--out', str(work / 'network.out'),
                                     '--err', str(work / 'network.err')], capture_output=True, text=True, timeout=10)
            return result

    def test_actual_backend_targets_and_observed_failures(self):
        for distro in ('arch', 'debian', 'ubuntu', 'fedora'):
            for fault in (None, 'mixed-failures'):
                with self.subTest(distro=distro, fault=fault):
                    result = self.probe(fault, distro)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    receipt = json.loads(result.stdout)
                    self.assertTrue(receipt['complete'])
                    self.assertEqual(receipt['network_scope'], 'network')
                    self.assertEqual(receipt['network_issues'], 2 if fault else 0)

    def test_report_cannot_pass_without_identity_counts_and_live_positives(self):
        for fault in ('wrong-target', 'duplicate', 'zero-addresses', 'no-http-positive',
                      'no-dns-positive', 'wrong-count', 'no-path-fault'):
            with self.subTest(fault=fault):
                result = self.probe(fault)
                self.assertNotEqual(result.returncode, 0)

    def test_live_row_is_distinct_and_requires_network_scope(self):
        rows = (ROOT / 'tests/cli_behavior_inventory.tsv').read_text().splitlines()
        live = [row.split('\t') for row in rows if row.startswith('doctor-network-live\t')]
        self.assertEqual(len(live), 1, 'an executed network-tier row is missing')
        self.assertEqual(live[0][1:7], ['["doctor","--network"]', 'controlled-error', '1', 'pass', '-', 'network'])
        self.assertEqual(live[0][8], 'doctor-network-live-state')
        offline = [row.split('\t') for row in rows if row.startswith('doctor-network\t')]
        self.assertEqual(offline[0][6], 'container')

    def test_real_executor_requires_the_live_report_oracle(self):
        from scripts.test_qemu_output_contracts import OutputContracts
        row = ('doctor-network-live\t["doctor","--network"]\tcontrolled-error\t1\tpass\t-\t'
               'network\tarch:pass,debian:pass,ubuntu:pass,fedora:pass\tdoctor-network-live-state\ttempdir-drop')
        for count, accepted in ((1, True), (2, False)):
            with self.subTest(count=count):
                product = '''[[ "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 ]] || exit 70
printf '  Internet connectivity (github.com reachable)\\n'
printf '  PATH resolves a different omg executable first: "%s"\\n' "$(command -v omg)"
if [[ "$2" == --network ]]; then
  printf 'Network Diagnostics\\n  ✓ Kernel.org (10 ms)\\n  ✓ GitHub (15 ms)\\n\\n  DNS Resolution:\\n    ✓ kernel.org (2 addresses)\\n    ✓ github.com (2 addresses)\\n'
  printf 'Error: doctor found COUNT health issue(s)\\n' >&2
else
  printf 'Error: doctor found 1 health issue(s)\\n' >&2
fi
exit 1
'''.replace('COUNT', str(count))
                runner = OutputContracts(methodName='runTest')
                result, rows, logs = runner.run_inventory(product, [row], distro='debian', tiers='network')
                self.assertEqual(len(rows), 1, 'the real executor did not admit the reviewed live network row')
                self.assertEqual(rows[0]['result'], 'PASS' if accepted else 'FAIL', logs)
                self.assertEqual(result.returncode, 0 if accepted else 1, logs)

    def test_oracle_is_staged_for_the_real_controller(self):
        source = (ROOT / 'scripts/benchmark-qemu.sh').read_text()
        begin = source.index('  cp "$here/qemu-inventory.sh"')
        end = source.index('  if [[ "$source_kind" == staged ]]', begin)
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['bash', '-e', '-c', source[begin:end]],
                                    env=dict(os.environ, here=str(ROOT / 'scripts'), work=directory),
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            staged = Path(directory) / 'qemu-doctor-live-oracle.py'
            self.assertTrue(staged.is_file(), 'real controllers must receive the live report oracle')
            self.assertEqual(staged.read_bytes(), (ROOT / 'scripts/qemu-doctor-live-oracle.py').read_bytes())


if __name__ == '__main__':
    unittest.main()

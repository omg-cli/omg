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
        self.assertEqual(live[0][1:7], ['["doctor","--network"]', 'controlled-error', '1', 'pass', 'doctor', 'network'])
        self.assertEqual(live[0][8], 'doctor-network-live-state')
        self.assertEqual(live[0][5], 'doctor', 'live probes require the native Doctor baseline')
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

    def live_admission_fixture(self, *, count=1, altered_controller=False):
        from contextlib import contextmanager
        import hashlib
        import importlib.util
        import shutil
        from unittest.mock import patch
        from scripts import test_qemu_output_contracts as output_contracts

        @contextmanager
        def fixture():
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                controller = root / 'controller'
                (controller / 'scripts').mkdir(parents=True)
                (controller / 'tests').mkdir()
                for source in (ROOT / 'scripts').iterdir():
                    if source.is_file() and source.suffix in ('.py', '.sh'):
                        shutil.copyfile(source, controller / 'scripts' / source.name)
                shutil.copyfile(ROOT / 'tests/man_page_inventory.txt', controller / 'tests/man_page_inventory.txt')
                if altered_controller:
                    helper = controller / 'scripts/qemu-doctor-live-oracle.py'
                    text = helper.read_text(encoding='utf-8')
                    self.assertEqual(text.count('if count != baseline_count + failed:'), 1)
                    helper.write_text(text.replace('if count != baseline_count + failed:',
                                                   'if False and count != baseline_count + failed:'), encoding='utf-8')
                row = ('doctor-network-live\t["doctor","--network"]\tcontrolled-error\t1\tpass\t-\t'
                       'network\tarch:pass,debian:pass,ubuntu:pass,fedora:pass\tdoctor-network-live-state\ttempdir-drop')
                product = """[[ "$OMG_DISABLE_DAEMON" == 1 && "$OMG_TEST_MODE" == 0 ]] || exit 70
printf '  Internet connectivity (github.com reachable)\\n'
printf '  PATH resolves a different omg executable first: "%s"\\n' "$(command -v omg)"
if [[ "$2" == --network ]]; then
  printf 'Network Diagnostics\\n  ✓ Kernel.org (10 ms)\\n  ✓ GitHub (15 ms)\\n\\n  DNS Resolution:\\n    ✓ kernel.org (2 addresses)\\n    ✓ github.com (2 addresses)\\n'
  printf 'Error: doctor found COUNT health issue(s)\\n' >&2
else
  printf 'Error: doctor found 1 health issue(s)\\n' >&2
fi
exit 1
""".replace('COUNT', str(count))
                # Copy the actual controller manifest into returned fixture logs;
                # execute the unchanged receiver with its authenticated stdin.
                ssh = ('cp "$(dirname "$0")/../inventory/input-sha256.txt" '
                       '"$(dirname "$0")/../inventory/rows/input-owners.log"\n'
                       'exec bash -c "${@: -1}"\n')
                runner = output_contracts.OutputContracts(methodName='runTest')
                with patch.object(output_contracts, 'ROOT', controller):
                    result, rows, logs = runner.run_inventory(product, [row], distro='debian',
                                                           tiers='network', isolation_scope='network', ssh_body=ssh)
                inventory = root / 'cases.tsv'
                inventory.write_text('case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup\n' + row + '\n', encoding='utf-8')
                digest = hashlib.sha256(inventory.read_bytes()).hexdigest()
                policy = root / 'policy.json'
                policy_directory = root / 'policy.d'
                policy_directory.mkdir()
                registry = json.loads((ROOT / 'tests/qemu-inventory-policy.json').read_bytes())
                source_snapshot = json.loads((ROOT / 'tests/qemu-inventory-policy.d/a9496dee12123c063780710826a9d2e7dba0a93826e21ca07944e6cacbf7b917.json').read_bytes())
                case = next(case for case in source_snapshot['cases'] if case['id'] == 'doctor-network-live')
                snapshot = policy_directory / (digest + '.json')
                snapshot.write_text(json.dumps({'releases': [], 'cases': [case]}) + '\n', encoding='utf-8')
                registry['inventories'] = {digest: hashlib.sha256(snapshot.read_bytes()).hexdigest()}
                registry['profiles']['network'] = ['network']
                policy.write_text(json.dumps(registry) + '\n', encoding='utf-8')
                evidence = root / 'inventory'
                streams = evidence / 'rows'
                streams.mkdir(parents=True)
                for suffix in ('stdout', 'stderr'):
                    (streams / f'doctor-network-live.{suffix}.log').write_text(logs[f'doctor-network-live.{suffix}.log'], encoding='utf-8')
                (evidence / 'input-sha256.txt').write_text(logs['input-owners.log'], encoding='utf-8')
                results = evidence / 'results.json'
                results.write_text(json.dumps(rows) + '\n', encoding='utf-8')
                summary = evidence / 'summary.json'
                summary.write_text(json.dumps({'complete': True, 'pass': sum(row['result'] == 'PASS' for row in rows),
                                               'fail': sum(row['result'] != 'PASS' for row in rows), 'skipped': 0}) + '\n', encoding='utf-8')
                # The checker stays in the trusted host source tree while only
                # the staged controller copy can change its executed helper.
                spec = importlib.util.spec_from_file_location('live_host_checker', ROOT / 'scripts/check-qemu-inventory.py')
                checker = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(checker)
                yield result, lambda: checker.admit(policy, inventory, results, summary, 'debian', 'network'), evidence
        return fixture()

    def test_live_admission_binds_the_executed_controller_helper_to_trusted_source(self):
        with self.live_admission_fixture() as (result, admit, _):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(admit()['passed'])
        with self.live_admission_fixture(count=2, altered_controller=True) as (result, admit, _):
            self.assertEqual(result.returncode, 0, 'control must reproduce the altered helper false PASS')
            with self.assertRaises(ValueError):
                admit()

    def test_live_admission_keeps_a_genuine_product_failure(self):
        with self.live_admission_fixture(count=2) as (result, admit, _):
            self.assertEqual(result.returncode, 1, result.stderr)
            receipt = admit()
            self.assertFalse(receipt['passed'])
            self.assertEqual(receipt['counts']['failed'], 1)
            self.assertEqual(receipt['counts']['harness_error'], 0)

    def test_live_admission_rejects_missing_or_inconsistent_provenance(self):
        with self.live_admission_fixture() as (result, admit, evidence):
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(admit()['passed'])
            manifest = evidence / 'input-sha256.txt'
            stderr = evidence / 'rows/doctor-network-live.stderr.log'
            stdout = evidence / 'rows/doctor-network-live.stdout.log'
            original = {path: path.read_bytes() for path in (manifest, stderr, stdout)}
            proof_line = next(line for line in original[stderr].decode().splitlines() if line.startswith('{'))
            proof = json.loads(proof_line)
            for field, value in [('oracle_sha256', '0' * 64), ('report_sha256', '0' * 64),
                                 ('distro', 'fedora'), ('network_scope', 'offline'), ('exit_code', 0),
                                 ('baseline_issues', True), ('health_issues', 2), ('http_positive', 0),
                                 ('dns_positive', 0), ('mirror_targets', ['Wrong mirror']),
                                 ('dns_targets', ['wrong.example'])]:
                with self.subTest(field=field):
                    changed = dict(proof, **{field: value})
                    stderr.write_bytes(original[stderr].replace(proof_line.encode(), json.dumps(changed).encode()))
                    with self.assertRaises(ValueError):
                        admit()
                    stderr.write_bytes(original[stderr])
            for fault in ('missing-manifest', 'missing-owner', 'duplicate-owner', 'wrong-owner',
                          'missing-proof', 'duplicate-proof', 'duplicate-key', 'coherent-wrong-counts', 'wrong-stream', 'wrong-trailer'):
                with self.subTest(fault=fault):
                    if fault == 'missing-manifest': manifest.unlink()
                    elif fault == 'missing-owner': manifest.write_bytes(b''.join(line for line in original[manifest].splitlines(keepends=True) if b'qemu-doctor-live-oracle.py' not in line))
                    elif fault == 'duplicate-owner': manifest.write_bytes(original[manifest] + next((line for line in original[manifest].splitlines(keepends=True) if b'qemu-doctor-live-oracle.py' in line), b'0' * 64 + b'  qemu-doctor-live-oracle.py\n'))
                    elif fault == 'wrong-owner': manifest.write_bytes(original[manifest].replace(b'qemu-doctor-live-oracle.py', b'other-doctor-oracle.py'))
                    elif fault == 'missing-proof': stderr.write_bytes(original[stderr].replace(proof_line.encode(), b''))
                    elif fault == 'duplicate-proof': stderr.write_bytes(original[stderr] + proof_line.encode() + b'\n')
                    elif fault == 'duplicate-key': stderr.write_bytes(original[stderr].replace(proof_line.encode(), proof_line[:-1].encode() + b', "complete": true}'))
                    elif fault == 'coherent-wrong-counts': stderr.write_bytes(original[stderr].replace(proof_line.encode(), json.dumps(dict(proof, baseline_issues=2, health_issues=2)).encode()))
                    elif fault == 'wrong-stream': stdout.write_bytes(b'changed\n' + original[stdout])
                    elif fault == 'wrong-trailer': stdout.write_bytes(original[stdout].replace(b'OMG_QEMU_RECEIPT:product:1:0', b'OMG_QEMU_RECEIPT:product:0:0'))
                    with self.assertRaises((ValueError, OSError)):
                        admit()
                    for path, content in original.items(): path.write_bytes(content)



if __name__ == '__main__':
    unittest.main()

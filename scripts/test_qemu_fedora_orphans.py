"""Require native RPM and DNF state for the Fedora orphan cleanup receipt."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FedoraOrphanOracleTests(unittest.TestCase):
    def test_fedora_orphan_receipt_rejects_unchanged_or_collateral_state(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        source = source[source.index('# BEGIN PRODUCT OUTPUT ORACLE'):
                        source.index('# END PRODUCT OUTPUT ORACLE')]
        # Confine the payload reference, just as the full runner's tree fixture does.
        source = source.replace('/usr/bin/tree', '$PWD/tree')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / 'commands'
            commands.mkdir()
            tools = {
                'rpm': '''case "$1" in
  -q) [[ "$TREE_PRESENT" == 1 ]] ;;
  -qa)
    printf 'base\\t0\\t%s\\t1\\tx86_64\\n' "$BASE_VERSION"
    [[ "$TREE_PRESENT" != 1 ]] || printf 'tree\\t0\\t2.0\\t1\\tx86_64\\n' ;;
  *) exit 70 ;;
esac
''',
                'dnf': '''printf 'base x86_64 %s\\n' "$BASE_REASON"
[[ "$TREE_PRESENT" != 1 ]] || printf 'tree x86_64 dependency\\n'
''',
                'dpkg-query': 'exit 70\n',
            }
            for name, contents in tools.items():
                path = commands / name
                path.write_text('#!/bin/bash\n' + contents, encoding='utf-8', newline='\n')
                path.chmod(0o755)
            (root / 'orphan-before.state').write_text(
                'installed packages\nbase\t0\t1.0\t1\tx86_64\n'
                'tree\t0\t2.0\t1\tx86_64\ninstall reasons\n'
                'base x86_64 user\ntree x86_64 dependency\n')
            (root / 'stdout').write_text('Complete!\n')
            (root / 'stderr').write_text('')
            (root / 'orphan-target.arch').write_text('x86_64')
            for present, version, reason, accepted in (
                ('0', '1.0', 'user', True),
                ('1', '1.0', 'user', False),
                ('0', '9.0', 'user', False),
                ('0', '1.0', 'dependency', False),
            ):
                with self.subTest(present=present, version=version, reason=reason):
                    environment = dict(os.environ, TREE_PRESENT=present,
                                       BASE_VERSION=version, BASE_REASON=reason,
                                       PATH=str(commands) + os.pathsep + os.environ['PATH'])
                    result = subprocess.run(
                        [shutil.which('bash'), '-c', source +
                         '\ncheck_product_output package-mutation native-apt-orphan-removed '
                         '0 stdout stderr fedora'],
                        cwd=root, env=environment, capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)


    def test_declined_cleanup_requires_unchanged_inventory_and_both_histories(self):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        start = source.index('check_fedora_orphan_decline() {')
        end = source.index('\ncheck_native_orphan_removed()', start)
        function = source[start:end].replace('/var/lib/omg/history.json', './history.json')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / 'commands'
            commands.mkdir()
            tools = {
                'sudo': '[[ $1 == -n ]] || exit 70\nshift\nexec "$@"\n',
                'dnf': '[[ $* == "--cacheonly history list --json" ]] || exit 70\ncat native-history.json\n',
                'omg': '''[[ $* == "clean --orphans" ]] || exit 70
read -r answer
[[ $answer == n ]] || exit 70
case "$FAULT" in
  inventory) printf 'changed' > inventory ;;
  native) printf '[{}]' > native-history.json ;;
  history) printf '[{}]' > history.json ;;
  no-prompt) echo 'Repository unavailable' >&2; exit 1 ;;
  fake-success) echo 'Operation aborted by the user' >&2; exit 0 ;;
esac
echo 'Operation aborted by the user.' >&2
exit 1
''',
            }
            for name, contents in tools.items():
                path = commands / name
                path.write_text('#!/bin/bash\n' + contents, encoding='utf-8', newline='\n')
                path.chmod(0o755)
            for fault in ('none', 'inventory', 'native', 'history', 'no-prompt', 'fake-success'):
                with self.subTest(fault=fault):
                    (root / 'inventory').write_text('tree present')
                    (root / 'native-history.json').write_text('[]')
                    (root / 'history.json').write_text('[]')
                    result = subprocess.run(
                        [shutil.which('bash'), '-euo', 'pipefail', '-c', function +
                         '\nnative_package_snapshot() { cat inventory; }\n'
                         'check_fedora_orphan_decline omg'],
                        cwd=root, env=dict(os.environ, FAULT=fault,
                                           PATH=str(commands) + os.pathsep + os.environ['PATH']),
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, fault == 'none', result.stderr)


if __name__ == '__main__':
    unittest.main()

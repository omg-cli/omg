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


if __name__ == '__main__':
    unittest.main()

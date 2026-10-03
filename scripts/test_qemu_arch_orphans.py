"""Require native Arch orphan selection and whole package/reason state."""
import csv
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ArchOrphanOracleTests(unittest.TestCase):
    def probe(self, operation, *, present=False, version='1.0-1', reason='explicit',
              baseline='empty', query_exit='1', query_error='', collateral='', mark_exit='0'):
        source = (ROOT / 'scripts/qemu-inventory.sh').read_text(encoding='utf-8')
        source = source[source.index('# BEGIN PRODUCT OUTPUT ORACLE'):
                        source.index('# END PRODUCT OUTPUT ORACLE')]
        source = source.replace('/usr/bin/tree', '$PWD/tree')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / 'commands'
            commands.mkdir()
            tools = {
                'pacman': '''case "$1" in
  -Qq) printf 'base\\n'; [[ "$TREE_PRESENT" != 1 ]] || printf 'tree\\n' ;;
  -Q) printf 'base %s\\n' "$BASE_VERSION"; [[ "$TREE_PRESENT" != 1 ]] || printf 'tree 2.0-1\\n' ;;
  -Qqe)
    if [[ "$BASE_REASON" == explicit && ( ! -f "$MARK_STATE" || "$COLLATERAL" != reason ) ]]; then printf 'base\\n'; fi
    if [[ "$TREE_PRESENT" == 1 && ! -f "$MARK_STATE" ]]; then printf 'tree\\n'; fi ;;
  -Qdtq)
    if [[ -f "$MARK_STATE" ]]; then printf 'tree\\n'; exit 0; fi
    [[ "$BASELINE" == empty ]] || printf '%s\\n' "$BASELINE"
    [[ -z "$QUERY_ERROR" ]] || printf '%s\\n' "$QUERY_ERROR" >&2
    exit "$QUERY_EXIT" ;;
  -D)
    [[ "$*" == '-D --asdeps tree' ]] || exit 70
    [[ "$MARK_EXIT" == 0 ]] || exit "$MARK_EXIT"
    printf marked > "$MARK_STATE" ;;
  *) exit 70 ;;
esac
exit 0
''',
                'sudo': '[[ "$1" == -n ]] || exit 70\nshift\nexec "$@"\n',
                'dpkg-query': 'exit 70\n',
                'apt-mark': 'exit 70\n',
                'apt-get': 'exit 70\n',
            }
            for name, contents in tools.items():
                path = commands / name
                path.write_text('#!/bin/bash\n' + contents, encoding='utf-8', newline='\n')
                path.chmod(0o755)
            if present:
                tree = root / 'tree'
                tree.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
                tree.chmod(0o755)
            (root / 'orphan-before.state').write_text(
                'installed packages\nbase 1.0-1\ntree 2.0-1\ninstall reasons\nbase\ntree\n')
            (root / 'stdout').write_text('Completed native orphan transaction\n')
            environment = dict(os.environ, TREE_PRESENT='1' if present else '0',
                               BASE_VERSION=version, BASE_REASON=reason, BASELINE=baseline,
                               QUERY_EXIT=query_exit, QUERY_ERROR=query_error, MARK_EXIT=mark_exit,
                               COLLATERAL=collateral, MARK_STATE=str(root / 'marked'),
                               PATH=str(commands) + os.pathsep + os.environ['PATH'])
            invocation = ('prepare_native_orphan arch' if operation == 'prepare'
                          else 'check_native_orphan_removed arch stdout')
            result = subprocess.run([shutil.which('bash'), '-c', source + '\n' + invocation],
                                    cwd=root, env=environment, capture_output=True, text=True, timeout=10)
            return result.returncode, result.stderr, (root / 'marked').exists()

    def test_native_preparation_accepts_empty_query_then_exact_tree_only(self):
        code, error, marked = self.probe('prepare', present=True)
        self.assertEqual(code, 0, error)
        self.assertTrue(marked)

    def test_preparation_refuses_unrelated_orphans_query_errors_and_mark_failure(self):
        for options in ({'baseline': 'unrelated', 'query_exit': '0'},
                        {'query_exit': '2'}, {'query_error': 'native query failed'},
                        {'mark_exit': '70'}, {'collateral': 'reason'}):
            with self.subTest(options=options):
                code, error, marked = self.probe('prepare', present=True, **options)
                self.assertNotEqual(code, 0, error)
                if 'mark_exit' not in options and 'collateral' not in options:
                    self.assertFalse(marked)

    def test_postcheck_accepts_exact_native_removal(self):
        code, error, _ = self.probe('check')
        self.assertEqual(code, 0, error)

    def test_postcheck_rejects_unchanged_or_collateral_native_state(self):
        for options in ({'present': True}, {'version': '9.0-1'}, {'reason': 'dependency'},
                        {'baseline': 'unrelated', 'query_exit': '0'}, {'query_exit': '2'},
                        {'query_error': 'native query failed'}):
            with self.subTest(options=options):
                code, error, _ = self.probe('check', **options)
                self.assertNotEqual(code, 0, error)

    def test_reviewed_current_row_executes_on_arch(self):
        with (ROOT / 'tests/cli_behavior_inventory.tsv').open(newline='') as stream:
            rows = {row['case']: row for row in csv.DictReader(stream, delimiter='\t')}
        row = rows['clean-orphans-native']
        self.assertIn('arch:pass', row['targets'].split(','))
        self.assertEqual(row['assertions'], 'native-orphan-removed')


if __name__ == '__main__':
    unittest.main()
"""Rollback must not advertise a release missing a required native ABI."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_release_workflow_boundaries import BASH

ROOT = Path(__file__).resolve().parents[1]


class RollbackArtifacts(unittest.TestCase):
    def test_apt7_required_and_legacy_exception_is_explicit(self):
        for case, extra, missing, expected in (
            ('complete', [], '', 0),
            ('missing-apt7', [], 'trixie.tar.gz', 66),
            ('missing-sidecar', [], 'trixie.tar.gz.sha256', 66),
            ('explicit-legacy', ['--allow-legacy-apt6'], 'trixie', 0),
            ('legacy-still-requires-apt6', ['--allow-legacy-apt6'], 'debian.tar.gz', 66),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                executable = root / '.github/deps/release-tools/node_modules/.bin/wrangler'
                executable.parent.mkdir(parents=True)
                executable.write_text(
                    '#!/usr/bin/env bash\nset -eu\n'
                    'printf "%s\\n" "$*" >> "$CALLS"\n'
                    '[[ "$1 $2 $3" == "r2 object get" ]] || exit 99\n'
                    'if [[ -n "$MISSING" && "$4" == *"$MISSING" ]]; then exit 1; fi\n')
                executable.chmod(0o755)
                calls = root / 'calls'
                # Refusal cases use the real mutation mode: the fake rejects
                # any attempted write, so a dry-run shortcut cannot hide one.
                mode = ['--dry-run'] if expected == 0 else []
                result = subprocess.run(
                    [BASH, str(ROOT / 'scripts/r2-rollback.sh'), '1.2.3', *mode, *extra],
                    cwd=root, env=dict(os.environ, CLOUDFLARE_API_TOKEN='fixture',
                                      CLOUDFLARE_ACCOUNT_ID='fixture', CALLS=str(calls),
                                      MISSING=missing),
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, expected, result.stderr)
                requests = calls.read_text() if calls.exists() else ''
                self.assertNotIn('object put', requests)
                if expected == 66:
                    self.assertIn('missing R2 object', result.stderr)
                    self.assertNotIn('would set latest-version', result.stdout)
                elif not extra:
                    self.assertEqual(len(requests.splitlines()), 12)
                    self.assertIn('trixie.tar.gz.sha256', requests)
                else:
                    self.assertEqual(len(requests.splitlines()), 10)
                    self.assertIn('APT7', result.stderr)


if __name__ == '__main__':
    unittest.main()

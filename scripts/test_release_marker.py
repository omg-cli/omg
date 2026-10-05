"""Exercise the production marker step offline; never contact R2."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_ci_gates import job_block
from test_release_workflow_boundaries import BASH, step_script

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/release.yml').read_text(encoding='utf-8')
MARKER = 'omg-releases/latest-version'
MOCK = r'''#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> calls
[[ "$1 $2" == 'r2 object' ]] || exit 99
operation=$3
object=$4
shift 4
file=''
pipe=false
for arg in "$@"; do
  case "$arg" in
    --file=*) file=${arg#--file=} ;;
    --pipe) pipe=true ;;
  esac
done
[[ " $* " == *' --remote '* ]] || exit 98
if [[ "$operation" == get ]]; then
  [[ "$object" != "$FAIL_GET" ]] || exit 1
  [[ -f "objects/$object" ]] || exit 1
  if [[ "$pipe" == true ]]; then cat "objects/$object";
  else cp "objects/$object" "$file"; fi
elif [[ "$operation" == put ]]; then
  mkdir -p "objects/$(dirname "$object")"
  cp "$file" "objects/$object"
else
  exit 99
fi
'''


class ReleaseMarkerTests(unittest.TestCase):
    def run_marker(self, current, candidate='1.2.0', sync='v1.2.0', fail_get=''):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / '.github/deps/release-tools/node_modules/.bin/wrangler'
            executable.parent.mkdir(parents=True)
            executable.write_text(MOCK, encoding='utf-8')
            executable.chmod(0o755)
            (root / 'release').mkdir()
            (root / 'objects/omg-releases').mkdir(parents=True)
            (root / 'install.sh').write_text('fixture installer\n')
            marker = root / 'objects' / MARKER
            if current is not None:
                marker.write_text(current)
            result = subprocess.run(
                [BASH, '-euo', 'pipefail', '-c', step_script(WORKFLOW, 'Upload latest-version marker')],
                cwd=root, env=dict(os.environ, VERSION=candidate, SYNC_EXISTING_TAG=sync,
                                   FAIL_GET=fail_get), capture_output=True, text=True,
                encoding='utf-8', timeout=15)
            calls = (root / 'calls').read_text() if (root / 'calls').exists() else ''
            return result, marker.read_text() if marker.exists() else None, calls

    def test_historical_resync_keeps_newer_marker(self):
        result, marker, calls = self.run_marker('1.3.0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(marker, '1.3.0')
        self.assertNotIn('object put ' + MARKER, calls)
        self.assertIn('object get ' + MARKER, calls)
        # Historical syncing still round-trip verifies the installer mirror.
        self.assertIn('object put omg-releases/install.sh --remote', calls)
        self.assertIn('object get omg-releases/install.sh.sha256 --remote', calls)

    def test_equal_resync_does_not_rewrite_marker(self):
        for current in ('1.2.0', '1.2.0+build.9'):
            with self.subTest(current=current):
                result, marker, calls = self.run_marker(current)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(marker, current)
                self.assertNotIn('object put ' + MARKER, calls)

    def test_newer_resync_promotes_using_numeric_precedence(self):
        for current, candidate in (('1.1.9', '1.2.0'), ('1.9.0', '1.10.0'),
                                   ('1.2.0-rc.1', '1.2.0'), ('0.99.99', '1.0.0')):
            with self.subTest(current=current, candidate=candidate):
                result, marker, calls = self.run_marker(current, candidate, 'v' + candidate)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(marker, candidate)
                self.assertIn('object put ' + MARKER, calls)

    def test_resync_refuses_unreadable_or_invalid_marker(self):
        for current, fail_get in ((None, ''), ('garbage', ''), ('01.2.0', ''),
                                  ('1.2.0-01', ''), ('', ''), ('1.3.0', MARKER)):
            with self.subTest(current=current, fail_get=fail_get):
                result, marker, calls = self.run_marker(current, fail_get=fail_get)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(marker, current)
                self.assertNotIn('object put ' + MARKER, calls)

    def test_installer_verification_failure_prevents_promotion(self):
        result, marker, calls = self.run_marker('1.1.0', fail_get='omg-releases/install.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker, '1.1.0')
        self.assertNotIn('object put ' + MARKER, calls)

    def test_fresh_release_keeps_existing_bootstrap_path(self):
        result, marker, calls = self.run_marker(None, sync='')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(marker, '1.2.0')
        self.assertIn('object put ' + MARKER, calls)

    def test_dry_run_dispatch_cannot_enter_publication_job(self):
        gate = job_block(WORKFLOW, 'sync-r2').split('steps:', 1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.dry_run == 'false'", gate)
        self.assertIn("inputs.sync_existing_tag != '' || needs.release.result == 'success'", gate)

    def test_explicit_rollback_can_regress_marker_and_dry_run_cannot(self):
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                executable = root / '.github/deps/release-tools/node_modules/.bin/wrangler'
                executable.parent.mkdir(parents=True)
                executable.write_text(MOCK, encoding='utf-8')
                executable.chmod(0o755)
                objects = root / 'objects/omg-releases'
                objects.mkdir(parents=True)
                (objects / 'latest-version').write_text('1.3.0')
                for platform in ('x86_64-linux-arch', 'x86_64-linux-debian',
                                 'x86_64-linux-debian-trixie', 'x86_64-linux-ubuntu',
                                 'x86_64-linux-fedora', 'aarch64-darwin'):
                    for suffix in ('tar.gz', 'tar.gz.sha256'):
                        (objects / f'omg-v1.2.0-{platform}.{suffix}').write_text('fixture')
                result = subprocess.run(
                    [BASH, str(ROOT / 'scripts/r2-rollback.sh'), '1.2.0',
                     *(['--dry-run'] if dry_run else [])], cwd=root,
                    env=dict(os.environ, CLOUDFLARE_API_TOKEN='fixture',
                             CLOUDFLARE_ACCOUNT_ID='fixture', FAIL_GET=''),
                    capture_output=True, text=True, encoding='utf-8', timeout=15)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((objects / 'latest-version').read_text(), '1.3.0' if dry_run else '1.2.0')
                calls = (root / 'calls').read_text()
                self.assertEqual('object put ' + MARKER in calls, not dry_run)


if __name__ == '__main__':
    unittest.main()

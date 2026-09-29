"""Dated .audit/run-* export directories are ignored; the audit record is not.

The QEMU lanes export allowlisted guest and controller diagnostics into
.audit/run-<id>/. Those directories carry runner host paths and guest serial
logs, so they must never become committable. .audit/deep-audit.tsv is the
first-class audit record referenced by tests/README.md and must stay
committable.
"""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]

RUN_ARTIFACT = '.audit/run-36304589368-ubuntu/export-report.json'
AUDIT_RECORD = '.audit/deep-audit.tsv'


def git(*args):
    return subprocess.run(
        ['git', '-C', str(ROOT), *args],
        capture_output=True, text=True, timeout=30)


class GitignoreAuditArtifacts(unittest.TestCase):
    def test_run_artifact_directory_is_ignored(self):
        result = git('check-ignore', '-v', RUN_ARTIFACT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Assert the behaviour, not which file declared the rule: a developer's
        # own .git/info/exclude can legitimately cover the same path, and this
        # test failed spuriously when one did.
        self.assertTrue(
            result.stdout.strip().endswith(RUN_ARTIFACT),
            f"check-ignore should name the ignored path, got {result.stdout!r}",
        )

    def test_audit_record_is_not_ignored(self):
        result = git('check-ignore', AUDIT_RECORD)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_audit_record_is_tracked(self):
        tracked = git('ls-files', '--', AUDIT_RECORD)
        self.assertEqual(tracked.stdout.strip(), AUDIT_RECORD)

    def test_run_directory_is_absent_from_status(self):
        # An untracked-but-unignored run directory would surface here.
        result = git('status', '--porcelain', '--untracked-files=all', '--', '.audit')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('run-', result.stdout, result.stdout)
        self.assertNotIn('.audit/', result.stdout, result.stdout)


if __name__ == '__main__':
    unittest.main()

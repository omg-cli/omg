from datetime import date
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qemu_review", ROOT / "scripts/check-qemu-review.py")
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "manifest.json"
        self.data = dict(schema_version=1, reviewed_on="2026-09-15", review_expires="2026-10-15")

    def check(self, today):
        self.path.write_text(json.dumps(self.data))
        return REVIEW.review(self.path, today)

    def test_alerts_a_week_before_expiry_and_remains_due_after_expiry(self):
        self.assertFalse(self.check(date(2026, 10, 7))["review_required"])
        self.assertTrue(self.check(date(2026, 10, 8))["review_required"])
        self.assertTrue(self.check(date(2026, 10, 15))["expired"])
        self.assertTrue(self.check(date(2026, 11, 1))["review_required"])

    def test_future_or_extended_review_is_rejected(self):
        with self.assertRaises(ValueError):
            self.check(date(2026, 9, 14))
        self.data["review_expires"] = "2027-10-15"
        with self.assertRaises(ValueError):
            self.check(date(2026, 9, 15))

    def test_workflow_has_no_pr_trigger_or_automatic_renewal(self):
        workflow = (ROOT / ".github/workflows/qemu-maintenance.yml").read_text()
        self.assertNotIn("pull_request", workflow)
        self.assertIn("issues: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)

    def maintenance_request(self, scenario):
        workflow = (ROOT / ".github/workflows/qemu-maintenance.yml").read_text()
        script = textwrap.dedent(workflow.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            calls = folder / "calls.jsonl"
            gh = folder / "gh"
            gh.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
if args[:2] == ['issue', 'list']:
    scenario = os.environ['SCENARIO']
    if scenario == 'query-failure':
        sys.exit(73)
    search = args[args.index('--search') + 1]
    title = 'chore(security): renew reviewed QEMU image provenance'
    # Model the independently verified GitHub phrase-search behavior, then
    # the exact-title --jq filter. Similar titles must not supply an issue.
    if scenario == 'exact' and ('"' + title + '" in:title') == search:
        print('889')
elif args[:2] == ['issue', 'create']:
    body = Path(args[args.index('--body-file') + 1]).read_text()
    if 'Do not extend the date without completing the review' not in body:
        sys.exit(74)
    print('https://github.com/example/omg/issues/900')
else:
    sys.exit(75)
''')
            gh.chmod(0o755)
            result = subprocess.run(
                ['bash', '-c', script], capture_output=True, text=True, timeout=15,
                env=dict(os.environ, PATH=str(folder) + os.pathsep + os.environ['PATH'],
                         CALLS=str(calls), SCENARIO=scenario, RUNNER_TEMP=str(folder)),
            )
            return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_due_review_reuses_exact_open_issue(self):
        result, calls = self.maintenance_request('exact')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[:2] for call in calls], [['issue', 'list']])

    def test_due_review_creates_once_when_no_exact_issue_exists(self):
        for scenario in ('empty', 'similar'):
            with self.subTest(scenario=scenario):
                result, calls = self.maintenance_request(scenario)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call[:2] for call in calls],
                                 [['issue', 'list'], ['issue', 'create']])

    def test_failed_issue_query_does_not_create_request(self):
        result, calls = self.maintenance_request('query-failure')
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual([call[:2] for call in calls], [['issue', 'list']])


if __name__ == "__main__":
    unittest.main()

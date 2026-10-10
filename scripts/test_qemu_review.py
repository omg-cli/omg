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
        triggers = workflow.split("permissions:", 1)[0]
        self.assertNotIn("pull_request", triggers)
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
import json, os, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
if args[:2] == ['issue', 'list'] or args[0] == 'api':
    scenario = os.environ['SCENARIO']
    if scenario == 'query-failure':
        sys.exit(73)
    title = 'chore(security): renew reviewed QEMU image provenance'
    issue = dict(title=title, number=889)
    pages = [[issue]] if scenario in ('exact', 'partial-failure') else [[]]
    if scenario == 'similar':
        pages = [[dict(title=title + ' (duplicate)', number=890)]]
    elif scenario == 'pull-request':
        pages = [[dict(title=title, number=893, pull_request={'url': 'fixture'})]]
    elif scenario == 'paginated':
        pages = [[dict(title=title + ' (copy ' + str(i) + ')', number=1000+i)
                  for i in range(100)], [issue]]
    if args[:2] == ['issue', 'list']:
        # gh issue list excludes PRs and returns at most 30 search matches by
        # default. Similar phrase titles can precede an older canonical issue.
        search = args[args.index('--search') + 1]
        matches = [row for page in pages for row in page
                   if 'pull_request' not in row and title in row['title']]
        if search != ('"' + title + '" in:title'):
            matches = []
        raw = json.dumps(matches[:30])
    else:
        if 'repos/omg-cli/omg/issues?state=open&per_page=100' not in args:
            sys.exit(76)
        selected = pages if '--paginate' in args else pages[:1]
        raw = '\\n'.join(json.dumps(page) for page in selected)
    # Execute the workflow's actual filter over raw JSON, including each API
    # page. Do not stub post-filtered IDs or reimplement jq's selection logic.
    filtered = subprocess.run(['jq', '-r', args[args.index('--jq') + 1]],
                              input=raw, text=True, capture_output=True, timeout=5)
    sys.stdout.write(filtered.stdout)
    sys.stderr.write(filtered.stderr)
    if filtered.returncode:
        sys.exit(filtered.returncode)
    if scenario == 'partial-failure':
        # An earlier page may already have printed the canonical ID before a
        # later HTTP/page failure. Bash must still honor the failing status.
        sys.exit(73)
elif args[:2] == ['issue', 'create']:
    body = Path(args[args.index('--body-file') + 1]).read_text()
    if 'Do not extend the date without completing the review' not in body:
        sys.exit(74)
    print('https://github.com/example/omg/issues/900')
else:
    sys.exit(75)
''')
            gh.chmod(0o755)
            environment = dict(os.environ, PATH=str(folder) + os.pathsep + os.environ['PATH'],
                               GH_REPO='omg-cli/omg', CALLS=str(calls),
                               SCENARIO=scenario, RUNNER_TEMP=str(folder))
            for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
                environment.pop(key, None)
            result = subprocess.run(
                ['bash', '-c', script], capture_output=True, text=True, timeout=15,
                env=environment,
            )
            return result, [json.loads(line) for line in calls.read_text().splitlines()]

    def test_due_review_reuses_exact_open_issue(self):
        result, calls = self.maintenance_request('exact')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([call[:2] for call in calls], [['api', '--paginate']])

    def test_due_review_creates_once_when_no_exact_issue_exists(self):
        for scenario in ('empty', 'similar'):
            with self.subTest(scenario=scenario):
                result, calls = self.maintenance_request(scenario)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([call[:2] for call in calls],
                                 [['api', '--paginate'], ['issue', 'create']])

    def test_failed_issue_query_does_not_create_request(self):
        result, calls = self.maintenance_request('query-failure')
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual([call[:2] for call in calls], [['api', '--paginate']])


if __name__ == "__main__":
    unittest.main()

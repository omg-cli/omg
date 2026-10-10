from datetime import date
import importlib.util
import json
from pathlib import Path
import tempfile
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


if __name__ == "__main__":
    unittest.main()

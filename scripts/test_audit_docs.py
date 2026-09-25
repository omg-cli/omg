"""Contract tests for scripts/audit_docs.py, which is wired as a CI gate.

The gate has to fail on real drift and stay green on the current tree; these
tests keep it from silently degrading into a no-op that always exits 0.
"""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_docs.py"
FIXTURE = ROOT / "docs" / "zz-audit-docs-gate-fixture.md"


def run_audit():
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )


class AuditDocsGateTests(unittest.TestCase):
    def tearDown(self):
        FIXTURE.unlink(missing_ok=True)

    def test_current_tree_passes_every_audit(self):
        result = run_audit()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("All doc audits passed successfully!", result.stdout)

    def test_broken_link_fails_the_gate(self):
        FIXTURE.write_text(
            "[missing](../docs/zz-does-not-exist.md)\n", encoding="utf-8"
        )
        result = run_audit()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Broken links: 1", result.stdout)

    def test_inline_phantom_option_fails_the_gate(self):
        FIXTURE.write_text(
            "Run `omg install --definitely-not-a-real-flag` now.\n",
            encoding="utf-8",
        )
        result = run_audit()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Command reference issues: 1", result.stdout)

    def test_code_block_phantom_option_fails_the_gate(self):
        FIXTURE.write_text(
            "```bash\nomg install --definitely-not-a-real-flag\n```\n",
            encoding="utf-8",
        )
        result = run_audit()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Command reference issues: 1", result.stdout)
        self.assertIn("code block option --definitely-not-a-real-flag", result.stdout)


if __name__ == "__main__":
    unittest.main()

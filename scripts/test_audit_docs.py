"""Contract tests for scripts/audit_docs.py, which is wired as a CI gate.

The gate has to fail on real drift and stay green on the current tree; these
tests keep it from silently degrading into a no-op that always exits 0.
"""

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "audit_docs.py"
FIXTURE = ROOT / "docs" / "zz-audit-docs-gate-fixture.md"
SPEC = importlib.util.spec_from_file_location("audit_docs", SCRIPT)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class AuditDocumentReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo / "docs").mkdir()
        (self.repo / "examples").mkdir()
        (self.repo / "examples" / "config.toml").write_text("", encoding="utf-8")
        (self.repo / "src" / "cli").mkdir(parents=True)
        (self.repo / "src" / "cli" / "args.rs").write_bytes(
            (ROOT / "src" / "cli" / "args.rs").read_bytes()
        )
        self.checks = (
            AUDIT.check_broken_links, AUDIT.check_forbidden_patterns,
            AUDIT.check_config_keys, AUDIT.check_all_command_references,
        )

    def assert_read_failure(self, path, cause):
        for check in self.checks:
            with self.subTest(check=check.__name__):
                findings = check(self.repo)
                self.assertEqual(len(findings), 1, findings)
                self.assertIn(path, findings[0])
                self.assertIn(cause, findings[0])

    def test_invalid_utf8_fails_every_pass(self):
        (self.repo / "docs" / "bad.md").write_bytes(b"\xff[hidden](missing.md)\n")
        self.assert_read_failure("docs/bad.md", "UnicodeDecodeError")

    def test_filesystem_read_failure_fails_every_pass(self):
        # A selected directory produces a real OS read error on Windows and Linux.
        (self.repo / "docs" / "unreadable.md").mkdir()
        self.assert_read_failure("docs/unreadable.md", "Error")

    def test_exempt_prose_still_requires_readable_document(self):
        (self.repo / "docs" / "mise-compatibility.md").write_bytes(b"\xff")
        findings = AUDIT.check_forbidden_patterns(self.repo)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("docs/mise-compatibility.md", findings[0])
        self.assertIn("UnicodeDecodeError", findings[0])

    def test_invalid_example_config_fails_config_pass(self):
        (self.repo / "examples" / "config.toml").write_bytes(b"\xff")
        findings = AUDIT.check_config_keys(self.repo)
        self.assertEqual(len(findings), 1, findings)
        self.assertIn("examples/config.toml", findings[0])
        self.assertIn("UnicodeDecodeError", findings[0])

    def test_valid_utf8_documents_pass_every_pass(self):
        (self.repo / "docs" / "valid.md").write_text(
            "# Café\n[local](#café)\nRun `omg install ripgrep`.\n", encoding="utf-8"
        )
        for check in self.checks:
            with self.subTest(check=check.__name__):
                self.assertEqual(check(self.repo), [])


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
        if FIXTURE.is_dir():
            FIXTURE.rmdir()
        else:
            FIXTURE.unlink(missing_ok=True)

    def test_invalid_utf8_fails_the_gate_with_path_and_cause(self):
        FIXTURE.write_bytes(b"\xff[hidden](missing.md)\n")
        result = run_audit()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("docs/zz-audit-docs-gate-fixture.md", result.stdout)
        self.assertIn("UnicodeDecodeError", result.stdout)
        self.assertNotIn("All doc audits passed successfully!", result.stdout)

    def test_filesystem_read_failure_fails_the_gate_with_path_and_cause(self):
        FIXTURE.mkdir()
        result = run_audit()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("docs/zz-audit-docs-gate-fixture.md", result.stdout)
        self.assertIn("cannot read", result.stdout)
        self.assertNotIn("All doc audits passed successfully!", result.stdout)

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

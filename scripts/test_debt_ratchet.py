"""Tests for the shrink-only debt ratchet (scripts/debt-ratchet.py).

Marker words are assembled at runtime so this test file does not itself trip
the ratchet it exercises.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "debt-ratchet.py"

MARKER = "TO" + "DO"
ALLOW = "allow(" + "dead_code)"


def run(root, baseline_dir, *flags):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root),
         "--baseline-dir", str(baseline_dir), *flags],
        capture_output=True, text=True, timeout=60,
    )


class DebtRatchetTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.baselines = self.root / "baselines"
        (self.root / "src").mkdir()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def seed(self):
        result = run(self.root, self.baselines, "--refresh")
        self.assertEqual(result.returncode, 0, result.stderr)

    def baseline_text(self, name):
        return (self.baselines / f"{name}.baseline").read_text(encoding="utf-8")

    def test_seeding_records_current_counts_and_gate_passes(self):
        self.write("src/a.py", f"# {MARKER} one\n# {MARKER} two\n")
        self.seed()
        self.assertIn("2 = src/a.py", self.baseline_text("todo-markers"))
        self.assertEqual(run(self.root, self.baselines).returncode, 0)

    def test_new_finding_in_unlisted_file_fails_and_names_the_file(self):
        self.write("src/a.py", "# clean\n")
        self.seed()
        self.write("src/b.py", f"# {MARKER} introduced\n")
        result = run(self.root, self.baselines)
        self.assertEqual(result.returncode, 1)
        self.assertIn("new_files: src/b.py", result.stderr)

    def test_increase_in_listed_file_fails_and_refresh_refuses_to_raise(self):
        self.write("src/a.py", f"# {MARKER}\n")
        self.seed()
        self.write("src/a.py", f"# {MARKER}\n# {MARKER}\n")
        gate = run(self.root, self.baselines)
        self.assertEqual(gate.returncode, 1)
        self.assertIn("increased: src/a.py", gate.stderr)
        refused = run(self.root, self.baselines, "--refresh")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("1 = src/a.py", self.baseline_text("todo-markers"))

    def test_decrease_refresh_lowers_the_floor(self):
        self.write("src/a.py", f"# {MARKER}\n# {MARKER}\n# {MARKER}\n")
        self.seed()
        self.write("src/a.py", f"# {MARKER}\n")
        refreshed = run(self.root, self.baselines, "--refresh")
        self.assertEqual(refreshed.returncode, 0, refreshed.stderr)
        self.assertIn("1 = src/a.py", self.baseline_text("todo-markers"))
        self.write("src/a.py", f"# {MARKER}\n# {MARKER}\n")
        self.assertEqual(run(self.root, self.baselines).returncode, 1)

    def test_excluded_generated_files_are_not_counted(self):
        self.write("docs/changelog.md", f"# {MARKER}\n")
        self.write("vendor/x.py", f"# {MARKER}\n")
        self.write("src/a.py", "# clean\n")
        self.seed()
        self.assertNotIn("docs/changelog.md", self.baseline_text("todo-markers"))
        self.assertNotIn("vendor/", self.baseline_text("todo-markers"))

    def test_malformed_baseline_is_a_configuration_error(self):
        self.write("src/a.py", "# clean\n")
        self.seed()
        (self.baselines / "todo-markers.baseline").write_text("garbage row\n", encoding="utf-8")
        self.assertEqual(run(self.root, self.baselines).returncode, 4)

    def test_dead_code_allow_ratchet_counts_annotations(self):
        self.write("src/a.rs", f"#[{ALLOW}]\nfn helper() {{}}\n")
        self.seed()
        self.assertIn("1 = src/a.rs", self.baseline_text("dead-code-allows"))

    def test_formatted_and_conditional_lint_lists_cannot_hide_new_debt(self):
        debt = "dead" + "_code"
        unused = "unused" + "_variables"
        samples = (
            f"#[allow(\n    {debt}\n)]",
            f"#![expect(\n    {unused},\n)]",
            f"#[allow(clippy::unused_async, {debt})]",
            f"#[expect(clippy::too_many_lines, {unused}, {debt})]",
            f"#[cfg_attr(feature = \"arch\", allow(\n {unused},\n))]",
            f"#[cfg_attr(all(), cfg_attr(any(), expect(\n {debt}\n)))]",
            f"#[r#allow(r#{debt})]",
        )
        self.seed()
        for attribute in samples:
            with self.subTest(attribute=attribute):
                self.write("src/candidate.rs", attribute + "\nfn main() {}\n")
                result = run(self.root, self.baselines)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("src/candidate.rs = 1", result.stderr)
                refused = run(self.root, self.baselines, "--refresh")
                self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
                self.assertEqual(self.baseline_text("dead-code-allows"), "")

    def test_multiple_debt_lints_in_one_attribute_count_once(self):
        debt = "dead" + "_code"
        unused = "unused" + "_variables"
        self.write("src/a.rs", f"#[allow({debt}, {unused}, unused_mut)]\nfn main() {{}}\n")
        self.seed()
        self.assertEqual(self.baseline_text("dead-code-allows"), "1 = src/a.rs\n")
        self.write("src/a.rs", f"#[allow(\n {unused},\n {debt},\n unused_mut,\n)]\nfn main() {{}}\n")
        self.assertEqual(run(self.root, self.baselines).returncode, 0)
        self.seed()
        self.assertEqual(self.baseline_text("dead-code-allows"), "1 = src/a.rs\n")

    def test_literal_reason_and_comment_text_are_not_lint_attributes(self):
        annotation = "#[" + ALLOW + "]"
        samples = (
            f"// {annotation}\nfn main() {{}}",
            f"/* outside /* {annotation} */ comment */\nfn main() {{}}",
            f'fn main() {{ println!("{annotation}"); }}',
            f'fn main() {{ println!(r###"{annotation} \\\"quoted\\\""###); }}',
            f'fn main() {{ let bytes = br##"{annotation}"##; }}',
            f'fn main() {{ let c_string = cr##"{annotation}"##; }}',
            f"fn main() {{ let quote = '\"'; /* {annotation} */ }}",
            f"fn borrow<'a>(value: &'a str) {{ /* {annotation} */ }}",
            f'#[allow(clippy::too_many_lines, reason = "{annotation}")]\nfn main() {{}}',
            f'#[allow(clippy::too_many_lines, reason = r#"{annotation}"#)]\nfn main() {{}}',
            '#[allow(clippy::unused_async)]\nfn main() {}',
        )
        self.seed()
        for source in samples:
            with self.subTest(source=source):
                self.write("src/candidate.rs", source + "\n")
                result = run(self.root, self.baselines)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_each_conditional_lint_list_counts_independently(self):
        debt = "dead" + "_code"
        self.write("src/a.rs", f'#[cfg_attr(any(), allow({debt}), expect(unused_mut))]\nfn main() {{}}\n')
        self.seed()
        self.assertEqual(self.baseline_text("dead-code-allows"), "2 = src/a.rs\n")


if __name__ == "__main__":
    unittest.main()

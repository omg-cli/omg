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



# Structured inventory references are metadata; surrounding work items remain debt.
import hashlib
import json
import os


class InventoryReferenceDebtTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='omg-inventory-debt-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'repo'
        self.root.mkdir()
        self.baselines = self.root / 'baselines'
        self.baselines.mkdir()
        for name in ('todo-markers', 'dead-code-allows'):
            (self.baselines / (name + '.baseline')).write_bytes(b'')
        self.git_home = Path(temporary.name) / 'git-home'
        self.git_home.mkdir()
        self.git_env = {
            name: os.environ[name] for name in ('PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP')
            if name in os.environ
        }
        self.git_env.update(HOME=str(self.git_home), GIT_CONFIG_NOSYSTEM='1',
                            GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_COUNT='0',
                            GIT_NO_REPLACE_OBJECTS='1', GIT_TERMINAL_PROMPT='0')
        self.git('init', '--initial-branch=main')
        self.filename = MARKER + '.md'
        payload = b'# Inventory fixture\n'
        (self.root / self.filename).write_bytes(payload)
        self.git('add', '--', self.filename)
        blob = self.git('rev-parse', ':' + self.filename)
        self.entry = {'path': self.filename, 'bytes': len(payload),
                      'sha256': hashlib.sha256(payload).hexdigest(),
                      'mode': '100644', 'blob': blob}
        index_row = self.git('ls-files', '--stage', '--', self.filename)
        self.assertEqual(index_row, '100644 ' + blob + ' 0\t' + self.filename)
        self.manifest_path = '.audit/proof/manifest.json'
        self.manifest = self.root / self.manifest_path
        self.manifest.parent.mkdir(parents=True)

    def git(self, *arguments):
        result = subprocess.run(
            ['git', '-c', 'maintenance.auto=false', '-c', 'gc.auto=0',
             '--no-optional-locks', '-C', str(self.root), *arguments],
            env=self.git_env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout.strip()

    def invoke(self, content):
        self.manifest.write_bytes(content.encode('utf-8'))
        before = {name: (self.baselines / (name + '.baseline')).read_bytes()
                  for name in ('todo-markers', 'dead-code-allows')}
        result = run(self.root, self.baselines)
        self.assertEqual({name: (self.baselines / (name + '.baseline')).read_bytes()
                          for name in before}, before)
        self.assertEqual((self.root / self.filename).read_bytes(), b'# Inventory fixture\n')
        return result

    def test_valid_tracked_inventory_filename_is_metadata(self):
        document = {'schema': 1, 'closure': [self.entry]}
        result = self.invoke(json.dumps(document, indent=2))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ratchet todo-markers: pass (0 findings', result.stdout)
        self.assertNotIn(self.manifest_path, result.stderr)

    def test_inventory_reference_does_not_hide_free_work_item(self):
        document = {'schema': 1, 'closure': [self.entry],
                    'description': MARKER + ': repair a genuine unfinished operation'}
        result = self.invoke(json.dumps(document))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('new_files: ' + self.manifest_path + ' = 1', result.stderr)
        self.assertIn('ratchet todo-markers: fail (1 findings', result.stdout)

    def test_invalid_inventory_shapes_and_prose_keep_marker_findings(self):
        valid = {'schema': 1, 'closure': [self.entry]}
        cases = []
        for field in ('bytes', 'sha256', 'mode', 'blob'):
            entry = dict(self.entry)
            del entry[field]
            cases.append(('missing-' + field, {'schema': 1, 'closure': [entry]}))
        for field, value in (('bytes', True), ('bytes', 1.0), ('sha256', 'not-a-digest'),
                             ('mode', '777777'), ('blob', 'not-an-object'),
                             ('path', './' + self.filename),
                             ('path', '../' + self.filename),
                             ('path', self.filename + ' needs repair')):
            entry = dict(self.entry)
            entry[field] = value
            cases.append(('invalid-' + field + '-' + repr(value),
                          {'schema': 1, 'closure': [entry]}))
        extra = dict(self.entry)
        extra['reason'] = 'clean metadata'
        cases.append(('extra-entry-field', {'schema': 1, 'closure': [extra]}))
        cases += [('schema-bool', {'schema': True, 'closure': [self.entry]}),
                  ('schema-float', {'schema': 1.0, 'closure': [self.entry]}),
                  ('closure-object', {'schema': 1, 'closure': self.entry}),
                  ('unstructured-path', {'path': self.filename}),
                  ('prose-message', {'message': self.filename + ' needs repair'})]
        for name, document in cases:
            with self.subTest(case=name):
                result = self.invoke(json.dumps(document))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('new_files: ' + self.manifest_path + ' = 1', result.stderr)
        duplicate = ('{"schema":1,"closure":[{"path":' + json.dumps(self.filename)
                     + ',"path":"clean.md","bytes":0,"sha256":"' + '0' * 64
                     + '","mode":"100644","blob":"' + '0' * 40 + '"}]}')
        with self.subTest(case='duplicate-key'):
            result = self.invoke(duplicate)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('new_files: ' + self.manifest_path + ' = 1', result.stderr)
        with self.subTest(case='malformed-json'):
            result = self.invoke(json.dumps(valid)[:-1])
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('new_files: ' + self.manifest_path + ' = 1', result.stderr)


if __name__ == "__main__":
    unittest.main()

"""Exercise exact coverage comparison and refusal of incomplete evidence."""
import importlib.util
import copy
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check-line-coverage.py")
SPEC = importlib.util.spec_from_file_location("line_coverage", SCRIPT)
coverage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = coverage
SPEC.loader.exec_module(coverage)


def report(hit=1, found=2, counts=(1, 0)):
    return "SF:/src/a.rs\n" + "".join(
        f"DA:{i},{count}\n" for i, count in enumerate(counts, 1)
    ) + f"LF:{found}\nLH:{hit}\nend_of_record\n"


class LineCoverageTests(unittest.TestCase):
    def read(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lcov.info"
            path.write_text(text, encoding="utf-8")
            return coverage.read_coverage(path)

    def test_equal_and_improved_coverage(self):
        base = self.read(report())
        coverage.require_no_regression(base, base)
        coverage.require_no_regression(base, self.read(report(2, 2, (1, 1))))

    def test_llvm_instantiation_summary_and_mapping_are_both_preserved(self):
        value = self.read(report(2, 3, (1, 0)))
        self.assertEqual((value.hit, value.found), (2, 3))
        self.assertEqual((value.mapped_hit, value.mapped), (1, 2))

    def test_summary_drop_is_fatal_even_when_mapping_improves(self):
        with self.assertRaisesRegex(ValueError, "Line coverage decreased"):
            coverage.require_no_regression(
                self.read(report(2, 3)), self.read(report(1, 3, (1, 1))))

    def test_mapping_drop_is_fatal_even_when_summary_improves(self):
        with self.assertRaisesRegex(ValueError, "Mapped line coverage decreased"):
            coverage.require_no_regression(
                self.read(report(1, 2, (1, 1))), self.read(report(2, 2)))

    def test_integer_comparison_rejects_drop_hidden_by_float_rounding(self):
        n = 10**20
        base = coverage.Coverage(1, n, n - 1, 2, 1, "base")
        head = coverage.Coverage(1, n, n - 2, 2, 1, "head")
        self.assertEqual(float(base.hit / n), float(head.hit / n))
        with self.assertRaisesRegex(ValueError, "Line coverage decreased"):
            coverage.require_no_regression(base, head)

    def test_all_file_sections_count(self):
        value = self.read(report() + report(0, 2, (0, 0)).replace("a.rs", "b.rs"))
        self.assertEqual((value.files, value.found, value.hit), (2, 4, 1))
        self.assertEqual((value.mapped, value.mapped_hit), (4, 1))

    def test_corrupt_or_missing_records_are_fatal(self):
        valid = report()
        bad = ["", valid.replace("end_of_record\n", ""), valid + valid,
               valid.replace("SF:/src/a.rs", "SF:"),
               valid.replace("LF:2\n", ""), valid.replace("LH:1\n", ""),
               valid.replace("LF:2", "LF:-2"), valid.replace("LH:1", "LH:3"),
               valid.replace("LF:2", "LF:2\nLF:2"),
               valid.replace("DA:1,1", "DA:0,1"),
               valid.replace("DA:2,0", "DA:1,0"),
               valid.replace("DA:1,1\nDA:2,0\n", ""),
               "DA:1,1\n" + valid, valid.replace("DA:1,1", "DA:1,-1"),
               valid.replace("DA:1,1", "DA:1,1,checksum,extra"),
               valid.replace("SF:/src/a.rs", "SF:/src/a.rs\nTN:late"),
               valid + "FNF:1\n", valid + "unknown:1\n"]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.read(text)

    def test_cli_regression_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "base.info"
            head = Path(directory) / "head.info"
            base.write_text(report(), encoding="utf-8")
            head.write_text(report(0, 2, (0, 0)), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--base", str(base), "--head", str(head)],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Line coverage decreased", result.stderr)



class SourceAwareCoverageTests(unittest.TestCase):
    old_source = b"fn obsolete() {\n}\nfn retained() {\n  exercised();\n  untested();\n}\n"
    new_source = b"fn retained() {\n  exercised();\n  untested();\n}\n"

    def fixture(self):
        before = [(1, 3), (2, 3), (3, 1), (4, 1), (5, 0), (6, 0)]
        after = [(1, 1), (2, 1), (3, 0), (4, 0)]
        return before, after

    def regions(self, rows, deleted):
        functions = [{"name": "retained", "filenames": ["/src/example.rs"],
                      "regions": [[line, 1, line, 2, count, 0, 0, 0]
                                  for line, count in rows if not deleted or line > 2]}]
        if deleted:
            functions.append({"name": "obsolete", "filenames": ["/src/example.rs"],
                              "regions": [[1, 1, 1, 2, 3, 0, 0, 0], [2, 1, 2, 2, 3, 0, 0, 0]]})
        return {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{
            "files": [{"filename": "/src/example.rs", "summary": {"lines": {
                "count": len(rows), "covered": sum(count > 0 for _, count in rows)}}}],
            "functions": functions}]}

    def compare(self, before=None, after=None, mutate=None, sources=None):
        default_before, default_after = self.fixture()
        before = default_before if before is None else before
        after = default_after if after is None else after
        def lcov(rows):
            return "SF:/src/example.rs\n" + "".join(f"DA:{line},{count}\n" for line, count in rows) + f"LF:{len(rows)}\nLH:{sum(count > 0 for _, count in rows)}\nend_of_record\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bp, hp = root / "b.info", root / "h.info"
            bp.write_text(lcov(before)); hp.write_text(lcov(after))
            br, hr = self.regions(before, True), self.regions(after, False)
            if mutate:
                mutate(br, hr)
            bg, hg = root / "b.json.gz", root / "h.json.gz"
            bg.write_bytes(gzip.compress(json.dumps(br).encode()))
            hg.write_bytes(gzip.compress(json.dumps(hr).encode()))
            old, new = sources or ({"example.rs": self.old_source}, {"example.rs": self.new_source})
            return coverage.require_source_no_regression(coverage.read_coverage(bp), coverage.read_coverage(hp), bg, hg, old, new)

    def test_proven_covered_helper_deletion_preserves_both_surfaces(self):
        self.assertEqual(self.compare(), {"deleted_summary_found": 2, "deleted_summary_hit": 2,
                                        "deleted_mapped": 2, "deleted_mapped_hit": 2})

    def test_retained_loss_is_fatal_despite_compensating_gain(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.compare(after=[(1, 0), (2, 1), (3, 1), (4, 0)])

    def test_missing_retained_mapping_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.compare(after=[(2, 1), (3, 0), (4, 0)])

    def test_new_uncovered_line_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "New uncovered"):
            self.compare(after=[(1, 1), (2, 1), (3, 0), (4, 0), (5, 0)],
                         sources=({"example.rs": self.old_source}, {"example.rs": self.new_source + b"untested_new();\n"}))

    def test_missing_region_owner_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "lacks region"):
            self.compare(mutate=lambda b, h: b["data"][0]["functions"].pop())

    def test_retained_function_region_cannot_be_called_deletion(self):
        with self.assertRaisesRegex(ValueError, "retained or ambiguous"):
            self.compare(mutate=lambda b, h: h["data"][0]["functions"].append(copy.deepcopy(b["data"][0]["functions"][-1])))

    def test_duplicate_deleted_function_owner_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "retained or ambiguous"):
            self.compare(mutate=lambda b, h: b["data"][0]["functions"].append(copy.deepcopy(b["data"][0]["functions"][-1])))

    def test_summary_substitution_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "summary mismatch"):
            self.compare(mutate=lambda b, h: b["data"][0]["files"][0]["summary"]["lines"].update(covered=1))

    def test_unsupported_region_schema_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "Unsupported region schema"):
            self.compare(mutate=lambda b, h: b.update(version="future"))

    def test_multi_line_deleted_region_is_not_approximated(self):
        with self.assertRaisesRegex(ValueError, "Unsupported deleted region"):
            self.compare(mutate=lambda b, h: b["data"][0]["functions"][-1]["regions"][0].__setitem__(2, 2))

    def test_ambiguous_repository_source_is_fatal(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous or missing"):
            self.compare(sources=({}, {"example.rs": self.new_source}))

    def test_exact_source_commit_is_required(self):
        with self.assertRaisesRegex(ValueError, "Exact source commit"):
            coverage.source_blobs(Path("."), "main")

    def test_deleted_gap_region_is_not_counted_as_covered_code(self):
        with self.assertRaisesRegex(ValueError, "Unsupported deleted region"):
            self.compare(mutate=lambda b, h: b["data"][0]["functions"][-1]["regions"][0].__setitem__(7, 3))

    def test_deleted_expansion_region_is_not_counted_as_a_simple_line(self):
        with self.assertRaisesRegex(ValueError, "Unsupported deleted region"):
            self.compare(mutate=lambda b, h: b["data"][0]["functions"][-1]["regions"][0].__setitem__(6, 1))

    def test_partial_cli_evidence_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bp, hp = root / "b.info", root / "h.info"
            bp.write_text(report()); hp.write_text(report())
            result = subprocess.run([sys.executable, str(SCRIPT), "--base", str(bp), "--head", str(hp),
                                     "--base-sha", "a" * 40], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Complete exact source/region evidence required", result.stderr)

    def test_tested_replacement_is_not_normalized_as_deletion(self):
        old = b"fn original() {\n  exercise_old();\n}\n"
        new = b"fn replacement() {\n  exercise_new();\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bp, hp = root / "b.info", root / "h.info"
            bp.write_text(report(2, 2, (1, 1))); hp.write_text(report(2, 2, (1, 1)))
            region = {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{
                "files": [{"filename": "/src/a.rs", "summary": {"lines": {"count": 2, "covered": 2}}}],
                "functions": []}]}
            bg, hg = root / "b.gz", root / "h.gz"
            bg.write_bytes(gzip.compress(json.dumps(region).encode())); hg.write_bytes(bg.read_bytes())
            result = coverage.require_source_no_regression(coverage.read_coverage(bp), coverage.read_coverage(hp),
                bg, hg, {"a.rs": old}, {"a.rs": new})
            self.assertEqual(result, {"deleted_summary_found": 0, "deleted_summary_hit": 0,
                                      "deleted_mapped": 0, "deleted_mapped_hit": 0})



    def phantom_owner_compare(self, extra, base_hit=6, head_hit=4):
        before, after = self.fixture()
        def lcov(rows, hit):
            return "SF:/src/example.rs\n" + "".join(f"DA:{line},{count}\n" for line, count in rows) + f"LF:8\nLH:{hit}\nend_of_record\n"
        def regions(hit):
            return {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{
                "files": [{"filename": "/src/example.rs", "summary": {"lines": {"count": 8, "covered": hit}}}],
                "functions": []}]}
        br, hr = regions(base_hit), regions(head_hit)
        br["data"][0]["functions"] = [{"name": "obsolete", "filenames": ["/src/example.rs"],
            "regions": [[1, 1, 1, 2, 3, 0, 0, 0], [2, 1, 2, 2, 3, 0, 0, 0]]}]
        for index in range(extra):
            owner = copy.deepcopy(br["data"][0]["functions"][0])
            owner["name"] = f"extra_owner_{index}"
            br["data"][0]["functions"].append(owner)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bp, hp, bg, hg = (root / name for name in ("b", "h", "br", "hr"))
            bp.write_text(lcov(before, base_hit)); hp.write_text(lcov(after, head_hit))
            bg.write_bytes(gzip.compress(json.dumps(br).encode())); hg.write_bytes(gzip.compress(json.dumps(hr).encode()))
            return coverage.require_source_no_regression(coverage.read_coverage(bp), coverage.read_coverage(hp),
                bg, hg, {"example.rs": self.old_source}, {"example.rs": self.new_source})

    def test_distinct_name_duplicate_deleted_owner_cannot_mask_regression(self):
        with self.assertRaises(ValueError):
            self.phantom_owner_compare(1)

    def test_phantom_owners_cannot_create_negative_normalized_coverage(self):
        with self.assertRaises(ValueError):
            self.phantom_owner_compare(2, 4, 2)

    def test_same_file_unexplained_instantiation_movement_refuses_deletion(self):
        with self.assertRaises(ValueError):
            self.phantom_owner_compare(0)

    def test_negative_or_excess_normalized_counts_are_fatal(self):
        valid = coverage.Coverage(1, 2, 1, 2, 1, "fixture")
        for invalid in (coverage.Coverage(1, 2, -1, 2, 1, "fixture"),
                        coverage.Coverage(1, 2, 3, 2, 1, "fixture"),
                        coverage.Coverage(1, 2, 1, 2, -1, "fixture"),
                        coverage.Coverage(1, 2, 1, 2, 3, "fixture")):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "Invalid normalized"):
                coverage.require_no_regression(invalid, valid)



    def test_real_git_unicode_rust_path_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); subprocess.run(["git", "-C", str(root), "init"], check=True, capture_output=True)
            (root / "src").mkdir(); (root / "src" / "café.rs").write_text("fn main() {}\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture"], check=True, capture_output=True)
            commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]).decode().strip()
            self.assertEqual(coverage.source_blobs(root, commit), {"src/café.rs": b"fn main() {}\n"})

    def test_uninstrumented_repeated_braces_do_not_invalidate_unique_covered_join(self):
        old = b"fn a() {\n olda();\n}\nfn b() {\n oldb();\n}\nfn kept() {\n keep();\n}\n"
        new = b"fn changed_a() {\n newa();\n}\nfn changed_b() {\n newb();\n}\nfn kept() {\n keep();\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); info, region_path = root / "lcov", root / "regions.gz"
            info.write_text("SF:/src/example.rs\nDA:8,1\nLF:1\nLH:1\nend_of_record\n")
            region = {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{
                "files": [{"filename": "/src/example.rs", "summary": {"lines": {"count": 1, "covered": 1}}}], "functions": []}]}
            region_path.write_bytes(gzip.compress(json.dumps(region).encode()))
            value = coverage.read_coverage(info)
            try:
                actual = coverage.require_source_no_regression(value, value, region_path, region_path,
                    {"example.rs": old}, {"example.rs": new})
            except ValueError as error:
                actual = str(error)
            self.assertEqual(actual, {"deleted_summary_found": 0, "deleted_summary_hit": 0,
                                      "deleted_mapped": 0, "deleted_mapped_hit": 0})


    def test_ambiguous_covered_brace_remains_refused(self):
        old = b"fn a() {\n olda();\n}\nfn b() {\n oldb();\n}\nfn kept() {\n keep();\n}\n"
        new = b"fn changed_a() {\n newa();\n}\nfn changed_b() {\n newb();\n}\nfn kept() {\n keep();\n}\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); info, region_path = root / "lcov", root / "regions.gz"
            info.write_text("SF:/src/example.rs\nDA:3,1\nLF:1\nLH:1\nend_of_record\n")
            region = {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{
                "files": [{"filename": "/src/example.rs", "summary": {"lines": {"count": 1, "covered": 1}}}], "functions": []}]}
            region_path.write_bytes(gzip.compress(json.dumps(region).encode()))
            value = coverage.read_coverage(info)
            with self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                coverage.require_source_no_regression(value, value, region_path, region_path,
                    {"example.rs": old}, {"example.rs": new})

if __name__ == "__main__":
    unittest.main()

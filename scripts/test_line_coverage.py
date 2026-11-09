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

    def shared_brace_compare(self, mutate=None, after=None):
        old = b"fn unrelated() {\n  unavailable();\n}\nfn obsolete() {\n  exercise();\n}\nfn retained() {\n  keep();\n}\n"
        new = b"fn unrelated() {\n  unavailable();\n}\nfn retained() {\n  keep();\n}\n"
        before = [(2, 0), (4, 3), (5, 3), (6, 3), (8, 1), (9, 1)]
        after = [(2, 0), (5, 1), (6, 1)] if after is None else after
        def owners(br, hr):
            br["data"][0]["functions"] = [
                {"name": "obsolete", "filenames": ["/src/example.rs"],
                 "regions": [[line, 1, line, 2, 3, 0, 0, 0] for line in (4, 5, 6)]},
                {"name": "retained", "filenames": ["/src/example.rs"],
                 "regions": [[line, 1, line, 2, count, 0, 0, 0]
                             for line, count in before if line not in (4, 5, 6)]}]
            if mutate:
                mutate(br, hr)
        return self.compare(before=before, after=after, mutate=owners,
                            sources=({"example.rs": old}, {"example.rs": new}))

    def test_deleted_helper_brace_is_not_an_unrelated_retained_brace(self):
        self.assertEqual(self.shared_brace_compare(), {
            "deleted_summary_found": 3, "deleted_summary_hit": 3,
            "deleted_mapped": 3, "deleted_mapped_hit": 3})

    def test_shared_brace_without_deleted_owner_is_refused(self):
        with self.assertRaises(ValueError):
            self.shared_brace_compare(mutate=lambda b, h: b["data"][0]["functions"].pop(0))

    def test_shared_brace_with_retained_owner_is_refused(self):
        with self.assertRaises(ValueError):
            self.shared_brace_compare(mutate=lambda b, h: h["data"][0]["functions"].append(
                copy.deepcopy(b["data"][0]["functions"][0])))

    def test_shared_brace_with_duplicate_owner_is_refused(self):
        with self.assertRaises(ValueError):
            self.shared_brace_compare(mutate=lambda b, h: b["data"][0]["functions"].append(
                copy.deepcopy(b["data"][0]["functions"][0])))

    def test_shared_brace_with_non_deleted_owner_region_is_refused(self):
        with self.assertRaises(ValueError):
            self.shared_brace_compare(mutate=lambda b, h: b["data"][0]["functions"][0]["regions"].append(
                [8, 1, 8, 2, 1, 0, 0, 0]))

    def test_shared_brace_with_unmapped_owner_span_is_refused(self):
        with self.assertRaises(ValueError):
            self.shared_brace_compare(mutate=lambda b, h: b["data"][0]["functions"][0]["regions"][0].__setitem__(2, 7))

    def test_shared_brace_does_not_excuse_real_retained_loss(self):
        with self.assertRaises(ValueError):
            self.shared_brace_compare(after=[(2, 0), (5, 0), (6, 1)])

    def multiline_boundary_compare(self, mutate=None):
        old = b'fn unrelated() {\n  unavailable();\n}\nfn obsolete() {\n  exercise(\n    "x");\n}\nfn retained() {\n  keep();\n}\nfn obsolete_test() {\n  cases(\n    "x");\n}\n'
        new = b"fn unrelated() {\n  unavailable();\n}\nfn retained() {\n  keep();\n}\n"
        tail = b"fn tail() {\n" + b"".join(f"  tail{i}();\n".encode() for i in range(8)) + b"}\n"
        before = [(2, 0)] + [(line, 1) for line in (*range(4, 15), 16)]
        after = [(2, 0)] + [(line, 1) for line in (4, 5, 6, 8)]
        def function(name, regions):
            return {"name": name, "filenames": ["/src/example.rs"], "regions": regions}
        def line(number):
            return [number, 1, number, 2, 1, 0, 0, 0]
        br, hr = self.regions(before, False), self.regions(after, False)
        br["data"][0]["files"][0]["summary"]["lines"] = {"count": 14, "covered": 13}
        br["data"][0]["functions"] = [
            function("obsolete", [line(4), [5, 1, 6, 8, 1, 0, 0, 0], line(7)]),
            function("closure", [line(5)]),
            function("retained", [line(n) for n in (8, 9, 10)]),
            function("obsolete_test", [line(11), [12, 1, 13, 8, 1, 0, 0, 0], line(14)]),
            function("tail", [line(16)])]
        hr["data"][0]["functions"] = [
            function("retained", [line(n) for n in (4, 5, 6)]), function("tail", [line(8)])]
        if mutate:
            mutate(br, hr)
        def lcov(rows, found, hit):
            return "SF:/src/example.rs\n" + "".join(f"DA:{n},{c}\n" for n, c in rows) + f"LF:{found}\nLH:{hit}\nend_of_record\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bp, hp, bg, hg = (root / name for name in ("b", "h", "br.gz", "hr.gz"))
            bp.write_text(lcov(before, 14, 13)); hp.write_text(lcov(after, 5, 4))
            bg.write_bytes(gzip.compress(json.dumps(br).encode())); hg.write_bytes(gzip.compress(json.dumps(hr).encode()))
            return coverage.require_source_no_regression(
                coverage.read_coverage(bp), coverage.read_coverage(hp), bg, hg,
                {"example.rs": old + tail}, {"example.rs": new + tail})

    def test_multiline_deletion_restores_retained_boundary_and_counts_both_surfaces(self):
        self.assertEqual(self.multiline_boundary_compare(), {
            "deleted_summary_found": 9, "deleted_summary_hit": 9,
            "deleted_mapped": 8, "deleted_mapped_hit": 8})

    def test_multiline_expansion_region_is_refused(self):
        with self.assertRaises(ValueError):
            self.multiline_boundary_compare(mutate=lambda b, h: b["data"][0]["functions"][0]["regions"][1].__setitem__(6, 1))

    def test_multiline_end_column_one_is_not_inclusively_expanded(self):
        with self.assertRaises(ValueError):
            self.multiline_boundary_compare(mutate=lambda b, h: b["data"][0]["functions"][0]["regions"][1].__setitem__(3, 1))

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


    def new_uncovered_diagnostic(self, added_lines):
        source_name = "src/runtimes/common.rs"
        before = [(1, 1)]
        after = [(1, 1)] + [(line, 0) for line in range(2, added_lines + 2)]
        def lcov(rows):
            return "SF:/checkout/src/runtimes/common.rs\n" + "".join(
                f"DA:{line},{count}\n" for line, count in rows
            ) + f"LF:{len(rows)}\nLH:1\nend_of_record\n"
        def regions(rows):
            value = self.regions(rows, False)
            value["data"][0]["files"][0]["filename"] = "/checkout/src/runtimes/common.rs"
            value["data"][0]["functions"] = []
            return gzip.compress(json.dumps(value).encode("utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bp, hp, bg, hg = (root / name for name in ("b.info", "h.info", "b.gz", "h.gz"))
            bp.write_text(lcov(before), encoding="utf-8")
            hp.write_text(lcov(after), encoding="utf-8")
            bg.write_bytes(regions(before))
            hg.write_bytes(regions(after))
            with self.assertRaises(ValueError) as caught:
                coverage.require_source_no_regression(
                    coverage.read_coverage(bp), coverage.read_coverage(hp), bg, hg,
                    {source_name: b"keep();\n"},
                    {source_name: b"keep();\n" + b"uncovered();\n" * added_lines})
            return str(caught.exception)

    def test_new_uncovered_diagnostic_identifies_actual_source_and_line(self):
        self.assertEqual(
            self.new_uncovered_diagnostic(1),
            "New uncovered instrumented line: src/runtimes/common.rs:2")

    def test_new_uncovered_diagnostic_reports_one_location_for_many_zeroes(self):
        self.assertEqual(
            self.new_uncovered_diagnostic(1000),
            "New uncovered instrumented line: src/runtimes/common.rs:2")

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

    def test_multi_line_deleted_region_cannot_include_retained_source(self):
        with self.assertRaisesRegex(ValueError, "Unsupported deleted region"):
            self.compare(mutate=lambda b, h: b["data"][0]["functions"][-1]["regions"][0].__setitem__(2, 3))

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

    def repeated_owned_brace_compare(self, missing=None, lost=False, mutate=None):
        old = b"fn first(old: bool) {\n  consume(old);\n}\nfn second(old: bool) {\n  consume_again(old);\n}\nfn kept() {\n  keep();\n}\n"
        new = old.replace(b"old", b"new")
        before = [(line, 1) for line in range(1, 10)]
        after = [(line, int(not lost or line != 3)) for line in range(1, 10)]

        def owners(base, head):
            for value, rows in [(base, before), (head, after)]:
                counts = dict(rows)
                value["data"][0]["functions"] = [
                    {"name": name, "filenames": ["/src/example.rs"],
                     "regions": [[line, 1, line, 2, counts[line], 0, 0, 0]
                                 for line in range(start, start + 3)]}
                    for name, start in [("first", 1), ("second", 4), ("kept", 7)]]
            if missing == "missing":
                head["data"][0]["functions"].pop(0)
            elif missing == "duplicate":
                head["data"][0]["functions"].append(
                    copy.deepcopy(head["data"][0]["functions"][0]))
            elif missing == "multifile":
                head["data"][0]["functions"][0]["filenames"].append("/src/other.rs")
            if mutate:
                mutate(base, head)

        return self.compare(before=before, after=after, mutate=owners,
                            sources=({"example.rs": old}, {"example.rs": new}))

    def test_unique_function_owners_resolve_repeated_covered_braces(self):
        self.assertEqual(self.repeated_owned_brace_compare(), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_owned_repeated_brace_still_rejects_coverage_loss(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.repeated_owned_brace_compare(lost=True)

    def test_repeated_brace_without_unique_same_file_owner_is_refused(self):
        for missing in ["missing", "duplicate", "multifile"]:
            with self.subTest(missing=missing), self.assertRaisesRegex(
                    ValueError, "Ambiguous unchanged source"):
                self.repeated_owned_brace_compare(missing=missing)

    def test_malformed_function_region_cannot_resolve_repeated_text(self):
        invalid = [
            [1, 1, 1, 2, -1, 0, 0, 0],
            [2, 1, 1, 2, 1, 0, 0, 0],
            [1, 1, 1, 0, 1, 0, 0, 0],
            [1, 1, 1, 2, True, 0, 0, 0],
            [1, 999, 1, 1000, 1, 0, 0, 0],
            [1, 1, 99, 2, 1, 0, 0, 0],
        ]
        for side in [0, 1]:
            for region in invalid:
                def corrupt(base, head):
                    [base, head][side]["data"][0]["functions"][0]["regions"][0] = region
                with self.subTest(side=side, region=region), self.assertRaisesRegex(
                        ValueError, "Ambiguous unchanged source"):
                    self.repeated_owned_brace_compare(mutate=corrupt)

    def test_exclusive_endpoint_cannot_prove_repeated_brace_ownership(self):
        def exclusive(base, head):
            for value in [base, head]:
                value["data"][0]["functions"][0]["regions"] = [[1, 1, 3, 1, 1, 0, 0, 0]]
        with self.assertRaises(ValueError):
            self.repeated_owned_brace_compare(mutate=exclusive)

    def duplicated_owned_calls_compare(self, before=None, after=None, head_source=None, mutate=None):
        old = b"fn retained(old: bool) {\n  first_input(old);\n  collect();\n  finish();\n  first_expected(old);\n  second_input(old);\n  collect();\n  finish();\n  second_expected(old);\n}\nfn tail() {\n  keep();\n}\n"
        new = head_source or old.replace(b"old", b"new")
        before = before if before is not None else [(line, 1) for line in range(1, 14)]
        after = after if after is not None else [(line, 1) for line in range(1, 14)]

        def owners(base, head):
            for value, rows in [(base, before), (head, after)]:
                counts = dict(rows)
                value["data"][0]["functions"] = [
                    {"name": name, "filenames": ["/src/example.rs"],
                     "regions": [[line, 1, line, 2, counts.get(line, 0), 0, 0, 0]
                                 for line in range(start, end + 1)]}
                    for name, start, end in [("retained", 1, 10), ("tail", 11, 13)]]
            if mutate:
                mutate(base, head)

        return self.compare(before=before, after=after, mutate=owners,
                            sources=({"example.rs": old}, {"example.rs": new}))

    def test_covered_duplicates_within_the_same_function_preserve_coverage(self):
        self.assertEqual(self.duplicated_owned_calls_compare(), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_every_in_owner_duplicate_requires_a_positive_head_counter(self):
        for line in [3, 4, 7, 8]:
            for missing in [False, True]:
                rows = [(at, int(at != line)) for at in range(1, 14)
                        if not missing or at != line]
                with self.subTest(line=line, missing=missing), self.assertRaises(ValueError):
                    self.duplicated_owned_calls_compare(after=rows)

    def test_covered_duplicates_cannot_exempt_an_unanchored_zero_head(self):
        with self.assertRaises(ValueError):
            self.duplicated_owned_calls_compare(
                before=[(line, int(line not in (4, 8))) for line in range(1, 14)],
                after=[(line, int(line not in (4, 8))) for line in range(1, 14)])

    def test_duplicate_candidate_outside_its_profile_regions_is_refused(self):
        def missing_region(base, head):
            owner = head["data"][0]["functions"][0]
            owner["regions"] = [region for region in owner["regions"] if region[0] != 7]
        with self.assertRaises(ValueError):
            self.duplicated_owned_calls_compare(mutate=missing_region)

    def test_owned_duplicate_can_improve_from_uncovered_to_covered(self):
        self.assertEqual(self.duplicated_owned_calls_compare(
            before=[(line, int(line != 4)) for line in range(1, 14)]), {
                "deleted_summary_found": 0, "deleted_summary_hit": 0,
                "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_duplicate_text_from_another_function_does_not_prove_retention(self):
        new = b"fn retained(new: bool) {\n  only_new(new);\n}\nfn foreign() {\n  collect();\n  finish();\n  gap();\n  collect();\n  finish();\n}\nfn tail() {\n  keep();\n}\n"
        def foreign_owner(base, head):
            first = head["data"][0]["functions"][0]
            first["regions"] = first["regions"][:3]
            head["data"][0]["functions"].append({
                "name": "foreign", "filenames": ["/src/example.rs"],
                "regions": [[line, 1, line, 2, 1, 0, 0, 0] for line in range(4, 11)]})
        with self.assertRaises(ValueError):
            self.duplicated_owned_calls_compare(head_source=new, mutate=foreign_owner)

    def test_covered_duplicates_do_not_excuse_unrelated_new_zero_lines(self):
        base = b"fn retained(old: bool) {\n  first_input(old);\n  collect();\n  finish();\n  first_expected(old);\n  second_input(old);\n  collect();\n  finish();\n  second_expected(old);\n}\nfn tail() {\n  keep();\n}\n"
        new = base.replace(b"old", b"new") + b"fn untested() {\n  missed();\n}\n"
        rows = [(line, int(line < 14)) for line in range(1, 17)]
        with self.assertRaisesRegex(ValueError, "New uncovered"):
            self.duplicated_owned_calls_compare(after=rows, head_source=new)

    def changed_profile_role_compare(self, after=None, mutate=None, head_source=None, duplicate_declaration=None, partial_base=False):
        old = b"fn checked() {\n  if isolated(old) {\n    return;\n  }\n  first(old);\n  probe();\n  finish();\n  second(old);\n  probe();\n  finish();\n}\nfn other() {\n  if unrelated() {\n    return;\n  }\n}\n"
        new = head_source or b"fn checked() {\n  if isolated(new) {\n    return;\n  }\n  with_env(|| {\n  first(new);\n  probe();\n  finish();\n  second(new);\n  probe();\n  finish();\n  });\n}\nfn other() {\n  if unrelated() {\n    return;\n  }\n}\n"
        if duplicate_declaration == "base":
            old += b"mod nested {\nfn checked() {\n}\n}\n"
        elif duplicate_declaration == "head":
            new += b"mod nested {\nfn checked() {\n}\n}\n"
        before = [(line, int(line != 3)) for line in range(1, 17)]
        after = after if after is not None else [(line, 1) for line in range(1, len(new.splitlines()) + 1)]

        def owners(base, head):
            def function(name, start, end, rows):
                counts = dict(rows)
                return {"name": name, "filenames": ["/src/example.rs"],
                        "regions": [[line, 1, line, 2, counts.get(line, 0), 0, 0, 0]
                                    for line in range(start, end + 1)]}
            base["data"][0]["functions"] = [
                function("closure_0", 1, 11, before), function("other", 12, 16, before)]
            if partial_base:
                base["data"][0]["functions"][0]["regions"].pop()
            head["data"][0]["functions"] = [
                function("plain_checked", 1, 13, after),
                function("closure_0", 5, 12, after), function("other", 14, 18, after)]
            if mutate:
                mutate(base, head)

        return self.compare(before=before, after=after, mutate=owners,
                            sources=({"example.rs": old}, {"example.rs": new}))

    def test_source_declaration_survives_a_profile_symbol_changing_role(self):
        self.assertEqual(self.changed_profile_role_compare(), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_source_header_can_pair_a_profile_that_ends_inside_the_function(self):
        self.assertEqual(self.changed_profile_role_compare(partial_base=True), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_source_header_pair_requires_every_candidate_counter(self):
        for lost in [3, 4, 7, 8, 10, 11]:
            for missing in [False, True]:
                with self.subTest(lost=lost, missing=missing), self.assertRaises(ValueError):
                    self.changed_profile_role_compare(partial_base=True,
                        after=[(line, int(line != lost)) for line in range(1, 19)
                               if not missing or line != lost])

    def test_partial_header_raw_owner_cannot_anchor_a_new_nested_zero(self):
        old = b"fn checked() {\n  if flag_old {\n    work();\n  }\n  before_old();\n}\nfn tail() {\n  keep();\n}\n"
        new = b"fn checked() {\n  if flag_new {\n    work();\n  }\n  if extra {\n    exercised();\n  }\n  before_new();\n}\nfn tail() {\n  keep();\n}\n"
        before = [(line, int(line != 4)) for line in range(1, 10)]
        after = [(line, int(line != 7)) for line in range(1, 13)]

        def owners(base, head):
            for value, source, rows, partial_end, tail in [
                    (base, old, before, 4, (7, 9)), (head, new, after, 7, (10, 12))]:
                lines = source.decode().splitlines()
                counts = dict(rows)
                value["data"][0]["functions"] = [
                    {"name": name, "filenames": ["/src/example.rs"],
                     "regions": [[line, 1, line, len(lines[line - 1].encode()) + 1,
                                  counts[line], 0, 0, 0]
                                 for line in range(start, end + 1)]}
                    for name, start, end in [("checked", 1, partial_end), ("tail", *tail)]]

        with self.assertRaisesRegex(ValueError, "New uncovered instrumented line: example.rs:7"):
            self.compare(before=before, after=after, mutate=owners,
                         sources=({"example.rs": old}, {"example.rs": new}))

    def test_source_declaration_pair_still_requires_covered_candidates(self):
        for lost in [3, 4, 7, 8, 10, 11]:
            with self.subTest(lost=lost), self.assertRaises(ValueError):
                self.changed_profile_role_compare(
                    after=[(line, int(line != lost)) for line in range(1, 19)])

    def test_source_declaration_pair_refuses_incomplete_owner_proof(self):
        mutations = {
            "missing": lambda base, head: head["data"][0]["functions"].pop(0),
            "duplicate": lambda base, head: head["data"][0]["functions"].append(
                copy.deepcopy(head["data"][0]["functions"][0])),
            "multifile": lambda base, head: head["data"][0]["functions"][0]["filenames"].append("/src/other.rs"),
            "malformed": lambda base, head: head["data"][0]["functions"][0]["regions"][0].__setitem__(4, -1),
            "before_candidate": lambda base, head: head["data"][0]["functions"][0].__setitem__(
                "regions", head["data"][0]["functions"][0]["regions"][:2]),
            "duplicate_base": lambda base, head: base["data"][0]["functions"].append(
                copy.deepcopy(base["data"][0]["functions"][0])),
            "malformed_base": lambda base, head: base["data"][0]["functions"][0]["regions"][0].__setitem__(4, -1),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.changed_profile_role_compare(mutate=mutate)

    def test_source_declaration_pair_refuses_repeated_declarations(self):
        for side in ["base", "head"]:
            with self.subTest(side=side), self.assertRaisesRegex(ValueError, "Ambiguous unchanged"):
                self.changed_profile_role_compare(duplicate_declaration=side)

    def test_source_declaration_pair_cannot_exempt_unrelated_new_zero(self):
        source = b"fn checked() {\n  if isolated(new) {\n    return;\n  }\n  with_env(|| {\n  first(new);\n  probe();\n  finish();\n  second(new);\n  probe();\n  finish();\n  });\n}\nfn other() {\n  if unrelated() {\n    return;\n  }\n}\nfn missed() {\n  pending();\n}\n"
        for partial in [False, True]:
            with self.subTest(partial=partial), self.assertRaisesRegex(ValueError, "New uncovered"):
                self.changed_profile_role_compare(
                    head_source=source, partial_base=partial,
                    after=[(line, int(line <= 18)) for line in range(1, 22)])

    def test_covered_file_suffix_survives_repeated_closing_braces(self):
        old = b"mod tests {\n    fn first() {\n        first();\n    }\n}\nmod last {\n    fn changed() {\n        old();\n    }\n}\n"
        new = old.replace(b"        old();", b"        new();\n        checked();")
        actual = self.compare(before=[(9, 1)], after=[(10, 1)],
                              sources=({"example.rs": old}, {"example.rs": new}))
        self.assertEqual(actual, {"deleted_summary_found": 0, "deleted_summary_hit": 0,
                                  "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def inserted_helper_compare(self, before=None, after=None, stable=False, mutate=None, marker=False):
        old = b"    fn checked() {\n        if skip() {\n            return;\n        }\n        work();\n    }\n"
        new = b"    fn checked() {\n        with_env(|| {\n            work();\n        });\n    }\n\n    fn inserted() {\n        for item in items {\n            consume(item);\n        }\n    }\n"
        if stable:
            old = old.replace(b"        work();", b"        stable();\n        work();")
            new = new.replace(b"        });", b"        });\n        stable();").replace(
                b"        }\n    }", b"        }\n        stable();\n    }")
        if marker:
            old = old.replace(b"        }\n", b"        // shared marker\n        }\n")
            new = new.replace(b"        }\n", b"        // shared marker\n        }\n")
        oldend, newend, helper = (7, 6, 8) if stable else (6, 5, 7)
        oldend += int(marker)
        before = before if before is not None else [(n, int(n != 3)) for n in range(1, oldend + 1)
                                                   if not marker or n != 4]
        after = after if after is not None else [(n, 1) for n in range(1, len(new.splitlines()) + 1)
                                                if n not in (newend + 1, helper + 3 + int(marker))
                                                and (not marker or n != helper + 3)]

        def owners(base, head):
            for value, source, rows, spans in [
                    (base, old, before, [("checked", 1, oldend)]),
                    (head, new, after, [("checked", 1, newend), ("inserted", helper, len(new.splitlines()))])]:
                lines, counts = source.decode().splitlines(), dict(rows)
                value["data"][0]["functions"] = [
                    {"name": name, "filenames": ["/src/example.rs"],
                     "regions": [[line, 1, line, len(lines[line - 1].encode()) + 1,
                                  counts[line], 0, 0, 0]
                                 for line in range(start, end + 1) if line in counts]}
                    for name, start, end in spans]
            if mutate:
                mutate(base, head)

        return self.compare(before=before, after=after, mutate=owners,
                            sources=({"example.rs": old}, {"example.rs": new}))

    def test_complete_function_replacement_cannot_retain_a_foreign_helper_brace(self):
        self.assertEqual(self.inserted_helper_compare(), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_scoped_statement_loss_cannot_use_a_covered_foreign_copy(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line|Ambiguous unchanged source"):
            self.inserted_helper_compare(stable=True,
                after=[(n, int(n != 5)) for n in range(1, 14) if n not in (7, 11)])

    def test_scoped_gray_branch_cannot_retain_a_new_helper_zero(self):
        with self.assertRaisesRegex(ValueError, "New uncovered instrumented line: example.rs:10"):
            self.inserted_helper_compare(before=[(n, int(n in (1, 5, 6))) for n in range(1, 7)],
                after=[(n, int(n != 10)) for n in range(1, 12) if n != 6])

    def test_incomplete_function_evidence_cannot_authorize_local_correspondence(self):
        mutations = {
            "missing": lambda base, head: head["data"][0]["functions"].pop(0),
            "duplicate": lambda base, head: head["data"][0]["functions"].append(
                copy.deepcopy(head["data"][0]["functions"][0])),
            "multifile": lambda base, head: head["data"][0]["functions"][0]["filenames"].append("/src/other.rs"),
            "malformed": lambda base, head: head["data"][0]["functions"][0]["regions"][0].__setitem__(4, -1),
            "partial": lambda base, head: head["data"][0]["functions"][0]["regions"].pop(),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.inserted_helper_compare(mutate=mutate)
            with self.subTest(name=name, gray=True), self.assertRaises(ValueError):
                self.inserted_helper_compare(mutate=mutate,
                    before=[(n, int(n in (1, 5, 6))) for n in range(1, 7)],
                    after=[(n, int(n != 10)) for n in range(1, 12) if n != 6])
            with self.subTest(name=name, gray=True, marker=True), self.assertRaises(ValueError):
                self.inserted_helper_compare(mutate=mutate, marker=True,
                    before=[(n, int(n in (1, 6, 7))) for n in range(1, 8) if n != 4],
                    after=[(n, int(n != 11)) for n in range(1, 13) if n not in (6, 10)])

    def test_unique_extracted_body_preserves_its_uncovered_error_oracle(self):
        old = b"fn checked() {\n  work();\n  if failed() {\n    report_error();\n  }\n}\n"
        new = b"fn checked() {\n  helper();\n}\nfn helper() {\n  work();\n  if failed() {\n    report_error();\n  }\n}\n"
        before = [(line, int(line not in (4, 5))) for line in range(1, 7)]
        after = [(line, int(line not in (7, 8))) for line in range(1, 10)]

        def owners(base, head):
            for value, source, rows, spans in [
                    (base, old, before, [("checked", 1, 6)]),
                    (head, new, after, [("checked", 1, 3), ("helper", 4, 9)])]:
                lines, counts = source.decode().splitlines(), dict(rows)
                value["data"][0]["functions"] = [
                    {"name": name, "filenames": ["/src/example.rs"],
                     "regions": [[line, 1, line, len(lines[line - 1].encode()) + 1,
                                  counts[line], 0, 0, 0] for line in range(start, end + 1)]}
                    for name, start, end in spans]

        self.assertEqual(self.compare(before=before, after=after, mutate=owners,
            sources=({"example.rs": old}, {"example.rs": new})), {
                "deleted_summary_found": 0, "deleted_summary_hit": 0,
                "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_non_eof_extraction_preserves_mapped_word_text_with_rust_prefixes(self):
        for statement in [b"  *state = value;", b"  /* reason */ report_error();"]:
            old = b"fn checked() {\n" + statement + b"\n}\n"
            new = b"fn checked() {\n  helper();\n}\nfn helper() {\n" + statement + b"\n}\nfn fresh() {\n  exercised();\n}\n"
            before = [(line, int(line != 2)) for line in range(1, 4)]
            after = [(line, int(line != 5)) for line in range(1, 10)]

            def owners(base, head):
                for value, source, rows, spans in [
                        (base, old, before, [("checked", 1, 3)]),
                        (head, new, after, [("checked", 1, 3), ("helper", 4, 6), ("fresh", 7, 9)])]:
                    lines, counts = source.decode().splitlines(), dict(rows)
                    value["data"][0]["functions"] = [
                        {"name": name, "filenames": ["/src/example.rs"],
                         "regions": [[line, 1, line, len(lines[line - 1].encode()) + 1,
                                      counts[line], 0, 0, 0] for line in range(start, end + 1)]}
                        for name, start, end in spans]

            with self.subTest(statement=statement):
                self.assertEqual(self.compare(before=before, after=after, mutate=owners,
                    sources=({"example.rs": old}, {"example.rs": new})), {
                        "deleted_summary_found": 0, "deleted_summary_hit": 0,
                        "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def wrapper_paint_compare(self, mutate=None):
        body = ["    work();", "    check()?;", "    (", "        value", "    )", "}"]
        untouched = ["fn unrelated() {", "    unavailable();", "}"]
        old = ["#[tokio::test]", "#[serial_test::serial]", "async fn checked() {", "    old_setup();", *body, *untouched]
        new = ["#[test]", "fn checked() {", "  helper();", "}", "async fn helper() {", *body, *untouched,
               "fn added() {", "    one();", "    two();", "    three();", "    four();", "}"]

        def row(source, line, count, column=1):
            return [line, column, line, len(source[line - 1].encode()) + 1, count, 0, 0, 0]

        def header(source, line):
            column = len(source[line - 1].encode())
            return [line, column, line, column + 1, 1, 0, 0, 0]

        def owner(name, regions):
            return dict(name=name, filenames=["/src/example.rs"], regions=regions)

        before = {3: 1, 4: 1, 5: 5, 6: 1, 7: 1, 8: 1, 9: 1, 11: 0, 12: 0, 13: 0}
        after = {2: 1, 3: 1, 4: 1, 5: 1, 6: 5, 7: 0, 8: 1, 10: 1,
                 **{n: 0 for n in range(12, 15)}, **{n: 1 for n in range(15, 21)}}
        value = dict(old=old, new=new, before=before, after=after, base=[
            owner("coarse", [header(old, 3), [5, 5, 9, 6, 1, 0, 0, 0]]),
            owner("precise", [header(old, 3), *[row(old, n, count, 5)
                for n, count in [(4, 1), (5, 5), (6, 0), (7, 1), (9, 1)]]]),
            owner("unrelated", [row(old, n, 0) for n in range(11, 14)])], head=[
            owner("coarse", [[2, 1, 4, 2, 1, 0, 0, 0]]),
            owner("renamed_precise", [header(new, 5), *[row(new, n + 1, count, 5)
                for n, count in [(5, 5), (6, 0), (7, 1), (9, 1)]]]),
            owner("unrelated", [row(new, n, 0) for n in range(12, 15)]),
            owner("added", [row(new, n, 1) for n in range(15, 21)])])
        if mutate:
            mutate(value)

        def owners(base, head):
            base["data"][0]["functions"], head["data"][0]["functions"] = value["base"], value["head"]

        return self.compare(before=sorted(before.items()), after=sorted(after.items()), mutate=owners,
            sources=({"example.rs": ("\n".join(old) + "\n").encode()},
                     {"example.rs": ("\n".join(new) + "\n").encode()}))

    def test_identical_precise_regions_resolve_only_retained_async_wrapper_paint(self):
        self.assertEqual(self.wrapper_paint_compare(), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0,
            "retained_wrapper_paint": [{"file": "example.rs", "base_range": [5, 9], "head_range": [6, 10],
                                        "precise_group_sizes": [4], "pairs": [[6, 7], [8, 9]]}]})

    def test_async_wrapper_paint_cannot_hide_precise_evidence_drift(self):
        mutations = {
            "genuine_hit_loss": lambda v: v["base"][1]["regions"][3].__setitem__(4, 1),
            "other_counter_loss": lambda v: v["head"][1]["regions"][1].__setitem__(4, 4),
            "column_drift": lambda v: v["head"][1]["regions"][1].__setitem__(1, 6),
            "source_drift": lambda v: v["new"].__setitem__(8, "        changed_value"),
            "duplicate_precise": lambda v: v["head"].append({**copy.deepcopy(v["head"][1]), "name": "extra_precise"}),
            "duplicate_coarse": lambda v: v["base"].append({**copy.deepcopy(v["base"][0]), "name": "extra_coarse"}),
            "duplicate_detailed": lambda v: v["base"].append({**copy.deepcopy(v["base"][1]), "name": "extra_detailed"}),
            "duplicate_base_name": lambda v: v["base"][0].__setitem__("name", v["base"][1]["name"]),
            "duplicate_head_name": lambda v: v["head"][0].__setitem__("name", v["head"][1]["name"]),
            "multifile": lambda v: v["head"][1]["filenames"].append("/src/other.rs"),
            "malformed": lambda v: v["head"][1]["regions"][1].__setitem__(4, True),
            "negative": lambda v: v["head"][1]["regions"][1].__setitem__(4, -1),
            "bad_column": lambda v: v["head"][1]["regions"][1].__setitem__(3, 999),
            "nonsimple": lambda v: v["head"][1]["regions"][1].__setitem__(7, 1),
            "crossing": lambda v: v["head"][1]["regions"].append([5, 1, 6, 6, 1, 0, 0, 0]),
            "entry_mismatch": lambda v: v["base"][0]["regions"][0].__setitem__(4, 2),
            "unexplained_base_da": lambda v: v["before"].__setitem__(6, 2),
            "unexplained_head_da": lambda v: v["after"].__setitem__(9, 0),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.wrapper_paint_compare(mutate=mutate)

    def test_async_wrapper_paint_requires_the_original_source_test_role(self):
        for declaration in ["fn checked() {", "async fn checked<T>() {", "async fn checked(value: u8) {"]:
            def change_header(value):
                value["old"][2] = declaration
                column = len(declaration.encode())
                for owner in value["base"][:2]:
                    owner["regions"][0][1:4] = [column, 3, column + 1]
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                self.wrapper_paint_compare(mutate=change_header)
        for attribute in ["#[test]", "#[other::test]", "// attributes are not contiguous"]:
            with self.subTest(attribute=attribute), self.assertRaises(ValueError):
                self.wrapper_paint_compare(mutate=lambda v: v["old"].__setitem__(0, attribute))

    def test_async_wrapper_paint_cannot_hide_boundary_line_precise_losses(self):
        for column in [1, 2, 5]:
            def lose_endpoint(value):
                value["base"][0]["regions"][1][3] = column
                value["head"][1]["regions"].pop(); del value["after"][10]
            with self.subTest(column=column), self.assertRaises(ValueError):
                self.wrapper_paint_compare(mutate=lose_endpoint)

        def suffix_loss(value):
            value["old"][8] = value["new"][9] = "    output();"
            value["base"][0]["regions"][1][3] = 6
            value["base"][1]["regions"][-1] = [9, 5, 9, 6, 0, 0, 0, 0]
            value["base"][1]["regions"].append([9, 7, 9, 14, 1, 0, 0, 0])
            value["head"][1]["regions"][-1] = [10, 5, 10, 6, 0, 0, 0, 0]
            value["after"][10] = 0

        def prefix_loss(value):
            value["old"][4] = value["new"][5] = "a(); work();"
            value["base"][1]["regions"][2][4] = value["head"][1]["regions"][1][4] = 0
            value["base"][1]["regions"].append([5, 1, 5, 5, 1, 0, 0, 0])
            value["before"][5] = 1; value["after"][6] = 0

        for mutate in [suffix_loss, prefix_loss]:
            with self.subTest(mutation=mutate.__name__), self.assertRaises(ValueError):
                self.wrapper_paint_compare(mutate=mutate)

    def test_async_wrapper_paint_cannot_authorize_new_or_unretained_zero_mappings(self):
        for copied_text in [False, True]:
            def new_zero(value):
                value["after"][16] = value["head"][3]["regions"][1][4] = 0
                if copied_text:
                    value["new"][15] = "    check()?;"
            with self.subTest(copied_text=copied_text), self.assertRaisesRegex(ValueError, "New uncovered"):
                self.wrapper_paint_compare(mutate=new_zero)

    def test_covered_file_suffix_loss_is_refused_despite_repeated_closing_braces(self):
        old = b"mod tests {\n    fn first() {\n        first();\n    }\n}\nmod last {\n    fn changed() {\n        old();\n    }\n}\n"
        new = old.replace(b"        old();", b"        new();\n        checked();")
        with self.assertRaisesRegex(ValueError, "Retained covered line lost coverage"):
            self.compare(before=[(9, 1)], after=[(10, 0)],
                         sources=({"example.rs": old}, {"example.rs": new}))

    def changed_owner_brace_compare(self, owned_count=1, inserted_count=0, mutate=None):
        old = b"fn retained() {\n  keep();\n}\nfn tail() {\n  tail();\n}\n"
        new = b"fn retained() {\n  checked();\n  keep();\n}\nfn inserted() {\n  pending();\n}\nfn tail() {\n  tail();\n}\n"

        def owners(base, head):
            def owner(name, start, end, count):
                return {"name": name, "filenames": ["/src/example.rs"],
                        "regions": [[start, 1, end, 2, count, 0, 0, 0]]}
            base["data"][0]["functions"] = [owner("retained", 1, 3, 1), owner("tail", 4, 6, 1)]
            head["data"][0]["functions"] = [
                owner("retained", 1, 4, owned_count),
                owner("inserted", 5, 7, inserted_count), owner("tail", 8, 10, 1)]
            if mutate:
                mutate(base, head)

        return self.compare(before=[(3, 1), (6, 1)],
                            after=[(4, owned_count), (7, inserted_count), (10, 1)],
                            mutate=owners, sources=({"example.rs": old}, {"example.rs": new}))

    def test_changed_owner_brace_is_not_an_inserted_function_brace(self):
        with self.assertRaisesRegex(ValueError, "New uncovered instrumented line: example.rs:7"):
            self.changed_owner_brace_compare()

    def test_changed_owner_brace_still_requires_coverage(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.changed_owner_brace_compare(owned_count=0, inserted_count=1)

    def test_changed_owner_brace_duplicate_owner_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.changed_owner_brace_compare(mutate=lambda base, head:
                head["data"][0]["functions"].append(copy.deepcopy(head["data"][0]["functions"][0])))

    def test_changed_owner_brace_duplicate_base_owner_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.changed_owner_brace_compare(mutate=lambda base, head:
                base["data"][0]["functions"].append(copy.deepcopy(base["data"][0]["functions"][0])))

    def test_changed_owner_brace_missing_owner_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.changed_owner_brace_compare(mutate=lambda base, head:
                head["data"][0]["functions"].pop(0))

    def test_changed_owner_brace_multifile_owner_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.changed_owner_brace_compare(mutate=lambda base, head:
                head["data"][0]["functions"][0]["filenames"].append("/src/other.rs"))

    def test_changed_owner_brace_end_column_one_is_refused(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.changed_owner_brace_compare(mutate=lambda base, head:
                head["data"][0]["functions"][0]["regions"][0].__setitem__(3, 1))


    def test_covered_retained_function_edit_needs_no_deletion_credit(self):
        old = b"fn retained() {\n  obsolete_step();\n  keep();\n}\n"
        new = b"fn retained() {\n  keep();\n}\n"
        def retained_owner(base, head):
            for value, end in [(base, 4), (head, 3)]:
                value["data"][0]["functions"] = [{
                    "name": "retained", "filenames": ["/src/example.rs"],
                    "regions": [[1, 1, end, 2, 1, 0, 0, 0]]}]
        try:
            actual = self.compare(before=[(1, 1), (2, 1), (3, 1), (4, 1)],
                                  after=[(1, 1), (2, 1), (3, 1)],
                                  mutate=retained_owner,
                                  sources=({"example.rs": old}, {"example.rs": new}))
        except ValueError as error:
            self.fail(f"fully covered retained-function edit was refused: {error}")
        self.assertEqual(actual, {"deleted_summary_found": 0, "deleted_summary_hit": 0,
                                  "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_reused_owner_symbol_needs_no_credit_when_raw_coverage_improves(self):
        def reused_owner(base, head):
            head["data"][0]["functions"].append(
                copy.deepcopy(base["data"][0]["functions"][-1]))
        try:
            actual = self.compare(after=[(1, 1), (2, 1), (3, 1), (4, 1)], mutate=reused_owner)
        except ValueError as error:
            self.fail(f"unadjusted coverage gain was refused: {error}")
        self.assertEqual(actual, {"deleted_summary_found": 0, "deleted_summary_hit": 0,
                                  "deleted_mapped": 0, "deleted_mapped_hit": 0})

    def test_retained_hit_loss_is_fatal_even_with_raw_ratio_gain(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.compare(after=[(1, 0), (2, 1), (3, 1), (4, 1)])

    def test_new_zero_is_fatal_even_with_raw_ratio_gain(self):
        with self.assertRaisesRegex(ValueError, "New uncovered"):
            self.compare(after=[(1, 1), (2, 1), (3, 1), (4, 1), (5, 0)],
                         sources=({"example.rs": self.old_source},
                                  {"example.rs": self.new_source + b"untested_new();\n"}))

    def raw_ratio_retained_owner_compare(self, head_summary, head_counts):
        old = b"fn retained() {\n  obsolete_step();\n  keep();\n  untested();\n}\n"
        new = b"fn retained() {\n  keep();\n  untested();\n}\n"
        before = [(1, 1), (2, 1), (3, 1), (4, 0), (5, 0)]
        after = list(enumerate(head_counts, 1))
        def lcov(rows, summary):
            found, hit = summary
            return "SF:/src/example.rs\n" + "".join(
                f"DA:{line},{count}\n" for line, count in rows
            ) + f"LF:{found}\nLH:{hit}\nend_of_record\n"
        def regions(rows, summary):
            found, hit = summary
            return {"type": "llvm.coverage.json.export", "version": "3.1.0", "data": [{
                "files": [{"filename": "/src/example.rs", "summary": {
                    "lines": {"count": found, "covered": hit}}}],
                "functions": [{"name": "retained", "filenames": ["/src/example.rs"],
                               "regions": [[line, 1, line, 2, count, 0, 0, 0]
                                           for line, count in rows]}]}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bp, hp, bg, hg = (root / name for name in ("b.info", "h.info", "b.gz", "h.gz"))
            bp.write_text(lcov(before, (6, 4)), encoding="utf-8")
            hp.write_text(lcov(after, head_summary), encoding="utf-8")
            bg.write_bytes(gzip.compress(json.dumps(regions(before, (6, 4))).encode("utf-8")))
            hg.write_bytes(gzip.compress(json.dumps(regions(after, head_summary)).encode("utf-8")))
            return coverage.require_source_no_regression(
                coverage.read_coverage(bp), coverage.read_coverage(hp), bg, hg,
                {"example.rs": old}, {"example.rs": new})

    def test_source_aware_summary_regression_refused_when_mapping_improves(self):
        with self.assertRaisesRegex(ValueError, "Line coverage decreased|retained or ambiguous"):
            self.raw_ratio_retained_owner_compare((6, 3), (1, 1, 1, 0))

    def test_source_aware_mapping_regression_refused_when_summary_holds(self):
        with self.assertRaisesRegex(ValueError, "Mapped line coverage decreased|retained or ambiguous"):
            self.raw_ratio_retained_owner_compare((6, 4), (1, 1, 0, 0))

if __name__ == "__main__":
    unittest.main()

"""Exercise exact coverage comparison and refusal of incomplete evidence."""
import importlib.util
import copy
import contextlib
import gzip
import json
import io
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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

    def test_wrapped_or_saturated_lcov_counter_is_invalid_evidence(self):
        maximum = 2**63 - 1
        self.assertEqual(self.read(report(counts=(maximum - 1, 0))).mapped_hit, 1)
        for count in (maximum, 18446744073709551614, 2**64):
            with self.subTest(count=count), self.assertRaisesRegex(
                    ValueError, r"Invalid LCOV coverage counter.*?/src/a\.rs:1"):
                self.read(report(counts=(count, 0)))

    def test_cli_identifies_the_side_with_invalid_counter_without_comparing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            base, head = Path(directory) / 'base.info', Path(directory) / 'head.info'
            for side in ('base', 'head'):
                base.write_text(report(), encoding='utf-8')
                head.write_text(report(), encoding='utf-8')
                (base if side == 'base' else head).write_text(
                    report(counts=(18446744073709551614, 0)), encoding='utf-8')
                result = subprocess.run([sys.executable, str(SCRIPT), '--base', str(base), '--head', str(head)],
                    capture_output=True, text=True, timeout=10)
                with self.subTest(side=side):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f'Invalid LCOV coverage counter ({side}) at /src/a.rs:1', result.stderr)
                    self.assertNotIn('Retained covered line lost', result.stderr)
                    self.assertNotIn('PASS:', result.stdout)

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

    def compare_additions(self, before=None, after=None, summaries=None, additions=None,
                          old=None, new=None, mutate=None):
        before = self.fixture()[0] if before is None else before
        after = self.fixture()[1] if after is None else after
        summaries = summaries or ((len(before), sum(c > 0 for _, c in before)),
                                  (len(after), sum(c > 0 for _, c in after)))
        additions = additions if additions is not None else {"new.rs": ([(1, 1)], (1, 1), b"new();\n")}
        old = {"example.rs": self.old_source} if old is None else old.copy()
        new = {"example.rs": self.new_source} if new is None else new.copy()
        def section(name, rows, summary):
            found, hit = summary
            return (f"SF:/src/{name}\n" + "".join(f"DA:{line},{count}\n" for line, count in rows)
                    + f"LF:{found}\nLH:{hit}\nend_of_record\n")
        br, hr = self.regions(before, True), self.regions(after, False)
        for doc, summary in ((br, summaries[0]), (hr, summaries[1])):
            doc["data"][0]["files"][0]["summary"]["lines"] = dict(zip(("count", "covered"), summary))
        head_lcov = section("example.rs", after, summaries[1])
        for name, (rows, summary, source) in additions.items():
            head_lcov += section(name, rows, summary)
            new[name] = source
            hr["data"][0]["files"].append({"filename": f"/src/{name}", "summary": {
                "lines": dict(zip(("count", "covered"), summary))}})
            hr["data"][0]["functions"].append({"name": f"owner_{name}", "filenames": [f"/src/{name}"],
                "regions": [[line, 1, line, 2, count, 0, 0, 0] for line, count in rows]})
        if mutate:
            br, hr, old, new, head_lcov = mutate(br, hr, old, new, head_lcov)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bp, hp, bg, hg = (root / name for name in ("b.info", "h.info", "b.gz", "h.gz"))
            bp.write_text(section("example.rs", before, summaries[0]))
            hp.write_text(head_lcov)
            bg.write_bytes(gzip.compress(json.dumps(br).encode()))
            hg.write_bytes(gzip.compress(json.dumps(hr).encode()))
            return coverage.require_source_no_regression(coverage.read_coverage(bp), coverage.read_coverage(hp),
                                                         bg, hg, old, new)

    def test_added_files_are_covered_and_sorted_with_deletion_credit(self):
        added = {"z.rs": ([(1, 1), (2, 4)], (2, 2), b"a();\nb();\n"),
                 "a.rs": ([(1, 2)], (1, 1), b"a();\n")}
        self.assertEqual(self.compare_additions(additions=added), {
            "deleted_summary_found": 2, "deleted_summary_hit": 2,
            "deleted_mapped": 2, "deleted_mapped_hit": 2,
            "added_files": [{"file": "a.rs", "summary_found": 1, "summary_hit": 1, "mapped": 1, "mapped_hit": 1},
                            {"file": "z.rs", "summary_found": 2, "summary_hit": 2, "mapped": 2, "mapped_hit": 2}]})

    def test_addition_with_unchanged_common_file_uses_fast_path(self):
        rows = [(1, 1), (2, 0)]
        source = b"covered();\nuncovered();\n"
        result = self.compare_additions(before=rows, after=rows,
            old={"example.rs": source}, new={"example.rs": source})
        self.assertEqual(result, {"deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0,
            "added_files": [{"file": "new.rs", "summary_found": 1, "summary_hit": 1,
                             "mapped": 1, "mapped_hit": 1}]})

    def test_empty_common_head_cannot_be_rescued_by_addition(self):
        for after in ([], [(1, 1)]):
            with self.subTest(after=after), self.assertRaisesRegex(ValueError, "No comparable common head"):
                self.compare_additions(after=after, summaries=((6, 4), (0, 0)))

    def test_added_file_requires_complete_independent_surfaces(self):
        for rows, summary, source, message in [
                ([(1, 1)], (2, 1), b"a();\n", "summary"),
                ([(1, 0)], (1, 1), b"a();\n", r"new.rs:1"),
                ([(2, 1)], (1, 1), b"a();\n", "source blob"),
                ([], (0, 0), b"", "Empty")]:
            with self.subTest(rows=rows, summary=summary), self.assertRaisesRegex(ValueError, message):
                self.compare_additions(additions={"new.rs": (rows, summary, source)})

    def test_added_file_must_not_exist_in_base_sources(self):
        old = {"example.rs": self.old_source, "new.rs": b"existing();\n"}
        with self.assertRaisesRegex(ValueError, "base source"):
            self.compare_additions(old=old)

    def test_added_owner_cannot_disguise_deletion(self):
        def reuse(br, hr, old, new, lcov):
            hr["data"][0]["functions"][-1]["name"] = "obsolete"
            return br, hr, old, new, lcov
        with self.assertRaisesRegex(ValueError, "retained or ambiguous"):
            self.compare_additions(mutate=reuse)

    def test_duplicate_added_owners_cannot_disguise_deletion(self):
        def reuse(br, hr, old, new, lcov):
            owner = hr["data"][0]["functions"][-1]
            owner["name"] = "obsolete"
            hr["data"][0]["functions"].append(copy.deepcopy(owner))
            return br, hr, old, new, lcov
        with self.assertRaisesRegex(ValueError, "retained or ambiguous"):
            self.compare_additions(mutate=reuse)

    def test_large_addition_cannot_mask_common_summary_or_mapping_regression(self):
        old = b"fn retained() {\n  obsolete_step();\n  keep();\n  untested();\n}\n"
        new = b"fn retained() {\n  replacement();\n  keep();\n  untested();\n}\n"
        additions = {"new.rs": ([(i, 1) for i in range(1, 101)], (100, 100), b"x();\n" * 100)}
        before = [(1, 1), (2, 1), (3, 1), (4, 0), (5, 0)]
        for summary, after, expected in [
                ((6, 3), before, "Line coverage decreased"),
                ((6, 4), [(1, 1), (3, 1), (4, 0), (5, 0)], "Mapped line coverage decreased")]:
            with self.subTest(summary=summary), self.assertRaisesRegex(ValueError, expected):
                self.compare_additions(before=before, after=after,
                    summaries=((6, 4), summary), additions=additions,
                    old={"example.rs": old}, new={"example.rs": new})

    def test_removed_coverage_file_is_refused_despite_addition(self):
        def remove(br, hr, old, new, lcov):
            hr["data"][0]["files"].pop(0)
            hr["data"][0]["functions"] = hr["data"][0]["functions"][1:]
            return br, hr, old, new, lcov[lcov.index("SF:/src/new.rs"):]
        with self.assertRaisesRegex(ValueError, "[Rr]emoved"):
            self.compare_additions(mutate=remove)

    def test_added_file_does_not_excuse_retained_loss_or_new_zero(self):
        with self.assertRaisesRegex(ValueError, "Retained covered line"):
            self.compare_additions(after=[(1, 0), (2, 1), (3, 1), (4, 1)])
        with self.assertRaisesRegex(ValueError, "New uncovered"):
            self.compare_additions(after=[(1, 1), (2, 1), (3, 1), (4, 1), (5, 0)],
                                   new={"example.rs": self.new_source + b"untested_new();\n"})

    def test_added_evidence_still_validates_metadata_and_counters(self):
        def change(kind):
            def mutate(br, hr, old, new, lcov):
                file = hr["data"][0]["files"][-1]
                if kind == "schema": hr["version"] = "0"
                if kind == "summary": file["summary"]["lines"]["covered"] = 0
                if kind == "missing": del new["new.rs"]
                if kind == "ambiguous": new["src/new.rs"] = b"x();\n"
                if kind == "section": hr["data"][0]["files"].pop()
                if kind == "json saturation": hr["data"][0]["functions"][-1]["regions"][0][4] = coverage.COUNTER_LIMIT
                if kind == "lcov saturation": lcov = lcov.replace("DA:1,1\nLF:1", f"DA:1,{coverage.COUNTER_LIMIT}\nLF:1")
                if kind == "malformed": lcov = lcov.replace("DA:1,1\nLF:1", "DA:1,-1\nLF:1")
                return br, hr, old, new, lcov
            return mutate
        for kind in ("schema", "summary", "missing", "ambiguous", "section", "json saturation", "lcov saturation", "malformed"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.compare_additions(mutate=change(kind))

    def test_proven_covered_helper_deletion_preserves_both_surfaces(self):
        self.assertEqual(self.compare(), {"deleted_summary_found": 2, "deleted_summary_hit": 2,
                                        "deleted_mapped": 2, "deleted_mapped_hit": 2})

    def test_json_saturation_rejects_either_side_before_source_correspondence(self):
        for side in ('base', 'head'):
            for count in (9223372036854775807, 18446744073709551614):
                def saturate(base, head):
                    document = base if side == 'base' else head
                    document['data'][0]['functions'][0]['regions'][0][4] = count
                with self.subTest(side=side, count=count), self.assertRaisesRegex(
                        ValueError, rf'Invalid JSON region coverage counter \({side}\) at /src/example\.rs:'):
                    self.compare(mutate=saturate)

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

    def multiline_copies_compare(self, mutate=None, fragments=False, copies=2):
        old = ["fn retained(", "    value: Input,", ") -> Value {",
               "    if old_first {", "        old_one();", "    }", "    old_middle();",
               "    if old_second {", "        old_two();", "    }", "    old_end();", "}"]
        new = ["fn retained(", "    value: Input,", ") -> Result<Value> {",
               "    if new_first {", "        new_one();", "        checked();", "    }",
               "    new_middle();", "    if new_second {", "        new_two();", "    }",
               "    new_end();", "}"]
        if fragments:
            for source, version in ((old, "old"), (new, "new")):
                source[3:-1] = [line for n, token in enumerate(("a", "b", "a", "b"))
                               for line in (f"    {version}_{n}();", f"    shared_{token}();")]
        value = {}
        for side, source in (("base", old), ("head", new)):
            end = len(source)
            source += ["fn tail() {", "    keep();", "}"]
            value[side] = {"source": source, "counts": {n: 1 for n in range(1, len(source) + 1)},
                          "owners": [{"name": f"{side}_crate_{instance}", "filenames": ["/src/example.rs"],
                                      "regions": [[n, 1, n, len(source[n - 1].encode()) + 1,
                                                   int(instance == copies - 1), 0, 0, 0]
                                                  for n in range(1, end + 1)]}
                                     for instance in range(copies)]}
            value[side]["owners"].append({"name": "tail", "filenames": ["/src/example.rs"],
                "regions": [[n, 1, n, len(source[n - 1].encode()) + 1, 1, 0, 0, 0]
                            for n in range(end + 1, len(source) + 1)]})
        if mutate:
            mutate(value)
        def owners(base, head):
            for document, side in ((base, "base"), (head, "head")):
                document["data"][0]["functions"] = value[side]["owners"]
        return self.compare(before=sorted(value["base"]["counts"].items()),
                            after=sorted(value["head"]["counts"].items()), mutate=owners,
                            sources=tuple({"example.rs": ("\n".join(value[side]["source"]) + "\n").encode()}
                                          for side in ("base", "head")))

    def test_multiline_return_change_preserves_covered_fragments_in_every_compiled_copy(self):
        result = self.multiline_copies_compare()
        self.assertEqual([result[key] for key in ("deleted_summary_found", "deleted_summary_hit",
                         "deleted_mapped", "deleted_mapped_hit")], [0, 0, 0, 0])
        self.assertEqual(result["positive_source_fragments"][0]["pairs"], [[6, 7], [10, 11]])

    def test_multiline_fragment_proof_preserves_instances_and_all_candidate_copies(self):
        def lose_instance(value):
            value["head"]["owners"][1]["regions"][10][4] = 0
        def foreign(value):
            value["head"]["owners"].append({"name": "foreign", "filenames": ["/src/example.rs"],
                "regions": [[7, 1, 7, 6, 1, 0, 0, 0]]})
        def foreign_path(value):
            foreign(value)
            value["head"]["owners"][-1]["filenames"] = ["/other-root/example.rs"]
        mutations = {
            "lost_instance": lose_instance,
            "zero_candidate": lambda v: v["head"]["counts"].__setitem__(11, 0),
            "missing_candidate": lambda v: v["head"]["counts"].pop(11),
            "missing_copy": lambda v: v["head"]["owners"].pop(0),
            "duplicate_symbol": lambda v: v["head"]["owners"].append(copy.deepcopy(v["head"]["owners"][0])),
            "different_geometry": lambda v: v["head"]["owners"][0]["regions"][0].__setitem__(3, 5),
            "different_parameter": lambda v: v["head"]["source"].__setitem__(1, "    value: OtherInput,"),
            "foreign_owner": foreign,
            "foreign_path_alias": foreign_path,
            "multifile_owner": lambda v: v["head"]["owners"][0]["filenames"].append("/src/other.rs"),
            "uninstrumented_duplicate": lambda v: v["head"]["source"].extend(
                ["mod nested {", "fn retained(value: Input) {}", "}"]),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                self.multiline_copies_compare(mutate=mutate)

    def test_multiline_fragment_receipts_do_not_depend_on_instance_order_or_frequency(self):
        expected = self.multiline_copies_compare()
        def reordered(value):
            value["head"]["owners"].reverse()
            for owner in value["head"]["owners"]:
                for region in owner["regions"]:
                    region[4] *= 19
        self.assertEqual(self.multiline_copies_compare(mutate=reordered), expected)
        self.multiline_copies_compare(copies=1)
        def same_return(value):
            value["head"]["source"][2] = ") -> Value {"
            for owner in value["head"]["owners"][:2]:
                owner["regions"][2][3] = len(value["head"]["source"][2]) + 1
        self.multiline_copies_compare(mutate=same_return)

    def test_multiline_fragment_proof_rejects_incomplete_or_unsupported_evidence(self):
        def extra_copy(value):
            extra = copy.deepcopy(value["head"]["owners"][0]); extra["name"] = "extra"
            value["head"]["owners"].append(extra)
        def global_duplicate(value):
            extra = copy.deepcopy(value["head"]["owners"][0]); extra["filenames"] = ["/src/excluded.rs"]
            value["head"]["owners"].append(extra)
        mutations = {
            "extra_copy": extra_copy,
            "global_duplicate": global_duplicate,
            "missing_region": lambda v: v["head"]["owners"][0]["regions"].pop(10),
            "exclusive_endpoint": lambda v: v["head"]["owners"][0]["regions"][-1].__setitem__(3, 1),
            "negative_count": lambda v: v["head"]["owners"][0]["regions"][0].__setitem__(4, -1),
            "boolean_count": lambda v: v["head"]["owners"][0]["regions"][0].__setitem__(4, True),
            "expansion": lambda v: v["head"]["owners"][0]["regions"][0].__setitem__(7, 1),
            "invalid_column": lambda v: v["head"]["owners"][0]["regions"][0].__setitem__(3, 999),
            "where_clause": lambda v: v["head"]["source"].__setitem__(2, ") -> Value where Value: Copy {"),
            "function_pointer": lambda v: v["head"]["source"].__setitem__(1, "    value: fn(Input) -> Value,"),
            "unclosed_literal": lambda v: v["head"]["source"].__setitem__(4, '        call(r##"unclosed);'),
            "hidden_duplicate_name": lambda v: v["head"]["source"].extend(
                ["fn /* comment /* nested */ */ r#retained(other: Input) {}"]),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                self.multiline_copies_compare(mutate=mutate)

    def test_multiline_fragment_proof_compares_complete_instance_vectors(self):
        def profiles(value, redistributed):
            for side in ("base", "head"):
                for instance, owner in enumerate(value[side]["owners"][:2]):
                    for region in owner["regions"]:
                        text = value[side]["source"][region[0] - 1]
                        if "shared_" in text:
                            region[4] = int(instance == (0 if "shared_a" in text else 1))
                            if redistributed and side == "head":
                                region[4] = int(instance == 0)
        self.multiline_copies_compare(mutate=lambda v: profiles(v, False), fragments=True)
        with self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
            self.multiline_copies_compare(mutate=lambda v: profiles(v, True), fragments=True)

    def test_multiline_fragment_refuses_foreign_owners_on_unmapped_candidate_lines(self):
        old = b"fn retained(\n    x: Input,\n) -> Value {\n    shared();\n    second();\n    old();\n    shared();\n    second();\n}\n"
        new = old.replace(b"-> Value", b"-> Result<Value>").replace(b"    old();", b"    new();")
        def compare(foreign_side=None, foreign_line=5):
            def owners(base, head):
                for side, document in (("base", base), ("head", head)):
                    document["data"][0]["functions"] = [
                        {"name": f"{side}_{instance}", "filenames": ["/src/example.rs"],
                         "regions": [[1, 1, 9, 2, instance, 0, 0, 0]]} for instance in (0, 1)]
                    if side == foreign_side:
                        document["data"][0]["functions"].append({
                            "name": "foreign_partial", "filenames": ["/src/example.rs"],
                            "regions": [[foreign_line, 5, foreign_line, 14, 1, 0, 0, 0]]})
            return self.compare(before=[(4, 1), (7, 1)], after=[(4, 1), (7, 1)], mutate=owners,
                                sources=({"example.rs": old}, {"example.rs": new}))
        result = compare()
        witness = result["positive_source_fragments"][0]
        self.assertEqual(witness["pairs"], [[4, 4]])
        self.assertEqual(witness["candidates"], [{"base": [[4, 5], [7, 8]], "head": [[4, 5], [7, 8]]}])
        for side in ("base", "head"):
            for line in (5, 8):
                with self.subTest(side=side, line=line), self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                    compare(side, line)

    def test_multiline_fragment_proof_cannot_grant_gray_mappings(self):
        def new_zero(value):
            value["head"]["source"].extend(["fn missed() {", "    never();", "}"])
            value["head"]["counts"][18] = 0
        with self.assertRaisesRegex(ValueError, "New uncovered instrumented line: example.rs:18"):
            self.multiline_copies_compare(mutate=new_zero)
        with self.assertRaisesRegex(ValueError, "New uncovered instrumented line: example.rs:6"):
            self.multiline_copies_compare(mutate=lambda v: v["head"]["counts"].__setitem__(6, 0))
        with self.assertRaisesRegex(ValueError, "Retained covered line lost coverage"):
            self.multiline_copies_compare(mutate=lambda v: v["head"]["counts"].__setitem__(15, 0))

    def test_multiline_fragment_proof_requires_the_actual_body_boundary(self):
        def partial(value):
            for side, end in (("base", 10), ("head", 11)):
                for owner in value[side]["owners"][:2]:
                    owner["regions"] = owner["regions"][:end]
        with self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
            self.multiline_copies_compare(mutate=partial)

    def test_multiline_fragment_proof_requires_a_parseable_bounded_header(self):
        parameters = (
            "value: Input,,", "value: Input Input,", "value: Vec<Input,,>,", "value: Vec<Input],",
            "value: (Input, Input),", "value: fn(Input) -> Input,", "value: if,",
            "value:" + " " * 4096 + "Input,",
        )
        for parameter in parameters:
            def malformed(value):
                for side in ("base", "head"):
                    source = value[side]["source"]
                    source[1] = "    " + parameter
                    for owner in value[side]["owners"][:2]:
                        owner["regions"][1][3] = len(source[1].encode()) + 1
            with self.subTest(parameter=parameter[:80]), self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                self.multiline_copies_compare(mutate=malformed)

    def test_multiline_parser_accepts_type_syntax_without_resolving_types(self):
        for parameter in ("value: Vec<>,", "value: &'static Input,", "value: &[Input],",
                          "value: " + "Vec<" * 33 + "Input" + ">" * 33 + ","):
            def header(value):
                for side in ("base", "head"):
                    value[side]["source"][1] = "    " + parameter
                    for owner in value[side]["owners"][:2]:
                        owner["regions"][1][3] = len(value[side]["source"][1].encode()) + 1
            with self.subTest(parameter=parameter[:80]):
                self.multiline_copies_compare(mutate=header)

    def test_multiline_fragment_proof_requires_balanced_body_delimiters(self):
        for statement in ("call(;", "let x = [;", "call(];"):
            def malformed(value):
                for side in ("base", "head"):
                    source = value[side]["source"]
                    source[4] = "        " + statement
                    for owner in value[side]["owners"][:2]:
                        owner["regions"][4][3] = len(source[4].encode()) + 1
            with self.subTest(statement=statement), self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                self.multiline_copies_compare(mutate=malformed)

    def test_multiline_fragment_proof_requires_parseable_modifiers_and_body(self):
        cases = [(0, modifier + " fn retained(") for modifier in
                 ("pub(foo)", "pub(in garbage::)", "async async", "unsafe const pub pub")]
        cases.append((4, "        let x = ;"))
        for line, text in cases:
            def malformed(value):
                for side in ("base", "head"):
                    value[side]["source"][line] = text
                    for owner in value[side]["owners"][:2]:
                        owner["regions"][line][3] = len(text.encode()) + 1
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                self.multiline_copies_compare(mutate=malformed)

    def test_multiline_fragment_proof_blocks_module_tokens_before_running_a_parser(self):
        for statement in ("mod external;", '#[path = "/do-not-read.rs"] mod external;',
                          "consume!(mod external;);", "r#mod();"):
            def module(value):
                for side in ("base", "head"):
                    value[side]["source"][4] = "        " + statement
                    for owner in value[side]["owners"][:2]:
                        owner["regions"][4][3] = len(value[side]["source"][4].encode()) + 1
            with self.subTest(statement=statement), mock.patch.object(
                    coverage.subprocess, "run", side_effect=AssertionError("module reached parser")), \
                    self.assertRaisesRegex(ValueError, "Ambiguous unchanged source"):
                self.multiline_copies_compare(mutate=module)

    def test_source_comparison_without_fallback_needs_no_rustfmt(self):
        with mock.patch.object(coverage.subprocess, "run", side_effect=AssertionError("unexpected parser dependency")):
            self.compare()

    def test_multiline_parser_uses_exact_stdin_and_private_configuration(self):
        expected = []; parsed = []; temporary = []; real_run = subprocess.run
        def capture(value):
            for side in ("base", "head"):
                source = value[side]["source"]
                expected.append(("\n".join(source[:source.index("}") + 1]) + "\n").encode())
        def run(command, **kwargs):
            work = Path(kwargs["cwd"])
            self.assertEqual(list(work.iterdir()), [])
            self.assertNotEqual(work, Path.cwd())
            self.assertEqual(work.parent.stat().st_mode & 0o777, 0o700)
            temporary.append(work.parent)
            if command[0] == "rustup":
                self.assertEqual(command, ["rustup", "which", "--toolchain", "1.95.0", "rustfmt"])
            else:
                self.assertTrue(Path(command[0]).is_absolute())
                config = Path(command[-1])
                self.assertEqual(config.parent, work.parent)
                self.assertEqual(config.read_text(), 'edition = "2024"\n')
                self.assertEqual(command[1:], ["--edition", "2024", "--emit", "stdout", "--config-path", str(config)])
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["timeout"], 10)
                parsed.append(kwargs["input"])
            return real_run(command, **kwargs)
        with mock.patch.object(coverage.subprocess, "run", side_effect=run):
            self.multiline_copies_compare(mutate=capture)
        self.assertEqual(parsed, expected)
        self.assertTrue(all(not path.exists() for path in temporary))

    def test_multiline_parser_dependency_failures_are_explicit(self):
        failures = (
            (FileNotFoundError("rustup"), "requires installed rustfmt 1.95.0"),
            (subprocess.CalledProcessError(1, ["rustup"]), "requires installed rustfmt 1.95.0"),
            (subprocess.TimeoutExpired(["rustup"], 10), "lookup timed out"),
        )
        for error, message in failures:
            with self.subTest(error=type(error).__name__), mock.patch.object(
                    coverage.subprocess, "run", side_effect=error), self.assertRaisesRegex(ValueError, message):
                self.multiline_copies_compare()
        for path in ("rustfmt", "/nonexistent-omg-toolchain/rustfmt"):
            with self.subTest(path=path), mock.patch.object(coverage.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], 0, stdout=path)), \
                    self.assertRaisesRegex(ValueError, "requires an absolute installed rustfmt 1.95.0 binary"):
                self.multiline_copies_compare()

    def test_multiline_parser_timeout_cannot_authorize_a_fragment(self):
        real_run = subprocess.run
        def run(command, **kwargs):
            if command[0] == "rustup":
                return real_run(command, **kwargs)
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        with mock.patch.object(coverage.subprocess, "run", side_effect=run), \
                self.assertRaisesRegex(ValueError, "syntax check timed out"):
            self.multiline_copies_compare()

    def test_multiline_parser_refuses_oversized_input_before_tool_execution(self):
        def oversized(value):
            for side in ("base", "head"):
                value[side]["source"][4] = '        consume("' + 'x' * (64 * 1024) + '");'
                for owner in value[side]["owners"][:2]:
                    owner["regions"][4][3] = len(value[side]["source"][4].encode()) + 1
        with mock.patch.object(coverage.subprocess, "run", side_effect=AssertionError("oversized parser input")), \
                self.assertRaisesRegex(ValueError, "exceeds 64 KiB syntax parser bound"):
            self.multiline_copies_compare(mutate=oversized)

    def test_multiline_parser_ignores_module_words_in_literals_and_does_not_expand_macros(self):
        for statement in ('consume("mod external;", r#"mod external;"#); // mod external;',
                          'include!("/nonexistent-omg-coverage-include.rs");'):
            def body(value):
                for side in ("base", "head"):
                    value[side]["source"][4] = "        " + statement
                    for owner in value[side]["owners"][:2]:
                        owner["regions"][4][3] = len(value[side]["source"][4].encode()) + 1
            with self.subTest(statement=statement):
                self.multiline_copies_compare(mutate=body)

    def test_multiline_fragment_proof_recognizes_the_real_hashmap_parameter(self):
        def header(value):
            for side in ("base", "head"):
                source = value[side]["source"]
                source[1] = "    packages: &HashMap<String, LocalDbPackage>,"
                result = "std::collections::HashSet<String>"
                source[2] = ") -> " + (result if side == "base" else f"Result<{result}>") + " {"
                for owner in value[side]["owners"][:2]:
                    for line in (2, 3):
                        owner["regions"][line - 1][3] = len(source[line - 1].encode()) + 1
        result = self.multiline_copies_compare(mutate=header)
        self.assertEqual(result["positive_source_fragments"][0]["pairs"], [[6, 7], [10, 11]])

    def test_multiline_body_scan_ignores_supported_literals_and_comments(self):
        def literals(value):
            for side in ("base", "head"):
                value[side]["source"][4] = ('        ' + side +
                    '_call("} {", \'{\', /* { /* nested } */ } */ value); // }')
        self.multiline_copies_compare(mutate=literals)
        def raw(value):
            for side in ("base", "head"):
                value[side]["source"][4] = '        ' + side + '_call(r###"} { fn retained(fake) {"###);'
        self.multiline_copies_compare(mutate=raw)

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

    def endpoint_paint_fixture(self):
        old = ["fn example(items: Items) -> Old {", "    for item in items {",
               "        value.push(item);", "    }", "}"]
        new = ["fn example(items: Items) -> New {", "    for item in items {",
               "        values", "            .push((item, value));", "    }", "}"]
        def owner(name, regions):
            return {"name": name, "filenames": ["/src/example.rs"], "regions": regions}
        base, head = [], []
        for i, count in enumerate((0, 5)):
            base.append(owner(f"base{i}", [[1, 1, 1, len(old[0]) + 1, 1, 0, 0, 0],
                [2, 23, 4, 6, count, 0, 0, 0], [5, 1, 5, 2, 1, 0, 0, 0]]))
            head.append(owner(f"head{i}", [[1, 1, 1, len(new[0]) + 1, 1, 0, 0, 0],
                [4, 14, 4, 18, count, 0, 0, 0], [4, 19, 4, 32, count, 0, 0, 0],
                [6, 1, 6, 2, 1, 0, 0, 0]]))
        return dict(name="example.rs", old=old, new=new, before={4: 5}, after={},
                    base=base, head=head, base_files={"/src/example.rs": "example.rs"},
                    head_files={"/src/example.rs": "example.rs"}, retained={4: 5})

    def test_endpoint_paint_integration_accepts_for_brace(self):
        value = self.endpoint_paint_fixture()
        def owners(base, head):
            base["data"][0]["functions"] = value["base"]
            head["data"][0]["functions"] = value["head"]
        sources = tuple({"example.rs": ("\n".join(value[side]) + "\n").encode()}
                        for side in ("old", "new"))
        result = self.compare(before=[(1, 1), (2, 1), (3, 5), (4, 5), (5, 1)],
                              after=[(1, 1), (2, 1), (3, 5), (4, 5), (6, 1)],
                              mutate=owners, sources=sources)
        self.assertEqual(result["retained_block_endpoint_paint"][0]["pairs"], [[4, 5]])

    def test_endpoint_paint_accepts_unmapped_retained_for_brace(self):
        witnesses = coverage.retained_block_endpoint_paint(**self.endpoint_paint_fixture())
        self.assertEqual([pair for witness in witnesses for pair in witness["pairs"]], [[4, 5]])

    def test_endpoint_paint_refuses_incomplete_or_conflicting_evidence(self):
        def foreign(value, side, region):
            value[side].append({"name": "foreign", "filenames": ["/src/example.rs"], "regions": [region]})
        cases = {
            "explicit_zero": lambda v: v["after"].update({5: 0}),
            "missing_copy": lambda v: v["head"].pop(),
            "duplicate_name": lambda v: v["head"][1].__setitem__("name", "head0"),
            "brace_touch": lambda v: v["head"][0]["regions"].append([5, 5, 5, 6, 1, 0, 0, 0]),
            "foreign_brace": lambda v: foreign(v, "base", [4, 5, 4, 6, 1, 0, 0, 0]),
            "foreign_witness": lambda v: foreign(v, "head", [4, 14, 4, 18, 1, 0, 0, 0]),
            "zero_terminal": lambda v: v["head"][1]["regions"][1].__setitem__(4, 0),
            "zero_argument": lambda v: v["head"][1]["regions"][2].__setitem__(4, 0),
            "state_change": lambda v: [r.__setitem__(4, 0) for r in v["head"][1]["regions"][1:3]],
            "changed_header": lambda v: v["new"].__setitem__(1, "    for item in other {"),
            "endpoint_start": lambda v: [o["regions"][1].__setitem__(1, 22) for o in v["base"]],
            "endpoint_end": lambda v: [o["regions"][1].__setitem__(3, 5) for o in v["base"]],
            "tail_return": lambda v: v["new"].__setitem__(2, "        return values"),
            "tail_macro": lambda v: v["new"].__setitem__(2, "        values!"),
            "tail_closure": lambda v: v["new"].__setitem__(2, "        |x| values"),
            "nested_call": lambda v: v["new"].__setitem__(3, "            .push(foo(item));"),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                value = self.endpoint_paint_fixture()
                mutate(value)
                self.assertEqual(coverage.retained_block_endpoint_paint(**value), [])

    def test_endpoint_paint_rejects_repeated_matching_loop_header(self):
        value = self.endpoint_paint_fixture()
        value["new"][5:5] = [value["new"][1], "    }"]
        for owner in value["head"]:
            owner["regions"][-1][0] = owner["regions"][-1][2] = 8
        self.assertEqual(coverage.retained_block_endpoint_paint(**value), [])

    def test_endpoint_paint_refuses_iterator_expression_block(self):
        value = self.endpoint_paint_fixture()
        for side, owners in (("old", "base"), ("new", "head")):
            value[side][1] = "    for item in {"
            value[side][-1:-1] = ["    {", "        break;", "    }"]
            for owner in value[owners]:
                owner["regions"][-1][0] = owner["regions"][-1][2] = len(value[side])
        for owner in value["base"]:
            owner["regions"][1][1] = len(value["old"][1])
        self.assertEqual(coverage.retained_block_endpoint_paint(**value), [])

    def test_endpoint_paint_refuses_argument_calls_with_exact_geometry(self):
        for argument in ("foo(item)", "(foo)(item)", "(foo.0)(item)",
                         "((foo))(item)", "foo.0(item)"):
            with self.subTest(argument=argument):
                value = self.endpoint_paint_fixture()
                row = value["new"][3] = f"            .push({argument});"
                match = re.fullmatch(r"\s*\.push\((.+)\);", row)
                for owner in value["head"]:
                    owner["regions"][2][1] = match.start(1) + 1
                    owner["regions"][2][3] = match.end(1) + 1
                self.assertEqual(coverage.retained_block_endpoint_paint(**value), [])

    def test_endpoint_argument_shape_accepts_only_data_expressions(self):
        for expression in ("item", "item.field", "&item", "&&item", "(item, &value.field)",
                           "(item, (first, second))", "first, second", " (item, &value.field) "):
            with self.subTest(expression=expression):
                self.assertTrue(coverage._data_argument_shape(expression))
        for expression in ("foo(item)", "(foo)(item)", "foo.0(item)", "(foo.0)(item)",
                           "((foo))(item)", "first & second", "value as Kind", "0", "[item]",
                           "item + other", "" , "&" * 4097 + "item"):
            with self.subTest(expression=expression):
                self.assertFalse(coverage._data_argument_shape(expression))

    def test_endpoint_paint_does_not_hide_other_coverage_losses(self):
        value = self.endpoint_paint_fixture()
        def owners(base, head):
            base["data"][0]["functions"] = value["base"]
            head["data"][0]["functions"] = value["head"]
        sources = tuple({"example.rs": ("\n".join(value[side]) + "\n").encode()}
                        for side in ("old", "new"))
        before = [(1, 1), (2, 1), (3, 5), (4, 5), (5, 1)]
        for after in ([(1, 1), (2, 1), (3, 5), (4, 5), (5, 0), (6, 1)],
                      [(1, 1), (2, 1), (3, 0), (4, 5), (6, 1)],
                      [(1, 1), (2, 0), (3, 5), (4, 5), (6, 1)]):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.compare(before=before, after=after, mutate=owners, sources=sources)

    def test_endpoint_paint_does_not_mistake_comment_semicolon_for_statement_end(self):
        value = self.endpoint_paint_fixture()
        value["new"].insert(2, "        return //;")
        for owner in value["head"]:
            for region in owner["regions"][1:]:
                region[0] += 1
                region[2] += 1
        value["retained"] = {4: 6}
        self.assertEqual(coverage.retained_block_endpoint_paint(**value), [])

    def test_endpoint_paint_requires_valid_full_function_syntax(self):
        value = self.endpoint_paint_fixture()
        value["new"].insert(5, "    let = ;")
        for owner in value["head"]:
            owner["regions"][-1][0] = owner["regions"][-1][2] = 7
        with self.assertRaisesRegex(ValueError, "rustfmt.*did not validate"):
            coverage.retained_block_endpoint_paint(**value)

    def wrapper_paint_compare(self, mutate=None, addition=False):
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

        sources = ({"example.rs": ("\n".join(old) + "\n").encode()},
                   {"example.rs": ("\n".join(new) + "\n").encode()})
        if addition:
            def with_addition(br, hr, old_sources, new_sources, lcov):
                extra = hr["data"][0]["functions"][-1]
                owners(br, hr)
                hr["data"][0]["functions"].append(extra)
                return br, hr, old_sources, new_sources, lcov
            return self.compare_additions(before=sorted(before.items()), after=sorted(after.items()),
                                          old=sources[0], new=sources[1], mutate=with_addition)
        return self.compare(before=sorted(before.items()), after=sorted(after.items()), mutate=owners, sources=sources)

    def test_identical_precise_regions_resolve_only_retained_async_wrapper_paint(self):
        self.assertEqual(self.wrapper_paint_compare(), {
            "deleted_summary_found": 0, "deleted_summary_hit": 0,
            "deleted_mapped": 0, "deleted_mapped_hit": 0,
            "retained_wrapper_paint": [{"file": "example.rs", "base_range": [5, 9], "head_range": [6, 10],
                                        "precise_counter_equivalence": "covered/uncovered",
                                        "precise_group_sizes": [4], "pairs": [[6, 7], [8, 9]]}]})

    def test_wrapper_proof_and_failure_with_added_file(self):
        expected = self.wrapper_paint_compare()
        expected["added_files"] = [{"file": "new.rs", "summary_found": 1, "summary_hit": 1,
                                    "mapped": 1, "mapped_hit": 1}]
        self.assertEqual(self.wrapper_paint_compare(addition=True), expected)
        def lose_precise(value):
            value["head"][1]["regions"][1][4] = 0
        with self.assertRaises(ValueError):
            self.wrapper_paint_compare(mutate=lose_precise, addition=True)

    def serial_wrapper_compare(self, mutate=None):
        old = ['#[tokio::test]', 'async fn checked() {', '    let callback = || {',
               '        7', '    };', '    assert_eq!(callback(), 7);', '}', '',
               'fn untouched() { unseen(); }']
        new = [old[0], '#[serial_test::serial]', *old[1:]]
        def row(line, start=1, end=None):
            return [line, start, line, end or len(old[line - 1]) + 1, 1, 0, 0, 0]
        brace = old[1].index('{') + 1
        body = [row(2, brace), row(3, 5), row(6, 5)]
        closure = [row(3, old[2].index('{') + 1), row(4, 9), row(5, 5)]
        coarse = [row(2, old[1].index('fn ') + 1, len(old[1][:-1].rstrip()) + 1), row(6, 5), row(7)]
        def shifted(regions):
            return [[r[0] + 1, r[1], r[2] + 1, *r[3:]] for r in regions]
        def owner(name, regions):
            return dict(name=name, filenames=['/src/example.rs'], count=1, regions=regions)
        value = dict(old=old, new=new, before={**{n: 1 for n in range(2, 8)}, 9: 0},
            after={**{n: 1 for n in range(3, 8)}, 10: 0}, base=[owner('outer', coarse),
                owner('body', body), owner('closure', closure)], head=[
                owner('renamed_outer', shifted([row(2, brace), row(6, 5)])),
                owner('renamed_body', shifted(body)), owner('renamed_closure', shifted(closure))],
            base_summary=[10, 9], head_summary=[7, 6])
        if mutate:
            mutate(value)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); reports = []; regions = []
            for side, counts in [('base', 'before'), ('head', 'after')]:
                found, hit = value[side + '_summary']
                path = root / (side + '.info')
                path.write_text('SF:/src/example.rs\n' + ''.join(
                    f'DA:{line},{count}\n' for line, count in sorted(value[counts].items())) +
                    f'LF:{found}\nLH:{hit}\nend_of_record\n')
                document = dict(type='llvm.coverage.json.export', version='3.1.0', data=[dict(
                    files=[dict(filename='/src/example.rs', summary=dict(lines=dict(count=found, covered=hit)))],
                    functions=value[side])])
                region_path = root / (side + '.json.gz')
                region_path.write_bytes(gzip.compress(json.dumps(document).encode()))
                reports.append(coverage.read_coverage(path)); regions.append(region_path)
            return coverage.require_source_no_regression(*reports, *regions,
                {'example.rs': ('\n'.join(value['old']) + '\n').encode()},
                {'example.rs': ('\n'.join(value['new']) + '\n').encode()})

    def test_serial_attribute_accounts_only_the_elided_wrapper_group_and_brace(self):
        result = self.serial_wrapper_compare()
        self.assertEqual([result[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                         'deleted_mapped', 'deleted_mapped_hit')], [3, 3, 1, 1])
        witness = result['serial_wrapper_elision'][0]
        self.assertEqual(witness['mapped_pairs'], [[7, 8]])
        self.assertEqual(witness['summary_credit'], [3, 3])

    def test_serial_wrapper_witness_refuses_unexplained_evidence(self):
        def duplicate(value):
            extra = copy.deepcopy(value['head'][2]); extra['name'] = 'duplicate'
            value['head'].append(extra)
        cases = {
            'body_hit_lost': lambda v: v['head'][1]['regions'][-1].__setitem__(4, 0),
            'statement_mapping_lost': lambda v: v['head'][1]['regions'].pop(),
            'new_zero': lambda v: v['after'].__setitem__(2, 0),
            'missing_owner': lambda v: v['head'].pop(),
            'duplicate_owner': duplicate,
            'different_attribute': lambda v: v['new'].__setitem__(1, '#[serial_test::serial(other)]'),
            'summary_drift': lambda v: v['head_summary'].__setitem__(0, 8),
            'head_brace_explicit_zero': lambda v: v['after'].__setitem__(8, 0),
            'zero_new_wrapper': lambda v: v['head'][0]['regions'][0].__setitem__(4, 0),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.serial_wrapper_compare(mutate)

    def test_async_wrapper_paint_accepts_positive_counter_frequency_changes(self):
        expected = self.wrapper_paint_compare()

        def old_positive_count_control(value):
            value["head"][1]["regions"][1][4] = value["after"][6] = 4

        def three_async_poll_counters(value):
            for base_index, head_index, oldline, newline in [(2, 1, 5, 6), (4, 3, 7, 8), (5, 4, 9, 10)]:
                value["base"][1]["regions"][base_index][4] = value["before"][oldline] = 3
                value["head"][1]["regions"][head_index][4] = value["after"][newline] = 2

        for mutate in [old_positive_count_control, three_async_poll_counters]:
            with self.subTest(mutation=mutate.__name__):
                self.assertEqual(self.wrapper_paint_compare(mutate=mutate), expected)

    def test_async_wrapper_paint_cannot_hide_precise_evidence_drift(self):
        def fingerprint_collision(value):
            for key, first, lines in [("base", 2, (5, 7, 9)), ("head", 1, (6, 8, 10))]:
                extra = copy.deepcopy(value[key][1]); extra["name"] = "distinct_" + key
                extra["regions"] = extra["regions"][first:]
                for region in extra["regions"]:
                    if region[4] > 0:
                        region[4] = 17
                value[key].append(extra)
                for line in lines:
                    value["before" if key == "base" else "after"][line] = 17

        def zero_to_positive(value):
            value["head"][1]["regions"][2][4] = value["after"][7] = 1

        mutations = {
            "genuine_hit_loss": lambda v: v["base"][1]["regions"][3].__setitem__(4, 1),
            "zero_to_positive": zero_to_positive,
            "fingerprint_collision": fingerprint_collision,
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


class BooleanArgumentPaintTests(unittest.TestCase):
    # Exact complete source items and LLVM rows from the frozen f2413f80/b22afa9b
    # pair, translated together into a compact module retaining its cfg and glob.
    base_source = '#[cfg(test)]\nmod tests {\n    use super::*;\n\n    fn transaction(\n        transaction_type: crate::core::history::TransactionType,\n        source: &str,\n        old_version: Option<&str>,\n        success: bool,\n    ) -> crate::core::history::Transaction {\n        crate::core::history::Transaction {\n            id: "test".to_string(),\n            timestamp: jiff::Timestamp::now(),\n            transaction_type,\n            changes: vec![crate::core::history::PackageChange {\n                name: "example".to_string(),\n                old_version: old_version.map(str::to_string),\n                new_version: Some("2.0-1".to_string()),\n                source: source.to_string(),\n            }],\n            success,\n        }\n    }\n\n    #[test]\n    fn rollback_plan_reverses_installs_and_restores_official_updates() -> Result<()> {\n        assert_eq!(\n            rollback_action(&transaction(\n                crate::core::history::TransactionType::Install,\n                "aur",\n                None,\n                true,\n            ))?,\n            RollbackAction::Remove(vec!["example".to_string()])\n        );\n        assert_eq!(\n            rollback_action(&transaction(\n                crate::core::history::TransactionType::Update,\n                "core",\n                Some("1.0-1"),\n                true,\n            ))?,\n            RollbackAction::Restore {\n                official: vec![("example".to_string(), "1.0-1".to_string())],\n                rebuild_from_aur: vec![],\n            }\n        );\n        Ok(())\n    }\n}\n'
    base_owners = [{'branches': [],
      'count': 6,
      'filenames': ['/src/example.rs'],
      'mcdc_records': [],
      'name': '_RNvNtNtNtCs40j12eeWnis_7omg_lib3cli8commands5tests11transaction',
      'regions': [[5, 5, 10, 43, 6, 0, 0, 0],
                  [11, 9, 22, 10, 6, 0, 0, 0],
                  [12, 17, 12, 23, 6, 0, 0, 0],
                  [12, 24, 12, 33, 6, 0, 0, 0],
                  [13, 24, 13, 44, 6, 0, 0, 0],
                  [14, 13, 14, 29, 6, 0, 0, 0],
                  [15, 22, 15, 26, 6, 0, 0, 0],
                  [16, 23, 16, 32, 6, 0, 0, 0],
                  [16, 33, 16, 42, 6, 0, 0, 0],
                  [17, 30, 17, 41, 6, 0, 0, 0],
                  [17, 42, 17, 45, 6, 0, 0, 0],
                  [18, 30, 18, 55, 6, 0, 0, 0],
                  [23, 5, 23, 6, 6, 0, 0, 0]]},
     {'branches': [],
      'count': 1,
      'filenames': ['/src/example.rs'],
      'mcdc_records': [],
      'name': '_RNvNtNtNtCs40j12eeWnis_7omg_lib3cli8commands5testss_61rollback_plan_reverses_installs_and_restores_official_updates',
      'regions': [[26, 5, 26, 85, 1, 0, 0, 0],
                  [27, 9, 27, 19, 1, 0, 0, 0],
                  [28, 13, 28, 28, 1, 0, 0, 0],
                  [28, 29, 33, 14, 1, 0, 0, 0],
                  [28, 30, 28, 41, 1, 0, 0, 0],
                  [29, 17, 29, 63, 1, 0, 0, 0],
                  [33, 15, 33, 16, 0, 0, 0, 0],
                  [34, 13, 34, 64, 1, 0, 0, 0],
                  [34, 36, 34, 40, 1, 0, 0, 0],
                  [36, 9, 36, 19, 1, 0, 0, 0],
                  [37, 13, 37, 28, 1, 0, 0, 0],
                  [37, 29, 42, 14, 1, 0, 0, 0],
                  [37, 30, 37, 41, 1, 0, 0, 0],
                  [38, 17, 38, 62, 1, 0, 0, 0],
                  [42, 15, 42, 16, 0, 0, 0, 0],
                  [43, 13, 46, 14, 1, 0, 0, 0],
                  [44, 27, 44, 31, 1, 0, 0, 0],
                  [44, 33, 44, 42, 1, 0, 0, 0],
                  [44, 43, 44, 52, 1, 0, 0, 0],
                  [48, 9, 48, 15, 1, 0, 0, 0],
                  [49, 5, 49, 6, 1, 0, 0, 0]]}]
    base_segments = [[5, 5, 6, True, True, False],
     [10, 43, 0, False, False, False],
     [11, 9, 6, True, True, False],
     [12, 17, 6, True, True, False],
     [12, 23, 6, True, False, False],
     [12, 24, 6, True, True, False],
     [12, 33, 6, True, False, False],
     [13, 24, 6, True, True, False],
     [13, 44, 6, True, False, False],
     [14, 13, 6, True, True, False],
     [14, 29, 6, True, False, False],
     [15, 22, 6, True, True, False],
     [15, 26, 6, True, False, False],
     [16, 23, 6, True, True, False],
     [16, 32, 6, True, False, False],
     [16, 33, 6, True, True, False],
     [16, 42, 6, True, False, False],
     [17, 30, 6, True, True, False],
     [17, 41, 6, True, False, False],
     [17, 42, 6, True, True, False],
     [17, 45, 6, True, False, False],
     [18, 30, 6, True, True, False],
     [18, 55, 6, True, False, False],
     [22, 10, 0, False, False, False],
     [23, 5, 6, True, True, False],
     [23, 6, 0, False, False, False],
     [26, 5, 1, True, True, False],
     [26, 85, 0, False, False, False],
     [27, 9, 1, True, True, False],
     [27, 19, 0, False, False, False],
     [28, 13, 1, True, True, False],
     [28, 28, 0, False, False, False],
     [28, 29, 1, True, True, False],
     [28, 30, 1, True, True, False],
     [28, 41, 1, True, False, False],
     [29, 17, 1, True, True, False],
     [29, 63, 1, True, False, False],
     [33, 14, 0, False, False, False],
     [33, 15, 0, True, True, False],
     [33, 16, 0, False, False, False],
     [34, 13, 1, True, True, False],
     [34, 36, 1, True, True, False],
     [34, 40, 1, True, False, False],
     [34, 64, 0, False, False, False],
     [36, 9, 1, True, True, False],
     [36, 19, 0, False, False, False],
     [37, 13, 1, True, True, False],
     [37, 28, 0, False, False, False],
     [37, 29, 1, True, True, False],
     [37, 30, 1, True, True, False],
     [37, 41, 1, True, False, False],
     [38, 17, 1, True, True, False],
     [38, 62, 1, True, False, False],
     [42, 14, 0, False, False, False],
     [42, 15, 0, True, True, False],
     [42, 16, 0, False, False, False],
     [43, 13, 1, True, True, False],
     [44, 27, 1, True, True, False],
     [44, 31, 1, True, False, False],
     [44, 33, 1, True, True, False],
     [44, 42, 1, True, False, False],
     [44, 43, 1, True, True, False],
     [44, 52, 1, True, False, False],
     [46, 14, 0, False, False, False],
     [48, 9, 1, True, True, False],
     [48, 15, 0, False, False, False],
     [49, 5, 1, True, True, False],
     [49, 6, 0, False, False, False]]
    head_source = '#[cfg(test)]\nmod tests {\n    use super::*;\n\n    fn transaction(\n        transaction_type: crate::core::history::TransactionType,\n        source: &str,\n        old_version: Option<&str>,\n        success: bool,\n    ) -> crate::core::history::Transaction {\n        crate::core::history::Transaction {\n            id: "test".to_string(),\n            timestamp: jiff::Timestamp::now(),\n            transaction_type,\n            changes: vec![crate::core::history::PackageChange {\n                name: "example".to_string(),\n                old_version: old_version.map(str::to_string),\n                new_version: Some("2.0-1".to_string()),\n                source: source.to_string(),\n            }],\n            success,\n        }\n    }\n\n    #[test]\n    fn install_rollback_refuses_unproven_package_removal() {\n        for source in ["pacman", "local", "aur"] {\n            let mut recorded = transaction(\n                crate::core::history::TransactionType::Install,\n                source,\n                None,\n                true,\n            );\n            for version in [None, Some("1-1".to_owned())] {\n                recorded.changes[0].new_version = version;\n                let error = rollback_action(&recorded)\n                    .expect_err("install history does not prove this package was newly installed");\n                assert!(error.to_string().contains("newly installed"), "{error:#}");\n            }\n        }\n    }\n}\n'
    head_owners = [{'branches': [],
      'count': 8,
      'filenames': ['/src/example.rs'],
      'mcdc_records': [],
      'name': '_RNvNtNtNtCskPrOzUXTdLt_7omg_lib3cli8commands5tests11transaction',
      'regions': [[5, 5, 10, 43, 8, 0, 0, 0],
                  [11, 9, 22, 10, 8, 0, 0, 0],
                  [12, 17, 12, 23, 8, 0, 0, 0],
                  [12, 24, 12, 33, 8, 0, 0, 0],
                  [13, 24, 13, 44, 8, 0, 0, 0],
                  [14, 13, 14, 29, 8, 0, 0, 0],
                  [15, 22, 15, 26, 8, 0, 0, 0],
                  [16, 23, 16, 32, 8, 0, 0, 0],
                  [16, 33, 16, 42, 8, 0, 0, 0],
                  [17, 30, 17, 41, 8, 0, 0, 0],
                  [17, 42, 17, 45, 8, 0, 0, 0],
                  [18, 30, 18, 55, 8, 0, 0, 0],
                  [23, 5, 23, 6, 8, 0, 0, 0]]},
     {'branches': [],
      'count': 1,
      'filenames': ['/src/example.rs'],
      'mcdc_records': [],
      'name': '_RNvNtNtNtCskPrOzUXTdLt_7omg_lib3cli8commands5testss_49install_rollback_refuses_unproven_package_removal',
      'regions': [[26, 5, 26, 59, 1, 0, 0, 0],
                  [27, 13, 27, 19, 3, 0, 0, 0],
                  [27, 23, 27, 49, 1, 0, 0, 0],
                  [28, 17, 28, 29, 3, 0, 0, 0],
                  [28, 32, 28, 43, 3, 0, 0, 0],
                  [29, 17, 29, 63, 3, 0, 0, 0],
                  [30, 17, 30, 23, 3, 0, 0, 0],
                  [31, 17, 31, 21, 3, 0, 0, 0],
                  [34, 17, 34, 24, 6, 0, 0, 0],
                  [34, 28, 34, 58, 3, 0, 0, 0],
                  [34, 29, 34, 33, 3, 0, 0, 0],
                  [35, 17, 35, 48, 6, 0, 0, 0],
                  [35, 51, 35, 58, 6, 0, 0, 0],
                  [36, 21, 36, 26, 6, 0, 0, 0],
                  [36, 29, 36, 44, 6, 0, 0, 0],
                  [36, 45, 36, 54, 6, 0, 0, 0],
                  [37, 22, 37, 32, 6, 0, 0, 0],
                  [37, 33, 37, 98, 6, 0, 0, 0],
                  [38, 17, 38, 24, 6, 0, 0, 0],
                  [38, 25, 38, 70, 6, 0, 0, 0],
                  [41, 5, 41, 6, 1, 0, 0, 0]]}]
    head_segments = [[5, 5, 8, True, True, False],
     [10, 43, 0, False, False, False],
     [11, 9, 8, True, True, False],
     [12, 17, 8, True, True, False],
     [12, 23, 8, True, False, False],
     [12, 24, 8, True, True, False],
     [12, 33, 8, True, False, False],
     [13, 24, 8, True, True, False],
     [13, 44, 8, True, False, False],
     [14, 13, 8, True, True, False],
     [14, 29, 8, True, False, False],
     [15, 22, 8, True, True, False],
     [15, 26, 8, True, False, False],
     [16, 23, 8, True, True, False],
     [16, 32, 8, True, False, False],
     [16, 33, 8, True, True, False],
     [16, 42, 8, True, False, False],
     [17, 30, 8, True, True, False],
     [17, 41, 8, True, False, False],
     [17, 42, 8, True, True, False],
     [17, 45, 8, True, False, False],
     [18, 30, 8, True, True, False],
     [18, 55, 8, True, False, False],
     [22, 10, 0, False, False, False],
     [23, 5, 8, True, True, False],
     [23, 6, 0, False, False, False],
     [26, 5, 1, True, True, False],
     [26, 59, 0, False, False, False],
     [27, 13, 3, True, True, False],
     [27, 19, 0, False, False, False],
     [27, 23, 1, True, True, False],
     [27, 49, 0, False, False, False],
     [28, 17, 3, True, True, False],
     [28, 29, 0, False, False, False],
     [28, 32, 3, True, True, False],
     [28, 43, 0, False, False, False],
     [29, 17, 3, True, True, False],
     [29, 63, 0, False, False, False],
     [30, 17, 3, True, True, False],
     [30, 23, 0, False, False, False],
     [31, 17, 3, True, True, False],
     [31, 21, 0, False, False, False],
     [34, 17, 6, True, True, False],
     [34, 24, 0, False, False, False],
     [34, 28, 3, True, True, False],
     [34, 29, 3, True, True, False],
     [34, 33, 3, True, False, False],
     [34, 58, 0, False, False, False],
     [35, 17, 6, True, True, False],
     [35, 48, 0, False, False, False],
     [35, 51, 6, True, True, False],
     [35, 58, 0, False, False, False],
     [36, 21, 6, True, True, False],
     [36, 26, 0, False, False, False],
     [36, 29, 6, True, True, False],
     [36, 44, 0, False, False, False],
     [36, 45, 6, True, True, False],
     [36, 54, 0, False, False, False],
     [37, 22, 6, True, True, False],
     [37, 32, 0, False, False, False],
     [37, 33, 6, True, True, False],
     [37, 98, 0, False, False, False],
     [38, 17, 6, True, True, False],
     [38, 24, 0, False, False, False],
     [38, 25, 6, True, True, False],
     [38, 70, 0, False, False, False],
     [41, 5, 1, True, True, False],
     [41, 6, 0, False, False, False]]

    def fixture(self):
        return dict(name='example.rs', old=self.base_source.splitlines(),
                    new=self.head_source.splitlines(), before={32: 1}, after={},
                    base=copy.deepcopy(self.base_owners), head=copy.deepcopy(self.head_owners),
                    base_files={'/src/example.rs': 'example.rs'},
                    head_files={'/src/example.rs': 'example.rs'}, retained={32: 32},
                    base_segments=copy.deepcopy(self.base_segments),
                    head_segments=copy.deepcopy(self.head_segments))

    def proof(self, value=None):
        return coverage.retained_boolean_argument_paint(**(value or self.fixture()))

    def compare(self, mutate=None):
        value = self.fixture()
        value['old'] = value['new'].copy()
        value['base'] = copy.deepcopy(value['head'])
        value['base_segments'] = copy.deepcopy(value['head_segments'])
        value['base'][-1]['regions'].append([32, 17, 32, 21, 3, 0, 0, 0])
        value['base_segments'].extend([[32, 17, 3, True, True, False],
                                      [32, 21, 0, False, False, False]])
        value['base_segments'].sort()
        value['before'] = {row[0]: row[4] for owner in value['base'] for row in owner['regions']}
        value['after'] = {row[0]: row[4] for owner in value['head'] for row in owner['regions']}
        if mutate:
            mutate(value)
        with tempfile.TemporaryDirectory() as directory:
            paths = []
            reports = []
            for side, rows, segments, owners in (
                    ('base', value['before'], value['base_segments'], value['base']),
                    ('head', value['after'], value['head_segments'], value['head'])):
                found, hit = value.get(side + '_summary', (len(rows), sum(count > 0 for count in rows.values())))
                path = Path(directory) / (side + '.info')
                path.write_text('SF:/src/example.rs\n' + ''.join(
                    f'DA:{line},{count}\n' for line, count in sorted(rows.items())) +
                    f'LF:{found}\nLH:{hit}\nend_of_record\n')
                reports.append(coverage.read_coverage(path))
                data = {'type': 'llvm.coverage.json.export', 'version': '3.1.0', 'data': [{
                    'files': [{'filename': '/src/example.rs', 'segments': segments, 'expansions': [],
                               'summary': {'lines': {'count': found, 'covered': hit}}}],
                    'functions': owners}]}
                region_path = Path(directory) / (side + '.gz')
                region_path.write_bytes(gzip.compress(json.dumps(data).encode()))
                paths.append(region_path)
            return coverage.require_source_no_regression(
                *reports, *paths, {'example.rs': value.get('old_raw', '\n'.join(value['old']).encode())},
                {'example.rs': value.get('new_raw', '\n'.join(value['new']).encode())})

    def test_boolean_paint_integration_proves_only_existing_pair_without_credit(self):
        try:
            receipt = self.compare()
        except ValueError as error:
            self.fail(f'proven eager boolean remains refused: {error}')
        self.assertEqual(receipt['retained_boolean_argument_paint'][0]['pairs'], [[32, 32]])
        for key in ('deleted_summary_found', 'deleted_summary_hit', 'deleted_mapped', 'deleted_mapped_hit'):
            self.assertEqual(receipt[key], 0)

    def test_boolean_actual_source_owner_fixture_records_both_base_occurrences(self):
        receipts = self.proof()
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt['pairs'], [[32, 32]])
        self.assertEqual((receipt['argument_ordinal'], receipt['arity']), (4, 4))
        self.assertEqual([entry['eligible'] for entry in receipt['base_occurrences']], [True, False])
        self.assertIn('non-leaf', receipt['base_occurrences'][1]['reason'])
        self.assertEqual(receipt['module_path'], ['tests'])
        self.assertEqual(receipt['test_gates'], ['tests'])
        self.assertEqual(receipt['head_call_region'], [28, 32, 28, 43, 3, 0, 0, 0])
        self.assertEqual(receipt['head_continuation_region'], [34, 28, 34, 58, 3, 0, 0, 0])
        self.assertFalse(any('credit' in key or 'deleted' in key for key in receipt))

    def test_boolean_explicit_zero_or_any_head_line_mapping_is_refused(self):
        for mode in ('da', 'positive_region', 'zero_region', 'positive_segment', 'zero_segment', 'gap_segment'):
            value = self.fixture()
            if mode == 'da':
                value['after'][32] = 0
            elif mode.endswith('region'):
                value['head'][-1]['regions'].append([32, 17, 32, 21, int(mode == 'positive_region'), 0, 0, 0])
            else:
                value['head_segments'].extend([[32, 17, int(mode == 'positive_segment'), True, True,
                                                mode == 'gap_segment'], [32, 21, 0, False, False, False]])
                value['head_segments'].sort()
            with self.subTest(mode=mode):
                self.assertEqual(self.proof(value), [])

    def test_boolean_exact_witnesses_are_required_and_counts_must_agree(self):
        for line in (28, 34):
            for mode in ('missing', 'zero', 'unequal', 'short_endpoint', 'foreign'):
                value = self.fixture()
                rows = value['head'][-1]['regions']
                row = next(row for row in rows if row[:4] == ([28, 32, 28, 43] if line == 28 else [34, 28, 34, 58]))
                if mode == 'missing':
                    rows.remove(row)
                elif mode == 'zero':
                    row[4] = 0
                elif mode == 'unequal':
                    row[4] += 1
                elif mode == 'short_endpoint':
                    row[3] -= 1
                else:
                    value['head'].append(dict(name='foreign', filenames=['/src/example.rs'], regions=[row.copy()]))
                with self.subTest(line=line, mode=mode):
                    self.assertEqual(self.proof(value), [])

    def test_boolean_complete_singleton_inventory_includes_unhit_owners(self):
        for side in ('base', 'head'):
            for index in (0, 1):
                for duplicate_name in (True, False):
                    value = self.fixture()
                    extra = copy.deepcopy(value[side][index])
                    if not duplicate_name:
                        extra['name'] += '_other_copy'
                    extra['count'] = 0
                    for row in extra['regions']:
                        row[4] = 0
                    value[side].append(extra)
                    with self.subTest(side=side, index=index, duplicate_name=duplicate_name):
                        self.assertEqual(self.proof(value), [])

    def test_boolean_unsafe_arguments_and_lazy_or_bypass_shapes_are_refused(self):
        for original, replacement in (
                ('let mut recorded = transaction(', 'let mut recorded = || transaction('),
                ('let mut recorded = transaction(', 'let mut recorded = async { transaction('),
                ('let mut recorded = transaction(', 'let mut recorded = object.transaction('),
                ('let mut recorded = transaction(', 'let mut recorded = transaction!('),
                ('let mut recorded = transaction(', 'if false { let mut recorded = transaction('),
                ('                source,', '                source(),'),
                ('                source,', '                source[0],'),
                ('                source,', '                source.field,'),
                ('                source,', '                source?, '),
                ('                true,', '                true && false,'),
                ('                true,', '                false,'),
                ('                true,', '                true, other(),'),
                ('            for version in', '            if false {} for version in'),
                ('            for version in', '        } for version in'),
                ('            for version in', '            let lazy = || for version in')):
            value = self.fixture()
            value['new'] = '\n'.join(value['new']).replace(original, replacement).splitlines()
            with self.subTest(replacement=replacement):
                self.assertEqual(self.proof(value), [])

    def test_boolean_binding_and_configuration_ambiguity_are_refused(self):
        for original, replacement in (
                ('use super::*;', 'use other::transaction;'),
                ('#[cfg(test)]', '#[cfg(feature = "other")]'),
                ('    fn transaction(', '    #[cfg(test)] fn transaction('),
                ('    fn transaction(', '    async fn transaction('),
                ('    fn transaction(', '    fn another_helper('),
                ('    #[test]', '    #[unknown_generator]'),
                ('fn install_rollback_refuses_unproven_package_removal()',
                 'fn install_rollback_refuses_unproven_package_removal(transaction: fn())'),
                ('let mut recorded = transaction(', 'let transaction = transaction('),
                ('            for version in', '            let transaction = alias; for version in'),
                ('            for version in', '            use other::transaction; for version in'),
                ('            for version in', '            create_binding!(); for version in'),
                ('use super::*;', 'use super::*; create_binding!();')):
            value = self.fixture()
            value['new'] = '\n'.join(value['new']).replace(original, replacement).splitlines()
            with self.subTest(replacement=replacement):
                self.assertEqual(self.proof(value), [])

    def test_boolean_second_safe_occurrence_is_ambiguous_independent_of_values(self):
        value = self.fixture()
        value['old'] = '\n'.join(value['old']).replace('Some("1.0-1"),', 'None         ,').splitlines()
        for row in value['base'][-1]['regions']:
            if row[0] >= 36:
                row[4] = 0
        # Matching byte widths and a second unhit call isolate occurrence uniqueness.
        self.assertEqual(self.proof(value), [])

    def test_boolean_caller_rename_and_different_positive_frequency_are_supported(self):
        value = self.fixture()
        original = 'install_rollback_refuses_unproven_package_removal'
        value['new'] = '\n'.join(value['new']).replace(original, 'x' * len(original)).splitlines()
        for row in value['head'][-1]['regions']:
            if row[4] == 3:
                row[4] = 4
        for row in value['head_segments']:
            if row[2] == 3:
                row[2] = 4
        self.assertEqual(self.proof(value)[0]['pairs'], [[32, 32]])

    def test_boolean_unhit_header_only_copy_is_not_omitted_from_inventory(self):
        value = self.fixture()
        row = value['head'][-1]['regions'][0].copy()
        row[4] = 0
        value['head'].append(dict(name='unhit_sparse_copy', filenames=['/src/example.rs'], regions=[row]))
        self.assertEqual(self.proof(value), [])

    def test_boolean_segment_counts_must_support_each_exact_witness(self):
        for line, column in ((28, 32), (34, 28)):
            for mode in ('missing', 'count', 'entry', 'gap'):
                value = self.fixture()
                row = next(row for row in value['head_segments'] if row[:2] == [line, column])
                if mode == 'missing':
                    value['head_segments'].remove(row)
                elif mode == 'count':
                    row[2] = 0
                elif mode == 'entry':
                    row[4] = False
                else:
                    row[5] = True
                with self.subTest(line=line, mode=mode):
                    self.assertEqual(self.proof(value), [])

    def test_boolean_same_owner_overlaps_must_agree_with_the_exact_witness(self):
        for shape in ([28, 33, 28, 42], [34, 30, 34, 32]):
            for count in (0, 4):
                value = self.fixture()
                value['head'][-1]['regions'].append(shape + [count, 0, 0, 0])
                with self.subTest(shape=shape, count=count):
                    self.assertEqual(self.proof(value), [])

    def test_boolean_inactive_segment_cannot_claim_a_region_entry(self):
        value = self.fixture()
        next(row for row in value['head_segments'] if not row[3])[4] = True
        self.assertEqual(self.proof(value), [])

    def test_boolean_base_token_segments_cannot_contradict_positive_line_paint(self):
        value = self.fixture()
        value['base_segments'].extend([[32, 17, 0, True, True, False], [32, 21, 1, True, False, False]])
        value['base_segments'].sort()
        self.assertEqual(self.proof(value), [])

    def test_boolean_exact_source_guard_refuses_normalized_callee_byte_changes(self):
        for separator in ('\r\n', '\v', '\u0085'):
            def different_raw_source(value):
                value['new_raw'] = separator.join(value['new']).encode()
            with self.subTest(separator=repr(separator)), self.assertRaisesRegex(ValueError, 'Retained covered line'):
                self.compare(different_raw_source)

    def test_boolean_exact_source_guard_allows_optional_final_lf_and_records_raw_hash(self):
        def trailing_lf(value):
            value['old_raw'] = ('\n'.join(value['old']) + '\n').encode()
        receipt = self.compare(trailing_lf)['retained_boolean_argument_paint'][0]
        self.assertEqual(len(receipt['source_blob_sha256']), 2)
        self.assertNotEqual(*receipt['source_blob_sha256'])
        self.assertEqual(*receipt['source_lines_sha256'])

    def test_boolean_call_signature_and_item_bounds_count_utf8_bytes(self):
        for mode in ('call', 'signature', 'item'):
            value = self.fixture()
            if mode == 'call':
                value['new'][29] += ' /*' + 'é' * 2100 + '*/'
            else:
                line, repetitions = (8, 2100) if mode == 'signature' else (11, 33000)
                for side in ('old', 'new'):
                    value[side][line] += ' /*' + 'é' * repetitions + '*/'
            with self.subTest(mode=mode), mock.patch.object(
                    coverage, 'require_rustfmt_syntax', side_effect=AssertionError('over-bound syntax invocation')):
                self.assertEqual(self.proof(value), [])

    def test_boolean_raw_identifier_and_late_block_glob_shadow_are_refused(self):
        for original, replacement in (
                ('fn install_rollback_refuses_unproven_package_removal()',
                 'fn install_rollback_refuses_unproven_package_removal(r#transaction: fn())'),
                ('        }\n    }', '        } use other::*;\n    }')):
            value = self.fixture()
            value['new'] = '\n'.join(value['new']).replace(original, replacement).splitlines()
            self.assertEqual(self.proof(value), [])

    def test_boolean_string_and_comment_tokens_do_not_create_occurrences(self):
        value = self.fixture()
        value['new'][-1] += ' // transaction(true), fn transaction() {}'
        value['new'].append('const WORDS: &str = "transaction(true), fn transaction() {}";')
        self.assertEqual(self.proof(value)[0]['pairs'], [[32, 32]])

    def test_boolean_adjacent_tokens_cannot_be_joined_into_a_pure_leaf(self):
        value = self.fixture()
        value['new'] = '\n'.join(value['new']).replace('                source,', '                source as Text,').splitlines()
        self.assertEqual(self.proof(value), [])

    def test_boolean_zero_callee_entry_and_nested_base_macro_are_refused(self):
        for mode in ('callee', 'macro'):
            value = self.fixture()
            if mode == 'callee':
                for row in value['head'][0]['regions']:
                    row[4] = 0
            else:
                value['old'] = '\n'.join(value['old']).replace('rollback_action(&transaction(', 'rollback_actio!(&transaction(').splitlines()
            self.assertEqual(self.proof(value), [])

    def test_boolean_proof_preserves_all_supplied_evidence(self):
        value = self.fixture()
        original = copy.deepcopy(value)
        self.assertEqual(len(self.proof(value)), 1)
        self.assertEqual(value, original)

    def test_boolean_changed_callee_or_base_attribution_is_refused(self):
        value = self.fixture()
        value['new'] = '\n'.join(value['new']).replace('"2.0-1"', '"3.0-1"').splitlines()
        self.assertEqual(self.proof(value), [])
        value = self.fixture()
        value['before'][32] = 2
        self.assertEqual(self.proof(value), [])

    def test_boolean_malformed_region_segment_and_parser_bounds_are_refused(self):
        for mode in ('region_column', 'region_expansion', 'region_schema', 'foreign_file',
                     'segment_schema', 'segment_column', 'segment_counter', 'missing_segments',
                     'source_bound', 'nesting_bound', 'syntax'):
            value = self.fixture()
            if mode.startswith('region_'):
                row = value['head'][-1]['regions'][0]
                if mode == 'region_column': row[3] = 10000
                elif mode == 'region_expansion': row[7] = 1
                else: row.append(0)
            elif mode == 'foreign_file':
                value['head'][-1]['filenames'].append('/src/other.rs')
            elif mode == 'segment_schema':
                value['head_segments'][0].append(False)
            elif mode == 'segment_column':
                value['head_segments'][0][1] = 10000
            elif mode == 'segment_counter':
                value['head_segments'][0][2] = coverage.COUNTER_LIMIT
            elif mode == 'missing_segments':
                value['head_segments'] = None
            elif mode == 'source_bound':
                value['new'].append(' ' * (1024 * 1024 + 1))
            elif mode == 'nesting_bound':
                value['new'][0] = '(' * 33 + ')' * 33
            else:
                value['new'][27] = value['new'][27].replace('let mut', 'let mut mut')
            with self.subTest(mode=mode):
                self.assertEqual(self.proof(value), [])

    def test_boolean_paint_does_not_hide_another_retained_zero(self):
        with self.assertRaisesRegex(ValueError, 'Retained covered line'):
            self.compare(lambda value: value['after'].__setitem__(36, 0))

    def test_boolean_paint_preserves_new_zero_raw_counter_and_ratio_failures(self):
        def new_zero(value):
            value['new'].append('fn uncovered() { untested(); }')
            value['after'][len(value['new'])] = 0
        def summary_loss(value):
            value['head_summary'] = (len(value['after']) + 1, len(value['after']))
        for mutate, error in ((new_zero, 'New uncovered'), (summary_loss, 'Line coverage decreased'),
                              (lambda value: value['after'].__setitem__(36, coverage.COUNTER_LIMIT),
                               'Invalid LCOV coverage counter')):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                self.compare(mutate)

    def test_boolean_paint_requires_the_pinned_syntax_validator(self):
        with mock.patch.object(coverage, 'require_rustfmt_syntax', side_effect=ValueError('parser unavailable')):
            with self.assertRaisesRegex(ValueError, 'parser unavailable'):
                self.proof()


class ExactObserverTests(unittest.TestCase):
    def fixture(self):
        source = b"fn work() {\n    step();\n}\n"
        filename = '/src/example.rs'
        owners = [dict(name=name, count=count, filenames=[filename], branches=[], mcdc_records=[],
                       regions=[[1, 1, 3, 2, count, 0, 0, 0]])
                  for name, count in [('live', 5), ('cold', 0)]]
        record = dict(filename=filename, branches=[], mcdc_records=[], expansions=[],
                      segments=[[1, 1, 5, True, True, False], [3, 2, 0, False, False, False]],
                      summary={'lines': {'count': 3, 'covered': 3},
                               'regions': {'count': 1, 'covered': 1},
                               'functions': {'count': 1, 'covered': 1},
                               'instantiations': {'count': 2, 'covered': 1}})
        lcov = dict(LF=3, LH=3, counts={1: 5, 2: 5, 3: 5})
        return filename, source, owners, record, lcov

    def test_exact_observer_preserves_cold_copies_and_separate_surfaces(self):
        observed = coverage.observe_llvm22_file(*self.fixture())
        self.assertEqual(observed.summary, (3, 3))
        self.assertEqual(observed.rows, ((1, 5), (2, 5), (3, 5)))
        self.assertEqual([owner.count for owner in observed.owners], [5, 0])
        self.assertEqual(observed.groups, (((1, 1), (0, 1)),))

    def test_observer_reconciles_every_segment_and_da_count(self):
        for kind in ('segment-count', 'segment-entry', 'segment-gap', 'missing-segment',
                     'da-count', 'missing-da', 'summary-found', 'summary-hit'):
            with self.subTest(kind=kind):
                args = list(self.fixture())
                if kind == 'segment-count': args[3]['segments'][0][2] = 4
                if kind == 'segment-entry': args[3]['segments'][0][4] = False
                if kind == 'segment-gap': args[3]['segments'][0][5] = True
                if kind == 'missing-segment': args[3]['segments'].pop()
                if kind == 'da-count': args[4]['counts'][2] = 4
                if kind == 'missing-da': del args[4]['counts'][2]
                if kind == 'summary-found': args[3]['summary']['lines']['count'] = 4; args[4]['LF'] = 4
                if kind == 'summary-hit': args[3]['summary']['lines']['covered'] = 2; args[4]['LH'] = 2
                with self.assertRaisesRegex(ValueError, 'reconciliation'):
                    coverage.observe_llvm22_file(*args)

    def test_observer_requires_complete_compiled_inventory_even_for_zero_owners(self):
        for kind in ('drop-cold-copy', 'duplicate-copy', 'change-cold-entry', 'missing-owner-count'):
            with self.subTest(kind=kind):
                args = list(self.fixture())
                if kind == 'drop-cold-copy': args[2].pop()
                if kind == 'duplicate-copy': args[2].append(copy.deepcopy(args[2][1]))
                if kind == 'change-cold-entry': args[2][1]['count'] = 1
                if kind == 'missing-owner-count': del args[2][1]['count']
                with self.assertRaisesRegex(ValueError, 'inventory|reconciliation'):
                    coverage.observe_llvm22_file(*args)

    def test_observer_refuses_unsupported_schema_geometry_and_saturation(self):
        mutations = {
            'foreign-file': lambda a: a[2][0]['filenames'].append('/src/foreign.rs'),
            'file-id': lambda a: a[2][0]['regions'][0].__setitem__(5, 1),
            'expanded-file': lambda a: a[2][0]['regions'][0].__setitem__(6, 1),
            'gap': lambda a: a[2][0]['regions'][0].__setitem__(7, 3),
            'reversed': lambda a: a[2][0]['regions'][0].__setitem__(2, 0),
            'column': lambda a: a[2][0]['regions'][0].__setitem__(3, 3),
            'negative': lambda a: a[2][0]['regions'][0].__setitem__(4, -1),
            'bool-count': lambda a: a[2][0]['regions'][0].__setitem__(4, True),
            'saturated-region': lambda a: a[2][0]['regions'][0].__setitem__(4, coverage.COUNTER_LIMIT),
            'saturated-entry': lambda a: a[2][0].__setitem__('count', coverage.COUNTER_LIMIT),
            'branch': lambda a: a[2][0]['branches'].append([1]),
            'expansion': lambda a: a[3]['expansions'].append({}),
            'record-filename': lambda a: a[3].__setitem__('filename', '/src/other.rs'),
            'source-crlf': lambda a: a.__setitem__(1, a[1].replace(b'\n', b'\r\n')),
        }
        for kind, mutate in mutations.items():
            with self.subTest(kind=kind):
                args = list(self.fixture()); mutate(args)
                with self.assertRaises(ValueError):
                    coverage.observe_llvm22_file(*args)

    def test_observer_rejects_counter_sum_that_would_saturate(self):
        args = list(self.fixture())
        args[2][0]['regions'][0][4] = coverage.COUNTER_LIMIT - 1
        args[2][1]['regions'][0][4] = 1
        with self.assertRaisesRegex(ValueError, 'saturated'):
            coverage.observe_llvm22_file(*args)

    def test_observer_validates_utf8_byte_boundaries(self):
        args = list(self.fixture())
        args[1] = b'fn work() {\n    step();\n}\xc3\xa9\n'
        for owner in args[2]: owner['regions'][0][3] = 3
        with self.assertRaisesRegex(ValueError, 'boundary'):
            coverage.observe_llvm22_file(*args)

    def test_group_maxima_do_not_require_identical_geometry_or_equal_da_hit_totals(self):
        filename, _, _, record, _ = self.fixture()
        source = b'fn work() {\n    a();\n    b();\n}\n'
        owners = [dict(name='wide', count=1, filenames=[filename], branches=[], mcdc_records=[],
                       regions=[[1, 1, 4, 2, 1, 0, 0, 0], [2, 1, 4, 1, 0, 0, 0, 0]]),
                  dict(name='short', count=2, filenames=[filename], branches=[], mcdc_records=[],
                       regions=[[1, 1, 3, 9, 2, 0, 0, 0]])]
        record['segments'] = [[1, 1, 2, True, True, False], [2, 1, 0, True, True, False],
                              [3, 9, 0, True, False, False], [4, 1, 1, True, False, False],
                              [4, 2, 0, False, False, False]]
        record['summary'] = {'lines': {'count': 4, 'covered': 3},
                             'regions': {'count': 2, 'covered': 1},
                             'functions': {'count': 1, 'covered': 1},
                             'instantiations': {'count': 2, 'covered': 2}}
        observed = coverage.observe_llvm22_file(filename, source, owners, record,
                                                dict(LF=4, LH=3, counts={1: 2, 2: 2, 3: 0, 4: 0}))
        self.assertEqual(observed.summary, (4, 3))
        self.assertEqual(sum(count > 0 for _, count in observed.rows), 2)
        self.assertEqual([len(owner.rows) for owner in observed.owners], [4, 3])

    def test_owner_order_is_preserved_without_changing_reconstructed_observations(self):
        args = list(self.fixture())
        original = coverage.observe_llvm22_file(*args)
        args[2].reverse()
        reordered = coverage.observe_llvm22_file(*args)
        self.assertEqual([owner.name for owner in reordered.owners], ['cold', 'live'])
        self.assertEqual((original.summary, original.rows, original.segments),
                         (reordered.summary, reordered.rows, reordered.segments))
        self.assertNotEqual(original.inventory_sha256, reordered.inventory_sha256)

    def test_whole_group_projection_preserves_all_compiled_copies_and_both_metrics(self):
        args = list(self.fixture())
        observed = coverage.observe_llvm22_file(*args)
        kept = coverage.project_observer_groups(observed, ())
        self.assertEqual((kept.summary, kept.rows), (observed.summary, observed.rows))
        removed = coverage.project_observer_groups(observed, ((1, 1),))
        self.assertEqual(removed.removed_owners, ('live', 'cold'))
        self.assertEqual((removed.summary, removed.rows), ((0, 0), ()))
        with self.assertRaisesRegex(ValueError, 'whole observer group'):
            coverage.project_observer_groups(observed, ('cold',))

    def test_overlap_projection_does_not_sum_mapped_rows_or_use_summary_as_da(self):
        filename, source, _, record, _ = self.fixture()
        owners = [dict(name='parent', count=5, filenames=[filename], branches=[], mcdc_records=[],
                       regions=[[1, 1, 3, 2, 5, 0, 0, 0]]),
                  dict(name='cold-closure', count=0, filenames=[filename], branches=[], mcdc_records=[],
                       regions=[[2, 5, 2, 9, 0, 0, 0, 0]])]
        record['segments'] = [[1, 1, 5, True, True, False], [2, 5, 0, True, True, False],
                              [2, 9, 5, True, False, False], [3, 2, 0, False, False, False]]
        record['summary'] = {'lines': {'count': 4, 'covered': 3},
                             'regions': {'count': 2, 'covered': 1},
                             'functions': {'count': 2, 'covered': 1},
                             'instantiations': {'count': 2, 'covered': 1}}
        observed = coverage.observe_llvm22_file(filename, source, owners, record,
                                                dict(LF=4, LH=3, counts={1: 5, 2: 5, 3: 5}))
        projected = coverage.project_observer_groups(observed, ((2, 5),))
        self.assertEqual(projected.summary, (3, 3))
        self.assertEqual(projected.rows, observed.rows)
        self.assertEqual(projected.removed_owners, ('cold-closure',))

    def test_projection_work_budget_is_shared_and_fails_closed(self):
        observed = coverage.observe_llvm22_file(*self.fixture())
        work = coverage._ObserverWork()
        work.remaining = 0
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage.project_observer_groups(observed, (), _work=work)


class SourceObligationLedgerTests(unittest.TestCase):
    def ledger(self, old, new, old_counts=None, new_counts=None):
        old_counts = old_counts or {i: 1 for i, line in enumerate(old.splitlines(), 1) if line.strip()}
        new_counts = new_counts or {i: 1 for i, line in enumerate(new.splitlines(), 1) if line.strip()}
        return coverage.source_obligation_ledger(old.encode(), new.encode(), old_counts, new_counts)

    def test_nested_endpoint_identity_has_linear_expanded_size(self):
        def expanded_units(value, memo):
            if not isinstance(value, tuple):
                return 1
            if id(value) not in memo:
                memo[id(value)] = 1 + sum(expanded_units(item, memo) for item in value)
            return memo[id(value)]

        for depth in (12, 30):
            source = 'fn work() {\n' + '{\n' * depth + '}\n' * (depth + 1)
            ledger = self.ledger(source, source)
            largest = max(expanded_units(atom.endpoint, {}) for atom in ledger.base_atoms)
            with self.subTest(depth=depth):
                self.assertLessEqual(largest, 16 * (depth + 1),
                                     'one endpoint must not recursively duplicate its ancestors')
            self.assertEqual(len(ledger.base_atoms), len(ledger.obligations))

    def test_wrong_function_to_struct_endpoint_keeps_every_old_obligation(self):
        old = 'fn obsolete() {\n    old();\n}\n'
        new = 'struct Manifest {\n    generation: String,\n}\n'
        ledger = self.ledger(old, new)
        self.assertEqual([atom.line for atom in ledger.base_atoms], [1, 2, 3])
        self.assertEqual([item.old_line for item in ledger.obligations], [1, 2, 3])
        endpoint = ledger.obligations[2]
        self.assertEqual(endpoint.role, 'Unresolved')
        self.assertEqual(endpoint.head_candidates, ())
        self.assertIn('endpoint', endpoint.reason)
        with self.assertRaisesRegex(ValueError, 'unresolved source obligations'):
            ledger.require_resolved()

    def test_function_endpoint_inventory_excludes_macro_with_same_spelling(self):
        old = 'fn retained() -> usize {\n    1\n}\n'
        new = 'fn retained() -> u64 {\n    2\n}\nthread_local! {\n    static VALUE: u8 = 0;\n}\n'
        ledger = self.ledger(old, new)
        endpoint = next(item for item in ledger.obligations if item.old_line == 3)
        self.assertEqual((endpoint.role, endpoint.head_line, endpoint.head_candidates),
                         ('Retained', 3, (3,)))
        self.assertEqual(ledger.head_atoms[-1].endpoint[0], 'macro')

    def test_repeated_function_candidates_are_not_selected_by_hit_count(self):
        old = 'fn retained() {\n    step();\n}\n'
        new = '#[cfg(first)]\nfn retained() {\n    step();\n}\n#[cfg(second)]\nfn retained() {\n    step();\n}\n'
        ledger = self.ledger(old, new, new_counts={2: 1, 3: 1, 4: 1, 6: 0, 7: 0, 8: 0})
        endpoint = next(item for item in ledger.obligations if item.old_line == 3)
        self.assertEqual(endpoint.role, 'Unresolved')
        self.assertEqual(endpoint.head_candidates, (4, 8))
        self.assertEqual([atom.count for atom in ledger.head_atoms], [1, 1, 1, 0, 0, 0])

    def test_same_function_path_and_parameters_bound_repeated_expression_inventory(self):
        old = 'fn load(items: &[u8]) -> usize {\n    items.par_iter()\n}\nfn other() {\n    items.par_iter()\n}\n'
        new = 'fn load(items: &[u8]) -> Result<usize> {\n    setup();\n    items.par_iter()\n}\nfn other() {\n    items.par_iter()\n}\n'
        ledger = self.ledger(old, new)
        expression = next(item for item in ledger.obligations if item.old_line == 2)
        self.assertEqual((expression.role, expression.head_line, expression.head_candidates),
                         ('Retained', 3, (3,)))

    def test_unique_complete_body_rename_preserves_endpoint_extraction_candidate(self):
        old = 'fn previous() {\n    step();\n}\n'
        new = 'fn renamed() {\n    step();\n}\n'
        ledger = self.ledger(old, new)
        endpoint = next(item for item in ledger.obligations if item.old_line == 3)
        self.assertEqual((endpoint.role, endpoint.head_line), ('Moved', 3))

    def test_deleted_or_replaced_rows_never_gain_implicit_zero_credit(self):
        for old, new in [('fn old() {\n    unhit();\n}\nfn keep() {}\n', 'fn keep() {}\n'),
                         ('fn keep() {\n    unhit();\n}\n', 'fn keep() {\n    replacement();\n}\n')]:
            ledger = self.ledger(old, new, old_counts={i: 0 for i in range(1, len(old.splitlines()) + 1)})
            self.assertEqual(len(ledger.base_atoms), len(ledger.obligations))
            self.assertFalse(any(item.role == 'Deleted' for item in ledger.obligations))
            with self.assertRaisesRegex(ValueError, 'unresolved source obligations'):
                ledger.require_resolved()

    def test_changed_conditional_definition_does_not_establish_endpoint_retention(self):
        old = '#[cfg(first)]\nfn retained() {\n    step();\n}\n'
        new = '#[cfg(second)]\nfn retained() {\n    step();\n}\n'
        endpoint = self.ledger(old, new).obligations[-1]
        self.assertEqual((endpoint.role, endpoint.head_candidates), ('Unresolved', (4,)))


class DiagnosticCoverageTests(unittest.TestCase):
    def test_serialization_admission_counts_unicode_escapes_and_shared_references(self):
        shared = ('"\t\\\x00é😀\x7f\n', True, False, None, -123)
        value = {'first': shared, 'second': [shared, coverage.SourceAtom(1, 'é', 0, None)]}
        plain = coverage._diagnostic_plain_value(value)
        self.assertEqual(coverage._diagnostic_size(value),
                         len(json.dumps(plain).encode('utf-8')))

    def test_deep_shared_graph_and_cycles_are_refused_before_copying(self):
        shared = ('x',)
        for _ in range(40):
            shared = (shared,)
        deep = shared
        for _ in range(30):
            deep = (deep,)
        cycle = []
        cycle.append(cycle)
        for value, reason in (({'shallow': shared, 'deep': deep}, 'nesting'), (cycle, 'cycle')):
            with self.subTest(reason=reason), \
                    mock.patch.object(coverage, 'asdict', side_effect=AssertionError('copy before admission')):
                with self.assertRaisesRegex(ValueError, reason):
                    coverage._diagnostic_plain_value(value)

    def fixture(self, root, lost=False):
        source = b'fn work() {\n    step();\n}\n'
        arguments = ['check-line-coverage.py', '--source-repo', str(root),
                     '--base-sha', 'a' * 40, '--head-sha', 'b' * 40]
        for side in ('base', 'head'):
            counts = [5, 0 if lost and side == 'head' else 5, 5]
            lcov = root / (side + '.info')
            lcov.write_text('SF:/src/example.rs\n' + ''.join(f'DA:{i},{c}\n' for i,c in enumerate(counts,1))
                            + f'LF:3\nLH:{sum(c>0 for c in counts)}\nend_of_record\n')
            regions = [[line, 1, line, end, count, 0, 0, 0]
                       for line, end, count in zip((1, 2, 3), (12, 12, 2), counts)]
            record = dict(filename='/src/example.rs', branches=[], mcdc_records=[], expansions=[],
                          segments=[segment for line,end,count in zip((1,2,3),(12,12,2),counts)
                                    for segment in ([line,1,count,True,True,False],[line,end,0,False,False,False])],
                          summary={'lines':dict(count=3,covered=sum(c>0 for c in counts)),
                                   'regions':dict(count=3,covered=sum(c>0 for c in counts)),
                                   'functions':dict(count=1,covered=1),
                                   'instantiations':dict(count=1,covered=1)})
            document = dict(type='llvm.coverage.json.export', version='3.1.0', data=[dict(files=[record],
                            functions=[dict(name='work', count=5, filenames=['/src/example.rs'],
                                            branches=[], mcdc_records=[], regions=regions)])])
            archive = root / (side + '.gz')
            archive.write_bytes(gzip.compress(json.dumps(document).encode()))
            arguments += ['--' + side, str(lcov), '--' + side + '-regions', str(archive)]
        return arguments, {'example.rs': source}

    def run_main(self, arguments, sources):
        out, err = io.StringIO(), io.StringIO()
        failure = None
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(coverage, 'source_blobs', return_value=sources), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                coverage.main()
            except ValueError as error:
                failure = str(error)
        return failure, out.getvalue(), err.getvalue()

    def test_optional_diagnostic_preserves_the_original_strict_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); arguments, sources = self.fixture(root, lost=True)
            original = self.run_main(arguments, sources)
            output = root / 'diagnostic.json'
            diagnostic = self.run_main(arguments + ['--diagnostic-output', str(output),
                                                     '--diagnostic-file', 'example.rs'], sources)
            self.assertEqual(diagnostic[:2], original[:2])
            self.assertIn('Retained covered line lost', diagnostic[0])
            self.assertNotIn('PASS:', diagnostic[1])
            report = json.loads(output.read_text())
            self.assertFalse(report['acceptance'])
            self.assertEqual(report['source_commits'], {'base': 'a' * 40, 'head': 'b' * 40})
            self.assertEqual([row['line'] for row in report['files'][0]['base']['atoms']], [1, 2, 3])
            self.assertEqual(report['files'][0]['base']['observer']['status'], 'reconciled')
            self.assertEqual(report['files'][0]['head']['observer']['status'], 'reconciled')

    def test_expanded_report_is_refused_before_dataclass_copy_or_json_serialization(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); arguments, sources = self.fixture(root, lost=True)
            original = self.run_main(arguments, sources)
            shared = ('x',)
            for _ in range(26):
                shared = (shared, shared)
            ledger = coverage.SourceLedger((coverage.SourceAtom(1, 'x', 1, shared),), (), (), ())
            output = root / 'report.json'
            with mock.patch.object(coverage, 'source_obligation_ledger', return_value=ledger), \
                    mock.patch.object(coverage, 'asdict', side_effect=AssertionError('copy before output admission')):
                diagnostic = self.run_main(arguments + ['--diagnostic-output', str(output),
                                                         '--diagnostic-file', 'example.rs'], sources)
            self.assertEqual(diagnostic[:2], original[:2])
            self.assertFalse(output.exists())
            self.assertIn('Diagnostic output exceeds 64 MiB bound', diagnostic[2])

    def test_diagnostic_cannot_turn_a_passing_comparison_into_a_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); arguments, sources = self.fixture(root)
            original = self.run_main(arguments, sources)
            diagnostic = self.run_main(arguments + ['--diagnostic-output', str(root / 'report.json'),
                                                     '--diagnostic-file', 'example.rs'], sources)
            self.assertEqual(diagnostic[:2], original[:2])
            self.assertIsNone(diagnostic[0])
            self.assertIn('PASS:', diagnostic[1])

    def test_unsupported_diagnostic_retains_old_atoms_and_the_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); arguments, sources = self.fixture(root, lost=True)
            original = self.run_main(arguments, sources)
            archive = root / 'head.gz'
            document = json.loads(gzip.decompress(archive.read_bytes()))
            document['data'][0]['functions'][0]['filenames'].append('/src/foreign.rs')
            archive.write_bytes(gzip.compress(json.dumps(document).encode()))
            output = root / 'report.json'
            diagnostic = self.run_main(arguments + ['--diagnostic-output', str(output),
                                                     '--diagnostic-file', 'example.rs'], sources)
            self.assertEqual(diagnostic[0], original[0])
            row = json.loads(output.read_text())['files'][0]
            self.assertEqual(len(row['base']['atoms']), 3)
            self.assertEqual(row['head']['observer']['status'], 'unsupported')

    def test_diagnostic_output_cannot_overwrite_an_input_or_change_the_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); arguments, sources = self.fixture(root, lost=True)
            original = self.run_main(arguments, sources)
            input_path = root / 'head.info'; original_bytes = input_path.read_bytes()
            diagnostic = self.run_main(arguments + ['--diagnostic-output', str(input_path),
                                                     '--diagnostic-file', 'example.rs'], sources)
            self.assertEqual(diagnostic[:2], original[:2])
            self.assertEqual(input_path.read_bytes(), original_bytes)
            self.assertIn('Diagnostic unavailable; strict comparison unchanged', diagnostic[2])

    def test_unsupported_lexical_partition_keeps_raw_old_obligations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); arguments, sources = self.fixture(root, lost=True)
            sources = {'example.rs': b'fn work() {\n    step();\n'}
            output = root / 'report.json'
            self.run_main(arguments + ['--diagnostic-output', str(output),
                                        '--diagnostic-file', 'example.rs'], sources)
            row = json.loads(output.read_text())['files'][0]
            self.assertEqual(row['source_obligations']['status'], 'unsupported')
            self.assertEqual(row['source_obligations']['old_obligations'],
                             [dict(old_line=i, role='Unresolved') for i in (1, 2, 3)])
            self.assertEqual([item['count'] for item in row['base']['atoms']], [5, 5, 5])


if __name__ == "__main__":
    unittest.main()

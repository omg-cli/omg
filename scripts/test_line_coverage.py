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
from unittest.mock import patch
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



class CompiledMethodParentFilesTests(unittest.TestCase):
    symbol = ('_RNvXNtNtNtNtNtCs40j12eeWnis_7omg_lib3cli8packages7install4arch5tests'
              'NtB2_13FixtureSourceNtNtNtNtBc_4core8security13vulnerability'
              '19VulnerabilitySource12scan_package')

    def test_complete_index_keeps_cross_file_copies_callbacks_and_impl_identity(self):
        child = '_RNC' + self.symbol[2:].replace('B2_', 'B4_').replace('Bc_', 'Be_') + '0Be_'
        foreign = self.symbol.replace('13FixtureSource', '13AnotherSource')
        owners = [dict(name=name, filenames=paths) for name, paths in (
            (self.symbol, ['/src/first.rs']),
            (self.symbol.replace('s40j12eeWnis_', 's99_'), ['/src/second.rs']),
            (child, ['/src/callback.rs']),
            (self.symbol, ['/unattributed.rs']),
            (foreign, ['/src/foreign.rs']),
            (self.symbol + '.llvm.1', ['/src/suffixed.rs']),
            ('_Rinvalid', ['/src/malformed.rs']),
            ('_ZNlegacy', ['/src/legacy.rs']))]
        files = {path: path[5:] for owner in owners for path in owner['filenames']
                 if path.startswith('/src/')}
        index, unknown = coverage.compiled_method_parent_files(owners, files, [64_000_000])
        key = coverage.nominal_method_parent(self.symbol, inventory=True)[1]
        other = coverage.nominal_method_parent(foreign, inventory=True)[1]
        self.assertEqual(index[key], {'first.rs', 'second.rs', 'callback.rs', 'suffixed.rs', '<unattributed source>'})
        self.assertEqual(index[other], {'foreign.rs'})
        self.assertEqual(set(index), {key, other})
        self.assertEqual(unknown, set())

    def test_unrecognized_owner_locations_remain_conservative_for_every_scope(self):
        owners = [dict(name='unknown', filenames=['/src/opaque.rs', '/unattributed.rs'])]
        index, unknown = coverage.compiled_method_parent_files(
            owners, {'/src/opaque.rs': 'opaque.rs'}, [64_000_000])
        self.assertEqual(index, {})
        self.assertEqual(unknown, {'opaque.rs', '<unattributed source>'})

    def test_bounded_prefix_scan_still_accounts_for_long_opaque_owners(self):
        owners = [
            dict(name='_RNvNtC' + 'x' * 512, filenames=['/src/free.rs']),
            dict(name='opaque-' + 'x' * 512, filenames=['/unknown.rs']),
            dict(name=self.symbol, filenames=['/src/method.rs']),
        ]
        files = {'/src/free.rs': 'free.rs', '/src/method.rs': 'method.rs'}
        index, unknown = coverage.compiled_method_parent_files(owners, files, [len(self.symbol) + 96])
        key = coverage.nominal_method_parent(self.symbol, inventory=True)[1]
        self.assertEqual(index, {key: {'method.rs'}})
        self.assertEqual(unknown, {'<unattributed source>'})

    def test_index_refuses_exhaustion_before_symbol_decoding(self):
        owners = [dict(name=self.symbol, filenames=['/src/example.rs'])]
        with patch.object(coverage, 'nominal_method_parent',
                          side_effect=AssertionError('decode before admission')):
            for budget in (len(owners), len(owners) + coverage._NOMINAL_METHOD_PREFIX_WORK):
                with self.subTest(budget=budget), self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                    coverage.compiled_method_parent_files(owners, {}, [budget])


class CompiledPlainParentFilesTests(unittest.TestCase):
    def test_lookup_preserves_literal_scopes_and_conservative_opaque_owners(self):
        scope = '7omg_lib3pkg5tests'
        owners = [dict(name=name, filenames=paths) for name, paths in (
            ('_RNvNtC' + scope + '3one', ['/src/first.rs']),
            ('_RNvNtC' + scope + '3one', ['/src/duplicate.rs']),
            ('_Runsupported_' + scope + '.llvm.1', ['/outside.rs']),
            ('_ZNembedded' + scope + 'E', ['/src/legacy.rs']),
            ('_R7omg_lib3pkg5other', ['/src/nonmatch.rs']),
            ('_Rprefixletters', ['/src/short.rs']),
            ('opaque', ['/src/opaque.rs']))]
        files = {path: path[5:] for owner in owners for path in owner['filenames']
                 if path.startswith('/src/')}
        lookup = coverage.compiled_plain_parent_files(owners, files, [64_000_000])
        for needle in (scope, '3pkg', '5tests', 'letters', '7absent', '', 'R'):
            with self.subTest(needle=needle):
                expected = {files.get(path, '<unattributed source>') for owner in owners
                            if needle in owner['name'] or not owner['name'].startswith(('_R', '_ZN'))
                            for path in owner['filenames']}
                self.assertEqual(lookup(needle), expected)

    def test_index_and_lookup_charge_before_decoding_or_traversal(self):
        owners = [dict(name='_R7omg_lib3pkg5tests', filenames=['/src/test.rs'])]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage.compiled_plain_parent_files(owners, {}, [len(owners)])
        work = [64_000_000]
        lookup = coverage.compiled_plain_parent_files(owners, {}, work)
        work[0] = 0
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            lookup('5tests')


class QualifiedFunctionCompletionTests(unittest.TestCase):
    def compare(self, fault=None):
        misleading = fault is not None and fault.startswith('misleading-')
        if misleading:
            fault = fault[len('misleading-'):]
        before = ['fn scaffold(name: &str) -> Result<()> {', '    write(name)', '}']
        after = ['fn scaffold(root: &Path, name: &str) -> Result<()> {',
                 '    write_at(root, name)', '}']
        if fault == 'different-result':
            after[0] = after[0].replace('Result<()>', 'Result<bool>')
        elif fault == 'same-parameters':
            after[0] = before[0]
        files = {'/src/example.rs': 'example.rs'}
        base, head = [[dict(name=f'_RNvNtCs{crate}_7omg_lib3cli8scaffold', count=1,
                            filenames=['/src/example.rs'], regions=[
                                [1, 1, 1, len(source[0]) + 1, 1, 0, 0, 0],
                                [3, 1, 3, 2, 1, 0, 0, 0]])
                       for crate in crates]
                      for source, crates in ((before, 'ab'), (after, 'cd'))]
        if fault == 'cold-copy':
            head[1]['regions'][-1][4] = 0
        elif fault == 'missing-copy':
            head.pop()
        elif fault == 'wrong-owner':
            head[0]['name'] = head[0]['name'].replace('3cli', '3pkg')
        elif fault == 'duplicate-name':
            head[1]['name'] = head[0]['name']
        elif fault == 'foreign-region':
            head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                             regions=[[3, 1, 3, 2, 1, 0, 0, 0]]))
        target = 3
        if misleading:
            after[:0] = ['enum Entry {', '    Variant,', '}', '']
            for owner in head:
                for row in owner['regions']:
                    row[0] += 4; row[2] += 4
            target = 7
            if fault == 'ambiguous-logical-function':
                after.extend(['', 'fn scaffold(other: &str) -> Result<()> {', '    other()', '}'])
                head.append(dict(name='_RNvNtCse_7omg_lib3cli8scaffold', count=1,
                    filenames=['/src/example.rs'], regions=[
                        [9, 1, 9, len(after[8])+1, 1, 0, 0, 0], [11, 1, 11, 2, 1, 0, 0, 0]]))
            elif fault == 'foreign-proposed-function':
                after[0] = 'fn foreign() {'
                after[1] = '    foreign_work();'
                head.append(dict(name='_RNvNtCse_7omg_lib3cli7foreign', count=1,
                    filenames=['/src/example.rs'], regions=[
                        [1, 1, 1, len(after[0])+1, 1, 0, 0, 0], [3, 1, 3, 2, 1, 0, 0, 0]]))
            elif fault == 'nonbare-proposal':
                after[2] = '    }'
        line = 2 if fault == 'body-line' else 3
        if line == 2:
            after[1] = before[1]
        mapped = {line: 2} if fault == 'missing-target-mapping' else {target: 2}
        return coverage.positive_source_fragments('example.rs', before, after,
            {line: 2}, mapped, base, head, files, files,
            [(line - 1, line, line - 1, line, [line])])

    def test_retains_only_the_exact_closing_regions_under_a_new_parameter_list(self):
        pairs, receipts = self.compare()
        self.assertEqual(pairs, {3: 3})
        receipt, = receipts
        self.assertEqual(receipt['kind'], 'qualified-function-completion')
        self.assertEqual(receipt['pairs'], [[3, 3]])
        self.assertEqual([len(side) for side in receipt['owners']], [2, 2])

    def test_misleading_enum_brace_resolves_the_unique_function_completion(self):
        pairs, receipts = self.compare('misleading-enum-brace')
        self.assertEqual(pairs, {3: 7})
        receipt, = receipts
        self.assertEqual(receipt['pairs'], [[3, 7]])
        self.assertEqual(receipt['head_range'], [5, 7])

    def test_completion_cannot_borrow_the_misleading_proposals_evidence(self):
        for fault in ('cold-copy', 'missing-copy', 'wrong-owner', 'duplicate-name',
                      'foreign-region', 'different-result', 'same-parameters',
                      'ambiguous-logical-function', 'missing-target-mapping', 'nonbare-proposal'):
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'Ambiguous'):
                self.compare('misleading-' + fault)
        pairs, _ = self.compare('misleading-foreign-proposed-function')
        self.assertEqual(pairs, {3: 7})

    def test_incomplete_or_different_owner_evidence_is_refused(self):
        for fault in ('cold-copy', 'missing-copy', 'wrong-owner', 'duplicate-name',
                      'foreign-region', 'different-result', 'body-line'):
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'Ambiguous'):
                self.compare(fault)


class SourceConstructCapacityTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        sources = {name: f'fn {name[:-3]}() {{\n    verified();\n}}\n'.encode()
                   for name in ('first.rs', 'second.rs')}
        section = lambda name: f'SF:/src/{name}\nDA:1,1\nDA:2,1\nDA:3,1\nLF:3\nLH:3\nend_of_record\n'
        document = {'type': 'llvm.coverage.json.export', 'version': '3.1.0', 'data': [{
            'files': [{'filename': f'/src/{name}', 'summary': {'lines': {'count': 3, 'covered': 3}}}
                      for name in sources],
            'functions': [dict(name=name[:-3], filenames=[f'/src/{name}'],
                               regions=[[1, 1, 3, 2, 1, 0, 0, 0]]) for name in sources]}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); lcov = root / 'coverage.info'; regions = root / 'regions.gz'
            lcov.write_text(''.join(section(name) for name in sources))
            regions.write_bytes(gzip.compress(json.dumps(document).encode()))
            yield lcov, regions, sources

    def compare(self):
        with self.fixture() as (lcov, regions, sources):
            report = coverage.read_coverage(lcov)
            return coverage.require_source_no_regression(report, report, regions, regions, sources, sources)

    def test_main_capacity_admits_work_above_old_limit_without_changing_other_limits(self):
        original = coverage.retained_construct_anchors
        calls = []
        def spend(name, old, new, before, after, base, head, base_files, head_files,
                  work=None, inventories=None, grouped=None):
            if not calls:
                coverage._construct_charge(work, 20_000_001)
            calls.append((name, id(work)))
            return original(name, old, new, before, after, base, head, base_files, head_files,
                            work, inventories, grouped)
        with patch.object(coverage, 'retained_construct_anchors', side_effect=spend):
            receipt = self.compare()
        self.assertEqual(len(calls), 2)
        self.assertEqual(len({identity for name, identity in calls}), 1)
        self.assertEqual(receipt['deleted_mapped'], 0)
        self.assertEqual(coverage.SOURCE_CONSTRUCT_WORK_CAPACITY, 64_000_000)
        self.assertEqual(coverage._ObserverWork().remaining, 20_000_000)

    def test_shared_cross_file_exhaustion_has_no_partial_success(self):
        calls = []
        def spend(name, old, new, before, after, base, head, base_files, head_files,
                  work=None, inventories=None, grouped=None):
            calls.append((name, id(work)))
            coverage._construct_charge(work, 600)
            return {}, []
        output = io.StringIO()
        with self.fixture() as (lcov, regions, sources):
            argv = ['check-line-coverage.py', '--base', str(lcov), '--head', str(lcov),
                    '--base-regions', str(regions), '--head-regions', str(regions),
                    '--source-repo', str(lcov.parent), '--base-sha', 'base', '--head-sha', 'head']
            with patch.object(coverage, 'SOURCE_CONSTRUCT_WORK_CAPACITY', 1000, create=True), \
                 patch.object(coverage, 'retained_construct_anchors', side_effect=spend), \
                 patch.object(coverage, 'source_blobs', return_value=sources), \
                 patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
                with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                    coverage.main()
        self.assertEqual([name for name, identity in calls], ['first.rs', 'second.rs'])
        self.assertEqual(len({identity for name, identity in calls}), 1)
        self.assertNotIn('PASS:', output.getvalue())
        self.assertNotIn('deleted_mapped', output.getvalue())

    def test_capacity_boundary_is_fail_closed_before_following_work(self):
        capacity = getattr(coverage, 'SOURCE_CONSTRUCT_WORK_CAPACITY', 64_000_000)
        remaining = [capacity]
        coverage._construct_charge(remaining, capacity)
        self.assertEqual(remaining, [0])
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage._construct_charge(remaining, 1)
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage._construct_inventory(['fn untouched() {}'], [0])

    def test_near_capacity_expensive_shapes_stop_at_existing_admission_boundaries(self):
        literal = ['fn bounded() {', '    consume("' + 'x' * 16_384 + '");', '}']
        owner = dict(regions=[[1, 1, 1, 2, 1, 0, 0, 0] for _ in range(128)])
        for capacity in (20_000_000, 64_000_000):
            with self.subTest(capacity=capacity):
                remaining = [capacity]
                coverage._construct_charge(remaining, capacity - 15)
                with patch.object(coverage.hashlib, 'sha256', side_effect=AssertionError('hash before admission')):
                    with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                        coverage._construct_inventory(literal, remaining)
                remaining = [capacity]
                coverage._construct_charge(remaining, capacity - 32)
                with patch.object(coverage, '_llvm22_segments', side_effect=AssertionError('projection before admission')):
                    with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                        coverage._owner_line_counts(owner, coverage._ObserverWork(remaining))
        with patch.object(coverage.subprocess, 'run', side_effect=AssertionError('parser before excerpt admission')):
            with self.assertRaisesRegex(ValueError, '64 KiB'):
                coverage.require_rustfmt_syntax([b' ' * (64 * 1024 + 1)])

    def test_repeated_line_alignment_keeps_the_same_outcome_at_both_capacities(self):
        old = ['fn bounded() {', *['    same();' for _ in range(96)], '    old();', '}']
        new = [line.replace('old();', 'new();') for line in old]
        outcomes = []
        for capacity in (20_000_000, 64_000_000):
            remaining = [capacity]
            coverage._construct_charge(remaining, capacity - 100_000)
            proposals, inventories = coverage._construct_replacements(old, new, remaining, deferred=True)
            outcomes.append(proposals)
            self.assertGreater(remaining[0], 0)
        self.assertEqual(outcomes[0], outcomes[1])

    def test_capacity_changes_admission_without_changing_valid_or_invalid_proof_outcomes(self):
        receipts = []
        failures = []
        for capacity in (20_000_000, 64_000_000):
            with patch.object(coverage, 'SOURCE_CONSTRUCT_WORK_CAPACITY', capacity, create=True):
                receipts.append(SourceAwareCoverageTests().renamed_capsule_compare())
                with self.assertRaises(ValueError) as failure:
                    SourceAwareCoverageTests().renamed_capsule_compare(
                        (((1, 0), (0, 1)), ((0, 0), (1, 1))))
                failures.append(str(failure.exception))
        self.assertEqual(receipts[0], receipts[1])
        self.assertEqual(failures[0], failures[1])


class SourceAwareCoverageTests(unittest.TestCase):
    def test_owner_inventory_index_retains_canonical_suffix_aliases_and_complete_duplicates(self):
        first = dict(name='same', filenames=['/one/example.rs'])
        second = dict(name='same', filenames=['/two/other.rs'])
        owners = [first, second]
        files = {'/one/example.rs': 'canonical.rs', '/two/other.rs': 'other.rs'}
        index = coverage.index_compiled_owner_sources(owners, files, [20_000_000])
        self.assertEqual(index.inventories['example.rs'], (first,))
        self.assertEqual(index.inventories['canonical.rs'], (first,))
        self.assertEqual(index.inventories['one/example.rs'], (first,))
        self.assertEqual(index.name_counts['same'], 2)
        self.assertIs(index.owners, owners)
        self.assertIs(index.files, files)

    def test_cached_positive_inventory_avoids_whole_owner_rescans_with_identical_proof(self):
        original = coverage.positive_source_fragments
        class ObservedOwners(list):
            scans = 0
            def __iter__(self):
                self.scans += 1
                return super().__iter__()
        def compare(*arguments, **keywords):
            expected = original(*arguments, **keywords)
            current = list(arguments)
            current[5:7] = [ObservedOwners(value) for value in current[5:7]]
            groups = tuple(coverage._compiled_function_groups(current[0], current[5 + side],
                current[7 + side], current[1 + side], [20_000_000]) for side in (0, 1))
            indexes = tuple(coverage.index_compiled_owner_sources(current[5 + side], current[7 + side],
                [20_000_000]) for side in (0, 1))
            for owners in current[5:7]:
                owners.scans = 0
            observed = original(*current, **keywords, compiled_groups=groups, owner_indexes=indexes)
            self.assertEqual(observed, expected)
            self.assertEqual([owners.scans for owners in current[5:7]], [0, 0])
            return observed
        with patch.object(coverage, 'positive_source_fragments', side_effect=compare):
            self.async_positive_fragment_compare()

    def test_cached_positive_inventory_preserves_suffix_collisions_and_unrelated_duplicates(self):
        original = coverage.positive_source_fragments
        for mode in ('suffix-collision', 'unrelated-duplicate', 'incomplete-closed-inventory',
                     'different-owners', 'different-files', 'missing-query', 'appended-owner'):
            with self.subTest(mode=mode):
                def compare(*arguments, **keywords):
                    current = copy.deepcopy(list(arguments))
                    groups = [coverage._compiled_function_groups(current[0], current[5 + side],
                        current[7 + side], current[1 + side], [20_000_000]) for side in (0, 1)]
                    if mode in ('suffix-collision', 'unrelated-duplicate'):
                        owner = copy.deepcopy(current[6][0])
                        owner['filenames'] = ['/other/example.rs' if mode == 'suffix-collision'
                                              else '/other/unrelated.rs']
                        if mode == 'suffix-collision':
                            owner['name'] = 'different-owner'
                        current[6].append(owner)
                        current[8][owner['filenames'][0]] = 'different-canonical.rs'
                        with self.assertRaises(ValueError):
                            original(*current, **keywords, compiled_groups=groups)
                    if mode == 'incomplete-closed-inventory':
                        inventory, valid, names = groups[1]
                        groups[1] = (inventory[:-1], valid, names)
                    indexes = [coverage.index_compiled_owner_sources(current[5 + side], current[7 + side],
                        [20_000_000], {'elsewhere.rs'} if mode == 'missing-query' else {'example.rs'})
                        for side in (0, 1)]
                    if mode == 'different-owners':
                        current[6] = list(current[6])
                    elif mode == 'different-files':
                        current[8] = dict(current[8])
                    elif mode == 'appended-owner':
                        current[6].append(copy.deepcopy(current[6][0]))
                    return original(*current, **keywords, compiled_groups=groups, owner_indexes=indexes)
                with patch.object(coverage, 'positive_source_fragments', side_effect=compare):
                    with self.assertRaises(ValueError):
                        self.async_positive_fragment_compare()

    def test_owner_inventory_index_refuses_before_unadmitted_owner_traversal(self):
        class UnadmittedOwners(list):
            def __iter__(self):
                raise AssertionError('owner traversal before work admission')
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage.index_compiled_owner_sources(UnadmittedOwners([{}]), {}, [0])

    def test_lifetime_method_prefixes_bind_the_complete_lexical_body(self):
        source = ["impl Source for Fixture {", "    fn assess<'a>(",
                  "        &'a self, packages: &'a [Package],", ") -> Result<Value> {",
                  "        checked();", "    }", "}"]
        prefixes = coverage.source_function_prefixes(source, [(2, 6)])
        self.assertEqual(prefixes, {(2, 6): "\n".join(source[1:4]).split(" ->")[0]})
        for header in ("    fn assess<T>(", "    fn assess<'a: 'b>("):
            with self.subTest(header=header):
                self.assertEqual(coverage.source_function_prefixes(
                    [source[0], header, *source[2:]], [(2, 6)]), {})

    def test_trait_replacement_parents_preserve_impl_type_trait_and_item_scope(self):
        original = '_RNvXNtNtNtNtNtCs40j12eeWnis_7omg_lib3cli8packages7install4arch5testsNtB2_13FixtureSourceNtNtNtNtBc_4core8security13vulnerability19VulnerabilitySource12scan_package'
        current = original.replace('s40j12eeWnis_', 'sjVdvAHsNP8N_').replace('12scan_package', '15assess_packages')
        parent = coverage.replacement_raw_parent(original, 'scan_package')
        self.assertIsNotNone(parent)
        self.assertEqual(parent, coverage.replacement_raw_parent(current, 'assess_packages'))
        for different in (original.replace('13FixtureSource', '13AnotherSource'),
                          original.replace('19VulnerabilitySource', '19VulnerabilityOther'),
                          original.replace('_RNvX', '_RNvXs_'),
                          original.replace('5tests', 's_5tests')):
            with self.subTest(symbol=different):
                self.assertNotEqual(parent, coverage.replacement_raw_parent(different, 'scan_package'))
        for invalid in (original + 'C3foo', original + '.llvm.1',
                        original.replace('B2_', 'Bz_'), original[:-1],
                        original.replace('NtNtNtNtBc_', 'NtNtNtNtCs123_7omg_lib')):
            with self.subTest(symbol=invalid):
                self.assertIsNone(coverage.replacement_raw_parent(invalid, 'scan_package'))

    def test_trait_closure_paths_rebase_backreferences_and_preserve_crate_copies(self):
        parent = '_RNvXNtNtNtNtNtCs40j12eeWnis_7omg_lib3cli8packages7install4arch5testsNtB2_13FixtureSourceNtNtNtNtBc_4core8security13vulnerability19VulnerabilitySource12scan_package'
        path = coverage.nominal_method_path(parent)
        for prefix, self_ref, trait_ref, suffix, depth in (
                ('_RNC', 'B4_', 'Be_', '0Be_', 1),
                ('_RNCNC', 'B6_', 'Bg_', '00Bg_', 2)):
            raw = prefix + parent[2:].replace('B2_', self_ref).replace('Bc_', trait_ref) + suffix
            child = coverage.nominal_method_path(raw)
            self.assertIsNotNone(child)
            self.assertEqual(child.copy_identity, path.copy_identity)
            self.assertEqual(child.callbacks, ('',) * depth)
            other = coverage.nominal_method_path(raw.replace('s40j12eeWnis_', 's99_'))
            self.assertNotEqual(other.copy_identity, path.copy_identity)
            self.assertIsNone(coverage.nominal_method_parent(raw))
            self.assertIsNone(coverage.nominal_method_path(raw.replace(self_ref, 'B2_')))

    def test_default_trait_methods_preserve_nominal_and_instantiating_crate_identity(self):
        symbols = [
            ('_RNvYNtNtNtCsaJq9CMLDmry_7omg_lib16package_managers4mock18MockPackageManagerNtNtB6_6traits14PackageManager18security_inventoryB8_',
             '_RNCNvYNtNtNtCsaJq9CMLDmry_7omg_lib16package_managers4mock18MockPackageManagerNtNtB8_6traits14PackageManager18security_inventory0Ba_'),
            ('_RNvYNtNtNtCs4c7pFuLdASW_21daemon_security_tests6common5mocks18MockPackageManagerNtNtNtCsaJq9CMLDmry_7omg_lib16package_managers6traits14PackageManager18security_inventoryB8_',
             '_RNCNvYNtNtNtCs4c7pFuLdASW_21daemon_security_tests6common5mocks18MockPackageManagerNtNtNtCsaJq9CMLDmry_7omg_lib16package_managers6traits14PackageManager18security_inventory0Ba_'),
        ]
        for parent, child in symbols:
            with self.subTest(symbol=parent):
                decoded = coverage.nominal_method_path(parent)
                self.assertIsNotNone(decoded, 'valid compiler-emitted default trait method was refused')
                nested = coverage.nominal_method_path(child)
                self.assertIsNotNone(nested)
                self.assertEqual(decoded.method, ('security_inventory', ''))
                self.assertEqual(decoded.callbacks, ())
                self.assertEqual(nested.callbacks, ('',))
                self.assertEqual(nested.copy_identity, decoded.copy_identity)
                self.assertNotEqual(coverage.nominal_method_path(child.replace('CsaJq9CMLDmry_', 'Cs99_')).copy_identity,
                                    decoded.copy_identity)
                self.assertIsNone(coverage.nominal_method_path(parent + '.llvm.1'))
                self.assertIsNone(coverage.nominal_method_path(child.replace('Ba_', 'B2_')))
        foreign = symbols[1][1]
        self.assertIsNotNone(coverage.nominal_method_path(foreign))
        self.assertNotEqual(coverage.nominal_method_path(foreign.replace('Cs4c7pFuLdASW_', 'Cs98_')).copy_identity,
                            coverage.nominal_method_path(foreign).copy_identity)

    def test_inherent_method_callbacks_preserve_impl_and_crate_scope(self):
        parent = '_RNvMs0_NtNtNtCsbXaNnEHeRiG_7omg_lib4core8security4scanNtB5_19SecurityAuditResult15validate_counts'
        child = '_RNCNvMs0_NtNtNtCsbXaNnEHeRiG_7omg_lib4core8security4scanNtB7_19SecurityAuditResult15validate_countss_0Bd_'
        decoded = coverage.nominal_method_path(parent)
        self.assertIsNotNone(decoded, 'valid compiler-emitted inherent method was refused')
        nested = coverage.nominal_method_path(child)
        self.assertIsNotNone(nested)
        self.assertEqual(decoded.copy_identity, nested.copy_identity)
        self.assertEqual(nested.callbacks, ('s_',))
        self.assertNotEqual(coverage.nominal_method_path(child.replace('Ms0_', 'Ms1_')).copy_identity,
                            decoded.copy_identity)

    def migrated_trait_compare(self, mutation=None, callback=False, method_kind='X', receiver_only=False,
                               multiline_header=False, duplicate_seed=False, retained_tail=False,
                               local_duplicate=False, test_scope=True):
        old = b"impl Source for FixtureSource {\n    fn scan_package<'a>(\n        &'a self,\n        name: &'a str,\n    ) -> Result<Value> {\n        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);\n        old_step();\n    }\n}\n"
        if method_kind == 'M':
            old = old.replace(b'impl Source for FixtureSource {', b'impl FixtureSource {')
        elif method_kind == 'Y':
            old = old.replace(b'impl Source for FixtureSource {', b'trait Source {')
        if callback:
            old = old.replace(b'        old_step();', b'        Box::pin(async move {\n            old_step();\n        })')
        if retained_tail:
            old = old.replace(b'            old_step();', b'            old_step();\n            Vec::new()')
        if multiline_header:
            old = old.replace(b') -> Result<Value> {',
                b') -> Pin<\n        Box<\n            Result<Value>,\n        >,\n    > {')
        new = old.replace(b'scan_package', b'assess_packages').replace(
            b"name: &'a str", b"packages: &'a [Package]").replace(b'Result<Value>', b'Result<Assessment>').replace(b'old_step()', b'new_step()')
        if retained_tail:
            new = new.replace(b'            Vec::new()', b'                    Vec::new()')
        if receiver_only:
            old = old.replace(b'impl Source', b'#[cfg(test)] impl Source')
            new = new.replace(b'impl Source', b'#[cfg(test)] impl Source').replace(b'fetch_add', b'fetch_sub')
        elif duplicate_seed and test_scope:
            old = old.replace(b'impl Source', b'#[cfg(test)] impl Source')
            new = new.replace(b'impl Source', b'#[cfg(test)] impl Source')
        original = '_RNvXNtNtNtNtNtCs40j12eeWnis_7omg_lib3cli8packages7install4arch5testsNtB2_13FixtureSourceNtNtNtNtBc_4core8security13vulnerability19VulnerabilitySource12scan_package'
        crate = 'Cs40j12eeWnis_7omg_lib'
        if method_kind == 'M':
            original = '_RNvM' + crate + 'Nt' + crate + '13FixtureSource12scan_package'
        elif method_kind == 'Y':
            original = '_RNvYNt' + crate + '13FixtureSourceNt' + crate + '6Source12scan_package' + crate
        current = original.replace('s40j12eeWnis_', 'sjVdvAHsNP8N_').replace('12scan_package', '15assess_packages')
        def owners(base, head):
            for document, source, symbol in ((base, old, original), (head, new, current)):
                lines = source.decode().splitlines()
                end = len(lines) - 1
                header_end = 9 if multiline_header else 5
                body = header_end + 1
                document['data'][0]['functions'] = [dict(name=symbol, count=1,
                    filenames=['/src/example.rs'], regions=[
                        [2, 5, header_end, len(lines[header_end - 1]), 1, 0, 0, 0],
                        *[[line, 9 if line < end else 5, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                          for line in ([body, body + 1, end] if callback else range(body, end + 1))]])]
                if callback:
                    rebased = symbol[2:].replace('B2_', 'B4_').replace('Bc_', 'Be_')
                    child = '_RNC' + rebased + '0Be_'
                    if method_kind == 'M':
                        child = '_RNC' + symbol[2:] + '0'
                    elif method_kind == 'Y':
                        root = crate if symbol == original else crate.replace('s40j12eeWnis_', 'sjVdvAHsNP8N_')
                        child = '_RNC' + symbol[2:-len(root)] + '0' + root
                    document['data'][0]['functions'].append(dict(name=child,
                        count=1, filenames=['/src/example.rs'], regions=[
                            [body + 1, lines[body].index('{') + 1, end - 1, 10, 1, 0, 0, 0],
                            *[[line, len(lines[line - 1]) - len(lines[line - 1].lstrip()) + 1,
                               line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                              for line in range(body + 2, end - 1)]]))
            if mutation:
                mutation(base, head)
        source_maps = ({'example.rs': old}, {'example.rs': new})
        if duplicate_seed:
            unrelated = (b'impl OtherTransport {\n    fn record(&self) {\n'
                b'        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);\n    }\n}\n')
            for source_map in source_maps:
                if local_duplicate:
                    source_map['example.rs'] += unrelated
                else:
                    source_map['other.rs'] = unrelated
        return self.compare(before=[(line, 1) for line in range(2, len(old.splitlines()))],
            after=[(line, 1) for line in range(2, len(new.splitlines()))], mutate=owners,
            sources=source_maps)

    def test_migrated_trait_retains_seed_and_header_without_deletion_credit(self):
        receipt = self.migrated_trait_compare()
        self.assertEqual([receipt[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertTrue(receipt['retained_replacement_obligations'])

    def test_test_only_migrated_receiver_has_declaration_only_proof_without_body_seed(self):
        observed = []
        original = coverage.test_declaration_header_obligations
        def inspect(*arguments):
            result = original(*arguments)
            observed.append(result)
            return result
        with patch.object(coverage, 'test_declaration_header_obligations', side_effect=inspect):
            with self.assertRaisesRegex(ValueError, r'example.rs:7 -> 7'):
                self.migrated_trait_compare(receiver_only=True, callback=True)
        proof, = [row[1] for row in observed if row is not None]
        self.assertEqual(proof['pairs'], [[3, 3]])
        self.assertEqual(proof['summary_credit'], [0, 0])
        self.assertEqual(proof['mapped_credit'], [0, 0])

    def declaration_receiver_fixture(self, multiline_header=False):
        observed = []
        original = coverage.test_declaration_header_obligations
        def inspect(*arguments):
            observed.append(arguments)
            return original(*arguments)
        with patch.object(coverage, 'test_declaration_header_obligations', side_effect=inspect):
            line = 11 if multiline_header else 7
            with self.assertRaisesRegex(ValueError, f'example.rs:{line} -> {line}'):
                self.migrated_trait_compare(receiver_only=True, callback=True, multiline_header=multiline_header)
        arguments, = observed
        return arguments

    def test_test_declaration_header_proves_only_exact_entry_painted_type_lines(self):
        observed = []
        original = coverage.test_declaration_header_obligations
        def inspect(*arguments):
            result = original(*arguments)
            observed.append(result)
            return result
        with patch.object(coverage, 'test_declaration_header_obligations', side_effect=inspect):
            with self.assertRaisesRegex(ValueError, r'example.rs:11 -> 11'):
                self.migrated_trait_compare(receiver_only=True, callback=True, multiline_header=True)
        proof, = [row[1] for row in observed if row is not None]
        self.assertEqual(proof['pairs'], [[3, 3], [5, 5], [6, 6], [8, 8]])
        self.assertEqual(proof['summary_credit'], [0, 0])
        self.assertEqual(proof['mapped_credit'], [0, 0])

    def test_test_receiver_proof_rejects_wrong_context_or_incomplete_compiler_copy(self):
        original = self.declaration_receiver_fixture()
        for mode in ('non-test', 'context', 'attributes', 'self-type', 'trait', 'impl',
                     'cold-entry', 'cold-region', 'overlapping-cold-region', 'callback-only',
                     'unrelated-paint', 'missing-copy', 'additional-copy', 'typed-receiver',
                     'mixed-line', 'changed-receiver', 'missing-mapping'):
            with self.subTest(mode=mode):
                arguments = copy.deepcopy(list(original))
                arguments[-1] = [20_000_000]
                sources, counts, descriptors, inventories, grouped = arguments[1:6]
                left, right = descriptors
                owner = right['group'][2][0]
                if mode == 'non-test':
                    for descriptor in descriptors:
                        descriptor['context'] = ((), descriptor['context'][1])
                elif mode == 'context':
                    right['context'] = (right['context'][0], ('changed_import',))
                elif mode == 'attributes':
                    right['attributes'] = ['unsafe']
                elif mode in ('self-type', 'trait', 'impl'):
                    old, new = {'self-type': ('13FixtureSource', '13AnotherSource'),
                                'trait': ('19VulnerabilitySource', '19VulnerabilityOther'),
                                'impl': ('_RNvX', '_RNvXs_')}[mode]
                    owner['name'] = owner['name'].replace(old, new)
                elif mode == 'cold-entry':
                    owner['count'] = 0
                elif mode == 'cold-region':
                    owner['regions'][0][4] = 0
                elif mode == 'overlapping-cold-region':
                    owner['regions'].append([3, 9, 3, 17, 0, 0, 0, 0])
                elif mode == 'callback-only':
                    owner['name'] = grouped[1][0][1]['name']
                elif mode == 'unrelated-paint':
                    grouped[1][0].append(dict(name='unrelated', count=1,
                        filenames=['/src/example.rs'], regions=[[3, 9, 3, 17, 1, 0, 0, 0]]))
                elif mode == 'missing-copy':
                    right['group'][2].clear()
                elif mode == 'additional-copy':
                    right['group'][2].append(copy.deepcopy(owner))
                elif mode == 'typed-receiver':
                    right['row']['header'] = tuple('fn changed ( self : Box < Self > , )'.split())
                elif mode in ('mixed-line', 'changed-receiver'):
                    sources[1][2] = ("        &'a self, other: usize," if mode == 'mixed-line'
                                     else "        &'a mut self,")
                elif mode == 'missing-mapping':
                    counts[1].pop(3)
                self.assertIsNone(coverage.test_declaration_header_obligations(*arguments))

    def test_test_receiver_proof_keeps_all_copies_and_refuses_a_cold_second_copy(self):
        arguments = copy.deepcopy(list(self.declaration_receiver_fixture()))
        arguments[-1] = [20_000_000]
        for side, descriptor in enumerate(arguments[3]):
            owner = copy.deepcopy(descriptor['group'][2][0])
            owner['name'] = owner['name'].replace('Cs40j12eeWnis_', 'Cs99_').replace('CsjVdvAHsNP8N_', 'Cs99_')
            descriptor['group'][2].append(owner)
            arguments[5][side][0].append(owner)
        proof = coverage.test_declaration_header_obligations(*arguments)
        self.assertIsNotNone(proof)
        self.assertEqual([len(side) for side in proof[1]['test_declaration_header']['owners']], [2, 2])
        arguments[3][1]['group'][2][1]['regions'][0][4] = 0
        self.assertIsNone(coverage.test_declaration_header_obligations(*arguments))

    def test_test_declaration_header_refuses_expression_grammar_and_changed_type_credit(self):
        original = self.declaration_receiver_fixture(multiline_header=True)
        for replacement in ('TypeMacro!()', 'Array<7>', 'fn()', 'Wrapper<{ cold() }>',
                            'Result<Value> where Self: Trait', 'extern "C" fn()'):
            with self.subTest(replacement=replacement):
                arguments = copy.deepcopy(list(original))
                arguments[-1] = [20_000_000]
                for side in (0, 1):
                    source = arguments[1][side]
                    source[6] = '            ' + replacement + ','
                    inventory = coverage._construct_inventory(source, [20_000_000])
                    arguments[4] = tuple(inventory if index == side else value
                                         for index, value in enumerate(arguments[4]))
                    rows = [row for row in inventory[1] if row['kind'] == 'fn']
                    if len(rows) == 1:
                        arguments[3][side]['row'] = rows[0]
                self.assertIsNone(coverage.test_declaration_header_obligations(*arguments))
        arguments = copy.deepcopy(list(original))
        arguments[-1] = [20_000_000]
        arguments[1][1][5] = '        Arc<'
        inventory = coverage._construct_inventory(arguments[1][1], [20_000_000])
        arguments[4] = (arguments[4][0], inventory)
        arguments[3][1]['row'] = next(row for row in inventory[1] if row['kind'] == 'fn')
        pairs, proof = coverage.test_declaration_header_obligations(*arguments)
        self.assertNotIn(6, pairs, 'Changed type tokens cannot receive retained credit')
        self.assertNotIn(7, pairs, 'Changed result type cannot receive retained credit')
        self.assertNotIn(9, pairs, 'A body-opening line is outside the complete declaration slice')
        self.assertNotIn(11, pairs, 'An async body is outside the declaration slice')
        self.assertEqual(proof['summary_credit'], [0, 0])

    def test_fully_covered_trait_migration_keeps_complete_async_owner_inventory(self):
        receipt = self.migrated_trait_compare(callback=True)
        self.assertEqual([receipt[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        proofs = receipt['retained_replacement_obligations']
        self.assertTrue(any(row.get('fully_covered_replacement_owners') for row in proofs))

    def test_qualified_test_seed_requires_full_owner_proof_when_other_type_repeats_statement(self):
        receipt = self.migrated_trait_compare(callback=True, duplicate_seed=True)
        proof, = [row for row in receipt['retained_replacement_obligations']
                  if row.get('qualified_test_statement')]
        self.assertIn([6, 6], proof['pairs'])
        self.assertEqual([len(side) for side in proof['fully_covered_replacement_owners']], [2, 2])
        self.assertEqual(proof['summary_credit'], [0, 0])
        self.assertEqual(proof['mapped_credit'], [0, 0])
        self.assertEqual(receipt['deleted_mapped'], 0)

    def test_qualified_test_seed_explicitly_proves_reindented_short_retained_body_statement(self):
        receipt = self.migrated_trait_compare(callback=True, duplicate_seed=True, retained_tail=True)
        proof, = [row for row in receipt['retained_replacement_obligations']
                  if row.get('qualified_test_statement')]
        statements = proof['qualified_test_statement']['statements']
        self.assertEqual(len(statements), 2)
        self.assertTrue(any(row['pair'] == [9, 9] for row in statements))
        self.assertIn([9, 9], proof['pairs'])
        self.assertTrue(all(row['owners'][0] and row['owners'][1] for row in statements))

    def test_qualified_test_seed_has_no_partial_fallback_when_full_owner_proof_fails(self):
        with patch.object(coverage, 'fully_covered_replacement', return_value=None):
            with self.assertRaisesRegex(ValueError, r'example.rs:6 -> 6'):
                self.migrated_trait_compare(callback=True, duplicate_seed=True)

    def test_qualified_test_seed_refuses_file_ambiguity_and_production_scope(self):
        for options in ({'local_duplicate': True}, {'test_scope': False}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.migrated_trait_compare(callback=True, duplicate_seed=True, **options)

    def test_qualified_statement_requires_complete_unique_matching_positive_region_evidence(self):
        observed = []
        original = coverage.qualified_test_retained_statements
        def inspect(*arguments):
            observed.append(arguments)
            return original(*arguments)
        with patch.object(coverage, 'qualified_test_retained_statements', side_effect=inspect):
            self.migrated_trait_compare(callback=True, duplicate_seed=True, retained_tail=True)
        arguments, = observed
        digest = arguments[6][0][0]['digest']
        for mode in ('duplicate-row', 'duplicate-file', 'missing-digest', 'unowned-paint',
                     'cold-region', 'changed-geometry', 'changed-source', 'missing-full-owner'):
            with self.subTest(mode=mode):
                current = copy.deepcopy(list(arguments)); current[-1] = [20_000_000]
                if mode == 'duplicate-row':
                    current[1][1]['statements'][digest].append(copy.deepcopy(current[1][1]['statements'][digest][0]))
                elif mode == 'duplicate-file':
                    current[4][1][digest] = 2
                elif mode == 'missing-digest':
                    current[5].append({'retained_statements': ['missing-statement']})
                elif mode == 'unowned-paint':
                    current[3][1][0].append(dict(name='unowned', count=1,
                        regions=[[6, 9, 6, 20, 1, 0, 0, 0]]))
                elif mode in ('cold-region', 'changed-geometry'):
                    parent = next(owner for owner in current[3][1][0] if owner['name'].startswith('_RNv'))
                    region = next(region for region in parent['regions'] if region[0] == 6)
                    if mode == 'cold-region':
                        region[4] = 0
                    else:
                        region[3] -= 1
                elif mode == 'changed-source':
                    current[0][1][5] = current[0][1][5].replace('fetch_add', 'fetch_sub')
                elif mode == 'missing-full-owner':
                    current[7]['fully_covered_replacement_owners'][1].clear()
                self.assertIsNone(original(*current))

    def test_qualified_test_seed_refuses_cold_missing_foreign_or_duplicate_child(self):
        observed = []
        original = coverage.fully_covered_replacement
        def inspect(*arguments):
            observed.append(arguments)
            return original(*arguments)
        with patch.object(coverage, 'fully_covered_replacement', side_effect=inspect):
            self.migrated_trait_compare(callback=True, duplicate_seed=True)
        arguments, = observed
        for mode in ('cold-entry', 'cold-region', 'missing-child', 'foreign-child', 'duplicate-child'):
            with self.subTest(mode=mode):
                current = copy.deepcopy(list(arguments)); current[-1] = [20_000_000]
                owners = current[6][1][0]
                child = next(owner for owner in owners if owner['name'].startswith('_RNC'))
                if mode == 'cold-entry':
                    child['count'] = 0
                elif mode == 'cold-region':
                    child['regions'][-1][4] = 0
                elif mode == 'missing-child':
                    owners.remove(child)
                elif mode == 'foreign-child':
                    child['name'] = child['name'].replace('13FixtureSource', '13AnotherSource')
                    current[6][1][2][child['name']] = 1
                elif mode == 'duplicate-child':
                    owners.append(copy.deepcopy(child))
                    current[6][1][2][child['name']] = 2
                self.assertIsNone(original(*current))

    def test_qualified_statement_admits_union_work_before_traversing_retained_lists(self):
        observed = []
        original = coverage.qualified_test_retained_statements
        def inspect(*arguments):
            observed.append(arguments)
            return original(*arguments)
        with patch.object(coverage, 'qualified_test_retained_statements', side_effect=inspect):
            self.migrated_trait_compare(callback=True, duplicate_seed=True)
        arguments, = observed
        class UnadmittedList(list):
            def __iter__(self):
                raise AssertionError('retained list traversed before work admission')
        current = copy.deepcopy(list(arguments))
        current[5] = [{'retained_statements': UnadmittedList(['digest'] * 100)}]
        current[-1] = [len(current[6]) + len(current[5])]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            original(*current)

    def test_fully_covered_nominal_method_migrations_preserve_every_owner(self):
        for kind in ('M', 'Y'):
            with self.subTest(kind=kind):
                receipt = self.migrated_trait_compare(callback=True, method_kind=kind)
                self.assertTrue(any(row.get('fully_covered_replacement_owners')
                                    for row in receipt['retained_replacement_obligations']))
                self.assertEqual(receipt['deleted_mapped'], 0)
                self.assertEqual(receipt['deleted_summary_found'], 0)

    def unseeded_nominal_compare(self, mutation=None, callback=False, ambiguous=False):
        body = ('        #[cfg(unix)]\n        return self\n            .status\n'
                '            .as_ref()\n            .and_then(CALL);\n'
                '        #[cfg(not(unix))]\n        None\n    }\n')
        old = ('impl App {\n    pub fn old_count(&self) -> Option<usize> {\n'
               + body.replace('CALL', 'old_value')
               + '    pub fn stable_count(&self) -> Option<usize> {\n'
               + body.replace('CALL', 'stable_value') + '}\n').encode()
        new = old.replace(b'old_count', b'new_summary').replace(
            b'old_value', b'new_value').replace(
            b'new_summary(&self) -> Option<usize>', b'new_summary(&self) -> Option<(usize, usize)>')
        if callback:
            new = new.replace(b'return self', b'return (|| self', 1).replace(
                b'.and_then(new_value);', b'.and_then(new_value))();', 1)
        if ambiguous:
            new = new.replace(b'stable_count', b'other_count')
        def owners(base, head):
            for document, source, method in ((base, old, 'old_count'), (head, new, 'new_summary')):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = []
                stable = 'other_count' if ambiguous and document is head else 'stable_count'
                for name, first in ((method, 2), (stable, 11)):
                    last = first + 8
                    rows = [[first, 5, first, len(lines[first - 1]) + 1, 1, 0, 0, 0],
                            [first + 2, 16, first + 3, 20, 1, 0, 0, 0],
                            [first + 4, 14, first + 4, 20, 1, 0, 0, 0],
                            [first + 5, 14, first + 5, 22, 1, 0, 0, 0],
                            [last, 5, last, 6, 1, 0, 0, 0]]
                    for instance in (1, 2):
                        crate = f'Cs{instance}_7example'
                        document['data'][0]['functions'].append(dict(
                            name=f'_RNvM{crate}Nt{crate}3App{len(name)}{name}', count=1,
                            filenames=['/src/example.rs'], regions=copy.deepcopy(rows)))
            if mutation:
                mutation(base, head)
        mapped = [line for first in (2, 11) for line in
                  (first, first + 2, first + 3, first + 4, first + 5, first + 8)]
        return self.compare(before=[(line, 2) for line in mapped],
            after=[(line, 2) for line in mapped], mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))

    def test_distinct_method_scope_queries_decode_the_complete_inventory_once(self):
        original = coverage.retained_replacement_obligations
        observed = []
        def inspect(*arguments, **keywords):
            lookup = arguments[-1]
            shapes = [coverage.nominal_method_parent(owner['name'], inventory=True)
                      for owner in arguments[6][0][0]]
            parent = next(shape for shape in shapes if shape is not None)
            foreign = (parent[0], parent[1] + ':foreign')
            with patch.object(coverage, 'nominal_method_parent',
                              wraps=coverage.nominal_method_parent) as decode:
                self.assertEqual(lookup(parent), {'example.rs'})
                self.assertEqual(lookup(foreign), set())
                self.assertEqual(lookup(('raw-parent', parent[1])), set())
                self.assertEqual(lookup(parent), {'example.rs'})
            observed.append((decode.call_count, len(arguments[6][0][0])))
            return original(*arguments, **keywords)
        with patch.object(coverage, 'retained_replacement_obligations', side_effect=inspect):
            self.unseeded_nominal_compare()
        self.assertTrue(observed)
        for calls, owners in observed:
            self.assertEqual(calls, owners, 'Each raw owner should be decoded once across method scopes')

    def test_method_migration_refuses_unrecognized_owner_in_unattributed_source(self):
        def unknown(base, head):
            base['data'][0]['functions'].append(dict(name='opaque', count=1,
                filenames=['/external/unknown.rs'], regions=[[100, 1, 100, 2, 1, 0, 0, 0]]))
        with self.assertRaises(ValueError):
            self.unseeded_nominal_compare(unknown)

    def test_fully_covered_public_method_migration_needs_no_unchanged_statement_seed(self):
        receipt = self.unseeded_nominal_compare()
        proof, = receipt['retained_replacement_obligations']
        self.assertEqual([len(side) for side in proof['fully_covered_replacement_owners']], [2, 2])
        self.assertEqual(receipt['deleted_mapped'], 0)
        self.assertEqual(receipt['deleted_summary_found'], 0)
        self.assertTrue(all([line, line] in proof['pairs'] for line in (4, 5, 6, 10)))

    def test_unseeded_method_migration_refuses_incomplete_or_cold_owner_inventory(self):
        def mutate(base, head, mode):
            owners = head['data'][0]['functions']
            owner = owners[0]
            if mode == 'cold-entry':
                owner['count'] = 0
            elif mode == 'cold-base-entry':
                base['data'][0]['functions'][0]['count'] = 0
            elif mode == 'cold-region':
                owner['regions'][2][4] = 0
            elif mode == 'missing-copy':
                owners.pop(0)
            elif mode == 'duplicate-copy':
                owners.append(copy.deepcopy(owner))
            elif mode == 'foreign-owner':
                extra = copy.deepcopy(owner); extra['name'] = 'foreign'
                owners.append(extra)
            elif mode == 'extra-callback':
                extra = copy.deepcopy(owner)
                extra['name'] = extra['name'].replace('_RNvM', '_RNCNvM') + '0'
                extra['regions'] = extra['regions'][1:2]
                owners.append(extra)
            elif mode == 'wrong-implementation':
                for item in owners[:2]:
                    item['name'] = item['name'].replace('_RNvM', '_RNvMs0_')
            elif mode == 'wrong-self-type':
                for item in owners[:2]:
                    item['name'] = item['name'].replace('3App', '5Other')
        for mode in ('cold-entry', 'cold-base-entry', 'cold-region', 'missing-copy', 'duplicate-copy',
                     'foreign-owner', 'extra-callback', 'wrong-implementation', 'wrong-self-type'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.unseeded_nominal_compare(lambda base, head: mutate(base, head, mode))

    def test_unseeded_migration_does_not_infer_a_missing_callback_owner(self):
        with self.assertRaises(ValueError):
            self.unseeded_nominal_compare(callback=True)

    def test_unseeded_migration_does_not_select_between_renamed_siblings(self):
        with self.assertRaises(ValueError):
            self.unseeded_nominal_compare(ambiguous=True)

    def test_unseeded_migration_spends_the_original_shared_work_budget(self):
        original = coverage.fully_covered_replacement
        def exhausted(*args):
            arguments = list(args); arguments[-1] = [0]
            return original(*arguments)
        with patch.object(coverage, 'fully_covered_replacement', side_effect=exhausted), \
                self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            self.unseeded_nominal_compare()

    def test_nominal_method_migration_cannot_borrow_coverage_from_another_copy(self):
        def mutate(base, head, mode):
            child = head['data'][0]['functions'][1]
            if mode == 'cold-entry':
                child['count'] = 0
            elif mode == 'cold-region':
                child['regions'][1][4] = 0
            else:
                child['name'] = child['name'].replace('sjVdvAHsNP8N_', 's99_')
        for kind in ('M', 'Y'):
            for mode in ('cold-entry', 'cold-region', 'foreign-copy'):
                with self.subTest(kind=kind, mode=mode), self.assertRaises(ValueError):
                    self.migrated_trait_compare(callback=True, method_kind=kind,
                        mutation=lambda base, head: mutate(base, head, mode))

    def test_nominal_migration_keeps_multiple_compiled_copy_states_separate(self):
        def copies(base, head, cold):
            for document in (base, head):
                duplicates = copy.deepcopy(document['data'][0]['functions'])
                for owner in duplicates:
                    owner['name'] = re.sub(r'Cs(?:40j12eeWnis|jVdvAHsNP8N)_', 'Cs88_', owner['name'])
                if cold and document is head:
                    duplicates[1]['count'] = 0
                    for region in duplicates[1]['regions']:
                        region[4] = 0
                document['data'][0]['functions'].extend(duplicates)
        for kind in ('M', 'Y'):
            with self.subTest(kind=kind):
                receipt = self.migrated_trait_compare(callback=True, method_kind=kind,
                    mutation=lambda base, head: copies(base, head, False))
                proof = next(row for row in receipt['retained_replacement_obligations']
                             if row.get('fully_covered_replacement_owners'))
                self.assertEqual([len(side) for side in proof['fully_covered_replacement_owners']], [4, 4])
                with self.assertRaises(ValueError):
                    self.migrated_trait_compare(callback=True, method_kind=kind,
                        mutation=lambda base, head: copies(base, head, True))

    def test_nominal_decoder_refuses_unsupported_or_ambiguous_paths(self):
        original = '_RNvYNtNtNtCs4c7pFuLdASW_21daemon_security_tests6common5mocks18MockPackageManagerNtNtNtCsaJq9CMLDmry_7omg_lib16package_managers6traits14PackageManager18security_inventoryB8_'
        for invalid in (original + '.llvm.1', original + 'junk', original[:-1],
                        original.replace('B8_', 'Bz_'), original.replace('B8_', 'B1_'),
                        original.replace('B8_', 'NtB8_6nested'),
                        original.replace('_RNvY', '_RNvI'),
                        original.replace('CsaJq9CMLDmry_7omg_lib', 'Cs99_21daemon_security_tests'),
                        original.replace('Y', 'Y' + 'Nt' * 17, 1)):
            with self.subTest(invalid=invalid):
                self.assertIsNone(coverage.nominal_method_path(invalid))
        first = coverage.nominal_method_path(original)
        self.assertIsNotNone(first)
        other = coverage.nominal_method_path(original[:-3] + 'C5other')
        self.assertIsNotNone(other)
        self.assertNotEqual(first.copy_identity, other.copy_identity)
        self.assertEqual(first.parent_scope, other.parent_scope)

    def test_trait_async_proof_refuses_incomplete_cold_or_foreign_owner_trees(self):
        def mutate(base, head, mode):
            owners = head['data'][0]['functions']
            child = owners[1]
            if mode == 'cold-region':
                child['regions'][1][4] = 0
            elif mode == 'cold-entry':
                child['count'] = 0
            elif mode == 'missing-child':
                owners.pop()
            elif mode == 'duplicate-child':
                owners.append(copy.deepcopy(child))
            elif mode == 'foreign-copy':
                child['name'] = child['name'].replace('sjVdvAHsNP8N_', 's99_')
            elif mode == 'foreign-method':
                child['name'] = child['name'].replace('15assess_packages', '15foreign_methodx')
            elif mode == 'crossing-boundary':
                child['regions'][0][2:4] = [11, 2]
            elif mode == 'unrebased-reference':
                child['name'] = child['name'].replace('B4_', 'B2_')
        for mode in ('cold-region', 'cold-entry', 'missing-child', 'duplicate-child',
                     'foreign-copy', 'foreign-method', 'crossing-boundary', 'unrebased-reference'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.migrated_trait_compare(lambda base, head: mutate(base, head, mode), callback=True)

    def test_migrated_trait_refuses_changed_identity_and_cold_retained_work(self):
        def mutate(base, head, mode):
            owner = head['data'][0]['functions'][0]
            if mode == 'type':
                owner['name'] = owner['name'].replace('13FixtureSource', '13AnotherSource')
            elif mode == 'impl':
                owner['name'] = owner['name'].replace('_RNvX', '_RNvXs_')
            elif mode == 'seed':
                owner['regions'][1][4] = 0
            elif mode == 'header':
                owner['regions'][0][4] = 0
        for mode in ('type', 'impl', 'seed', 'header'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.migrated_trait_compare(lambda base, head: mutate(base, head, mode))

    def caller_entry_compare(self, mutation=None, body=False):
        def fixture(operation):
            return (f'#[cfg(unix)]\n#[test]\nfn checked() {{\n'
                    f'    let path = vec![1];\n    caller(&path, || {{\n'
                    f'        {operation}();\n    }});\n}}\n')
        old = (fixture('before') + fixture('unchanged').replace('checked', 'sibling')).splitlines()
        new = (fixture('after') + fixture('unchanged').replace('checked', 'sibling')).splitlines()
        def owners(source):
            result = []
            for name, start in [('checked', 3), ('sibling', 11)]:
                line = start + 2
                call = source[line - 1]
                brace = call.index('{') + 1
                for copy in range(2):
                    parent = f'_RNvCs{copy + 1}_7example{len(name)}{name}'
                    result.extend([
                        dict(name=parent, count=2, filenames=['/src/example.rs'], regions=[
                            [start, 1, start, source[start-1].index('{')+1, 2, 0, 0, 0],
                            [line, 5, line, 11, 1, 0, 0, 0],
                            [line, 12, line, 17, 1, 0, 0, 0],
                            [start+5, 1, start+5, 2, 1, 0, 0, 0]]),
                        dict(name='_RNC'+parent[2:]+'0B3_', count=1,
                             filenames=['/src/example.rs'], regions=[
                                 [line, brace, line, brace+1, 1, 0, 0, 0],
                                 [line+1, 9, line+1, len(source[line])+1, 1, 0, 0, 0],
                                 [line+2, 5, line+2, 6, 1, 0, 0, 0]])])
            return result
        base, head = owners(old), owners(new)
        if mutation:
            mutation(old, new, base, head)
        span = (5, 6) if body else (5, 5)
        prefix = 'fn checked()'
        return coverage.positive_source_fragments(
            'example.rs', old, new, {n: 1 for n in range(1, 17)},
            {n: 1 for n in range(1, 17)}, base, head,
            {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'},
            [(span[0]-1, span[1], span[0]-1, span[1], list(range(span[0], span[1]+1)))],
            callback_functions=(prefix,))

    def test_closed_test_caller_entry_retains_every_parent_and_child_copy(self):
        pairs, receipts = self.caller_entry_compare()
        self.assertEqual(pairs, {5: 5})
        self.assertTrue(any(witness['kind'] == 'zero-arg-callback-call-entry'
                            for receipt in receipts for witness in receipt.get('callback_owners', [])))

    def test_caller_entry_refuses_missing_cold_foreign_or_ambiguous_authority(self):
        def mutate(old, new, base, head, mode):
            if mode == 'cold-child':
                head[1]['count'] = head[1]['regions'][0][4] = 0
            elif mode == 'cold-callee':
                head[0]['regions'][1][4] = 0
            elif mode == 'cold-argument':
                head[0]['regions'][2][4] = 0
            elif mode == 'disagreed-parent-entry':
                head[0]['count'] += 1
            elif mode == 'disagreed-child-entry':
                head[1]['count'] += 1
            elif mode == 'missing-copy':
                del head[2:4]
            elif mode == 'missing-child':
                del head[1]
            elif mode == 'duplicate-symbol':
                head.append(copy.deepcopy(head[1]))
            elif mode == 'foreign-overlap':
                head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                                 regions=[copy.deepcopy(head[1]['regions'][0])]))
            elif mode == 'wrong-parent':
                head[1]['name'] = head[1]['name'].replace('7checked', '7another')
            elif mode == 'foreign-child-file':
                head[1]['filenames'] = ['/src/foreign.rs']
            elif mode == 'wrong-child-end':
                head[1]['regions'][-1][3] += 1
            elif mode == 'broad-parent-row':
                head[0]['regions'][1][2] += 1
            elif mode == 'extra-child-entry-region':
                head[1]['regions'].append([5, 18, 5, 19, 1, 0, 0, 0])
            elif mode in ('stable-wrong-slot', 'stable-wrong-tail', 'stable-child-tail'):
                for members in (base, head):
                    for parent, child in zip(members[::2], members[1::2]):
                        if mode == 'stable-wrong-slot':
                            parent['regions'][1][1] += 1
                        elif mode == 'stable-wrong-tail':
                            parent['regions'][1][5] = 1
                        else:
                            child['regions'][0][7] = 1
            elif mode == 'nested-placement':
                for source in (old, new):
                    source[3] = '    if ready {'
                    source[6] += ' }'
            elif mode == 'duplicate-caller-in-parent':
                for source, members in ((old, base), (new, head)):
                    source[7:7] = ['    caller(&path, || {', '    });']
                    for owner in members:
                        for row in owner['regions']:
                            for column in (0, 2):
                                if row[column] >= 8:
                                    row[column] += 2
            elif mode == 'different-cfg':
                new[0] = '#[cfg(windows)]'
            elif mode == 'not-test':
                new[1] = '#[inline]'
            elif mode == 'changed-callee':
                new[4] = new[4].replace('caller', 'otherf')
            elif mode == 'changed-argument':
                new[4] = new[4].replace('&path', '&else')
            elif mode == 'macro-caller':
                for source in (old, new):
                    source[4] = source[4].replace('caller(', 'caller!(')
            elif mode == 'body-as-caller':
                for source in (old, new):
                    source[4] += ' inline();'
        for mode in ('cold-child', 'cold-callee', 'cold-argument', 'disagreed-parent-entry',
                     'disagreed-child-entry', 'missing-copy', 'missing-child', 'duplicate-symbol',
                     'foreign-overlap', 'wrong-parent', 'foreign-child-file', 'wrong-child-end',
                     'broad-parent-row', 'extra-child-entry-region', 'different-cfg', 'not-test',
                     'changed-callee', 'changed-argument', 'macro-caller', 'body-as-caller',
                     'stable-wrong-slot', 'stable-wrong-tail', 'stable-child-tail',
                     'nested-placement', 'duplicate-caller-in-parent'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.caller_entry_compare(lambda old, new, base, head: mutate(old, new, base, head, mode))

    def test_caller_entry_never_credits_changed_callback_body(self):
        with self.assertRaises(ValueError):
            self.caller_entry_compare(body=True)

    def test_caller_entry_preserves_default_callback_proof_and_shared_work_bound(self):
        original = coverage.zero_arg_callback_fragment
        captured = []
        def record(*args, **kwargs):
            result = original(*args, **kwargs)
            if kwargs.get('caller_entry'):
                captured.append(args)
            else:
                self.assertIsNone(result)
            return result
        with patch.object(coverage, 'zero_arg_callback_fragment', side_effect=record):
            self.caller_entry_compare()
        self.assertTrue(captured)
        args = list(captured[0])
        args[-1] = [0]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            original(*args, caller_entry=True)
        args = list(captured[0])
        args[5] = 6
        self.assertIsNone(original(*args, caller_entry=True))


    def literal_pair_loop_compare(self, mutation=None, body=False, fragment=None):
        captured = {}
        def nest(old, new, base, head):
            for source, members, suffix in ((old, base, 'before'), (new, head, 'after')):
                operation = source[5].strip()
                source[5:6] = [
                    '        for (manager, expected_error) in [',
                    '            ("npm", "' + ('NPM install' if suffix == 'before' else 'NPM materialization') + '"),',
                    '            ("cargo", "' + suffix + '"),',
                    '        ] {',
                    '            ' + operation,
                    '        }',
                ]
                for owner in members:
                    for row in owner['regions']:
                        for column in (0, 2):
                            if row[column] >= 7:
                                row[column] += 5
                for outer in (members[1], members[3]):
                    outer['regions'] = [row for row in outer['regions'] if row[0] != 6]
                    line = source[5]
                    slots = [(line.index('manager')+1, len('manager')),
                             (line.index('expected_error')+1, len('expected_error'))]
                    outer['regions'].extend([[6, column, 6, column+width, 2, 0, 0, 0]
                                             for column, width in slots])
                    outer['regions'].extend([
                        [6, line.index('[')+1, 9, source[8].index(']')+2, 1, 0, 0, 0],
                        [7, source[6].index('(')+1, 7, source[6].rindex(')')+2, 1, 0, 0, 0],
                        [10, 13, 10, len(source[9])+1, 2, 0, 0, 0],
                        [11, 9, 11, 10, 1, 0, 0, 0],
                    ])
            if mutation:
                mutation(old, new, base, head)
            captured.update(old=old, new=new, base=base, head=head)
        self.caller_entry_compare(mutation=nest)
        first, last = fragment or ((6, 10) if body else (6, 6))
        return coverage.positive_source_fragments(
            'example.rs', captured['old'], captured['new'], {n: 1 for n in range(1, 23)},
            {n: 1 for n in range(1, 23)}, captured['base'], captured['head'],
            {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'},
            [(first-1, last, first-1, last, list(range(first, last+1)))],
            callback_functions=('fn checked()',))

    def test_literal_pair_loop_retains_binding_and_array_roles_with_inert_error_updates(self):
        pairs, receipts = self.literal_pair_loop_compare()
        self.assertEqual(pairs, {6: 6})
        self.assertTrue(any(proof['kind'] == 'literal-pair-loop-header'
            for receipt in receipts for proof in receipt.get('callback_owners', [])))

    def test_literal_pair_loop_binds_retained_tuple_and_array_close_lines(self):
        def unchanged_first_pair(old, new, base, head):
            new[6] = old[6]
            for outer in (head[1], head[3]):
                outer['regions'][5][3] = old[6].rindex(')')+2
        for fragment in ((7, 7), (9, 9)):
            with self.subTest(fragment=fragment):
                pairs, _ = self.literal_pair_loop_compare(unchanged_first_pair, fragment=fragment)
                self.assertEqual(pairs, {fragment[0]: fragment[1]})

    def test_literal_pair_loop_refuses_missing_foreign_cold_or_rebound_roles(self):
        def mutate(old, new, base, head, mode):
            if mode == 'missing-copy':
                del head[2:4]
            elif mode == 'missing-child':
                del head[1]
            elif mode == 'duplicate-owner':
                head.append(copy.deepcopy(head[1]))
            elif mode == 'foreign-overlap':
                head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                    regions=[[6, 14, 6, 21, 1, 0, 0, 0]]))
            elif mode == 'wrong-child-file':
                head[1]['filenames'] = ['/src/foreign.rs']
            elif mode == 'wrong-child-symbol':
                head[1]['name'] = head[1]['name'].replace('7checked', '7another')
            elif mode in ('cold-binding', 'cold-array', 'disagreed-binding', 'disagreed-array'):
                row = head[1]['regions'][2 if mode.endswith('binding') else 4]
                row[4] = 0 if mode.startswith('cold') else row[4]+1
            elif mode == 'missing-tuple-role':
                del head[1]['regions'][5]
            elif mode == 'cold-tuple-role':
                head[1]['regions'][5][4] = 0
            elif mode == 'stable-wrong-tuple-span':
                for members in (base, head):
                    for outer in (members[1], members[3]):
                        outer['regions'][5][3] -= 1
            elif mode == 'cold-complete-header-copy':
                for row in head[1]['regions'][2:6]:
                    row[4] = 0
            elif mode == 'cold-outer':
                head[1]['count'] = head[1]['regions'][0][4] = 0
            elif mode == 'cold-root':
                head[0]['count'] = head[0]['regions'][0][4] = 0
            elif mode in ('stable-wrong-slot', 'stable-extra-role', 'stable-wrong-tail'):
                for members in (base, head):
                    for outer in (members[1], members[3]):
                        if mode == 'stable-wrong-slot':
                            outer['regions'][2][1] += 1
                        elif mode == 'stable-wrong-tail':
                            outer['regions'][2][7] = 1
                        else:
                            outer['regions'].append([7, 1, 7, 2, 1, 0, 0, 0])
            elif mode == 'array-spans-body':
                head[1]['regions'][4][2] = 10
            elif mode == 'changed-first-value':
                new[6] = new[6].replace('npm', 'bun')
            elif mode == 'changed-binding':
                new[5] = new[5].replace('manager', 'carrier')
            elif mode == 'changed-caller':
                new[4] = new[4].replace('caller', 'otherf')
            elif mode == 'conditional-placement':
                for source in (old, new):
                    source[5] = '        if ready { ' + source[5]
                    source[10] += ' }'
            elif mode == 'nonliteral-second':
                for source in (old, new):
                    source[7] = '            ("cargo", compute()),'
            elif mode == 'escaped-second':
                for source in (old, new):
                    source[7] = '            ("cargo", "escaped\\ntext"),'
            elif mode == 'rebound-complete-loop':
                for source in (old, new):
                    source[5] = source[5].replace('(manager, expected_error)', '(manager, manager)')
        for mode in ('missing-copy', 'missing-child', 'duplicate-owner', 'foreign-overlap',
                'wrong-child-file', 'wrong-child-symbol', 'cold-binding', 'cold-array',
                'disagreed-binding', 'disagreed-array', 'missing-tuple-role', 'cold-tuple-role',
                'stable-wrong-tuple-span', 'cold-complete-header-copy', 'cold-outer', 'cold-root',
                'stable-wrong-slot', 'stable-extra-role', 'stable-wrong-tail', 'array-spans-body',
                'changed-first-value', 'changed-binding', 'changed-caller', 'conditional-placement',
                'nonliteral-second', 'escaped-second', 'rebound-complete-loop'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.literal_pair_loop_compare(lambda old, new, base, head: mutate(old, new, base, head, mode))

    def test_literal_pair_loop_normalization_is_explicit_and_work_is_bounded(self):
        original = coverage.literal_pair_loop_fragment
        captured = []
        def record(*args, **kwargs):
            result = original(*args, **kwargs)
            if result is not None:
                captured.append((args, kwargs))
            return result
        with patch.object(coverage, 'literal_pair_loop_fragment', side_effect=record):
            self.literal_pair_loop_compare()
        self.assertTrue(captured)
        args, kwargs = captured[0]
        exhausted = list(args); exhausted[-1] = [0]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            original(*exhausted, **kwargs)
        def exact(*args, **kwargs):
            return original(*args, **(kwargs | {'normalize_second': False}))
        with patch.object(coverage, 'literal_pair_loop_fragment', side_effect=exact):
            with self.assertRaises(ValueError):
                self.literal_pair_loop_compare()

    def test_literal_pair_loop_never_credits_changed_body(self):
        with self.assertRaises(ValueError):
            self.literal_pair_loop_compare(body=True)


    def literal_loop_async_compare(self, mutation=None, body=False):
        captured = {}
        def nest(old, new, base, head):
            for source, members in ((old, base), (new, head)):
                operation = source[9].strip()
                source[9:10] = ['            runtime.block_on(async {',
                               '                ' + operation, '            });']
                for owner in members:
                    for row in owner['regions']:
                        for column in (0, 2):
                            if row[column] >= 11:
                                row[column] += 2
                line = source[9]; brace = line.index('{')+1
                for root, outer in ((members[0], members[1]), (members[2], members[3])):
                    outer['regions'] = [row for row in outer['regions'] if row[0] != 10]
                    for name in ('runtime', 'block_on'):
                        first = line.index(name)+1
                        outer['regions'].append([10, first, 10, first+len(name), 2, 0, 0, 0])
                    members.append(dict(name='_RNCNC'+root['name'][2:]+'00B5_', count=2,
                        filenames=['/src/example.rs'], regions=[
                            [10, brace, 10, brace+1, 2, 0, 0, 0],
                            [11, 17, 11, len(source[10])+1, 2, 0, 0, 0],
                            [12, 13, 12, 14, 2, 0, 0, 0]]))
            if mutation:
                mutation(old, new, base, head)
            captured.update(old=old, new=new, base=base, head=head)
        self.literal_pair_loop_compare(nest)
        first, last = (10, 11) if body else (10, 10)
        return coverage.positive_source_fragments('example.rs', captured['old'], captured['new'],
            {n: 1 for n in range(1, 25)}, {n: 1 for n in range(1, 25)},
            captured['base'], captured['head'], {'/src/example.rs': 'example.rs'},
            {'/src/example.rs': 'example.rs'},
            [(first-1, last, first-1, last, list(range(first, last+1)))],
            callback_functions=('fn checked()',))

    def test_literal_loop_async_entry_retains_full_loop_and_call_authority(self):
        pairs, receipts = self.literal_loop_async_compare()
        self.assertEqual(pairs, {10: 10})
        self.assertTrue(any(proof['kind'] == 'literal-pair-loop-async-call-entry'
            for receipt in receipts for proof in receipt.get('callback_owners', [])))

    def test_literal_loop_async_entry_refuses_rebound_missing_cold_and_deeper_paths(self):
        def mutate(old, new, base, head, mode):
            if mode == 'missing-async':
                del head[8]
            elif mode == 'duplicate-async':
                head.append(copy.deepcopy(head[8]))
            elif mode == 'foreign-overlap':
                head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                    regions=[copy.deepcopy(head[8]['regions'][0])]))
            elif mode == 'wrong-depth':
                head[8]['name'] = head[8]['name'].replace('_RNCNC', '_RNC')
            elif mode == 'foreign-file':
                head[8]['filenames'] = ['/src/foreign.rs']
            elif mode == 'cold-async':
                head[8]['count'] = head[8]['regions'][0][4] = 0
            elif mode == 'disagreed-entry':
                head[8]['count'] += 1
            elif mode == 'different-loop-count':
                head[8]['count'] = head[8]['regions'][0][4] = 1
                head[1]['regions'][-2][4] = head[1]['regions'][-1][4] = 1
            elif mode == 'cold-receiver':
                head[1]['regions'][-2][4] = 0
            elif mode == 'cold-method':
                head[1]['regions'][-1][4] = 0
            elif mode == 'cold-loop':
                for row in head[1]['regions'][2:6]:
                    row[4] = 0
            elif mode == 'changed-first-literal':
                new[6] = new[6].replace('npm', 'bun')
            elif mode == 'changed-method':
                new[9] = new[9].replace('block_on', 'other_fn')
            elif mode == 'changed-receiver':
                new[9] = new[9].replace('runtime', 'another')
            elif mode == 'conditional-call':
                for source in (old, new):
                    source[9] = '            if ready { ' + source[9]
                    source[11] += ' }'
            elif mode == 'deeper-loop':
                for source in (old, new):
                    source[9] = '            for inner in [1] { ' + source[9]
                    source[11] += ' }'
            elif mode in ('stable-wrong-slot', 'stable-wrong-tail'):
                for members in (base, head):
                    for outer in (members[1], members[3]):
                        outer['regions'][-1][1 if mode == 'stable-wrong-slot' else 7] += 1
            elif mode == 'wrong-span':
                head[8]['regions'][-1][3] += 1
            elif mode == 'async-move':
                for source in (old, new):
                    source[9] = source[9].replace('async {', 'async move {')
        for mode in ('missing-async', 'duplicate-async', 'foreign-overlap', 'wrong-depth',
                'foreign-file', 'cold-async', 'disagreed-entry', 'different-loop-count',
                'cold-receiver', 'cold-method', 'cold-loop', 'changed-first-literal',
                'changed-method', 'changed-receiver', 'conditional-call', 'deeper-loop',
                'stable-wrong-slot', 'stable-wrong-tail', 'wrong-span', 'async-move'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.literal_loop_async_compare(lambda old, new, base, head: mutate(old, new, base, head, mode))

    def test_literal_loop_async_entry_never_credits_body_work(self):
        with self.assertRaises(ValueError):
            self.literal_loop_async_compare(body=True)


    def join_result_compare(self, mutation=None, expansions=([], []), body=False, fragment=None,
                            with_guard=False, with_statements=False, guard_close=False, phase_close=False):
        captured = {}
        def nest(old, new, base, head):
            for source, members, callee, request in ((old, base, 'before', '"fixture-tool"'),
                                                    (new, head, 'after', 'request')):
                source[10:11] = [
                    '                let (outcome, tick_elapsed) = tokio::join!(',
                    '                    biased;',
                    '                    ' + callee + '(manager, ' + request + ', "fixture-tool", &tools, &bin),',
                    '                    async {',
                    '                        tokio::time::sleep(Duration::from_millis(50)).await;',
                    '                        started.elapsed()',
                    '                    },',
                    '                );',
                ]
                for owner in members:
                    for row in owner['regions']:
                        for column in (0, 2):
                            if row[column] >= 12:
                                row[column] += 7
                for root, phase in ((members[0], members[8]), (members[2], members[9])):
                    phase['regions'] = [row for row in phase['regions'] if row[0] != 11]
                    line = source[10]
                    for name in ('outcome', 'tick_elapsed', 'tokio::join!'):
                        start = line.index(name)+1
                        phase['regions'].append([11, start, 11, start+len(name), 2, 0, 0, 0])
                    line = source[12]
                    matched = re.fullmatch(r'\s*(?P<callee>\w+)\((?P<a>manager), (?P<b>"fixture-tool"|request), '
                        r'(?P<c>"fixture-tool"), (?P<d>&tools), (?P<e>&bin)\),', line)
                    for name in ('callee', 'a', 'b', 'c', 'd', 'e'):
                        phase['regions'].append([13, matched.start(name)+1, 13, matched.end(name)+1, 2, 0, 0, 0])
                    brace = source[13].index('{')+1; sleep = source[14].index('tokio')+1
                    started = source[15].index('started')+1; elapsed = source[15].index('elapsed')+1
                    end = source[16].index('}')+1
                    members.append(dict(name='_RNCNCNC'+root['name'][2:]+'000B7_', count=2,
                        filenames=['/src/example.rs'], regions=[
                            [14, brace, 14, brace+1, 2, 0, 0, 0],
                            [15, sleep, 15, sleep+len('tokio::time::sleep'), 2, 0, 0, 0],
                            [15, sleep, 15, source[14].index(';')+1, 2, 0, 0, 0],
                            [16, started, 16, started+len('started'), 2, 0, 0, 0],
                            [16, elapsed, 16, elapsed+len('elapsed'), 2, 0, 0, 0],
                            [17, end, 17, end+1, 2, 0, 0, 0],
                        ]))
                if with_statements:
                    source[18:18] = ['                let error = outcome.expect_err("fixture failure");',
                                     '                assert!(error.is_expected());',
                                     '                fs::remove_file(marker).expect("reset marker");']
                    for owner in members:
                        for row in owner['regions']:
                            for column in (0,2):
                                if row[column]>=19:
                                    row[column] += 3
                    for phase in (members[8], members[9]):
                        for line, word in ((19,'error'),(20,'assert!'),(21,'fs::remove_file')):
                            start = source[line-1].index(word)+1
                            phase['regions'].append([line,start,line,start+len(word),2,0,0,0])
                if with_guard:
                    source[18:18] = ['                if tick_elapsed >= Duration::from_millis(500) {',
                                     '                    starved.push(manager);',
                                     '                }']
                    for owner in members:
                        for row in owner['regions']:
                            for column in (0, 2):
                                if row[column] >= 19:
                                    row[column] += 3
                    for phase in (members[8], members[9]):
                        guard = source[18]; expression = guard.index('tick_elapsed') + 1
                        brace = guard.index('{') + 1; end = source[20].index('}') + 1
                        phase['regions'].extend([
                            [19, expression, 19, brace - 1, 2, 0, 0, 0],
                            [19, brace, 21, end + 1, 0, 0, 0, 0],
                            [20, 21, 20, 33, 0, 0, 0, 0],
                            [21, end, 21, end + 1, 2, 0, 0, 0],
                        ])
            if mutation:
                mutation(old, new, base, head)
            captured.update(old=old, new=new, base=base, head=head)
        self.literal_loop_async_compare(nest)
        first, last = fragment or ((11, 15) if body else (11, 11))
        requested = [(first-1, last, first-1, last, list(range(first,last+1)))]
        if with_guard:
            requested.append((18, 19, 18, 19, [19]))
            if guard_close:
                requested.append((20,21,20,21,[21]))
        if with_statements:
            requested.extend((line-1,line,line-1,line,[line]) for line in range(19,22))
        if phase_close:
            requested.append((18,19,18,19,[19]))
        inventories = tuple(coverage._construct_inventory(captured[side],[100_000]) for side in ('old','new'))
        return coverage.positive_source_fragments('example.rs', captured['old'], captured['new'],
            {n: 1 for n in range(1, 32)}, {n: 1 for n in range(1, 32)},
            captured['base'], captured['head'], {'/src/example.rs': 'example.rs'},
            {'/src/example.rs': 'example.rs'}, requested,
            callback_functions=('fn checked()',), macro_expansions=expansions, construct_inventories=inventories)

    def test_join_result_binds_exact_result_roles_and_unchanged_owned_timer(self):
        pairs, receipts = self.join_result_compare()
        self.assertEqual(pairs, {11: 11})
        proofs = [proof for receipt in receipts for proof in receipt.get('callback_owners', [])
                  if proof['kind'] == 'biased-join-result-binding']
        self.assertEqual(len(proofs), 2)
        self.assertEqual([proof['first_callee_unclaimed'] for proof in proofs], ['before', 'after'])
        self.assertTrue(all(proof['empty_expansion_metadata'] for proof in proofs))

    def test_join_result_projects_only_the_exact_closed_timer_owner(self):
        for first,last in ((14,14),(15,15),(16,16),(17,17),(14,17)):
            with self.subTest(fragment=(first,last)):
                pairs,receipts=self.join_result_compare(fragment=(first,last))
                self.assertEqual(pairs, {line:line for line in range(first,last+1)})
                self.assertTrue(any(proof['kind']=='biased-join-owned-timer-fragment'
                    for receipt in receipts for proof in receipt.get('callback_owners',[])))
        for fragment in ((12,12),(13,13),(11,15),(13,17)):
            with self.subTest(unclaimed=fragment),self.assertRaises(ValueError):
                self.join_result_compare(fragment=fragment)

    def test_join_scope_proves_the_unchanged_direct_conditional_and_preserves_cold_regions(self):
        pairs, receipts = self.join_result_compare(with_guard=True)
        self.assertEqual(pairs, {11:11,19:19})
        proofs = [proof for receipt in receipts for proof in receipt.get('callback_owners', [])
                  if proof['kind']=='joined-async-condition']
        self.assertEqual(len(proofs), 2)
        self.assertTrue(all(proof['condition_span'] == [19,21] for proof in proofs))

    def test_join_scope_proves_the_exact_conditional_completion(self):
        pairs, receipts = self.join_result_compare(with_guard=True, guard_close=True)
        self.assertEqual(pairs, {11:11,19:19,21:21})
        self.assertEqual(sum(proof['kind']=='joined-async-condition-completion' for receipt in receipts
            for proof in receipt.get('callback_owners', [])),2)

    def test_join_scope_proves_its_exact_async_phase_completion(self):
        pairs, receipts = self.join_result_compare(phase_close=True)
        self.assertEqual(pairs, {11:11,19:19})
        self.assertEqual(sum(proof['kind']=='joined-async-phase-completion' for receipt in receipts
            for proof in receipt.get('callback_owners', [])),2)

    def test_join_scope_refuses_changed_conditional_body_and_lost_copy_state(self):
        def change(old, new, base, head, mode):
            if mode == 'different-body':
                new[19] = new[19].replace('push', 'drop')
            elif mode == 'foreign-region':
                head.append(dict(name='foreign', filenames=['/src/example.rs'], count=2,
                    regions=[[19,20,19,24,2,0,0,0]]))
            else:
                next(row for row in head[8]['regions'] if row[0]==19 and row[2]==19)[4] = 0
        for mode in ('different-body','foreign-region','lost-copy'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.join_result_compare(lambda *args: change(*args, mode), with_guard=True)

    def test_join_scope_matches_each_unchanged_post_join_statement(self):
        pairs, receipts = self.join_result_compare(with_statements=True)
        self.assertEqual(pairs, {11:11,19:19,20:20,21:21})
        self.assertEqual(sum(proof['kind']=='joined-async-statement' for receipt in receipts
            for proof in receipt.get('callback_owners',[])),6)

    def test_join_scope_refuses_unbound_or_cold_statement_regions(self):
        def control(old,new,base,head,mode):
            if mode=='foreign':
                head.append(dict(name='foreign',filenames=['/src/example.rs'],count=2,
                                 regions=[[20,17,20,24,2,0,0,0]]))
            elif mode=='lost-state':
                next(row for row in head[8]['regions'] if row[0]==20)[4] = 0
            else:
                new[19] = new[19].replace('is_expected','is_unrelated')
        for mode in ('foreign','lost-state','changed-statement'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.join_result_compare(lambda *args:control(*args,mode),with_statements=True)

    def test_join_prepared_cache_is_scoped_to_exact_immutable_inputs_and_metadata(self):
        original=coverage.biased_join_result_fragment
        captured=[]
        def record(*args,**kwargs):
            value=original(*args,**kwargs)
            if value is not None and first_not_captured(args,captured):
                captured.append((args,kwargs))
            return value
        def first_not_captured(args,captured):
            return all(old[0][0] is not args[0] for old in captured)
        with patch.object(coverage,'biased_join_result_fragment',side_effect=record):
            self.join_result_compare()
        self.assertEqual(len(captured),2)
        cache={}
        for (args,kwargs),callee in zip(captured,('before','after')):
            value=original(*args,**(kwargs|{'cache':cache}))
            self.assertEqual(value.witness['first_callee_unclaimed'],callee)
            for missing in (None,[{}]):
                self.assertIsNone(original(*args,**(kwargs|{'cache':cache,'expansions':missing})))
        args,kwargs=captured[1];changed=list(args);changed[2]=list(args[2]);changed[2].pop()
        self.assertIsNone(original(*changed,**(kwargs|{'cache':cache})))
        exhausted=list(args);exhausted[7]=[0]
        with self.assertRaisesRegex(ValueError,'work bound exceeded'):
            original(*exhausted,**(kwargs|{'cache':cache}))

    def test_join_result_refuses_unavailable_or_nonempty_expansion_metadata(self):
        for expansions in ((None,None), ([],None), (None,[]), ([{}],[]), ([],[{}])):
            with self.subTest(expansions=expansions), self.assertRaises(ValueError):
                self.join_result_compare(expansions=expansions)

    def test_join_result_refuses_cold_foreign_missing_or_changed_macro_control(self):
        def mutate(old,new,base,head,mode):
            if mode == 'missing-timer':
                del head[10]
            elif mode == 'duplicate-timer':
                head.append(copy.deepcopy(head[10]))
            elif mode == 'foreign-overlap':
                head.append(dict(name='foreign',count=1,filenames=['/src/example.rs'],
                    regions=[copy.deepcopy(head[10]['regions'][0])]))
            elif mode == 'wrong-timer-depth':
                head[10]['name'] = head[10]['name'].replace('_RNCNCNC','_RNCNC')
            elif mode == 'timer-foreign-file':
                head[10]['filenames'] = ['/src/foreign.rs']
            elif mode == 'cold-timer':
                head[10]['count'] = head[10]['regions'][0][4] = 0
            elif mode == 'cold-timer-subregion':
                head[10]['regions'][2][4] = 0
            elif mode == 'disagreed-timer-entry':
                head[10]['count'] += 1
            elif mode == 'cold-result':
                head[8]['regions'][2][4] = 0
            elif mode == 'cold-first-call':
                head[8]['regions'][-1][4] = 0
            elif mode == 'changed-timer':
                new[14] = new[14].replace('(50)','(60)')
            elif mode == 'changed-manager':
                new[12] = new[12].replace('(manager,','(another,')
            elif mode == 'no-biased-control':
                for source in (old,new):
                    source[11] = '                    unbiased;'
            elif mode == 'third-branch':
                for source in (old,new):
                    source[16] += ' another(),'
            elif mode == 'expression-escape':
                for source in (old,new):
                    source[12] = source[12].replace('before(','return before(').replace('after(','return after(')
            elif mode == 'wrong-macro':
                for source in (old,new):
                    source[10] = source[10].replace('tokio::join!', 'other::join!')
            elif mode in ('stable-bad-slot','stable-bad-tail'):
                for members in (base,head):
                    for phase in (members[8],members[9]):
                        phase['regions'][2][1 if mode=='stable-bad-slot' else 7] += 1
            elif mode == 'wrong-timer-end':
                head[10]['regions'][-1][3] += 1
        for mode in ('missing-timer','duplicate-timer','foreign-overlap','wrong-timer-depth',
                'timer-foreign-file','cold-timer','cold-timer-subregion','disagreed-timer-entry',
                'cold-result','cold-first-call','changed-timer','changed-manager','no-biased-control',
                'third-branch','expression-escape','wrong-macro','stable-bad-slot','stable-bad-tail','wrong-timer-end'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.join_result_compare(lambda old,new,base,head:mutate(old,new,base,head,mode))

    def test_join_result_never_credits_macro_body_or_first_callee_semantics(self):
        with self.assertRaises(ValueError):
            self.join_result_compare(body=True)

    def nested_async_entry_compare(self, mutation=None, body=False):
        captured = {}
        def nest(old, new, base, head):
            for source, members in ((old, base), (new, head)):
                source.insert(5, '        runtime.block_on(async {')
                source[6] = '    ' + source[6]
                source.insert(7, '        });')
                for owner in members:
                    for row in owner['regions']:
                        for column in (0, 2):
                            number = row[column]
                            row[column] = number + (1 if number == 6 else 2 if number >= 7 else 0)
                for parent, outer in zip(members[:4:2], members[1:4:2]):
                    outer['regions'].extend([
                        [6, 9, 6, 16, 1, 0, 0, 0],
                        [6, 17, 6, 25, 1, 0, 0, 0]])
                    brace = source[5].index('{') + 1
                    members.append(dict(name='_RNCNC'+parent['name'][2:]+'00B5_', count=1,
                        filenames=['/src/example.rs'], regions=[
                            [6, brace, 6, brace+1, 1, 0, 0, 0],
                            [7, 13, 7, len(source[6])+1, 1, 0, 0, 0],
                            [8, 9, 8, 10, 1, 0, 0, 0]]))
            if mutation:
                mutation(old, new, base, head)
            captured.update(old=old, new=new, base=base, head=head)
        self.caller_entry_compare(mutation=nest)
        first, last = (6, 7) if body else (6, 6)
        return coverage.positive_source_fragments(
            'example.rs', captured['old'], captured['new'], {n: 1 for n in range(1, 19)},
            {n: 1 for n in range(1, 19)}, captured['base'], captured['head'],
            {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'},
            [(first-1, last, first-1, last, list(range(first, last+1)))],
            callback_functions=('fn checked()',))

    def test_nested_async_entry_retains_root_outer_and_async_copies(self):
        pairs, receipts = self.nested_async_entry_compare()
        self.assertEqual(pairs, {6: 6})
        self.assertTrue(any(witness['kind'] == 'nested-async-call-entry'
                            for receipt in receipts for witness in receipt.get('callback_owners', [])))

    def test_nested_async_entry_refuses_incomplete_or_rebound_phase_authority(self):
        def mutate(old, new, base, head, mode):
            if mode == 'cold-root':
                head[0]['count'] = head[0]['regions'][0][4] = 0
            elif mode == 'cold-outer':
                head[1]['count'] = head[1]['regions'][0][4] = 0
            elif mode == 'cold-async':
                head[8]['count'] = head[8]['regions'][0][4] = 0
            elif mode == 'cold-receiver':
                head[1]['regions'][-2][4] = 0
            elif mode == 'cold-method':
                head[1]['regions'][-1][4] = 0
            elif mode == 'redistributed-copy-states':
                for members, matrix in ((base, ((1, 0), (0, 1))), (head, ((1, 1), (0, 0)))):
                    for outer, values in zip((members[1], members[3]), matrix):
                        outer['regions'][-2][4], outer['regions'][-1][4] = values
            elif mode == 'stable-root-overlap':
                for members in (base, head):
                    for root in (members[0], members[2]):
                        root['regions'].append([6, 1, 6, 2, 1, 0, 0, 0])
            elif mode == 'duplicate-method-caller':
                for source, members in ((old, base), (new, head)):
                    source[8:8] = ['        runtime.block_on(async {', '        });']
                    for owner in members:
                        for row in owner['regions']:
                            for column in (0, 2):
                                if row[column] >= 9:
                                    row[column] += 2
            elif mode == 'entry-disagrees':
                head[8]['count'] += 1
            elif mode == 'missing-copy':
                del head[9]
            elif mode == 'extra-copy':
                head.append(copy.deepcopy(head[8]))
            elif mode == 'foreign-overlap':
                head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                                 regions=[copy.deepcopy(head[8]['regions'][0])]))
            elif mode == 'foreign-file':
                head[8]['filenames'] = ['/src/foreign.rs']
            elif mode == 'sibling-symbol':
                head[8]['name'] = head[8]['name'].replace('7checked', '7sibling')
            elif mode == 'wrong-depth':
                head[8]['name'] = head[8]['name'].replace('_RNCNC', '_RNC')
            elif mode == 'wrong-span':
                head[8]['regions'][-1][3] += 1
            elif mode in ('stable-wrong-slot', 'stable-parent-tail', 'stable-async-tail'):
                for members in (base, head):
                    for outer in (members[1], members[3]):
                        if mode == 'stable-wrong-slot':
                            outer['regions'][-2][1] += 1
                        elif mode == 'stable-parent-tail':
                            outer['regions'][-2][7] = 1
                    if mode == 'stable-async-tail':
                        for child in members[8:]:
                            child['regions'][0][7] = 1
            elif mode == 'extra-child-overlap':
                head[8]['regions'].append([6, 1, 6, 2, 1, 0, 0, 0])
            elif mode == 'body-spanning-slot':
                head[1]['regions'][-2][2] += 1
            elif mode == 'changed-outer-context':
                new[4] = new[4].replace('caller', 'otherf')
            elif mode == 'changed-method':
                new[5] = new[5].replace('block_on', 'other_fn')
            elif mode == 'changed-receiver':
                new[5] = new[5].replace('runtime', 'another')
            elif mode == 'async-move':
                for source in (old, new):
                    source[5] = source[5].replace('async {', 'async move {')
            elif mode == 'inline-body':
                for source in (old, new):
                    source[5] += ' do_work();'
            elif mode == 'conditional-placement':
                for source in (old, new):
                    source[5] = '        if ready { ' + source[5]
                    source[7] += ' }'
        for mode in ('cold-root', 'cold-outer', 'cold-async', 'cold-receiver', 'cold-method',
                     'entry-disagrees', 'redistributed-copy-states', 'stable-root-overlap', 'duplicate-method-caller', 'missing-copy', 'extra-copy', 'foreign-overlap',
                     'foreign-file', 'sibling-symbol', 'wrong-depth', 'wrong-span',
                     'stable-wrong-slot', 'stable-parent-tail', 'stable-async-tail',
                     'extra-child-overlap', 'body-spanning-slot', 'changed-outer-context',
                     'changed-method', 'changed-receiver', 'async-move', 'inline-body',
                     'conditional-placement'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.nested_async_entry_compare(lambda old, new, base, head: mutate(old, new, base, head, mode))

    def test_nested_async_entry_refuses_body_credit_and_exhausted_work(self):
        with self.assertRaises(ValueError):
            self.nested_async_entry_compare(body=True)
        original = coverage.nested_async_call_entry_fragment
        captured = []
        def record(*args, **kwargs):
            result = original(*args, **kwargs)
            if result is not None:
                captured.append(args)
            return result
        with patch.object(coverage, 'nested_async_call_entry_fragment', side_effect=record):
            self.nested_async_entry_compare()
        self.assertTrue(captured)
        args = list(captured[0]); args[-1] = [0]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            original(*args)

    def changed_callback_compare(self, mutation=None, context_change=False, joint=False, callback_form='||',
                                 header_end='brace'):
        def function(name, operation, setup='setup'):
            return (f'#[test]\nfn {name}() {{\n    {setup}();\n    isolate("MODE", {callback_form} {{\n'
                    f'        {operation}();\n        verify();\n        finish();\n    }});\n}}\n')
        old = (function('checked', 'old_step') + function('retained', 'old_step')).encode()
        new = (function('checked', 'new_step', 'different_setup' if context_change else 'setup')
               + function('retained', 'old_step')).encode()
        def owners(base, head):
            for document, source in ((base, old), (head, new)):
                lines = source.decode().splitlines(); members = []
                for name, first in (('checked', 2), ('retained', 11)):
                    opening = lines[first - 1].index('{') + 1
                    call = first + 2; body = lines[call - 1].index('{') + 1
                    for number in range(2):
                        parent = f'_RNvCs{number + 1}_7examples_{len(name)}{name}'
                        members.extend([
                            dict(name=parent, count=1, filenames=['/src/example.rs'], regions=[
                                [first, 1, first, opening - int(header_end == 'token'), 1, 0, 0, 0],
                                [first + 1, 5, first + 1, len(lines[first]) + 1, 1, 0, 0, 0],
                                [call, 5, call, 12, 1, 0, 0, 0],
                                [first + 7, 1, first + 7, 2, 1, 0, 0, 0]]),
                            dict(name='_RNC' + parent[2:] + '0B3_', count=1,
                                 filenames=['/src/example.rs'], regions=[
                                     [call, body, call, body + 1, 1, 0, 0, 0],
                                     [call + 1, 9, call + 1, len(lines[call]) + 1, 1, 0, 0, 0],
                                     [call + 2, 9, call + 2, len(lines[call + 1]) + 1, 1, 0, 0, 0],
                                     [call + 3, 9, call + 3, len(lines[call + 2]) + 1, 1, 0, 0, 0],
                                     [call + 4, 5, call + 4, 6, 1, 0, 0, 0]])])
                if joint:
                    for number in (1, 3):
                        for index in (2, 3):
                            members[number]['regions'][index][4] = int(number == 1)
                document['data'][0]['functions'] = members
            if mutation:
                mutation(head['data'][0]['functions'])
        counts = [(line, 2) for line in range(1, 19) if line not in (1, 10)]
        return self.compare(before=counts, after=counts, mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))

    def extracted_callback_predicate_compare(self, mutation=None):
        old = b'fn checked(text: &str) -> String {\n    text.chars()\n        .filter(|character| {\n            !character.is_control()\n        })\n        .collect()\n}\n'
        new = (b'fn checked(text: &str) -> String {\n    text.chars()\n        .filter(|character| allowed(*character))\n        .collect()\n}\n'
               b'fn allowed(character: char) -> bool {\n    !character.is_control()\n}\n')
        def owners(base, head):
            for document, source in ((base, old), (head, new)):
                lines = source.decode().splitlines()
                end = 7 if document is base else 5
                members = []
                for number in range(2):
                    parent = f'_RNvCs{number + 1}_7example7checked'
                    members.append(dict(name=parent, count=1, filenames=['/src/example.rs'], regions=[
                        [1, 1, 1, lines[0].index('{') + 1, 1, 0, 0, 0],
                        [2, 5, 2, len(lines[1]) + 1, 1, 0, 0, 0],
                        [3, 10, 3, 16, 1, 0, 0, 0],
                        [end-1, 9, end-1, len(lines[end-2]) + 1, 1, 0, 0, 0],
                        [end, 1, end, 2, 1, 0, 0, 0]]))
                    child_regions = ([[3, 29, 3, 30, 1, 0, 0, 0],
                                      [4, 13, 4, len(lines[3]) + 1, 1, 0, 0, 0],
                                      [5, 9, 5, 10, 1, 0, 0, 0]]
                                     if document is base else [[3, 29, 3, 36, 1, 0, 0, 0],
                                                               [3, 37, 3, 47, 1, 0, 0, 0]])
                    members.append(dict(name='_RNC' + parent[2:] + '0B3_', count=1,
                        filenames=['/src/example.rs'], regions=child_regions))
                    if document is head:
                        members.append(dict(name=f'_RNvCs{number + 1}_7example7allowed', count=1,
                            filenames=['/src/example.rs'], regions=[
                                [6, 1, 6, lines[5].index('{') + 1, 1, 0, 0, 0],
                                [7, 5, 7, len(lines[6]) + 1, 1, 0, 0, 0],
                                [8, 1, 8, 2, 1, 0, 0, 0]]))
                document['data'][0]['functions'] = members
            if mutation:
                mutation(base['data'][0]['functions'], head['data'][0]['functions'])
        before, after = ([(line, 2) for line in range(1, 8)],
                         [(line, 2) for line in range(1, 9)])
        return self.compare(before=before, after=after, mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))

    def eager_prefix_compare(self, mutation=None, fixture_name='coverage-eager-prefix.json'):
        fixture = json.loads((SCRIPT.parent / 'fixtures' / fixture_name).read_text(encoding='utf-8'))
        if mutation:
            mutation(fixture['base'], fixture['head'])
        def owners(base, head):
            base['data'][0]['functions'] = fixture['base']['owners']
            head['data'][0]['functions'] = fixture['head']['owners']
        return self.compare(before=fixture['base']['counts'], after=fixture['head']['counts'],
            mutate=owners, sources=tuple({'example.rs': ('\n'.join(fixture[side]['source'])+'\n').encode()}
                                        for side in ('base', 'head')))

    def test_identical_eager_prefix_survives_a_later_call_result_check(self):
        receipt = self.eager_prefix_compare()
        self.assertEqual(receipt['deleted_mapped'], 0)
        witnesses = [row for row in receipt['retained_replacement_obligations'] if 'eager_call_prefix' in row]
        self.assertEqual(len(witnesses), 1)
        self.assertTrue(all(line <= 9 for line, target in witnesses[0]['pairs']))

    def test_native_eager_chain_prefix_survives_a_changed_return_type_and_continuation(self):
        receipt = self.eager_prefix_compare(fixture_name='coverage-eager-chain-prefix.json')
        witnesses = [row for row in receipt['retained_replacement_obligations'] if 'eager_call_prefix' in row]
        self.assertEqual(len(witnesses), 1)
        self.assertEqual(receipt['deleted_mapped'], 0)

    def test_native_eager_chain_refuses_changed_conditions_or_mixed_regions(self):
        for mode in ('condition', 'cold_subregion'):
            def mutate(base, head):
                if mode == 'condition':
                    head['source'][7] = head['source'][7].replace('if parent_records', 'if changed_flag')
                else:
                    for side, line in ((base, 27), (head, 26)):
                        for owner in side['owners']:
                            if owner['regions'][0][0] == 1:
                                state = int(owner['count'] > 0) if side is base else 0
                                owner['regions'].append([line, 13, line, 20, state, 0, 0, 0])
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.eager_prefix_compare(mutate, fixture_name='coverage-eager-chain-prefix.json')

    def test_changed_parameters_or_missing_copies_cannot_receive_an_eager_chain_prefix_witness(self):
        for mode in ('parameter', 'missing_copy'):
            def mutate(base, head):
                if mode == 'parameter':
                    head['source'][1] = head['source'][1].replace('sudo_program:', 'different_program:')
                else:
                    index = next(index for index, owner in enumerate(head['owners']) if owner['regions'][0][0] == 1)
                    del head['owners'][index]
            with self.subTest(mode=mode):
                receipt = self.eager_prefix_compare(mutate, fixture_name='coverage-eager-chain-prefix.json')
                self.assertFalse(any('eager_call_prefix' in row
                    for row in receipt.get('retained_replacement_obligations', [])))

    def test_eager_prefix_refuses_cold_or_changed_raw_parent_regions(self):
        for mode in ('cold', 'geometry', 'missing'):
            def mutate(base, head):
                parent = head['owners'][1]
                if mode == 'cold':
                    parent['regions'][6][4] = 0
                elif mode == 'geometry':
                    parent['regions'][6][1] += 1
                else:
                    del parent['regions'][6]
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.eager_prefix_compare(mutate)

    def test_eager_prefix_witness_refuses_preceding_deferred_control_or_macro_work(self):
        calls = []
        original = coverage.eager_call_prefix_obligations
        def inspect(*args):
            calls.append(args)
            return original(*args)
        with patch.object(coverage, 'eager_call_prefix_obligations', side_effect=inspect):
            self.eager_prefix_compare()
        self.assertEqual(len(calls), 1)
        name, sources, counts, descriptors, inventories, grouped, work = calls[0]
        for expression in ('hidden(|| make_path())', 'resolve!()',
                           'match enabled { true => make_path(), false => fallback() }'):
            changed = [list(source) for source in sources]
            for source in changed:
                source[4] = '        let exe = ' + expression + ';'
            budget = [64_000_000]
            inventory = [coverage._construct_inventory(source, budget) for source in changed]
            descriptor = [dict(previous, row=next(row for row in current[1] if row['kind'] == 'fn'))
                          for previous, current in zip(descriptors, inventory)]
            with self.subTest(expression=expression):
                self.assertIsNone(original(name, changed, counts, descriptor, inventory, grouped, budget))

    def test_eager_prefix_keeps_one_joint_matching_across_complete_copies(self):
        def copies(base, head, split=False):
            for side in (base, head):
                extra = json.loads(json.dumps(side['owners']))
                for owner in extra:
                    owner['name'] = re.sub(r'Cs[^_]+_', 'Cs2_', owner['name'])
                    owner['count'] = 0
                    for region in owner['regions']:
                        region[4] = 0
                side['owners'].extend(extra)
            if split:
                head['owners'][1]['regions'][6][4] = 0
                head['owners'][3]['regions'][6][4] = 1
        receipt = self.eager_prefix_compare(copies)
        proof = next(row for row in receipt['retained_replacement_obligations'] if 'eager_call_prefix' in row)
        self.assertEqual(len(proof['base_instance_states']), 2)
        self.assertEqual(len(proof['instance_matching']), 2)
        with self.assertRaisesRegex(ValueError, 'Eager call prefix lost compiled-copy coverage'):
            self.eager_prefix_compare(lambda base, head: copies(base, head, split=True))

    def test_eager_prefix_refuses_foreign_overlapping_owners_and_changed_bindings(self):
        for mode in ('foreign', 'binding', 'callee'):
            def mutate(base, head):
                if mode == 'foreign':
                    head['owners'].append(dict(name='_RNvCs2_7example7foreign', count=1,
                        filenames=['/src/example.rs'], regions=[[7, 13, 7, 41, 1, 0, 0, 0]]))
                elif mode == 'binding':
                    for side, provider in ((base, 'first'), (head, 'second')):
                        side['source'].insert(0, f'use {provider}::payload_command;')
                        side['counts'] = [[line+1, count] for line, count in side['counts']]
                        for owner in side['owners']:
                            for region in owner['regions']:
                                region[0] += 1; region[2] += 1
                else:
                    head['source'][5] = head['source'][5].replace('payload_command', 'changed_command')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.eager_prefix_compare(mutate)

    def test_eager_prefix_cannot_paint_a_cold_subregion_under_a_hot_parent(self):
        def mutate(base, head):
            for side in (base, head):
                side['owners'][1]['regions'].append([6, 1, 9, 34, 1, 0, 0, 0])
            head['owners'][1]['regions'][6][4] = 0
        with self.assertRaisesRegex(ValueError, 'Eager call prefix lost compiled-copy coverage'):
            self.eager_prefix_compare(mutate)

    def test_eager_prefix_obeys_the_shared_work_bound(self):
        calls = []
        original = coverage.eager_call_prefix_obligations
        def inspect(*args):
            calls.append(args)
            return original(*args)
        with patch.object(coverage, 'eager_call_prefix_obligations', side_effect=inspect):
            self.eager_prefix_compare()
        self.assertEqual(len(calls), 1)
        budget = [64_000_000]
        result = original(*calls[0][:-1], budget)
        self.assertIsNotNone(result)
        used = 64_000_000 - budget[0]
        self.assertGreater(used, 0)
        with self.assertRaisesRegex(ValueError, 'work'):
            original(*calls[0][:-1], [used - 1])

    def test_extracted_callback_requires_complete_source_ownership_proof(self):
        with self.assertRaisesRegex(ValueError, 'complete callback/phase evidence required'):
            self.extracted_callback_predicate_compare()

    def test_closed_compiled_owner_inventory_cannot_fall_back_after_losing_a_copy_or_layout(self):
        for mode in ('missing_copy', 'changed_geometry'):
            def mutate(base, head):
                if mode == 'missing_copy':
                    del head[3:]
                else:
                    head[3]['regions'][1][1] += 1
            with self.subTest(mode=mode), self.assertRaisesRegex(
                    ValueError, 'complete compiled-copy inventory|closed compiled-owner layout'):
                self.extracted_callback_predicate_compare(mutate)

    def nominal_async_callback_compare(self, mutation=None, context_change=False, inherent=False):
        old = (b'impl Model for StatusModel {\n'
               b'    fn update(&mut self) -> Cmd {\n'
               b'        Cmd::exec(move || {\n'
               b'            bridge(async move {\n'
               b'                timeout(500, async {\n'
               b'                    old_step();\n'
               b'                    verify(first && second, third && fourth);\n'
               b'                }).await\n'
               b'            });\n'
               b'            bridge(async move {\n'
               b'                fallback();\n'
               b'            })\n'
               b'        })\n'
               b'    }\n'
               b'}\n')
        if inherent:
            old = old.replace(b'impl Model for StatusModel', b'impl StatusModel')
        new = old.replace(b'old_step', b'new_step')
        if context_change:
            new = new.replace(b'timeout', b'reroute')
        def owners(base, head):
            for document, source in ((base, old), (head, new)):
                lines = source.decode().splitlines(); members = []
                def region(line, token, count):
                    column = lines[line-1].index(token) + 1
                    return [line, column, line, column+len(token), count, 0, 0, 0]
                for number in (1, 2):
                    scope = f'NtCs{number}_7example5scope'
                    parent = (f'_RNvM{scope}Nt{scope}11StatusModel6update' if inherent
                              else f'_RNvX{scope}Nt{scope}11StatusModelNt{scope}5Model6update')
                    count = int(number == 1)
                    declarations = [
                        (parent, 1, [[2, 5, 2, lines[1].index('{')+1, 1, 0, 0, 0],
                                     region(3, 'Cmd::exec', 1), region(14, '}', 1)]),
                        ('_RNC'+parent[2:]+'0', count,
                         [region(3, '{', count), region(4, 'bridge', count),
                          region(10, 'bridge', count), region(13, '}', count)]),
                        ('_RNCNC'+parent[2:]+'00', count,
                         [region(4, '{', count), region(5, 'reroute' if document is head and context_change else 'timeout', count),
                          region(8, '.await', count), region(9, '}', count)]),
                        ('_RNCNCNC'+parent[2:]+'000', count,
                         [region(5, '{', count), region(6, 'old_step()' if document is base else 'new_step()', count),
                          region(7, 'verify', count), region(7, 'second', count),
                          region(7, 'fourth', count), region(8, '}', count)]),
                        ('_RNCNC'+parent[2:]+'0s_0', count,
                         [region(10, '{', count), region(11, 'fallback()', count), region(12, '}', count)])]
                    members.extend(dict(name=name, count=hits, filenames=['/src/example.rs'], regions=regions)
                                   for name, hits, regions in declarations)
                document['data'][0]['functions'] = members
            if mutation:
                mutation(base['data'][0]['functions'], head['data'][0]['functions'])
        counts = [(line, 2 if line in (2, 3, 14) else 1) for line in range(2, 15)]
        return self.compare(before=counts, after=counts, mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))

    def test_nominal_nested_async_fragment_keeps_constructor_and_poll_owners(self):
        for inherent in (False, True):
            with self.subTest(inherent=inherent):
                result = self.nominal_async_callback_compare(inherent=inherent)
                self.assertTrue(any(proof.get('nominal_phase_fragments')
                                    for proof in result['positive_source_fragments']))
                self.assertEqual([result[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                         'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])

    def test_nominal_async_phase_refuses_missing_cold_or_foreign_evidence(self):
        def mutate(base, head, mode):
            if mode in ('constructor-only', 'poll-only'):
                owner = head[3 if mode == 'constructor-only' else 2]
                owner['count'] = 0
                for region in owner['regions']: region[4] = 0
            elif mode == 'missing-poll': head.pop(3)
            elif mode == 'missing-sibling': head.pop(4)
            elif mode == 'foreign-copy': head[3]['name'] = head[3]['name'].replace('Cs1_', 'Cs9_')
            elif mode == 'wrong-parent': head[3]['name'] = head[3]['name'][:-3] + '0s_00'
            elif mode == 'duplicate-owner': head.append(copy.deepcopy(head[3]))
            elif mode == 'foreign-file': head[3]['filenames'] = ['/another/example.rs']
            elif mode == 'changed-geometry':
                for index in (2, 7): head[index]['regions'][1][3] -= 1
            elif mode == 'cold-subregion': head[3]['regions'][2][4] = 0
            elif mode == 'disagreed-entry': head[3]['count'] = 0
            elif mode == 'cold-completion': head[3]['regions'][-1][4] = 0
            elif mode == 'missing-entry': head[3]['regions'].pop(0)
            elif mode == 'missing-fragment':
                for index in (3, 8):
                    head[index]['regions'] = [region for region in head[index]['regions'] if region[0] != 7]
            elif mode in ('cold-root', 'cold-sync', 'cold-sibling'):
                owner = head[{'cold-root': 0, 'cold-sync': 1, 'cold-sibling': 4}[mode]]
                owner['count'] = 0
                for region in owner['regions']: region[4] = 0
            elif mode == 'missing-sync': head.pop(1)
            elif mode == 'wide-region': head[3]['regions'][1][2] = 13
            elif mode == 'foreign-overlap':
                head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                                 regions=[copy.deepcopy(head[2]['regions'][1])]))
            elif mode == 'different-type':
                for owner in head: owner['name'] = owner['name'].replace('11StatusModel', '12AnotherModel')
            elif mode == 'swapped-siblings':
                for index in (2, 7):
                    head[index]['name'], head[index+2]['name'] = head[index+2]['name'], head[index]['name']
        for mode in ('constructor-only', 'poll-only', 'missing-poll', 'missing-sibling', 'foreign-copy',
                     'wrong-parent', 'duplicate-owner', 'foreign-file', 'changed-geometry', 'cold-subregion',
                     'disagreed-entry', 'cold-completion', 'missing-entry', 'wide-region', 'foreign-overlap',
                     'different-type', 'swapped-siblings', 'missing-fragment',
                     'cold-root', 'cold-sync', 'cold-sibling', 'missing-sync'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.nominal_async_callback_compare(lambda base, head: mutate(base, head, mode))

    def test_nominal_async_phase_preserves_one_matching_across_all_regions(self):
        def populate(base, head):
            for members in (base, head):
                for owner in members:
                    owner['count'] = 1
                    for region in owner['regions']: region[4] = 1
                members[3]['regions'][3][4] = 0
                members[8]['regions'][4][4] = 0
        self.nominal_async_callback_compare(populate)
        def redistribute(base, head):
            populate(base, head)
            head[3]['regions'][3][4] = 1
            head[8]['regions'][3][4] = 0
        with self.assertRaises(ValueError):
            self.nominal_async_callback_compare(redistribute)

    def test_nominal_async_phase_accepts_newly_executed_complete_copy(self):
        def execute(base, head):
            for owner in head[5:]:
                owner['count'] = 1
                for region in owner['regions']: region[4] = 1
        self.nominal_async_callback_compare(execute)

    def test_nominal_async_phase_cannot_borrow_identical_text_from_a_changed_call_context(self):
        with self.assertRaises(ValueError):
            self.nominal_async_callback_compare(context_change=True)

    def test_nominal_async_phase_obeys_shared_work_exhaustion_with_and_without_prepared_inventory(self):
        original = coverage.nominal_phase_fragment
        captured = []
        def record(*args):
            captured.append(args)
            return original(*args)
        with patch.object(coverage, 'nominal_phase_fragment', side_effect=record):
            self.nominal_async_callback_compare()
        self.assertTrue(captured)
        for cache in ({}, captured[-1][-1]):
            args = list(captured[-1])
            args[-2] = [0]
            args[-1] = cache
            with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                original(*args)
        self.nominal_async_callback_compare()

    def test_changed_callback_body_keeps_precise_parent_and_child_obligations(self):
        result = self.changed_callback_compare()
        self.assertEqual([result[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        proofs = result['positive_source_fragments']
        self.assertTrue(any(row.get('callback_fragments') for row in proofs))

    def test_changed_callback_accepts_move_closure(self):
        self.changed_callback_compare(callback_form='move ||')

    def test_changed_callback_accepts_header_region_ending_at_its_last_token(self):
        self.changed_callback_compare(header_end='token')

    def test_changed_callback_refuses_partial_duplicate_or_changed_header_regions(self):
        def mutate(owners, mode):
            for owner in (owners[0], owners[2]):
                if mode == 'duplicate':
                    owner['regions'].append(copy.deepcopy(owner['regions'][0]))
                else:
                    owner['regions'][0][3] -= 2 if mode == 'partial' else 1
        for mode in ('partial', 'duplicate', 'changed-geometry'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.changed_callback_compare(lambda owners: mutate(owners, mode))

    def test_changed_callback_refuses_boolean_or_and_async_closure(self):
        for form in ('ready ||', 'async ||', 'async move ||'):
            with self.subTest(form=form), self.assertRaises(ValueError):
                self.changed_callback_compare(callback_form=form)

    def test_changed_callback_body_refuses_cold_missing_or_aliased_owners(self):
        def mutate(owners, mode):
            if mode == 'cold-parent':
                owners[0]['count'] = owners[0]['regions'][0][4] = 0
            elif mode == 'cold-child':
                owners[1]['count'] = owners[1]['regions'][0][4] = 0
            elif mode == 'cold-call-prefix': owners[0]['regions'][2][4] = 0
            elif mode == 'cold-parent-setup': owners[0]['regions'][1][4] = 0
            elif mode == 'cold-child-work': owners[1]['regions'][2][4] = 0
            elif mode == 'missing-child': owners.pop(1)
            elif mode == 'duplicate-ordinal':
                extra = copy.deepcopy(owners[1])
                extra['name'] = extra['name'].replace('checked0B3_', 'checkeds_0B3_')
                owners.append(extra)
            elif mode == 'different-item':
                for owner in owners[:4]: owner['name'] = owner['name'].replace('s_7checked', 's0_7checked')
        for mode in ('cold-parent', 'cold-child', 'cold-call-prefix', 'cold-parent-setup', 'cold-child-work',
                     'missing-child', 'duplicate-ordinal', 'different-item'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.changed_callback_compare(lambda owners: mutate(owners, mode))
        with self.assertRaises(ValueError):
            self.changed_callback_compare(context_change=True)

    def test_changed_callback_fragments_require_one_joint_parent_child_matching(self):
        self.changed_callback_compare(joint=True)
        def split(owners):
            owners[1]['regions'][3][4] = 0
            owners[3]['regions'][3][4] = 1
        with self.assertRaises(ValueError):
            self.changed_callback_compare(mutation=split, joint=True)

    def test_rust_function_paths_preserve_identifier_disambiguators(self):
        symbol = '_RNvNtCs1_7example5testss_7checked'
        path = coverage.plain_rust_function_symbol(symbol)
        self.assertIsNotNone(path)
        self.assertEqual(path.identifiers, ('example', 'tests', 'checked'))
        self.assertEqual(path.disambiguators, ('', '', 's_'))
        self.assertEqual(path.identity, (('example', ''), ('tests', ''), ('checked', 's_')))
        other = coverage.plain_rust_function_symbol('_RNvNtCs2_7examples_5testss0_7checked')
        self.assertEqual(other.identifiers, path.identifiers)
        self.assertNotEqual(other.identity, path.identity)

    def test_rust_function_paths_keep_crate_copies_separate_from_item_identity(self):
        paths = [coverage.plain_rust_function_symbol(f'_RNvNtCs{number}_7example5testss_7checked')
                 for number in (1, 2)]
        self.assertTrue(all(path is not None for path in paths))
        self.assertEqual(paths[0].identity, paths[1].identity)

    def test_rust_function_paths_refuse_incomplete_or_instantiated_identifiers(self):
        for symbol in ('_RNvNtCs1_7example5testss7checked',
                       '_RNvNtCs1_7example5testss_7checkedC3foo',
                       '_RNvNtCs1_7example5testss_8checked'):
            with self.subTest(symbol=symbol):
                self.assertIsNone(coverage.plain_rust_function_symbol(symbol))

    def changed_async_arguments_compare(self, mutation=None, base_called=True, base_mutation=None):
        old = (b'async fn checked() {\n    enforce(\n        old_argument(),\n    );\n}\n'
               b'async fn retained() {\n    enforce(\n        old_argument(),\n    );\n}\n')
        new = old.replace(b'old_argument()', b'new_argument()', 1)
        def owners(base, head):
            for document, source in ((base, old), (head, new)):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = []
                for name, first in (('checked', 1), ('retained', 6)):
                    opening = lines[first - 1].index('{') + 1
                    for number in range(2):
                        parent = f'_RNvCs{number + 1}_7example{len(name)}{name}'
                        document['data'][0]['functions'].extend([
                            dict(name=parent, count=1, filenames=['/src/example.rs'],
                                 regions=[[first, 1, first, opening - 1, 1, 0, 0, 0]]),
                            dict(name='_RNC' + parent[2:] + '0B3_', count=1,
                                 filenames=['/src/example.rs'], regions=[
                                     [first, opening, first, opening + 1, 1, 0, 0, 0],
                                     *[[line, 1, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                                       for line in range(first + 1, first + 5)]])])
            if mutation:
                mutation(head['data'][0]['functions'])
            if not base_called:
                for owner in base['data'][0]['functions'][:4]:
                    owner['count'] = 0
                    for region in owner['regions']:
                        region[4] = 0
            if base_mutation:
                base_mutation(base['data'][0]['functions'])
        return self.compare(before=[(line, 2 if base_called or line > 5 else 0) for line in range(1, 11)],
            after=[(line, 2) for line in range(1, 11)], mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))

    def test_changed_async_arguments_keep_the_covered_call_obligation(self):
        result = self.changed_async_arguments_compare()
        self.assertEqual([result[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertTrue(result['positive_source_fragments'])

    def test_changed_async_arguments_preserve_previously_unexecuted_copies(self):
        result = self.changed_async_arguments_compare(base_called=False)
        self.assertEqual([result[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertTrue(result['positive_source_fragments'])

    def test_async_call_head_keeps_different_raw_annotations_distinct(self):
        def original(owners):
            for owner in (owners[1], owners[3]):
                owner['regions'].append([2, 5, 2, 12, 1, 0, 0, 0])
        def current(owners):
            for owner in (owners[1], owners[3]):
                owner['regions'][1][1:4] = [5, 2, 12]
        # Equal observed hit counts do not prove that two compiler counters
        # represent the same work. Preserve the refusal until identity is proved.
        with self.assertRaisesRegex(ValueError, r'example\.rs:2-2 -> 2-2'):
            self.changed_async_arguments_compare(current, base_mutation=original)

    def test_async_call_head_refuses_mixed_partial_or_punctuation_only_contributors(self):
        def extra(owners, mode):
            for owner in (owners[1], owners[3]):
                row = {'mixed': [2, 5, 2, 12, 0, 0, 0, 0],
                       'partial': [2, 6, 2, 12, 1, 0, 0, 0],
                       'punctuation': [2, 12, 2, 13, 1, 0, 0, 0]}[mode]
                owner['regions'].append(row)
        def current(owners):
            for owner in (owners[1], owners[3]):
                owner['regions'][1][1:4] = [5, 2, 12]
        for mode in ('mixed', 'partial', 'punctuation'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.changed_async_arguments_compare(current,
                    base_mutation=lambda owners: extra(owners, mode))

    def test_changed_async_arguments_cannot_borrow_phase_or_subexpression_hits(self):
        def mutate(owners, mode):
            if mode == 'cold-constructor': owners[0]['regions'][0][4] = 0
            elif mode == 'cold-call': owners[1]['regions'][1][4] = 0
            elif mode == 'cold-subexpression':
                for owner in (owners[1], owners[3]):
                    owner['regions'].append([2, 5, 2, 8, 0, 0, 0, 0])
            elif mode == 'missing-constructor': owners.pop(0)
            elif mode == 'missing-all-constructors':
                owners.pop(2); owners.pop(0)
            elif mode == 'unsupported-symbols':
                for number, owner in enumerate(owners[:4]):
                    owner['name'] = f'unsupported_owner_{number}'
        for mode in ('cold-constructor', 'cold-call', 'cold-subexpression', 'missing-constructor',
                     'missing-all-constructors', 'unsupported-symbols'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.changed_async_arguments_compare(lambda owners: mutate(owners, mode))

    def async_positive_fragment_compare(self, mutation=None, joint=False, inherent=False):
        old = ['async fn checked(', '    old: bool,', ') {',
               '    verify();', '    finish();', '}']
        new = [line.replace('old:', 'new:') for line in old]
        documents = []
        for side, source in enumerate((old, new)):
            owners = []
            for copy_number in range(2):
                parent = f'_RNvCs{copy_number + 1}_7example7checked'
                owners.extend([
                    dict(name=parent, count=1, filenames=['/src/example.rs'],
                         regions=[[1, 1, 3, 2, 1, 0, 0, 0]]),
                    dict(name='_RNC' + parent[2:] + '0B3_', count=1,
                         filenames=['/src/example.rs'], regions=[
                             [3, 3, 3, 4, 1, 0, 0, 0],
                             [4, 5, 4, 14, int(not joint or copy_number == 0), 0, 0, 0],
                             [5, 5, 5, 14, int(not joint or copy_number == 0), 0, 0, 0],
                             [6, 1, 6, 2, 1, 0, 0, 0]])])
            documents.append(owners)
        fragments = [(3, 4, 3, 4, (4,))]
        if joint:
            fragments.append((4, 5, 4, 5, (5,)))
        before = {4: 1 if joint else 2, 5: 1 if joint else 2}
        if inherent:
            new = old if joint else [line.replace('finish();', 'review();') for line in old]
            old, new = (['impl Manager {', *('    ' + line for line in source), '}']
                        for source in (old, new))
            for owners in documents:
                for owner in owners:
                    child = owner['name'].startswith('_RNC')
                    reference = 'B4_' if child else 'B2_'
                    owner['name'] = owner['name'].replace('NvC', 'NvMC').replace(
                        '7example7checked', f'7exampleNt{reference}7Manager7checked')
                    if child:
                        owner['name'] = owner['name'].removesuffix('B3_') + reference
                    for region in owner['regions']:
                        region[0] += 1; region[2] += 1
                        region[1] += 4; region[3] += 4
            fragments = [(a + 1, b + 1, c + 1, d + 1, tuple(line + 1 for line in lines))
                         for a, b, c, d, lines in fragments]
            before = {line + 1: count for line, count in before.items()}
        if mutation:
            mutation(documents)
        original = copy.deepcopy(documents)
        phase_lines = dict(inherent_async_lines=((5,), (5,))) if inherent else {}
        try:
            return coverage.positive_source_fragments('example.rs', old, new, before, before.copy(), *documents,
                {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'}, fragments, **phase_lines)
        finally:
            self.assertEqual(documents, original, 'phase proof must preserve the raw producer evidence')

    def test_async_positive_fragment_preserves_distinct_constructor_and_body_copies(self):
        pairs, receipts = self.async_positive_fragment_compare()
        self.assertEqual(pairs, {4: 4})
        self.assertEqual(receipts[0]['instances'], 2)
        self.assertEqual(len(receipts[0]['async_copies']['base']), 2)
        self.assertEqual(len(receipts[0]['async_copies']['head']), 2)

    def test_inherent_async_fragment_preserves_both_phases_of_each_compiled_copy(self):
        pairs, receipts = self.async_positive_fragment_compare(inherent=True)
        self.assertEqual(pairs, {5: 5})
        self.assertEqual(receipts[0]['instances'], 2)
        self.assertEqual(len(receipts[0]['async_copies']['head']), 2)

    def test_inherent_async_fragment_refuses_unbound_or_cold_evidence(self):
        def change(owners, mode):
            head = owners[1]
            if mode == 'foreign-type':
                head[1]['name'] = head[1]['name'].replace('Manager', 'Another')
            elif mode == 'foreign-copy':
                head[1]['name'] = head[1]['name'].replace('Cs1_', 'Cs3_')
            elif mode == 'same-copy-different-spelling':
                head[2]['name'] = head[0]['name'].replace('B2_', 'Cs1_7example')
            elif mode == 'cold-constructor':
                head[0]['regions'][0][4] = 0
            elif mode == 'cold-body':
                head[1]['regions'][1][4] = 0
            elif mode == 'missing-body':
                head.pop(1)
            else:
                head.append(copy.deepcopy(head[1]))
        for mode in ('foreign-type', 'foreign-copy', 'same-copy-different-spelling', 'cold-constructor', 'cold-body',
                     'missing-body', 'duplicate-body'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.async_positive_fragment_compare(lambda owners: change(owners, mode), inherent=True)

    def test_inherent_async_retains_execution_within_matching_copy_identities(self):
        def move_hits(owners):
            owners[1][1]['regions'][1][4] = owners[1][1]['regions'][2][4] = 0
            owners[1][3]['regions'][1][4] = owners[1][3]['regions'][2][4] = 1
        pairs, _ = self.async_positive_fragment_compare(joint=True, inherent=True)
        self.assertEqual(pairs, {5: 5, 6: 6})
        with self.assertRaisesRegex(ValueError, 'Ambiguous unchanged'):
            self.async_positive_fragment_compare(move_hits, joint=True, inherent=True)

    def guarded_async_compare(self, mutation=None, modules=('tests',), feature_guard=True,
                              joint=False, exhausted=False):
        original = coverage.positive_source_fragments
        def scoped(name, old, new, before, after, base, head, base_files, head_files, fragments):
            prefix = []
            for depth, module in enumerate(modules):
                if depth == 0:
                    prefix.append('#[cfg(test)]')
                prefix.append('    ' * depth + f'mod {module} {{')
            indent = '    ' * len(modules)
            if feature_guard:
                prefix.append(indent + '#[cfg(feature = "arch")]')
            shift = len(prefix)
            sources = [prefix + [indent + line for line in source]
                       + ['    ' * depth + '}' for depth in reversed(range(len(modules)))]
                       for source in (old, new)]
            documents = copy.deepcopy([base, head])
            for owners in documents:
                for owner in owners:
                    owner['name'] = owner['name'].replace('NvCs', 'Nv' + 'Nt' * len(modules) + 'Cs')
                    owner['name'] = owner['name'].replace('7example7checked', '7example'
                        + ''.join(f'{len(module)}{module}' for module in modules) + '7checked')
                    if owner['name'].endswith('B3_'):
                        owner['name'] = owner['name'][:-3] + 'B' + str(3 + 2 * len(modules)) + '_'
                    for row in owner['regions']:
                        row[0] += shift; row[2] += shift
                        row[1] += len(indent); row[3] += len(indent)
            if mutation:
                mutation(sources, documents)
            mapped = [{line + shift: count for line, count in counts.items()} for counts in (before, after)]
            pending = [(a+shift, b+shift, c+shift, d+shift, [line+shift for line in lines])
                       for a, b, c, d, lines in fragments]
            return original(name, *sources, *mapped, *documents, base_files, head_files, pending,
                            work=[0] if exhausted else None)
        with patch.object(coverage, 'positive_source_fragments', side_effect=scoped):
            return self.async_positive_fragment_compare(joint=joint)

    def test_guarded_async_functions_bind_module_and_feature_context(self):
        for modules, guard in (((), True), (('tests',), True), (('tests',), False),
                               (('outer', 'tests'), True)):
            with self.subTest(modules=modules, feature_guard=guard):
                pairs, receipts = self.guarded_async_compare(modules=modules, feature_guard=guard)
                self.assertEqual(len(pairs), 1)
                self.assertEqual(len(receipts[0]['async_copies']['base']), 2)
                self.assertEqual(len(receipts[0]['async_copies']['head']), 2)
        def test_guard(sources, documents):
            for source in sources:
                source[:] = [line.replace('#[cfg(feature = "arch")]', '#[cfg(test)]') for line in source]
        pairs, _ = self.guarded_async_compare(test_guard, modules=())
        self.assertEqual(len(pairs), 1)

    def test_guarded_async_functions_refuse_changed_guards_and_foreign_modules(self):
        def mutate(sources, documents, mode):
            replacements = {
                'feature': ('#[cfg(feature = "arch")]', '#[cfg(feature = "debian")]'),
                'module-guard': ('#[cfg(test)]', '#[cfg(feature = "arch")]'),
                'duplicate-module-guard': ('#[cfg(test)]', '#[cfg(test)] #[cfg(test)]'),
                'module': ('mod tests {', 'mod other {'),
                'attribute': ('#[cfg(feature = "arch")]', '#[trace]'),
                'cfg-attribute-macro': ('#[cfg(feature = "arch")]', '#[cfg_attr(feature = "arch", trace)]'),
            }
            if mode in replacements:
                old, new = replacements[mode]
                sources[1][:] = [line.replace(old, new) for line in sources[1]]
            else:
                for owner in documents[1]:
                    owner['name'] = owner['name'].replace('5tests', '5other')
        for mode in ('feature', 'module-guard', 'duplicate-module-guard', 'module', 'attribute',
                     'cfg-attribute-macro', 'raw-module'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.guarded_async_compare(lambda sources, documents: mutate(sources, documents, mode))

    def test_guarded_async_functions_keep_every_constructor_and_poll_copy(self):
        def mutate(sources, documents, mode):
            owners = documents[1]
            if mode == 'missing-constructor':
                owners.pop(0)
            elif mode == 'missing-poll':
                owners.pop(1)
            elif mode == 'duplicate-poll':
                owners.append(copy.deepcopy(owners[1]))
            elif mode == 'cold-constructor':
                owners[0]['regions'][0][4] = 0
            else:
                owners[1]['regions'][0][4] = 0
        for mode in ('missing-constructor', 'missing-poll', 'duplicate-poll', 'cold-constructor', 'cold-poll'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.guarded_async_compare(lambda sources, documents: mutate(sources, documents, mode))

    def test_guarded_async_fragments_require_one_joint_copy_matching(self):
        pairs, _ = self.guarded_async_compare(joint=True)
        self.assertEqual(len(pairs), 2)
        def split(sources, documents):
            documents[1][1]['regions'][2][4] = 0
            documents[1][3]['regions'][2][4] = 1
        with self.assertRaises(ValueError):
            self.guarded_async_compare(split, joint=True)

    def test_guarded_async_discovery_obeys_the_shared_work_budget(self):
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            self.guarded_async_compare(exhausted=True)

    def test_async_positive_fragment_refuses_incomplete_or_cold_phase_evidence(self):
        def mutate(owners, mode):
            head = owners[1]
            if mode == 'cold-constructor': head[0]['regions'][0][4] = 0
            elif mode == 'cold-body': head[1]['regions'][1][4] = 0
            elif mode == 'cold-poll-entry-with-hot-enclosing-region':
                head[1]['regions'][0][4] = 0
                for owner in (head[1], head[3]):
                    owner['regions'].append([3, 3, 6, 2, 1, 0, 0, 0])
            elif mode == 'cold-fragment-subexpression':
                for owner in (head[1], head[3]):
                    owner['regions'].append([4, 5, 4, 11, 0, 0, 0, 0])
            elif mode == 'missing-constructor': head.pop(0)
            elif mode == 'missing-body': head.pop(1)
            elif mode == 'foreign-file': head[1]['filenames'] = ['/src/elsewhere.rs']
            elif mode == 'multi-file': head[1]['filenames'].append('/src/elsewhere.rs')
            elif mode == 'unlinked-body': head[1]['name'] += 'x'
            elif mode == 'duplicate-body': head.append(copy.deepcopy(head[1]))
            elif mode == 'different-namespace':
                for owner in head: owner['name'] = owner['name'].replace('7example', '7another')
        for mode in ('cold-constructor', 'cold-body', 'cold-poll-entry-with-hot-enclosing-region',
                     'cold-fragment-subexpression',
                     'missing-constructor', 'missing-body',
                     'foreign-file', 'multi-file', 'unlinked-body', 'duplicate-body', 'different-namespace'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.async_positive_fragment_compare(lambda owners: mutate(owners, mode))

    def test_async_positive_fragments_require_one_joint_copy_matching(self):
        pairs, _ = self.async_positive_fragment_compare(joint=True)
        self.assertEqual(pairs, {4: 4, 5: 5})
        def split_hits(owners):
            owners[1][1]['regions'][2][4] = 0
            owners[1][3]['regions'][2][4] = 1
        with self.assertRaises(ValueError):
            self.async_positive_fragment_compare(split_hits, joint=True)

    def test_async_fragment_failure_identifies_the_fragment_being_checked(self):
        def change_second_fragment(owners):
            for owner in (owners[1][1], owners[1][3]):
                owner['regions'].append([5, 5, 5, 11, 0, 0, 0, 0])
        with self.assertRaisesRegex(ValueError, r'example\.rs:5-5 -> 5-5'):
            self.async_positive_fragment_compare(change_second_fragment, joint=True)

    def async_endpoint_compare(self, alternative_kind='else'):
        old = ['async fn checked(', '    old: bool,', ') {', '    if old {',
               '        verify();', '    }', '    finish();', '}']
        new = ['async fn checked(', '    new: bool,', ') {', '    if new {',
               '        verify();', '    }',
               '    {' if alternative_kind == 'block' else '    if new {', '        finish();',
               '    } else {' if alternative_kind == 'else' else '        // separate block',
               '        finish();', '    }', '}']
        owners = []
        for side, source in enumerate((old, new)):
            rows = []
            for copy_number in range(2):
                parent = f'_RNvCs{copy_number + 1}_7example7checked'
                rows.extend([
                    dict(name=parent, count=1, filenames=['/src/example.rs'],
                         regions=[[1, 1, 3, 2, 1, 0, 0, 0]]),
                    dict(name='_RNC' + parent[2:] + '0B3_', count=1,
                         filenames=['/src/example.rs'], regions=[
                             [3, 3, 3, 4, 1, 0, 0, 0],
                             *[[number, 1, number, len(text) + 1, 1, 0, 0, 0]
                               for number, text in enumerate(source, 1)
                               if number > 3 and not (side == 1 and number == 11)]])])
            owners.append(rows)
        return coverage.positive_source_fragments('example.rs', old, new, {6: 2}, {6: 2},
            *owners, {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'},
            [(5, 6, 5, 6, (6,))])

    def test_async_endpoint_uses_its_lexical_control_owner(self):
        pairs, receipts = self.async_endpoint_compare()
        self.assertEqual(pairs, {6: 6})
        self.assertTrue(receipts[0]['async_endpoint_contexts'])

    def test_async_await_fragments_compare_their_immediate_call(self):
        source = ['async fn checked() {', '    let first = request', '        .send()',
                  '        .await', '        .done();', '    let second = first',
                  '        .decode()', '        .await', '        .done();', '}']
        filename = '/src/example.rs'
        files = {filename: 'example.rs'}
        def owners(crate, second_column):
            parent = f'_RNvCs{crate}_7example7checked'
            opening = source[0].index('{') + 1
            return [dict(name=parent, count=1, filenames=[filename],
                         regions=[[1, 1, 1, opening - 1, 1, 0, 0, 0]]),
                    dict(name='_RNC' + parent[2:] + '0B3_', count=1, filenames=[filename],
                         regions=[[1, opening, 1, opening + 1, 1, 0, 0, 0],
                                  [4, 1, 4, 15, 1, 0, 0, 0],
                                  [8, second_column, 8, 15, 1, 0, 0, 0],
                                  [10, 1, 10, 2, 1, 0, 0, 0]])]
        def compare(head, target, head_owners):
            return coverage.positive_source_fragments('example.rs', source, head,
                {4: 1, 8: 1}, {4: 1, 8: 1}, owners(1, 9), head_owners, files, files,
                [(3, 4, target - 1, target, (4,))])
        pairs, receipts = compare(source, 4, owners(2, 9))
        self.assertEqual(pairs, {4: 4})
        self.assertEqual(receipts[0]['async_await_contexts'][1]['candidates'], [[4, 'send'], [8, 'decode']])
        with self.assertRaisesRegex(ValueError, 'Ambiguous unchanged'):
            compare(source, 8, owners(2, 1))
        with self.assertRaisesRegex(ValueError, 'Ambiguous unchanged'):
            compare([*source[:2], '        .publish()', *source[3:]], 4, owners(2, 9))

    def test_async_endpoint_keeps_unmapped_candidates_of_the_same_control_kind(self):
        with self.assertRaises(ValueError):
            self.async_endpoint_compare(alternative_kind='if')

    def test_async_endpoint_refuses_an_unclassified_alternative_owner(self):
        with self.assertRaises(ValueError):
            self.async_endpoint_compare(alternative_kind='block')

    def test_async_phase_discovery_obeys_the_existing_shared_work_bound(self):
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage.compiled_async_function_groups('example.rs', [], {},
                ['async fn checked() {', '    verify();', '}'], work=[0])

    def retained_record_field_compare(self, head_counts=(1, 1), ancestor_counts=None,
                                      refinement_counts=None, base_refinement_counts=None):
        old = b'struct Config { name: String }\nimpl Config {\n    pub fn make(section: &str) -> Self {\n        Self {\n            name: section.to_string(),\n        }\n    }\n}\n'
        new = b'struct Config { name: String, enabled: bool }\nimpl Config {\n    pub fn make(section: &str) -> Self {\n        Self {\n            name: section.to_string(),\n            enabled: true,\n        }\n    }\n}\n'
        def owners(base, head):
            for document, source, last, counts in ((base, old, 7, (1, 1)),
                                                   (head, new, 8, head_counts)):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(
                    name=f'make_{instance}', filenames=['/src/example.rs'],
                    regions=[[3, lines[2].index('{') + 1, last, 6, count, 0, 0, 0]])
                    for instance, count in enumerate(counts)]
                if document is base and base_refinement_counts is not None:
                    for instance, function in enumerate(document['data'][0]['functions']):
                        function['regions'].append([5, 19, 5, 26,
                            base_refinement_counts[instance], 0, 0, 0])
                if document is head:
                    for instance, function in enumerate(document['data'][0]['functions']):
                        count = (counts if ancestor_counts is None else ancestor_counts)[instance]
                        function['regions'].append([4, 9, 7, 10, count, 0, 0, 0])
                        if refinement_counts is not None:
                            function['regions'].append([5, 19, 5, 26,
                                refinement_counts[instance], 0, 0, 0])
        return self.compare(before=[(line, 2) for line in range(3, 8)],
            after=[(line, sum(head_counts)) for line in range(3, 9)], mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))

    def test_retained_record_field_preserves_execution_in_every_compiled_copy(self):
        receipt = self.retained_record_field_compare()
        self.assertEqual(receipt['deleted_mapped_hit'], 0)

    def test_retained_record_field_cannot_borrow_another_compiled_copy(self):
        with self.assertRaises(ValueError):
            self.retained_record_field_compare((2, 0))

    def test_retained_record_field_cannot_paint_a_cold_nested_region(self):
        with self.assertRaises(ValueError):
            self.retained_record_field_compare(ancestor_counts=(0, 2))

    def test_retained_record_field_permits_uniform_region_refinement(self):
        receipt = self.retained_record_field_compare(refinement_counts=(1, 1))
        self.assertEqual(receipt['deleted_mapped_hit'], 0)

    def test_retained_record_field_refinement_cannot_paint_a_cold_subexpression(self):
        with self.assertRaises(ValueError):
            self.retained_record_field_compare(refinement_counts=(0, 2))

    def test_retained_record_field_keeps_existing_cold_subexpression_obligations(self):
        receipt = self.retained_record_field_compare(refinement_counts=(0, 2),
                                                     base_refinement_counts=(0, 2))
        self.assertEqual(receipt['deleted_mapped_hit'], 0)

    old_source = b"fn obsolete() {\n}\nfn retained() {\n  exercised();\n  untested();\n}\n"
    new_source = b"fn retained() {\n  exercised();\n  untested();\n}\n"

    def control_endpoint_compare(self, *, cold=False, rewrite=None, extra_head=None):
        old = ('async fn checked(\n    old: bool,\n) {\n'
               '    if old {\n        old_work();\n    }\n    old_tail();\n}\n')
        new = ('async fn checked(\n    new: bool,\n) {\n    new_head();\n'
               '    if new {\n        new_work();\n    } else {\n'
               '        replacement();\n    }\n    new_tail();\n}\n')
        if rewrite:
            old, new = rewrite(old, new)
        sources = [source.splitlines() for source in (old, new)]
        target = next(n for n, text in enumerate(sources[1], 1) if text == '    }')
        counts = [[(n, 2 * int(not (side == 1 and cold and n == target)))
                   for n in range(1, len(source) + 1) if side == 0 or cold or n != target]
                  for side, source in enumerate(sources)]
        def owners(base, head):
            for side, document in enumerate((base, head)):
                source = sources[side]
                document['data'][0]['functions'] = []
                for copy in range(2):
                    constructor = f'_RNvCs{copy + 1}_7example7checked'
                    document['data'][0]['functions'].extend([
                        dict(name=constructor, count=1, filenames=['/src/example.rs'],
                             regions=[[1, 1, 3, 2, 1, 0, 0, 0]]),
                        dict(name='_RNC' + constructor[2:] + '0B3_', count=1,
                             filenames=['/src/example.rs'], regions=[
                                [3, 3, 3, 4, 1, 0, 0, 0],
                                *[[n, 1, n, len(source[n - 1]) + 1, count // 2, 0, 0, 0]
                                  for n, count in counts[side] if n > 3]])])
        head_sources = {'example.rs': new.encode()}
        if extra_head is not None:
            head_sources['elsewhere.rs'] = extra_head
        return self.compare(before=counts[0], after=counts[1], mutate=owners,
            sources=({'example.rs': old.encode()}, head_sources))

    def test_replaced_control_endpoint_keeps_old_counts_without_deletion_credit(self):
        result = self.control_endpoint_compare()
        self.assertEqual([result[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                         'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertTrue(any(row['base_construct'] == row['head_construct'] == 'if'
                            for row in result['source_replacements']))
        self.assertTrue(all(row['summary_credit'] == row['mapped_credit'] == [0, 0]
                            for row in result['source_replacements']))

    def test_replaced_control_endpoint_cannot_retain_a_new_cold_mapping(self):
        with self.assertRaisesRegex(ValueError, r'(Retained covered line lost coverage|Ambiguous unchanged source)'):
            self.control_endpoint_compare(cold=True)

    def test_control_replacement_cannot_hide_retained_work_in_another_file(self):
        with self.assertRaises(ValueError):
            self.control_endpoint_compare(extra_head=b'fn elsewhere() { old_work(); }\n')

    def test_control_replacement_does_not_bypass_an_unchanged_parameter_scope(self):
        def rewrite(old, new):
            return (old.replace('old: bool', 'state: bool').replace('if old', 'if state'),
                    new.replace('new: bool', 'state: bool').replace('if new', 'if !state'))
        with self.assertRaises(ValueError):
            self.control_endpoint_compare(rewrite=rewrite)

    def test_replaced_iterative_and_match_endpoints_keep_old_counts(self):
        for kind in ('while', 'for', 'match'):
            def rewrite(old, new):
                new = new.replace('    } else {\n        replacement();\n    }', '    }')
                if kind == 'for':
                    return (old.replace('old: bool', 'old: Vec<usize>').replace('if old', 'for item in old'),
                            new.replace('new: bool', 'new: Vec<u64>').replace('if new', 'for item in new'))
                if kind == 'match':
                    return (old.replace('if old', 'match old').replace('old_work();', '_ => old_work(),'),
                            new.replace('if new', 'match new').replace('new_work();', '_ => new_work(),'))
                return old.replace('if old', 'while old'), new.replace('if new', 'while new')
            with self.subTest(kind=kind):
                result = self.control_endpoint_compare(rewrite=rewrite)
                self.assertEqual(result['deleted_summary_found'], 0)
                self.assertEqual(result['deleted_mapped'], 0)

    def test_control_replacement_blocks_module_tokens_before_syntax_parser(self):
        for statement in ('mod external;', '#[path = "/do-not-read.rs"] mod external;',
                          'mod nested { fn helper() {} }'):
            def rewrite(old, new):
                return old, new.replace('    new_head();', '    ' + statement + '\n    new_head();')
            with self.subTest(statement=statement), patch.object(
                    coverage.subprocess, 'run', side_effect=AssertionError('module reached syntax parser')):
                with self.assertRaises(ValueError):
                    self.control_endpoint_compare(rewrite=rewrite)

    def test_control_replacement_refuses_retained_work_changed_owners_and_invalid_syntax(self):
        rewrites = {
            'retained_body': lambda old, new: (old, new.replace('new_work();', 'old_work();')),
            'retained_statement': lambda old, new: (old, new.replace('new_work();', 'if nested { old_work(); }')),
            'retained_elsewhere': lambda old, new: (old, new + 'fn elsewhere() { old_work(); }\n'),
            'different_function': lambda old, new: (old, new.replace('fn checked(', 'fn unrelated(')),
            'duplicate_function': lambda old, new: (old, new + 'mod nested { async fn checked() {} }\n'),
            'invalid_signature': lambda old, new: (old, new.replace('new: bool', 'new: @')),
        }
        for label, rewrite in rewrites.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.control_endpoint_compare(rewrite=rewrite)

    def test_alignment_does_not_retain_a_function_endpoint_as_a_struct_endpoint(self):
        old = ['fn obsolete() {', '    old();', '}',
               'fn retained() {', '    same();', '}']
        new = ['struct Manifest {', '    generation: String,', '}',
               'fn retained() {', '    same();', '}']
        rows = list(coverage.source_opcodes(old, new, [(4, 6, 4, 6)], {3: 1, 5: 1, 6: 1}))
        pairs = {line + 1: c + line - a + 1 for tag, a, b, c, d, *_ in rows
                 if tag == 'equal' for line in range(a, b)}
        self.assertNotIn(3, pairs)
        self.assertEqual(pairs[5], 5)
        self.assertFalse(any(tag == 'delete' and a <= 2 < b for tag, a, b, *_ in rows))

    def test_alignment_does_not_retain_a_method_on_a_replaced_receiver(self):
        old = ['fn retained() {', '    let packages = db_paths', '        .par_iter()',
               '        .map(old_parse)', '        .collect();', '}']
        new = ['fn retained() {', '    let packages = config.repos', '        .par_iter()',
               '        .map(new_parse)', '        .collect();', '}']
        rows = list(coverage.source_opcodes(old, new, [(1, 6, 1, 6)],
                                            {line: 1 for line in range(1, 7)}))
        pairs = {line + 1: c + line - a + 1 for tag, a, b, c, d, *_ in rows
                 if tag == 'equal' for line in range(a, b)}
        self.assertNotIn(3, pairs)
        self.assertFalse(any(tag == 'delete' for tag, *_ in rows))

    def test_alignment_replaces_a_changed_tail_receiver_and_record_initializer(self):
        cases = [
            (['fn f() {', '    db_paths', '        .par_iter()', '        .collect()', '}'],
             ['fn f() {', '    config.repos', '        .par_iter()', '        .collect()', '}'], 3),
            (['fn f() {', '    Ok(Self {', '        files,', '        digest: encode(hash),', '    })', '}'],
             ['fn f() {', '    Ok(Self {', '        files,', '        digest: encode(hash),',
              '        parsed: OnceLock::new(),', '    })', '}'], 5),
        ]
        for old, new, endpoint in cases:
            with self.subTest(endpoint=endpoint):
                rows = list(coverage.source_opcodes(old, new, [(1, len(old), 1, len(new))],
                                                    {line: 1 for line in range(1, len(old) + 1)}))
                pairs = {line + 1: c + line - a + 1 for tag, a, b, c, d, *_ in rows
                         if tag == 'equal' for line in range(a, b)}
                self.assertNotIn(endpoint, pairs)

    def test_alignment_replaces_complete_await_receivers_and_map_statements(self):
        cases = [
            (['fn f() {', '    let client = Client {', '        path: directory.path(),', '    };', '}'],
             ['fn f() {', '    let client = Client {', '        path: directory.path().join("aur"),', '    };', '}'], 2),
            (['fn f() {', '    let result = names.map(|name| {', '        cache',
              '            .get(name)', '            .filter(|item| {', '                !old_filter(item)',
              '            })', '            .map(old_convert)', '    }).collect();', '}'],
             ['fn f() {', '    let result = names.map(|name| {', '        packages',
              '            .get(name.as_str())', '            .filter(|item| {', '                !new_filter(item)',
              '            })', '            .map(new_convert)', '    }).collect();', '}'], 5),
            (['fn f() {', '    let error = client', '        .plan(directory.path())',
              '        .await;', '}'],
             ['fn f() {', '    let error = client', '        .plan(&reviewed)',
              '        .await;', '}'], 2),
            (['async fn f() {', '    match spawn_blocking({', '        move || old()',
              '    })', '    .await', '    {', '        Ok(value) => value,', '    }', '}'],
             ['async fn f() {', '    finish(spawn_blocking(move || {', '        new()',
              '    }))', '    .await', '}'], 5),
            (['fn f() {', '    let results = paths', '        .map(|(path, name)| {',
              '            old_parse(path, name)', '        })', '        .collect();', '}'],
             ['fn f() {', '    let results = repos', '        .map(|repo| {',
              '            new_parse(repo)', '        })', '        .collect();', '}'], 5),
        ]
        for old, new, endpoint in cases:
            with self.subTest(endpoint=endpoint, old=old):
                rows = list(coverage.source_opcodes(old, new, [(1, len(old), 1, len(new))],
                                                    {line: 1 for line in range(1, len(old) + 1)}))
                pairs = {line + 1: c + line - a + 1 for tag, a, b, c, d, *_ in rows
                         if tag == 'equal' for line in range(a, b)}
                self.assertNotIn(endpoint, pairs)
                self.assertFalse(any(tag == 'delete' and a <= endpoint - 1 < b
                                     for tag, a, b, *_ in rows))

    def test_replaced_function_and_struct_endpoints_earn_no_subtraction_credit(self):
        old = b'fn obsolete() {\n    old();\n}\nfn retained() {\n    same();\n}\n'
        new = b'struct Manifest {\n    generation: String,\n}\nfn retained() {\n    same();\n}\n'
        def owners(base, head):
            for document, source, spans in ((base, old, [('obsolete', 1, 3), ('retained', 4, 6)]),
                                            (head, new, [('retained', 4, 6)])):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(name=name, filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                             for line in range(first, last + 1)]) for name, first, last in spans]
        receipt = self.compare(before=[(line, 1) for line in range(1, 7)],
            after=[(line, 1) for line in range(4, 7)], mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))
        self.assertEqual([receipt[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertEqual(receipt['source_replacements'][0]['base_line'], 3)

    def test_replaced_await_owner_without_an_execution_seed_is_refused(self):
        old = b'async fn obsolete() {\n    match spawn_blocking({\n        move || old()\n    })\n    .await\n    {\n        Ok(value) => value,\n    }\n}\n'
        new = b'async fn replacement() {\n    finish(spawn_blocking(move || {\n        new()\n    }))\n    .await\n}\n'
        def owners(base, head):
            for document, source, name in ((base, old, 'obsolete'), (head, new, 'replacement')):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(name=name, filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(text) + 1, 1, 0, 0, 0]
                             for line, text in enumerate(lines, 1)])]
        with self.assertRaisesRegex(ValueError, r'Unproved retained execution.*example\.rs:\d+ -> \d+; base_count=1 head_count=1'):
            self.compare(before=[(line, 1) for line in range(1, 10)],
                after=[(line, 1) for line in range(1, 7)], mutate=owners,
                sources=({'example.rs': old}, {'example.rs': new}))

    def test_function_completion_keeps_its_compiler_partition_with_multiple_copies(self):
        old = b'fn checked() {\n    old();\n}\nfn retained() {\n    same();\n}\n'
        new = b'fn checked() {\n    new();\n    more();\n}\nfn inserted() {\n    other();\n}\nfn retained() {\n    same();\n}\n'
        lose_copy = [False]
        def owners(base, head):
            for document, source, spans in ((base, old, [('checked', 1, 3), ('retained', 4, 6)]),
                                            (head, new, [('checked', 1, 4), ('retained', 8, 10)])):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(name=f'{name}_{instance}',
                    filenames=['/src/example.rs'], regions=[[
                        first, lines[first - 1].index('{') + 1, last, 2,
                        int(lose_copy[0] or instance) if document is base else instance, 0, 0, 0]])
                    for name, first, last in spans for instance in range(2)]
        receipt = self.compare(before=[(3, 1), (5, 1), (6, 1)],
            after=[(4, 1), (9, 1), (10, 1)], mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))
        self.assertIn([3, 4], [pair for witness in receipt['retained_function_completions']
                              for pair in witness['pairs']])
        lose_copy[0] = True
        with self.assertRaisesRegex(ValueError, r'Function completion lost compiled-copy coverage.*example\.rs:3 -> 4; base_states=\[\[1\], \[1\]\] head_states=\[\[0\], \[1\]\]'):
            self.compare(before=[(3, 2), (5, 2), (6, 2)],
                after=[(4, 1), (9, 1), (10, 1)], mutate=owners,
                sources=({'example.rs': old}, {'example.rs': new}))

    def test_replacement_cannot_hide_an_unchanged_body_in_another_source_file(self):
        old = b'fn obsolete() {\n    old();\n}\nfn retained() {\n    same();\n}\n'
        new = b'struct Manifest {\n    generation: String,\n}\nfn retained() {\n    same();\n}\n'
        def owners(base, head):
            for document, source, spans in ((base, old, [('obsolete', 1, 3), ('retained', 4, 6)]),
                                            (head, new, [('retained', 4, 6)])):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(name=name, filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                             for line in range(first, last + 1)]) for name, first, last in spans]
        for body in (b'fn renamed() {\n    old();\n}\n',
                     b'fn renamed() {\n    if gate() {\n        old();\n    }\n}\n'):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.compare(before=[(line, 1) for line in range(1, 7)],
                    after=[(line, 1) for line in range(4, 7)], mutate=owners,
                    sources=({'example.rs': old}, {'example.rs': new, 'elsewhere.rs': body}))

    def test_repeated_signature_verification_keeps_every_hot_compiled_copy(self):
        old = b'fn obsolete(archive: &Archive, keys: &Keys) -> Result<()> {\n    let verified = verify_archive_signature(archive, keys)?;\n    old(verified);\n    Ok(())\n}\nfn retained(archive: &Archive, keys: &Keys) -> Result<()> {\n    let verified = verify_archive_signature(archive, keys)?;\n    same(verified);\n    Ok(())\n}\n'
        new = old.replace(b'fn obsolete(', b'fn replacement(').replace(b'old(verified)', b'new(verified)')
        def owners(base, head):
            for document, source, first in ((base, old, 'obsolete'), (head, new, 'replacement')):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(
                    name=f'{name}_{instance}', filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(lines[line - 1]) + 1,
                              int(not (document is head and name == first and instance == 0)), 0, 0, 0]
                             for line in range(start, end + 1)])
                    for name, start, end in ((first, 1, 5), ('retained', 6, 10))
                    for instance in range(2)]
        with self.assertRaises(ValueError):
            self.compare(before=[(line, 2) for line in range(1, 11)],
                after=[(line, 1 if line < 6 else 2) for line in range(1, 11)],
                mutate=owners, sources=({'example.rs': old}, {'example.rs': new}))

    def test_changed_sibling_does_not_erase_verification_copy_obligation(self):
        bodies = (
            '    let payload = Payload {\n        verified: gate()\n            && verify_archive_signature(archive, keys),\n        other: old(),\n    };\n',
            '    let payload = dispatch(\n        gate()\n            && verify_archive_signature(archive, keys),\n        old(),\n    );\n',
        )
        for body in bodies:
            with self.subTest(body=body.splitlines()[0]):
                old = ('fn obsolete(archive: &Archive, keys: &Keys) -> Payload {\n' + body + '    old_finish(payload)\n}\n').encode()
                new = old.replace(b'fn obsolete(', b'fn replacement(').replace(b'old()', b'new()').replace(b'old_finish(', b'new_finish(')
                def owners(base, head):
                    for document, source in ((base, old), (head, new)):
                        lines = source.decode().splitlines()
                        document['data'][0]['functions'] = [dict(
                            name=f'{"obsolete" if document is base else "replacement"}_{copy}', filenames=['/src/example.rs'],
                            regions=[[line, 1, line, len(lines[line - 1]) + 1,
                                      int(not(document is head and copy == 0 and line == 4)), 0, 0, 0]
                                     for line in range(1, 9)]) for copy in range(2)]
                with self.assertRaises(ValueError):
                    self.compare(
                        before=[(line, 2) for line in range(1, 9)],
                        after=[(line, 1 if line == 4 else 2) for line in range(1, 9)],
                        mutate=owners, sources=({'example.rs': old}, {'example.rs': new}))

    def test_construct_ancestry_is_depth_bounded_and_charged_before_traversal(self):
        source = coverage._boolean_source(['[' * 32 + 'value' + ']' * 32])
        self.assertIsNotNone(source)
        self.assertEqual(len(coverage._construct_ancestors(source, source.words.index('value'), [32])), 32)
        self.assertIsNone(coverage._boolean_source(['[' * 33 + 'value' + ']' * 33]))
        class Unreadable:
            def __getitem__(self, index):
                raise AssertionError('ancestry read before budget admission')
        malformed = coverage._BooleanSource('', ['value'], [0], [5], Unreadable(), {}, [0])
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage._construct_ancestors(malformed, 0, [0])
        cyclic = coverage._BooleanSource('', ['value'], [0], [5], [0], {}, [0])
        with self.assertRaisesRegex(ValueError, 'ancestr'):
            coverage._construct_ancestors(cyclic, 0, [32])

    def test_binding_contexts_share_one_ordered_lexical_index(self):
        old = ['use std::fmt::Debug;']
        for ordinal in range(20):
            old.extend([f'mod scope{ordinal} {{', '    use std::cmp::Ord;',
                f'    fn retained{ordinal}() {{', '        old();', '        verified();', '    }', '}'])
        new = [line.replace('old();', 'new();') for line in old]
        work = [75_000]
        inventories = [coverage._construct_inventory(source, work) for source in (old, new)]
        owners = []
        for source in (old, new):
            members = []
            for ordinal in range(20):
                start = 4 + 7 * ordinal
                members.append(dict(name=f'retained{ordinal}', filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(source[line - 1]) + 1, 1, 0, 0, 0]
                             for line in range(start, start + 4)]))
            owners.append(members)
        groups = [coverage._compiled_function_groups('example.rs', members,
            {'/src/example.rs': 'example.rs'}, source, work) for members, source in zip(owners, (old, new))]
        proposals = coverage._construct_replacements(old, new, work, compatible=lambda *args: True,
            inventories=inventories, deferred=True)[0]
        result = coverage.retained_replacement_obligations('example.rs', old, new,
            {line: 1 for line in range(1, len(old) + 1)}, {line: 1 for line in range(1, len(new) + 1)},
            inventories, groups, proposals, work)
        self.assertEqual(len(result[1]), 20)
        self.assertGreater(work[0], 0)

    def test_supplied_construct_groups_do_not_charge_unread_global_owner_arrays(self):
        class UnreadOwners:
            def __len__(self):
                raise AssertionError('precomputed groups must bypass global owner arrays')
        old = ['fn retained() {', '    old();', '}']
        new = ['fn retained() {', '    new();', '}']
        work = [1000]
        inventories = [coverage._construct_inventory(source, work) for source in (old, new)]
        grouped = [((), {}, {}), ((), {}, {})]
        pairs, receipts = coverage.retained_construct_anchors('example.rs', old, new,
            {2: 1}, {2: 1}, UnreadOwners(), UnreadOwners(), {}, {}, work, inventories, grouped)
        self.assertEqual((pairs, receipts), ({}, []))

    def single_bound_phase_fixture(self, *, repeated=False, mutate=None, compare=None):
        sources = [
            ['fn retained() {', '    dispatch(|handle| {', '        verify(handle);',
             *(['        verify(handle);'] if repeated else []), '        old_step();', '    });', '}'],
            ['fn retained() {', '    dispatch(|handle| {', '        verify(handle);',
             '        new_step();', '    });', '}']]
        documents = []; inventories = []; grouped = []; descriptors = []
        work = [2_000_000]
        for source in sources:
            opening = source[1].index('{') + 1; closing = len(source) - 1
            members = []
            for index, state in enumerate((1, 0)):
                parent = f'_RNvCs{index + 1}_7example8retained'
                members.extend([
                    dict(name=parent, count=state, filenames=['/src/example.rs'], regions=[
                        [1, 1, 1, source[0].index('{') + 1, state, 0, 0, 0],
                        [2, 5, 2, 13, state, 0, 0, 0],
                        [len(source), 1, len(source), 2, state, 0, 0, 0]]),
                    dict(name='_RNC' + parent[2:] + '0B3_', count=state,
                         filenames=['/src/example.rs'], regions=[
                             [2, opening, 2, opening + 1, state, 0, 0, 0],
                             *[[line, 9, line, len(source[line - 1]) + 1, state, 0, 0, 0]
                               for line in range(3, closing)],
                             [closing, 5, closing, 6, state, 0, 0, 0]])])
            documents.append(members)
            inventory = coverage._construct_inventory(source, work); inventories.append(inventory)
            compiled = coverage._compiled_function_groups('example.rs', members,
                {'/src/example.rs': 'example.rs'}, source, work); grouped.append(compiled)
            code = inventory[0]; function = next(row for row in inventory[1] if row['kind'] == 'fn')
            statements = {}
            for row in inventory[1]:
                if row['kind'] == 'statement' and function['opening'] < row['first'] <= row['end'] < function['end']:
                    statements.setdefault(row['digest'], []).append(row)
            descriptors.append({'fn retained()': dict(group=compiled[1]['fn retained()'],
                row=function, declaration='retained', signature=function['header'],
                attributes=(), context=((), ()), statements=statements)})
        code = inventories[0][0]
        retained = next(row['digest'] for row in inventories[0][1]
            if row['kind'] == 'statement' and code.position(code.starts[row['first']])[0] == 3)
        replacements = {0: dict(base_line=len(sources[0])-1, head_line=len(sources[1])-1,
            base_range=[2, len(sources[0])-1], head_range=[2, len(sources[1])-1],
            retained_statements={retained})}
        counts = [{line: 1 for line in range(1, len(source)+1)} for source in sources]
        if mutate:
            mutate(replacements, counts)
        compare = compare or coverage.one_bound_phase_obligations
        return compare('example.rs', sources, counts, descriptors,
            inventories, grouped, replacements, work)

    def test_single_bound_phase_retains_complete_hot_and_cold_copies(self):
        pairs, receipts, proved = self.single_bound_phase_fixture()
        self.assertEqual(pairs, {2: 2, 3: 3})
        self.assertEqual(proved, {(1, 6)})
        self.assertEqual(len(receipts), 1)
        self.assertTrue(any(not any(row) for row in receipts[0]['base_instance_states']))
        self.assertTrue(any(any(row) for row in receipts[0]['base_instance_states']))

    def test_single_bound_phase_refuses_cross_scope_and_overlapping_obligations(self):
        def outside_head(replacements, counts):
            record = copy.deepcopy(replacements[0]); record['head_line'] += 10
            record['head_range'] = [line + 10 for line in record['head_range']]
            replacements[1] = record
        def overlapping_old(replacements, counts):
            record = copy.deepcopy(replacements[0]); record['base_line'] = 8
            record['base_range'] = [5, 8]; replacements[1] = record
        for mutate in (outside_head, overlapping_old):
            with self.subTest(mutate=mutate.__name__):
                self.assertEqual(self.single_bound_phase_fixture(mutate=mutate), ({}, [], set()))

    def test_single_bound_phase_refuses_missing_statement_or_construction_da(self):
        for line in (2, 3):
            with self.subTest(line=line):
                def missing(replacements, counts):
                    counts[1].pop(line)
                self.assertEqual(self.single_bound_phase_fixture(mutate=missing), ({}, [], set()))

    def test_single_bound_phase_cannot_credit_repeated_old_calls_to_one_head_call(self):
        self.assertEqual(self.single_bound_phase_fixture(repeated=True), ({}, [], set()))

    def test_callback_entry_reuses_immutable_source_and_owner_indexes(self):
        class CountedRows(list):
            document_scans = 0

            def __iter__(self):
                self.document_scans += 1
                return super().__iter__()

        def compare(name, sources, counts, descriptors, inventories, grouped, replacements, work):
            code, rows, *rest = inventories[0]
            counted = CountedRows(rows)
            inventory = (code, counted, *rest)
            owners, _, names = grouped[0]
            args = (sources[0], descriptors[0]['fn retained()']['group'], owners, names, 2, 2, inventory, work)
            cache = {}
            first = coverage.zero_arg_callback_fragment(*args, single_binding=True, phase_cache=cache)
            self.assertIsNotNone(first)
            source_scans = counted.document_scans
            charged_before = work[0]
            second = coverage.zero_arg_callback_fragment(*args, single_binding=True, phase_cache=cache)
            self.assertEqual(first, second)
            self.assertEqual(counted.document_scans, source_scans)
            self.assertLess(work[0], charged_before)

        self.single_bound_phase_fixture(compare=compare)

    def closed_retained_callback_island_fixture(self, record=False, fault=None):
        if record:
            old=['fn inventory(input: &[Row]) -> Vec<Row> {','    input.iter()',
                 '        .map(|row| Row {','            name: row.name.clone(),',
                 '        })','        .collect()','}']
        else:
            old=['fn inventory(input: &[Row]) -> Result<Vec<Row>> {','    input.iter()',
                 '        .map(|row| {','            let note = fetch(row).with_context(|| format!("missing"))?;',
                 '            let values = row.values.iter().map(|value| clone_value(value)).collect();',
                 '            Ok((row.name.clone(), note, values))','        })','        .collect()','}']
        added=['        .filter(|row| {','            visible(row)','        })']
        new=old[:2]+added+old[2:];sources=[old,new];documents=[]
        for side,source in enumerate(sources):
            mapper=3+3*side;ending=(5 if record else 7)+3*side;members=[]
            for copy_number,state in enumerate((1,0),1):
                root=f'_RNvCs{copy_number}_7example9inventory'
                selected=('_RNC'+root[2:]+('s_' if side else '')+'0B3_')
                def row(line,start,end,count=state):return [line,start,line,end,count,0,0,0]
                def owner(name,count,regions):return dict(name=name,count=count,filenames=['/src/example.rs'],regions=regions,branches=[],mcdc_records=[])
                members.append(owner(root,state,[row(1,1,source[0].index('{')+1),row(len(source),1,2)]))
                if side:
                    opening=source[2].index('{')+1
                    members.append(owner('_RNC'+root[2:]+'0B3_',4*state,[row(3,opening,opening+1,4*state),
                        row(4,13,20,4*state),row(5,9,10,4*state)]))
                hits=3*state;raw=[]
                if record:
                    line=mapper+1;start=source[line-1].index('row.name')+1
                    raw.append(row(line,start,len(source[line-1]),hits))
                else:
                    opening=source[mapper-1].index('{')+1
                    raw.append(row(mapper,opening,opening+1,hits))
                    line=mapper+1;text=source[line-1]
                    raw.extend([row(line,13,16,hits),row(line,text.index('fetch')+1,text.index('fetch')+6,hits),
                        row(line,text.index('?')+1,text.index('?')+2,0),row(mapper+2,13,16,hits),row(mapper+3,13,15,hits)])
                    start=text.index('format!')+1
                    members.append(owner('_RNCNC'+root[2:]+('s_' if side else '')+'00B5_',0,[row(line,start,start+7,0)]))
                    line=mapper+2;start=source[line-1].index('clone_value')+1
                    members.append(owner('_RNCNC'+root[2:]+('s_' if side else '')+'0s_0B5_',2*state,[row(line,start,start+11,2*state)]))
                raw.append(row(ending,9,10,hits));members.append(owner(selected,hits,raw))
            documents.append(members)
        if fault=='missing-cold-descendant':
            documents[1]=[o for o in documents[1] if not (o['count']==0 and o['name'].startswith('_RNCNC'))]
        elif fault=='foreign-descendant':
            documents[1][2]['name']=documents[1][2]['name'].replace('9inventory','7another')
        elif fault=='lost-hot-mapper':
            for o in documents[1]:
                if o['name'].startswith('_RNC') and 's_0B3_' in o['name']:
                    o['count']=0
                    for r in o['regions']:r[4]=0
        elif fault=='lost-region':
            next(o for o in documents[1] if o['name'].startswith('_RNCNv') and 's_0B3_' in o['name'])['regions'][1][4]=0
        elif fault=='extra-touching-owner':
            extra=copy.deepcopy(documents[1][2]);extra['name']='foreign';documents[1].append(extra)
        elif fault=='changed-body':
            sources[1][6]=sources[1][6].replace('missing','changed')
        elif fault=='changed-receiver':sources[1][1]='    other.iter()'
        elif fault=='changed-signature':sources[1][0]=sources[1][0].replace('&[Row]','&[Other]')
        elif fault=='changed-lexical-role':sources[1][5]=sources[1][5].replace('.map(','.filter(')
        elif fault=='wrong-nested-ordinal':
            documents[1][2]['name']=documents[1][2]['name'].replace('s_00B5_','s_0s_0B5_')
        elif fault=='missing-filter':documents[1].pop(1)
        elif fault=='cold-filter':
            documents[1][1]['count']=0
            for r in documents[1][1]['regions']:r[4]=0
        counts=[]
        for members in documents:
            work=coverage._ObserverWork();counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [r for owner in members for r in owner['regions']],work),work)))
        if fault=='missing-da':counts[1]=[(n,c) for n,c in counts[1] if n!=7]
        def owners(base,head):
            for document,members in zip((base,head),documents):
                document['data'][0]['functions']=members
                document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
        return self.compare(before=counts[0],after=counts[1],mutate=owners,sources=(
            {'example.rs':('\n'.join(sources[0])+'\n').encode()},
            {'example.rs':('\n'.join(sources[1])+'\n').encode()}))

    def test_block_mapper_preserves_complete_cold_descendant_and_context(self):
        receipt=self.closed_retained_callback_island_fixture()
        proof,=[r for r in receipt['retained_replacement_obligations'] if r['kind']=='closed-retained-callback-island']
        self.assertEqual(proof['pairs'],[[3,6],[4,7],[5,8],[6,9],[7,10]])
        self.assertEqual(receipt['deleted_mapped'],0)
        self.assertEqual(len(proof['forest_names'][0]),2)
        self.assertEqual([len(names) for names in proof['forest_names'][0]],[3,3])

    def test_record_expression_mapper_preserves_complete_cold_context(self):
        receipt=self.closed_retained_callback_island_fixture(record=True)
        proof,=[r for r in receipt['retained_replacement_obligations'] if r['kind']=='closed-retained-callback-island']
        self.assertEqual(proof['pairs'],[[4,7],[5,8]])
        self.assertEqual(receipt['deleted_mapped'],0)

    def test_callback_island_refuses_missing_foreign_and_changed_authority(self):
        for fault in ('missing-cold-descendant','foreign-descendant','lost-hot-mapper','lost-region','extra-touching-owner',
                      'changed-body','changed-receiver','changed-signature','changed-lexical-role','wrong-nested-ordinal','missing-da'):
            with self.subTest(fault=fault):
                try:receipt=self.closed_retained_callback_island_fixture(fault=fault)
                except ValueError:continue
                self.assertFalse(any(r['kind']=='closed-retained-callback-island' for r in receipt.get('retained_replacement_obligations',[])))

    def test_callback_island_requires_real_added_filter_owner(self):
        for fault in ('missing-filter','cold-filter'):
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):self.closed_retained_callback_island_fixture(fault=fault)

    def test_callback_import_change_requires_an_unused_exact_non_trait_enum(self):
        old=((),(('use','super','::','scan','::','{','Severity',',','Result','}',';'),))
        new=((),(('use','super','::','scan','::','{','Severity',',','Coverage',',','Result','}',';'),))
        blobs=({}, {'src/core/security/scan.rs':b'pub enum Coverage { Assessed, Unknown }'})
        check=coverage.callback_island_import_context
        self.assertTrue(check('src/core/security/sbom_shared.rs',(old,new),('license','clone'),blobs,[100000]))
        for source in (b'pub trait Coverage { fn clone(&self); }',b'pub type Coverage = Other;',
                       b'pub enum Other { Unknown }',b'pub enum Coverage { Unknown } fn Coverage() {}'):
            with self.subTest(source=source):
                self.assertFalse(check('src/core/security/sbom_shared.rs',(old,new),('clone',),
                    ({},{'src/core/security/scan.rs':source}),[100000]))
        self.assertFalse(check('src/core/security/sbom_shared.rs',(old,new),('Coverage',),blobs,[100000]))
        self.assertFalse(check('src/core/security/sbom_shared.rs',(old,new),('clone',),None,[100000]))

    def closed_record_field_forest_compare(self, kind='free', mutation=None):
        if kind == 'free':
            old = ['fn security_inventory() -> Vec<Row> {', '    with_handle(|handle| {',
                   '        handle.map(|package| {', '            let name = package.name;',
                   '            Row {', '                name,',
                   '                version: package.version,', '            }',
                   '        }).collect()', '    })', '}']
        else:
            old = ['pub trait PackageManager {',
                   '    fn security_inventory(&self) -> Pin<Box<dyn Future<Output = Vec<Row>>>> {',
                   '        Box::pin(async move {', '            source().map(|package| Row {',
                   '                name: package.name,', '                version: package.version,',
                   '            }).collect()', '        })', '    }', '}']
        record = next(i for i, text in enumerate(old) if 'Row {' in text)
        new = old[:record+1] + ['                origin: SecurityOrigin::Unknown,'] + old[record+1:]
        sources = [old, new]; documents = []
        for source in sources:
            first = 1 if kind == 'free' else 2; last = len(source) if kind == 'free' else len(source)-1
            outer = first+1; map_line = outer+1
            record_line = next(i for i, text in enumerate(source, 1) if 'Row {' in text)
            record_end = next(i for i in range(record_line+1, len(source)+1) if source[i-1].lstrip().startswith('}'))
            map_end = record_end+1 if kind == 'free' else record_end
            outer_end = last-1
            members = []
            for copy_number, state in enumerate((1, 0), 1):
                if kind == 'free':
                    parent = f'_RNvCs{copy_number}_7example18security_inventory'
                    children = ['_RNC' + parent[2:] + '0B3_', '_RNCNC' + parent[2:] + '00B5_']
                else:
                    suffix = '14PackageManager18security_inventory'
                    parent = f'_RNvYNtCs{copy_number}_7example4MockNtB4_' + suffix + 'B4_'
                    children = [f'_RNCNvYNtCs{copy_number}_7example4MockNtB6_' + suffix + '0B6_',
                                f'_RNCNCNvYNtCs{copy_number}_7example4MockNtB8_' + suffix + '00B8_']
                    self.assertIsNotNone(coverage.nominal_method_path(children[1]))
                def row(line, start, end, count=state):
                    return [line, start, line, end, count, 0, 0, 0]
                def owner(name, count, rows):
                    return dict(name=name, count=count, filenames=['/src/example.rs'],
                                regions=rows, branches=[], mcdc_records=[])
                outer_open = source[outer-1].index('{')+1
                map_open = source[map_line-1].index('{')+1
                members.append(owner(parent, state, [
                    row(first, len(source[first-1])-len(source[first-1].lstrip())+1,
                        source[first-1].index('{')+1),
                    row(outer, len(source[outer-1])-len(source[outer-1].lstrip())+1,
                        source[outer-1].index('(')+1),
                    row(last, source[last-1].index('}')+1, source[last-1].index('}')+2)]))
                members.append(owner(children[0], state, [row(outer, outer_open, outer_open+1),
                    row(map_line, len(source[map_line-1])-len(source[map_line-1].lstrip())+1,
                        source[map_line-1].index('.map')+5),
                    row(outer_end, source[outer_end-1].index('}')+1, source[outer_end-1].index('}')+2)]))
                count = 3*state; mapped = []
                if kind == 'free':
                    mapped.extend([row(map_line, map_open, map_open+1, count),
                        row(map_line+1, 13, len(source[map_line])+1, count),
                        [record_line, 13, record_end, source[record_end-1].index('}')+2, count, 0, 0, 0]])
                for line in range(record_line+1, record_end):
                    text = source[line-1]
                    start = (text.index(':')+2 if ':' in text else len(text)-len(text.lstrip()))+1
                    mapped.append(row(line, start, text.index(',')+1, count))
                mapped.append(row(map_end, source[map_end-1].index('}')+1,
                                  source[map_end-1].index('}')+2, count))
                members.append(owner(children[1], count, mapped))
            documents.append(members)
        counts = []
        for members in documents:
            work = coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [row for owner in members for row in owner['regions']], work), work)))
        if mutation:
            mutation(sources, documents, counts)
        def owners(base, head):
            for document, members in zip((base, head), documents):
                document['data'][0]['functions'] = members
                document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
        return self.compare(before=counts[0], after=counts[1], mutate=owners,
            sources=({'example.rs': ('\n'.join(sources[0])+'\n').encode()},
                     {'example.rs': ('\n'.join(sources[1])+'\n').encode()}))

    def synchronous_tail_record_compare(self, direct_first=False, fault=None, shorthand=False):
        old = ['impl Widget {', '    pub fn create() -> Self {', '        Self {',
               '            directory: super::DATA_DIR.join("widget"),',
               '            client: download_client(),', '        }', '    }', '}',
               'use support::{Auxiliary};']
        if shorthand:
            old[1:4] = ['    #[cfg(test)]',
                        '    fn create(directory: PathBuf, keyring: PathBuf) -> Self {',
                        '        Self {', '            directory,', '            keyring,']
            if fault == 'wrong-shorthand':
                old[4] = '            elsewhere,'
            elif fault == 'reordered-shorthand':
                old[4:6] = list(reversed(old[4:6]))
            elif fault == 'wrong-guard':
                old[1] = '    #[cfg(unix)]'
            elif fault == 'pattern-parameter':
                old[2] = old[2].replace('directory:', 'mut directory:')
        entry = 3 if shorthand else 2
        first = entry+2
        close = len(old)-2
        new = old[:first-1] + ['            security: super::audit::Witness::default(),'] + old[first-1:]
        new[-1] = 'use support::{Auxiliary, Monument};'
        if fault == 'changed-parameter':
            new[entry-1] = new[entry-1].replace('directory: PathBuf', 'directory: PathBox')
        documents = []
        for side, source in enumerate((old, new)):
            members = []
            for copy_number, hits in enumerate((3+side, int(not direct_first)), 1):
                rows = []
                def raw(first, column, last, endpoint):
                    return [first, column, last, endpoint, hits, 0, 0, 0]
                def value(line):
                    text = source[line-1]
                    start = text.index(': ')+3 if ': ' in text else len(text)-len(text.lstrip())+1
                    return raw(line, start, line, text.rfind(',')+1-2*text.endswith('(),'))
                rows.extend([raw(entry, 5, entry, source[entry-1].index('{')+1),
                             raw(entry+1, 9, close-1+side, 10),
                             raw(close+side, 5, close+side, 6)])
                if direct_first:
                    rows.append(value(first+side))
                if side:
                    rows.append(value(first))
                owner = f'_RNvMNtCs{copy_number}_7example7exampleNtB2_6Widget6create'
                self.assertIsNotNone(coverage.nominal_method_path(owner))
                members.append(dict(name=owner, count=hits, filenames=['/src/example.rs'],
                                    regions=rows, branches=[], mcdc_records=[]))
            documents.append(members)

        head = documents[1]
        addition = head[0]['regions'][-1]
        if fault == 'missing-added':
            head[0]['regions'].pop()
        elif fault == 'zero-added':
            addition[4] = 0
        elif fault == 'misplaced-added':
            addition[1] += 1
        elif fault == 'mismapped-retained':
            head[0]['regions'][-2][1] += 1
        elif fault == 'changed-retained':
            new[4] = new[4].replace('"widget"', '"gadget"')
        elif fault == 'changed-tail':
            new[7] = '    };'
        elif fault == 'new-argument':
            new[3] = new[3].replace('default()', 'default(1)')
            for owner in head:
                owner['regions'][-1][3] += 1
        elif fault == 'foreign-owner':
            head.append(dict(name='foreign', count=1, filenames=['/src/example.rs'],
                             regions=[copy.deepcopy(addition)]))
        elif fault == 'missing-cold-copy':
            head.pop()
        elif fault == 'lost-copy-hit':
            self.assertFalse(direct_first)
            head[1]['count'] = 0
            for row in head[1]['regions']:
                row[4] = 0
        elif fault == 'lost-retained-hit':
            head[0]['regions'][-2][4] = 0
        elif fault == 'foreign-type':
            head[0]['name'] = head[0]['name'].replace('6Widget', '6Gadget')
        elif fault == 'wrong-new-field-count':
            addition[4] += 1
        elif fault == 'missing-direct-slot':
            for side in documents:
                for owner in side:
                    owner['regions'].pop(3)
        elif fault == 'changed-binding':
            new[-1] = 'use support::{Auxiliary, download_client};'
        elif fault == 'new-glob':
            new[-1] = 'use support::*;'
        elif fault == 'new-alias':
            new[-1] = 'use support::Another as download_client;'
        counts = []
        for members in documents:
            work = coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [row for owner in members for row in owner['regions']], work), work)))

        def owners(base, head):
            for document, members in zip((base, head), documents):
                document['data'][0]['functions'] = members
                document['data'][0]['files'][0].update(expansions=[], branches=[], mcdc_records=[])
        return self.compare(before=counts[0], after=counts[1], mutate=owners,
            sources=({'example.rs': ('\n'.join(old)+'\n').encode()},
                     {'example.rs': ('\n'.join(new)+'\n').encode()}))

    def test_tail_record_insertion_retains_inherited_and_direct_field_regions(self):
        for direct_first in (False, True):
            with self.subTest(direct_first=direct_first):
                report = self.synchronous_tail_record_compare(direct_first)
                proof, = [row for row in report['retained_replacement_obligations']
                          if row.get('kind') == 'retained-record-field-forest']
                self.assertEqual(proof['pairs'], [[2,2], [3,3], [4,5], [5,6], [6,7], [7,8]])
                self.assertEqual(proof['added_line'], 4)
                self.assertEqual(report['deleted_mapped'], 0)
                self.assertEqual([r['extra_field'][4] for r in proof['forests'][1]],
                                 [4, int(not direct_first)])

    def test_cfg_tail_record_insertion_binds_ordered_typed_shorthand_slots(self):
        report = self.synchronous_tail_record_compare(True, shorthand=True)
        proof, = [row for row in report['retained_replacement_obligations']
                  if row.get('kind') == 'retained-record-field-forest']
        self.assertEqual(proof['pairs'], [[3,3], [4,4], [5,6], [6,7], [7,8], [8,9], [9,10]])
        self.assertEqual([copy['extra_field'][4] for copy in proof['forests'][1]], [4, 0])
        self.assertEqual(proof['added_line'], 5)
        self.assertEqual(proof['typed_parameter_slots'],
                         (('directory', 'PathBuf'), ('keyring', 'PathBuf')))
        self.assertEqual(proof['first_shorthand_spans'], [(5,13,5,22), (6,13,6,22)])
        self.assertEqual(report['deleted_mapped'], 0)

    def test_cfg_tail_record_insertion_refuses_unbound_shorthand_and_incomplete_regions(self):
        for fault in ('wrong-shorthand', 'reordered-shorthand', 'wrong-guard',
                      'pattern-parameter', 'changed-parameter', 'missing-added', 'missing-cold-copy',
                      'mismapped-retained', 'lost-retained-hit', 'missing-direct-slot', 'foreign-owner'):
            with self.subTest(fault=fault):
                try:
                    report = self.synchronous_tail_record_compare(True, fault, shorthand=True)
                except ValueError:
                    continue
                self.assertFalse(any(row.get('kind') == 'retained-record-field-forest'
                    for row in report.get('retained_replacement_obligations', [])))

    def test_tail_record_insertion_refuses_unproved_forests(self):
        for fault in ('missing-added', 'zero-added', 'misplaced-added', 'mismapped-retained',
                      'foreign-owner', 'missing-cold-copy', 'lost-copy-hit', 'lost-retained-hit',
                      'foreign-type', 'wrong-new-field-count', 'changed-retained', 'changed-tail',
                      'new-argument', 'changed-binding', 'new-glob', 'new-alias'):
            with self.subTest(fault=fault):
                try:
                    report = self.synchronous_tail_record_compare(fault != 'lost-copy-hit', fault)
                except ValueError:
                    continue
                self.assertFalse(any(row.get('kind') == 'retained-record-field-forest'
                    for row in report.get('retained_replacement_obligations', [])))

    def test_retained_record_field_preserves_nested_block_forest_and_cold_copy(self):
        receipt = self.closed_record_field_forest_compare()
        self.assertTrue(any(row.get('kind') == 'retained-record-field-forest'
            for row in receipt.get('retained_replacement_obligations', [])))
        self.assertEqual(receipt['deleted_mapped'], 0)

    def test_retained_record_field_preserves_default_trait_expression_mapper(self):
        receipt = self.closed_record_field_forest_compare('trait')
        self.assertTrue(any(row.get('kind') == 'retained-record-field-forest'
            for row in receipt.get('retained_replacement_obligations', [])))
        self.assertEqual(receipt['deleted_summary_found'], 0)

    def test_retained_record_field_refuses_changed_nested_callback_ordinal(self):
        def mutate(sources, documents, counts):
            for owner in documents[1][2::3]:
                owner['name'] = owner['name'].replace('00B5_', '0s_0B5_')
        with self.assertRaises(ValueError):
            self.closed_record_field_forest_compare(mutation=mutate)

    def test_retained_record_field_refuses_incomplete_forests_and_foreign_roles(self):
        def mutate(sources, documents, counts, mode):
            head = documents[1]
            if mode == 'missing-mapper':
                head.pop(2)
            elif mode == 'duplicate-mapper':
                head.append(copy.deepcopy(head[2]))
            elif mode == 'foreign-owner':
                foreign = copy.deepcopy(head[2]); foreign['name'] = 'foreign-owner'; head.append(foreign)
            elif mode == 'wrong-file':
                head[2]['filenames'] = ['/other/example.rs']
            elif mode == 'different-receiver':
                for owner in head:
                    owner['name'] = owner['name'].replace('4Mock', '5Other')
            elif mode == 'unbound-mapper-receiver':
                head[2]['name'] = head[2]['name'].replace('4Mock', '5Other')
            elif mode == 'reassigned-cold-copy':
                for owner in head:
                    owner['count'] = 0 if owner['count'] else 3 if owner is head[5] else 1
                    for row in owner['regions']:
                        row[4] = 0 if row[4] else owner['count']
            else:
                head[2]['regions'][0][5] = 1
        for kind, mode in [('free','missing-mapper'),('free','duplicate-mapper'),('free','foreign-owner'),
                           ('free','wrong-file'),('trait','different-receiver'),('trait','unbound-mapper-receiver'),
                           ('free','reassigned-cold-copy'),('free','region-kind')]:
            with self.subTest(kind=kind, mode=mode), self.assertRaises(ValueError):
                self.closed_record_field_forest_compare(kind, lambda s,d,c: mutate(s,d,c,mode))

    def test_retained_record_field_keeps_each_counter_channel_and_hidden_cold_region(self):
        def mutate(sources, documents, counts, mode):
            head = documents[1]; text = sources[1]
            added = next(i for i,line in enumerate(text,1) if 'origin:' in line)
            for owner in head[2::3]:
                scalar = next(row for row in owner['regions'] if row[0]==row[2]==added)
                if mode == 'wrong-positive-scalar-count':
                    if scalar[4]: scalar[4] = 1
                elif mode == 'borrowed-mapper-count':
                    for row in owner['regions']:
                        if (row[0] == added-1 and row[2] > added or row[0] in (added+1,added+2)) and row[4]:
                            row[4] = 1
                elif mode == 'cold-version-hidden-by-record':
                    for row in owner['regions']:
                        if row[0] == row[2] == added+2:
                            row[4] = 0
                else:
                    owner['count'] += 1
            if mode == 'borrowed-mapper-count':
                work = coverage._ObserverWork()
                counts[1][:] = coverage._llvm22_rows(coverage._llvm22_segments(
                    [row for owner in head for row in owner['regions']], work), work)
        for mode in ('wrong-positive-scalar-count','borrowed-mapper-count',
                     'cold-version-hidden-by-record','entry-counter'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.closed_record_field_forest_compare(mutation=lambda s,d,c: mutate(s,d,c,mode))

    def test_retained_record_field_requires_exact_source_and_da_reconstruction(self):
        def mutate(sources, documents, counts, mode):
            text = sources[1]; added = next(i for i,line in enumerate(text,1) if 'origin:' in line)
            if mode == 'call-initializer':
                text[added-1] = text[added-1].replace('SecurityOrigin::Unknown','make_origin()')
            elif mode == 'changed-old-field':
                text[added+1] = text[added+1].replace('package.version','package.changed')
            elif mode == 'not-first-field':
                text[added-1],text[added] = text[added],text[added-1]
            elif mode == 'missing-old-da':
                counts[1][:] = [(line,count) for line,count in counts[1] if line != added+1]
            else:
                counts[1][:] = [(line,count+1 if line == added+1 else count) for line,count in counts[1]]
        for mode in ('call-initializer','changed-old-field','not-first-field','missing-old-da','wrong-da-count'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.closed_record_field_forest_compare(mutation=lambda s,d,c: mutate(s,d,c,mode))

    def attribution_obligations(self, old, new, *, excluded=(), painted=(), callbacks=False,
                                parent_states=((1, 1), (1, 1)), child_states=None, mutation=None):
        sources = [source.splitlines() for source in (old, new)]
        counts = [{line: 1 for line in range(1, len(source) + 1) if line not in excluded}
                  for source in sources]
        for values in counts:
            values.update((line, 1) for line in painted)
        owners = []
        for side, source in enumerate(sources):
            members = []
            for copy, state in enumerate(parent_states[side]):
                parent = f'_RNvCs{copy + 1}_7example8retained'
                regions = [[line, 1, line, len(text) + 1, state, 0, 0, 0]
                           for line, text in enumerate(source, 1) if line not in excluded]
                members.append(dict(name=parent, filenames=['/src/example.rs'], regions=regions))
                if callbacks:
                    line = next(index for index, text in enumerate(source, 1) if 'verify_archive_signature' in text)
                    text = source[line - 1]; start = text.index('verify') + 1
                    child = (child_states or parent_states)[side][copy]
                    members.append(dict(name='_RNC' + parent[2:] + '0B3_', filenames=['/src/example.rs'],
                        regions=[[line, start, line, text.rindex(');') + 1, child, 0, 0, 0]]))
            owners.append(members)
        if mutation:
            mutation(owners, sources)
        work = [20_000_000]
        inventories = [coverage._construct_inventory(source, work) for source in sources]
        groups = [coverage._compiled_function_groups('example.rs', members,
            {'/src/example.rs': 'example.rs'}, source, work) for members, source in zip(owners, sources)]
        proposals = coverage._construct_replacements(*sources, work, compatible=lambda *args: True,
            inventories=inventories, deferred=True)[0]
        result = coverage.retained_replacement_obligations('example.rs', *sources, *counts,
            inventories, groups, proposals, work)
        return result

    def macro_literal_obligations(self, *, capture=False, mutate=None, rewrite=None):
        old = ('fn retained(key: &str) {\n'
               '    anyhow::bail!(\n'
               '        "Unknown key. \\\n'
               '         old explanation"\n'
               '    );\n'
               '}\n')
        if capture:
            old = old.replace('Unknown key.', "Unknown '{key}'.")
        new = old.replace('old explanation', 'new explanation')
        if rewrite:
            old, new = rewrite(old, new)
        return self.attribution_obligations(old, new, excluded=(3, 4, 5), painted=(3, 4, 5),
            parent_states=((1, 0), (1, 0)), mutation=mutate)

    def unmapped_record_field_obligations(self, field='enabled: false,', **kwargs):
        old = ('impl Model {\n    fn retained() -> Self {\n        old();\n        Self {\n'
               '            enabled: false,\n            value: checked(),\n        }\n    }\n}\n')
        old = old.replace('enabled: false,', field)
        new = old.replace('old();', 'replacement();')
        return self.attribution_obligations(old, new, excluded=(1, 5, 9), **kwargs)

    def test_unmapped_literal_record_field_preserves_covered_neighbors(self):
        for literal in ('false', 'true', '0', '91'):
            with self.subTest(literal=literal):
                pairs, receipts, _ = self.unmapped_record_field_obligations(f'enabled: {literal},')
                self.assertIn((6, 6), pairs.items())
                self.assertTrue(receipts)
                self.assertNotIn(5, pairs, 'an unmapped literal cannot earn mapped coverage credit')
                self.assertIn([5, 5], receipts[0]['non_executable_rows'])

    def test_unmapped_record_field_requires_a_bare_literal_and_no_mapping(self):
        for field in ('enabled: checked(),', 'enabled: enabled,', 'enabled: None,',
                      'enabled: { false },', 'enabled: false || true,'):
            with self.subTest(field=field):
                self.assertFalse(self.unmapped_record_field_obligations(field)[0])
        self.assertFalse(self.unmapped_record_field_obligations(painted=(5,))[0])

    def test_unmapped_record_field_refuses_foreign_ir_and_lost_neighbor_regions(self):
        def foreign(owners, sources):
            owners[1].append(dict(name='foreign', filenames=['/src/example.rs'],
                regions=[[5, 13, 5, 27, 0, 0, 0, 0]]))
        def missing(owners, sources):
            owners[1][0]['regions'] = [row for row in owners[1][0]['regions'] if row[0] != 6]
        def added(owners, sources):
            owners[1][0]['regions'].append([5, 13, 5, 27, 0, 0, 0, 0])
        for mutation in (foreign, missing, added):
            with self.subTest(mutation=mutation.__name__):
                self.assertFalse(self.unmapped_record_field_obligations(mutation=mutation)[0])
        def cold(owners, sources):
            for row in owners[1][0]['regions']:
                if row[0] == 6:
                    row[4] = 0
        with self.assertRaisesRegex(ValueError, 'lost compiled-copy coverage'):
            self.unmapped_record_field_obligations(mutation=cold)


    def test_qualified_macro_retains_head_and_associated_literal_paint(self):
        for capture in (False, True):
            with self.subTest(capture=capture):
                pairs, receipts, _ = self.macro_literal_obligations(capture=capture)
                self.assertIn((2, 2), pairs.items())
                self.assertIn([3, 3], receipts[0]['non_executable_rows'])

    def test_macro_literal_refuses_binding_fine_geometry_and_copy_changes(self):
        rewrites = (
            lambda old, new: (old, new.replace('key: &str', 'other: &str')),
            lambda old, new: (old, new.replace('key: &str', '(key, other): (&str, &str)')),
            lambda old, new: (old.replace('{\n', '{ let key = original();\n', 1),
                              new.replace('{\n', '{ let key = replacement();\n', 1)),
            lambda old, new: (old.replace('{\n', '{ let (key, _) = original();\n', 1),
                              new.replace('{\n', '{ let (key, _) = replacement();\n', 1)),
            lambda old, new: (old, new.replace('{\n', '{ use replacement as anyhow;\n', 1)),
            lambda old, new: (old, new.replace('{\n', '{ macro_rules! shadow { () => {} }\n', 1)),
            lambda old, new: (old, new.replace("'{key}'", "'{key:?}'")),
        )
        for rewrite in rewrites:
            with self.subTest(rewrite=rewrites.index(rewrite)):
                self.assertEqual(self.macro_literal_obligations(capture=True, rewrite=rewrite)[0], {})
        def foreign(owners, sources):
            owners[1].append(dict(name='foreign', filenames=['/src/example.rs'],
                regions=[[3, 9, 3, 18, 0, 0, 0, 0]]))
        def child(owners, sources):
            owners[1].append(dict(name='_RNCNvCs1_7example8retained0B3_', filenames=['/src/example.rs'],
                regions=[[3, 9, 3, 18, 0, 0, 0, 0]]))
        def added_fine(owners, sources):
            owners[1][0]['regions'].append([3, 9, 3, 18, 0, 0, 0, 0])
        for mutation in (foreign, child, added_fine):
            with self.subTest(mutation=mutation.__name__):
                self.assertEqual(self.macro_literal_obligations(mutate=mutation)[0], {})
        def swap(owners, sources):
            for copy, owner in enumerate(owners[1]):
                for region in owner['regions']:
                    if region[0] == 2:
                        region[4] = copy
        try:
            result = self.macro_literal_obligations(mutate=swap)
        except ValueError:
            pass
        else:
            self.assertEqual(result[0], {})

    def test_macro_literal_preserves_visible_extern_crate_bindings(self):
        body = ('fn retained(key: &str) {\n    anyhow::bail!(\n'
                '        "Unknown key. \\\n         old explanation"\n    );\n}\n')
        def proof(prefix, replacement, suffix=''):
            old = prefix + body + suffix
            new = replacement + body.replace('old explanation', 'new explanation') + suffix
            start = prefix.count('\n') + 1
            paint = tuple(start + offset for offset in (2, 3, 4))
            excluded = tuple(range(1, start)) + paint + tuple(range(start + 6, len(old.splitlines()) + 1))
            return self.attribution_obligations(old, new, excluded=excluded, painted=paint,
                parent_states=((1, 0), (1, 0)))
        declaration = 'extern crate original as anyhow;\n'
        changed = declaration.replace('original', 'replacement')
        with self.subTest(context='visible module binding changed'):
            self.assertEqual(proof(declaration, changed)[0], {})
        with self.subTest(context='visible module binding unchanged'):
            self.assertTrue(proof(declaration, declaration)[1])
        with self.subTest(context='ancestor module binding changed'):
            self.assertEqual(proof('mod scope {\n' + declaration,
                'mod scope {\n' + changed, '}\n')[0], {})
        with self.subTest(context='foreign module binding changed'):
            self.assertTrue(proof('mod foreign { ' + declaration.strip() + ' }\n',
                'mod foreign { ' + changed.strip() + ' }\n')[1])

    def test_macro_literal_cannot_hide_a_cold_runtime_argument(self):
        old = ('fn retained() {\n    anyhow::bail!(\n'
               '        "old message",\n        gate() && verify()\n    );\n}\n')
        new = old.replace('old message', 'new message')
        def cold(owners, sources):
            for side, members in enumerate(owners):
                for copy, owner in enumerate(members):
                    owner['regions'].append([4, 19, 4, 27, int(not(side == 1 and copy == 0)), 0, 0, 0])
        result = self.attribution_obligations(old, new, excluded=(3, 5), painted=(3, 5),
            parent_states=((1, 1), (1, 1)), mutation=cold)
        self.assertEqual(result[0], {})

    def test_replacement_obligations_ignore_only_tokenless_rows_without_any_ir(self):
        old = 'fn retained() {\n    // unchanged security explanation\n    old();\n    verified();\n}\n'
        new = old.replace('old();', 'new();')
        pairs, receipts, _ = self.attribution_obligations(old, new, excluded=(2,))
        self.assertIn((4, 4), pairs.items())
        self.assertTrue(receipts)
        painted = self.attribution_obligations(old, new, excluded=(2,), painted=(2,))
        self.assertIn((2, 2), painted[0].items())
        self.assertIn([2, 2], painted[1][0]['non_executable_rows'])
        def cold_comment_region(owners, sources):
            owners[1][0]['regions'][1][4] = 0
        with self.assertRaises(ValueError):
            self.attribution_obligations(old, new, mutation=cold_comment_region)
        for token in ('let text = r#"// unchanged security explanation"#;', 'real_macro!();'):
            with self.subTest(token=token):
                before = old.replace('// unchanged security explanation', token)
                result = self.attribution_obligations(before, before.replace('old();', 'new();'), excluded=(2,))
                self.assertEqual(result[0], {})

    def test_unmapped_else_separator_preserves_both_branch_obligations(self):
        old = ('fn retained(flag: bool) {\n    old();\n    if flag {\n        first();\n'
               '    } else {\n        second();\n    }\n    finish();\n}\n')
        new = old.replace('old();', 'replacement();')
        pairs, receipts, _ = self.attribution_obligations(old, new, excluded=(5,))
        self.assertIn((4, 4), pairs.items())
        self.assertIn((6, 6), pairs.items())
        self.assertNotIn(5, pairs)
        self.assertIn([5, 5], receipts[0]['non_executable_rows'])
        def cold(owners, sources):
            for row in owners[1][0]['regions']:
                if row[0] == 6:
                    row[4] = 0
        with self.assertRaisesRegex(ValueError, 'lost compiled-copy coverage'):
            self.attribution_obligations(old, new, excluded=(5,), mutation=cold)

    def test_replacement_obligations_attach_unchanged_callbacks_to_each_parent_copy(self):
        old = 'fn retained() {\n    old();\n    consume(|| verify_archive_signature());\n    finish();\n}\n'
        new = old.replace('old();', 'new();')
        pairs, receipts, _ = self.attribution_obligations(old, new, callbacks=True,
            parent_states=((1, 0), (1, 0)), child_states=((1, 0), (1, 0)))
        self.assertIn((3, 3), pairs.items())
        self.assertTrue(receipts)
        cold = self.attribution_obligations(old, new, callbacks=True,
            parent_states=((1, 0), (1, 0)), child_states=((0, 0), (0, 0)))
        self.assertTrue(cold[1])
        self.assertEqual(len(cold[1][0]['callback_capsule_sha256']), 1)
        macro = old.replace('verify_archive_signature()', 'verify_archive_signature(real_macro!())')
        self.assertEqual(self.attribution_obligations(macro, macro.replace('old();', 'new();'), callbacks=True)[0], {})
        outer_macro = old.replace('consume(', 'consume!(')
        self.assertEqual(self.attribution_obligations(outer_macro,
            outer_macro.replace('old();', 'new();'), callbacks=True)[0], {})
        with self.assertRaises(ValueError):
            self.attribution_obligations(old, new, callbacks=True,
                parent_states=((1, 0), (1, 0)), child_states=((1, 0), (0, 1)))
        def duplicate(owners, sources):
            owners[1].append(dict(owners[1][1]))
        def duplicate_ordinal(owners, sources):
            extra = copy.deepcopy(owners[1][1])
            extra['name'] = extra['name'].replace('retained0B3_', 'retaineds_0B3_')
            owners[1].append(extra)
        def wrong_parent(owners, sources):
            owners[1][1]['name'] = '_RNCNvCs9_7example8retained0B3_'
        duplicate_source = old.replace('    consume(|| verify_archive_signature());',
            '    consume(|| verify_archive_signature());\n    consume(|| verify_archive_signature());')
        self.assertEqual(self.attribution_obligations(duplicate_source,
            duplicate_source.replace('old();', 'new();'), callbacks=True)[0], {})
        for mutate in (duplicate, duplicate_ordinal, wrong_parent):
            with self.subTest(mutation=mutate.__name__):
                result = self.attribution_obligations(old, new, callbacks=True, mutation=mutate)
                self.assertEqual(result[0], {})

    def test_callback_capsules_preserve_item_disambiguators_and_namespace(self):
        old = 'fn retained() {\n    old();\n    consume(|| verify_archive_signature());\n    finish();\n}\n'
        new = old.replace('old();', 'new();')
        def identity(owners, sources, mode):
            for side, members in enumerate(owners):
                for owner in members:
                    if mode in ('stable', 'different-function'):
                        discriminator = 's0_' if mode == 'different-function' and side == 1 else 's_'
                        owner['name'] = owner['name'].replace('8retained', discriminator + '8retained')
                    else:
                        discriminator = 's_' if side == 1 else ''
                        owner['name'] = (owner['name'].replace('NvCs', 'NvNtCs')
                            .replace('_7example8retained', '_7example' + discriminator + '5tests8retained')
                            .replace('B3_', 'B5_'))
        pairs, receipts, _ = self.attribution_obligations(old, new, callbacks=True,
            mutation=lambda owners, sources: identity(owners, sources, 'stable'))
        self.assertIn((3, 3), pairs.items())
        self.assertTrue(receipts)
        for mode in ('different-function', 'different-module'):
            with self.subTest(mode=mode):
                result = self.attribution_obligations(old, new, callbacks=True,
                    mutation=lambda owners, sources: identity(owners, sources, mode))
                self.assertEqual(result[0], {})

    def test_repeated_statements_require_unique_ancestor_source_context(self):
        old = ('fn retained() {\n    for value in values {\n        if skip(value) {\n'
               '            continue;\n        }\n        if reject(value) {\n'
               '            continue;\n        }\n        old(value);\n    }\n}\n')
        new = old.replace('old(value)', 'new(value)')
        pairs, receipts, _ = self.attribution_obligations(old, new)
        self.assertIn((4, 4), pairs.items())
        self.assertIn((7, 7), pairs.items())
        self.assertTrue(receipts)
        duplicate = old.replace('reject(value)', 'skip(value)')
        self.assertEqual(self.attribution_obligations(duplicate, duplicate.replace('old(value)', 'new(value)'))[0], {})
        self.assertEqual(self.attribution_obligations(old, new.replace('skip(value)', 'unrelated(value)'))[0], {})
        def swapped_rows(owners, sources):
            for side, members in enumerate(owners):
                for copy, owner in enumerate(members):
                    for region in owner['regions']:
                        if region[0] in (4, 7):
                            states = ((1, 0), (0, 1)) if side == 0 else ((1, 1), (0, 0))
                            region[4] = states[region[0] == 7][copy]
        with self.assertRaises(ValueError):
            self.attribution_obligations(old, new, mutation=swapped_rows)

    def renamed_capsule_compare(self, copy_states=None, mutate=None, new_source=None, async_base=False):
        old = b'#[test]\nfn obsolete() -> Result<()> {\n    assert_eq!(old(), false);\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\n'
        if async_base:
            old = old.replace(b'#[test]\nfn', b'#[tokio::test]\nasync fn')
        new = new_source or b'#[test]\nfn replacement() -> Result<()> {\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\n'
        copy_states = copy_states or (((1, 1),), ((1, 1),))
        def owners(base, head):
            for side, (document, source, name, zero) in enumerate(((base, old, 'obsolete', 6),
                                                                  (head, new, 'replacement', 5))):
                lines = source.decode().splitlines()
                end = next(line for line, text in enumerate(lines, 1) if text == '}')
                document['data'][0]['functions'] = []
                for instance, states in enumerate(copy_states[side]):
                    symbol = f'_RNvNtCs{instance + 1}_7example5testss_' + str(len(name)) + name
                    rows = [[line, 1, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                            for line in range(3, end + 1)]
                    for number, state in zip((5 - side, 6 - side), states):
                        rows[number - 3][4] = state
                    tail = [] if async_base else [
                        [zero, len(lines[zero - 1]), zero, len(lines[zero - 1]) + 1, 0, 0, 0, 0]]
                    owner = dict(name=symbol, filenames=['/src/example.rs'], regions=[
                        [2, lines[1].index('{') + 1, end, 2, 1, 0, 0, 0], *rows, *tail])
                    if async_base:
                        owner['count'] = 1
                    document['data'][0]['functions'].append(owner)
                    if async_base and side == 0:
                        document['data'][0]['functions'].append(dict(name='_RNC' + symbol[2:] + '0B5_',
                            count=1, filenames=['/src/example.rs'], regions=[
                                [2, lines[1].index('{') + 1, 2, lines[1].index('{') + 2, 1, 0, 0, 0],
                                *copy.deepcopy(rows[:-1])]))
            if mutate:
                mutate(base, head)
        return self.compare(before=[(line, len(copy_states[0])) for line in range(2, 10)],
            after=[(line, len(copy_states[1])) for line in range(2, len(new.decode().splitlines()) + 1)],
            mutate=owners, sources=({'example.rs': old}, {'example.rs': new}))

    def test_renamed_owner_retains_only_its_unique_capsule_and_proved_tail(self):
        receipt = self.renamed_capsule_compare()
        self.assertEqual([receipt[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        proofs = receipt['retained_replacement_obligations']
        pairs = [pair for row in proofs for pair in row['pairs']]
        self.assertTrue(all([line, line - 1] in pairs for line in range(4, 10)))
        self.assertIn(0, proofs[0]['base_instance_states'][0])
        self.assertEqual(proofs[0]['base_instance_states'], proofs[0]['head_instance_states'])

    def test_fully_covered_async_test_migration_retains_all_owner_trees(self):
        new = b'#[test]\nfn replacement() -> Result<()> {\n    use support::Value;\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\n'
        receipt = self.renamed_capsule_compare(new_source=new, async_base=True)
        self.assertEqual([receipt[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertTrue(any(row.get('fully_covered_replacement_owners')
                            for row in receipt['retained_replacement_obligations']))

    def test_fully_covered_test_migration_refuses_missing_future_body(self):
        def missing(base, head):
            base['data'][0]['functions'].pop()
        new = b'#[test]\nfn replacement() -> Result<()> {\n    use support::Value;\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\n'
        with self.assertRaises(ValueError):
            self.renamed_capsule_compare(new_source=new, async_base=True, mutate=missing)

    def test_fully_covered_test_migration_refuses_cold_or_foreign_copies(self):
        new = b'#[test]\nfn replacement() -> Result<()> {\n    use support::Value;\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\n'
        def mutate(base, head, mode):
            future = base['data'][0]['functions'][1]
            current = head['data'][0]['functions'][0]
            if mode == 'cold-future-entry':
                future['count'] = 0
            elif mode == 'cold-future-region':
                future['regions'][-1][4] = 0
            elif mode == 'cold-head-entry':
                current['count'] = 0
            elif mode == 'cold-head-region':
                current['regions'][-1][4] = 0
            elif mode == 'foreign-item':
                future['name'] = future['name'].replace('s_8obsolete', 's0_8obsolete')
            elif mode == 'foreign-namespace':
                future['name'] = future['name'].replace('5tests', '5other')
            elif mode == 'foreign-crate-copy':
                future['name'] = future['name'].replace('Cs1_', 'Cs99_')
            elif mode == 'duplicate-future':
                base['data'][0]['functions'].append(copy.deepcopy(future))
        for mode in ('cold-future-entry', 'cold-future-region', 'cold-head-entry', 'cold-head-region',
                     'foreign-item', 'foreign-namespace', 'foreign-crate-copy', 'duplicate-future'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.renamed_capsule_compare(new_source=new, async_base=True,
                    mutate=lambda base, head: mutate(base, head, mode))

    def test_replacement_residuals_cannot_swap_matching_copies_per_row(self):
        with self.assertRaisesRegex(ValueError, 'Replacement residual lost compiled-copy coverage'):
            self.renamed_capsule_compare((((1, 0), (0, 1)), ((0, 0), (1, 1))))

    def test_renamed_capsule_does_not_authorize_a_cold_tail(self):
        def cold_tail(base, head):
            for region in head['data'][0]['functions'][0]['regions']:
                if region[0] == region[2] == 7:
                    region[4] = 0
        with self.assertRaisesRegex(ValueError, 'Replacement residual lost compiled-copy coverage'):
            self.renamed_capsule_compare((((1, 1), (1, 1)), ((1, 1), (1, 1))), mutate=cold_tail)

    def test_renamed_capsule_refuses_missing_copies_foreign_owners_and_changed_attributes(self):
        def partial(base, head):
            head['data'][0]['functions'].pop()
        def foreign(base, head):
            head['data'][0]['functions'].append(dict(name='foreign', filenames=['/src/example.rs'],
                regions=[[4, 9, 4, 19, 1, 0, 0, 0]]))
        def wrong_parent(base, head):
            head['data'][0]['functions'][0]['name'] = '_RNvNtCs1_7example5otherss_11replacement'
        for mutation in (partial, foreign, wrong_parent):
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                self.renamed_capsule_compare((((1, 1), (1, 1)), ((1, 1), (1, 1))), mutate=mutation)
        changed = b'#[cfg(test)]\nfn replacement() -> Result<()> {\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\n'
        with self.assertRaises(ValueError):
            self.renamed_capsule_compare(new_source=changed)

    def test_renamed_capsule_does_not_choose_one_of_duplicate_sources(self):
        duplicate = b'#[test]\nfn replacement() -> Result<()> {\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n    Ok(())\n}\nfn unrelated() {\n    assert_eq!(\n        restored(),\n        expected()?\n    );\n}\n'
        def covered_foreign(base, head):
            lines = duplicate.decode().splitlines()
            head['data'][0]['functions'].append(dict(name='unrelated', filenames=['/src/example.rs'],
                regions=[[line, 1, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                         for line in range(9, len(lines) + 1)]))
        with self.assertRaisesRegex(ValueError, 'Unproved retained execution'):
            self.renamed_capsule_compare(new_source=duplicate, mutate=covered_foreign)

    def test_replacement_witness_refuses_an_exhausted_shared_budget(self):
        original = coverage.retained_replacement_obligations
        def exhausted(*args, **kwargs):
            arguments = list(args)
            arguments[8] = [0]
            return original(*arguments, **kwargs)
        with patch.object(coverage, 'retained_replacement_obligations', side_effect=exhausted):
            with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                self.renamed_capsule_compare()

    def test_construct_budget_covers_multiline_index_growth(self):
        cases = [
            (['fn f() {'] + ['    let value = {'] * 8 + [''] * 2000
             + ['        one()'] + ['    };'] * 8 + ['}'], 1000),
            (['async fn f() {', '    match operation('] + [''] * 2000
             + ['    ).await {', '        Ok(value) => value,', '    };', '}'], 3000),
        ]
        for source, budget in cases:
            with self.subTest(budget=budget), self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                coverage._construct_inventory(source, [budget])

    def test_removed_attributed_owner_does_not_identify_a_foreign_duplicate_setup(self):
        old = b'#[test]\nfn obsolete() {\n    let directory = prepare();\n    old(directory);\n}\nfn retained() {\n    let directory = prepare();\n    same(directory);\n}\n'
        new = old.replace(b'fn obsolete()', b'fn replacement()').replace(b'old(directory)', b'new(directory)')
        def owners(base, head):
            for document, source, first in ((base, old, 'obsolete'), (head, new, 'replacement')):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(name=name, filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(lines[line - 1]) + 1, 1, 0, 0, 0]
                             for line in range(start, end + 1)])
                    for name, start, end in ((first, 2, 5), ('retained', 6, 9))]
        rows = [(line, 1) for line in range(2, 10)]
        with self.assertRaises(ValueError):
            self.compare(before=rows, after=rows, mutate=owners,
                sources=({'example.rs': old}, {'example.rs': new}))
        ambiguous_sources = old, new
        old = old.replace(b'fn retained() {\n    let directory = prepare();',
                          b'fn retained() {\n    let directory = retained_setup();')
        new = old.replace(b'fn obsolete()', b'fn replacement()').replace(b'old(directory)', b'new(directory)')
        new = new.replace(b'let directory = prepare();', b'let directory = replacement_setup();')
        receipt = self.compare(before=rows, after=rows, mutate=owners,
            sources=({'example.rs': old}, {'example.rs': new}))
        self.assertEqual([receipt[key] for key in ('deleted_summary_found', 'deleted_summary_hit',
                                                 'deleted_mapped', 'deleted_mapped_hit')], [0, 0, 0, 0])
        self.assertIn(5, [row['base_line'] for row in receipt['source_replacements']])
        old, new = ambiguous_sources
        for moved in (b'fn moved() {\n    let directory = prepare();\n    old(directory);\n}\n',
                      b'fn moved() {\n    if guard() {\n        old(directory);\n    }\n}\n'):
            with self.subTest(moved=moved), self.assertRaises(ValueError):
                self.compare(before=rows, after=rows, mutate=owners,
                    sources=({'example.rs': old}, {'example.rs': new, 'moved.rs': moved}))

    def test_removed_owner_keeps_repeated_rich_work_in_its_original_scope(self):
        old = ['#[test]', 'fn obsolete() {', '    let directory = prepare();',
               '    old(directory);', '    old(directory);', '}', 'fn retained() {',
               '    let directory = prepare();', '    same(directory);', '}']
        new = [text.replace('obsolete', 'replacement').replace('old(directory)', 'new(directory)') for text in old]
        moved = ['fn moved() {', '    if guard() {', '        old(directory);', '    }', '}']
        inventories = [coverage._construct_inventory(source, [20_000_000]) for source in (new, moved)]
        def all_head():
            return (set().union(*(inventory[4] for inventory in inventories)),
                    set().union(*(inventory[5] for inventory in inventories)))
        with self.assertRaisesRegex(ValueError, 'Ambiguous unchanged work'):
            coverage._construct_replacements(old, new, [20_000_000], all_head,
                lambda line, target, kind: kind == 'owner' and line < 7 and target < 7)

    def formatting_closure_endpoint_compare(self, mutate=None, only_anchors=False):
        old = ['fn retained(input: &[Value]) -> std::fmt::Result {',
               '    for item in input {', '        if let Some(value) = item.value {',
               '            use_value(value)?;', '        }', '    }', '    Ok(())', '}']
        new = [old[0], '    let formatted = (|| -> std::fmt::Result {',
               '        for item in input {', '            if let Some(value) = item.value {',
               '                use_value(value)?;', '            }', '        }',
               '        Ok(())', '    })();', '    formatted', '}']
        inventory = {}
        for side, source, endpoint in (('base', old, 5), ('head', new, 6)):
            owners = []
            for instance in range(2):
                parent = f'_RNvCs{instance + 1}_7example8retained'
                owners.append(dict(name=parent, filenames=['/src/example.rs'],
                    regions=[[1, source[0].index('{') + 1, len(source), 2, instance, 0, 0, 0]]))
                column = len(source[endpoint - 1])
                row = [endpoint, column, endpoint, column + 1, instance, 0, 0, 0]
                if side == 'base':
                    owners[-1]['regions'].append(row)
                else:
                    owners.append(dict(name='_RNC' + parent[2:] + '0B3_',
                        filenames=['/src/example.rs'], count=instance,
                        regions=[[2, new[1].index('||') + 1, 9, 6, instance, 0, 0, 0],
                                 [2, new[1].index('{') + 1, 2, new[1].index('{') + 2, instance, 0, 0, 0], row]))
            inventory[side] = dict(source=source, owners=owners)
        if mutate:
            mutate(inventory)
        if only_anchors:
            return coverage.retained_construct_anchors('example.rs', inventory['base']['source'],
                inventory['head']['source'], {1: 1, 5: 1, 8: 1},
                {line: 1 for line in range(1, 12) if line != 7},
                inventory['base']['owners'], inventory['head']['owners'],
                {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'})
        def owners(base, head):
            for document, side in ((base, 'base'), (head, 'head')):
                document['data'][0]['functions'] = inventory[side]['owners']
        return self.compare(before=[(1, 1), (5, 1), (8, 1)],
            after=[(line, 1) for line in range(1, 12) if line != 7], mutate=owners,
            sources=tuple({'example.rs': ('\n'.join(inventory[side]['source']) + '\n').encode()}
                          for side in ('base', 'head')))

    def test_formatting_closure_uses_the_identical_inner_construct_endpoint(self):
        receipt = self.formatting_closure_endpoint_compare()
        pairs = [pair for row in receipt['retained_constructs'] for pair in row['pairs']]
        self.assertIn([5, 6], pairs)

    def test_formatting_closure_refuses_cold_children_and_foreign_contexts(self):
        def cold_child(value):
            child = value['head']['owners'][3]
            child['count'] = 0
            for row in child['regions']:
                row[4] = 0
        with self.assertRaisesRegex(ValueError, 'Retained construct lost compiled-copy coverage'):
            self.formatting_closure_endpoint_compare(mutate=cold_child, only_anchors=True)
        def duplicate_child(value):
            value['head']['owners'].append(copy.deepcopy(value['head']['owners'][3]))
        def foreign_context(value):
            value['head']['owners'][3]['name'] += 'C3foo'
        def changed_geometry(value):
            value['head']['owners'][3]['regions'][-1][0] -= 1
            value['head']['owners'][3]['regions'][-1][2] -= 1
        def owner_attribute(value):
            value['head']['source'].insert(0, '#[rewrite_capture]')
            for owner in value['head']['owners']:
                for row in owner['regions']:
                    row[0] += 1; row[2] += 1
        for mutate in (duplicate_child, foreign_context, changed_geometry, owner_attribute):
            with self.subTest(mutation=mutate.__name__):
                self.assertEqual(self.formatting_closure_endpoint_compare(
                    mutate=mutate, only_anchors=True), ({}, []))

    def test_moved_constructs_cannot_redistribute_work_between_compiled_copies(self):
        old = ['fn retained() -> std::fmt::Result {', '    if first() {',
               '        work_one();', '    }', '    if second() {', '        work_two();', '    }', '}']
        new = [old[0], '    let formatted = (|| -> std::fmt::Result {',
               *['    ' + text for text in old[1:7]], '        Ok(())', '    })();', '    formatted', '}']
        inventories = []
        for side, source, states in ((0, old, ((1, 0), (0, 1))), (1, new, ((0, 0), (1, 1)))):
            owners = []
            for instance, state in enumerate(states):
                parent = f'_RNvCs{instance + 1}_7example8retained'
                owner = dict(name=parent, filenames=['/src/example.rs'],
                    regions=[[1, source[0].index('{') + 1, len(source), 2, 1, 0, 0, 0]])
                owners.append(owner)
                if side:
                    owner = dict(name='_RNC' + parent[2:] + '0B3_', filenames=['/src/example.rs'], count=1,
                        regions=[[2, new[1].index('||') + 1, 10, 6, 1, 0, 0, 0],
                                 [2, new[1].index('{') + 1, 2, new[1].index('{') + 2, 1, 0, 0, 0]])
                    owners.append(owner)
                for start, count in zip((2 + side, 5 + side), state):
                    column = len(source[start - 1]) - len(source[start - 1].lstrip()) + 1
                    owner['regions'].append([start, column, start + 2, column + 1, count, 0, 0, 0])
            inventories.append(owners)
        with self.assertRaisesRegex(ValueError, 'Retained construct lost compiled-copy coverage'):
            coverage.retained_construct_anchors('example.rs', old, new,
                {line: 1 for line in range(1, len(old) + 1)},
                {line: 2 for line in range(1, len(new) + 1)}, *inventories,
                {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'})

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

    def default_trait_additions_compare(self, change=None):
        old = b'pub trait Backend {\n    fn index(&self) -> usize {\n        self.fetch()\n    }\n}\n'
        new = b'// Additional consumers of the same default.\n' + old
        def owner(role, crate, shift, count):
            name = f'_RNvYNtCs{crate}_3pkg{len(role)}{role}NtB4_7Backend5index'
            return dict(name=name, filenames=['/src/example.rs'], count=count,
                        regions=[[2+shift, 5, 2+shift, 30, count, 0, 0, 0],
                                 [3+shift, 9, 3+shift, 21, count, 0, 0, 0],
                                 [4+shift, 5, 4+shift, 6, count, 0, 0, 0]])
        def bind(base, head):
            base['data'][0]['functions'] = [owner('Alpha', '1', 0, 1), owner('Beta', '1', 0, 0)]
            candidates = [owner('Alpha', '2', 1, 1), owner('Beta', '2', 1, 0), owner('Gamma', '2', 1, 1)]
            if change == 'cold-new':
                candidates[1:] = [owner('Beta', '2', 1, 1), owner('Gamma', '2', 1, 0)]
            elif change == 'cold-retained':
                candidates[:2] = [owner('Alpha', '2', 1, 0), owner('Beta', '2', 1, 1)]
            elif change == 'lost-type':
                candidates[0] = owner('Delta', '2', 1, 1)
            elif change == 'unmapped-new':
                candidates[2]['regions'][1][4] = 0
            elif change == 'unknown-symbol':
                candidates[2]['name'] = 'foreign'
            head['data'][0]['functions'] = candidates
        if change == 'changed-body':
            new = new.replace(b'self.fetch()', b'self.query()')
        return self.compare(before=[(2,1),(3,1),(4,1)], after=[(3,2),(4,2),(5,2)],
                            mutate=bind, sources=({'example.rs': old}, {'example.rs': new}))

    def test_retained_default_trait_method_can_gain_a_fully_observed_type(self):
        receipt = self.default_trait_additions_compare()
        self.assertEqual(receipt['deleted_mapped'], 0)
        self.assertEqual(receipt['additive_trait_copies'][0]['pairs'], [[2,3],[3,4],[4,5]])

    def test_default_trait_additions_require_all_original_types_and_live_new_copies(self):
        for change in ('cold-new', 'cold-retained', 'lost-type', 'unmapped-new', 'unknown-symbol', 'changed-body'):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'complete compiled-copy'):
                self.default_trait_additions_compare(change)

    def path_reference_additions_compare(self, change=None):
        old = (b'impl Fixture {\n    pub fn new_in(distro: &str, dir: impl AsRef<Path>) -> Self {\n'
               b'        Self::build(distro, dir.as_ref().to_path_buf())\n    }\n}\n')
        new = b'// Another integration test uses this constructor.\n' + old
        def owner(crate, instance, shift, count, argument='RNtNtCs7_3std4path4Path'):
            return dict(name=f'_RINvMs_NtCs{crate}_3pkg7exampleNtB5_7Fixture6new_in{argument}E{instance}',
                        filenames=['/src/example.rs'], count=count,
                        regions=[[2+shift, 5, 2+shift, 65, count, 0, 0, 0],
                                 [3+shift, 9, 3+shift, 56, count, 0, 0, 0],
                                 [4+shift, 5, 4+shift, 6, count, 0, 0, 0]])
        def bind(base, head):
            base['data'][0]['functions'] = [owner('1', 'Cs8_5alpha', 0, 1), owner('1', 'B7_', 0, 0, 'p')]
            candidates = [owner('2', 'Cs9_5alpha', 1, 1), owner('2', 'B7_', 1, 0, 'p'),
                          owner('2', 'Csa_4beta', 1, 1)]
            if change == 'lost-consumer':
                candidates[0]['name'] = candidates[0]['name'].replace('5alpha', '5gamma')
            elif change == 'lost-cold-root':
                candidates[1]['name'] = candidates[1]['name'].removesuffix('B7_') + 'Csb_5gamma'
            elif change == 'cold-added':
                candidates[2] = owner('2', 'Csa_4beta', 1, 0)
            elif change == 'changed-type':
                candidates[0]['name'] = candidates[0]['name'].replace('4PathE', '7PathBufE')
            elif change == 'foreign-type':
                candidates[2]['name'] = candidates[2]['name'].replace('3std4path4Path', '3abc4path4Path')
            elif change == 'foreign-impl':
                candidates[2]['name'] = candidates[2]['name'].replace('7Fixture', '7Foreign')
            elif change == 'foreign-std-copy':
                candidates[2]['name'] = candidates[2]['name'].replace('Cs7_3std', 'Cs8_3std')
            elif change == 'unknown-suffix':
                candidates[2]['name'] += '.llvm.1'
            elif change == 'duplicate-copy':
                candidates[2] = candidates[0]
            head['data'][0]['functions'] = candidates
        if change == 'changed-body':
            new = new.replace(b'Self::build', b'Self::apply')
        after = [(3, 2), (4, 2), (5, 2)] if change != 'cold-added' else [(3, 1), (4, 1), (5, 1)]
        return self.compare(before=[(2, 1), (3, 1), (4, 1)], after=after,
                            mutate=bind, sources=({'example.rs': old}, {'example.rs': new}))

    def test_retained_path_constructor_can_gain_a_fully_observed_consumer(self):
        receipt = self.path_reference_additions_compare()
        self.assertEqual(receipt['deleted_mapped'], 0)
        self.assertEqual(receipt['additive_path_reference_copies'][0]['pairs'], [[2, 3], [3, 4], [4, 5]])

    def test_path_constructor_addition_requires_every_original_copy_and_known_new_consumer(self):
        for change in ('lost-consumer', 'lost-cold-root', 'cold-added', 'changed-type', 'foreign-type',
                       'foreign-impl', 'foreign-std-copy', 'unknown-suffix', 'duplicate-copy', 'changed-body'):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'complete compiled-copy'):
                self.path_reference_additions_compare(change)

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

    def nested_callback_compare(self, mutate=None, fragments=None):
        old = ["fn retained(", "    value: Input,", ") -> Result<Value> {",
               "    let capture = make_state();", "    old_step();", "    action()",
               "        .map_err(|error| override_error(&capture).unwrap_or(error))?;",
               "    old_middle();", "    action()",
               "        .map_err(|error| override_error(&capture).unwrap_or(error))?;",
               "    finish()", "}", "fn override_error(state: &State) -> Option<Error> {",
               "    None", "}"]
        new = [line.replace('old_', 'new_') for line in old]
        value = {}
        for side, source in (("base", old), ("head", new)):
            owners = []
            for instance in range(2):
                parent = f"_RNvCs{instance + 1}_7example8retained"
                owners.append(dict(name=parent, filenames=["/src/example.rs"],
                    regions=[[n, 1, n, len(source[n - 1]) + 1, instance, 0, 0, 0]
                             for n in range(1, 13)]))
                for line, discriminator in ((7, ''), (10, 's_')):
                    first = source[line - 1].index('override_error') + 1
                    end = source[line - 1].rindex('))') + 2
                    owners.append(dict(name='_RNC' + parent[2:] + discriminator + '0B3_', count=instance,
                        filenames=["/src/example.rs"],
                        regions=[[line, first, line, end, instance, 0, 0, 0]]))
            owners.append(dict(name='override_error', filenames=["/src/example.rs"],
                regions=[[n, 1, n, len(source[n - 1]) + 1, 1, 0, 0, 0] for n in (13, 14, 15)]))
            value[side] = dict(source=source, owners=owners)
        if mutate:
            mutate(value)
        counts = [{n: 1 for n in range(1, len(value[side]['source']) + 1)}
                  for side in ('base', 'head')]
        return coverage.positive_source_fragments('example.rs', value['base']['source'],
            value['head']['source'], *counts, value['base']['owners'], value['head']['owners'],
            {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'},
            fragments if fragments is not None else [(6, 7, 6, 7, [7]), (9, 10, 9, 10, [10])])

    def test_nested_callback_refuses_outer_owner_attributes(self):
        for side in ('base', 'head'):
            def mutate(value):
                value[side]['source'].insert(0, '#[rewrite_capture]')
                for owner in value[side]['owners']:
                    for region in owner['regions']:
                        region[0] += 1
                        region[2] += 1
            fragments = ([(7, 8, 6, 7, [8]), (10, 11, 9, 10, [11])] if side == 'base'
                         else [(6, 7, 7, 8, [7]), (9, 10, 10, 11, [10])])
            with self.subTest(side=side), self.assertRaisesRegex(ValueError, 'Ambiguous unchanged'):
                self.nested_callback_compare(mutate=mutate, fragments=fragments)

    def test_nested_map_err_owners_preserve_complete_child_obligations(self):
        pairs, receipts = self.nested_callback_compare()
        self.assertEqual(pairs, {7: 7, 10: 10})
        self.assertEqual(receipts[0]['instances'], 2)
        self.assertTrue(receipts[0]['nested_callbacks'])

    def test_nested_callback_refuses_foreign_or_incomplete_compiled_children(self):
        def children(value):
            return [owner for owner in value['head']['owners'] if owner['name'].startswith('_RNC')]
        def child_name(change):
            def mutate(value):
                children(value)[0]['name'] = change(children(value)[0]['name'])
            return mutate
        def missing(value):
            value['head']['owners'].remove(children(value)[0])
        def extra(value):
            child = copy.deepcopy(children(value)[0]); child['name'] = child['name'].replace('0B3_', 's0_0B3_')
            value['head']['owners'].append(child)
        def escaping(value):
            children(value)[0]['regions'][0][1] = 1
        def changed_geometry(value):
            for owner in children(value):
                owner['regions'][0][3] -= 1
        def lost_child(value):
            for owner in children(value):
                owner['count'] = 0
                for region in owner['regions']:
                    region[4] = 0
        def split_credit(value):
            for owner in value['head']['owners']:
                if owner['name'].startswith('_RNv'):
                    for region in owner['regions']:
                        region[4] = int('Cs1_' in owner['name'])
        cases = {
            'missing': missing, 'extra': extra, 'outside_body': escaping,
            'changed_geometry': changed_geometry, 'lost_child_hot_bits': lost_child,
            'parent_child_credit_split': split_credit,
            'wrong_crate': child_name(lambda name: name.replace('Cs1_', 'Cs9_')),
            'shim': child_name(lambda name: name.replace('_RNC', '_RNS')),
            'wrong_backref': child_name(lambda name: name.replace('B3_', 'B2_')),
            'foreign_instantiation': child_name(lambda name: name + 'C3foo'),
            'vendor_suffix': child_name(lambda name: name + '.llvm.1'),
            'unknown_symbol': child_name(lambda name: 'foreign'),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.nested_callback_compare(mutate=mutate)

    def test_nested_callback_refuses_changed_or_unsupported_capture_construction(self):
        def lines(changes):
            def mutate(value):
                head = value['head']
                for line, text in changes.items():
                    head['source'][line - 1] = text
                for owner in head['owners']:
                    if not owner['name'].startswith('_RNC'):
                        for region in owner['regions']:
                            region[3] = len(head['source'][region[2] - 1]) + 1
            return mutate
        cases = {
            'changed_initializer': {4: '    let capture = other_state();'},
            'mutable': {4: '    let mut capture = make_state();'},
            'type_annotation': {4: '    let capture: State = make_state();'},
            'destructuring': {4: '    let (capture, other) = make_state();'},
            'duplicate_binding': {8: '    let capture = make_state();'},
            'scoped_import': {8: '    use overrides::override_error;'},
            'shadowed_function': {5: '    let override_error = another_handler;'},
            'ancestor_capture': {5: '    if ready {', 8: '    }'},
            'if_let_function': {4: '    if let Some(override_error) = handler {',
                                5: '        let capture = make_state();', 8: '    }'},
            'for_function': {4: '    for override_error in handlers {',
                             5: '        let capture = make_state();', 8: '    }'},
            'conditional_root_function': {13: '#[cfg(any())] fn override_error(state: &State) -> Option<Error> {'},
            'method_not_root_function': {13: 'impl Host {',
                14: '    fn override_error(state: &State) -> Option<Error> { None }', 15: '}'},
        }
        for label, changes in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.nested_callback_compare(mutate=lines(changes))

    def test_nested_callback_refuses_macro_or_attribute_created_capture_shadows(self):
        cases = {
            'parentheses': (5, '    shadow!(capture);'),
            'braces': (5, '    shadow! { capture }'),
            'brackets': (5, '    shadow![capture];'),
            'qualified': (5, '    crate::shadow!(capture);'),
            'raw_keyword': (5, '    r#return!(capture);'),
            'late_item': (11, '    shadow!(); finish()'),
            'local_definition': (5, '    macro_rules! shadow { () => { let capture = other_state(); }; }'),
            'attribute': (4, '    #[replace_binding] let capture = make_state();'),
        }
        for label, (line, replacement) in cases.items():
            def mutate(value):
                head = value['head']
                head['source'][line - 1] = replacement
                head['source'].append(
                    'macro_rules! shadow { () => { fn override_error(_: &State) -> Option<Error> { other_error() } }; }'
                    if label == 'late_item' else
                    'macro_rules! shadow { ($name:ident) => { let $name = other_state(); }; }')
                for owner in head['owners']:
                    if not owner['name'].startswith('_RNC'):
                        for region in owner['regions']:
                            region[3] = len(head['source'][region[2] - 1]) + 1
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.nested_callback_compare(mutate=mutate)

    def test_nested_callback_preserves_expression_macro_construction(self):
        def mutate(value):
            for side in ('base', 'head'):
                value[side]['source'][4] = (
                    '    let extra = if matches!(value, Some(_)) { 1 } else { 0 };')
                for owner in value[side]['owners']:
                    if not owner['name'].startswith('_RNC'):
                        for region in owner['regions']:
                            region[3] = len(value[side]['source'][region[2] - 1]) + 1
        pairs, _ = self.nested_callback_compare(mutate=mutate)
        self.assertEqual(pairs, {7: 7, 10: 10})

    def test_nested_callback_rejects_raw_context_suffixes_before_decoding(self):
        def contexts(value):
            for side in ('base', 'head'):
                for owner in value[side]['owners']:
                    if owner['name'].startswith('_RNv'):
                        owner['name'] += 'C3foo'
                    elif owner['name'].startswith('_RNC'):
                        owner['name'] += 'C3bar'
        with mock.patch.object(coverage, 'demangle_plain_rust_callbacks',
                               side_effect=AssertionError('invalid raw context reached GNU')):
            with self.assertRaises(ValueError):
                self.nested_callback_compare(mutate=contexts)

    def test_nested_callback_rejects_colliding_decoded_parent_contexts(self):
        def collide(value):
            for owner in value['head']['owners']:
                owner['name'] = owner['name'].replace('Cs2_', 'Cs01_')
        with self.assertRaises(ValueError):
            self.nested_callback_compare(mutate=collide)

    def test_nested_callback_requires_supported_gnu_decoder(self):
        coverage.demangle_plain_rust_callbacks.cache_clear()
        with mock.patch.object(coverage.shutil, 'which', return_value=None), \
                self.assertRaisesRegex(ValueError, r'requires GNU c\+\+filt'):
            self.nested_callback_compare()

    def test_nested_callback_refuses_decoder_failures_and_unparsed_output(self):
        def output(value):
            def run(argv, **kwargs):
                data = b'GNU c++filt fixture\n' if '--version' in argv else value(kwargs['input'])
                return subprocess.CompletedProcess(argv, 0, data, b'')
            return run
        cases = {
            'echo': output(lambda data: data),
            'missing_row': output(lambda data: b'unknown\n'),
            'oversized': output(lambda data: b'x' * (256 * 1024 + 1)),
            'non_ascii': output(lambda data: b'\xff\n' * len(data.splitlines())),
            'timeout': subprocess.TimeoutExpired(['c++filt'], 5),
            'failed_process': subprocess.CalledProcessError(1, ['c++filt']),
        }
        for label, result in cases.items():
            coverage.demangle_plain_rust_callbacks.cache_clear()
            try:
                with self.subTest(label=label), mock.patch.object(coverage.subprocess, 'run', side_effect=result), \
                        self.assertRaises(ValueError):
                    self.nested_callback_compare()
            finally:
                coverage.demangle_plain_rust_callbacks.cache_clear()

    def test_callback_decoder_rejects_unsupported_input_before_process_execution(self):
        parent = '_RNvCs1_7example8retained'
        cases = [
            (parent, parent),
            ('_R' + 'x' * 4096,),
            tuple('_RNvCs' + str(n) + '_7example8retained' for n in range(257)),
            (parent, parent + 'C3foo'),
            (parent, '_RNC' + parent[2:] + '0B2_'),
            (parent, parent + 'I' + 'B0_' * 1000),
        ]
        for symbols in cases:
            with self.subTest(count=len(symbols)), mock.patch.object(coverage.subprocess, 'run',
                    side_effect=AssertionError('unsupported symbol inventory reached GNU')), self.assertRaises(ValueError):
                coverage.demangle_plain_rust_callbacks(symbols)

    def transparent_forwarder_compare(self, mutate=None):
        def extracted(value):
            head = value["head"]
            end = head["owners"][0]["regions"][-1][0]
            body, tail = head["source"][3:end], head["source"][end:]
            wrapper = value["base"]["source"][:3] + ["    extracted(value, None, &[])", "}"]
            header = ["fn extracted(", "    value: Input,", "    policy: Option<&[Policy]>,",
                      "    selections: &[Selection],", ") -> Value {"]
            source = wrapper + header + body + tail
            last = len(wrapper + header + body)
            owners = []
            for instance, owner in enumerate(head["owners"][:2]):
                owners.append({"name": owner["name"], "filenames": owner["filenames"],
                    "regions": [[n, 1, n, len(source[n - 1].encode()) + 1, instance, 0, 0, 0]
                                for n in range(len(wrapper) + 1, last + 1)]})
            for name, first, final in (("wrapper", 1, len(wrapper)), ("tail", last + 1, len(source))):
                owners.append({"name": name, "filenames": ["/src/example.rs"],
                    "regions": [[n, 1, n, len(source[n - 1].encode()) + 1, 1, 0, 0, 0]
                                for n in range(first, final + 1)]})
            head.update(source=source, counts={n: 1 for n in range(1, len(source) + 1)}, owners=owners)
            if mutate:
                mutate(value)
        return self.multiline_copies_compare(mutate=extracted)

    def test_transparent_forwarder_preserves_extracted_fragment_obligations(self):
        result = self.transparent_forwarder_compare()
        witness = result["positive_source_fragments"][0]
        self.assertEqual(witness["pairs"], [[6, 14], [10, 18]])
        self.assertEqual(witness["forwarder"]["wrapper_range"], [1, 5])
        self.assertEqual(witness["forwarder"]["callee_range"], [6, 20])

    def test_transparent_forwarder_refuses_changed_arguments_and_signatures(self):
        def change(line, text):
            def mutate(value):
                head = value["head"]
                head["source"][line - 1] = text
                for owner in head["owners"]:
                    for region in owner["regions"]:
                        region[3] = len(head["source"][region[2] - 1].encode()) + 1
            return mutate
        cases = {
            "swapped": (4, "    extracted(None, value, &[])"),
            "repeated": (4, "    extracted(value, value, &[])"),
            "omitted": (4, "    extracted(None, &[])"),
            "transformed": (4, "    extracted(&value, None, &[])"),
            "nested_call": (4, "    extracted(rewrite(value), None, &[])"),
            "question": (4, "    extracted(value, None, &[])?"),
            "qualified": (4, "    self::extracted(value, None, &[])"),
            "statement": (4, "    log(); extracted(value, None, &[])"),
            "return": (4, "    return extracted(value, None, &[])"),
            "different_default": (4, "    extracted(value, Some(value), &[])"),
            "changed_parameter_type": (7, "    value: OtherInput,"),
            "duplicate_parameter_name": (8, "    value: Option<&[Policy]>,"),
            "changed_return": (10, ") -> OtherValue {"),
            "unsafe_callee": (6, "unsafe fn extracted("),
        }
        for label, (line, text) in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "Ambiguous unchanged"):
                self.transparent_forwarder_compare(mutate=change(line, text))
        def shadowed(value):
            change(6, "fn value(")(value)
            change(4, "    value(value, None, &[])")(value)
        with self.assertRaisesRegex(ValueError, "Ambiguous unchanged"):
            self.transparent_forwarder_compare(mutate=shadowed)

    def test_transparent_forwarder_refuses_conditional_nested_or_shadowed_contexts(self):
        def insert(head, first, lines):
            head["source"][first - 1:first - 1] = lines
            for owner in head["owners"]:
                for region in owner["regions"]:
                    for field in (0, 2):
                        if region[field] >= first:
                            region[field] += len(lines)
            head["counts"] = {n: 1 for n in range(1, len(head["source"]) + 1)}
        def surrounded(before, after):
            def mutate(value):
                head = value["head"]
                insert(head, 21, after)
                insert(head, 6, before)
            return mutate
        cases = {
            "attribute": surrounded(["#[", "cfg(test)", "]"], []),
            "impl": surrounded(["impl Holder {"], ["}"]),
            "module": surrounded(["mod nested {"], ["}"]),
            "macro_parentheses": surrounded(["generate!("], [");"]),
            "macro_braces": surrounded(["generate! {"], ["}"]),
        }
        for label, lines in {
            "glob_import": ["use hidden::*;"],
            "shadowed_none_import": ["use hidden::{None};"],
            "shadowed_none_constant": ["const None: Option<&[Policy]> = Option::Some(&[]);"],
            "no_prelude": ["#![no_implicit_prelude]"],
        }.items():
            cases[label] = lambda value, lines=lines: insert(value["head"], 1, lines)
        for label, mutate in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.transparent_forwarder_compare(mutate=mutate)

    def test_transparent_forwarder_refuses_existing_or_shared_callees(self):
        def append_function(side, name, body):
            start = len(side["source"]) + 1
            side["source"] += [f"fn {name}(", "    value: Input,", ") -> Value {", body, "}"]
            side["counts"] = {n: 1 for n in range(1, len(side["source"]) + 1)}
            side["owners"].append({"name": name, "filenames": ["/src/example.rs"],
                "regions": [[n, 1, n, len(side["source"][n - 1].encode()) + 1, 1, 0, 0, 0]
                            for n in range(start, start + 5)]})
        def existing(value):
            append_function(value["base"], "extracted", "    keep()")
        def shared(value):
            append_function(value["base"], "another", "    keep()")
            append_function(value["head"], "another", "    extracted(value, None, &[])")
        for label, mutate in (("existing", existing), ("shared", shared)):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.transparent_forwarder_compare(mutate=mutate)

    def test_transparent_forwarder_refuses_split_fragment_ownership(self):
        captured = {}
        self.transparent_forwarder_compare(mutate=lambda value: captured.update(value))
        groups = []
        for side in ("base", "head"):
            value = captured[side]
            by_span = {}
            for owner in value["owners"]:
                regions = owner["regions"]
                by_span.setdefault((regions[0][0], regions[-1][2]), []).append(owner)
            groups.append({prefix: (*span, by_span[span]) for span, prefix in
                           coverage.source_function_prefixes(value["source"], by_span).items()})
        self.assertEqual(coverage.transparent_forwarder_groups(
            captured["base"]["source"], captured["head"]["source"], groups,
            [(5, 6, 13, 14, [6]), (11, 12, 4, 5, [12])]), {})

    def test_transparent_forwarder_retains_every_compiled_copy_and_foreign_owner_guard(self):
        def missing(value):
            value["head"]["owners"].pop(0)
        def lost(value):
            value["head"]["owners"][1]["regions"][8][4] = 0
        def foreign(value):
            value["head"]["owners"].append({"name": "foreign", "filenames": ["/src/example.rs"],
                "regions": [[14, 1, 14, 6, 1, 0, 0, 0]]})
        for label, mutate in (("missing_copy", missing), ("lost_hot_bit", lost), ("foreign_owner", foreign)):
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.transparent_forwarder_compare(mutate=mutate)

    def cold_fragment_compare(self, mutate=None):
        old = ['fn retained() {', '    if ready {', '        if permitted {',
               '            if extra { old();', '        }', '    }', '    }', '    finish();', '}']
        new = [line.replace('old();', 'new();') for line in old]
        value = {}
        for side, source in (('base', old), ('head', new)):
            value[side] = dict(source=source, counts={5: int(side == 'head'), 6: 1, 8: 1},
                owners=[dict(name=f'{side}_copy_{instance}', filenames=['/src/example.rs'],
                    regions=[[n, 1, n, len(source[n - 1]) + 1,
                              int(instance == 0 and (n != 5 or side == 'head')), 0, 0, 0]
                             for n in range(1, 10) if n != 7]) for instance in range(2)])
        if mutate:
            mutate(value)
        return coverage.positive_source_fragments('example.rs', old, new,
            value['base']['counts'], value['head']['counts'],
            value['base']['owners'], value['head']['owners'],
            {'/src/example.rs': 'example.rs'}, {'/src/example.rs': 'example.rs'},
            [(4, 7, 4, 7, [5, 6]), (7, 8, 7, 8, [8])])

    def test_fragment_preserves_cold_rows_when_every_head_candidate_is_covered(self):
        pairs, receipts = self.cold_fragment_compare()
        self.assertEqual(pairs, {5: 5, 6: 6, 8: 8})
        self.assertEqual(receipts[0]['instance_states'], [[0, 0, 0], [0, 1, 1]])
        self.assertEqual(receipts[0]['head_instance_states'], [[0, 0, 0], [1, 1, 1]])

    def test_cold_fragment_requires_complete_consistent_counters_and_owners(self):
        def foreign(value):
            value['head']['owners'].append(dict(name='foreign', filenames=['/src/example.rs'],
                regions=[[5, 1, 5, 10, 1, 0, 0, 0]]))
        def lost(value):
            value['head']['owners'][0]['regions'][5][4] = 0
            value['head']['owners'][1]['regions'][5][4] = 1
        def foreign_unmapped(value):
            foreign(value)
            value['head']['owners'][-1]['regions'] = [[7, 1, 7, 6, 1, 0, 0, 0]]
        mutations = {
            'base_mapping_missing': lambda v: v['base']['counts'].pop(5),
            'head_mapping_missing': lambda v: v['head']['counts'].pop(5),
            'head_still_cold': lambda v: v['head']['counts'].__setitem__(5, 0),
            'base_hot_region': lambda v: v['base']['owners'][0]['regions'][4].__setitem__(4, 1),
            'base_cold_region': lambda v: v['base']['owners'][0]['regions'][5].__setitem__(4, 0),
            'head_cold_regions': lambda v: v['head']['owners'][0]['regions'][4].__setitem__(4, 0),
            'lost_correlated_copy': lost,
            'missing_copy': lambda v: v['head']['owners'].pop(),
            'foreign_owner': foreign,
            'foreign_unmapped_owner': foreign_unmapped,
            'new_cold_mapping': lambda v: v['head']['counts'].__setitem__(7, 0),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'Ambiguous unchanged source'):
                self.cold_fragment_compare(mutate)

    def test_multiline_return_change_preserves_covered_fragments_in_every_compiled_copy(self):
        result = self.multiline_copies_compare()
        self.assertEqual([result[key] for key in ("deleted_summary_found", "deleted_summary_hit",
                         "deleted_mapped", "deleted_mapped_hit")], [0, 0, 0, 0])
        self.assertEqual(result["positive_source_fragments"][0]["pairs"], [[6, 7], [10, 11]])

    def test_multiline_fragment_accepts_newly_covered_compiled_copies(self):
        def cover_cold_copy(value):
            for owner in value["head"]["owners"][:2]:
                for region in owner["regions"]:
                    region[4] = 1
        result = self.multiline_copies_compare(mutate=cover_cold_copy)
        self.assertEqual(result["positive_source_fragments"][0]["pairs"], [[6, 7], [10, 11]])
        self.assertEqual(result["positive_source_fragments"][0]["instance_states"], [[0, 0], [1, 1]])
        witness = result["positive_source_fragments"][0]
        self.assertEqual(witness["head_instance_states"], [[1, 1], [1, 1]])
        self.assertEqual(sorted(witness["instance_matching"]), [0, 1])

    def test_multiline_fragment_preserves_whole_copy_obligations_when_coverage_grows(self):
        def grow(value):
            for side in ("base", "head"):
                for instance, owner in enumerate(value[side]["owners"][:2]):
                    for region in owner["regions"]:
                        text = value[side]["source"][region[0] - 1]
                        if "shared_" in text:
                            region[4] = int(instance == (0 if "shared_a" in text else 1))
                            if side == "head" and instance == 0:
                                region[4] = 1
                            elif side == "head":
                                region[4] = int("shared_a" in text)
        result = self.multiline_copies_compare(mutate=grow, fragments=True)
        self.assertTrue(result["positive_source_fragments"])

    def test_compiled_hit_state_matching_refuses_excessive_work(self):
        before = [[0, 0]] * 1024
        after = [[0, 0]] * 1023 + [[0, 1]]
        self.assertIsNone(coverage.compiled_hit_state_matching(before, after))

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
        with self.assertRaisesRegex(ValueError, r'Retained covered line lost coverage.*example\.rs:14 -> 15; base_count=1 head_count=0'):
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

    def proof(self, value=None, **options):
        return coverage.retained_boolean_argument_paint(**(value or self.fixture()), **options)

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

    def eager_peer_fixture(self):
        value = self.fixture()
        value['before'].update({29: 1, 31: 1})
        value['after'].update({29: 3, 31: 3})
        return value

    def test_eager_boolean_witness_only_exposes_already_positive_same_ordinal_peers(self):
        receipt = self.proof(self.eager_peer_fixture(), eager_peers=True)[0]
        self.assertEqual(receipt['pairs'], [[32, 32]])
        peers = receipt['eager_argument_peers']
        self.assertEqual([peer['pairs'] for peer in peers], [[[29, 29]], [[31, 31]]])
        self.assertEqual([peer['argument_ordinal'] for peer in peers], [1, 3])
        self.assertTrue(all(region[4] > 0 for peer in peers
                            for key in ('base_observation', 'head_observation')
                            for region in peer[key]['regions']))

    def test_eager_peers_refuse_cold_copies_and_zero_subregions_under_hot_ancestors(self):
        value = self.eager_peer_fixture()
        extra = copy.deepcopy(value['head'][-1]); extra['name'] += '_cold'
        for region in extra['regions']:
            region[4] = 0
        value['head'].append(extra)
        self.assertEqual(self.proof(value, eager_peers=True), [])
        value = self.eager_peer_fixture()
        value['head'][-1]['regions'].append([29, 17, 29, 63, 0, 0, 0, 0])
        receipt = self.proof(value, eager_peers=True)[0]
        self.assertEqual([peer['pairs'] for peer in receipt['eager_argument_peers']], [[[31, 31]]])
        value = self.eager_peer_fixture(); value['after'][29] = 0
        receipt = self.proof(value, eager_peers=True)[0]
        self.assertNotIn([[29, 29]], [peer['pairs'] for peer in receipt['eager_argument_peers']])

    def test_eager_peers_do_not_follow_a_leaf_to_another_argument_ordinal(self):
        value = self.eager_peer_fixture()
        value['new'][29] = '                None,'
        value['new'][30] = '                source,'
        value['after'][30] = 3
        for row in value['head'][-1]['regions']:
            if row[:3] == [30, 17, 30]:
                row[3] = 21
            elif row[:3] == [31, 17, 31]:
                row[3] = 23
        for row in value['head_segments']:
            if row[:2] == [30, 23]:
                row[1] = 21
            elif row[:2] == [31, 21]:
                row[1] = 23
        receipt = self.proof(value, eager_peers=True)[0]
        self.assertEqual([peer['pairs'] for peer in receipt['eager_argument_peers']], [[[29, 29]]])

    def test_eager_peers_do_not_borrow_none_from_an_unrelated_hot_call(self):
        value = self.eager_peer_fixture()
        value['new'][30] = '                other,'
        for row in value['head'][-1]['regions']:
            if row[:3] == [31, 17, 31]:
                row[3] = 22
            for index in (0, 2):
                if row[index] >= 41:
                    row[index] += 1
        for row in value['head_segments']:
            if row[:2] == [31, 21]:
                row[1] = 22
            if row[0] >= 41:
                row[0] += 1
        value['new'].insert(40, '        unrelated(None);')
        value['head'][-1]['regions'].append([41, 9, 41, 25, 1, 0, 0, 0])
        value['head_segments'].extend([[41, 9, 1, True, True, False], [41, 25, 0, False, False, False]])
        value['head_segments'].sort(); value['after'][41] = 1
        receipt = self.proof(value, eager_peers=True)[0]
        self.assertEqual([peer['pairs'] for peer in receipt['eager_argument_peers']], [[[29, 29]]])

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


class ConstructBudgetAndConstructorRegressions(unittest.TestCase):
    def test_unchanged_source_reuses_lexical_work_without_sharing_changed_inputs(self):
        source = b'fn retained() {\n  step(); /*' + b'a' * 100_000 + b'*/\n}\n'
        rows = [(1, 1), (2, 1), (3, 1)]
        def owners(base, head):
            for document in (base, head):
                document['data'][0]['functions'] = [dict(name='retained', filenames=['/src/example.rs'],
                    regions=[[1, 15, 3, 2, 1, 0, 0, 0]])]
        with patch.object(coverage, 'SOURCE_CONSTRUCT_WORK_CAPACITY', 150_000):
            SourceAwareCoverageTests().compare(before=rows, after=rows, mutate=owners,
                sources=({'example.rs': source}, {'example.rs': source}))
            for changed in (source.replace(b'a' * 100_000, b'b' * 100_000),
                            source.replace(b'\n', b'\r\n')):
                with self.subTest(source_sha256=coverage.hashlib.sha256(changed).hexdigest()):
                    with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
                        SourceAwareCoverageTests().compare(before=rows, after=rows, mutate=owners,
                            sources=({'example.rs': source}, {'example.rs': changed}))

    def test_side_effecting_local_Ok_keeps_hot_copy_obligation(self):
        old = b'fn obsolete() -> Result<()> {\n    old();\n    Ok(())\n}\nfn retained() -> Result<()> {\n    same();\n    Ok(())\n}\nfn Ok(value: ()) -> Result<()> {\n    verify();\n    std::result::Result::Ok(value)\n}\n'
        new = old.replace(b'fn obsolete(', b'fn replacement(').replace(b'old();', b'new();')
        def owners(base, head):
            for document, source, first in ((base, old, 'obsolete'), (head, new, 'replacement')):
                lines = source.decode().splitlines()
                document['data'][0]['functions'] = [dict(name=f'{name}_{copy}', filenames=['/src/example.rs'],
                    regions=[[line, 1, line, len(lines[line-1])+1,
                        int(not(document is head and name == first and copy == 0)), 0, 0, 0]
                        for line in range(start, end+1)])
                    for name, start, end in ((first, 1, 4), ('retained', 5, 8), ('Ok', 9, 12))
                    for copy in range(2)]
        with self.assertRaises(ValueError):
            SourceAwareCoverageTests().compare(before=[(i,2) for i in range(1,13)],
                after=[(i,1 if i < 5 else 2) for i in range(1,13)], mutate=owners,
                sources=({'example.rs':old}, {'example.rs':new}))

    def test_function_span_expansion_uses_shared_budget(self):
        old = ['fn outer() {'] + [f'    fn nested{i}() {{' for i in range(8)] + ['']*2000 + ['        old();'] + ['    }']*8 + ['}']
        new = [line.replace('old();', 'new();') for line in old]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage._construct_replacements(old, new, [2000])

    def test_retained_anchor_materialization_uses_remaining_shared_budget(self):
        old=['fn retained() {','    if gate() {','        work();','    }','}']
        new=['fn retained() {','        if gate() {','            work();','        }','}']
        owners=[]
        for source in (old,new):
            column=len(source[3]); owners.append([dict(name='f', filenames=['/src/example.rs'],
                regions=[[1,source[0].index('{')+1,5,2,1,0,0,0],[4,column,4,column+1,1,0,0,0]])])
        inventories=[coverage._construct_inventory(source,[20_000_000]) for source in (old,new)]
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage.retained_construct_anchors('example.rs',old,new,{4:1},{4:1},*owners,
                {'/src/example.rs':'example.rs'}, {'/src/example.rs':'example.rs'},
                work=[0], inventories=inventories)


class RetiredAsyncMethodTests(unittest.TestCase):
    def fixture(self, file):
        source = '''struct SecurityPolicy;
impl SecurityPolicy {
    pub async fn assign_grade(
        &self,
    ) -> u8 {
        step()
    }
}'''.splitlines()
        scope, crate_backref = (('NtC{crate}7omg_lib7example','9') if file == '/src/example.rs'
                                else ('NtNtNtC{crate}7omg_lib4core8security6policy','d'))
        root = '_RNvMs0_'+scope+'NtB5_14SecurityPolicy12assign_grade'
        body = '_RNCNvMs0_'+scope+'NtB7_14SecurityPolicy12assign_grade0B'+crate_backref+'_'
        owners = []
        for crate, count in (('saJq9CMLDmry_', 1), ('s40j12eeWnis_', 3)):
            for symbol, regions in ((root, [[3,5,5,12,count,0,0,0]]), (body,
                    [[5,13,5,14,count,0,0,0], [6,9,6,15,count,0,0,0], [7,5,7,6,count,0,0,0]])):
                owners.append(dict(name=symbol.format(crate=crate), count=count, filenames=[file], regions=regions))
        return source, owners

    def witness(self, mutation=None):
        file = '/__w/omg/omg/src/core/security/policy.rs'
        source, owners = self.fixture(file)
        work = [1_000_000]
        inventory = coverage._construct_inventory(source, work)
        args = dict(owners=owners, files={file:'src/core/security/policy.rs'}, before={line:4 for line in range(3,8)}, head_names=set(),
                    head_file_owners=[], head_inventory=(set(),set()), head_declarations=set())
        if mutation is not None:
            mutation(args)
        name = args['files'][file]
        indexes = (coverage.index_compiled_owner_sources(owners, args['files'], work, {name}),
                   coverage.index_compiled_owner_sources([{'name':symbol,'filenames':['/other.rs']}
                       for symbol in args['head_names']]+[dict(row,filenames=[file])
                       for row in args['head_file_owners']], args['files'], work, {name}))
        return coverage.retired_async_methods(name, {4}, source, inventory, args['before'], *indexes,
            args['head_inventory'], args['head_declarations'], work)

    def test_exact_retired_owner_receives_no_ratio_adjustment(self):
        receipt, = self.witness()
        self.assertEqual(receipt['base_range'], [3, 7])
        self.assertEqual(len(receipt['owners']), 2)
        self.assertEqual(receipt['summary_credit'], [0, 0])
        self.assertEqual(receipt['mapped_credit'], [0, 0])

    def test_comparator_keeps_new_owner_independent_after_retirement(self):
        file = '/src/example.rs'
        old, baseline = self.fixture(file)
        new = (old[:2] + ['    pub fn replacement(', *old[3:5], '        new_step()', '    }',
                         '    pub fn another(', *old[3:5], '        another_step()', '    }', '}'])
        def compare(cold_head_line=None):
            before = [(line,4) for line in range(3,8)]
            after = [(line,int(line != cold_head_line)) for line in range(3,13)]
            def mutate(base, head):
                base['data'][0]['functions'] = baseline
                head['data'][0]['functions'] = [dict(name=f'head_method_{start}', filenames=[file],
                    regions=[[line,5,line,len(new[line-1])+1,count,0,0,0]
                             for line,count in after if start <= line <= start+4]) for start in (3,8)]
            return SourceAwareCoverageTests().compare(before, after, mutate,
                tuple({'src/example.rs': ('\n'.join(source)+'\n').encode()} for source in (old,new)))
        receipt = compare()
        self.assertEqual(receipt['retired_async_methods'][0]['base_range'], [3,7])
        self.assertEqual({key: value for key,value in receipt.items() if key.startswith('deleted_')},
                         dict(deleted_summary_found=0, deleted_summary_hit=0, deleted_mapped=0, deleted_mapped_hit=0))
        with self.assertRaisesRegex(ValueError, 'New uncovered instrumented line: src/example.rs:4'):
            compare(cold_head_line=4)

    def test_refuses_partial_ambiguous_or_persisting_method_evidence(self):
        def missing_child(a): a['owners'].pop()
        def missing_copy(a): del a['owners'][-2:]
        def opaque_touch(a): a['owners'].append(dict(a['owners'][0], name='opaque'))
        def wrong_scope(a): a['owners'][0]['name'] = a['owners'][0]['name'].replace('8security6policy', '8security6otherx')
        def wrong_geometry(a): a['owners'][1]['regions'][0][1] -= 1
        def wrong_lcov(a): a['before'][4] = 5
        def stale_head(a): a['head_names'].add(a['owners'][0]['name'].replace('saJq9CMLDmry_', 'saaaaaaaaaaa_'))
        def stale_body(a): a['head_names'].add(a['owners'][1]['name'].replace('saJq9CMLDmry_', 'saaaaaaaaaaa_'))
        def opaque_head(a): a['head_file_owners'].append(dict(name='unknown::assign_grade'))
        def keeps_declaration(a): a['head_declarations'].add('assign_grade')
        def relocated_statement(a):
            lines = ['fn other() {','    step()','}']
            a['head_inventory'][1].update(coverage._construct_inventory(lines,[10_000])[5])
        for mutate in (missing_child, missing_copy, opaque_touch, wrong_scope, wrong_geometry, wrong_lcov,
                       stale_head, stale_body, opaque_head, keeps_declaration, relocated_statement):
            with self.subTest(mutate=mutate.__name__):
                self.assertEqual(self.witness(mutate), [])


class RetiredDeclarationParameterTests(unittest.TestCase):
    def compare_signature(self, foreign_return_paint=False):
        old = ['pub(crate) fn previous(', '    ttl: Duration,', ') -> Result<',
               '    OldValue,', '    Error,', '> {', '    check_old(ttl)', '}']
        replacement = ['fn replacement(', '    ttl: Duration,', ') -> Result<',
                       '    NewValue,', '    Error,', '>  {', '    check_new(ttl)', '}']
        new = replacement + [line.replace('replacement','another').replace('check_new','check_another')
                             for line in replacement]
        file = '/src/example.rs'
        def owner(name, source, first, crate, entry_end):
            return dict(name=f'_RNvNtCs{crate}_7omg_lib7example{len(name)}{name}', count=1, filenames=[file],
                regions=[[first,1,first+5,entry_end,1,0,0,0],
                         [first+6,5,first+6,len(source[first+5])+1,1,0,0,0],
                         [first+7,1,first+7,2,1,0,0,0]])
        def mutate(base, head):
            base['data'][0]['functions'] = [owner('previous',old,1,1,2)]
            if foreign_return_paint:
                base['data'][0]['functions'].append(dict(name='opaque', count=1, filenames=[file],
                    regions=[[5,5,5,10,1,0,0,0]]))
            head['data'][0]['functions'] = [owner(name,new,first,2,3)
                                         for name, first in (('replacement',1),('another',9))]
        sources = tuple({'src/example.rs': ('\n'.join(source)+'\n').encode()} for source in (old,new))
        return SourceAwareCoverageTests().compare([(line,1) for line in range(1,len(old)+1)],
            [(line,1) for line in range(1,len(new)+1)], mutate, sources)

    def test_only_closed_signature_rows_share_the_retired_parameter_proof(self):
        proof, = self.compare_signature()['retired_declarations']
        self.assertEqual(proof['pairs'], [])
        self.assertEqual(proof['mapped_credit'], [0,0])
        self.assertEqual([(row['line'],row['head_candidate'],row['role']) for row in proof['other_signature_lines']],
                         [(3,3,'return-type'),(5,5,'return-type')])
        with self.assertRaisesRegex(ValueError, 'Unproved retained execution|Ambiguous unchanged source correspondence'):
            self.compare_signature(foreign_return_paint=True)

    def compare(self, cold_head_line=None, mutate_old=None, mutate_head=None, head_sources=None):
        old = ['pub(crate) fn previous(', '    ttl: Duration,', ') -> u8 {',
               '    check_old(ttl)', '}']
        new = ['fn replacement(', '    ttl: Duration,', ') -> bool {', '    check_new(ttl)', '}',
               'fn another(', '    ttl: Duration,', ') -> bool {', '    another_check(ttl)', '}']
        file = '/src/example.rs'
        old_rows = [dict(name='_RNvNtCs1_7omg_lib7example8previous', count=1, filenames=[file], regions=[
            [1,1,3,8,1,0,0,0],[4,5,4,19,1,0,0,0],[5,1,5,2,1,0,0,0]])]
        if mutate_old:
            mutate_old(old_rows)
        before = [(line,1) for line in range(1,6)]
        after = [(line,int(line != cold_head_line)) for line in range(1,11)]
        def mutate(base, head):
            base['data'][0]['functions'] = old_rows
            head['data'][0]['functions'] = [dict(name=f'_RNvNtCs2_7omg_lib7example{len(name)}{name}',
                count=1, filenames=[file], regions=[[first,1,first+2,10,1,0,0,0],
                [first+3,5,first+3,len(new[first+2])+1,int(first+3 != cold_head_line),0,0,0],
                [first+4,1,first+4,2,1,0,0,0]])
                for first,name in ((1,'replacement'),(6,'another'))]
            if mutate_head:
                mutate_head(head['data'][0]['functions'])
        sources = tuple({'src/example.rs': ('\n'.join(source)+'\n').encode()} for source in (old,new))
        sources[1].update(head_sources or {})
        return SourceAwareCoverageTests().compare(before, after, mutate, sources)

    def test_retires_only_the_old_header_projection(self):
        receipt = self.compare()
        proof, = receipt['retired_declarations']
        self.assertEqual((proof['line'], proof['head_candidate']), (2,2))
        self.assertEqual(proof['pairs'], [])
        self.assertEqual({key: value for key,value in receipt.items() if key.startswith('deleted_')},
            dict(deleted_summary_found=0, deleted_summary_hit=0, deleted_mapped=0, deleted_mapped_hit=0))

    def test_cold_new_executable_line_and_opaque_old_header_are_still_refused(self):
        with self.assertRaisesRegex(ValueError, 'New uncovered instrumented line: src/example.rs:4'):
            self.compare(cold_head_line=4)
        def opaque(owners):
            owners.append(dict(name='opaque', count=1, filenames=['/src/example.rs'],
                               regions=[[2,5,2,18,1,0,0,0]]))
        with self.assertRaises(ValueError):
            self.compare(mutate_old=opaque)

    def test_persisting_head_declaration_or_raw_root_blocks_neutrality(self):
        with self.assertRaisesRegex(ValueError, 'Unproved retained execution in replaced construct'):
            self.compare(head_sources={'src/different.rs': b'fn previous() {}\n'})
        def displaced_owner(owners):
            owners.append(dict(name='_RNvNtCs3_7omg_lib7example8previous', count=1,
                filenames=['/unselected/different.rs'], regions=[[1,1,1,5,1,0,0,0]]))
        with self.assertRaisesRegex(ValueError, 'Unproved retained execution in replaced construct'):
            self.compare(mutate_head=displaced_owner)


class InherentAsyncLeafTests(unittest.TestCase):
    def compare(self, kind, mutation=None):
        if kind == 'assigned':
            old = ['impl Manager {', '    async fn checked() {', '        let refreshed = async {',
                   '            before();', '        }', '        .await;', '    }', '}']
            new = [line.replace('before()', 'after()') for line in old]
            line = 3
        else:
            old = ['impl Manager {', '    async fn checked() {', '        old_source',
                   '            .error_for_status()', '            .with_context(|| format!("fixture"))?',
                   '            .bounded_json();', '    }', '}']
            new = [line.replace('old_source','new_source') for line in old]
            line = 5
        path = '/src/example.rs'
        docs = []
        for side, source in enumerate((old,new)):
            owners = []
            for slot in range(2):
                crate = 1+slot+side*2
                value = int(side and slot == 0)
                anchor = source[1].index('{')+1
                root = [[2,5,2,anchor-1,value,0,0,0]]
                parent = [[2,anchor,2,anchor+1,value,0,0,0],[7,5,7,6,value,0,0,0]]
                if kind == 'assigned':
                    start = source[line-1].index('refreshed')+1
                    opener = source[line-1].index('{')+1
                    parent.append([line,start,line,start+len('refreshed'),value,0,0,0])
                    child = [[line,opener,line,opener+1,value,0,0,0],[5,9,5,10,value,0,0,0]]
                    child_count = value
                else:
                    method = source[line-1].index('with_context')+1
                    question = source[line-1].index('?')+1
                    macro = source[line-1].index('format!')+1
                    parent.extend([[line,method,line,method+len('with_context'),value,0,0,0],
                                   [line,question,line,question+1,0,0,0,0]])
                    child = [[line,macro,line,macro+len('format!'),0,0,0,0]]
                    child_count = 0
                tail = f'MCs{crate}_7exampleNtB{{offset}}_7Manager7checked'
                for symbol, count, regions in ((f'_RNv{tail.format(offset=2)}',value,root),
                        (f'_RNCNv{tail.format(offset=4)}0B4_',value,parent),
                        (f'_RNCNCNv{tail.format(offset=6)}00B6_',child_count,child)):
                    owners.append(dict(name=symbol, count=count, filenames=[path], regions=sorted(regions)))
            docs.append(owners)
        if mutation:
            mutation(docs,line)
        files = {path:'example.rs'}
        return coverage.positive_source_fragments('example.rs',old,new,{line:0},{line:1},*docs,files,files,
                                                  [(line-1,line,line-1,line,[line])],
                                                  inherent_async_lines=((line,),(line,)))

    def test_closed_nested_inherent_phases_preserve_exact_entry_geometry(self):
        for kind,line in (('assigned',3),('context',5)):
            with self.subTest(kind=kind):
                pairs, receipts = self.compare(kind)
                self.assertEqual(pairs, {line:line})
                self.assertEqual(receipts[0]['kind'], 'inherent-async-leaf-entry')
                self.assertEqual(len(receipts[0]['async_copies']['base']), 2)
                self.assertEqual(len(receipts[0]['async_copies']['head']), 2)

    def test_refuses_missing_foreign_and_inconsistent_nested_phase_observations(self):
        def missing(docs,line): docs[1].pop(2)
        def other_copy(docs,line): docs[1][2]['name'] = docs[1][2]['name'].replace('Cs3_', 'Cs5_')
        def foreign(docs,line):
            docs[1].append(dict(copy.deepcopy(docs[1][2]),name='opaque'))
        def shifted(docs,line): docs[1][2]['regions'][0][1] += 1
        def disagree(docs,line): docs[1][1]['regions'][1][4] = 2
        for mutation in (missing, other_copy, foreign, shifted, disagree):
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                self.compare('assigned',mutation)


class RetiredAssertionDelimiterTests(unittest.TestCase):
    def proof(self, mutation=None):
        name = 'src/example.rs'; path = '/src/example.rs'
        old = ['fn trial() {', '    for value in input {', '        assert_eq!(',
               '            value,', '            expected,', '        );', '    }', '}']
        new = ['fn trial() {', '    for value in replacement {', '        assert!(',
               '            accepts(value),', '            "fixture"', '        );', '    }', '}']
        before = {6:1}; after = {}
        owners = [[dict(name=f'_RNvNtCs{i}_7omg_lib7example5trial',count=1,filenames=[path],regions=[
            [1,1,1,12,1,0,0,0], *([[2,5,7,6,1,0,0,0]] if i==1 else []), [8,1,8,2,1,0,0,0]])]
            for i in (1,2)]
        expansions = [[],[]]; retained = []
        if mutation:
            mutation(old,new,before,after,owners,expansions,retained)
        work = [1_000_000]; files = {path:name}
        inventories = [coverage._construct_inventory(source,work) for source in (old,new)]
        indexes = [coverage.index_compiled_owner_sources(rows,files,work,{name}) for rows in owners]
        sides = [(source,inv,{id(owner):coverage.source_owner_span(owner,name,files,source)
                 for owner in owners[side]},counts,expansions[side])
                 for side,(source,inv,counts) in enumerate(zip((old,new),inventories,(before,after)))]
        head = set(inventories[1][5])
        for source in retained:
            head.update(coverage._construct_inventory(source,work)[5])
        return coverage.retired_assertion_delimiter(name,6,6,sides,indexes,(set(),head),work)

    def test_enclosing_ordinary_paint_supports_zero_credit_retirement(self):
        proof = self.proof()
        self.assertEqual(proof['base_range'], [3,6])
        self.assertEqual(proof['pairs'], [])
        self.assertEqual(proof['summary_credit'], [0,0])
        self.assertEqual(proof['mapped_credit'], [0,0])

    def test_refuses_nonassertions_real_paint_inconsistent_counts_and_retained_work(self):
        def changed(a,b,*_): b[5] = '        ) ;'
        def nonassertion(a,b,*_): b[2] = '        other!('
        def old_direct(a,b,c,d,owners,*_): owners[0][0]['regions'].append([6,9,6,11,1,0,0,0])
        def foreign_old(a,b,c,d,owners,*_):
            owners[0].append(dict(name='foreign',count=1,filenames=['/src/example.rs'],regions=[[6,9,6,11,1,0,0,0]]))
        def head_direct(a,b,c,d,owners,*_): owners[1][0]['regions'].append([6,9,6,11,0,0,0,0])
        def repeat(a,b,c,d,owners,expansions,retained): retained.append(a[:])
        def wrong_da(a,b,c,*_): c[6] = 2
        def head_da(a,b,c,d,*_): d[6] = 0
        def expand(a,b,c,d,owners,expansions,*_): expansions[1].append({'expanded':True})
        for mutation in (changed,nonassertion,old_direct,foreign_old,head_direct,repeat,wrong_da,head_da,expand):
            with self.subTest(mutation=mutation.__name__):
                self.assertIsNone(self.proof(mutation))


class IntactFixtureCallbackForestTests(unittest.TestCase):
    def binding_compare(self, fault=None, repeated=False):
        old = ['#[cfg(test)]','mod tests {','    #[test]','    fn trial() {',
               '        let path = std::env::join_paths(paths).expect("fixture PATH");',
               '        with_managed_fixture_environment(&path, || {',
               '            let runtime = fixture_runtime();',
               '            runtime.block_on(async {','                run_fixture();',
               '            });','        });','    }','}']
        if repeated:
            old[6:7] = ['            for (kind, diagnostic) in [',
                        '                ("npm", "before"),', '            ] {',
                        '                let runtime = fixture_runtime(kind);',
                        '            }']
        new = old[:4]+['        prepare_fixture();']+old[4:]
        extra = 4*int(repeated)
        binding_shift = 3*int(repeated)
        new[9+extra] = '                run_changed();'
        if repeated:
            new[8] = new[8].replace('"before"','"update"')
            if fault == 'different-kind':
                new[8] = new[8].replace('"npm"','"pip"')
            if fault == 'reads-diagnostic':
                for source, position in ((old,9),(new,10)):
                    source[position] = source[position].replace('kind','diagnostic')
        if fault == 'binding':
            new[7+binding_shift] = new[7+binding_shift].replace('fixture_runtime', 'prepare_runtime')
        file = '/src/cli/tool.rs'; name = 'src/cli/tool.rs'; files = {file:name}
        reports = []; mapped = []
        for shift, source in enumerate((old, new)):
            root = f'_RNvNtNtNtCs{1+shift}_7omg_lib3cli4tool5testss_5trial'
            outer = source[5+shift].index('{')+1
            inner = source[7+shift+extra].index('{')+1
            bind_line = 7+shift+binding_shift
            indent = 4*int(repeated)
            binding = [bind_line, 17+indent, bind_line, 24+indent, 1, 0, 0, 0]
            value = [bind_line, 27+indent, bind_line, len(source[bind_line-1]), 1, 0, 0, 0]
            if shift and fault == 'geometry':
                binding[1] += 1
            if shift and fault == 'cold':
                binding[4] = 0
            outer_regions = [[6+shift,outer,6+shift,outer+1,1,0,0,0]]
            if repeated:
                line = source[6+shift]
                for token in ('kind','diagnostic'):
                    start = line.index(token)+1
                    outer_regions.append([7+shift,start,7+shift,start+len(token),1,0,0,0])
                outer_regions.append([7+shift,line.index('[')+1,9+shift,14,1,0,0,0])
            outer_regions.extend([binding,value,[11+shift+extra,9,11+shift+extra,10,1,0,0,0]])
            inner_regions = [[8+shift+extra,inner,8+shift+extra,inner+1,1,0,0,0],
                             [9+shift+extra,17,9+shift+extra,30,1,0,0,0],
                             [10+shift+extra,13,10+shift+extra,14,1,0,0,0]]
            call_regions = [[6+shift,9,6+shift,41,1,0,0,0],[6+shift,42,6+shift,47,1,0,0,0]]
            reports.append([dict(name=symbol, count=count, filenames=[file], regions=regions) for symbol,count,regions in (
                (root,2,[[4,5,4,16,2,0,0,0],*call_regions,[12+shift+extra,5,12+shift+extra,6,2,0,0,0]]),
                ('_RNC'+root[2:]+'0B9_',1,outer_regions),('_RNCNC'+root[2:]+'00Bb_',1,inner_regions))])
            mapped.append(coverage._owner_line_counts({'regions':call_regions+outer_regions+inner_regions},
                                                       coverage._ObserverWork([10_000])))
        if fault == 'missing-child':
            reports[1].pop()
        line = 7+binding_shift
        return coverage.positive_source_fragments(name, old, new, *mapped, *reports, files, files,
            [(line-1,line,line,line+1,[line])], callback_functions={'    fn trial()'}, macro_expansions=([],[]))

    def test_retained_binding_before_changed_fixture_work(self):
        pairs, receipts = self.binding_compare()
        self.assertEqual(pairs, {7:8})
        proof, = receipts
        self.assertEqual(proof['kind'], 'retained-fixture-bindings')
        self.assertEqual(proof['pairs'], [[7,8]])

    def test_retained_binding_requires_source_and_every_raw_owner(self):
        for fault in ('binding', 'geometry', 'cold', 'missing-child'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.binding_compare(fault)

    def test_retained_loop_prefix_uses_unchanged_input_slots(self):
        pairs, _ = self.binding_compare(repeated=True)
        self.assertEqual(pairs, {10:11})
        for fault in ('different-kind', 'reads-diagnostic', 'geometry', 'cold', 'missing-child'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.binding_compare(fault, repeated=True)

    def async_binding_compare(self, fault=None, footer=False):
        old = ['#[cfg(test)]','mod tests {','    #[test]','    fn trial() {',
               '        let path = std::env::join_paths(paths).expect("fixture PATH");',
               '        with_managed_fixture_environment(&path, || {',
               '            for (kind, diagnostic) in [','                ("npm", "before"),','            ] {',
               '                runtime.block_on(async {','                    let started = Instant::now();',
               '                    run_fixture();','                });','            }','        });','    }','}']
        extra = 0
        if footer:
            old[14:14] = ['            assert!(', '                observed.is_empty(),',
                          '                "fixture completed",', '            );']
            extra = 4
        new = old[:4]+['        prepare_fixture();']+old[4:]
        new[8] = new[8].replace('before','after')
        new[12] = new[12].replace('fixture','changed')
        if fault == 'receiver':
            new[10] = new[10].replace('runtime','another')
        file = '/src/cli/tool.rs'; name = 'src/cli/tool.rs'; files = {file:name}
        reports = []; mapped = []
        for shift, source in enumerate((old,new)):
            root = f'_RNvNtNtNtCs{1+shift}_7omg_lib3cli4tool5testss_5trial'
            def row(line, column, last, end, hits=1):
                return [line+shift,column,last+shift,end,hits,0,0,0]
            def token(line, word, hits=1):
                at = source[line+shift-1].index(word)+1
                return row(line,at,line,at+len(word),hits)
            outer_open = token(6,'{')
            child_open = token(10,'{')
            call_regions = [row(6,9,6,41),row(6,42,6,47)]
            owner_regions = [outer_open,token(7,'kind'),token(7,'diagnostic'),
                row(7,source[6+shift].index('[')+1,9,14),
                token(10,'another' if shift and fault=='receiver' else 'runtime'),token(10,'block_on'),row(15+extra,9,15+extra,10)]
            if footer:
                owner_regions.extend((token(15,'assert!'),token(16,'observed',0 if shift and fault=='cold-footer' else 1),
                                      token(16,'is_empty')))
            child_regions = [child_open,token(11,'started',0 if shift and fault=='cold' else 1),
                token(11,'Instant::now()'),token(12,'run_changed' if shift else 'run_fixture'),row(13,17,13,18)]
            reports.append([dict(name=symbol,count=count,filenames=[file],regions=regions) for symbol,count,regions in (
                (root,2,[[4,5,4,16,2,0,0,0],*call_regions,row(16+extra,5,16+extra,6,2)]),
                ('_RNC'+root[2:]+'0B9_',1,owner_regions),('_RNCNC'+root[2:]+'00Bb_',1,child_regions))])
            mapped.append(coverage._owner_line_counts({'regions':call_regions+owner_regions+child_regions},
                coverage._ObserverWork([10_000])))
        fragments = [(10,11,11,12,[11])]
        if footer:
            fragments.extend(((14,16,15,17,[15,16]),(18,19,19,20,[19])))
        return coverage.positive_source_fragments(name,old,new,*mapped,*reports,files,files,
            fragments,callback_functions={'    fn trial()'},macro_expansions=([],[]))

    def test_retained_nested_binding_requires_proved_async_call_and_raw_entry(self):
        self.assertEqual(self.async_binding_compare()[0],{11:12})
        for fault in ('receiver','cold'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.async_binding_compare(fault)

    def test_retained_fixture_completion_is_proved_after_the_literal_loop(self):
        pairs, receipts = self.async_binding_compare(footer=True)
        self.assertEqual(pairs,{11:12,15:16,16:17,19:20})
        self.assertEqual(receipts[-1]['kind'],'retained-fixture-loop-completion')
        with self.assertRaises(ValueError):
            self.async_binding_compare('cold-footer',footer=True)

    def compare(self, mutation=None, expansions=([],[])):
        old = ['#[cfg(test)]','mod tests {','    #[test]','    fn trial() {',
               '        let path = std::env::join_paths(paths).expect("fixture PATH");',
               '        with_managed_fixture_environment(&path, || {',
               '            runtime.block_on(async {','                run_fixture();',
               '                cold_fixture();','            });','        });','    }','}']
        new = old[:4]+['        prepare_fixture();']+old[4:]
        file = '/src/cli/tool.rs'; name = 'src/cli/tool.rs'; files = {file:name}
        reports = []; mapped = []
        for shift,source in enumerate((old,new)):
            root = f'_RNvNtNtNtCs{1+shift}_7omg_lib3cli4tool5testss_5trial'
            outer = source[5+shift].index('{')+1
            inner = source[6+shift].index('{')+1
            outer_regions = [[6+shift,outer,6+shift,outer+1,1,0,0,0],[11+shift,9,11+shift,10,1,0,0,0]]
            inner_regions = [[7+shift,inner,7+shift,inner+1,1,0,0,0],
                             [8+shift,17,8+shift,30,1,0,0,0],[9+shift,17,9+shift,31,0,0,0,0],
                             [10+shift,13,10+shift,14,1,0,0,0]]
            call_regions = [[6+shift,9,6+shift,41,1,0,0,0],[6+shift,42,6+shift,47,1,0,0,0]]
            reports.append([dict(name=symbol, count=count, filenames=[file], regions=regions) for symbol,count,regions in (
                (root,2,[[4,5,4,17,2,0,0,0],*call_regions,[12+shift,5,12+shift,6,2,0,0,0]]),
                ('_RNC'+root[2:]+'0B9_',1,outer_regions),('_RNCNC'+root[2:]+'00Bb_',1,inner_regions))])
            mapped.append(coverage._owner_line_counts({'regions':call_regions+outer_regions+inner_regions},
                                                       coverage._ObserverWork([10_000])))
        if mutation:
            mutation(new,reports,mapped)
        return coverage.positive_source_fragments(name,old,new,*mapped,*reports,files,files,
            [(5,6,6,7,[6]),(7,8,8,9,[8]),(8,9,9,10,[9])],
            callback_functions={'    fn trial()'},macro_expansions=expansions)

    def test_whole_closed_fixture_call_preserves_covered_and_cold_rows_together(self):
        pairs, receipts = self.compare()
        self.assertEqual(pairs, {6:7,8:9,9:10})
        proof, = receipts
        self.assertEqual(proof['kind'], 'intact-fixture-callback-forest')
        self.assertEqual([row['path'] for row in proof['owners']['base']], [(),('',),('','')])
        self.assertEqual(len(proof['callback_fragments']), 3)

    def test_refuses_incomplete_changed_or_foreign_call_observations(self):
        def missing(s,o,c): o[1].pop()
        def extra(s,o,c): o[1].append(dict(copy.deepcopy(o[1][-1]),name='opaque'))
        def flags(s,o,c): o[1][-1]['regions'][1][7] = 1
        def unrelated(s,o,c): o[1][-1]['name'] = o[1][-1]['name'].replace('Cs2_','Cs3_')
        def shifted(s,o,c): o[1][-1]['regions'][1][1] += 1
        def changed(s,o,c): s[9] = s[9].replace('cold','warm')
        def loses_hit(s,o,c): o[1][-1]['regions'][1][4] = c[1][9] = 0
        for mutation in (missing,extra,flags,unrelated,shifted,changed,loses_hit):
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                self.compare(mutation)
        with self.assertRaises(ValueError):
            self.compare(expansions=([],[{'expansion':True}]))


if __name__ == "__main__":
    unittest.main()

"""Exercise exact coverage comparison and refusal of incomplete evidence."""
from collections import Counter
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
    def test_single_validated_owner_reuses_its_raw_span_without_sorting_one_shape(self):
        name = 'src/example.rs'
        filename = '/artifact/src/example.rs'
        source = ['fn retained() {', '    sample();', '}']
        fields = [filename]
        regions = [[1, 1, 1, 14, 1, 0, 0, 0],
                   *([[2, 5, 2, 11, 1, 0, 0, 0]] * 80),
                   [3, 1, 3, 2, 1, 0, 0, 0]]
        owner = dict(name='compiled', filenames=fields, regions=regions)
        files = {filename: name}
        spans = {id(owner): coverage.source_owner_span(owner, name, files, source)}
        structure = coverage._source_structural_map(source)
        prefixes = coverage.source_function_prefixes(source, [(1, 3)], structure=structure)
        _, groups, _ = coverage._compiled_function_groups(name, [owner], files, source, [12],
            source_structure=structure, validated_spans=spans, shared_prefixes=prefixes)
        self.assertEqual(list(groups.values()), [(1, 3, [owner])])

        owner['regions'] = [regions[-1], *regions[:-1]]
        self.assertEqual(coverage.source_owner_span(owner, name, files, source), spans[id(owner)])
        _, reversed_groups, _ = coverage._compiled_function_groups(
            name, [owner], files, source, [200], source_structure=structure,
            validated_spans=spans, shared_prefixes=prefixes)
        self.assertEqual(reversed_groups, groups)

    def test_replacement_and_retained_rows_share_the_same_full_source_diff(self):
        old = ['fn retained() {', '    before();', '    keep();', '}']
        new = ['fn retained() {', '    after();', '    keep();', '}']
        with patch.object(coverage.difflib, 'SequenceMatcher', wraps=coverage.difflib.SequenceMatcher) as match:
            rows = list(coverage.source_opcodes(old, new, [], {1: 1, 3: 1, 4: 1}))
        self.assertEqual([row[:5] for row in rows], [
            ('equal', 0, 1, 0, 1),
            ('replace', 1, 2, 1, 2),
            ('equal', 2, 4, 2, 4),
        ])
        full_diffs = [call for call in match.call_args_list if call.args[1] is old and call.args[2] is new]
        self.assertEqual(len(full_diffs), 1)

    def test_module_tokens_keep_the_same_bounded_lexical_scope(self):
        code = coverage._boolean_source([
            'mod outer {',
            '    fn example() {',
            '        /* mod ignored */ log("mod ignored");',
            '        mod local {} r#mod();',
            '    }',
            '}',
        ])
        self.assertEqual(len(code.module_tokens), 3)
        work = [100_000]
        for start in range(len(code.words) + 1):
            for end in range(start, len(code.words) + 1):
                self.assertEqual(code.has_module_token(start, end, work),
                                 'mod' in code.words[start:end], (start, end))

    def test_foreign_compiled_regions_respect_half_open_utf8_line_boundaries(self):
        source = ['abc', '', 'é', '𐀀', 'xy']
        positions = [(line, column) for line, row in enumerate(source, 1)
                     for column in range(1, len(row.encode('utf-8')) + 2)]
        for selected in ([], [2], [3], [1, 3, 4], [2, 3, 4, 5]):
            ends = [(line, len(source[line - 1].encode('utf-8')) + 1) for line in selected]
            for index, start in enumerate(positions):
                for end in positions[index + 1:]:
                    expected = any(start < (line, width) and end > (line, 1)
                                   for line, width in ends)
                    self.assertEqual(coverage.region_overlaps_observed_lines((*start, *end), ends),
                                     expected, (selected, start, end))

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


class RetainedSearchLoopTests(unittest.TestCase):
    def compare(self, fault=None):
        from collections import Counter
        old = [
            'pub fn load(query: &str) -> Result<()> {',
            '    with_handle(|handle| {',
            '        for db in handle.syncdbs() {',
            '            if db.hint().is_some_and(|d| accepted(d, query)) {',
            '                consume(db);',
            '            }',
            '        }',
            '        Ok(())',
            '    })',
            '}',
        ]
        insertion = ['            reject_if_unavailable(db)?;']
        new = old[:3] + insertion + old[3:]
        if fault == 'changed-loop':
            new[2] = new[2].replace('syncdbs', 'readers')
        if fault == 'changed-capture':
            new[4] = new[4].replace('query', 'other')
        filename = '/src/example.rs'
        files = {filename:'example.rs'}
        inventory = []
        descriptors = []
        indexes = []
        counts = []
        work = [coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        for side, source in enumerate((old,new)):
            owner_set = []
            for copy_number in (1,2):
                count = 0 if copy_number==2 else 2+side
                root = f'_RNvNtCs{copy_number}_7example7example4load'
                # Closed root + outer callback + unbraced method predicate.
                names = [root,'_RNC'+root[2:]+'0B5_','_RNCNC'+root[2:]+'00B7_']
                if side and fault=='bad-child-suffix':
                    names[2]=names[2][:-3]+'B8_'
                body = source[3+side]
                lexemes = ['accepted','d,','query']
                positions = [body.index(word,body.index('|d|')+3)+1 for word in lexemes[:2]]
                positions.append(body.rfind('query' if fault!='changed-capture' or not side else 'other')+1)
                def row(line, start, end, hits=count):
                    return [line,start,line,end,hits,0,0,0]
                def token(line, text, hits=count):
                    start = source[line-1].index(text)+1
                    return row(line,start,start+len(text),hits)
                def owner(name, rows):
                    return dict(name=name,filenames=[filename],count=count,regions=rows,branches=[],mcdc_records=[])
                head = [row(1,1,source[0].index('{')),token(2,'with_handle'),token(10+side,'}')]
                outer = [token(2,'{'),token(3,'db',0 if side and copy_number==1 and fault=='cold-for-binding' else count),
                         token(3,'handle'),token(3,'syncdbs' if not side or fault!='changed-loop' else 'readers'),
                         token(5+side,'consume'),token(8+side,'Ok'),token(9+side,'}')]
                if side:
                    outer.append(token(4,'reject_if_unavailable'))
                if side and fault=='missing-for-slot':
                    outer.pop(3)
                if side and fault=='missing-new-region':
                    outer.pop()
                if side and fault=='cross-insertion':
                    outer.append([3,33,4,38,count,0,0,0])
                nested = [row(4+side,start,start+size) for start,size in zip(positions,(8,1,5))]
                owner_set.extend([owner(names[0],head),owner(names[1],outer),owner(names[2],nested)])
                if side and copy_number==2 and fault=='missing-cold-child':
                    owner_set.pop()
            if side and fault=='opaque-owner':
                owner_set.append(dict(owner_set[1],name='unresolved-origin'))
            if side and fault=='changed-entry-count':
                owner_set[1]['count']+=1
            lexer,rows,*rest=coverage._construct_inventory(source,work)
            inventory.append((lexer,rows,*rest))
            definition,=[r for r in rows if r['kind']=='fn']
            parent=[o for o in owner_set if coverage.plain_rust_function_symbol(o['name'])]
            descriptors.append(dict(group=(1,10+side,parent),row=definition,attributes=['pub'],
                context=((),()),declaration='load',signature=definition['header']))
            indexes.append(coverage.index_compiled_owner_sources(owner_set,files,work,{'example.rs'}))
            observer=coverage._ObserverWork(work)
            counts.append(dict(coverage._llvm22_rows(coverage._llvm22_segments(
                [r for o in owner_set for r in o['regions']],observer),observer)))
        if fault=='mismatched-da':
            counts[1][3]+=1
        return coverage.retained_inline_callback_obligations(
            'example.rs',(old,new),counts,descriptors,inventory,[],indexes,Counter(),work)

    def test_retained_for_loop_insertion_keeps_complete_copies_and_fresh_regions(self):
        result = self.compare()
        self.assertIsNotNone(result)
        pairs, receipt = result
        self.assertEqual(pairs[3],3)
        self.assertEqual(pairs[4],5)
        self.assertNotIn(4,pairs.values())
        self.assertEqual(receipt['inserted_loop_lines'],[4])
        self.assertEqual(receipt['preserved_base_mapped'],[])
        self.assertEqual([len(side) for side in receipt['compiled_forests']],[2,2])

    def test_retained_for_loop_refuses_incomplete_or_rebound_observations(self):
        for fault in ('changed-loop','changed-capture','bad-child-suffix','cold-for-binding',
                      'missing-for-slot','missing-new-region','cross-insertion','missing-cold-child','opaque-owner',
                      'changed-entry-count','mismatched-da'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.compare(fault))


class RetainedTestQueueExpectationTests(unittest.TestCase):
    def compare(self, refusal=None):
        old = [
            '#[cfg(test)]',
            'mod tests {',
            '    #[test]',
            '    fn checked() {',
            '        let (tx, _rx) = request_channel();',
            '        for index in 0..2 {',
            '            let (reply, _response) = oneshot::channel();',
            '            tx.try_send(Request::Info(index.to_string(), reply))',
            '                .expect("each queued response must fit");',
            '        }',
            '        let (reply, _response) = oneshot::channel();',
            '        let _ = reply;',
            '    }',
            '}',
        ]
        new = old.copy()
        new[4] = '        let (tx, mut rx) = request_channel();'
        new[5] = '        for _ in 0..2 {'
        new[7] = '            tx.try_send(reply)'
        if refusal == 'changed-range':
            new[5] = '        for _ in 0..3 {'
        if refusal == 'control-escape':
            new[6] = '            continue;'
        filename = '/artifact/src/example.rs'
        files = {filename: 'src/example.rs'}
        documents = []
        counts = []
        inventories = []
        for side, text in enumerate((old,new)):
            def region(line, word, count):
                column = text[line-1].index(word)+1
                return [line,column,line,column+len(word),count,0,0,0]
            rows = [[4,5,4,17,1,0,0,0],
                    [6,text[5].index('{')+1,10,10,2,0,0,0],
                    region(8,'tx',2),region(8,'try_send',2),
                    region(11,'oneshot::channel()',0 if side and refusal=='cold-successor' else 1),
                    region(13,'}',1)]
            if side and refusal=='missing-send':
                del rows[3]
            root = dict(name=f'_RNvNtNtCs{side+1}_7omg_lib7example5tests7checked',
                        filenames=[filename],regions=rows,count=1,branches=[],mcdc_records=[])
            owners = [root]
            if side and refusal=='foreign-owner':
                owners.append(dict(root,name='opaque',regions=[region(9,'expect',1)]))
            work = [coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
            observer = coverage._ObserverWork(work)
            counts.append(dict(coverage._llvm22_rows(coverage._llvm22_segments(
                [r for owner in owners for r in owner['regions']],observer),observer)))
            documents.append(owners)
            inventories.append(coverage._construct_inventory(text,work))
        return coverage.positive_source_fragments(
            'src/example.rs',old,new,*counts,*documents,files,files,[(8,9,8,9,[9])],
            construct_inventories=inventories,callback_functions=('    fn checked()',),
            macro_expansions=([],[]))

    def test_retained_queue_expectation_binds_the_loop_and_separate_successor(self):
        pairs, receipts = self.compare()
        self.assertEqual(pairs,{9:9})
        witness, = [entry for entry in receipts if entry.get('kind')=='retained-test-queue-expectation']
        self.assertEqual(witness['callback_fragments'][0]['pairs'],[[9,9]])
        self.assertEqual(witness['iterations'],2)

    def test_retained_queue_expectation_refuses_borrowed_loop_paint(self):
        for mode in ('changed-range','control-escape','cold-successor','missing-send','foreign-owner'):
            with self.subTest(mode=mode):
                try:
                    _, receipts = self.compare(mode)
                except ValueError:
                    continue
                self.assertFalse(any(entry.get('kind')=='retained-test-queue-expectation' for entry in receipts))


class RetainedDirectUnitAssertionTests(unittest.TestCase):
    def compare(self, macro, fault=None):
        old_condition,new_condition = {
            'assert':('matches!(tx.try_send(req), Err(channel::SendError::Full(_)))',
                      'matches!(&overflow, channel::SendError::Full(_))'),
            'assert_eq':('normalize(Path::new("./demo")).unwrap()',
                         'normalize(Path::new("demo"), false).unwrap()'),
        }[macro]
        expected='"expected"'
        filename='/artifact/src/example.rs'
        files={filename:'src/example.rs'}
        sources=[]; counts=[]; documents=[]; inventories=[]
        for side,condition in enumerate((old_condition,new_condition)):
            if side and fault=='changed-anchor':
                condition=condition.replace('Full','Closed').replace('normalize','different')
            if side and fault=='changed-qualified-path':
                condition=condition.replace('channel::','elsewhere::')
            message='"wrong"' if side and fault=='changed-anchor' else expected
            source=['#[cfg(test)]','mod tests {','    #[test]','    fn checked() {',
                    f'        {macro}!(',f'            {condition},',f'            {message}','        );']
            if side and fault=='ambiguous-anchor':
                source.extend(source[4:8])
            source.extend(['    }','}'])
            sources.append(source)
            def region(line, text, count=1):
                col=source[line-1].index(text)+1
                return [line,col,line,col+len(text),count,0,0,0]
            regions=[region(4,'fn checked()'),region(5,macro+'!'),region(len(source)-1,'}')]
            if macro=='assert':
                regions.extend([region(6,'matches!',int(bool(side and fault=='changed-marker-state'))),
                                region(6,'overflow' if side else 'try_send')])
            else:
                regions.extend([region(6,condition.split('(')[0]),region(6,'unwrap')])
            if side and fault=='missing-opener':
                del regions[1]
            if side and fault=='cold-argument':
                regions[-1][4]=0
            root=dict(name=f'_RNvNtNtCs{side+1}_7omg_lib7example5tests7checked',
                      filenames=[filename],regions=regions,count=1,branches=[],mcdc_records=[])
            owners=[root]
            if side and fault=='foreign-owner':
                owners.append(dict(root,name='opaque',regions=[region(6,condition.split('(')[0])]))
            work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
            observer=coverage._ObserverWork(work)
            counts.append(dict(coverage._llvm22_rows(coverage._llvm22_segments(
                 [r for owner in owners for r in owner['regions']],observer),observer)))
            documents.append(owners)
            inventories.append(coverage._construct_inventory(source,work))
        return coverage.positive_source_fragments(
            'src/example.rs',*sources,*counts,*documents,files,files,[(4,5,4,5,[5])],
            construct_inventories=inventories,macro_expansions=([],[]))

    def test_assertion_entry_and_stable_operand_slots_are_bound(self):
        for macro,states in (('assert',(False,)),('assert_eq',(True,True))):
            with self.subTest(macro=macro):
                pairs,receipts=self.compare(macro)
                self.assertEqual(pairs,{5:5})
                proof,=[entry for entry in receipts if entry['kind']=='retained-direct-unit-assertion']
                self.assertEqual(proof['states'],states)
                self.assertEqual(proof['callback_fragments'][0]['pairs'],[[5,5]])

    def test_assertion_entry_refuses_lost_or_ambiguous_observations(self):
        for macro in ('assert','assert_eq'):
            faults=['changed-anchor','ambiguous-anchor','missing-opener','cold-argument','foreign-owner']
            if macro=='assert':
                faults.extend(('changed-marker-state','changed-qualified-path'))
            for fault in faults:
                with self.subTest(macro=macro,fault=fault):
                    try:
                        _,receipts=self.compare(macro,fault)
                    except ValueError:
                        continue
                    self.assertFalse(any(entry.get('kind')=='retained-direct-unit-assertion' for entry in receipts))



class AsyncTestExpectedVariantTests(unittest.TestCase):
    def compare(self, fault=None):
        files={'/src/example.rs':'src/example.rs'}
        sources=[]; documents=[]; counts=[]; inventories=[]
        for side in range(2):
            source=['#[cfg(test)]','mod tests {','    #[tokio::test]',
                    '    async fn verify() -> anyhow::Result<()> {',
                    '        let error = fixture().await',
                    '            .expect_err("owned fixture refused");',
                    '        assert!(matches!(',
                    '            error,' if side else '            error.downcast_ref::<Error>(),',
                    '            Error::TooLow {' if side else '            Some(Error::TooLow {',
                    '                grade: Grade::Community,',
                    '                ..',
                    '            }' if side else '            })',
                    '        ));','        Ok(())','    }','}']
            if side and fault=='changed-variant':
                source[8]=source[8].replace('TooLow','Forbidden')
            if side and fault=='changed-field':
                source[9]=source[9].replace('grade:','required:')
            if side and fault=='changed-value':
                source[7]=source[7].replace('error','different')
            if side and fault=='duplicate-label':
                source[13]='        Err(anyhow::anyhow!("owned fixture refused"))'
            opening=source[3].index('{')+1
            def region(line, text, count=1):
                col=source[line-1].index(text)+1
                return [line,col,line,col+len(text),count,0,0,0]
            root=dict(name=f'_RNvNtNtCs{side+1}_7omg_lib7example5tests6verify',
                      filenames=list(files),count=1,regions=[[4,11,4,opening-1,1,0,0,0],region(15,'}')])
            rows=[[4,opening,4,opening+1,1,0,0,0],region(6,'expect_err'),region(6,'"owned fixture refused"'),
                  region(7,'assert!'),region(7,'matches!',int(bool(side and fault=='changed-cold-marker'))),
                  region(8,'different' if side and fault=='changed-value' else 'error')]
            if not side:
                rows.append(region(8,'downcast_ref'))
            if side and fault=='missing-marker':
                del rows[4]
            if side and fault=='extra-pattern-paint':
                rows.append(region(10,'grade'))
            child=dict(root,name='_RNC'+root['name'][2:]+'0B7_',regions=rows)
            owners=[root,child]
            if side and fault=='foreign-owner':
                owners.append(dict(root,name='opaque',regions=[region(8,'error')]))
            work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
            observer=coverage._ObserverWork(work)
            counts.append(dict(coverage._llvm22_rows(coverage._llvm22_segments(
                 [r for owner in owners for r in owner['regions']],observer),observer)))
            inventories.append(coverage._construct_inventory(source,work))
            sources.append(source)
            documents.append(owners)
        return coverage.positive_source_fragments('src/example.rs',*sources,*counts,*documents,files,files,
            [(6,7,6,7,[7])],construct_inventories=inventories,macro_expansions=([],[]))

    def test_observes_opener_and_stable_cold_matches_marker(self):
        pairs,receipts=self.compare()
        self.assertEqual(pairs,{7:7})
        witnesses=[entry for entry in receipts if entry.get('kind')=='async-test-expected-variant-entry']
        self.assertEqual(len(witnesses),1)
        self.assertEqual([[row[4] for row in item['regions']] for item in witnesses[0]['owners']],
                         [[1,1,1,0,1,1],[1,1,1,0,1]])

    def test_refuses_rebound_or_incomplete_evidence(self):
        for fault in ('changed-variant','changed-field','changed-value','duplicate-label',
                      'changed-cold-marker','missing-marker','extra-pattern-paint','foreign-owner'):
            with self.subTest(fault=fault):
                try:
                    _,receipts=self.compare(fault)
                except ValueError:
                    continue
                self.assertFalse(any(entry.get('kind')=='async-test-expected-variant-entry' for entry in receipts))


class RetainedEnsureEntryTests(unittest.TestCase):
    def compare(self, *, local=False, fault=None, same_condition=False, terminal=False):
        name='src/package_managers/aur/client.rs' if local else 'src/example.rs'
        filename=f'/artifact/{name}'
        files={filename:name}
        sides=[]; indexes=[]
        work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        for side in range(2):
            source=['pub(crate) fn check(valid: bool) -> anyhow::Result<()> {']
            if local:
                source=['struct ReviewedSource;', 'impl ReviewedSource {',
                        '    fn capture(valid: bool) -> anyhow::Result<()> {',
                        '        fn visit(valid: bool) -> anyhow::Result<()> {',
                        '            if valid {']
            indentation='                ' if local else '    '
            condition='!valid' if side and not same_condition else 'valid'
            message='wrong fixture assertion' if side and fault=='changed-label' else 'owned fixture assertion'
            opener=len(source)+1
            conditions=[f'{condition},']
            slots=[condition]
            if terminal:
                bound='super::source_file::MAX_SOURCE_FILE_BYTES' if side else '16 * 1024 * 1024'
                limit='20_000' if side and fault=='changed-tail' else '10_000'
                operator='||' if side and fault=='different-guard' else '&&'
                slots=['metadata.is_file()',f'metadata.len() <= {bound}',f'files.len() < {limit}']
                conditions=[slots[0],f'    && {slots[1]}',f'    {operator} {slots[2]},']
            source.extend([f'{indentation}anyhow::ensure!(',*[f'{indentation}    {value}' for value in conditions],
                           f'{indentation}    "{message}: {{}}",',f'{indentation}    '+('new_display()' if side else 'old_display()'),
                           f'{indentation});'])
            if side and fault=='duplicate-label':
                source.append(f'{indentation}let _ = "{message}: {{}}";')
            if local:
                source.extend(['            }','            Ok(())','        }','        visit(valid)','    }','}'])
            else:
                source.extend(['    Ok(())','}'])
            first=4 if local else 1
            last=len(source)-3 if local else len(source)
            def row(line, text, count):
                col=source[line-1].index(text)+1
                return [line,col,line,col+len(text),count,0,0,0]
            owners=[]
            for copy in range(2):
                if side and fault=='missing-cold-copy' and copy==0:
                    continue
                counter=4 if copy else 0
                if side and fault=='moved-cold-state':
                    counter=2
                crate=f's{"cf"[side]}{copy}_'
                parent=None
                if local:
                    scope=('s0_' if side else 's_')
                    namespace=f'NtNtNtC{crate}7omg_lib16package_managers3aur6client'
                    parent=f'_RNvM{scope}{namespace}NtB{5 if side else 4}_14ReviewedSource7capture'
                    symbol=f'_RNvNvM{scope}{namespace}NtB{7 if side else 6}_14ReviewedSource7capture5visit'
                else:
                    symbol=f'_RNvNtC{crate}7omg_lib7example5check'
                if side and fault=='trailing-symbol' and copy:
                    symbol+='x'
                regions=[row(first,'fn',counter),row(last,'}',counter),
                         row(opener,'anyhow::ensure!',counter)]
                regions.extend(row(opener+offset,slot,0 if side and
                    (fault=='condition-cold' or fault=='terminal-cold' and offset==3) else counter)
                    for offset,slot in enumerate(slots,1))
                regions.append(row(opener+2+len(slots),'new_display' if side else 'old_display',counter))
                if side and fault=='missing-slot' and not copy:
                    del regions[2]
                owners.append(dict(name=symbol,filenames=[filename],count=counter,regions=regions))
                if parent and not (side and fault=='missing-parent' and copy):
                    owners.append(dict(name=parent,filenames=[filename],count=counter,
                        regions=[row(3,'fn',counter),row(len(source)-1,'}',counter)]))
            if side and fault=='foreign-owner':
                owners.append(dict(name='opaque',filenames=[filename],count=1,regions=[row(opener,'anyhow',1)]))
            counts=coverage._owner_line_counts({'regions':[r for owner in owners for r in owner['regions']]},
                                              coverage._ObserverWork(work))
            spans={id(owner):coverage.source_owner_span(owner,name,files,source) for owner in owners}
            sides.append((source,coverage._construct_inventory(source,work),spans,counts,opener))
            indexes.append(coverage.index_compiled_owner_sources(owners,files,work,{name}))
        return coverage.retained_ensure_entry(name,sides,indexes,work)

    def test_projects_exact_entry_in_plain_and_local_owners(self):
        for local in (False,True):
            with self.subTest(local=local):
                witness=self.compare(local=local)
                self.assertIsNotNone(witness)
                self.assertEqual(witness['instance_states'],[[False,True],[False,True]])
                self.assertEqual(len(witness['pairs']),1)
                self.assertEqual([len(side['parents']) for side in witness['observations']],[2 if local else 0]*2)

    def test_condition_projects_only_exact_source_and_complete_copy_counters(self):
        witness=self.compare(local=True,same_condition=True)
        self.assertEqual(witness['pairs'],[[6,6],[7,7]])
        self.assertEqual(witness['condition_pairs'],[[7,7]])
        for mode in ('changed-source','condition-cold'):
            with self.subTest(mode=mode):
                separate=self.compare(local=True,same_condition=mode!='changed-source',fault=mode)
                self.assertEqual(separate['pairs'],[[6,6]])
                self.assertEqual(separate['condition_pairs'],[])

    def test_terminal_guard_keeps_its_complete_copy_and_counter_obligations(self):
        witness=self.compare(local=True,terminal=True)
        self.assertEqual(witness['condition_pairs'],[[7,7],[9,9]])
        for fault in ('terminal-cold','changed-tail','different-guard'):
            with self.subTest(fault=fault):
                separate=self.compare(local=True,terminal=True,fault=fault)
                self.assertNotIn([9,9],separate['condition_pairs'])

    def test_rejects_foreign_or_incomplete_copy_and_source_evidence(self):
        for local in (False,True):
            faults=['changed-label','duplicate-label','missing-cold-copy','moved-cold-state',
                    'trailing-symbol','missing-slot','foreign-owner']
            if local:
                faults.append('missing-parent')
            for fault in faults:
                with self.subTest(local=local,fault=fault):
                    self.assertIsNone(self.compare(local=local,fault=fault))


class RetainedAlpmRegistrationTests(unittest.TestCase):
    def compare(self, fault=None):
        sides=[]; inventories=[]; all_names=[]; groups=[]
        filename='/artifact/src/package_managers/alpm_ops.rs'
        for side in range(2):
            original='setup_alpm_callbacks'
            declaration=original+'_in' if side else original
            parameters='alpm: &alpm::Alpm, refusals: &Refusals,'
            source=[]
            if side:
                forwarding='Omarchy' if fault=='wrong-forwarder' else 'Standard'
                source=['#[cfg(test)]',f'fn {original}({parameters}) -> ProgressTask {{',
                        f'    {declaration}(alpm, refusals, TransactionPolicy::{forwarding})','}']
            start=len(source)+1
            header=parameters+(' policy: TransactionPolicy,' if side else '')
            callback=('(Arc::clone(refusals), policy), |question, (refusals, policy)| {'
                      if side else 'Arc::clone(refusals), |question, refusals| {')
            source.extend([f'fn {declaration}({header}) -> ProgressTask {{',
                f'    alpm.set_question_cb({callback}',
                '        match question.question() {',
                '            alpm::Question::Replace(q) => {',
                '                let auto_accept = allowed();',
                '                let confirmed = if auto_accept {',
                '                    false' if side and fault=='different-branch' else '                    true',
                '                } else { false };', '            }',
                '            alpm::Question::RemovePkgs(q) => {',
                '                q.packages().iter().map(|package| package.name().to_string());',
                '            }',
                '            alpm::Question::SelectProvider(q) => {',
                '                q.providers().iter().map(|package| package.name().to_string());',
                '            }','        }','    });','    task','}'])
            end=len(source); first=start+5; last=first+1
            def slot(line,text,hits):
                col=source[line-1].index(text)+1
                return [line,col,line,col+len(text),hits,0,0,0]
            rows=[]; roots=[]
            for copy in range(2):
                count=1
                hits=1 if copy else 0
                mangled=(f'NvNtNtCs{side+1}{copy+1}_7omg_lib16package_managers8alpm_ops'
                         f'{len(declaration)}{declaration}')
                root_rows=[slot(start,'fn',count),slot(start+1,'alpm',count),
                           slot(start+1,'set_question_cb',count),slot(end,'}',count)]
                if side and fault=='missing-registration' and copy:
                    del root_rows[2]
                root=dict(name='_R'+mangled,filenames=[filename],regions=root_rows,count=count)
                roots.append(root); rows.append(root)
                condition='false' if side and fault=='different-branch' else 'true'
                condition_hits=0 if side and fault=='lost-accepted-branch' else hits
                child_rows=[slot(start+1,'{',hits),slot(first,'confirmed',hits),
                            slot(first,'auto_accept',hits),slot(last,condition,condition_hits),
                            slot(end-2,'}',hits)]
                rows.append(dict(root,name='_RNC'+mangled+'0B7_',regions=child_rows,count=hits))
                for offset,role in ((10,'00B9_'),(13,'0s_0B9_')):
                    if side and fault=='missing-descendant' and offset==10 and copy:
                        continue
                    leaves=[slot(start+offset,'package.name()',hits),slot(start+offset,'to_string',hits)]
                    if side and fault=='wrong-descendant-layout' and offset==10 and copy:
                        leaves[0][3]-=1
                    rows.append(dict(root,name='_RNCNC'+mangled+role,regions=leaves,count=hits))
            if side and fault=='foreign':
                rows.append(dict(roots[0],name='opaque',regions=[slot(last,'true',1)]))
            work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
            counts=coverage._owner_line_counts({'regions':[r for owner in rows for r in owner['regions']]},
                                              coverage._ObserverWork(work))
            sides.append((source,coverage._construct_inventory(source,work),counts,first,last))
            inventories.append(rows); all_names.append(Counter(r['name'] for r in rows))
            groups.append({declaration:(start,end,roots)})
        return coverage.retained_alpm_replace_branch(sides,inventories,all_names,groups,work)

    def test_scopes_each_replace_branch_to_its_exact_registration_copy(self):
        scopes,owners,states=self.compare()
        self.assertEqual(states,[[(False,False,False),(True,True,True)]]*2)
        self.assertEqual([[len(row['descendants']) for row in side] for side in owners],[[2,2],[2,2]])

    def test_refuses_changed_registration_or_missing_branch_execution(self):
        for fault in ('wrong-forwarder','different-branch','lost-accepted-branch','missing-registration',
                      'missing-descendant','wrong-descendant-layout','foreign'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.compare(fault))


class ColdArchSnapshotReaderTests(unittest.TestCase):
    def observe(self, fault=None):
        filename = 'src/core/security/vulnerability.rs'
        files = {'/artifact/' + filename: filename}
        declaration = '    pub async fn fetch_alsa_issues(&self) -> Result<Vec<AlsaIssue>, VulnerabilityError> {'
        sources = [
            ['        let response = self.client.get(ARCH_UPSTREAM_URL).send().await?;',
             '        Ok(response.json().await?)'],
            ['        let snapshot = self.arch_snapshot(AssessmentUse::Admission).await?;',
             '        Ok(snapshot.issues.clone())'],
        ]
        if fault == 'changed-wrapper':
            sources[1][0] = sources[1][0].replace('Admission', 'Review')
        work = [coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        sides = []
        indexes = []
        for side, body in enumerate(sources):
            source = ['impl VulnerabilityScanner {', declaration, *body, '    }', '}']
            owners = []
            futures = []
            def add(symbol, hits, geometry):
                owner = dict(name=symbol, count=hits, filenames=list(files),
                             regions=[[*position,hits,0,0,0] for position in geometry])
                owners.append(owner)
                return owner
            for crate, hits in (('saJq9CMLDmry_',0),('s40j12eeWnis_',int(
                    fault=='hot-baseline' if not side else fault!='cold-replacement'))):
                scope = 's2_' if side else 's_'
                namespace = f'M{scope}NtNtNtC{crate}7omg_lib4core8security13vulnerability'
                method = '_20VulnerabilityScanner17fetch_alsa_issues'
                add(f'_RNv{namespace}NtB{5 if side else 4}{method}',hits,
                    [(2,5,2,len(declaration)+1)])
                future_name = f'_RNCNv{namespace}NtB{7 if side else 6}{method}0'
                futures.append(add(future_name+('Bd_' if side else 'Bc_'),hits,[(2,5,5,6)]))
                if side and not hits and crate=='saJq9CMLDmry_':
                    futures.append(add(future_name+'CsiKC45NoN8w3_22real_world_integration',0,[(2,5,5,6)]))
                if not side:
                    nested = f'_RNCNCNv{namespace}NtB8{method}0'
                    suffixes = ('0Be_','s0_0Be_','s1_0Be_','s_0Be_')
                    if fault=='missing-cold-child':
                        suffixes=suffixes[:-1]
                    for suffix in suffixes:
                        add(nested+suffix,0,[(3,9,3,18)])
            observer = coverage._ObserverWork()
            raw = [region for owner in owners for region in owner['regions']]
            counts = dict(coverage._llvm22_rows(coverage._llvm22_segments(raw,observer),observer))
            spans = {id(owner):coverage.source_owner_span(owner,filename,files,source) for owner in futures}
            sides.append((source,spans,counts,futures))
            indexes.append(coverage.index_compiled_owner_sources(owners,files,work,{filename}))
        return coverage.replaced_cold_arch_snapshot_reader(filename,declaration,sides,indexes,work)

    def test_changed_arch_reader_admits_only_a_complete_cold_baseline(self):
        proof = self.observe()
        self.assertEqual(proof['summary_credit'], [0,0])
        self.assertEqual(proof['mapped_credit'], [0,0])
        self.assertEqual(proof['preserved_base_mapped'], [2,3,4,5])
        for fault in ('hot-baseline','missing-cold-child','cold-replacement','changed-wrapper'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(fault))


class RetainedSourceEntryTests(unittest.TestCase):
    def observe(self, name, variants, source_observer, *, fault=None):
        sides=[]; indexes=[]
        work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        files={'/artifact/'+name:name}
        for side,(source,line,markers,hit_counts,root_counts,scope) in enumerate(variants):
            owners=[]
            for copy,(hits,count) in enumerate(zip(hit_counts,root_counts)):
                if side and fault=='missing-copy' and not copy:
                    continue
                depth = name.removeprefix('src/').count('/') + 1
                prefix = f'_RNv{"Nt" * depth}Cs{side+1}{copy+1}_7omg_lib'
                symbol=prefix+scope
                def region(number,text,value,end_number=None,end_text=None):
                    col=source[number-1].rindex(text)+1
                    if end_number is None:
                        end_number, end_column = number, col + len(text)
                    else:
                        end_column = source[end_number - 1].index(end_text) + len(end_text) + 1
                    return [number,col,end_number,end_column,value,0,0,0]
                raw=[region(1,'fn',count),region(len(source),'}',count)]
                raw.extend(region(*marker[:2], hits, *marker[2:]) for marker in markers)
                if side and fault=='missing-slot' and copy:
                    raw.pop()
                if side and fault=='prefix-lost' and copy:
                    raw[3][4]=0
                owner=dict(name=symbol,filenames=list(files),regions=raw,count=count)
                owners.append(owner)
            if side and fault=='foreign':
                owners.append(dict(owners[0],name='opaque',regions=[owners[0]['regions'][2]]))
            counts=coverage._owner_line_counts({'regions':[r for item in owners for r in item['regions']]},
                                              coverage._ObserverWork(work))
            spans={id(item):coverage.source_owner_span(item,name,files,source) for item in owners}
            sides.append((source,coverage._construct_inventory(source,work),spans,counts,line))
            indexes.append(coverage.index_compiled_owner_sources(owners,files,work,{name}))
        return coverage.retained_observed_entry(name,sides,indexes,work,source_observer)

    def map_entry(self, fault=None):
        variants=[]
        for side in range(2):
            result='Result<Vec<UpdateInfo>>' if side else 'Vec<UpdateInfo>'
            value='alpm::Package' if side else 'str'
            if side and fault=='changed-map-type':
                value='Other'
            count_method='count' if side and fault=='changed-precondition' else 'len'
            source=[f'pub(crate) fn collect_updates(alpm: &alpm::Alpm) -> {result} {{',
                    '    let localdb = alpm.localdb();','    let syncdbs = alpm.syncdbs();',
                    f'    let local_pkg_count = localdb.pkgs().{count_method}();',
                    f'    let mut sync_map: ahash::AHashMap<&str, (&{value}, &str)> =',
                    '        ahash::AHashMap::with_capacity(local_pkg_count);',
                    '    finish(sync_map)','}']
            hits=(6,7) if side else (0,4)
            if side and fault=='lost-hit':
                hits=(0,0)
            variants.append((source,6,[(6,'ahash::AHashMap::with_capacity'),(6,'local_pkg_count')],
                             hits,hits,'16package_managers8alpm_ops15collect_updates'))
        return self.observe('src/package_managers/alpm_ops.rs',variants,coverage.map_capacity_entry_source,fault=fault)

    def alpm_record_entry(self, fault=None):
        variants = []
        for side in range(2):
            result = 'Result<Vec<UpdateInfo>>' if side else 'Vec<UpdateInfo>'
            binding = 'sync_pkg' if side else 'sync_ver_str'
            compare_version = 'sync_pkg.version().as_str()' if side else binding
            guard = ' && !sync_pkg.should_ignore()' if side and fault != 'ignored-package-guard' else ''
            new_version = 'sync_pkg.version()' if side else binding
            receiver = 'other' if side and fault == 'changed-record-receiver' else 'updates'
            source = [
                f'pub(crate) fn collect_updates(alpm: &alpm::Alpm) -> {result} {{',
                '    for pkg in localdb.pkgs() {',
                *(['        if pkg.should_ignore() { continue; }']
                  if side and fault != 'ignored-installed-guard' else []),
                '        let name = pkg.name();',
                '        let local_ver_str = pkg.version().as_str();',
                f'        if let Some(&({binding}, repo)) = sync_map.get(name){guard}',
                f'            && alpm::vercmp({compare_version}, local_ver_str) == std::cmp::Ordering::Greater',
                '        {',
                f'            {receiver}.push(UpdateInfo {{',
                '                name: name.to_string(),',
                '                old_version: local_ver_str.to_string(),',
                f'                new_version: {new_version}.to_string(),',
                '                repo: repo.to_string(),',
                '            });',
                '        }',
                '    }',
                '    Ok(updates)' if side else '    updates',
                '}',
            ]
            line = next(index for index, row in enumerate(source, 1) if 'push(UpdateInfo' in row)
            markers = [
                (line - 1, '{', line + 6, '}'), (line, receiver), (line, 'push'),
                (line + 1, 'name'), (line + 1, 'to_string'),
                (line + 2, 'local_ver_str'), (line + 2, 'to_string'),
                (line + 3, new_version), (line + 3, 'to_string'),
                (line + 6, '}'),
            ]
            hits = (9, 72) if side and fault != 'lost-hit' else (0, 0 if side else 4)
            root_counts = (14, 28) if side else (0, 4)
            variants.append((source, line, markers, hits, root_counts, '16package_managers8alpm_ops15collect_updates'))
        return self.observe('src/package_managers/alpm_ops.rs', variants, coverage.alpm_update_record_entry_source,
                            fault=fault)

    def test_alpm_update_requires_the_guarded_branch_and_bound_record_entry(self):
        proof = self.alpm_record_entry()
        self.assertEqual(proof['pairs'], [[8, 9], [9, 10], [10, 11], [12, 13], [13, 14], [14, 15]])
        self.assertEqual(proof['instance_states'], [[False, True], [True, True]])
        for fault in ('ignored-package-guard', 'ignored-installed-guard', 'changed-record-receiver',
                      'lost-hit', 'missing-copy', 'missing-slot', 'foreign'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.alpm_record_entry(fault))

    def repeated_ensure(self,fault=None):
        variants=[]
        for side in range(2):
            sibling='1' if side and fault=='same-control-role' else '0'
            source=['fn checked() -> anyhow::Result<()> {']
            repeated=not (side and fault=='outside-loop')
            source.append('    for value in [0, 1] {' if repeated else '    let value = 1;')
            source.extend([f'        if value == {sibling} {{',
                           '            anyhow::ensure!(',
                           '                true,',
                           '                "same diagnostic"',
                           '            );',
                           '        }',
                           '        if value == 1 {',
                           '            anyhow::ensure!(',
                           '                true,',
                           '                "same diagnostic"',
                           '            );',
                           '        }'])
            if repeated:
                source.append('    }')
            source.extend(['    Ok(())','}'])
            hits=(0,3) if side else (0,2)
            if side and fault=='cold-entry-count':
                hits=(3,3)
            variants.append((source,10,[(10,'anyhow::ensure!'),(11,'true')],hits,(0,1),'7example7checked'))
        return self.observe('src/example.rs',variants,coverage.ensure_entry_source,fault=fault)

    def leading_ensure(self, fault=None):
        variants=[]
        for side in range(2):
            receiver='other' if side and fault=='changed-receiver' else 'path'
            operand=f'{receiver}.is_file()'
            operator='||' if side and fault=='not-conjunction' else '&&'
            suffix='new_limit()' if side else 'old_limit()'
            source=['fn checked() -> anyhow::Result<()> {',
                    '    anyhow::ensure!(',f'        {operand}',f'            {operator} {suffix},',
                    '        "same diagnostic"','    );','    Ok(())','}']
            markers=[(2,'anyhow::ensure!'),(3,operand),(4,suffix)]
            if side and fault=='foreign-prefix-paint':
                markers.append((3,'    '))
            variants.append((source,2,markers,(0,1),(0,1),'7example7checked'))
        return self.observe('src/example.rs',variants,coverage.ensure_entry_source,fault=fault)

    def test_changed_tail_leaves_only_the_exact_first_conjunct(self):
        proof=self.leading_ensure()
        self.assertEqual(proof['pairs'],[[2,2],[3,3]])
        self.assertEqual(proof['condition_pairs'],[[3,3]])
        for fault in ('changed-receiver','not-conjunction','foreign-prefix-paint','prefix-lost'):
            with self.subTest(fault=fault):
                proof=self.leading_ensure(fault)
                self.assertEqual(proof['pairs'],[[2,2]])
                self.assertEqual(proof['condition_pairs'],[])

    def test_super_visible_duplicate_identity_guard_preserves_its_entry(self):
        variants = []
        for key in ('key', 'key.clone()'):
            condition = f'identities.insert({key}, reference.clone()).is_none()'
            source = [
                'pub(super) fn compose(installed: &[Package]) -> anyhow::Result<()> {',
                '    for package in installed {',
                '        anyhow::ensure!(',
                f'            {condition},',
                '            "Duplicate installed SBOM identity"',
                '        );',
                '    }',
                '    Ok(())',
                '}',
            ]
            variants.append((source,3,[(3,'anyhow::ensure!'),(4,condition)],
                             (0,2),(0,1),'4core8security11sbom_shared7compose'))
        def observe(fault=None):
            return self.observe('src/core/security/sbom_shared.rs',variants,
                                coverage.ensure_entry_source,fault=fault)
        self.assertEqual(observe()['pairs'], [[3, 3]])
        self.assertIsNone(observe('missing-copy'))
        self.assertIsNone(observe('foreign'))


    def test_map_initializer_tracks_both_copies_when_a_cold_copy_executes(self):
        proof=self.map_entry()
        self.assertEqual(proof['pairs'],[[6,6]])
        self.assertEqual(proof['instance_states'],[[False,True],[True,True]])
        self.assertEqual([[copy['entry_count'] for copy in side['owners']] for side in proof['observations']],
                         [[0,4],[6,7]])
        for fault in ('lost-hit','missing-copy','missing-slot','foreign','changed-map-type','changed-precondition'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.map_entry(fault))

    def test_duplicate_labels_and_repeated_hits_require_distinct_loop_control(self):
        proof=self.repeated_ensure()
        self.assertEqual(proof['pairs'],[[10,10],[11,11]])
        self.assertEqual(proof['instance_states'],[[False,True],[False,True]])
        for fault in ('same-control-role','outside-loop','cold-entry-count'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.repeated_ensure(fault))


class AsyncPolicyUnavailableAssertionTests(unittest.TestCase):
    def observe(self, typed, fault=None):
        lines=['#[cfg(test)]','mod tests {','    #[tokio::test]',
               '    async fn checked() -> anyhow::Result<()> {']
        if typed:
            mode='FreshSnapshot' if fault=='changed-policy' else 'Review'
            lines.extend(['        let service = update_service(',
                '            SecurityPolicy {',
                f'                advisory_requirement: AdvisoryRequirement::{mode},',
                '                ..policy','            },',
                '            std::sync::Arc::new(FailingVulns),','        )',
                '        .expect("construct the fake package-service fixture");',
                '        let error = service','            .update()','            .await',
                '            .expect_err("review must preserve unavailable evidence");'])
        assertion=len(lines)+1
        lines.append('        assert!(')
        if typed:
            reason='different' if fault=='changed-reason' else 'osv unavailable'
            lines.append('            matches!(error.downcast_ref::<VulnerabilityError>(), '
                         f'Some(VulnerabilityError::Unavailable {{ reason }}) if reason == "{reason}")')
        else:
            lines.extend(['            check_prepared_with_source(&policy, package(false), &FailingVulns)',
                          '                .await','                .is_err()'])
        lines.extend(['        );','        Ok(())','    }','}'])
        first,end=4,len(lines)-1
        def marker(line,text,count=1):
            col=lines[line-1].index(text)+1
            return [line,col,line,col+len(text),count,0,0,0]
        opening=lines[3].index('{')+1
        filename='/artifact/src/example.rs'
        root_symbol='_RNvNtNtCs1_7omg_lib7example5tests7checked'
        root=dict(name=root_symbol,filenames=[filename],count=1,
                  regions=[[4,11,4,opening-1,1,0,0,0],marker(end-1,'Ok(())'),marker(end,'}')])
        raw=[marker(4,'{'),marker(assertion,'assert!'),marker(end-1,'Ok(())')]
        if typed:
            raw.extend([marker(10,'std::sync::Arc::new(FailingVulns)'),
                        [13,21,15,19,1,0,0,0],marker(16,'expect_err'),marker(assertion+1,'downcast_ref')])
        else:
            raw.extend([marker(assertion+1,'check_prepared_with_source'),
                        marker(assertion+1,'&FailingVulns'),marker(assertion+2,'await'),
                        marker(assertion+3,'is_err')])
        if fault=='missing-await':
            del raw[4]
        if fault=='missing-tail':
            del root['regions'][1]
        owners=[root,dict(root,name='_RNC'+root_symbol[2:]+'0B7_',regions=raw)]
        if fault=='foreign':
            owners.append(dict(root,name='opaque',regions=[marker(assertion,'assert!')]))
        work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        counts=coverage._owner_line_counts({'regions':[r for item in owners for r in item['regions']]},
                                          coverage._ObserverWork(work))
        inventory=coverage._construct_inventory(lines,work)
        return coverage.async_policy_unavailable_assertion('src/example.rs',lines,counts,(first,end,[root]),
            owners,Counter(item['name'] for item in owners),inventory,assertion,assertion,work)

    def test_requires_executed_terminal_assertion_and_exact_typed_driver(self):
        old, head=[self.observe(typed) for typed in (False,True)]
        self.assertEqual(old[0],head[0])
        self.assertEqual([item[1]['typed'] for item in (old,head)],[False,True])
        self.assertEqual([item[1]['entry'][1] for item in (old,head)],[9,9])
        for fault in ('changed-policy','changed-reason','missing-await','missing-tail','foreign'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(True,fault))


class PreparedPolicyEnvironmentEntryTests(unittest.TestCase):
    def observe(self, modern, fault=None, *, file_checks=False):
        lines=['#[cfg(test)]','mod tests {','    #[cfg(debug_assertions)]','    #[test]',
               '    fn checked() -> anyhow::Result<()> {','        let directory = tempfile::tempdir()?;']
        if modern:
            lines.append('        let data_dir = directory.path().join("data");')
        call=len(lines)+1
        config='OMG_CACHE_DIR' if fault=='changed-config' else 'OMG_CONFIG_DIR'
        lines.extend(['        temp_env::with_vars(','            [',
                      f'                ("{config}", Some(directory.path().as_os_str())),',
                      '                ("OMG_TEST_MODE", Some(std::ffi::OsStr::new("1"))),',
                      '                ("OMG_DATA_DIR", Some(data_dir.as_os_str())),' if modern else
                      '                ("OMG_TEST_DISTRO", Some(std::ffi::OsStr::new("fedora"))),',
                      '            ],','            || -> anyhow::Result<()> {'])
        opening=len(lines)
        if modern:
            field='other_field' if fault=='lost-legacy-control' else 'advisory_requirement'
            lines.extend([f'                policy.remove("{field}");',
                          '                assert_eq!(loaded.advisory_requirement, AdvisoryRequirement::Review);'])
        else:
            lines.append('                let package = || { 1 };')
        if file_checks:
            path_line=len(lines)+1
            name='other.toml' if fault=='changed-path' else 'policy.toml'
            content='legacy' if modern else 'SecurityPolicy::default()'
            lines.extend([f'                let path = directory.path().join("{name}");',
                          f'                let bytes = toml::to_string(&{content})?;',
                          '                fs::write(&path, &bytes)?;'])
            driver='runtime.block_on(service.update())' if modern else 'check_prepared_packages(package())'
            legacy='legacy ' if modern else ''
            reason=('osv unavailable' if modern else
                    'OSV has no configured ecosystem for the running package backend')
            if fault=='changed-error':
                reason='different source'
            lines.extend([f'                let error = {driver}.expect_err("explicit policy requires available '
                          f'advisory evidence even when all {legacy}fields have their default values");',
                          '                assert!(',
                          '                    matches!(error.downcast_ref::<VulnerabilityError>(), '
                          f'Some(VulnerabilityError::Unavailable {{ reason }}) if reason == "{reason}")',
                          '                );'])
        lines.extend(['                assert_eq!(fs::read_to_string(&path)?, bytes);',
                      '                Ok(())','            },','        )','    }','}'])
        closing=len(lines)-3
        def row(line,text,count=1):
            col=lines[line-1].index(text)+1
            return [line,col,line,col+len(text),count,0,0,0]
        symbol='_RNvNtNtCs1_7omg_lib7example5tests7checked'
        root=dict(name=symbol,filenames=['/artifact/src/example.rs'],count=2,
                  regions=[row(5,'fn checked()',2),row(6,'directory'),row(call,'temp_env::with_vars'),
                           [call+1,13,opening-1,14,1,0,0,0],row(len(lines)-1,'}',2)])
        if fault!='missing-config-region':
            root['regions'].append(row(call+2,lines[call+1].strip().removesuffix(',')))
        if fault!='missing-test-mode-region':
            root['regions'].append(row(call+3,'"OMG_TEST_MODE"',int(fault!='cold-test-mode')))
        child=dict(root,name='_RNC'+symbol[2:]+'0B7_',count=1,
                   regions=[row(opening,'{',0 if fault=='cold-opener' else 1),row(closing,'}')])
        if file_checks:
            write,assertion,readback=path_line+2,path_line+4,closing-2
            check=assertion+1
            binding=row(check,'reason')
            guard=lines[check-1].index('reason',binding[1]+len('reason')-1)+1
            child['regions'].extend([
                row(path_line,'path'),row(path_line,'directory.path()'),row(path_line,'join'),
                row(write,'fs::write'),row(write,'&path'),row(write,'&bytes'),
                row(write,'?',int(fault=='unexpected-write-early-exit')),
                row(assertion,'assert!'),row(check,'matches!'),row(check,'downcast_ref'),binding,
                [check,guard,check,guard+len('reason'),1,0,0,0],
                row(readback,'assert_eq!'),row(readback,'fs::read_to_string'),row(readback,'&path'),
                row(closing-1,'Ok(())')])
            if fault!='missing-cold-readback':
                child['regions'].append(row(readback,'?',0))
            child['regions'].sort()
        owners=[root,child]
        if not modern and fault!='missing-factory':
            owners.append(dict(root,name='_RNCNC'+symbol[2:]+'00B9_',count=1,
                               regions=[row(opening+1,'{ 1 }')]))
        if fault=='foreign':
            owners.append(dict(root,name='opaque',regions=[row(opening,'{')]))
        work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        counts=coverage._owner_line_counts({'regions':[r for item in owners for r in item['regions']]},
                                          coverage._ObserverWork(work))
        inventory=coverage._construct_inventory(lines,work)
        return coverage.prepared_policy_environment_entry('src/example.rs',lines,counts,(5,len(lines)-1,[root]),
            owners,Counter(item['name'] for item in owners),inventory,opening,work)

    def test_single_config_entry_binds_the_call_argument_and_callback(self):
        def observe(operation, fault=None):
            key = 'OMG_CACHE_DIR' if fault == 'wrong-key' else 'OMG_CONFIG_DIR'
            capture = 'other' if fault == 'wrong-capture' else 'directory'
            lines = ['#[cfg(test)]', 'mod tests {', '    #[test]',
                     '    fn checked() -> anyhow::Result<()> {',
                     '        let directory = tempfile::tempdir()?;',
                     '        temp_env::with_var(', f'            "{key}",',
                     f'            Some({capture}.path()),',
                     '            || -> anyhow::Result<()> {', f'                {operation}()?;',
                     '                Ok(())', '            },', '        )', '    }', '}']
            def slot(line, value, count=1):
                start = lines[line-1].index(value)+1
                return [line,start,line,start+len(value),count,0,0,0]
            symbol = '_RNvNtNtCs1_7omg_lib7example5tests7checked'
            argument = slot(8, f'Some({capture}.path())', int(fault != 'cold-argument'))
            root = dict(name=symbol, count=2, filenames=['/artifact/src/example.rs'], regions=[
                slot(4, 'fn checked() -> anyhow::Result<()>', 2), slot(5, 'directory'),
                slot(6, 'temp_env::with_var'), argument, slot(14, '}', 2)])
            child = dict(root, name='_RNC'+symbol[2:]+'0B7_', count=1, regions=[
                slot(9, '{', int(fault != 'cold-opener')), slot(10, operation), slot(12, '}')])
            owners = [root, child]
            if fault == 'foreign':
                owners.append(dict(root, name='opaque', regions=[slot(8, 'Some', 0)]))
            if fault == 'literal-paint':
                root['regions'].append(slot(7, f'"{key}"'))
            work = [coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
            counts = coverage._owner_line_counts({'regions': [r for owner in owners for r in owner['regions']]},
                                                  coverage._ObserverWork(work))
            return coverage.prepared_policy_environment_entry('src/example.rs', lines, counts, (4,14,[root]),
                owners, Counter(owner['name'] for owner in owners), coverage._construct_inventory(lines, work),
                6, work)

        before, after = observe('old_policy_check'), observe('new_policy_check')
        self.assertIsNotNone(before)
        self.assertEqual(before[0], after[0])
        self.assertEqual(after[1]['observed_lines'], [6,8,9,12])
        for fault in ('wrong-key', 'wrong-capture', 'cold-argument', 'cold-opener', 'foreign', 'literal-paint'):
            with self.subTest(fault=fault):
                self.assertIsNone(observe('new_policy_check', fault))

    def test_distinct_environment_arguments_preserve_only_the_direct_closure_entry(self):
        old,head=[self.observe(modern) for modern in (False,True)]
        self.assertEqual(old[0],head[0])
        self.assertEqual([old[1]['modern'],head[1]['modern']],[False,True])
        self.assertEqual([len(old[1]['nested']),len(head[1]['nested'])],[1,0])
        for modern,fault in ((True,'changed-config'),(True,'lost-legacy-control'),
                             (True,'cold-opener'),(True,'foreign'),(False,'missing-factory')):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(modern,fault))

    def test_multi_config_callback_preserves_executed_shared_inputs(self):
        old,new=[self.observe(modern)[1]['environment_entries'] for modern in (False,True)]
        self.assertEqual(set(old),{'call','config-directory','test-mode'})
        self.assertEqual(set(new),set(old))
        for fault,role in (('missing-config-region','config-directory'),('missing-test-mode-region','test-mode'),
                           ('cold-test-mode','test-mode')):
            with self.subTest(fault=fault):
                self.assertNotIn(role,self.observe(True,fault)[1]['environment_entries'])

    def test_file_checks_preserve_typed_assertion_and_cold_file_error_slots(self):
        for modern in (False,True):
            with self.subTest(modern=modern):
                proof=self.observe(modern,file_checks=True)
                self.assertEqual([item['role'] for item in proof[1]['file_steps']],
                                 ['path','write','typed-error','readback','return','close'])
        for fault in ('changed-path','changed-error','unexpected-write-early-exit','missing-cold-readback'):
            with self.subTest(fault=fault):
                proof=self.observe(True,fault,file_checks=True)
                self.assertIsNotNone(proof)
                self.assertIsNone(proof[1]['file_steps'])


class RetainedPolicyDefaultRecordTests(unittest.TestCase):
    def compare(self,fault=None):
        name='src/core/security/policy.rs'
        filename='/artifact/'+name
        files={filename:name}
        sides=[]; indexes=[]
        work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        for side in range(2):
            source=['impl Default for SecurityPolicy {','    fn default() -> Self {','        Self {',
                    '            minimum_grade: SecurityGrade::Community,','            allow_aur: true,',
                    '            require_pgp: false,','            allowed_licenses: Vec::new(),',
                    '            banned_packages: Vec::new(),']
            if side and fault=='changed-field':
                source[4]='            allow_aur: false,'
            if side:
                source.extend(['            advisory_requirement: AdvisoryRequirement::Optional,',
                               '            arch_advisory_repositories: BTreeSet::new(),'])
            source.extend(['        }','    }','}'])
            last=len(source)-1
            def row(line,text,count):
                col=source[line-1].index(text)+1
                return [line,col,line,col+len(text),count,0,0,0]
            owners=[]
            for copy in range(2):
                if side and fault=='missing-cold-copy' and not copy:
                    continue
                count=copy
                symbol=(f'_RNvXs_NtNtNtCs{side+1}{copy+1}_7omg_lib4core8security6policy'
                        'NtB4_14SecurityPolicyNtNtCs4_4core7default7Default7default')
                if side and fault=='wrong-trait' and copy:
                    symbol=symbol.replace('7default7Default','7unknown7Default')
                raw=[row(2,'fn default() -> Self',count),[3,9,last-1,10,count,0,0,0],
                     row(last,'}',count)]
                if not side or fault!='lost-refinement':
                    raw.append(row(4,'SecurityGrade::Community',count))
                if side:
                    raw.extend([row(7,'Vec::new',count),row(8,'Vec::new',count)])
                owners.append(dict(name=symbol,count=count,filenames=[filename],regions=raw))
            if side and fault=='foreign':
                owners.append(dict(owners[0],name='opaque',regions=[row(5,'true',1)]))
            counts=coverage._owner_line_counts({'regions':[r for item in owners for r in item['regions']]},
                                              coverage._ObserverWork(work))
            if side and fault=='uncovered-new-field':
                counts[9]=0
            spans={id(item):coverage.source_owner_span(item,name,files,source) for item in owners}
            sides.append((source,coverage._construct_inventory(source,work),spans,counts,4))
            indexes.append(coverage.index_compiled_owner_sources(owners,files,work,{name}))
        return coverage.retained_policy_default_record(name,sides,indexes,work)

    def test_retains_record_fields_and_observes_head_only_fields_across_both_copies(self):
        proof=self.compare()
        self.assertEqual(proof['instance_states'],[[False,True],[False,True]])
        self.assertEqual(proof['direct_field_indices'],[(0,),(0,3,4)])
        self.assertEqual(proof['added_lines'],[9,10])
        self.assertTrue(set(proof['added_lines']).isdisjoint(target for _,target in proof['pairs']))
        for fault in ('missing-cold-copy','wrong-trait','changed-field','lost-refinement',
                      'foreign','uncovered-new-field'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.compare(fault))


class OsvRequestMigrationTests(unittest.TestCase):
    def test_complete_osv_fixture_keeps_the_nested_future_and_every_counter(self):
        name = 'src/core/security/vulnerability.rs'
        test = 'incomplete_osv_pages_fail_without_caching_partial_findings'
        symbol = f'_RNvNtNtNtNtCs1_7omg_lib4core8security13vulnerability5tests{len(test)}{test}'

        def side(method, missing_future=False, cold=False, endpoint='"Debian:12"'):
            source = ['#[cfg(test)]','mod tests {','    #[tokio::test]',
                      f'    async fn {test}() -> anyhow::Result<()> {{',
                      f'        let scanner = VulnerabilityScanner::with_osv_endpoint(endpoint, {endpoint}.into());',
                      '        let fixture = tokio::spawn(async move {', '            Ok(())', '        });',
                      f'        scanner.{method}(&name, &version).await?;', '        Ok(())','    }','}']
            path = '/artifact/'+name
            root = dict(name=symbol,filenames=[path],count=1,regions=[[4,11,4,len(source[3])-1,1,0,0,0],
                                                                    [5,9,10,15,1,0,0,0]])
            body_name = '_RNC'+symbol[2:]+'0Bb_'
            method_first = source[8].index(method)+1
            body = dict(name=body_name,filenames=[path],count=1,regions=[
                [4,len(source[3]),4,len(source[3])+1,1,0,0,0], [9,method_first,9,method_first+len(method),1,0,0,0],
                [9,len(source[8])-1,9,len(source[8]),int(cold),0,0,0], [11,5,11,6,1,0,0,0]])
            nested = dict(name='_RNCNC'+symbol[2:]+'00Bd_',filenames=[path],count=1,
                          regions=[[6,len(source[5]),8,10,1,0,0,0]])
            owners = [root, body] + ([] if missing_future else [nested])
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':[r for o in owners for r in o['regions']]},
                                                 coverage._ObserverWork(work))
            return source, counts, (4,11,[root]), owners, Counter(o['name'] for o in owners), coverage._construct_inventory(source,work)

        old = side('scan_package')
        proof = coverage.retained_osv_fixture_migration((old,side('scan_osv_package')),[100_000])
        self.assertIsNotNone(proof)
        self.assertIn([9,9],proof['pairs'])
        self.assertEqual(proof['async_copies']['base'][0]['body'], '_RNC'+symbol[2:]+'0Bb_')
        self.assertEqual(proof['async_copies']['head'][0]['body_state'], 1)
        self.assertEqual(proof['async_fragment_regions'][0]['base_range'], [4,11])
        self.assertEqual(proof['async_fragment_regions'][0]['head_range'], [4,11])
        for mismatch in ({'missing_future':True},{'cold':True},{'endpoint':'"Alpine:v3"'}):
            with self.subTest(mismatch=mismatch):
                self.assertIsNone(coverage.retained_osv_fixture_migration((old,side('scan_osv_package',**mismatch)),[100_000]))

    def test_report_fixture_binds_renamed_osv_call_and_its_wait_phases(self):
        name = 'src/core/security/vulnerability.rs'
        test = 'test_vulnerability_report_creation'
        symbol = f'_RNvNtNtNtNtCs1_7omg_lib4core8security13vulnerability5tests{len(test)}{test}'

        def observe(method, args='&package, &version', resume=1):
            source = ['#[cfg(test)]','mod tests {','    #[tokio::test]',f'    async fn {test}() {{',
                      '        let scanner = VulnerabilityScanner {',
                      '            osv_ecosystem_override: Some("Debian:12".to_string()),',
                      '        };','        let reports = scanner',f'            .{method}({args})',
                      '            .await','            .expect("actual report");','    }','}']
            brace = len(source[3])
            root = dict(name=symbol,filenames=['/artifact/'+name],count=1,regions=[[4,11,4,brace-1,1,0,0,0]])
            start, end = 14, 14+len(method)
            child = dict(root,name='_RNC'+symbol[2:]+'0Bb_',regions=[
                [4,brace,4,brace+1,1,0,0,0], [8,13,8,20,1,0,0,0], [8,23,8,30,1,0,0,0],
                [8,23,10,19,1,0,0,0], [9,start,9,end,1,0,0,0], [9,end+1,9,end+9,1,0,0,0],
                [11,14,11,20,resume,0,0,0], [11,21,11,36,resume,0,0,0], [12,5,12,6,1,0,0,0]])
            owners = (root,child)
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':child['regions']},coverage._ObserverWork(work))
            return coverage.async_osv_report_call(name,source,counts,(4,12,[root]),owners,
                Counter(o['name'] for o in owners),coverage._construct_inventory(source,work),8,8,work)

        baseline = observe('scan_package')
        head = observe('scan_osv_package')
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline[0],head[0])
        self.assertIsNone(observe('scan_osv_package',args='&other, &version'))
        self.assertIsNone(observe('scan_osv_package',resume=0))

    def test_vector_score_fixture_preserves_the_unexecuted_try_return(self):
        name = 'src/core/security/vulnerability.rs'
        test = 'osv_ingestion_retains_the_highest_numeric_or_vector_score'
        symbol = f'_RNvNtNtNtNtCs1_7omg_lib4core8security13vulnerability5tests{len(test)}{test}'

        def observe(method, try_hits=0):
            source = ['#[cfg(test)]','mod tests {','    #[tokio::test]',
                      f'    async fn {test}() -> anyhow::Result<()> {{',
                      '        let scanner = VulnerabilityScanner::with_osv_endpoint(endpoint, "Debian:12".into());',
                      '        let reports = scanner',f'            .{method}(',
                      '                &format!("vector-test-{}", uuid::Uuid::new_v4()),',
                      '                &crate::package_managers::parse_version_or_zero("1.0"),',
                      '            )','            .await?;','    }','}']
            brace = len(source[3])
            root = dict(name=symbol,filenames=['/artifact/'+name],count=1,regions=[[4,11,4,brace-1,1,0,0,0]])
            child = dict(root,name='_RNC'+symbol[2:]+'0Bb_',regions=[
                [4,brace,4,brace+1,1,0,0,0], [6,13,6,20,1,0,0,0], [6,23,6,30,1,0,0,0],
                [6,23,11,19,1,0,0,0], [7,14,7,14+len(method),1,0,0,0], [8,17,8,65,1,0,0,0],
                [11,19,11,20,try_hits,0,0,0], [12,5,12,6,1,0,0,0]])
            owners = (root,child)
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':child['regions']},coverage._ObserverWork(work))
            return coverage.async_osv_report_call(name,source,counts,(4,12,[root]),owners,
                Counter(o['name'] for o in owners),coverage._construct_inventory(source,work),6,6,work)

        baseline, head = observe('scan_package'), observe('scan_osv_package')
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline[0],head[0])
        self.assertIsNone(observe('scan_osv_package',try_hits=1))

    def test_scanner_fixture_observes_the_expanded_eager_record(self):
        name = 'src/core/security/vulnerability.rs'
        test = 'test_vulnerability_report_creation'
        symbol = f'_RNvNtNtNtNtCs1_7omg_lib4core8security13vulnerability5tests{len(test)}{test}'
        field = 'arch_endpoint: ARCH_ADVISORY_ENDPOINT.to_owned(),'

        def observe(addition=None, shortened=False, extra_region_delta=0):
            source = ['#[cfg(test)]','mod tests {','    #[tokio::test]',f'    async fn {test}() {{',
                      '        let scanner = VulnerabilityScanner {', '            client: Client::builder()',
                      '                .no_proxy()', '                .build()', '                .expect("fixture"),',
                      '            osv_api_url: endpoint,',
                      '            osv_ecosystem_override: Some("Debian:12".to_string()),']
            if addition:
                source.append('            '+addition)
            source.extend(['        };','    }','}'])
            end = len(source)-2
            brace = len(source[3])
            root = dict(name=symbol,filenames=['/artifact/'+name],count=1,regions=[[4,11,4,brace-1,1,0,0,0]])
            child = dict(root,name='_RNC'+symbol[2:]+'0Bb_',regions=[
                [4,brace,4,brace+1,1,0,0,0], [5,13,5,20,1,0,0,0],
                [5,23,end-int(shortened),10,1,0,0,0], [end+1,5,end+1,6,1,0,0,0]])
            if addition:
                start = source[10].index('Some(')+1
                child['regions'].insert(3,[11,start,11,len(source[10])+extra_region_delta,1,0,0,0])
            owners = (root,child)
            work = [500_000]
            counts = coverage._owner_line_counts({'regions':child['regions']},coverage._ObserverWork(work))
            return coverage.async_runtime_fixture_record(name,source,counts,(4,end+1,[root]),owners,
                Counter(o['name'] for o in owners),coverage._construct_inventory(source,work),5,5,work)

        old = observe()
        head = observe(field)
        self.assertIsNotNone(old)
        self.assertEqual(old[0],head[0])
        self.assertNotEqual(old[0],observe(field,extra_region_delta=-1)[0])
        self.assertIsNone(observe(field,shortened=True))
        self.assertIsNone(observe('arch_endpoint: endpoint.clone(),'))



    def test_scanner_constructor_retains_both_compiled_copies(self):
        name = 'src/core/security/vulnerability.rs'
        filename = '/artifact/' + name
        files = {filename: name}

        def compare(cold=False, drop=False, change=False):
            sides, indexes = [], []
            work = [1_000_000]
            for side in range(2):
                source = ['impl VulnerabilityScanner {','    pub fn new() -> Self {','        Self {',
                          '            client: shared_client().clone(),',
                          '            osv_api_url: "https://api.osv.dev/v1/query".to_string(),',
                          '            osv_ecosystem_override: None,']
                if side:
                    source.append('            arch_endpoint: ARCH_ADVISORY_ENDPOINT.to_owned(),')
                if side and change:
                    source[3] = '            client: custom_client().clone(),'
                source.extend(['        }','    }','}'])
                last = len(source)-1
                owners = []
                for instance in range(2):
                    if side and drop and instance:
                        continue
                    hits = int(not side or not cold or not instance)
                    disambiguator = str(side+1)+str(instance+1)
                    symbol = (f'_RNvMs_NtNtNtCs{disambiguator}_7omg_lib4core8security13vulnerability'
                              'NtB4_20VulnerabilityScanner3new')
                    rows = [[2,5,2,25], [3,9,last-1,10], [4,21,4,36], [4,37,4,42],
                            [5,26,5,56], [last,5,last,6]]
                    if side:
                        rows.extend([[5,57,5,66],[6,37,6,41]])
                    owners.append(dict(name=symbol,count=hits,filenames=[filename],
                                       regions=[[*row,hits,0,0,0] for row in rows]))
                counts = coverage._owner_line_counts({'regions':[r for o in owners for r in o['regions']]},
                                                      coverage._ObserverWork(work))
                spans = {id(o):coverage.source_owner_span(o,name,files,source) for o in owners}
                sides.append((source,coverage._construct_inventory(source,work),spans,counts,4))
                indexes.append(coverage.index_compiled_owner_sources(owners,files,work,{name}))
            return coverage.retained_scanner_construction(name,sides,indexes,work)

        proof = compare()
        self.assertEqual(proof['pairs'], [[2,2],[3,3],[4,4],[5,5],[6,6],[7,8],[8,9]])
        self.assertEqual(proof['instance_states'], [[True,True],[True,True]])
        self.assertEqual(proof['added_lines'], [7])
        self.assertIsNone(compare(cold=True))
        self.assertIsNone(compare(drop=True))
        self.assertIsNone(compare(change=True))

    def test_scanner_fixture_keeps_the_covered_ecosystem_loop(self):
        name = 'src/core/security/vulnerability.rs'
        test = 'cache_key_includes_the_ecosystem'
        symbol = f'_RNvNtNtNtNtCs1_7omg_lib4core8security13vulnerability5tests{len(test)}{test}'
        def observe(modern=False, iterations=2, case='Debian:13', retained_field_hits=2):
            source = ['#[cfg(test)]','mod tests {','    #[tokio::test]',
                f'    async fn {test}() -> anyhow::Result<()> {{',
                f'        for (expected_requests, ecosystem) in [(1, "Debian:12"), (2, "{case}")] {{',
                '            let scanner = VulnerabilityScanner {',
                '                client: shared_client().clone(),',
                '                osv_api_url: endpoint.clone(),',
                '                osv_ecosystem_override: Some(ecosystem.to_string()),']
            if modern:
                source.append('                arch_endpoint: ARCH_ADVISORY_ENDPOINT.to_owned(),')
            source.extend(['            };','        }','        Ok(())','    }','}'])
            close = len(source)-4
            end = len(source)-1
            brace = len(source[3])
            rows = [[4,brace,4,brace+1,1,0,0,0],
                [5,14,5,31,iterations,0,0,0], [5,33,5,42,2,0,0,0], [5,47,5,83,1,0,0,0],
                [6,17,6,24,2,0,0,0], [6,27,close,14,2,0,0,0],
                [7,25,7,40,2,0,0,0], [7,41,7,46,2,0,0,0],
                [8,30,8,38,2,0,0,0], [8,39,8,44,2,0,0,0], [end,5,end,6,1,0,0,0]]
            if modern:
                rows.insert(-1,[9,41,9,68,retained_field_hits,0,0,0])
            root = dict(name=symbol,filenames=['/artifact/'+name],count=1,
                        regions=[[4,11,4,brace-1,1,0,0,0]])
            child = dict(root,name='_RNC'+symbol[2:]+'0Bb_',regions=rows)
            owners = (root,child)
            work = [500_000]
            counts = coverage._owner_line_counts({'regions':rows},coverage._ObserverWork(work))
            return coverage.async_runtime_fixture_record(name,source,counts,(4,end,[root]),owners,
                Counter(o['name'] for o in owners),coverage._construct_inventory(source,work),6,6,work)

        old = observe()
        head = observe(modern=True)
        self.assertIsNotNone(old)
        self.assertIsNotNone(head)
        self.assertEqual(old[0],head[0])
        self.assertEqual(head[1]['loop_iterations'],2)
        self.assertIsNone(observe(modern=True, iterations=0))
        self.assertIsNone(observe(modern=True, case='Debian:14'))
        cold = observe(modern=True, retained_field_hits=0)
        self.assertTrue(cold is None or cold[0] != old[0])

    def test_request_observation_requires_exact_coordinates_and_all_compiled_copies(self):
        def scenario(modern, fault=None):
            name = 'scan_osv_coordinates' if modern else 'scan_package'
            source = [f'async fn {name}() {{', '    let mut request = OsvRequest {',
                      '        package: OsvPackage {', '            name: name.to_string(),',
                      '            ecosystem: ecosystem.to_owned(),' if modern else '            ecosystem,',
                      '        },', '        version: version.to_owned(),' if modern else '        version: version_str,',
                      '        page_token: None,', '    };', '}']
            if fault == 'changed-page':
                source[7] = '        page_token: page,'
            spans = [[2,9,2,20], [2,23,9,6], [3,18,6,10], [4,19,4,23], [4,24,4,33]]
            if modern:
                spans.append([7,18,7,25])
            owners = []
            copies = []
            for role in range(2):
                hits = 0 if fault == 'cold-copy' and role == 1 else 1
                regions = [[*span, hits, 0,0,0] for span in spans]
                if fault == 'missing-operand':
                    regions.pop(3)
                if fault == 'lost-call-region' and role == 1:
                    regions.pop(4)
                parent = dict(name=f'root-{role}', count=1)
                body = dict(name=f'body-{role}', regions=regions, count=1)
                copies.append(coverage.AsyncCompiledCopy(parent, body, ('compiled', str(role))))
                owners.append(body)
            if fault == 'foreign-owner':
                owners.append(dict(owners[0], name='foreign'))
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':[r for o in owners for r in o['regions']]},
                                                  coverage._ObserverWork(work))
            return (source, counts, coverage._construct_inventory(source, work), owners, tuple(copies), 2)

        base = scenario(False)
        proof = coverage.retained_osv_request((base, scenario(True)), [100_000])
        self.assertEqual(proof['pairs'], [[2,2], [3,3], [4,4], [6,6], [8,8], [9,9]])
        for fault in ('changed-page', 'missing-operand', 'lost-call-region', 'cold-copy', 'foreign-owner'):
            with self.subTest(fault=fault):
                self.assertIsNone(coverage.retained_osv_request((base, scenario(True, fault)), [100_000]))


class RetainedFixtureConstructorTests(unittest.TestCase):
    def test_pi_fixture_exit_requires_the_constructor_and_all_record_regions(self):
        filename = 'src/runtimes/pi.rs'
        symbol = '_RNvMNtNtCs1_7omg_lib8runtimes2piNtB2_9PiManager10with_paths'

        def side(modern, cold=False, missing=False):
            parameter = '_unused_ambient_npm' if modern else 'npm'
            declaration = f'    fn with_paths(versions_dir: PathBuf, {parameter}: PathBuf) -> Self {{'
            fields = ['        Self {', '            versions_dir,',
                      '            advisories: Arc::new(TestAdvisories::default()),',
                      '            security: RuntimeSecurity::fixture(),', '        }'] if modern else [
                         '        Self { versions_dir, npm }']
            lines = ['impl PiManager {','    #[cfg(test)]',declaration,*fields,'    }','}']
            end = len(lines)-1
            hits = 11 if modern else 6
            body = [[4,9,end-1,len(fields[-1])+1,hits,0,0,0]]
            if modern and not missing:
                body.append([5,13,5,25,hits,0,0,0])
            raw = [[3,5,3,len(declaration)-1,hits,0,0,0],*body,[end,5,end,6,0 if cold else hits,0,0,0]]
            root = dict(name=symbol,filenames=['/artifact/'+filename],regions=raw,count=hits)
            work = [30_000]
            counts = coverage._owner_line_counts({'regions':raw}, coverage._ObserverWork(work))
            return lines,counts,(3,end,[root]),[root],Counter({symbol:1}),end

        oldest = side(False)
        proof = coverage.retained_pi_fixture_exit((oldest,side(True)),[30_000])
        self.assertEqual(proof['pairs'],[[5,9]])
        self.assertIsNone(coverage.retained_pi_fixture_exit((oldest,side(True,cold=True)),[30_000]))
        self.assertIsNone(coverage.retained_pi_fixture_exit((oldest,side(True,missing=True)),[30_000]))


class SbomComponentPushTests(unittest.TestCase):
    def test_audit_fixture_observes_coverage_and_applicability_separately(self):
        name = 'src/core/security/sbom_shared.rs'
        symbol = '_RNvNtNtNtNtCs1_7omg_lib4core8security11sbom_shared5tests7fixture'
        fields = ('coverage: crate::core::security::scan::AuditCoverage::Unreported,',
                  'applicability: crate::core::security::scan::FindingApplicability::Possible,')

        def observe(modern=False, applicability_hits=1):
            source = ['#[cfg(test)]','mod tests {','    #[test]','    fn fixture() {',
                      '        let audit = SecurityAuditResult {','            total_vulnerabilities: 1,',
                      '            high_severity: 0,','            vulnerabilities: vec![(',
                      '                old.name.clone(),','                vec![Vulnerability {',
                      '                    id: "fixture-advisory".into(),',
                      '                    summary: "fixture".into(),','                    score: None,',
                      '                    advisory_severity: None,','                    native_advisory: None,',
                      '                    affected_installed: vec![InstalledIdentity::from(&old)],',
                      '                }],','            )],','        };','    }','}']
            raw = [[4,5,4,17,1,0,0,0],[5,13,5,18,1,0,0,0]]
            if modern:
                for offset, indent, field, count in ((1,12,fields[0],1),(7,20,fields[1],applicability_hits)):
                    text = ' '*indent + field
                    source.insert(4+offset,text)
                    col = text.index(': ')+3
                    raw.append([5+offset,col,5+offset,len(text),count,0,0,0])
            end = len(source)-2
            raw.extend([[5,21,end,10,1,0,0,0],[end+1,5,end+1,6,1,0,0,0]])
            root = dict(name=symbol,filenames=['/artifact/'+name],regions=raw,count=1)
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':raw},coverage._ObserverWork(work))
            return coverage.async_runtime_fixture_record(name,source,counts,(4,end+1,[root]),[root],
                        Counter({symbol:1}),coverage._construct_inventory(source,work),5,5,work)

        old, head = observe(), observe(True)
        self.assertIsNotNone(old)
        self.assertEqual(old[0],head[0])
        self.assertIsNone(observe(True,applicability_hits=0))

    def test_package_identity_fixture_adds_an_observed_unknown_origin(self):
        name = 'src/core/security/sbom_shared.rs'
        symbol = '_RNvNtNtNtNtCs1_7omg_lib4core8security11sbom_shared5tests7fixture'
        origin = 'crate::package_managers::types::SecurityOrigin::Unknown'

        def observe(addition=None, count=1):
            source = ['#[cfg(test)]', 'mod tests {', '    #[test]', '    fn fixture() {',
                      '        let package = SecurityPackage {']
            if addition is not None:
                source.append(f'            origin: {addition},')
            source.extend(['            name: "fixture".into(),', '            version: "1".into(),',
                           '            advisory_source: None,', '            architecture: None,',
                           '            description: String::new(),', '            licenses: vec![],',
                           '        };', '    }', '}'])
            end = len(source)-2
            raw = [[4,5,4,17,1,0,0,0],[5,13,5,20,1,0,0,0],[5,23,end,10,1,0,0,0],
                   [end+1,5,end+1,6,1,0,0,0]]
            if addition is not None:
                raw.append([6,21,6,21+len(addition),count,0,0,0])
            root = dict(name=symbol, filenames=['/artifact/'+name], regions=raw, count=1)
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':raw},coverage._ObserverWork(work))
            return coverage.async_runtime_fixture_record(name,source,counts,(4,end+1,[root]),[root],
                        Counter({symbol:1}),coverage._construct_inventory(source,work),5,5,work)

        old = observe()
        current = observe(origin)
        self.assertIsNotNone(old)
        self.assertEqual(old[0],current[0])
        self.assertIsNone(observe(origin,count=0))
        self.assertIsNone(observe('SecurityOrigin::DistributionPackage'))

    def test_system_component_metadata_requires_its_original_fields_and_regions(self):
        name = '_RNvNtNtNtCs1_7omg_lib4core8security11sbom_shared7compose'

        def scenario(properties, name_field='os_name', hits=1, vendor='None'):
            source = ['fn compose() {', '    Ok(Sbom {', '        bom_format: "CycloneDX".into(),',
                      '        metadata: SbomMetadata {', '            component: Some(SbomComponent {',
                      f'                name: {name_field}.into(),', f'                properties: {properties},',
                      '            }),', f'            manufacture: {vendor},', '        },', '    })', '}']
            raw = [[3,21,3,32,1,0,0,0], [6,23,6,30,hits,0,0,0], [9,26,9,30,1,0,0,0]]
            root = dict(name=name, regions=raw, count=1)
            work = [100_000]
            return (source, {3:1,6:hits,9:1}, (1,len(source),[root]), [root], Counter({name:1}),
                    coverage._construct_inventory(source,work), 3)

        base = scenario('None')
        proof = coverage.retained_sbom_metadata((base,scenario('Some(properties)')), [100_000])
        self.assertEqual(proof['pairs'], [[3,3], [6,6], [9,9]])
        self.assertIsNone(coverage.retained_sbom_metadata(
            (base,scenario('Some(properties)', name_field='new_name')), [100_000]))
        self.assertIsNone(coverage.retained_sbom_metadata(
            (base,scenario('Some(properties)', hits=0)), [100_000]))
        self.assertIsNone(coverage.retained_sbom_metadata(
            (base,scenario('Some(properties)', vendor='Some(vendor)')), [100_000]))

    def test_component_properties_cannot_replace_coverage_of_the_record_or_its_mapper(self):
        name = 'src/core/security/sbom_shared.rs'
        filename = '/artifact/' + name

        def scenario(properties, fault=None, vulnerability=False):
            source = ['fn compose() {', '    for package in installed {',
                      '        components.push(SbomComponent {',
                      '            name: package.name.clone(),',
                      '            licenses: package.licenses.iter().map(|label| label.clone()).collect(),',
                      f'            properties: {properties},', '        });', '    }', '}']
            receiver = 'components'
            if vulnerability:
                receiver = 'vulnerabilities'
                source = ['fn compose() {', '    for finding in findings {',
                          '        vulnerabilities.push(SbomVulnerability {',
                          '            id: finding.id.clone(),',
                          '            advisories: finding.iter().map(|native| {',
                          '                native.iter().map(|reference| reference.id.clone()).collect()',
                          '            }).collect(),', f'            {properties},', '        });', '    }', '}']
            if fault == 'changed-field':
                source[3] = '            name: package.description.clone(),'
            def region(line, value, hits):
                start = source[line - 1].index(value) + 1
                return [line, start, line, start + len(value), hits, 0, 0, 0]
            roots = []
            owners = []
            for role, hits in (('1', 1), ('2', 0)):
                symbol = f'_RNvNtNtNtCs{role}_7omg_lib4core8security11sbom_shared7compose'
                regions = [region(3, receiver, hits), region(3, 'push', hits),
                           region(4, source[3].strip(), hits)]
                if not vulnerability:
                    regions.append(region(6, properties, hits))
                if fault == 'missing-property':
                    regions.pop()
                if fault == 'mixed-root' and role == '1':
                    regions[1][4] = 0
                if fault == 'moved-field-region':
                    regions[2] = region(4, 'package.name', hits)
                root = dict(name=symbol, filenames=[filename], count=1, regions=regions)
                roots.append(root)
                owners.append(root)
                child_hits = 0 if fault == 'cold-mapper' else hits
                expression = 'native.iter()' if vulnerability else 'label.clone()'
                mapper = dict(root, name='_RNC' + symbol[2:] + '0B9_', count=child_hits,
                              regions=[region(6 if vulnerability else 5, expression, child_hits)])
                owners.append(mapper)
                if vulnerability and fault != 'missing-nested':
                    owners.append(dict(mapper, name='_RNCNC' + symbol[2:] + '00Bb_',
                                       regions=[region(6, 'reference.id.clone()', child_hits)]))
            if fault == 'duplicate-mapper':
                owners.append(owners[-1])
            raw = [region for owner in owners for region in owner['regions']]
            work = [100_000]
            counts = coverage._owner_line_counts({'regions': raw}, coverage._ObserverWork(work))
            return (source, counts, (1, len(source), roots), owners, Counter(o['name'] for o in owners),
                    coverage._construct_inventory(source, work), 3)

        base = scenario('None')
        result = coverage.retained_sbom_push((base, scenario('Some(properties)')), [100_000])
        self.assertEqual(result['pairs'], [[3, 3], [4, 4], [5, 5]])
        for fault in ('changed-field', 'missing-property', 'mixed-root', 'moved-field-region',
                      'cold-mapper', 'duplicate-mapper'):
            with self.subTest(fault=fault):
                self.assertIsNone(coverage.retained_sbom_push(
                    (base, scenario('Some(properties)', fault)), [100_000]))
        base = scenario('properties: finding.props', vulnerability=True)
        head = scenario('properties', vulnerability=True)
        result = coverage.retained_sbom_push((base,head), [100_000], vulnerability=True)
        self.assertEqual(result['pairs'], [[3,3], [4,4], [6,6]])
        incomplete = scenario('properties', 'missing-nested', vulnerability=True)
        self.assertIsNone(coverage.retained_sbom_push((base,incomplete), [100_000], vulnerability=True))


class AdvisoryCountAssertionTests(unittest.TestCase):
    def test_daemon_status_assertion_retains_the_known_count_and_requires_no_missing_regions(self):
        name = 'src/daemon/status_policy.rs'
        filename = '/artifact/' + name
        symbol = '_RNvNtNtNtCs1_7omg_lib6daemon13status_policy5tests43successful_scan_replaces_the_previous_count'
        counts = {4: 1, 5: 1, 6: 1, 9: 1}

        def observe(result, prior, expected, fault=None):
            call = 'vulnerability_count_from_scan::<()>'
            source = ['#[cfg(test)]', 'mod tests {', '    #[test]',
                      '    fn successful_scan_replaces_the_previous_count() {',
                      '        assert_eq!(', f'            {call}({result}, {prior}),',
                      f'            {expected}', '        );', '    }', '}']
            def region(line, token):
                start = source[line - 1].index(token) + 1
                return [line, start, line, start + len(token), 1, 0, 0, 0]
            raw = [region(4, source[3].strip()), region(5, 'assert_eq!'),
                   region(6, call), region(6, result), region(6, prior), region(9, '}')]
            if fault == 'missing':
                raw.pop(4)
            if fault == 'cold':
                raw[3][4] = 0
            root = dict(name=symbol, filenames=[filename], regions=raw, count=1)
            owners = [root]
            if fault == 'foreign':
                owners.append(dict(root, name='foreign', regions=[region(6, prior)]))
            work = [100_000]
            return coverage.retained_direct_unit_assertion(name, source, 5, counts,
                (4, 9, [root]), owners, Counter(owner['name'] for owner in owners),
                {filename: name}, coverage._construct_inventory(source, work), work)

        previous = observe('&Ok(3)', 'Some(5)', 'Some(3)')
        current = observe('&Ok((3, 0))', 'Some((5, 0))', 'Some((3, 0))')
        self.assertIsNotNone(previous)
        self.assertEqual(previous[:3], current[:3])
        for fault in ('missing', 'cold', 'foreign'):
            with self.subTest(fault=fault):
                self.assertIsNone(observe('&Ok((3, 0))', 'Some((5, 0))', 'Some((3, 0))', fault))
        self.assertIsNone(observe('&Ok((3, 1))', 'Some((5, 0))', 'Some((3, 0))'))
        self.assertNotEqual(previous[1], observe('&Ok(4)', 'Some(5)', 'Some(4)')[1])


class PolicyLicenseFixtureAssertionTests(unittest.TestCase):
    def observe(self, modern, fault=None):
        name='src/core/security/policy.rs'
        filename='/artifact/'+name
        files={filename:name}
        lines=['#[cfg(test)]','mod tests {','    #[test]','    fn checked() {',
               '        let policy = SecurityPolicy {','            allowed_licenses: vec!["MIT".into()],',
               '            ..SecurityPolicy::default()','        };']
        def region(line,text,hits=1):
            pos=lines[line-1].index(text)+1
            return [line,pos,line,pos+len(text),hits,0,0,0]
        raw=[region(4,'fn checked()')]
        cases=(('licenses','"MIT", "GPL-3.0"','"multi"','is_err'),
               ('alternatives','"MIT OR Apache-2.0", "GPL-3.0"','"multi"','is_err'),
               ('allowed','"MIT"','"single"','is_ok'))
        for index,(variable,values,package,result) in enumerate(cases):
            if modern and fault=='changed-license' and index==1:
                values=values.replace('Apache-2.0','BSD-3-Clause')
            if modern and fault=='wrong-result' and index==2:
                result='is_err'
            origin='&SecurityOrigin::Unknown' if fault=='wrong-origin' else '&SecurityOrigin::DistributionPackage'
            binding=len(lines)+1
            lines.extend([f'        let {variable} = combined_license_expression([{values}]);',
                          '        assert!(','            policy'])
            opener=binding+1
            if modern:
                lines.extend(['                .check_source(',f'                    {package},',
                              f'                    {origin},',f'                    {variable}.as_deref()',
                              '                )'])
                package_line=opener+3
            else:
                lines.append(f'                .check_source({package}, false, {variable}.as_deref())')
                package_line=opener+2
            close=len(lines)
            lines.extend([f'                .{result}()','        );'])
            receiver=region(opener+1,'policy')
            envelope=[opener+1,receiver[1],close,len(lines[close-1])+1,1,0,0,0]
            raw.extend([region(binding,variable),region(binding,'combined_license_expression'),
                        region(binding,f'[{values}]'),region(opener,'assert!'),receiver,envelope,
                        region(opener+2,'check_source'),region(package_line,package)])
            if modern and not (fault=='missing-origin' and index==1):
                raw.append(region(opener+4,origin))
            raw.append(region(close+1,result,0 if fault=='cold-result' and index==2 else 1))
        lines.extend(['        assert!(combined_license_expression(std::iter::empty()).is_none());','    }','}'])
        end=len(lines)-1
        raw.extend([region(end-1,'assert!'),region(end,'}')])
        symbol='_RNvNtNtNtNtCs1_7omg_lib4core8security6policy5tests7checked'
        root=dict(name=symbol,filenames=[filename],count=1,regions=raw)
        owners=[root]
        if fault=='foreign':
            owners.append(dict(root,name='opaque',regions=[region(10,'assert!')]))
        work=[coverage.SOURCE_CONSTRUCT_WORK_CAPACITY]
        counts=coverage._owner_line_counts({'regions':[r for item in owners for r in item['regions']]},
                                          coverage._ObserverWork(work))
        inventory=coverage._construct_inventory(lines,work)
        return coverage.policy_license_fixture_assertions(name,lines,counts,(4,end,[root]),owners,
                  Counter(item['name'] for item in owners),files,inventory,10,work)

    def test_all_three_license_cases_keep_exact_source_and_origin_roles(self):
        old,head=[self.observe(modern) for modern in (False,True)]
        self.assertEqual(old[0],head[0])
        self.assertEqual([old[2]['modern'],head[2]['modern']],[False,True])
        self.assertEqual([len(old[1]),len(head[1])],[12,12])
        for fault in ('changed-license','wrong-result','wrong-origin','missing-origin','cold-result','foreign'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(True,fault))


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

    def paused_daemon_source_compare(self, fault=None):
        name='src/daemon/server.rs'
        sources=[];documents=[];counts=[]
        for side,method in enumerate(('scan_package','assess_packages')):
            lines=['#[cfg(test)]','mod tests {',
                   '    impl crate::core::security::vulnerability::VulnerabilitySource for PausedAdvisorySource {',
                   f"        fn {method}<'a>(","            &'a self,",
                   "            packages: &'a [Package]," if side else "            _name: &'a str,",
                   '        ) -> Pin<Box<dyn Future<Output = '+('PackageAssessment' if side else 'VulnerabilityReport')+'>>> {',
                   '            Box::pin(async move {',
                   '                self.started.notify_one();',
                   '                self.resume.notified().await;',
                   '                Ok(packages.iter().map(|package| package.clone()).collect())' if side else '                Ok(vec![])',
                   '            })','        }','    }','}']
            if side and fault=='receiver':
                lines[9]=lines[9].replace('self.resume','self.other')
            if fault=='production-scope':
                lines[0]='#[cfg(feature = "daemon")]'
            def slot(line,text,count=2):
                start=lines[line-1].index(text)+1
                return [line,start,line,start+len(text),count,0,0,0]
            qualified=f'NtNtNtCs{side+1}_7omg_lib6daemon6server5tests'
            def owner(kind,binding,trait,suffix,count,regions):
                return dict(name=f'_R{kind}NvX{qualified}Nt{binding}_20PausedAdvisorySourceNtNtNtNt{trait}_4core8security13vulnerability19VulnerabilitySource{len(method)}{method}{suffix}',
                            count=count,filenames=['/src/'+name],regions=regions)
            members=[owner('','B2','B8','',2,[[4,9,7,len(lines[6]),2,0,0,0],slot(8,'Box::pin'),slot(13,'}')]),
                     owner('NC','B4','Ba','0Ba_',2,[slot(8,'{'),slot(9,'self.started'),slot(9,'notify_one'),
                           slot(10,'self.resume'),slot(10,lines[9].strip().removesuffix(';')),
                           slot(11,'Ok',1),slot(12,'}',1)])]
            if side and fault!='missing-mapper':
                hit=int(fault!='cold-mapper')
                members.append(owner('NCNC','B6','Bc','00Bc_',hit,[slot(11,'package.clone()',hit)]))
            sources.append({name:('\n'.join(lines)+'\n').encode(),
                'other.rs':b'fn notification_fixture() {\n    self.started.notify_one();\n    self.resume.notified().await;\n}\n'})
            documents.append(members)
            work=coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [row for item in members for row in item['regions']],work),work)))
        def owners(base,head):
            for document,members in zip((base,head),documents):
                document['data'][0]['functions']=members
        return self.compare(before=counts[0],after=counts[1],mutate=owners,sources=sources,filename=name)

    def test_daemon_advisory_wait_requires_complete_test_only_compiler_owners(self):
        receipt=self.paused_daemon_source_compare()
        proof,=[row for row in receipt['retained_replacement_obligations'] if row.get('qualified_test_statement')]
        self.assertEqual([len(side) for side in proof['fully_covered_replacement_owners']],[2,3])
        self.assertTrue({(9,9),(10,10)}<={tuple(pair) for pair in proof['pairs']})
        self.assertEqual(proof['mapped_credit'],[0,0])
        for fault in ('cold-mapper','missing-mapper','receiver','production-scope'):
            with self.subTest(fault=fault),self.assertRaises(ValueError):
                self.paused_daemon_source_compare(fault)

    def daemon_audit_record_compare(self, fault=None):
        name = 'src/daemon/server.rs'
        old = [
            '#[cfg(test)]', 'mod tests {', '    #[test]',
            '    fn oversized_security_audit_is_not_reported_as_complete() {',
            '        let vulnerability = super::super::protocol::Vulnerability {',
            '            id: "CVE-fixture".into(),',
            '        };',
            '        let response = Response::Success {',
            '            result: ResponseResult::SecurityAudit(SecurityAuditResult {',
            '                vulnerabilities: (0..2)',
            '                    .map(|index| (format!("package-{index}"), vec![vulnerability.clone()]))',
            '                    .collect(),',
            '            }),',
            '        };',
            '        assert!(encode_frame(&response).is_err());',
            '    }', '}',
        ]
        new = old.copy()
        new.insert(5, '            applicability: crate::core::security::scan::FindingApplicability::Possible,')
        new.insert(10, '                coverage: crate::core::security::scan::AuditCoverage::Unreported,')
        if fault == 'variant':
            new[5] = new[5].replace('Possible', 'Applicable')
        documents = []
        counts = []
        for side, source in enumerate((old, new)):
            def line(number):
                return number + side * (int(number >= 6) + int(number >= 10))
            def span(number, text, hits=1):
                start = source[number - 1].index(text) + 1
                return [number, start, number, start + len(text), hits, 0, 0, 0]
            root = f'_RNvNtNtNtCs{side + 1}_7omg_lib6daemon6server5testss_52oversized_security_audit_is_not_reported_as_complete'
            rows = [
                span(4, 'fn oversized_security_audit_is_not_reported_as_complete()'),
                [5, 29, line(7), 10, 1, 0, 0, 0],
                [line(8), 24, line(14), 10, 1, 0, 0, 0],
                span(line(10), '(0..2)'),
                span(line(12), 'collect'),
                span(line(15), 'encode_frame', int(fault != 'cold-retained' or not side)),
                span(line(16), '}'),
            ]
            if side:
                rows += [span(6, source[5].strip().split(': ', 1)[1][:-1]),
                         span(11, 'crate::core::security::scan::AuditCoverage::Unreported')]
                if fault == 'missing-field':
                    rows.pop()
            child = '_RNC' + root[2:] + ('s_0B9_' if side and fault == 'wrong-owner' else '0B9_')
            members = [
                dict(name=root, count=1, regions=rows, filenames=['/src/' + name]),
                dict(name=child, count=2, regions=[span(line(11), 'format!', 2),
                     span(line(11), 'vulnerability.clone()', 2)], filenames=['/src/' + name]),
            ]
            observer = coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [row for owner in members for row in owner['regions']], observer), observer)))
            documents.append(members)
        def owners(base, head):
            for document, members in zip((base, head), documents):
                document['data'][0]['functions'] = members
                document['data'][0]['files'][0]['expansions'] = []
        return self.compare(before=counts[0], after=counts[1], mutate=owners, filename=name,
            sources=tuple({name: ('\n'.join(source) + '\n').encode()} for source in (old, new)))

    def test_daemon_audit_fixture_retains_mapper_after_enum_fields_are_added(self):
        result = self.daemon_audit_record_compare()
        receipt, = [row for row in result['retained_replacement_obligations']
                    if row['kind'] == 'retained-daemon-audit-fixture-fields']
        self.assertEqual(receipt['added_lines'], [6, 11])
        self.assertIn([11, 13], receipt['pairs'])
        self.assertEqual(result['deleted_mapped'], 0)
        for fault in ('variant', 'missing-field', 'cold-retained', 'wrong-owner'):
            with self.subTest(fault=fault):
                try:
                    rejected = self.daemon_audit_record_compare(fault)
                except ValueError:
                    continue
                self.assertFalse(any(row['kind'] == 'retained-daemon-audit-fixture-fields'
                                     for row in rejected['retained_replacement_obligations']))

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

    def test_async_phase_reuses_checked_source_owners_and_their_lexical_signature(self):
        source = ['async fn checked() {', '    verify();', '}']
        file = '/src/example.rs'
        opening = source[0].index('{')+1
        root = dict(name='_RNvCs1_7example7checked',count=1,filenames=[file],regions=[
            [1,1,1,opening-1,1,0,0,0]])
        child = dict(root,name='_RNC'+root['name'][2:]+'0B3_',regions=[
            [1,opening,1,opening+1,1,0,0,0], [2,5,2,11,0,0,0,0], [3,1,3,2,1,0,0,0]])
        owners = [root,child]
        files = {file:'example.rs'}
        expected = coverage.compiled_async_function_groups('example.rs',owners,files,source)
        self.assertEqual(len(expected),1)
        compiled = coverage._compiled_function_groups('example.rs',owners,files,source)
        with (mock.patch.object(coverage,'source_function_prefixes',wraps=coverage.source_function_prefixes) as parse,
              mock.patch.object(coverage,'source_owner_span',wraps=coverage.source_owner_span) as inspect):
            actual = coverage.compiled_async_function_groups('example.rs',compiled[0],files,source,
                compiled_groups=compiled)
        self.assertEqual(actual,expected)
        parse.assert_not_called()
        inspect.assert_not_called()
        self.assertEqual(coverage.compiled_async_function_groups('example.rs',owners,files,source,
            compiled_groups=compiled),{})

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
        malformed = coverage._BooleanSource('', ['value'], [0], [5], Unreadable(), {}, [0], ())
        with self.assertRaisesRegex(ValueError, 'work bound exceeded'):
            coverage._construct_ancestors(malformed, 0, [0])
        cyclic = coverage._BooleanSource('', ['value'], [0], [5], [0], {}, [0], ())
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

    def named_record_child_callback_fixture(self, fault=None):
        old = [
            'fn inventory(input: &[Row]) -> Result<Vec<Row>> {',
            '    input.iter()',
            '        .map(|row| {',
            '            let values = row.values.iter()',
            '                .map(|value| Child {',
            '                    name: value.name.clone(),',
            '                    kind: value.kind.clone(),',
            '                })',
            '                .collect();',
            '            Ok(values)',
            '        })',
            '        .collect()',
            '}',
        ]
        new = old[:2] + ['        .filter(|row| {', '            visible(row)', '        })'] + old[2:]
        sources = [old, new]
        documents = []
        for side, source in enumerate(sources):
            members = []
            shift = 3 * side
            for copy_number, state in enumerate((1, 0), 1):
                root = f'_RNvCs{copy_number}_7example9inventory'
                ordinal = 's_' if side else ''
                def row(line, start, end, quantity):
                    return [line, start, line, end, quantity, 0, 0, 0]
                def owner(symbol, count, regions):
                    return dict(name=symbol, count=count, filenames=['/src/example.rs'],
                                regions=regions, branches=[], mcdc_records=[])
                prefix_start=source[2+shift].index('map')+1
                members.append(owner(root, state, [row(1, 1, source[0].index('{') + 1, state),
                    row(3+shift,prefix_start,prefix_start+3,4*state),row(len(source), 1, 2, state)]))
                if side:
                    opening = source[2].index('{') + 1
                    members.append(owner('_RNC' + root[2:] + '0B3_', 4 * state,
                        [row(3, opening, opening + 1, 4 * state), row(4, 13, 20, 4 * state),
                         row(5, 9, 10, 4 * state)]))
                opening = source[2 + shift].index('{') + 1
                members.append(owner('_RNC' + root[2:] + ordinal + '0B3_', 3 * state,
                    [row(3 + shift, opening, opening + 1, 3 * state),
                     row(4 + shift, 13, 16, 3 * state),
                     row(4 + shift, source[3 + shift].index('row.values') + 1, len(source[3 + shift]) + 1, 3 * state),
                     row(5 + shift, 18, 21, 3 * state),
                     row(9 + shift, 18, 25, 3 * state), row(10 + shift, 13, 15, 3 * state),
                     row(11 + shift, 9, 10, 3 * state)]))
                raw = []
                for number in (6 + shift, 7 + shift):
                    text = source[number - 1]
                    if number==6+shift:
                        raw.append(row(number, text.index('value.') + 1, len(text), 2 * state))
                    else:
                        raw.extend([row(number,text.index('value.')+1,text.index('.clone')+1,2*state),
                                    row(number,text.index('clone')+1,text.index('clone')+6,2*state)])
                raw.append(row(8 + shift, 17, 18, 2 * state))
                members.append(owner('_RNCNC' + root[2:] + ordinal + '00B5_', 2 * state, raw))
            documents.append(members)
        children = [owner for owner in documents[1] if owner['name'].startswith('_RNCNC')]
        hot, cold = children
        if fault == 'foreign-prefix':
            foreign=copy.deepcopy(documents[1][0]);foreign['name']='foreign'
            foreign['regions']=[foreign['regions'][1]];documents[1].append(foreign)
        elif fault == 'cold-prefix':
            documents[1][0]['regions'][1][4]=0
        elif fault == 'missing-cold-prefix':
            next(o for o in documents[1] if o['name']=='_RNvCs2_7example9inventory')['regions'].pop(1)
        elif fault == 'wide-prefix':
            documents[1][0]['regions'][1][3]+=1
        elif fault == 'missing-cold':
            documents[1].remove(cold)
        elif fault == 'lost-hot':
            hot['count'] = 0
            for region in hot['regions']: region[4] = 0
        elif fault == 'hidden-cold':
            hot['regions'][1][4] = 0
        elif fault == 'entry-count':
            hot['count'] += 1
        elif fault == 'truncated-method':
            hot['regions'][2][3] -= 1
        elif fault == 'partial-call':
            hot['regions'][2][3] += 1
        elif fault == 'dropped-receiver':
            hot['regions'].pop(1)
        elif fault == 'foreign-copy':
            hot['name'] = hot['name'].replace('Cs1_', 'Cs9_')
        elif fault == 'extra-owner':
            foreign = copy.deepcopy(hot); foreign['name'] = 'foreign'; documents[1].append(foreign)
        elif fault == 'missing-field':
            hot['regions'].pop(1)
        elif fault == 'prefix-paint':
            hot['regions'].insert(0, [8, 30, 8, 35, hot['count'], 0, 0, 0])
        elif fault == 'channel':
            hot['regions'][0][7] = 1
        elif fault == 'changed-type':
            sources[1][7] = sources[1][7].replace('Child', 'Other')
        elif fault == 'changed-field':
            sources[1][9] = sources[1][9].replace('value.kind', 'value.name')
        counts = []
        for members in documents:
            work = coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [region for owner in members for region in owner['regions']], work), work)))
        if fault == 'missing-da':
            counts[1] = [(line, quantity) for line, quantity in counts[1] if line != 9]
        def owners(base, head):
            for document, members in zip((base, head), documents):
                document['data'][0]['functions'] = members
                document['data'][0]['files'][0].update(expansions=[], branches=[], mcdc_records=[])
        return self.compare(before=counts[0], after=counts[1], mutate=owners, sources=(
            {'example.rs': ('\n'.join(sources[0]) + '\n').encode()},
            {'example.rs': ('\n'.join(sources[1]) + '\n').encode()}))

    def test_named_record_child_keeps_complete_cold_and_hot_field_geometry(self):
        receipt = self.named_record_child_callback_fixture()
        proof, = [row for row in receipt['retained_replacement_obligations']
                  if row['kind'] == 'closed-retained-callback-island']
        self.assertEqual([len(names) for names in proof['forest_names'][0]], [2, 2])
        self.assertEqual(receipt['deleted_mapped'], 0)
        self.assertIn([6, 9], proof['pairs'])
        self.assertIn([8, 11], proof['pairs'])

    def test_named_record_child_refuses_changed_counts_copies_source_or_fields(self):
        for fault in ('missing-cold', 'lost-hot', 'hidden-cold', 'entry-count', 'foreign-copy',
                      'extra-owner', 'missing-field', 'prefix-paint', 'channel', 'changed-type',
                      'changed-field', 'missing-da', 'truncated-method', 'partial-call', 'dropped-receiver',
                      'foreign-prefix', 'cold-prefix', 'missing-cold-prefix', 'wide-prefix'):
            with self.subTest(fault=fault):
                try: receipt = self.named_record_child_callback_fixture(fault)
                except ValueError: continue
                self.assertFalse(any(row['kind'] == 'closed-retained-callback-island'
                    for row in receipt.get('retained_replacement_obligations', [])))

    def sbom_advisory_property_array_compare(self, fault=None):
        file = 'src/core/security/sbom_shared.rs'
        entries = [
            'SbomProperty {',
            '    name: "omg:advisory:title".into(),',
            '    value: finding.summary.clone(),',
            '},',
            'SbomProperty {',
            '    name: "omg:advisory:nevra".into(),',
            '    value: native.advisory_nevra.clone(),',
            '},',
            'SbomProperty {',
            '    name: "omg:advisory:published-severity".into(),',
            '    value: native.published_severity.clone(),',
            '},',
        ]
        beginning = ['fn compose(audit: &Audit) {',
                     '    for (name, findings) in &audit.vulnerabilities {',
                     '        for finding in findings {']
        lookup = [
            '            let reference = identities.get(&key).ok_or_else(|| {',
            '                anyhow::anyhow!("missing fixture component")',
            '            })?;',
        ]
        advisories = [
            '                advisories: finding.native_advisory.as_ref().map(|native| {',
            '                    describe(native);',
            '                }),',
        ]
        sources = [
            [*beginning, *lookup, '            vulnerabilities.push(SbomVulnerability {',
             '                properties: finding.native_advisory.as_ref().map(|native| {',
             '                    vec![', *['                        ' + line for line in entries],
             '                    ]',
             '                    .into_iter().filter(|property| !property.value.is_empty()).collect()',
             '                }).unwrap_or_default(),', *advisories, '            });', '        }', '    }', '}'],
            [*beginning, *lookup, '            if let Some(native) = &finding.native_advisory {',
             '                properties.extend(', '                    [',
             *['                    ' + line for line in entries],
             '                    ]',
             '                    .into_iter().filter(|property| !property.value.is_empty()),',
             '                );', '            }',
             '            vulnerabilities.push(SbomVulnerability {',
             '                properties,', *advisories, '            });',
             '        }', '    }', '}'],
        ]
        docs = []
        counts = []
        for side, lines in enumerate(sources):
            array = lines.index('                    [' if side else '                    vec![') + 1
            lookup_line = lines.index(lookup[0]) + 1
            copies = []
            for copy_number in (0, 1):
                state = int(copy_number == 1)
                if side and fault == 'redistributed-count':
                    state = 1 - state
                symbol = f'_RNvNtNtNtCs{1 + copy_number}_7omg_lib4core8security11sbom_shared7compose'
                def span(number, value, quantity):
                    column = lines[number - 1].index(value) + 1
                    return [number, column, number, column + len(value), quantity, 0, 0, 0]
                root = dict(name=symbol, count=1, filenames=['/src/' + file],
                            regions=[span(1, 'fn compose(audit: &Audit)', 1), span(len(lines), '}', 1)])
                root['regions'].extend([
                    span(lookup_line, 'reference', state),
                    span(lookup_line, 'identities', state),
                    span(lookup_line, 'ok_or_else', state),
                    span(lookup_line+2, '?', state),
                ])
                if side and fault == 'missing-lookup-continuation' and copy_number == 0:
                    root['regions'].pop()
                copies.append(dict(name='_RNC'+symbol[2:]+'s2_0B9_', count=state,
                    filenames=['/src/' + file], regions=[span(lookup_line, '{',state),
                    span(lookup_line+1,'anyhow::anyhow!',state), span(lookup_line+2,'}',state)]))
                raw = [[array, 21, array+13, 22, state, 0, 0, 0]] if side else [span(array, 'vec!', state)]
                for record in (array+1, array+5, array+9):
                    first = lines[record - 1].index('SbomProperty') + 1
                    if not side or record != array+9:
                        raw.append([record, first, record + 3, first + 1, state, 0, 0, 0])
                    literal = entries[record - array].split('"')[1]
                    raw.extend([span(record + 1, '"' + literal + '"', state),
                                span(record + 1, 'into', state)])
                if side:
                    if fault == 'foreign-record-owner' and copy_number == 0:
                        copies.append(dict(name='foreign',count=1,filenames=['/src/' + file],regions=[raw.pop()]))
                    root['regions'].extend(raw)
                else:
                    copies.append(dict(name='_RNC'+symbol[2:]+'s1_0B9_', count=state,
                                       filenames=['/src/' + file], regions=raw))
                callback = lines.index(advisories[0]) + 1
                copies.append(dict(name='_RNC'+symbol[2:]+'0B9_', count=1,
                    filenames=['/src/' + file], regions=[span(callback,'{',1),
                    span(callback+1,'describe',1),span(callback+2,'}',1)]))
                copies.append(root)
            if side and fault == 'source-value':
                lines[array+2] = lines[array+2].replace('finding.summary', 'finding.id')
            work = coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [row for owner in copies for row in owner['regions']], work), work)))
            docs.append(copies)
        def owners(base, head):
            for document, members in zip((base, head), docs):
                document['data'][0]['functions'] = members
                document['data'][0]['files'][0]['expansions'] = []
        return self.compare(before=counts[0], after=counts[1], mutate=owners, filename=file,
            sources=tuple({file: ('\n'.join(lines) + '\n').encode()} for lines in sources))

    def test_sbom_advisory_properties_keep_all_observed_initializer_copies(self):
        result = self.sbom_advisory_property_array_compare()
        proof, = [row for row in result['retained_replacement_obligations']
                  if row.get('kind') == 'retained-sbom-advisory-properties']
        self.assertIn([15, 15], proof['pairs'])
        self.assertEqual(result['deleted_mapped'], 0)
        for fault in ('redistributed-count', 'foreign-record-owner', 'source-value'):
            with self.subTest(fault=fault):
                try:
                    rejected = self.sbom_advisory_property_array_compare(fault)
                except ValueError:
                    continue
                self.assertFalse(any(row.get('kind') == 'retained-sbom-advisory-properties'
                                     for row in rejected['retained_replacement_obligations']))

    def test_sbom_identity_lookup_retains_the_call_and_error_propagation(self):
        def lookup_pairs(result):
            return [row['pairs'] for row in result.get('retained_replacement_obligations', [])
                    if row.get('kind') == 'closed-retained-callback-island' and [4,4] in row['pairs']]
        result = self.sbom_advisory_property_array_compare()
        self.assertEqual(lookup_pairs(result), [[[4,4],[5,5],[6,6]]])
        try:
            missing = self.sbom_advisory_property_array_compare('missing-lookup-continuation')
        except ValueError:
            return
        self.assertFalse(lookup_pairs(missing))

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

    def same_qualified_positive_routine_fixture(self,kind='sync',fault=None):
     old=['#[cfg(test)]','mod tests {','    #[tokio::test]','    async fn routine() {',
          '        let error = action_old()','            .await','            .expect_err("must refuse unavailable evidence");',
          '        assert_eq!(','            error.old_kind(),','            "unavailable"','        );','    }','}']
     if kind=='sync':
      new=[*old[:2],'    #[test]','    fn routine() {','        let error = action_new();',
           '        assert_eq!(','            error.new_kind(),','            "unavailable"','        );','    }','}']
     else:
      new=[*old[:5],old[5],old[6],'        let typed = error.downcast::<E>().expect("typed error");',*old[7:]]
      new[4]=new[4].replace('action_old','action_new');new[9]=new[9].replace('old_kind','new_kind')
     sources=[old,new];documents=[]
     for side,source in enumerate(sources):
      parent=f'_RNvNtCs{side+1}_7example5tests7routine';async_body=side==0 or kind=='async'
      first,last=4,len(source)-1;assert_line=next(i for i,t in enumerate(source,1) if 'assert_eq!' in t)
      def row(a,b,c,d,count=1):return [a,b,c,d,count,0,0,0]
      def owner(name,regions):return dict(name=name,count=1,filenames=['/src/example.rs'],regions=regions,branches=[],mcdc_records=[])
      entry=row(first,source[first-1].index('fn')+1,first,source[first-1].index('{'))
      closing=row(last,5,last,6)
      active=[row(5,13,5,len(source[4])+1)]
      if async_body:active.extend([row(6,14,6,19),row(7,14,7,len(source[6])+1)])
      if side and kind=='async':active.append(row(8,13,8,len(source[7])+1))
      active.extend([row(assert_line,9,assert_line,19),row(assert_line+1,13,assert_line+1,len(source[assert_line])+1)])
      if async_body:
       body_col=source[3].index('{')+1
       documents.append([owner(parent,[entry,row(assert_line,9,assert_line+3,11),closing]),
         owner('_RNC'+parent[2:]+'0B5_',[row(first,body_col,first,body_col+1),*active])])
      else:documents.append([owner(parent,[entry,row(assert_line,9,assert_line+3,11),*active,closing])])
     if fault=='hidden-cold-region':documents[1][-1]['regions'][-2][4]=0
     elif fault=='cold-entry':documents[1][-1]['count']=0
     elif fault=='foreign-touching-owner':
      o=copy.deepcopy(documents[1][-1]);o['name']='foreign';o['count']=0
      for r in o['regions']:r[4]=0
      documents[1].append(o)
     elif fault=='missing-body' and kind=='async':documents[1].pop()
     elif fault=='different-declaration':
      new[3]=new[3].replace('routine','another');
      for o in documents[1]:o['name']=o['name'].replace('7routine','7another')
     elif fault=='different-module':
      for o in documents[1]:o['name']=o['name'].replace('5tests','5other')
     elif fault=='different-disambiguator':
      for o in documents[1]:o['name']=o['name'].replace('7routine','s_7routine')
     elif fault=='missing-copy':
      for o in copy.deepcopy(documents[0]):o['name']=o['name'].replace('Cs1_','Cs3_');documents[0].append(o)
     elif fault=='raw-channel-flag':documents[1][-1]['regions'][0][5]=1
     elif fault=='branch-channel':documents[1][-1]['branches']=[[4,1,4,2,1,0,0,0,0]]
     elif fault=='unknown-test-attribute':new[2]='    #[other::test]'
     elif fault=='result-type':new[3]=new[3].replace('() {','() -> Result<()> {')
     elif fault=='missing-test-gate':new[0]='#[cfg(feature = "other")]'
     counts=[]
     for owners in documents:
      work=coverage._ObserverWork();counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments([r for o in owners for r in o['regions']],work),work)))
     def owners(base,head):
      for document,members in zip((base,head),documents):
       document['data'][0]['functions']=members
       document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
     return self.compare(before=counts[0],after=counts[1],mutate=owners,sources=(
      {'example.rs':('\n'.join(old)+'\n').encode()},{'example.rs':('\n'.join(new)+'\n').encode()}))

    def test_existing_positive_sync_rewrite_keeps_zero_deletion_credit(self):
     result=self.same_qualified_positive_routine_fixture()
     self.assertEqual(result['deleted_mapped'],0)
     self.assertEqual(result['deleted_summary_found'],0)

    def test_same_qualified_async_routine_retains_await_and_refusal(self):
     result=self.same_qualified_positive_routine_fixture('async')
     proof,=[r for r in result.get('retained_replacement_obligations',[]) if r.get('kind')=='same-qualified-positive-test']
     self.assertEqual([len(side[0]) for side in proof['phase_forests']],[2,2])
     self.assertIn([6,6],proof['pairs']);self.assertIn([7,7],proof['pairs'])

    def test_same_qualified_positive_routine_rejects_cold_foreign_or_missing_evidence(self):
     for fault in ('hidden-cold-region','cold-entry','foreign-touching-owner','missing-body','different-declaration',
                   'different-module','different-disambiguator','missing-copy','raw-channel-flag','branch-channel',
                   'unknown-test-attribute','result-type','missing-test-gate'):
      with self.subTest(fault=fault):
       try:result=self.same_qualified_positive_routine_fixture('async',fault)
       except ValueError:continue
       self.assertFalse(any(r.get('kind')=='same-qualified-positive-test' for r in result.get('retained_replacement_obligations',[])))

    def local_impl_fixture(self,fault=None):
     old=['#[cfg(test)]','mod tests {','    #[tokio::test]','    async fn routine() {','        struct Local;',
          '        impl Source for Local {','            fn old_call(&self) -> Pin<Box<dyn Future<Output = ()>>> {',
          '                Box::pin(async move {','                    checked_old();','                })','            }','        }',
          '        route_old().await;','    }','}']
     new=[line.replace('old_call','new_call').replace('checked_old','checked_new').replace('route_old','route_new') for line in old]
     sources=[old,new];documents=[]
     for side,source in enumerate(sources):
      root=f'_RNvNtCs{side+1}_7example5tests7routine'
      local=f'_RNvXNCNvNtCs{side+1}_7example5tests7routine0NtB2_5LocalNtB8_6Source8'+('old_call' if side==0 else 'new_call')
      nested=f'_RNCNvXNCNvNtCs{side+1}_7example5tests7routine0NtB4_5LocalNtBa_6Source8'+('old_call' if side==0 else 'new_call')+'0Ba_'
      def row(line,start,end,count=1):return [line,start,line,end,count,0,0,0]
      def owner(name,regions):return dict(name=name,count=1,filenames=['/src/example.rs'],regions=regions,branches=[],mcdc_records=[])
      outer_col=source[3].index('{')+1;inner_col=source[7].index('{')+1
      members=[owner(root,[row(4,11,source[3].index('{')),row(13,9,len(source[12])+1),row(14,5,6)]),
          owner('_RNC'+root[2:]+'0B5_',[row(4,outer_col,outer_col+1),row(13,9,len(source[12])+1)]),
          owner(local,[row(7,13,source[6].index('{')),row(8,17,25),row(11,13,14)]),
          owner(nested,[row(8,inner_col,inner_col+1),row(9,21,len(source[8])+1),row(10,17,18)])]
      documents.append(members)
     if fault=='cold-local-region':documents[1][3]['regions'][1][4]=0
     elif fault=='cold-local-entry':documents[1][2]['count']=0
     elif fault=='foreign-local-namespace':
      for member in documents[1][2:]:member['name']=member['name'].replace('7routine','7another')
     elif fault=='wrong-trait':
      for member in documents[1][2:]:member['name']=member['name'].replace('6Source','6Differ')
     elif fault=='wrong-self-type':
      for member in documents[1][2:]:member['name']=member['name'].replace('5Local','5Other')
     elif fault=='missing-local-body':documents[1].pop()
     elif fault=='extra-local-body':documents[1].append(copy.deepcopy(documents[1][3]))
     elif fault=='wrong-body-counter':documents[1][3]['regions'][0][4]=2
     elif fault=='wrong-closing-counter':documents[1][2]['regions'][-1][4]=2
     elif fault=='raw-flag':documents[1][3]['regions'][0][5]=1
     counts=[]
     for members in documents:
      work=coverage._ObserverWork();counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments([r for o in members for r in o['regions']],work),work)))
     def owners(base,head):
      for document,members in zip((base,head),documents):
       document['data'][0]['functions']=members;document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
     return self.compare(before=counts[0],after=counts[1],mutate=owners,sources=(
       {'example.rs':('\n'.join(old)+'\n').encode()},{'example.rs':('\n'.join(new)+'\n').encode()}))

    def test_positive_local_impl_forest_keeps_source_bound_constructor_and_body(self):
     result=self.local_impl_fixture()
     proof,=[r for r in result.get('retained_replacement_obligations',[]) if r.get('kind')=='same-qualified-positive-test']
     self.assertEqual([len(side[0]) for side in proof['phase_forests']],[4,4])
     self.assertEqual(proof['mapped_credit'],[0,0]);self.assertEqual(proof['summary_credit'],[0,0])
     self.assertEqual(proof['local_impl_roles'][0],proof['local_impl_roles'][1])

    def test_local_impl_forest_refuses_cold_foreign_or_incomplete_members(self):
     for fault in ('cold-local-region','cold-local-entry','foreign-local-namespace','wrong-trait','wrong-self-type',
                   'missing-local-body','extra-local-body','wrong-body-counter','wrong-closing-counter','raw-flag'):
      with self.subTest(fault=fault):
       try:r=self.local_impl_fixture(fault)
       except ValueError:continue
       self.assertFalse(any(p.get('kind')=='same-qualified-positive-test' and any(p.get('local_impl_roles',())) for p in r.get('retained_replacement_obligations',[])))

    def test_local_scope_decoder_is_opt_in_and_requires_complete_backreferences(self):
     symbol='_RNvXNCNvNtCs1_7example5tests7routine0NtB2_5LocalNtB8_6Source8old_call'
     self.assertIsNone(coverage.nominal_method_path(symbol))
     shape=coverage.nominal_method_path(symbol,local_scope=True)
     self.assertEqual(shape.self_type[-1],('Local',''))
     self.assertEqual(shape.method,('old_call',''))
     for bad in (symbol.replace('B2_','B9_'),symbol.replace('routine0','routine1'),symbol+'extra'):
      self.assertIsNone(coverage.nominal_method_path(bad,local_scope=True))

    def projected_input_fixture(self,fault=None):
     old=['fn channel_sdks(channel: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {', '    channel', '        .get("releases")', '        .and_then(serde_json::Value::as_array)', '        .into_iter()', '        .flatten()', '        .flat_map(|release| {', '            release.get("sdk").into_iter().chain(', '                release', '                    .get("sdks")', '                    .and_then(serde_json::Value::as_array)', '                    .into_iter()', '                    .flatten(),', '            )', '        })', '}', '', '/// Collect every SDK feature band from one channel document.', 'fn parse_channel_sdks(channel: &serde_json::Value, prerelease: bool) -> Vec<DotnetVersion> {', '    let mut versions: Vec<_> = channel_sdks(channel)', '        .filter_map(|sdk| {', '            sdk.get("version")', '                .and_then(serde_json::Value::as_str)', '                .filter(|version| !version.is_empty())', '                .map(|version| DotnetVersion {', '                    version: version.to_owned(),', '                    prerelease,', '                })', '        })', '        .collect();', '    versions.sort_by(|a, b| super::common::version_cmp(&b.version, &a.version));', '    versions.dedup_by(|a, b| a.version == b.version);', '    versions', '}']
     new=['fn channel_sdks(channel: &serde_json::Value) -> impl Iterator<Item = (&serde_json::Value, &serde_json::Value)> {', '    channel', '        .get("releases")', '        .and_then(serde_json::Value::as_array)', '        .into_iter()', '        .flatten()', '        .flat_map(|release| {', '            release.get("sdk").into_iter().chain(', '                release', '                    .get("sdks")', '                    .and_then(serde_json::Value::as_array)', '                    .into_iter()', '                    .flatten(),', '            )', '                .map(move |sdk| (release, sdk))', '        })', '}', '', '/// Collect every SDK feature band from one channel document.', 'fn parse_channel_sdks(channel: &serde_json::Value, prerelease: bool) -> Vec<DotnetVersion> {', '    let mut versions: Vec<_> = channel_sdks(channel)', '        .filter_map(|(_, sdk)| {', '            sdk.get("version")', '                .and_then(serde_json::Value::as_str)', '                .filter(|version| !version.is_empty())', '                .map(|version| DotnetVersion {', '                    version: version.to_owned(),', '                    prerelease,', '                })', '        })', '        .collect();', '    versions.sort_by(|a, b| super::common::version_cmp(&b.version, &a.version));', '    versions.dedup_by(|a, b| a.version == b.version);', '    versions', '}']
     if fault=='standard-unused-import':new=['use std::collections::BTreeMap;']+new
     if fault=='impure-first-field':new=[s.replace('(release, sdk)','(inspect(release), sdk)') for s in new]
     if fault=='unknown-producer-receiver':
      old=[s.replace('release.get("sdk")','release.custom("sdk")') for s in old];new=[s.replace('release.get("sdk")','release.custom("sdk")') for s in new]
     if fault=='wrong-projected-value':new=[s.replace('(release, sdk)','(sdk, release)') for s in new]
     elif fault=='changed-producer':new=[s.replace('.get("sdks")','.get("other")') for s in new]
     elif fault=='changed-caller':new=[s.replace('sdk.get("version")','sdk.get("other")') for s in new]
     elif fault=='trait-import':new=['use extension::MapTrait;']+new
     sources=[old,new];documents=[]
     for side,source in enumerate(sources):
      first=next(i for i,s in enumerate(source,1) if s.startswith('fn parse_channel_sdks'))
      last=len(source);cb=next(i for i,s in enumerate(source,1) if '.filter_map(' in s)
      cbend=next(i for i in range(cb+1,last+1) if source[i-1]=='        })')
      filterline=next(i for i in range(first,last+1) if '.filter(|version|' in source[i-1]);record=filterline+1
      sort=next(i for i in range(first,last+1) if 'versions.sort_by' in source[i-1]);dedup=sort+1
      members=[]
      for number,state in enumerate((0,1),1):
       root=f'_RNvCs{side*2+number}_7example18parse_channel_sdks'
       def row(line,start,end,count=state):return [line,start,line,end,count,0,0,0]
       def owner(name,rows):return dict(name=name,count=state,filenames=['/src/example.rs'],regions=rows,branches=[],mcdc_records=[])
       brace=source[cb-1].index('{')+1
       members += [owner(root,[row(first,1,source[first-1].index('{')),row(first+1,9,len(source[first])+1),row(cbend+1,9,len(source[cbend])+1),row(last,1,2)]),
         owner('_RNC'+root[2:]+'0B3_',[row(cb,brace,brace+1),row(cb+1,13,len(source[cb])+1),row(cbend,9,10)]),
         owner('_RNCNC'+root[2:]+'00B5_',[row(filterline,source[filterline-1].index('!')+1,len(source[filterline-1])-1)]),
         owner('_RNCNC'+root[2:]+'0s_0B5_',[row(record,source[record-1].index('DotnetVersion')+1,len(source[record-1])+1),row(record+1,21,len(source[record])+1),row(record+2,21,len(source[record+1])+1)]),
         owner('_RNC'+root[2:]+'s_0B3_',[row(sort,29,len(source[sort-1]))]),
         owner('_RNC'+root[2:]+'s0_0B3_',[row(dedup,30,len(source[dedup-1]))])]
      documents.append(members)
     if fault=='lost-hot-region':documents[1][-5]['regions'][1][4]=0
     elif fault=='missing-cold-copy':documents[1]=documents[1][6:]
     elif fault=='extra-cold-copy':
      for o in copy.deepcopy(documents[1][:6]):o['name']=o['name'].replace('Cs3_','Cs9_');documents[1].append(o)
     elif fault=='foreign-callback':documents[1][1]['name']=documents[1][1]['name'].replace('18parse_channel_sdks','18parse_channel_sdkz')
     elif fault=='wrong-ordinal':documents[1][2]['name']=documents[1][2]['name'].replace('00B5_','0s0_0B5_')
     elif fault=='raw-channel':documents[1][1]['regions'][0][5]=1
     elif fault=='wrong-header-coordinate':documents[1][1]['regions'][0][1]-=1
     counts=[]
     for members in documents:
      work=coverage._ObserverWork();counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments([r for o in members for r in o['regions']],work),work)))
     def owners(base,head):
      for document,members in zip((base,head),documents):document['data'][0]['functions']=members;document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
     return self.compare(before=counts[0],after=counts[1],mutate=owners,sources=tuple({'example.rs':('\n'.join(s)+'\n').encode()} for s in sources))
    def test_projected_input_preserves_complete_hot_and_cold_forests(self):
     result=self.projected_input_fixture();proof,=[r for r in result.get('retained_replacement_obligations',[]) if r.get('kind')=='projected-iterator-input']
     self.assertEqual([len(s) for s in proof['forest_names']],[12,12]);self.assertEqual(proof['summary_credit'],[0,0]);self.assertEqual(proof['mapped_credit'],[0,0])
    def test_projected_input_allows_only_unused_standard_collection_import(self):
     result=self.projected_input_fixture('standard-unused-import')
     self.assertTrue(any(r.get('kind')=='projected-iterator-input' for r in result.get('retained_replacement_obligations',[])))
    def test_projected_input_refuses_changed_values_context_or_incomplete_forests(self):
     for fault in ('impure-first-field','unknown-producer-receiver','wrong-projected-value','changed-producer','changed-caller','trait-import','lost-hot-region','missing-cold-copy','extra-cold-copy','foreign-callback','wrong-ordinal','raw-channel','wrong-header-coordinate'):
      with self.subTest(fault=fault):
       try:result=self.projected_input_fixture(fault)
       except ValueError:continue
       self.assertFalse(any(r.get('kind')=='projected-iterator-input' for r in result.get('retained_replacement_obligations',[])))

    def closed_sync_fixture(self,callbacks=True,fault=None,factory=False,array=False):
     old=['#[cfg(test)]','mod tests {','    #[test]','    fn routine() {',
          '        let finding = Row {','            id: "fixture",','        };']
     if callbacks:old+=['        let values = items().map(|item| item.name()).collect::<Vec<_>>();',
                       '        assert!(items().any(|item| item.name() == "fixture"));']
     old+=['        assert!(finding.id == "fixture");','    }','}']
     if factory:
      old[4]='        let finding = |id: &str| Row {'
      old[6:6]=['            name: id.into(),']
      old[-3]='        assert!(finding("sample").id == "fixture");'
     if array:
      old[4]='        let finding = [Row {'
      old[6]='        }];'
      old[-3]='        assert!(finding[0].id == "fixture");'
     new=old[:5]+['            status: Status::Applicable,']+old[5:]
     if callbacks:
      old=[line.replace('Row {','serde_json::json!({').replace('id: "fixture",','"id": "fixture"').replace('        };','        });') for line in old]
      new=old[:5]+['            "status": "applicable",']+old[5:]
     if callbacks:new=[line.replace('.any(|item|','.find(|(_, item)|') for line in new]
     if fault=='changed-json-value':new=[line.replace('"id": "fixture"','"id": "other"') for line in new]
     elif fault=='live-json-value':new=[line.replace('"status": "applicable"','"status": side_effect()') for line in new]
     elif fault=='impure-record-field':new=[line.replace('Status::Applicable','Status::from_code()') for line in new]
     elif fault=='changed-old-assert':new=[line.replace('finding.id == "fixture"','finding.id == "other"') for line in new]
     if fault=='foreign-context':new=[line.replace('mod tests','mod other') for line in new]
     elif fault=='missing-test-gate':new[0]='#[cfg(feature = "other")]'
     elif fault=='unknown-callback':new=[line.replace('.find(','.inspect(') for line in new]
     elif fault=='block-callback':new=[line.replace('| item.name() == "fixture"','| { item.name() == "fixture" }') for line in new]
     elif fault=='factory-parameter':new[4]=new[4].replace('&str','&Path')
     sources=[old,new];documents=[]
     for side,source in enumerate(sources):
      root=f'_RNvNtCs{side+1}_7example5tests7routine'
      def row(line,start,end,count=1):return [line,start,line,end,count,0,0,0]
      def owner(name,quantity,regions):return dict(name=name,count=quantity,filenames=['/src/example.rs'],regions=regions,branches=[],mcdc_records=[])
      last=len(source)-1
      members=[owner(root,1,[row(4,5,source[3].index('{')),row(5,9,len(source[4])+1),row(last-1,9,len(source[last-2])+1),row(last,5,6)])]
      if callbacks:
       for number,method in enumerate(('map','any' if side==0 else 'find')):
        line=[n for n,text in enumerate(source,1) if 'item.name()' in text][number]
        first=source[line-1].index('item.name()')+1;lastcol=first+len('item.name()' if number==0 else 'item.name() == "fixture"')
        ordinal=('0','s_0')[number if side==0 else 1-number]
        quantity=number+2
        members.append(owner('_RNC'+root[2:]+ordinal+'B5_',quantity,[row(line,first,first+len('item.name'),quantity),row(line,first+len('item.name()'),lastcol,quantity)] if number else [row(line,first,first+len('item'),quantity),row(line,first+len('item.'),lastcol-2,quantity)]))
      if factory:
       record=[row(n,source[n-1].index(': ')+3,len(source[n-1]),3) for n in range(6,8+side)]
       record.append(row(8+side,9,10,3))
       members.append(owner('_RNC'+root[2:]+'0B5_',3,record))
      if array:
       members[0]['regions'].extend(row(n,source[n-1].index(': ')+3,len(source[n-1])) for n in range(6,7+side))
      documents.append(members)
     if fault=='cold-root':documents[1][0]['count']=0;documents[1][0]['regions'][0][4]=0
     elif fault=='cold-child':documents[1][1]['count']=0;documents[1][1]['regions'][0][4]=0
     elif fault=='hidden-child-region':documents[1][1]['regions'][-1][4]=0
     elif fault=='missing-child':documents[1].pop()
     elif fault=='foreign-child':documents[1][1]['name']=documents[1][1]['name'].replace('7routine','7another')
     elif fault=='wrong-child-slot':documents[1][1]['regions'][0][1]-=1
     elif fault=='raw-channel':documents[1][1]['regions'][0][5]=1
     elif fault=='foreign-source':documents[1][1]['filenames']=['/src/other.rs']
     elif fault=='extra-cold-copy':
      for member in copy.deepcopy(documents[1]):
       member['name']=member['name'].replace('Cs2_','Cs9_');member['count']=0
       for r in member['regions']:r[4]=0
       documents[1].append(member)
     counts=[]
     for members in documents:
      work=coverage._ObserverWork();counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments([r for o in members for r in o['regions']],work),work)))
     def owners(base,head):
      for document,members in zip((base,head),documents):document['data'][0]['functions']=members;document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
     return self.compare(before=counts[0],after=counts[1],mutate=owners,sources=tuple({'example.rs':('\n'.join(s)+'\n').encode()} for s in sources))
    def test_closed_sync_test_forest_preserves_root_and_expression_callback_ownership(self):
     for callbacks in (False,True):
      with self.subTest(callbacks=callbacks):
       result=self.closed_sync_fixture(callbacks)
       proof,=[r for r in result.get('retained_replacement_obligations',[]) if r.get('kind')=='same-qualified-positive-test']
       self.assertEqual([len(s[0]) for s in proof['phase_forests']],[3,3] if callbacks else [1,1])
       self.assertEqual(proof['mapped_credit'],[0,0]);self.assertEqual(proof['summary_credit'],[0,0])
    def test_closed_sync_fixture_growth_preserves_prior_values_and_rejects_live_inputs(self):
     for callbacks,fault in ((True,'changed-json-value'),(True,'live-json-value'),(False,'impure-record-field'),(False,'changed-old-assert')):
      with self.subTest(fault=fault):
       try:result=self.closed_sync_fixture(callbacks,fault)
       except ValueError:continue
       self.assertFalse(any(r.get('kind')=='same-qualified-positive-test' for r in result.get('retained_replacement_obligations',[])))
    def test_closed_sync_cohort_refuses_cold_foreign_or_unsupported_members(self):
     for fault in ('cold-root','cold-child','hidden-child-region','missing-child','foreign-child','wrong-child-slot','raw-channel','foreign-source','extra-cold-copy','foreign-context','missing-test-gate','unknown-callback','block-callback'):
      with self.subTest(fault=fault):
       try:result=self.closed_sync_fixture(True,fault)
       except ValueError:continue
       self.assertFalse(any(r.get('kind')=='same-qualified-positive-test' for r in result.get('retained_replacement_obligations',[])))

    def test_closed_sync_record_factory_retains_its_compiled_child(self):
     result=self.closed_sync_fixture(False,factory=True)
     proof,=[r for r in result.get('retained_replacement_obligations',[]) if r.get('kind')=='same-qualified-positive-test']
     self.assertEqual([len(s[0]) for s in proof['phase_forests']],[2,2])
     self.assertEqual(proof['mapped_credit'],[0,0])
     for fault in ('factory-parameter','impure-record-field','cold-child','hidden-child-region',
                   'missing-child','foreign-child','wrong-child-slot','raw-channel'):
      with self.subTest(fault=fault):
       try:result=self.closed_sync_fixture(False,fault,factory=True)
       except ValueError:continue
       self.assertFalse(any(r.get('kind')=='same-qualified-positive-test' for r in result.get('retained_replacement_obligations',[])))

    def test_closed_sync_record_retains_a_single_element_array_fixture(self):
     result=self.closed_sync_fixture(False,array=True)
     proof,=[r for r in result.get('retained_replacement_obligations',[]) if r.get('kind')=='same-qualified-positive-test']
     self.assertEqual([len(s[0]) for s in proof['phase_forests']],[1,1])
     self.assertEqual(proof['summary_credit'],[0,0])

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

    def result_test_record_update_compare(self, fault=None):
        old = ['use other::Unused;', '#[cfg(test)]', 'mod tests {', '    #[test]',
               '    fn handoff() -> anyhow::Result<()> {', '        temp_env::with_var(',
               '            "TEST_ROOT",', '            Some(root()),',
               '            || -> anyhow::Result<()> {', '                let policy = Policy {',
               '                    names: vec!["fixture".into()],', '                };',
               '                assert!(admitted(&policy));', '                Ok(())',
               '            },', '        )', '    }', '}']
        new = old[:11] + ['                    ..Policy::default()'] + old[11:]
        new[0] = 'use other::Separate;' if fault != 'changed-binding' else 'use other::Policy;'
        documents = []
        for side, source in enumerate((old, new)):
            def slot(a, start, b, end, count=1):
                return [a, start, b, end, count, 0, 0, 0]
            root = f'_RNvNtNtCs{side+1}_7omg_lib7example5tests7handoff'
            child = '_RNC' + root[2:] + '0B7_'
            opening = source[8].index('{') + 1
            members = [dict(name=root, count=1, filenames=['/src/example.rs'], regions=[
                slot(5, 5, 5, source[4].index('{')+1), slot(6, 9, 6, 27),
                slot(17+side, 5, 17+side, 6)]),
                dict(name=child, count=1, filenames=['/src/example.rs'], regions=[
                    slot(9, opening, 9, opening+1), slot(10, 30, 12+side, 18),
                    slot(13+side, 17, 13+side, 39), slot(13+side, 40, 13+side, 41,
                        int(not (side and fault == 'lost-region'))),
                    slot(14+side, 17, 15+side, 14)])]
            if side and fault != 'missing-refinement':
                start = source[10].index('"fixture"') + 1
                members[1]['regions'].append(slot(11, start, 11, start+len('"fixture"')))
            documents.append(members)

        def owners(base, head):
            for document, members in zip((base, head), documents):
                document['data'][0]['functions'] = members
                document['data'][0]['files'][0].update(expansions=[], branches=[], mcdc_records=[])
        counts = []
        for members in documents:
            work = coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [row for owner in members for row in owner['regions']], work), work)))
        return self.compare(before=counts[0], after=counts[1], mutate=owners,
            sources=({'example.rs': ('\n'.join(old)+'\n').encode()},
                     {'example.rs': ('\n'.join(new)+'\n').encode()}))

    def test_result_test_record_update_preserves_closed_callback_forest(self):
        receipt = self.result_test_record_update_compare()
        proof, = [row for row in receipt['retained_replacement_obligations']
                  if row['kind'] == 'retained-record-update-forest']
        self.assertIn([9, 9], proof['pairs'])
        self.assertEqual(receipt['deleted_mapped_hit'], 0)
        for fault in ('changed-binding', 'missing-refinement', 'lost-region'):
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):
                    self.result_test_record_update_compare(fault)

    def test_unit_test_record_update_preserves_closed_root(self):
        def compare(fault=None):
            old = ['#[cfg(test)]', 'mod tests {', '    #[test]', '    fn handoff() {',
                   '        let policy = Policy {', '            end: vec!["last".to_string()],',
                   '        };', '        assert!(admitted(&policy));', '    }', '}']
            new = old[:6] + ['            ..Policy::default()'] + old[6:]
            documents = []
            for side, source in enumerate((old, new)):
                def slot(a, start, b, end, count=1):
                    return [a, start, b, end, count, 0, 0, 0]
                root = f'_RNvNtNtCs{side+1}_7omg_lib7example5tests7handoff'
                rows = [slot(4, 5, 4, source[3].index('{')+1), slot(5, 22, 7+side, 10),
                        slot(6, 23, 6, 27), slot(8+side, 9, 8+side, 34),
                        slot(8+side, 35, 8+side, 36, int(not (side and fault == 'lost-retained-hit'))),
                        slot(9+side, 5, 9+side, 6)]
                if side and fault != 'missing-refinement':
                    first = source[5].index('"last"')+1
                    rows.append(slot(6, first, 6, first+6, int(fault != 'unexecuted-refinement')))
                members = [dict(name=root, count=1, filenames=['/src/example.rs'], regions=rows)]
                if side and fault == 'foreign-owner':
                    members.append(dict(name='_RNC'+root[2:]+'0B7_', count=0,
                        filenames=['/src/example.rs'], regions=[slot(6, 23, 6, 27, 0)]))
                documents.append(members)

            def owners(base, head):
                for document, members in zip((base, head), documents):
                    document['data'][0]['functions'] = members
                    document['data'][0]['files'][0].update(expansions=[], branches=[], mcdc_records=[])
            counts = []
            for members in documents:
                work = coverage._ObserverWork()
                counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                    [row for owner in members for row in owner['regions']], work), work)))
            return self.compare(before=counts[0], after=counts[1], mutate=owners,
                sources=({'example.rs': ('\n'.join(old)+'\n').encode()},
                         {'example.rs': ('\n'.join(new)+'\n').encode()}))

        receipt = compare()
        proof, = [row for row in receipt['retained_replacement_obligations']
                  if row.get('kind') == 'retained-record-update-forest']
        self.assertIn([5, 5], proof['pairs'])
        self.assertIn([7, 8], proof['pairs'])
        self.assertEqual(receipt['deleted_mapped_hit'], 0)
        self.assertFalse(any(row.get('kind') == 'retained-record-update-forest'
                             for row in compare('missing-refinement')['retained_replacement_obligations']))
        for fault in ('unexecuted-refinement', 'lost-retained-hit', 'foreign-owner'):
            with self.subTest(fault=fault):
                with self.assertRaises(ValueError):
                    compare(fault)

    def test_result_test_coverage_binds_the_environment_callback_and_assertion_entries(self):
        source = ['#[cfg(test)]', 'mod tests {', '    #[test]',
                  '    fn handoff() -> anyhow::Result<()> {', '        temp_env::with_var(',
                  '            "TEST_ROOT",', '            Some(root()),',
                  '            || -> anyhow::Result<()> {', '                assert!(',
                  '                    admitted()', '                );', '                Ok(())',
                  '            },', '        )', '    }', '}']
        root_name = '_RNvNtNtCs1_7omg_lib7example5tests7handoff'
        file = '/src/example.rs'
        root = dict(name=root_name, count=2, filenames=[file], regions=[
            [4,5,4,source[3].index('{')+1,2,0,0,0], [15,5,15,6,2,0,0,0]])
        opening = source[7].index('{')+1
        child = dict(name='_RNC'+root_name[2:]+'0B7_', count=1, filenames=[file], regions=[
            [8,opening,8,opening+1,1,0,0,0], [9,17,9,24,1,0,0,0], [13,13,13,14,1,0,0,0]])

        def observe(line, texts=source, owner=child):
            return coverage.zero_arg_callback_fragment(texts, (4,15,[root]), [root,owner],
                {root['name']:1,owner['name']:1}, line, line, coverage._construct_inventory(texts,[1_000_000]),
                [1_000_000], environment_test=True)

        for line in (8,9):
            self.assertEqual(observe(line).line_states, ((1,),))
        self.assertIsNone(observe(10))
        wrong_extent = copy.deepcopy(child)
        wrong_extent['regions'][1][3] += 1
        self.assertIsNone(observe(9, owner=wrong_extent))
        foreign_owner = dict(child, name=child['name'].replace('7handoff','7unknown'))
        self.assertIsNone(observe(9, owner=foreign_owner))
        changed = source[:4] + ['        temp_env::different('] + source[5:]
        self.assertIsNone(observe(8, texts=changed))

    def test_initial_async_test_record_requires_its_own_eager_body_counters(self):
        source = ['#[cfg(test)]', 'mod tests {', '    #[tokio::test]',
                  '    async fn verify() -> anyhow::Result<()> {',
                  '        use fixture::Spare;', '        let policy = Policy {',
                  '            grade: Grade::Verified,', '            ..Policy::default()',
                  '        };', '        Ok(())', '    }', '}']
        declaration = source[3]
        opening = declaration.index('{')+1
        root = dict(name='_RNvNtNtCs1_7omg_lib7example5tests6verify',
                    filenames=['/src/example.rs'], count=1, regions=[
                        [4,11,4,opening-1,1,0,0,0], [11,5,11,6,1,0,0,0]])
        child = dict(root, name='_RNC'+root['name'][2:]+'0B7_', regions=[
            [4,opening,4,opening+1,1,0,0,0], [6,13,6,19,1,0,0,0], [6,22,9,10,1,0,0,0]])

        def observe(lines=source, owners=(root,child)):
            return coverage.initial_async_test_record('src/example.rs', lines, dict.fromkeys(range(6,10),1),
                (4,11,[root]), owners, Counter(owner['name'] for owner in owners),
                coverage._construct_inventory(lines,[1_000_000]), 6, 9, [1_000_000])

        self.assertEqual(observe()[1]['regions'], child['regions'][1:])
        rebound = source[:4] + ['        use fixture::Policy;'] + source[5:]
        self.assertIsNone(observe(lines=rebound))
        cold = copy.deepcopy(child)
        cold['regions'][2][4] = 0
        self.assertIsNone(observe(owners=(root,cold)))
        extra = dict(root, name='unexpected', regions=[child['regions'][1]])
        self.assertIsNone(observe(owners=(root,child,extra)))

    def test_async_test_expected_error_claims_only_the_unchanged_result_call(self):
        source = ['#[cfg(test)]', 'mod tests {', '    #[tokio::test]',
                  '    async fn verify() -> anyhow::Result<()> {',
                  '        let error = fixture().await', '            .expect_err("owned fixture refused");',
                  '        Ok(())', '    }', '}']
        opening = source[3].index('{')+1
        root = dict(name='_RNvNtNtCs1_7omg_lib7example5tests6verify',
                    filenames=['/src/example.rs'], count=1, regions=[
                        [4,11,4,opening-1,1,0,0,0], [8,5,8,6,1,0,0,0]])
        literal = '"owned fixture refused"'
        start = source[5].index(literal)+1
        child = dict(root, name='_RNC'+root['name'][2:]+'0B7_', regions=[
            [4,opening,4,opening+1,1,0,0,0], [6,14,6,24,1,0,0,0], [6,start,6,start+len(literal),1,0,0,0]])

        def observe(lines=source, owner=child):
            return coverage.async_test_expected_error('src/example.rs', lines, {6:1},
                (4,8,[root]), (root,owner), Counter((root['name'],owner['name'])),
                coverage._construct_inventory(lines,[1_000_000]), 6, 6, [1_000_000])

        self.assertEqual(observe()[1]['regions'], child['regions'][1:])
        call_changed = source[:4]+['        let error = another_fixture()']+source[5:]
        self.assertEqual(observe(lines=call_changed)[0], observe()[0])
        self.assertIsNone(observe(lines=source[:4]+['        fixture().await']+source[5:]))
        extra = dict(child, regions=child['regions']+[[6,13,6,14,1,0,0,0]])
        self.assertIsNone(observe(owner=extra))
        owners=[root,child]
        files={'/src/example.rs':'src/example.rs'}
        work=[1_000_000]
        inventories=tuple(coverage._construct_inventory(lines,work) for lines in (source,call_changed))
        pairs,receipts=coverage.positive_source_fragments(
            'src/example.rs',source,call_changed,{6:1},{6:1},owners,owners,files,files,
            [(5,6,5,6,[6])],work,construct_inventories=inventories,macro_expansions=([],[]))
        self.assertEqual(pairs,{6:6})
        receipt,=receipts
        self.assertEqual(receipt['kind'],'async-test-expected-error-call')
        self.assertEqual(receipt['async_copies']['base'][0]['body'],child['name'])
        self.assertEqual(receipt['async_fragment_regions'][0]['base_range'],[6,6])

    def test_runtime_record_counts_are_bound_to_the_literal_install_loop(self):
        def observe(insert=False, fault=None):
            source=['#[cfg(test)]','mod tests {','    async fn incremental_updates_fixture() -> Result<()> {',
                    '        for (installed, candidate, compatible) in [',
                    '            (Some("1.0"), "2.0", false),',
                    '            (None, "1.0", true),','        ] {',
                    '            let versions = TempDir::new()?;',
                    '            let manager = RustManager {',
                    '                versions_dir: versions.path().to_path_buf(),',
                    '                client: download_client(),','            };','        }','        Ok(())','    }','}']
            factory='crate::runtimes::security::RuntimeSecurity::fixture'
            if insert:
                source.insert(9,f'                security: {factory}(),')
            shift=int(insert)
            if fault=='different-literal':
                source[4]=source[4].replace('"2.0"','"3.0"')
            if fault=='dynamic':
                source[5]=source[5].replace('None','discover()')
            filename='/src/src/runtimes/rust.rs'
            symbol='_RNvNtNtNtCs1_7omg_lib8runtimes4rust5tests27incremental_updates_fixture'
            def slot(line,value,count):
                start=source[line-1].index(value)+1
                return [line,start,line,start+len(value),count,0,0,0]
            start=source[2].index('{')+1
            root=dict(name=symbol,count=1,filenames=[filename],regions=[[3,5,3,start-1,1,0,0,0]])
            case=source[4].strip().removesuffix(',')
            loop=[slot(4,'installed',2),slot(4,'candidate',1 if fault=='binding-count' else 2),
                  slot(4,'compatible',2),[4,source[3].index('[')+1,7,10,1,0,0,0],slot(5,case,1)]
            record=[slot(9,'manager',2),[9,27,12+shift,14,2,0,0,0],
                    slot(10+shift,'versions.path()',2),slot(11+shift,'download_client',2)]
            if insert:
                record.append(slot(10,factory,int(fault!='cold-field')*2))
            child=dict(root,name='_RNC'+symbol[2:]+'0B9_',regions=[[3,start,3,start+1,1,0,0,0],*loop,*record])
            owners=[root,child]
            if fault=='foreign-overlap':
                owners.append(dict(root,name='unbound',regions=[slot(4,'compatible',0)]))
            work=[2_000_000]
            counts=coverage._owner_line_counts({'regions':record},coverage._ObserverWork(work))
            return coverage.async_runtime_fixture_record(
                'src/runtimes/rust.rs',source,counts,(3,15+shift,[child]),owners,
                Counter(owner['name'] for owner in owners),coverage._construct_inventory(source,work),9,9,work)

        before,after=observe(),observe(True)
        self.assertIsNotNone(before)
        self.assertIsNotNone(after)
        self.assertEqual(before[0],after[0])
        self.assertEqual(after[1]['security_initializer'][0][4],2)
        self.assertNotEqual(observe(True,'different-literal')[0],before[0])
        for fault in ('dynamic','binding-count','foreign-overlap','cold-field'):
            with self.subTest(fault=fault):
                self.assertIsNone(observe(True,fault))

    def parameterized_rust_helper_record(self, insertion=False, fault=None, body_group=True, enum_role=False):
        source = ['#[cfg(test)]', '#[expect(clippy::unwrap_used)]', 'mod tests {',
            '    async fn install_fixture(corrupt: bool, missing_launcher: Option<&str>) -> Result<()> {',
            '        let ready = read_fixture().await?;',
            '        let manager = RustManager {',
            '            versions_dir: fixture.path(),',
            '            client: fixture.client(true)?,',
            '        };', '        Ok(())', '    }', '}']
        field = 'crate::runtimes::security::RuntimeSecurity::fixture'
        shift = int(insertion)
        if insertion: source.insert(6, f'            security: {field}(),')
        if enum_role:
            source[3]='    async fn rust_src_install_fixture(incremental: bool, selection: SourceSelection) -> Result<()> {'
            source[-1:-1]=['    #[derive(Clone, Copy, Debug)]',
                           '    enum SourceSelection { Wildcard, HostPreferred, Unavailable, Missing, }']
            if fault=='enum-payload': source[-2]=source[-2].replace('Wildcard,','Wildcard(u8),')
            elif fault=='enum-no-copy': source[-3]=source[-3].replace('Copy, ','')
            elif fault=='enum-variant': source[-2]=source[-2].replace('Missing','Other')
            elif fault=='enum-public': source[-2]=source[-2].replace('enum ','pub enum ')
            elif fault=='enum-alias': source[-2]='    type SourceSelection = Other;'
            elif fault=='enum-duplicate': source[-1:-1]=source[-3:-1]
            elif fault=='enum-foreign-module': source[-3:-1]=['    mod other {',*source[-3:-1],'    }']
            elif fault=='enum-reference': source[3]=source[3].replace('selection: SourceSelection','selection: &SourceSelection')

        if fault == 'parameter-type': source[3] = source[3].replace('corrupt: bool', 'corrupt: usize')
        elif fault == 'parameter-name': source[3] = source[3].replace('missing_launcher:', 'other:')
        elif fault == 'return-type': source[3] = source[3].replace('Result<()>', 'Option<()>')
        elif fault == 'public-helper': source[3] = source[3].replace('async fn', 'pub async fn')
        elif fault == 'production-module': source[0] = '#[cfg(feature = "fixture")]'
        elif fault == 'wrong-factory' and insertion: source[6] = source[6].replace('::fixture()', '::default()')
        opening = source[3].index('{') + 1
        end = 11 + shift
        root = dict(name='_RNvNtNtNtCs1_7omg_lib8runtimes4rust5tests15install_fixture', count=4,
                    filenames=['/src/runtimes/rust.rs'], regions=[[4,5,4,opening-1,4,0,0,0]])
        if enum_role: root['name']=root['name'].replace('15install_fixture','24rust_src_install_fixture')
        question = source[7+shift].index('?') + 1
        fields = [[6,13,6,20,4,0,0,0],
            [7+shift,source[6+shift].index('fixture')+1,7+shift,len(source[6+shift]),4,0,0,0],
            [8+shift,source[7+shift].index('fixture')+1,8+shift,question,4,0,0,0],
            [8+shift,question,8+shift,question+1,0,0,0,0]]
        if insertion:
            column = source[6].index(field) + 1 if field in source[6] else source[6].index('crate') + 1
            fields.append([7,column,7,column+len(field),4,0,0,0])
        raw = [[4,opening,4,opening+1,4,0,0,0], [5,13,5,18,4,0,0,0], *fields,
               [end,5,end,6,1,0,0,0]]
        child = dict(root, name='_RNC'+root['name'][2:]+'0B9_', regions=raw)
        owners = [root, child]
        if fault == 'missing-constructor': owners.remove(root)
        elif fault == 'duplicate-constructor': owners.append(copy.deepcopy(root))
        elif fault == 'foreign-constructor': root['name']=root['name'].replace('Cs1_','Cs9_')
        elif fault == 'foreign-body': child['name'] = child['name'].replace('15install_fixture','7another')
        elif fault == 'wrong-constructor-start': root['regions'][0][1]=11
        elif fault == 'cold-entry': child['regions'][0][4] = 0
        elif fault == 'body-under-count':
            child['count']=1;child['regions'][0][4]=1
            if insertion: fields[-1][4]=1
        elif fault == 'lost-field': fields[1][4] = 0
        elif fault == 'lost-cold': child['regions'].remove(fields[3])
        elif fault == 'channel': fields[1][7] = 1
        elif fault == 'duplicate-body': owners.append(copy.deepcopy(child))
        elif fault == 'foreign-overlap':
            owners.append(dict(child,name='foreign',regions=[fields[1][:]]))
        counts = coverage._owner_line_counts({'regions':fields},coverage._ObserverWork())
        if fault == 'missing-da': counts.pop(7+shift)
        return coverage.async_runtime_fixture_record('src/runtimes/rust.rs',source,counts,
            (4,end,[child if body_group else root]),owners,Counter(o['name'] for o in owners),
            coverage._construct_inventory(source,[1_000_000]),6,6,[1_000_000])

    def rust_inventory_boundary_fixture(self, fault=None):
        old = ['#[cfg(test)]', '#[expect(clippy::unwrap_used)]', 'mod tests {',
            '    async fn install_fixture(corrupt: bool, missing_launcher: Option<&str>) -> Result<()> {',
            '        let versions = TempDir::new()?;',
            '        if corrupt || missing_launcher.is_some() {',
            '            return Ok(());', '        }',
            '        let names: BTreeSet<_> = fs::read_dir(versions.path())?',
            '            .map(|entry| entry.map(|item| item.file_name()))',
            '            .collect::<std::io::Result<_>>()?;',
            '        assert_eq!(', '            names,', '            BTreeSet::from([',
            '                ".mutation.lock".into(),', '                "current".into(),',
            '                toolchain.name().into()', '            ])', '        );',
            '        Ok(())', '    }', '}']
        inserted = ['                format!(".admission-{}.lock", toolchain.name()).into(),',
                    '                ".security".into(),']
        new = old[:15] + inserted + old[15:]
        sources = [old,new]; documents = []
        for side, source in enumerate(sources):
            shift = 2 * side
            def row(line,start,end,hits=1): return [line,start,line,end,hits,0,0,0]
            def token(line,text,hits=1):
                start=source[line-1].index(text)+1
                return row(line,start,start+len(text),hits)
            root='_RNvNtNtNtCs1_7omg_lib8runtimes4rust5tests15install_fixture'
            def owner(name,count,regions):
                return dict(name=name,count=count,filenames=['/src/src/runtimes/rust.rs'],
                            regions=regions,branches=[],mcdc_records=[])
            opening=source[3].index('{')+1
            future=[row(4,opening,opening+1,4),token(5,'TempDir',4),token(5,'?',0),
                    token(6,'corrupt',4),token(7,'Ok',3),token(8,'}',3),
                    token(9,'fs::read_dir'),token(9,'?',0),token(10,'map'),token(11,'collect'),
                    token(11,'?',0),token(12,'assert_eq!'),token(14,'BTreeSet::from'),
                    [14,28,18+shift,14,1,0,0,0],token(15,'".mutation.lock"'),token(15,'into')]
            if side:
                future.extend([token(16,'format!'),token(16,'toolchain'),token(16,'name'),token(16,'into'),
                               token(17,'".security"'),token(17,'into')])
            future.extend([token(16+shift,'"current"'),token(16+shift,'into'),
                           token(17+shift,'toolchain'),token(20+shift,'Ok'),token(21+shift,'}',4)])
            documents.append([owner(root,4,[row(4,5,opening-1,4)]),owner('_RNC'+root[2:]+'0B9_',4,future)])
        body=documents[1][1]
        if fault == 'changed-receiver': sources[1][8] = sources[1][8].replace('versions.path()', 'other.path()')
        elif fault == 'changed-parameter': sources[1][3] = sources[1][3].replace('corrupt: bool','corrupt: usize')
        elif fault == 'changed-retained-term': sources[1][17] = sources[1][17].replace('current','different')
        elif fault == 'wrong-authority-term': sources[1][15] = sources[1][15].replace('.admission-', '.other-')
        elif fault == 'wrong-security-term': sources[1][16] = sources[1][16].replace('.security', '.otherdir')
        elif fault == 'cold-argument': next(r for r in body['regions'] if r[0]==18)[4]=0
        elif fault == 'missing-new-region': body['regions'].remove(next(r for r in body['regions'] if r[0]==16 and r[1]>24))
        elif fault == 'foreign-copy': body['name']=body['name'].replace('Cs1_', 'Cs9_')
        elif fault == 'duplicate-body': documents[1].append(copy.deepcopy(body))
        elif fault == 'foreign-overlap': documents[1].append(dict(body,name='foreign',regions=[next(r for r in body['regions'] if r[0]==16)]))
        elif fault == 'channel': next(r for r in body['regions'] if r[0]==16)[7]=1
        elif fault == 'cold-header': next(r for r in body['regions'] if r[0]==12)[4]=0
        counts=[]
        for document in documents:
            work=coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [r for owner in document for r in owner['regions']],work),work)))
        if fault == 'missing-da': counts[1]=[(n,c) for n,c in counts[1] if n!=16]
        def bind(base,head):
            for document,owners in zip((base,head),documents):
                document['data'][0]['functions']=owners
                document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
        filename='src/runtimes/rust.rs'
        return self.compare(before=counts[0],after=counts[1],mutate=bind,
            sources=({filename:('\n'.join(sources[0])+'\n').encode()},
                     {filename:('\n'.join(sources[1])+'\n').encode()}),filename=filename)

    def test_runtime_inventory_assertion_preserves_boundary_and_counts_new_authority_terms(self):
        receipt=self.rust_inventory_boundary_fixture()
        proof,=[r for r in receipt['positive_source_fragments'] if r['kind']=='async-runtime-inventory-assertion']
        self.assertEqual(proof['pairs'],[(12,12),(14,14),(15,15),(16,18),(17,19),(18,20)])
        self.assertEqual(len(proof['owners'][1]['security_terms']),6)
        self.assertEqual(receipt['deleted_mapped'],0)

    def test_runtime_inventory_assertion_refuses_cold_foreign_and_changed_source_roles(self):
        for fault in ('changed-receiver','changed-parameter','changed-retained-term','wrong-authority-term',
                      'wrong-security-term','cold-argument','missing-new-region','foreign-copy','duplicate-body',
                      'foreign-overlap','channel','cold-header','missing-da'):
            with self.subTest(fault=fault):
                try: receipt=self.rust_inventory_boundary_fixture(fault)
                except ValueError: continue
                self.assertFalse(any(row['kind']=='async-runtime-inventory-assertion'
                    for row in receipt.get('positive_source_fragments',[])))

    def sync_runtime_record_fixture(self, runtime='java', fault=None, observe=False, unit=False):
        manager={'java':'JavaManager','rust':'RustManager'}[runtime]
        declaration={'java':'publication_refuses_a_home_without_java_before_creating_a_version',
                     'rust':'mutation_lock_rejects_symlinks_without_changing_the_target'}[runtime]
        prefix=['#[cfg(test)]']+(['#[expect(clippy::unwrap_used)]'] if runtime=='rust' else [])
        prefix+=['mod tests {','    #[test]']+(['    #[cfg(unix)]'] if runtime=='rust' else [])
        old=prefix+[f'    fn {declaration}() -> Result<()> {{','        let versions = tempfile::tempdir()?;',
            f'        let manager = {manager} {{','            versions_dir: versions.path().to_path_buf(),',
            '            client: download_client(),','        };',
            '        let staging = begin_staged_install(versions.path())?;',
            '        assert!(manager.publish_install(&staging, "21").is_err());',
            '        assert!(!versions.path().join("21").exists());','        Ok(())','    }','}']
        if unit:
            old=[line.replace(' -> Result<()>', '').replace('tempfile::tempdir()?;',
                 'tempfile::tempdir().expect("temp dir");').replace('begin_staged_install(versions.path())?;',
                 'begin_staged_install(versions.path()).expect("staging");').replace('Ok(())','()') for line in old]
        function=next(i+1 for i,line in enumerate(old) if f'fn {declaration}' in line)
        first=function+2
        field='crate::runtimes::security::RuntimeSecurity::fixture'
        new=old[:first]+[f'            security: {field}(),']+old[first:]
        sources=[old,new];documents=[]
        for side,source in enumerate(sources):
            shift=side;opening=source[function-1].index('{')+1;closing=len(source)-1
            def row(line,start,end,hits=1):return [line,start,line,end,hits,0,0,0]
            def token(line,text,hits=1):
                at=source[line-1].index(text)+1
                return row(line,at,at+len(text),hits)
            regions=[row(function,5,opening-1,1),token(function+1,'tempfile::tempdir'),token(function+1,'expect' if unit else '?',1 if unit else 0),
                row(first,13,20),[first,23,first+3+shift,10,1,0,0,0],
                token(first+1+shift,'versions.path()'),token(first+4+shift,'begin_staged_install'),
                token(first+4+shift,'expect' if unit else '?',1 if unit else 0),token(first+5+shift,'assert!'),token(first+6+shift,'assert!'),
                token(first+7+shift,'(' if unit else 'Ok'),row(closing,5,6)]
            if side:
                at=source[first].index(field)+1
                regions.append(row(first+1,at,at+len(field)))
            root=f'_RNvNtNtNtCs1_7omg_lib8runtimes{len(runtime)}{runtime}5testss_{len(declaration)}{declaration}'
            documents.append([dict(name=root,count=1,filenames=[f'/src/src/runtimes/{runtime}.rs'],
                                  regions=regions,branches=[],mcdc_records=[])])
        head=documents[1][0]
        if fault=='parameter':sources[1][function-1]=sources[1][function-1].replace(f'{declaration}()',f'{declaration}(value: bool)')
        elif fault=='return-type':sources[1][function-1]=(sources[1][function-1].replace(f'{declaration}()',f'{declaration}() -> Option<()>') if unit
            else sources[1][function-1].replace('Result<()>','Option<()>'))
        elif fault=='public':sources[1][function-1]=sources[1][function-1].replace(f'fn {declaration}',f'pub fn {declaration}')
        elif fault=='module':sources[1][0]='#[cfg(feature = "production")]'
        elif fault=='factory':sources[1][first]=sources[1][first].replace('::fixture()', '::default()')
        elif fault=='cold-field':next(r for r in head['regions'] if r[0]==first+2)[4]=0
        elif fault=='cold-entry':head['regions'][0][4]=0
        elif fault=='channel':next(r for r in head['regions'] if r[0]==first+2)[7]=1
        elif fault=='foreign-owner':head['name']=head['name'].replace('Cs1_', 'Cs9_').replace(f'{len(declaration)}{declaration}','7another')
        elif fault=='duplicate-owner':documents[1].append(copy.deepcopy(head))
        elif fault=='foreign-overlap':documents[1].append(dict(head,name='foreign',regions=[next(r for r in head['regions'] if r[0]==first+2)]))
        counts=[]
        for document in documents:
            work=coverage._ObserverWork()
            counts.append(list(coverage._llvm22_rows(coverage._llvm22_segments(
                [r for owner in document for r in owner['regions']],work),work)))
        if fault=='missing-da':counts[1]=[(n,c) for n,c in counts[1] if n!=first+2]
        def bind(base,head):
            for document,owners in zip((base,head),documents):
                document['data'][0]['functions']=owners
                document['data'][0]['files'][0].update(expansions=[],branches=[],mcdc_records=[])
        filename=f'src/runtimes/{runtime}.rs'
        if observe:
            observations=[]
            for side,(source,document) in enumerate(zip(sources,documents)):
                mapped=dict(counts[side]);group=(function,len(source)-1,[document[0]])
                observations.append(coverage.async_runtime_fixture_record(filename,source,mapped,
                    group,document,Counter(o['name'] for o in document),
                    coverage._construct_inventory(source,[1_000_000]),first,first,[1_000_000]))
            return observations
        return self.compare(before=counts[0],after=counts[1],mutate=bind,filename=filename,
            sources=({filename:('\n'.join(old)+'\n').encode()},{filename:('\n'.join(new)+'\n').encode()}))

    def test_sync_runtime_result_record_preserves_failure_control_and_field_regions(self):
        for runtime in ('java','rust'):
            with self.subTest(runtime=runtime):
                before,after=self.sync_runtime_record_fixture(runtime,observe=True)
                self.assertIsNotNone(before)
                self.assertIsNotNone(after)
                self.assertEqual(before[0],after[0])
                self.assertTrue(before[1]['synchronous'])
                self.assertNotIn('body',after[1])
                self.assertEqual(len(after[1]['security_initializer']),1)
                receipt=self.sync_runtime_record_fixture(runtime)
                self.assertEqual(receipt['deleted_mapped'],0)

    def test_sync_runtime_result_record_refuses_unbound_source_and_compiled_roles(self):
        for runtime in ('java','rust'):
            for fault in ('parameter','return-type','public','module','factory','cold-field','cold-entry',
                          'channel','foreign-owner','duplicate-owner','foreign-overlap','missing-da'):
                with self.subTest(runtime=runtime,fault=fault):
                    before,after=self.sync_runtime_record_fixture(runtime,fault,observe=True)
                    self.assertTrue(before is None or after is None or before[0]!=after[0])

    def test_unit_runtime_record_retains_qualified_owner_without_claiming_result_rewrite(self):
        for runtime in ('java','rust'):
            with self.subTest(runtime=runtime):
                before,after=self.sync_runtime_record_fixture(runtime,observe=True,unit=True)
                self.assertIsNotNone(before)
                self.assertIsNotNone(after)
                self.assertEqual(before[0],after[0])
                self.assertNotEqual(before[0],self.sync_runtime_record_fixture(runtime,observe=True)[0][0])
                self.assertNotIn('body',after[1])
                self.assertEqual(len(after[1]['security_initializer']),1)
                for fault in ('parameter','return-type','public','module','factory','cold-field','cold-entry',
                              'channel','foreign-owner','duplicate-owner','foreign-overlap','missing-da'):
                    with self.subTest(fault=fault):
                        old,new=self.sync_runtime_record_fixture(runtime,fault,observe=True,unit=True)
                        self.assertTrue(old is None or new is None or old[0]!=new[0])

    def test_owned_source_enum_parameter_reuses_exact_record_and_cold_slot_proof(self):
        old=self.parameterized_rust_helper_record(enum_role=True)
        new=self.parameterized_rust_helper_record(insertion=True,enum_role=True)
        self.assertIsNotNone(old)
        self.assertIsNotNone(new)
        self.assertEqual(old[0],new[0])
        self.assertNotEqual(old[0],self.parameterized_rust_helper_record()[0])
        self.assertFalse(old[1]['security_initializer'])
        self.assertEqual(len(new[1]['security_initializer']),1)
        self.assertIn(False,[row[-1] for row in old[0][2]])

    def test_owned_source_enum_parameter_refuses_unbound_layout_scope_and_cold_state(self):
        for fault in ('enum-payload','enum-no-copy','enum-variant','enum-public','enum-alias',
                      'enum-duplicate','enum-foreign-module','enum-reference','production-module',
                      'wrong-factory','foreign-constructor','missing-constructor','duplicate-body',
                      'foreign-overlap','channel','cold-entry','missing-da'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.parameterized_rust_helper_record(insertion=True,enum_role=True,fault=fault))
        old=self.parameterized_rust_helper_record(enum_role=True)
        for fault in ('lost-field','lost-cold'):
            with self.subTest(fault=fault):
                new=self.parameterized_rust_helper_record(insertion=True,enum_role=True,fault=fault)
                self.assertTrue(new is None or new[0]!=old[0])

    def test_parameterized_runtime_helper_record_retains_cold_field_and_exact_role(self):
        old = self.parameterized_rust_helper_record()
        new = self.parameterized_rust_helper_record(insertion=True)
        self.assertIsNotNone(old)
        self.assertIsNotNone(new)
        self.assertEqual(old[0], new[0])
        self.assertEqual(old[0], self.parameterized_rust_helper_record(body_group=False)[0])
        self.assertEqual(new[0], self.parameterized_rust_helper_record(insertion=True,body_group=False)[0])
        self.assertFalse(old[1]['security_initializer'])
        self.assertEqual(len(new[1]['security_initializer']), 1)
        self.assertIn(False, [row[-1] for row in old[0][2]])

    def test_parameterized_runtime_helper_record_refuses_unbound_parameters_and_owners(self):
        for fault in ('parameter-type','parameter-name','return-type','public-helper','production-module',
                      'wrong-factory','missing-constructor','duplicate-constructor','foreign-constructor',
                      'foreign-body','wrong-constructor-start','cold-entry','body-under-count','channel','duplicate-body',
                      'foreign-overlap','missing-da'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.parameterized_rust_helper_record(insertion=True,fault=fault))
        baseline = self.parameterized_rust_helper_record()
        for fault in ('lost-field','lost-cold'):
            with self.subTest(fault=fault):
                changed = self.parameterized_rust_helper_record(insertion=True,fault=fault)
                self.assertTrue(changed is None or changed[0] != baseline[0])

    def test_async_runtime_fixture_record_keeps_original_regions_and_cold_error_slots(self):
        source = ['#[cfg(test)]', '#[expect(clippy::unwrap_used)]', 'mod tests {', '    #[tokio::test]',
                  '    async fn verify() -> Result<()> {', '        let manager = RustManager {',
                  '            versions_dir: fixture.path(),', '            client: fixture.client()?,',
                  '        };', '        Ok(())', '    }', '}']
        field = 'crate::runtimes::security::RuntimeSecurity::fixture'

        def observe(insertion=False, cold=True, foreign=False):
            texts = source[:]
            shift = int(insertion)
            if insertion:
                texts.insert(6, f'            security: {field}(),')
            if foreign:
                texts[1] = '#[cfg(feature = "private")]'
            opening = source[4].index('{')+1
            root = dict(name='_RNvNtNtNtCs1_7omg_lib8runtimes4rust5tests6verify', count=1,
                        filenames=['/src/runtimes/rust.rs'], regions=[
                            [5,11,5,opening-1,1,0,0,0], [11+shift,5,11+shift,6,1,0,0,0]])
            cold_column = source[7].index('?')+1
            raw = [[6,13,6,20,1,0,0,0], [6,23,9+shift,10,1,0,0,0]]
            if cold:
                raw.append([8+shift,cold_column,8+shift,cold_column+1,0,0,0,0])
            if insertion:
                column = texts[6].index(field)+1
                raw.append([7,column,7,column+len(field),1,0,0,0])
            child = dict(root,name='_RNC'+root['name'][2:]+'0B9_', regions=[
                [5,opening,5,opening+1,1,0,0,0], *raw])
            return coverage.async_runtime_fixture_record('src/runtimes/rust.rs', texts,
                coverage._owner_line_counts({'regions':raw},coverage._ObserverWork()),
                (5,11+shift,[root]), (root,child),Counter((root['name'],child['name'])),
                coverage._construct_inventory(texts,[1_000_000]),6,6,[1_000_000])

        original = observe()
        updated = observe(insertion=True)
        self.assertEqual(original[0],updated[0])
        self.assertFalse(original[1]['security_initializer'])
        self.assertEqual(len(updated[1]['security_initializer']),1)
        self.assertNotEqual(original[0],observe(insertion=True,cold=False)[0])
        self.assertIsNone(observe(insertion=True,foreign=True))

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

    def test_result_cleanup_binds_to_its_own_condition_and_compiled_copies(self):
        old = ['fn install_managed_blocking() -> Result<()> {',
               '    let outcome: Result<()> = run_install();',
               '    if let Err(error) = outcome {',
               '        pb.finish_and_clear();',
               '        let _ = fs::remove_dir_all(&staging_dir);',
               '        return Err(error);', '    }','    Ok(())','}']
        new = old[:2]+['']+old[2:]
        new[0] = 'fn install_managed_blocking(_receipt: &Receipt) -> Result<()> {'
        name = 'src/cli/tool.rs'; file = '/src/cli/tool.rs'; files = {file:name}
        def owner(shift, hits):
            return dict(name=f'_RNvNtNtCs{1+shift}_7omg_lib3cli4tool24install_managed_blocking',
                filenames=[file],count=hits,regions=[[1,1,1,3,hits,0,0,0],
                    *[[line+shift,col,line+shift,end,hits,0,0,0] for line,col,end in (
                        (3,16,21),(4,9,11),(5,17,34),(6,16,26),(7,5,6))],
                    [9+shift,1,9+shift,2,hits,0,0,0]])
        before = {line:1 for line in range(3,8)}; after = {line:1 for line in range(4,9)}
        def compare(source, compiled):
            return coverage.retained_construct_anchors(
                name, old, source, before, after, [owner(0,1)], [compiled], files, files)[0]
        self.assertEqual(compare(new, owner(1,1)), {line:line+1 for line in before})
        rebound = new[:1]+['    let outcome: Result<()> = other_install();']+new[2:]
        self.assertEqual(compare(rebound, owner(1,1)), {})
        foreign = owner(1,1)
        foreign['name'] = foreign['name'].replace('4tool', '4swap')
        self.assertEqual(compare(new, foreign), {})

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
        shift = int(change != 'identical-source')
        new = b'// Another integration test uses this constructor.\n' + old if shift else old
        def owner(crate, instance, shift, count, argument='RNtNtCs7_3std4path4Path'):
            return dict(name=f'_RINvMs_NtCs{crate}_3pkg7exampleNtB5_7Fixture6new_in{argument}E{instance}',
                        filenames=['/src/example.rs'], count=count,
                        regions=[[2+shift, 5, 2+shift, 65, count, 0, 0, 0],
                                 [3+shift, 9, 3+shift, 56, count, 0, 0, 0],
                                 [4+shift, 5, 4+shift, 6, count, 0, 0, 0]])
        def bind(base, head):
            base['data'][0]['functions'] = [owner('1', 'Cs8_5alpha', 0, 1), owner('1', 'B7_', 0, 0, 'p')]
            candidates = [owner('2', 'Cs9_5alpha', shift, 1), owner('2', 'B7_', shift, 0, 'p'),
                          owner('2', 'Csa_4beta', shift, 1)]
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
        after = [(line+shift,1 if change=='cold-added' else 2) for line in range(2,5)]
        return self.compare(before=[(2, 1), (3, 1), (4, 1)], after=after,
                            mutate=bind, sources=({'example.rs': old}, {'example.rs': new}))

    def test_retained_path_constructor_can_gain_a_fully_observed_consumer(self):
        receipt = self.path_reference_additions_compare()
        self.assertEqual(receipt['deleted_mapped'], 0)
        self.assertEqual(receipt['additive_path_reference_copies'][0]['pairs'], [[2, 3], [3, 4], [4, 5]])

    def test_same_source_specialization_reuses_the_lexical_inventory(self):
        with patch.object(coverage,'_construct_inventory',wraps=coverage._construct_inventory) as inventory:
            receipt = self.path_reference_additions_compare('identical-source')
        self.assertEqual(receipt['additive_path_reference_copies'][0]['pairs'],[[2,2],[3,3],[4,4]])
        self.assertEqual(inventory.call_count,1)

    def test_path_constructor_addition_requires_every_original_copy_and_known_new_consumer(self):
        for change in ('lost-consumer', 'lost-cold-root', 'cold-added', 'changed-type', 'foreign-type',
                       'foreign-impl', 'foreign-std-copy', 'unknown-suffix', 'duplicate-copy', 'changed-body'):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'complete compiled-copy'):
                self.path_reference_additions_compare(change)

    def test_identical_source_parses_compiled_declarations_once(self):
        source = {'example.rs': b'fn retained() {\n    checked();\n}\n'}
        observed = [(1,1),(2,1),(3,1)]

        def owners(base, head):
            for document in (base,head):
                document['data'][0]['functions'] = [dict(name='retained', filenames=['/src/example.rs'],
                    count=1, regions=[[1,1,3,2,1,0,0,0]])]

        with mock.patch.object(coverage,'source_function_prefixes',wraps=coverage.source_function_prefixes) as parse:
            self.compare(before=observed,after=observed,mutate=owners,sources=(source,source))
        self.assertEqual(parse.call_count,1)

    def compare(self, before=None, after=None, mutate=None, sources=None, filename="example.rs"):
        default_before, default_after = self.fixture()
        before = default_before if before is None else before
        after = default_after if after is None else after
        def lcov(rows):
            return f"SF:/src/{filename}\n" + "".join(f"DA:{line},{count}\n" for line, count in rows) + f"LF:{len(rows)}\nLH:{sum(count > 0 for _, count in rows)}\nend_of_record\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); bp, hp = root / "b.info", root / "h.info"
            bp.write_text(lcov(before)); hp.write_text(lcov(after))
            br, hr = self.regions(before, True), self.regions(after, False)
            if filename != "example.rs":
                for document in (br, hr):
                    document['data'][0]['files'][0]['filename'] = f'/src/{filename}'
                    for owner in document['data'][0]['functions']:
                        owner['filenames'] = [f'/src/{filename}' if name == '/src/example.rs' else name
                                              for name in owner['filenames']]
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
    def test_same_module_trait_and_next_line_brace_preserve_syntax_only(self):
        name = 'src/core/security/vulnerability.rs'
        filename = '/artifact/' + name
        files = {filename:name}
        work = [500_000]

        def fixture(method, crate, split_brace=False, trait='VulnerabilitySource'):
            lines = [f'pub trait {trait} {{}}', 'impl VulnerabilitySource for VulnerabilityScanner {',
                     f"    fn {method}<'a>(", "        &'a self,", '    ) -> usize']
            end = len(lines[-1])+1
            if split_brace:
                lines.append('    {')
            else:
                lines[-1] += ' {'
            lines.extend(['        1', '    }', '}'])
            terminal = len(lines)-1
            raw = [[3,5,5,end,1,0,0,0], [terminal-1,9,terminal-1,10,1,0,0,0],
                   [terminal,5,terminal,6,1,0,0,0]]
            symbol = (f'_RNvXs0_NtNtNtCs{crate}_7omg_lib4core8security13vulnerability'
                      f'NtB5_20VulnerabilityScannerNtB5_19VulnerabilitySource{len(method)}{method}')
            roots = [dict(name=symbol,count=1,filenames=[filename],regions=raw)]
            spans = {id(owner):coverage.source_owner_span(owner,name,files,lines) for owner in roots}
            index = coverage.index_compiled_owner_sources(roots,files,work,{name},index_declaration_ends=True)
            return (lines,coverage._construct_inventory(lines,work),spans,{4:1}), index

        base = fixture('scan_package','aJq9CMLDmry')
        head = fixture('assess_packages','40j12eeWnis',split_brace=True)
        proof, peers = coverage.retired_declaration_parameter(name,4,4,
            (base[0],head[0]),(base[1],head[1]),{'assess_packages'},work)
        self.assertEqual((proof['declaration'],proof['pairs'],proof['mapped_credit']), ('scan_package',[],[0,0]))
        self.assertEqual(peers,{})
        foreign = fixture('assess_packages','40j12eeWnis',split_brace=True,trait='DifferentTrait')
        self.assertIsNone(coverage.retired_declaration_parameter(name,4,4,
            (base[0],foreign[0]),(base[1],foreign[1]),{'assess_packages'},work))

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
    def test_arch_install_preparation_keeps_each_reviewed_branch_in_a_compiled_copy(self):
        source = ['impl PackageManager for ArchPackageManager {','    fn install(&self) {',
                  '        let packages = packages.to_vec();','        Box::pin(async move {',
                  '            if packages.is_empty() {','                return Ok(());','            }',
                  '            crate::core::security::validate_package_names_or_files(&packages)?;',
                  '        })','    }','}']

        def scenario(modern, lose_empty=False):
            roots = []; owners = []
            for index,crate in enumerate(('aJq9CMLDmry','40j12eeWnis')):
                base = f'NvXs0_NtNtCs{crate}_7omg_lib16package_managers4arch'
                calls = (24,2)[index] if modern else (2,0)[index]
                empty = int(index==0 and not lose_empty)
                remaining = calls-empty
                root = dict(name=f'_R{base}NtB5_18ArchPackageManagerNtNtB7_6traits14PackageManager7install',
                            filenames=['/src/package_managers/arch.rs'],count=calls,
                            regions=[[3,13,3,21,calls,0,0,0],[3,24,3,32,calls,0,0,0],
                                     [3,33,3,39,calls,0,0,0],[4,9,4,17,calls,0,0,0]])
                roots.append(root); owners.append(root)
                hits=[calls,calls,calls,empty,remaining,remaining,remaining,int(modern and index==0)]
                positions=[(4,29,4,30),(5,16,5,24),(5,25,5,33),(6,24,6,30),(7,13,7,14),
                           (8,13,8,67),(8,68,8,77),(8,78,8,79)]
                owners.append(dict(root,name=f'_RNC{base}NtB7_18ArchPackageManagerNtNtB9_6traits14PackageManager7install0Bb_',
                                   regions=[[*slot,count,0,0,0] for slot,count in zip(positions,hits,strict=True)]))
            work = [100_000]
            counts = coverage._owner_line_counts({'regions':[r for o in owners for r in o['regions']]},
                                                  coverage._ObserverWork(work))
            return source,counts,(2,10,roots),owners,Counter(o['name'] for o in owners),4

        baseline = scenario(False)
        proof = coverage.retained_arch_install_prelude((baseline,scenario(True)),[100_000])
        self.assertEqual(proof['pairs'],[[line,line] for line in range(3,9)])
        self.assertIsNone(coverage.retained_arch_install_prelude((baseline,scenario(True,True)),[100_000]))

    def test_arch_audit_advisory_await_requires_all_copies_and_rejects_other_providers(self):
        def scenario(modern, fault=None, finish=False):
            scanner = 'crate::core::security::vulnerability::VulnerabilityScanner::new()'
            operation = ['                let operation = '+scanner, '                    .assess_arch_operation(',
                         '                        &before,',
                         '                        crate::core::security::vulnerability::AssessmentUse::Admission,',
                         '                    )'] if modern else [
                             '                let advisories = '+scanner, '                    .fetch_alsa_issues()']
            if fault=='provider':
                operation[1] = '                    .another_operation('
            source = ['impl PackageManager for ArchPackageManager {', '    fn security_audit(&self) {',
                      '        Some(Box::pin(async move {', '            use anyhow::Context;', '            async {',
                      *operation,'                    .await?;']
            line = 6+len(operation)
            if finish:
                if modern:
                    source.append('                operation.validate_now()?;')
                source.extend(['                Ok(result)','            }','            .await',
                               '            .context("Failed to query native security advisories")'])
                line = len(source)-1
            else:
                source.append('            }.await')
            source.extend(['        }))','    }','}'])
            roots = []; owners = []
            for index,crate in enumerate(('aJq9CMLDmry','40j12eeWnis')):
                base = f'NvXs0_NtNtCs{crate}_7omg_lib16package_managers4arch'
                root = dict(name=f'_R{base}NtB5_18ArchPackageManagerNtNtB7_6traits14PackageManager14security_audit',
                            filenames=['/src/package_managers/arch.rs'],count=3,regions=[[3,14,3,22,3,0,0,0]])
                roots.append(root); owners.append(root)
                hits = 2 if modern and index==1 else 0
                if fault!='missing' or index==0:
                    if finish:
                        owners.append(dict(root,name=f'_RNC{base}NtB7_18ArchPackageManagerNtNtB9_6traits14PackageManager14security_audit0Bb_',
                                           count=hits,regions=[[line,14,line,19,hits,0,0,0],
                                                                [line+1,14,line+1,21,hits,0,0,0]]))
                    else:
                        owners.append(dict(root,name=f'_RNCNC{base}NtB9_18ArchPackageManagerNtNtBb_6traits14PackageManager14security_audit00Bd_',
                                           regions=[[6,operation[0].index(scanner)+1,line,27,hits,0,0,0],
                                                    [line,27,line,28,hits//2,0,0,0]]))
            work = [200_000]
            counts = coverage._owner_line_counts({'regions':[r for o in owners for r in o['regions']]},
                                                  coverage._ObserverWork(work))
            return source,counts,(2,len(source)-1,roots),owners,Counter(o['name'] for o in owners),line

        baseline = scenario(False)
        proof = coverage.retained_arch_advisory_await((baseline,scenario(True)),[200_000])
        self.assertEqual(proof['pairs'],[[8,11]])
        self.assertIsNone(coverage.retained_arch_advisory_await((baseline,scenario(True,'missing')),[200_000]))
        self.assertIsNone(coverage.retained_arch_advisory_await((baseline,scenario(True,'provider')),[200_000]))
        finished = coverage.retained_arch_advisory_await((scenario(False,finish=True),scenario(True,finish=True)),
                                                         [200_000],finish=True)
        self.assertEqual(finished['pairs'],[[11,15],[12,16]])

    def test_arch_audit_entry_observes_both_box_and_future_in_each_compiled_copy(self):
        source = ['impl PackageManager for ArchPackageManager {', '    fn security_audit(&self) {',
                  '        Some(Box::pin(async move {', '            use anyhow::Context;',
                  '            async {', '                audit().await', '            }.await',
                  '        }))', '    }', '}']
        namespace = '7omg_lib16package_managers4arch'
        work = [200_000]

        def scenario(hits, fault=None):
            owners = []
            roots = []
            for crate in ('aJq9CMLDmry','40j12eeWnis'):
                base = f'NvXs0_NtNtCs{crate}_{namespace}'
                root = dict(name=f'_R{base}NtB5_18ArchPackageManagerNtNtB7_6traits14PackageManager14security_audit',
                            filenames=['/src/package_managers/arch.rs'],count=hits,regions=[[3,14,3,22,hits,0,0,0]])
                roots.append(root)
                owners.append(root)
                if fault != 'missing-future' or len(roots)==1:
                    child_hits = 0 if fault=='cold-future' and len(roots)==2 else hits
                    owners.append(dict(root,name=f'_RNC{base}NtB7_18ArchPackageManagerNtNtB9_6traits14PackageManager14security_audit0Bb_',
                                       count=child_hits,regions=[[3,34,3,35,child_hits,0,0,0]]))
                if fault != 'missing-inner' or len(roots)==1:
                    owners.append(dict(root,name=f'_RNCNC{base}NtB9_18ArchPackageManagerNtNtBb_6traits14PackageManager14security_audit00Bd_',
                                       regions=[[5,19,5,20,hits,0,0,0]]))
            projection = coverage._owner_line_counts({'regions':[r for o in owners for r in o['regions']]},
                                                     coverage._ObserverWork(work))
            return (source,projection,(2,9,roots),owners,Counter(o['name'] for o in owners),
                    coverage._construct_inventory(source,work),3)

        base = scenario(0)
        proof = coverage.retained_arch_audit_entry((base,scenario(1)),work)
        self.assertEqual(proof['pairs'],[[3,3],[5,5]])
        for fault in ('missing-future','cold-future','missing-inner'):
            with self.subTest(fault=fault):
                self.assertIsNone(coverage.retained_arch_audit_entry((base,scenario(1,fault)),work))

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
    def test_policy_grade_metadata_requires_the_executed_assertions_on_both_sides(self):
        name='src/core/security/policy.rs'
        filename='/src/'+name
        expected='SecurityGrade::Verified'
        diagnostic='"package names must not mint a Locked SLSA grade"'
        declaration='official_packages_are_verified_not_locked_by_name'
        def fixture(head,fault):
            expression='SecurityPolicy::source_grade(&package.package.origin)' if head else 'grade'
            lines=['#[cfg(test)]','mod tests {',
                   '    #[test]' if head else '    #[tokio::test]',
                   f'    {"async " if not head else ""}fn {declaration}() {{',
                   '        assert_eq!(',f'            {expression},',
                   f'            {expected},',f'            {diagnostic}','        );','    }','}']
            if head and fault=='different-expectation':
                lines[6]=lines[6].replace('Verified','Community')
            def slot(line,value,count=1):
                start=lines[line-1].index(value)+1
                return [line,start,line,start+len(value),count,0,0,0]
            symbol='_RNvNtNtNtNtCs1_7omg_lib4core8security6policy5tests'
            symbol+=f'{len(declaration)}{declaration}'
            raw=[slot(4,f'fn {declaration}()'),slot(10,'}')]
            regions=[slot(5,'assert_eq!')]
            if head:
                regions.extend([slot(6,'SecurityPolicy::source_grade',int(fault!='cold-comparison')),
                                slot(6,'&package.package.origin')])
                raw.extend(regions)
            else:
                raw.append([5,9,9,11,1,0,0,0])
            root=dict(name=symbol,filenames=[filename],count=1,regions=raw)
            owners=[root]
            if not head:
                owners.append(dict(root,name='_RNC'+symbol[2:]+'0Bb_',regions=regions))
            if fault=='foreign-region':
                owners.append(dict(root,name='foreign',regions=[slot(7,expected)],count=1))
            work=[2_000_000]
            counts=coverage._owner_line_counts({'regions':[r for owner in owners for r in owner['regions']]},
                                              coverage._ObserverWork(work))
            inventory=coverage._construct_inventory(lines,work)
            index=coverage.index_compiled_owner_sources(owners,{filename:name},work,{name})
            return (lines,inventory,counts),index

        def observe(fault=None):
            old,base=fixture(False,fault if fault=='foreign-region' else None)
            current,head=fixture(True,fault if fault!='foreign-region' else None)
            return coverage.retired_policy_grade_metadata(name,(7,7),(old,current),(base,head),[2_000_000])

        proof=observe()
        self.assertEqual(proof['retired_lines'],[[7,7],[8,8],[9,9]])
        self.assertEqual(proof['mapped_credit'],[0,0])
        for fault in ('different-expectation','cold-comparison','foreign-region'):
            with self.subTest(fault=fault):
                self.assertIsNone(observe(fault))

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


class DirectMatchSelectorTests(unittest.TestCase):
    def observe(self, fault=None, default=False):
        old = ['fn accepts(registry: &str) -> bool {',
               '    let valid = match registry {', '        "npm" => parse_old(),',
               '        _ => false,', '    };', '    valid', '}']
        new = old.copy()
        new[2] = '        "npm" => parse_new(),'
        if fault == 'rebound':
            new[1:1] = ['    let registry = another_registry();']
        if fault == 'selector':
            new[1] = '    let valid = match alternate {'
        if fault == 'label':
            new[2] = new[2].replace('"npm"','"pip"')
        file = '/src/example.rs'; name = 'src/example.rs'
        sides = []; indexes = []
        work = [100_000]
        for side, source in enumerate((old,new)):
            shift = len(source)-len(old); line = (4 if default else 2)+shift
            def owner(crate, hits):
                raw = [[line,14,line,19,hits if side else 0,0,0,0]] if default else [
                    [line,9,line,14,hits,0,0,0],[line,23,line,31,hits,0,0,0]]
                return dict(name=f'_RNvNtCs{crate}_7omg_lib7example7accepts', count=hits,
                    filenames=[file], regions=[[1,1,1,35,hits,0,0,0],*raw,
                       [7+shift,1,7+shift,2,hits,0,0,0]])
            roots = [owner(1,0),owner(2,2)] if not side else [owner(3,1),owner(4,3)]
            if side and fault=='lost-copy':
                roots[1] = owner(4,0)
                roots[0] = owner(3,0)
            if side and fault=='moved-region':
                roots[0]['regions'][1][1] += 1
            inventory = list(roots)
            if side and fault=='foreign':
                inventory.append(dict(name='foreign',count=1,filenames=[file],
                                      regions=[[line,9,line,14,1,0,0,0]]))
            counts = {line:sum(o['regions'][1][4] for o in roots)}
            if side and fault=='wrong-lcov':
                counts[line]+=1
            indexes.append(coverage.index_compiled_owner_sources(inventory,{file:name},work))
            sides.append((source,coverage._construct_inventory(source,work),(1,len(source),roots),counts,line))
        return coverage.retained_match_selector(name,sides,indexes,work)

    def test_direct_parameter_selector_keeps_both_compiler_regions_and_copies(self):
        proof = self.observe()
        self.assertEqual(proof['pairs'],[[2,2]])
        self.assertEqual(proof['kind'],'direct-match-selector')
        for fault in ('rebound','selector','lost-copy','moved-region','foreign','wrong-lcov'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(fault))

    def test_unselected_default_remains_bound_to_the_same_literal_routes(self):
        proof = self.observe(default=True)
        self.assertEqual(proof['pairs'],[[4,4]])
        self.assertEqual(proof['kind'],'direct-match-default')
        for fault in ('label','rebound','moved-region','wrong-lcov'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(fault,default=True))


class FixtureScriptWriteTests(unittest.TestCase):
    def observe(self, fault=None):
        old = ['use std::fs;', '#[cfg(test)]','mod tests {','    #[cfg(unix)]','    #[test]',
               '    fn trial() {',
               '        if crate::core::testing::run_isolated_test("cli::tool::tests::trial",) {',
               '            return;', '        }','        let npm = fixture_path();',
               '        fs::write(', '            &npm,', '            br#"old input', '"#,', '        )',
               '        .expect("write fixture");', '    }', '}']
        new = old[:13]+['second input line']+old[13:]
        new[12] = new[12].replace('old','new')
        if fault=='destination':
            new[11] = new[11].replace('npm','bin')
        if fault=='changed-prelude':
            new[9] = new[9].replace('fixture_path','another_path')
        file = '/src/cli/tool.rs'; name = 'src/cli/tool.rs'; work = [100_000]
        sides = []; indexes = []
        for offset,source in enumerate((old,new)):
            symbol = f'_RNvNtNtNtCs{1+offset}_7omg_lib3cli4tool5testss_5trial'
            hit = int(not (offset and fault=='cold'))
            raw = [[11,9,11,18,hit,0,0,0],[12,13,12,17,hit,0,0,0],
                   [16+offset,10,16+offset,16,hit,0,0,0],[16+offset,17,16+offset,32,hit,0,0,0]]
            if offset and fault=='payload-paint':
                raw.append([13,13,13,16,hit,0,0,0])
            owner = dict(name=symbol, count=2, filenames=[file], regions=raw)
            inventory = [owner]
            if offset and fault=='foreign':
                inventory.append(dict(name='foreign',count=1,filenames=[file],regions=[raw[0]]))
            counts = coverage._owner_line_counts(owner,coverage._ObserverWork(work))
            indexes.append(coverage.index_compiled_owner_sources(inventory,{file:name},work))
            sides.append((source,coverage._construct_inventory(source,work),(6,17+offset,[owner]),counts,11))
        return coverage.retained_fixture_script_write(name,sides,indexes,work)

    def test_retained_fixture_write_slots_across_opaque_byte_payload_edit(self):
        proof = self.observe()
        self.assertEqual(proof['pairs'],[[11,11],[12,12],[16,17]])
        self.assertEqual(proof['kind'],'retained-fixture-script-write')
        for fault in ('destination','changed-prelude','cold','payload-paint','foreign'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe(fault))

    def observe_loop(self, fault=None):
        old = ['use std::fs;', '#[cfg(test)]','mod tests {','    #[cfg(unix)]','    #[test]',
               '    fn trial() {',
               '        if crate::core::testing::run_isolated_test("cli::tool::tests::trial",) {',
               '            return;', '        }','        let managers = fixture_path();',
               '        for executable in ["npm", "cargo"] {',
               '            let program = managers.join(executable);',
               '            fs::write(', '                &program,', '                b"old input",',
               '            )', '            .expect("write fixture");', '        }','    }','}']
        new = old.copy()
        new[14] = '                format!("new {marker}"),'
        if fault=='loop-values':
            new[10] = new[10].replace('"cargo"','"pip"')
        if fault=='loop-binding':
            new[11] = new[11].replace('managers','alternate')
        file = '/src/cli/tool.rs'; name = 'src/cli/tool.rs'; work = [100_000]
        sides = []; indexes = []
        for offset,source in enumerate((old,new)):
            symbol = f'_RNvNtNtNtCs{1+offset}_7omg_lib3cli4tool5testss_5trial'
            def slot(line, text, hits=2):
                column = source[line-1].index(text)+1
                return [line,column,line,column+len(text),hits,0,0,0]
            array = source[10][source[10].index('['):source[10].index(']')+1]
            envelope = [11,source[10].index('{')+1,18,10,1 if offset and fault=='partial-loop' else 2,0,0,0]
            raw = [slot(11,'executable'),slot(11,array,1),envelope,slot(13,'fs::write'),
                   slot(14,'&program'),slot(17,'expect'),slot(17,'"write fixture"')]
            if offset:
                raw.insert(5,slot(15,'format!',1 if fault=='cold-format' else 2))
            owner = dict(name=symbol,count=2,filenames=[file],regions=raw)
            counts = coverage._owner_line_counts(owner,coverage._ObserverWork(work))
            indexes.append(coverage.index_compiled_owner_sources([owner],{file:name},work))
            sides.append((source,coverage._construct_inventory(source,work),(6,19,[owner]),counts,13))
        return coverage.retained_fixture_script_write(name,sides,indexes,work)

    def test_retained_loop_write_requires_complete_iteration_and_unchanged_destination(self):
        proof = self.observe_loop()
        self.assertEqual(proof['pairs'],[[13,13],[14,14],[16,16],[17,17]])
        for fault in ('loop-values','loop-binding','partial-loop','cold-format'):
            with self.subTest(fault=fault):
                self.assertIsNone(self.observe_loop(fault))


class ConstructorDelimiterTests(unittest.TestCase):
 def constructor_fixture(self,fault=None):
  old=['#[cfg(test)]','mod tests {','    #[tokio::test]','    async fn completion() {',
       '        for score in [None, Some("0"), Some("9.8")] {','            for official in [false, true] {',
       '                assert!(matches!(before(score, official), Err(Error::Risk)));','            }','        }','    }','}']
  new=[*old[:2],'    #[test]','    fn completion() {',old[4],
       '            for origin in [Origin::Community, Origin::Official] {',
       '                assert!(matches!(after(score, origin), Err(Error::Risk)));',*old[7:]]
  sources=[old,new];documents=[]
  for side,source in enumerate(sources):
   root=f'_RNvNtCs{side+1}_7example5tests10completion'
   def row(bounds,count=1):return [*bounds,count,0,0,0]
   entry=(4,source[3].index('fn')+1,4,source[3].index('{'))
   body_start=(4,source[3].index('{')+1)
   channels=[]
   for line,binding,count,parent in [(5,'score',3,1),(6,'official' if side==0 else 'origin',6,3)]:
    text=source[line-1];a=text.index(binding)+1;channels.append(row((line,a,line,a+len(binding)),count))
    channels.append(row((line,text.index('[')+1,line,text.index(']')+2),parent))
   cold=row((7,25,7,33),0);hot=row((7,source[6].index('before' if side==0 else 'after')+1,7,len(source[6])+1),6)
   def owner(name,regions):return dict(name=name,count=1,filenames=['/src/example.rs'],regions=regions,branches=[],mcdc_records=[])
   if side==0:
    documents.append([owner(root,[row(entry),row((5,9,9,10)),row((10,5,10,6))]),
      owner('_RNC'+root[2:]+'0B5_',[row((*body_start,body_start[0],body_start[1]+1)),*channels,hot,cold])])
   else:documents.append([owner(root,[row(entry),*channels,hot,cold,row((10,5,10,6))])])
  if fault=='constructor-count':documents[0][0]['regions'][1][4]=2
  elif fault=='missing-envelope':documents[0][0]['regions'].pop(1)
  elif fault=='foreign-old-delimiter':
   documents[0].append(dict(name='foreign',count=0,filenames=['/src/example.rs'],regions=[[8,13,8,14,0,0,0,0]],branches=[],mcdc_records=[]))
  elif fault=='head-delimiter-paint':
   documents[1].append(dict(name='foreign',count=0,filenames=['/src/example.rs'],regions=[[8,13,8,14,0,0,0,0]],branches=[],mcdc_records=[]))
  elif fault=='lost-iteration-channel':documents[1][0]['regions'][3][4]=3
  elif fault=='changed-outer-values':new[4]=new[4].replace('9.8','9.9')
  elif fault=='different-loop-cardinality':new[5]=new[5].replace(', Origin::Official','')
  elif fault=='foreign-root':documents[1][0]['name']=documents[1][0]['name'].replace('5tests','5other')
  elif fault=='cold-completion':documents[1][0]['regions'][-1][4]=0
  elif fault=='early-transfer':new[6]='                continue;'
  elif fault=='executable-delimiter':old[7]=new[7]='            } after();'
  elif fault=='unknown-attribute':new[2]='    #[other::test]'
  elif fault=='missing-test-gate':new[0]='#[cfg(feature = "special")]'
  elif fault=='foreign-owner-copy':documents[0].append(copy.deepcopy(documents[0][0]))
  counts=[];inventories=[];indexes=[]
  for source,owners in zip(sources,documents):
   work=coverage._ObserverWork();counts.append(dict(coverage._llvm22_rows(coverage._llvm22_segments([r for o in owners for r in o['regions']],work),work)))
   inventories.append(coverage._construct_inventory(source,[64000000]))
   indexes.append(coverage.index_compiled_owner_sources(owners,{'/src/example.rs':'example.rs'},[64000000],{'example.rs'}))
  result=coverage.retired_async_test_constructor_delimiters('example.rs',(7,10,7,10,[8,9,10]),sources,counts,inventories,indexes,[64000000],([],[]))
  return result
 def test_constructor_paint_retirement_retains_iteration_and_completion_channels(self):
  result=self.constructor_fixture()
  self.assertEqual(result['retired_lines'],[8,9])
  self.assertEqual(result['pairs'],[[10,10]])
  self.assertEqual(result['summary_credit'],[0,0]);self.assertEqual(result['mapped_credit'],[0,0])
  self.assertEqual([o['sizes'] for o in result['observations']],[(3,2),(3,2)])
  self.assertEqual([o['owners'][0]['unclaimed_body_cold_regions'] for o in result['observations']],[[[7,25,7,33]],[[7,25,7,33]]])
 def test_constructor_retirement_refuses_changed_or_incomplete_evidence(self):
  for fault in ('constructor-count','missing-envelope','foreign-old-delimiter','head-delimiter-paint',
                'lost-iteration-channel','changed-outer-values','different-loop-cardinality','foreign-root',
                'cold-completion','early-transfer','executable-delimiter','unknown-attribute','missing-test-gate','foreign-owner-copy'):
   with self.subTest(fault=fault):self.assertIsNone(self.constructor_fixture(fault))

class CfgMethodTests(unittest.TestCase):
 def fixture(self,fault=None):
  name='src/runtimes/node.rs';filename='/src/runtimes/node.rs'
  source=['impl NodeManager {','    #[cfg(feature = "pgp")]',
    '    async fn fetch_checksum(&self, version: &str, filename: &str) -> Result<String> {',
    '        first(version)?;','        Ok(filename.into())','    }',
    '    #[cfg(not(feature = "pgp"))]',
    '    fn fetch_checksum(&self, _version: &str, _filename: &str) -> std::future::Ready<Result<String>> {',
    '        std::future::ready(Err(anyhow::anyhow!("PGP required")))','    }','}']
  if fault=='non-complement':source[6]='    #[cfg(not(feature = "other"))]'
  elif fault=='missing-active-cfg':source[1]='    #[cfg(feature = "other")]'
  elif fault=='extra-attribute':source[1]='    #[allow(dead_code)] #[cfg(feature = "pgp")]'
  elif fault=='extra-gated-prefix':source[1:1]=['    #[cfg(', '        feature = "extra"', '    )]']
  elif fault=='extra-inactive-attribute':source[6]='    #[allow(dead_code)] #[cfg(not(feature = "pgp"))]'
  elif fault=='different-impl':source[5:7]=['    }','}','impl OtherManager {','    #[cfg(not(feature = "pgp"))]']
  active=next(n for n,line in enumerate(source,1) if 'async fn fetch_checksum' in line);last=active+3
  owners=[]
  for scope,quantity in [('s1_',1),('s2_',0)]:
   ctor=f'_RNvMs0_NtNtC{scope}7omg_lib8runtimes4nodeNtB5_11NodeManager14fetch_checksum'
   body=f'_RNCNvMs0_NtNtC{scope}7omg_lib8runtimes4nodeNtB7_11NodeManager14fetch_checksum0Bb_'
   opening=source[active-1].find('{')+1;end=len(source[active-1].split('{')[0].rstrip())+1
   def owner(symbol,rows):return dict(name=symbol,count=quantity,filenames=[filename],regions=rows,branches=[],mcdc_records=[])
   owners.extend([owner(ctor,[[active,5,active,end,quantity,0,0,0]]),owner(body,[
      [active,opening,active,opening+1,quantity,0,0,0],
      [active+1,9,active+1,len(source[active])+1,quantity,0,0,0],
      [active+1,len(source[active])-1,active+1,len(source[active]),0,0,0,0],
      [active+2,9,active+2,len(source[active+1])+1,quantity,0,0,0],
      [last,5,last,6,quantity,0,0,0]])])
  if fault=='missing-constructor':owners.pop(0)
  elif fault=='missing-body':owners.pop(1)
  elif fault=='wrong-source':owners[1]['filenames']=['/other.rs']
  elif fault=='wrong-instance':owners[1]['name']=owners[1]['name'].replace('s1_','s3_')
  elif fault=='raw-channel':owners[1]['regions'][0][5]=1
  elif fault=='wrong-entry':owners[1]['regions'][0][1]+=1
  elif fault=='inactive-owner':
   extra=copy.deepcopy(owners[0]);extra['name']=extra['name'].replace('s1_','s9_');extra['regions']=[[8,5,8,6,1,0,0,0],[10,5,10,6,1,0,0,0]];owners.append(extra)
  elif fault=='foreign-envelope':
   extra=copy.deepcopy(owners[0]);extra['name']='foreign';extra['regions']=[[1,1,1,2,1,0,0,0],[7,1,7,2,1,0,0,0]];owners.append(extra)
  elif fault=='extra-nested-child':
   extra=copy.deepcopy(owners[1]);extra['name']=extra['name'].replace('_RNCNv','_RNCNCNv').replace('0Bb_','00Bd_');owners.append(extra)
  result=coverage._compiled_function_groups(name,owners,{filename:name},source,[64000000])
  return source,owners,result
 def test_complementary_pgp_method_has_complete_active_cold_and_hot_copies(self):
  source,owners,result=self.fixture()
  groups=list(result[1].values());self.assertEqual(len(groups),1)
  self.assertEqual(groups[0][:2],(3,6));self.assertEqual({o['name'] for o in groups[0][2]},{owners[1]['name'],owners[3]['name']})
  self.assertEqual(groups[0][2],[owners[1],owners[3]])
  self.assertEqual([o['count'] for o in groups[0][2]],[1,0])
  self.assertEqual(sum(r[4]==0 for o in groups[0][2] for r in o['regions']),6)
 def test_default_function_name_uniqueness_remains_strict(self):
  source,owners,result=self.fixture()
  self.assertEqual(coverage.source_function_prefixes(source,[(3,6)]),{})
  self.assertFalse(coverage._compiled_function_groups('src/runtimes/node.rs',owners,{'/src/runtimes/node.rs':'src/runtimes/node.rs'},source)[1])
  self.assertFalse(coverage._compiled_function_groups('src/runtimes/node.rs',owners,{'/src/runtimes/node.rs':'src/runtimes/node.rs'},source,[64000000],shared_prefixes={})[1])
 def test_complementary_pgp_method_refuses_unsupported_cfg_and_unclosed_owners(self):
  for fault in ('non-complement','missing-active-cfg','extra-attribute','extra-gated-prefix','extra-inactive-attribute','different-impl','missing-constructor','missing-body','wrong-source','wrong-instance','raw-channel','wrong-entry','inactive-owner','foreign-envelope','extra-nested-child'):
   with self.subTest(fault=fault):
    try:source,owners,result=self.fixture(fault)
    except ValueError:continue
    self.assertFalse(result and result[1])

if __name__ == "__main__":
    unittest.main()

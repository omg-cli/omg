"""Execution reconciliation fixtures, not product coverage receipts."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'test_selection', Path(__file__).with_name('check-test-selection.py'))
SELECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTION)


def listing():
    return {'test-count': 2, 'rust-suites': {'omg::cli_surface': {
        'binary-id': 'omg::cli_surface', 'status': 'listed',
        'binary-path': '/tmp/cli_surface', 'testcases': {
            'parser': {'ignored': False, 'filter-match': {'status': 'matches'}},
            'unsupported': {'ignored': True, 'filter-match': {'status': 'mismatch', 'reason': 'ignored'}},
        },
    }}}


def junit(contents='<testcase name="parser" classname="omg::cli_surface" time="0.001"/>'):
    return ('<testsuites><testsuite name="omg::cli_surface">' + contents
            + '</testsuite></testsuites>').encode()


class TestSelection(unittest.TestCase):
    def test_nonempty_selection_preserves_ignored_denominator(self):
        report = SELECTION.reconcile(listing(), junit(), ['omg::cli_surface'])
        self.assertEqual(report['counts'], dict(discovered=2, selected=1, executed=1,
                                               passed=1, failed=0, skipped=1, filtered=0, retried=0))
        self.assertEqual(report['tests']['omg::cli_surface::parser']['attempts'],
                         [{'result': 'PASS', 'duration_ms': 1.0}])
        self.assertEqual(report['tests']['omg::cli_surface::parser']['selection_state'], 'selected')

    def test_missing_native_binary_and_cfg_empty_binary_are_rejected(self):
        for mode in ('missing', 'empty', 'filtered'):
            data = listing()
            if mode == 'missing':
                required = ['omg::debian_tests']
            else:
                required = ['omg::cli_surface']
                if mode == 'empty':
                    data['rust-suites']['omg::cli_surface']['testcases'] = {}
                    data['test-count'] = 0
                else:
                    data['rust-suites']['omg::cli_surface']['testcases']['parser']['filter-match'] = {'status': 'mismatch', 'reason': 'expression'}
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                SELECTION.reconcile(data, junit(), required)

    def test_missing_duplicate_and_foreign_execution_are_rejected(self):
        for contents in ('', '<testcase name="parser" classname="omg::cli_surface" time="0"/>' * 2,
                         '<testcase name="unknown" classname="omg::cli_surface" time="0"/>'):
            with self.subTest(contents=contents), self.assertRaises(ValueError):
                SELECTION.reconcile(listing(), junit(contents), ['omg::cli_surface'])

    def test_retries_keep_original_failure_before_success(self):
        xml = junit('<testcase name="parser" classname="omg::cli_surface" time="0.003">'
                    '<flakyFailure time="0.001"/><flakyError time="0.002"/></testcase>')
        report = SELECTION.reconcile(listing(), xml, ['omg::cli_surface'])
        self.assertEqual([item['result'] for item in report['tests']['omg::cli_surface::parser']['attempts']],
                         ['FAIL', 'FAIL', 'PASS'])
        self.assertEqual(report['counts']['retried'], 1)
        self.assertEqual(report['counts']['failed'], 1)

    def test_failed_retries_preserve_each_attempt(self):
        xml = junit('<testcase name="parser" classname="omg::cli_surface" time="0.001">'
                    '<failure/><rerunFailure time="0.002"/></testcase>')
        report = SELECTION.reconcile(listing(), xml, ['omg::cli_surface'])
        self.assertEqual(report['tests']['omg::cli_surface::parser']['attempts'], [
            {'result': 'FAIL', 'duration_ms': 1.0}, {'result': 'FAIL', 'duration_ms': 2.0}])

    def test_early_return_skip_marker_cannot_pass(self):
        xml = junit('<testcase name="parser" classname="omg::cli_surface" time="0.001">'
                    '<system-out>[omg-skip] unavailable backend</system-out></testcase>')
        report = SELECTION.reconcile(listing(), xml, ['omg::cli_surface'])
        self.assertEqual(report['counts']['passed'], 0)
        self.assertEqual(report['counts']['executed'], 0)
        self.assertEqual(report['counts']['skipped'], 2)
        self.assertFalse(report['executed_required_binaries'])
        self.assertEqual(report['tests']['omg::cli_surface::parser']['runtime_skip_reason'],
                         'unavailable backend')

    def test_reported_ignored_skip_is_not_double_counted(self):
        xml = junit('<testcase name="parser" classname="omg::cli_surface" time="0"/>'
                    '<testcase name="unsupported" classname="omg::cli_surface"><skipped/></testcase>')
        self.assertEqual(SELECTION.reconcile(listing(), xml, ['omg::cli_surface'])['counts']['skipped'], 1)

    def test_xml_entities_nonfinite_time_and_conflicting_verdicts_rejected(self):
        for xml in (b'<!DOCTYPE x [<!ENTITY a "boom">]><testsuites/>',
                    junit('<testcase name="parser" classname="omg::cli_surface" time="NaN"/>'),
                    junit('<testcase name="parser" classname="omg::cli_surface" time="1e308"/>'),
                    junit('<testcase name="parser" classname="omg::cli_surface" time="0"><failure/><skipped/></testcase>')):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                SELECTION.reconcile(listing(), xml, ['omg::cli_surface'])

    def test_unlisted_duplicate_identity_or_bad_count_rejected(self):
        for mode in ('unlisted', 'duplicate', 'count'):
            data = listing()
            if mode == 'unlisted':
                data['rust-suites']['omg::cli_surface']['status'] = 'skipped'
            elif mode == 'duplicate':
                data['rust-suites']['alias'] = copy.deepcopy(data['rust-suites']['omg::cli_surface'])
            else:
                data['test-count'] = 0
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                SELECTION.reconcile(data, junit(), ['omg::cli_surface'])


if __name__ == '__main__':
    unittest.main()

"""Literal JUnit streams exercised through the production selection parser."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'test_selection', Path(__file__).with_name('check-test-selection.py'))
SELECTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTION)


def read_case(children):
    document = (
        '<testsuites><testsuite name="omg::unit">'
        '<testcase name="native" classname="omg::unit" time="0.01">'
        + children + '</testcase></testsuite></testsuites>')
    return SELECTION.read_junit(document.encode())['omg::unit::native']


class JunitSkipReporting(unittest.TestCase):
    def test_mixed_valid_and_malformed_markers_are_refused(self):
        streams = [
            '<system-out>[omg-skip] requires Fedora\nprefix [omg-skip] other</system-out>',
            '<system-out>[omg-skip] requires Fedora</system-out>'
            '<system-err>prefix [omg-skip] other</system-err>',
            '<system-err>[omg-skip] reason [omg-skip] other</system-err>',
        ]
        for stream in streams:
            with self.subTest(stream=stream):
                with self.assertRaisesRegex(ValueError, 'runtime skip'):
                    read_case(stream)

    def test_empty_malformed_and_duplicate_markers_are_refused(self):
        for marker in ['[omg-skip] ', '[omg-skip]', 'prefix [omg-skip] other',
                       '[omg-skip] one\n[omg-skip] two']:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(ValueError, 'runtime skip'):
                    read_case('<system-err>' + marker + '</system-err>')

    def test_one_marker_preserves_reason_without_execution_credit(self):
        result = read_case('<system-err>[omg-skip] requires Fedora\n</system-err>')
        self.assertEqual(result['runtime_skip_reason'], 'requires Fedora')
        self.assertTrue(result['runtime_skip'])
        self.assertEqual(result['attempts'], [{'result': 'SKIPPED', 'duration_ms': 10.0}])

    def test_runner_message_text_and_type_are_preserved_separately(self):
        result = read_case(
            '<skipped message="ignored: native fixture" type="ignored"> source reason </skipped>')
        self.assertEqual(result.get('runner_skip_message'), 'ignored: native fixture')
        self.assertEqual(result.get('runner_skip_text'), ' source reason ')
        self.assertEqual(result.get('runner_skip_type'), 'ignored')
        self.assertEqual(result.get('runner_skip_reason'), 'ignored: native fixture')
        self.assertIs(result.get('runner_skip_reason_known'), True)
        self.assertFalse(result['runtime_skip'])

    def test_runner_text_fallback_does_not_invent_an_unknown_reason(self):
        result = read_case('<skipped type="ignored"> requires Fedora </skipped>')
        self.assertEqual(result.get('runner_skip_reason'), 'requires Fedora')
        result = read_case('<skipped type="ignored"/>')
        self.assertIsNone(result.get('runner_skip_reason'))
        self.assertIs(result.get('runner_skip_reason_known'), False)
        self.assertEqual(result.get('runner_skip_type'), 'ignored')

    def test_failure_and_error_keep_precedence_over_valid_markers(self):
        for tag in ['failure', 'error']:
            with self.subTest(tag=tag):
                result = read_case('<' + tag + '/><rerunFailure time="0.002"/>'
                                   '<system-err>[omg-skip] requires Fedora</system-err>')
                self.assertEqual([attempt['result'] for attempt in result['attempts']],
                                 ['FAIL', 'FAIL'])

    def test_first_flaky_failure_precedes_later_runtime_skip(self):
        result = read_case('<flakyFailure time="0.002"/>'
                           '<system-err>[omg-skip] requires Fedora</system-err>')
        self.assertEqual([attempt['result'] for attempt in result['attempts']],
                         ['FAIL', 'SKIPPED'])

    def test_pass_and_runner_skip_remain_distinct(self):
        self.assertEqual(read_case('')['attempts'], [{'result': 'PASS', 'duration_ms': 10.0}])
        self.assertEqual(read_case('<skipped/>')['attempts'],
                         [{'result': 'SKIPPED', 'duration_ms': 0.0}])


if __name__ == '__main__':
    unittest.main()

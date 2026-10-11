"""Run the actual maintenance step over raw offline JSON and the real jq filter.

Retains PR895's three request contracts and adds pagination/PR/partial-failure
controls. The fake gh boundary never contacts GitHub or receives credentials.
"""
import unittest

import test_qemu_review as fixture


class MaintenanceRequestTests(unittest.TestCase):
    def run_request(self, scenario):
        return fixture.ReviewTests().maintenance_request(scenario)

    def test_existing_request_prevents_duplicate_creation(self):
        result, commands = self.run_request('exact')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(command[:2] == ['issue', 'create'] for command in commands))

    def test_missing_request_creates_one_labeled_issue(self):
        result, commands = self.run_request('empty')
        self.assertEqual(result.returncode, 0, result.stderr)
        creations = [command for command in commands if command[:2] == ['issue', 'create']]
        self.assertEqual(len(creations), 1)
        self.assertIn('--label', creations[0])
        self.assertIn('security,type:maintenance,priority:p2', creations[0])

    def test_failed_lookup_never_creates_an_issue(self):
        result, commands = self.run_request('query-failure')
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(any(command[:2] == ['issue', 'create'] for command in commands))

    def test_second_page_canonical_issue_suppresses_creation(self):
        result, commands = self.run_request('paginated')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(command[:2] == ['issue', 'create'] for command in commands),
                         'canonical issue after 100 similar titles must be reused')

    def test_same_title_pull_request_does_not_suppress_issue_creation(self):
        result, commands = self.run_request('pull-request')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(command[:2] == ['issue', 'create'] for command in commands), 1)

    def test_partial_lookup_output_then_failure_never_creates_issue(self):
        result, commands = self.run_request('partial-failure')
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(any(command[:2] == ['issue', 'create'] for command in commands))


if __name__ == '__main__':
    unittest.main()

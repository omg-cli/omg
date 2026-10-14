"""Real CLI span controls; original policy regression source stays unchanged."""
import json
import unittest
import test_debt_ratchet as fixture_source


class InventorySpanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_source.InventoryReferenceDebtTests(
            'test_valid_tracked_inventory_filename_is_metadata')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def expect(self, document, count):
        result = self.fixture.invoke(document)
        self.assertEqual(result.returncode, 0 if count == 0 else 1,
                         result.stdout + result.stderr)
        if count:
            self.assertIn('new_files: ' + self.fixture.manifest_path + ' = ' + str(count),
                          result.stderr)
        self.assertIn('(' + str(count) + ' findings', result.stdout)

    def test_identical_message_value_is_not_subtracted_with_inventory_path(self):
        document = {'schema': 1, 'closure': [self.fixture.entry],
                    'message': self.fixture.filename}
        self.expect(json.dumps(document), 1)

    def test_escaped_path_key_and_reordered_fields_keep_exact_value_span(self):
        entry = dict(reversed(list(self.fixture.entry.items())))
        document = {'message': self.fixture.filename, 'closure': [entry], 'schema': 1}
        raw = json.dumps(document, indent=2).replace('"path":', '"p\\u0061th":')
        self.expect(raw, 1)

    def test_nested_lookalike_outside_closure_remains_a_finding(self):
        document = {'schema': 1, 'closure': [self.fixture.entry],
                    'description': dict(self.fixture.entry)}
        self.expect(json.dumps(document), 1)

    def test_escaped_path_value_does_not_subtract_identical_free_text(self):
        document = {'schema': 1, 'closure': [self.fixture.entry],
                    'message': self.fixture.filename}
        raw = json.dumps(document)
        encoded = json.dumps(self.fixture.filename)
        replacement = encoded.replace('O', '\\u004f', 1)
        raw = raw.replace(encoded, replacement, 1)
        self.expect(raw, 1)

    def test_ambiguous_and_non_json_values_preserve_raw_findings(self):
        document = {'schema': 1, 'closure': [self.fixture.entry],
                    'message': self.fixture.filename}
        raw = json.dumps(document)
        cases = [raw[:-1] + ',"message":"clean"}',
                 raw[:-1] + ',"numeric":NaN}',
                 raw[:-1] + ',"numeric":Infinity}']
        for value in cases:
            with self.subTest(document=value):
                self.expect(value, 2)


if __name__ == '__main__':
    unittest.main()

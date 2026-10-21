"""Cloud selection retains every case with explicit native custody."""
import importlib.util
from pathlib import Path
import unittest

HELPER = Path(__file__).resolve().parents[1] / "services/cloud-ci/runner/script-contracts.py"

def case(name):
    class NamedCase(unittest.TestCase):
        def id(self):
            return name
        def runTest(self):
            raise AssertionError("selection must not execute a case")
    return NamedCase()

class CustodyTests(unittest.TestCase):
    def helper(self):
        self.assertTrue(HELPER.is_file(), "trusted script custody selector is missing")
        spec = importlib.util.spec_from_file_location("cloud_script_custody", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_every_case_has_exactly_one_execution_lane(self):
        helper = self.helper()
        native = {"native.kernel"}
        suite = unittest.TestSuite([case("portable.first"), unittest.TestSuite([case("native.kernel"), case("portable.second")])])
        selected, custody = helper.partition(suite, native)
        self.assertEqual([case.id() for case in selected], ["portable.first", "portable.second"])
        self.assertEqual(custody, ["native.kernel"])
        self.assertEqual(selected.countTestCases() + len(custody), 3)

    def test_stale_native_custody_cannot_silently_remove_a_case(self):
        helper = self.helper()
        with self.assertRaisesRegex(ValueError, "missing native"):
            helper.partition(unittest.TestSuite([case("portable.first")]), {"native.renamed"})

    def test_duplicate_case_identity_is_rejected(self):
        helper = self.helper()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            helper.partition(unittest.TestSuite([case("portable.first"), case("portable.first")]), set())

    def test_empty_portable_selection_cannot_pass(self):
        helper = self.helper()
        with self.assertRaisesRegex(ValueError, "empty portable"):
            helper.partition(unittest.TestSuite([case("native.kernel")]), {"native.kernel"})

if __name__ == "__main__":
    unittest.main()

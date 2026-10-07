"""Execute current transaction functions; fixtures do not boot a QEMU guest."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name("qemu-transactions.sh")
PREVIOUS = b'{"previous":"good"}\n'


class TransactionSummary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.summary = self.root / "summary.json"
        self.summary.write_bytes(PREVIOUS)
        (self.root / "results.json").write_text('[{"id":"trial","result":"NOT_RUN"}]')
        (self.root / "bases.json").write_text('{"install":null,"remove":null}')
        source = SOURCE.read_text()
        self.functions = source[source.index("write_summary() {"):
                                source.index("trap finish EXIT")]

    def run_shell(self, command, fault=""):
        return subprocess.run(
            ["bash", "-c", 'set -euo pipefail\noutput=$1\ndistro=arch\n'
             'phase=trial\npreparation_step=ready\nsamples=1\ncurrent_id=\n'
             'failure_result=HARNESS_ERROR\nfailure_exit=\n'
             + self.functions + '\n' + fault + '\n' + command,
             "summary-test", str(self.root)],
            capture_output=True, text=True, timeout=10, check=False)

    def assert_previous(self):
        self.assertEqual(self.summary.read_bytes(), PREVIOUS)

    def test_partial_serializer_failure_preserves_bytes_and_status_under_or_list(self):
        result = self.run_shell('write_summary false || exit "$?"',
                                'jq() { printf partial; return 17; }')
        self.assert_previous()
        self.assertEqual(result.returncode, 17, result.stderr)

    def test_real_jq_invalid_input_preserves_previous_summary(self):
        (self.root / "results.json").write_text('{invalid')
        result = self.run_shell('write_summary false || exit "$?"')
        self.assert_previous()
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("Bad JSON in --slurpfile rows", result.stderr)

    def test_rename_failure_preserves_bytes_and_status(self):
        result = self.run_shell('write_summary false || exit "$?"',
                                'mv() { return 23; }')
        self.assert_previous()
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertFalse(json.loads((self.root / "summary.next.json").read_text())["complete"])

    def test_success_publishes_complete_json_by_same_directory_rename(self):
        previous_inode = self.summary.stat().st_ino
        # Inspect both files immediately before the real rename.
        observer = '''mv() {
          [[ "$1" == "$output/summary.next.json" && "$2" == "$output/summary.json" ]]
          [[ $(cat "$2") == '{"previous":"good"}' ]]
          command jq -e '.complete == true and .expected_trials == 4' "$1" >/dev/null
          stat -c %i "$1" > "$output/next.inode"
          command mv "$@"
        }'''
        result = self.run_shell('write_summary true', observer)
        self.assertEqual(result.returncode, 0, result.stderr)
        published = json.loads(self.summary.read_text())
        self.assertTrue(published["complete"])
        self.assertEqual(published["results"], [{"id": "trial", "result": "NOT_RUN"}])
        self.assertEqual(published["bases"], {"install": None, "remove": None})
        self.assertEqual(self.summary.stat().st_ino, int((self.root / "next.inode").read_text()))
        self.assertNotEqual(self.summary.stat().st_ino, previous_inode)
        self.assertFalse((self.root / "summary.next.json").exists())

    def test_finish_preserves_original_exit_and_reports_serializer_failure(self):
        result = self.run_shell('trap finish EXIT\nexit 73',
                                'jq() { printf partial; return 17; }')
        self.assert_previous()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("Could not update incomplete summary", result.stderr)

    def test_finish_preserves_original_exit_and_reports_rename_failure(self):
        result = self.run_shell('trap finish EXIT\nexit 73', 'mv() { return 23; }')
        self.assert_previous()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("Could not update incomplete summary", result.stderr)

    def test_finish_keeps_failed_trial_when_only_summary_serializer_fails(self):
        fault = '''jq() {
          if [[ "$1" == -n ]]; then printf partial; return 17; fi
          command jq "$@"
        }'''
        result = self.run_shell('current_id=trial\nfailure_exit=19\ntrap finish EXIT\nexit 73', fault)
        self.assert_previous()
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertIn("Could not update incomplete summary", result.stderr)
        self.assertEqual(json.loads((self.root / "results.json").read_text()),
                         [{"id": "trial", "result": "HARNESS_ERROR", "exit_code": 19}])


if __name__ == "__main__":
    unittest.main()

import hashlib
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("qemu_policy", ROOT / "scripts/check-qemu-inventory.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PolicyTests(unittest.TestCase):
    def test_current_inventory_has_exact_policy_case_set(self):
        inventory = ROOT / "tests/cli_behavior_inventory.tsv"
        rules = json.loads((ROOT / "tests/qemu-inventory-policy.json").read_text())
        cases = rules["inventories"][hashlib.sha256(inventory.read_bytes()).hexdigest()]["cases"]
        with inventory.open(newline="") as source:
            expected = {row["case"] for row in csv.DictReader(source, delimiter="\t")}
        self.assertEqual({case["id"] for case in cases}, expected)
        self.assertEqual(len(cases), len(expected))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.inventory = self.root / "cases.tsv"
        self.inventory.write_bytes(b"fixture inventory\n")
        self.policy = self.root / "policy.json"
        self.policy.write_text(json.dumps({"profiles": {"hermetic": ["hermetic"]}, "inventories": {
            hashlib.sha256(self.inventory.read_bytes()).hexdigest(): {"cases": [
                {"id": "required", "tiers": ["hermetic"], "network_scope": "offline", "allowed_skips": {}},
                {"id": "optional", "tiers": ["hermetic"], "network_scope": "offline", "allowed_skips": {"arch": "declared-cli-shape-only"}},
            ]}}}))
        self.results = self.root / "results.json"
        self.summary = self.root / "summary.json"
        self.rows = [dict(case_id="qemu-arch-required", distro="arch", artifact_source="inventory",
                          result="PASS", exit_code=0, network_scope="offline"),
                     dict(case_id="qemu-arch-optional", distro="arch", artifact_source="inventory",
                          result="SKIPPED", exit_code=-1)]
        self.summary.write_text('{"complete":true,"pass":1,"fail":0,"skipped":1}')

    def admit(self):
        self.results.write_text(json.dumps(self.rows))
        return POLICY.admit(self.policy, self.inventory, self.results, self.summary, "arch", "hermetic")

    def test_counts_separate_executed_from_selected(self):
        receipt = self.admit()
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["counts"], dict(selected=2, executed=1, passed=1, failed=0,
                                               blocked=0, harness_error=0, skipped=1))

    def test_missing_duplicate_substituted_and_unapproved_skip_fail(self):
        original = self.rows[:]
        for rows in (original[:1], [original[0], original[0]],
                     [dict(original[0], case_id="qemu-arch-substitute"), original[1]],
                     [dict(original[0], result="SKIPPED", exit_code=-1), original[1]]):
            self.rows = rows
            with self.assertRaises(ValueError):
                self.admit()

    def test_incomplete_and_inconsistent_summary_fail(self):
        for summary in ({"complete": False, "pass": 1, "fail": 0, "skipped": 1},
                        {"complete": True, "pass": 2, "fail": 0, "skipped": 0}):
            self.summary.write_text(json.dumps(summary))
            with self.assertRaises(ValueError):
                self.admit()

    def test_changed_inventory_needs_policy_review(self):
        self.inventory.write_bytes(b"changed inventory\n")
        with self.assertRaises(KeyError):
            self.admit()

    def test_unconfined_hermetic_result_is_rejected(self):
        self.rows[0]["network_scope"] = "unconfined"
        with self.assertRaises(ValueError):
            self.admit()

    def test_published_and_current_network_dependencies_are_explicit(self):
        rules = json.loads((ROOT / "tests/qemu-inventory-policy.json").read_text())
        current = hashlib.sha256((ROOT / "tests/cli_behavior_inventory.tsv").read_bytes()).hexdigest()
        cases = {case['id']: case for case in rules['inventories'][current]['cases']}
        self.assertEqual(cases['audit-sbom-offline']['network_scope'], 'offline')
        self.assertEqual(cases['update-turbo']['network_scope'], 'network')
        self.assertTrue(cases['update-turbo']['network_reason'])
        self.assertEqual(cases['daemon-foreground']['network_scope'], 'offline')
        for inventory in rules["inventories"].values():
            cases = {case["id"]: case for case in inventory["cases"]}
            for identity in ("doctor", "update", "runtime-python-install", "container-list"):
                self.assertEqual(cases[identity]["network_scope"], "network")
                self.assertTrue(cases[identity]["network_reason"])
            self.assertEqual(cases["info"]["network_scope"], "offline")
            self.assertTrue(all(case["network_scope"] in ("network", "offline") for case in cases.values()))

    def test_product_failure_is_not_admitted(self):
        self.rows[0].update(result="FAIL", exit_code=1)
        self.summary.write_text('{"complete":true,"pass":0,"fail":1,"skipped":1}')
        self.assertFalse(self.admit()["passed"])

    def test_duplicate_json_keys_cannot_replace_failure_or_completion(self):
        self.results.write_text(json.dumps(self.rows))
        original_results = self.results.read_text()
        original_summary = self.summary.read_text()
        for target in ('results', 'summary'):
            with self.subTest(target=target):
                self.results.write_text(original_results)
                self.summary.write_text(original_summary)
                if target == 'results':
                    self.results.write_text(original_results.replace(
                        '"result": "PASS"', '"result": "FAIL", "result": "PASS"', 1))
                else:
                    self.summary.write_text(original_summary.replace(
                        '"complete":true', '"complete":false,"complete":true', 1))
                with self.assertRaises(ValueError):
                    POLICY.admit(self.policy, self.inventory, self.results,
                                 self.summary, 'arch', 'hermetic')

    def test_current_inventory_and_workflow_have_reviewed_policy(self):
        content = (ROOT / "tests/cli_behavior_inventory.tsv").read_bytes().replace(b"\r\n", b"\n")
        rules = json.loads((ROOT / "tests/qemu-inventory-policy.json").read_text())
        cases = rules["inventories"][hashlib.sha256(content).hexdigest()]["cases"]
        self.assertEqual(len(cases), len(content.splitlines()) - 1)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        workflow = (ROOT / ".github/workflows/qemu-matrix.yml").read_text() + (ROOT / ".github/workflows/qemu-lane.yml").read_text()
        self.assertEqual(workflow.count("--inventory-policy tests/qemu-inventory-policy.json"), 2)


if __name__ == "__main__":
    unittest.main()

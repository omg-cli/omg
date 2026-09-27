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

    def test_fedora_fingerprint_rows_require_real_success(self):
        with (ROOT / "tests/cli_behavior_inventory.tsv").open(newline="") as source:
            rows = {row["case"]: row for row in csv.DictReader(source, delimiter="\t")}
        for case in (
            "snapshot-create", "migrate-export", "migrate-import", "env-capture",
            "env-check", "team-status", "team-push", "team-pull",
        ):
            with self.subTest(case=case):
                self.assertEqual(rows[case]["expected_exit"], "0")
                self.assertEqual(rows[case]["targets"], "hermetic:pass")
                self.assertEqual(rows[case]["assertions"], f"fingerprint:{case}")
        self.assertEqual(rows["team-status"]["requires"], "team-push")
        self.assertEqual(rows["team-pull"]["requires"], "team-push")

    def test_workspace_and_container_scaffold_rows_require_semantic_assertions(self):
        with (ROOT / "tests/cli_behavior_inventory.tsv").open(newline="") as source:
            rows = {row["case"]: row for row in csv.DictReader(source, delimiter="\t")}
        for case, assertion, prerequisite in (
            ("workspace-list", "workspace-project-listed", "workspace-add"),
            ("workspace-remove", "workspace-project-removed", "workspace-add"),
            ("container-init", "container-init-scaffold", "-"),
        ):
            with self.subTest(case=case):
                self.assertEqual(rows[case]["assertions"], assertion)
                self.assertEqual(rows[case]["requires"], prerequisite)
                self.assertEqual(rows[case]["targets"], "hermetic:pass")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.inventory = self.root / "cases.tsv"
        self.inventory.write_bytes(
            b"case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup\n"
            b"required\t[\"doctor\"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\tnone\n"
            b"optional\t[\"doctor\",\"--turbo\"]\tread\t-\tdeclared\t-\thermetic\tarch:pending\t-\tnone\n"
        )
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

    def repolicy_inventory(self, content):
        self.inventory.write_bytes(content.encode("utf-8"))
        rules = json.loads(self.policy.read_text())
        cases = next(iter(rules["inventories"].values()))
        rules["inventories"] = {hashlib.sha256(self.inventory.read_bytes()).hexdigest(): cases}
        self.policy.write_text(json.dumps(rules))

    def admit(self, distro="arch"):
        self.results.write_text(json.dumps(self.rows))
        return POLICY.admit(self.policy, self.inventory, self.results, self.summary, distro, "hermetic")

    def test_counts_separate_executed_from_selected(self):
        receipt = self.admit()
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["counts"], dict(selected=2, executed=1, passed=1, failed=0,
                                               blocked=0, harness_error=0, skipped=1))

    def test_wrong_pass_exit_is_rejected(self):
        self.rows[0]["exit_code"] = 1
        with self.assertRaises(ValueError):
            self.admit()

    def test_pass_accepts_intentional_nonzero_scalar_and_mapped_exits(self):
        content = self.inventory.read_text().replace("\t0\tpass\t", "\t2\tpass\t", 1)
        self.repolicy_inventory(content)
        self.rows[0]["exit_code"] = 2
        self.assertTrue(self.admit()["passed"])
        self.rows[0]["exit_code"] = 0
        with self.assertRaises(ValueError):
            self.admit()

        mapping = "arch:1,debian:0,ubuntu:0,fedora:125"
        self.repolicy_inventory(content.replace("\t2\tpass\t", f"\t{mapping}\tpass\t", 1))
        self.rows[0]["exit_code"] = 1
        self.assertTrue(self.admit()["passed"])
        self.rows[0]["exit_code"] = 2
        with self.assertRaises(ValueError):
            self.admit()

        rules = json.loads(self.policy.read_text())
        cases = next(iter(rules["inventories"].values()))["cases"]
        cases[1]["allowed_skips"]["fedora"] = "declared-cli-shape-only"
        self.policy.write_text(json.dumps(rules))
        for row in self.rows:
            row["case_id"] = row["case_id"].replace("qemu-arch-", "qemu-fedora-")
            row["distro"] = "fedora"
        self.rows[0]["exit_code"] = 125
        self.assertTrue(self.admit("fedora")["passed"])
        self.rows[0]["exit_code"] = 0
        with self.assertRaises(ValueError):
            self.admit("fedora")

    def test_declared_case_cannot_report_pass(self):
        self.rows[1].update(result="PASS", exit_code=0, network_scope="offline")
        self.summary.write_text('{"complete":true,"pass":2,"fail":0,"skipped":0}')
        with self.assertRaises(ValueError):
            self.admit()

    def test_rehashed_malformed_inventory_cannot_admit_pass(self):
        original = self.inventory.read_text()
        required = original.splitlines()[1]
        malformed = (
            original + required + "\n",
            original.replace("\t0\tpass\t", "\t0\tpass\tEXTRA\t", 1),
            original.replace("\t0\tpass\t", "\tpass\t", 1),
            original.replace("\t0\tpass\t", "\tarch:1,arch:0,ubuntu:0,fedora:0\tpass\t", 1),
            original.replace("\t0\tpass\t", "\tarch:1,debian:0,ubuntu:0,fedora:256\tpass\t", 1),
        )
        for content in malformed:
            with self.subTest(content=content.splitlines()[1]):
                self.repolicy_inventory(content)
                with self.assertRaises(ValueError):
                    self.admit()

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
        self.assertEqual(cases['doctor-network']['network_scope'], 'offline')
        self.assertEqual(cases['doctor-network']['tiers'], ['container'])
        self.assertEqual(cases['doctor-network']['allowed_skips'], {})
        self.assertIn('container', rules['profiles']['hermetic,container'])
        self.assertEqual(cases['audit-secrets']['network_scope'], 'offline')
        self.assertEqual(cases['audit-secrets-critical']['tiers'], ['hermetic'])
        self.assertEqual(cases['audit-secrets-critical']['allowed_skips'], {})
        self.assertEqual(cases['audit-eol']['tiers'], ['hermetic'])
        self.assertEqual(cases['audit-eol']['network_scope'], 'offline')
        self.assertEqual(cases['audit-eol']['allowed_skips'], {})
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
        by_id = {case["id"]: case for case in cases}
        self.assertEqual(by_id["run-watch"], {
            "id": "run-watch", "tiers": ["container", "pty"],
            "allowed_skips": {}, "network_scope": "offline",
        })
        self.assertEqual(by_id["doctor-eol"], {
            "id": "doctor-eol", "tiers": ["container"],
            "allowed_skips": {}, "network_scope": "offline",
        })
        self.assertEqual(by_id["container-run-detached-argv"], {
            "id": "container-run-detached-argv", "tiers": ["hermetic"],
            "allowed_skips": {}, "network_scope": "offline",
        })
        for case_id in ("container-shell-argv", "container-build-argv"):
            self.assertEqual(by_id[case_id], {
                "id": case_id, "tiers": ["hermetic"],
                "allowed_skips": {}, "network_scope": "offline",
            })
        for case_id in ("container-run-detached", "container-run-interactive",
                        "container-shell-flags", "container-build-flags"):
            self.assertEqual(set(by_id[case_id]["allowed_skips"]),
                             {"arch", "debian", "ubuntu", "fedora"})
        for runtime in ("node", "python", "go"):
            with self.subTest(runtime=runtime):
                self.assertEqual(by_id[f"runtime-{runtime}-uninstall"], {
                    "id": f"runtime-{runtime}-uninstall", "tiers": ["container"],
                    "allowed_skips": {}, "network_scope": "offline",
                })
                for operation in ("list", "switch"):
                    case_id = f"runtime-{runtime}-{operation}-installed"
                    self.assertEqual(by_id[case_id], {
                        "id": case_id, "tiers": ["container"],
                        "allowed_skips": {}, "network_scope": "offline",
                    })
        workflow = (ROOT / ".github/workflows/qemu-matrix.yml").read_text() + (ROOT / ".github/workflows/qemu-lane.yml").read_text()
        self.assertEqual(workflow.count("--inventory-policy tests/qemu-inventory-policy.json"), 2)
        self.assertIn('--inventory-tiers "hermetic,container"', workflow)


if __name__ == "__main__":
    unittest.main()

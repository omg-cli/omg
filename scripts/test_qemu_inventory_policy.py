import hashlib
import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from qemu_inventory_policy import all_snapshots, load_index, load_snapshot, network_scopes


def reviewed_rules():
    index, snapshots = all_snapshots(ROOT / "tests/qemu-inventory-policy.json")
    return {"profiles": index["profiles"], "inventories": snapshots}


SPEC = importlib.util.spec_from_file_location("qemu_policy", ROOT / "scripts/check-qemu-inventory.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class PolicyTests(unittest.TestCase):
    def test_native_orphan_cleanup_executes_on_fedora(self):
        with (ROOT / 'tests/cli_behavior_inventory.tsv').open(newline='') as source:
            rows = {row['case']: row for row in csv.DictReader(source, delimiter='\t')}
        row = rows['clean-orphans-native']
        self.assertEqual(json.loads(row['args_json']), ['clean', '--orphans', '--yes'])
        self.assertIn('fedora:pass', row['targets'].split(','))
        self.assertEqual(row['assertions'], 'native-orphan-removed')

    def test_golden_path_chain_requires_semantic_state_oracles(self):
        with (ROOT / 'tests/cli_behavior_inventory.tsv').open(newline='') as source:
            rows = {row['case']: row for row in csv.DictReader(source, delimiter='\t')}
        for case, prerequisite, assertion in (
            ('team-golden-create', 'team-init', 'golden-path-created'),
            ('team-golden-list', 'team-golden-create', 'golden-path-listed'),
            ('team-golden-delete', 'team-golden-list', 'golden-path-deleted'),
        ):
            with self.subTest(case=case):
                self.assertEqual(rows[case]['requires'], prerequisite)
                self.assertEqual(rows[case]['assertions'], assertion)
                self.assertEqual(rows[case]['targets'], 'hermetic:pass')

    def test_all_historical_snapshot_hashes_are_bounded_and_reportable(self):
        policy = ROOT / "tests/qemu-inventory-policy.json"
        index, snapshots = all_snapshots(policy)
        self.assertGreaterEqual(len(snapshots), 23)
        self.assertEqual(set(snapshots), set(index["inventories"]))
        self.assertLessEqual(policy.stat().st_size, 1024 * 1024)
        for digest, snapshot in snapshots.items():
            with self.subTest(digest=digest):
                self.assertTrue(snapshot["cases"])
                self.assertLessEqual((policy.with_name(policy.stem + ".d") /
                                      f"{digest}.json").stat().st_size, 1024 * 1024)

    def test_current_inventory_has_exact_policy_case_set(self):
        inventory = ROOT / "tests/cli_behavior_inventory.tsv"
        rules = reviewed_rules()
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
        self.policy_dir = self.root / "policy.d"
        self.policy_dir.mkdir()
        self.selection = {"releases": [], "cases": [
                {"id": "required", "tiers": ["hermetic"], "network_scope": "offline", "allowed_skips": {}},
                {"id": "optional", "tiers": ["hermetic"], "network_scope": "offline", "allowed_skips": {"arch": "declared-cli-shape-only"}},
            ]}
        self.write_policy()
        self.results = self.root / "results.json"
        self.summary = self.root / "summary.json"
        self.rows = [dict(case_id="qemu-arch-required", distro="arch", artifact_source="inventory",
                          result="PASS", exit_code=0, network_scope="offline"),
                     dict(case_id="qemu-arch-optional", distro="arch", artifact_source="inventory",
                          result="SKIPPED", exit_code=-1)]
        self.summary.write_text('{"complete":true,"pass":1,"fail":0,"skipped":1}')

    def repolicy_inventory(self, content):
        self.inventory.write_bytes(content.encode("utf-8"))
        self.write_policy()

    def write_policy(self):
        for old in self.policy_dir.iterdir():
            old.unlink()
        digest = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        content = json.dumps(self.selection).encode("utf-8")
        (self.policy_dir / f"{digest}.json").write_bytes(content)
        self.policy.write_text(json.dumps({"schema_version": 2,
            "profiles": {"hermetic": ["hermetic"]},
            "inventories": {digest: hashlib.sha256(content).hexdigest()}}))

    def admit(self, distro="arch"):
        self.results.write_text(json.dumps(self.rows))
        return POLICY.admit(self.policy, self.inventory, self.results, self.summary, distro, "hermetic")

    def test_staged_network_profile_requires_live_result(self):
        self.inventory.write_bytes(self.inventory.read_bytes() +
            b'live\t["doctor","--network"]\tcontrolled-error\t1\tpass\trequired\tnetwork\tarch:pass\t-\tnone\n')
        self.selection['cases'].append(dict(id='live', tiers=['network'],
            network_scope='network', allowed_skips={}))
        self.write_policy()
        index = json.loads(self.policy.read_text())
        index['profiles'] = load_index(ROOT / 'tests/qemu-inventory-policy.json')['profiles']
        self.policy.write_text(json.dumps(index))
        self.rows.append(dict(case_id='qemu-arch-live', distro='arch',
            artifact_source='inventory', result='PASS', exit_code=1, network_scope='network'))
        self.results.write_text(json.dumps(self.rows))
        self.summary.write_text('{"complete":true,"pass":2,"fail":0,"skipped":1}')
        command = [sys.executable, str(ROOT / 'scripts/check-qemu-inventory.py'),
            '--policy', str(self.policy), '--inventory', str(self.inventory),
            '--results', str(self.results), '--summary', str(self.summary),
            '--distro', 'arch', '--tiers', 'hermetic,container,network']
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertTrue(receipt['passed'])
        self.assertEqual(receipt['counts'], dict(selected=3, executed=2, passed=2,
            failed=0, blocked=0, harness_error=0, skipped=1))
        self.results.write_text(json.dumps(self.rows[:-1]))
        result = subprocess.run(command, capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)['passed'])

    def test_counts_separate_executed_from_selected(self):
        receipt = self.admit()
        self.assertTrue(receipt["passed"])
        self.assertEqual(receipt["counts"], dict(selected=2, executed=1, passed=1, failed=0,
                                               blocked=0, harness_error=0, skipped=1))

    def test_scope_projection_is_bound_to_inventory_digest(self):
        result = network_scopes(self.policy, self.inventory)
        self.assertEqual(result, {"inventory_sha256": hashlib.sha256(
            self.inventory.read_bytes()).hexdigest(),
            "scopes": {"required": "offline", "optional": "offline"}})
        self.inventory.write_bytes(b"different inventory\n")
        with self.assertRaises(KeyError):
            network_scopes(self.policy, self.inventory)

    def test_tampered_snapshot_fails_admission_and_scope_projection(self):
        snapshot = next(self.policy_dir.iterdir())
        snapshot.write_bytes(snapshot.read_bytes().replace(b'"offline"', b'"network"', 1))
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.admit()
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            network_scopes(self.policy, self.inventory)

    def test_signed_snapshot_cannot_hide_or_retier_inventory_case(self):
        original = [dict(case) for case in self.selection["cases"]]
        self.selection["cases"] = original[:1]
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "cases or tiers"):
            self.admit()
        self.selection["cases"] = original
        self.selection["cases"][0]["tiers"] = ["container"]
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "cases or tiers"):
            self.admit()

    def test_duplicate_keys_in_index_and_snapshot_fail_closed(self):
        index = self.policy.read_text()
        self.policy.write_text(index.replace('"profiles":', '"profiles": {}, "profiles":', 1))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.admit()
        self.write_policy()
        snapshot = next(self.policy_dir.iterdir())
        content = snapshot.read_text().replace('"network_scope": "offline"',
            '"network_scope": "network", "network_scope": "offline"', 1).encode()
        snapshot.write_bytes(content)
        index = json.loads(self.policy.read_text())
        index["inventories"][next(iter(index["inventories"]))] = hashlib.sha256(content).hexdigest()
        self.policy.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.admit()

    def test_traversal_digest_and_oversized_snapshot_fail_closed(self):
        index = json.loads(self.policy.read_text())
        file_hash = next(iter(index["inventories"].values()))
        index["inventories"] = {"../outside": file_hash}
        self.policy.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.admit()
        self.write_policy()
        snapshot = next(self.policy_dir.iterdir())
        snapshot.write_bytes(b" " * (1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "invalid inventory evidence file"):
            self.admit()

    def test_symlinked_snapshot_and_directory_fail_closed(self):
        snapshot = next(self.policy_dir.iterdir())
        target = self.root / "target.json"
        snapshot.replace(target)
        try:
            snapshot.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.admit()
        snapshot.unlink()
        self.policy_dir.rmdir()
        self.policy_dir.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "snapshot directory"):
            self.admit()

    def test_fifo_inputs_and_digest_shards_are_rejected_before_blocking_open(self):
        for kind in ("policy", "inventory", "results", "summary", "snapshot"):
            with self.subTest(kind=kind):
                self.write_policy()
                self.results.write_text(json.dumps(self.rows))
                self.summary.write_text('{"complete":true,"pass":1,"fail":0,"skipped":1}')
                target = next(self.policy_dir.iterdir()) if kind == "snapshot" else getattr(self, kind)
                content = target.read_bytes()
                target.unlink()
                os.mkfifo(target, 0o600)
                try:
                    started = time.monotonic()
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/check-qemu-inventory.py"),
                        "--policy", str(self.policy), "--inventory", str(self.inventory),
                        "--results", str(self.results), "--summary", str(self.summary),
                        "--distro", "arch", "--tiers", "hermetic"],
                        capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(json.loads(result.stdout), {
                        "schema_version": 1, "passed": False, "error": "inventory policy admission failed"})
                    self.assertLess(time.monotonic() - started, 3)
                finally:
                    target.unlink()
                    target.write_bytes(content)

    def test_add_command_appends_only_one_reviewed_digest(self):
        prior = self.policy.read_bytes()
        prior_file = next(self.policy_dir.iterdir())
        prior_content = prior_file.read_bytes()
        self.inventory.write_bytes(self.inventory.read_bytes() +
            b"new\t[\"status\"]\tread\t0\tpass\t-\thermetic\thermetic:pass\t-\tnone\n")
        candidate = self.root / "candidate.json"
        candidate.write_text(json.dumps({"releases": [], "cases": self.selection["cases"] +
            [{"id": "new", "tiers": ["hermetic"], "network_scope": "offline", "allowed_skips": {}}]}))
        result = subprocess.run([sys.executable, str(ROOT / "scripts/add-qemu-inventory-snapshot.py"),
            "--policy", str(self.policy), "--inventory", str(self.inventory),
            "--snapshot", str(candidate)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = hashlib.sha256(self.inventory.read_bytes()).hexdigest()
        self.assertEqual(result.stdout.strip(), digest)
        self.assertEqual(len(load_index(self.policy)["inventories"]), 2)
        self.assertEqual(prior_file.read_bytes(), prior_content)
        self.assertNotEqual(self.policy.read_bytes(), prior)
        self.assertEqual(len(load_snapshot(self.policy, load_index(self.policy), digest)["cases"]), 3)

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

        self.selection["cases"][1]["allowed_skips"]["fedora"] = "declared-cli-shape-only"
        self.write_policy()
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
        rules = reviewed_rules()
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
        rules = reviewed_rules()
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
        import re
        profiles = re.findall(r'--inventory-tiers ["]?([a-z,-]+)', workflow)
        self.assertEqual(len(profiles), 3)
        for profile in profiles:
            self.assertIn(profile, rules['profiles'], 'workflow selection requires reviewed admission')


    def test_index_admits_the_inventory_that_is_actually_shipped(self):
        """The current cli_behavior_inventory.tsv must be admissible.

        Admission computes sha256 over the inventory file and looks the digest
        up in the index, so a policy that does not contain that digest rejects
        every run. That is a silent-coverage failure: the sharding change and
        a content change to the reviewed inventory can land together, drop the
        old digest, and leave the harness unable to admit anything.
        """
        import hashlib

        inventory = (ROOT / "tests" / "cli_behavior_inventory.tsv").read_bytes()
        digest = hashlib.sha256(inventory).hexdigest()
        index = json.loads(
            (ROOT / "tests" / "qemu-inventory-policy.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            digest,
            index["inventories"],
            "the shipped inventory is not admissible by the shipped policy",
        )

    def test_every_indexed_digest_has_a_shard(self):
        """A digest with no shard file would KeyError at admission time."""
        policy = ROOT / "tests" / "qemu-inventory-policy.json"
        shard_dir = policy.with_name(policy.stem + ".d")
        index = json.loads(policy.read_text(encoding="utf-8"))
        missing = [d for d in index["inventories"] if not (shard_dir / f"{d}.json").is_file()]
        self.assertEqual(missing, [], "indexed digests without a shard file")

    def test_index_digests_are_unique_lowercase_hex(self):
        policy = ROOT / "tests" / "qemu-inventory-policy.json"
        index = json.loads(policy.read_text(encoding="utf-8"))
        for digest in index["inventories"]:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()

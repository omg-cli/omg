"""Falsify the guest oracle with success-shaped but incomplete artifacts."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace


SOURCE = Path(__file__).with_name("qemu-fingerprint-oracle.py")
SPEC = importlib.util.spec_from_file_location("fingerprint_oracle", SOURCE)
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class FingerprintOracleTests(unittest.TestCase):
    def test_fedora_native_query_keeps_literal_dnf_format_escape(self):
        with patch.object(ORACLE.subprocess, "run",
                          return_value=SimpleNamespace(stdout="curl\ngit\n")) as run:
            self.assertEqual(ORACLE.native_packages("fedora"), {"curl", "git"})
        self.assertEqual(run.call_args.args[0][-1], "%{name}\\n")
        self.assertIn("--cacheonly", run.call_args.args[0])
        self.assertIn("--disable-repo=*", run.call_args.args[0])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.names = {"curl", "git"}
        digest = hashlib.sha256(b"curl;git;").hexdigest()
        self.state = {"schema_version": 1, "runtimes": {}, "packages": ["curl", "git"],
                      "timestamp": 1700000000, "hash": digest}
        self.output = self.root / "stdout.log"

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def lock(self):
        self.write("omg.lock", 'schema_version = 1\npackages = ["curl", "git"]\n'
                   f'timestamp = 1700000000\nhash = "{self.state["hash"]}"\n[runtimes]\n')

    def run_case(self, case):
        with patch.object(ORACLE, "native_packages", return_value=self.names), \
             patch.object(ORACLE.sys, "argv", ["oracle", case, "fedora", str(self.root),
                                            str(self.output)]), \
             patch.dict(ORACLE.os.environ, {"OMG_DATA_DIR": str(self.data)}):
            ORACLE.main()

    def test_env_capture_rejects_empty_stale_and_corrupted_locks(self):
        self.output.write_text("Environment state captured\n")
        with self.assertRaises(AssertionError):
            self.run_case("env-capture")
        self.lock()
        self.output.write_text(f"Environment state captured {self.state['hash'][:16]} Packages: 2")
        self.run_case("env-capture")
        self.write("omg.lock", (self.root / "omg.lock").read_text().replace("curl", "wget"))
        with self.assertRaises(AssertionError):
            self.run_case("env-capture")

    def test_snapshot_requires_new_index_and_native_backed_sidecar(self):
        self.output.write_text("Snapshot created! ID: snap-1 Packages: 2")
        with self.assertRaises(AssertionError):
            self.run_case("snapshot-create")
        self.write("data/snapshots/index.json", json.dumps({"snapshots": [
            {"id": "snap-1", "message": "smoke", "hash": self.state["hash"]}]}))
        with self.assertRaises(AssertionError):
            self.run_case("snapshot-create")
        sidecar = {"id": "snap-1", "message": "smoke", "state": self.state}
        self.write("data/snapshots/snap-1.json", json.dumps(sidecar))
        self.run_case("snapshot-create")
        sidecar["state"] = dict(self.state, packages=[])
        self.write("data/snapshots/snap-1.json", json.dumps(sidecar))
        with self.assertRaises(AssertionError):
            self.run_case("snapshot-create")

    def test_manifest_requires_native_package_mapping(self):
        self.output.write_text("Exported to manifest.json Packages: 2")
        self.write("manifest.json", "{}")
        with self.assertRaises(AssertionError):
            self.run_case("migrate-export")
        manifest = {"version": "1.0", "source_distro": "fedora", "packages": [
            {"original_name": "curl"}, {"original_name": "git"}]}
        self.write("manifest.json", json.dumps(manifest))
        self.run_case("migrate-export")
        manifest["packages"].pop()
        self.write("manifest.json", json.dumps(manifest))
        with self.assertRaises(AssertionError):
            self.run_case("migrate-export")

    def test_team_push_requires_persisted_lock_and_matching_status(self):
        self.lock()
        self.output.write_text("Team lock updated!")
        self.write(".omg/team.toml", 'team_id = "smoke/team"\nmember_id = "tester"\n')
        status = {"config": {"team_id": "smoke/team"}, "lock_hash": "",
                  "members": [{"id": "tester", "env_hash": self.state["hash"],
                               "in_sync": True, "drift_summary": None}]}
        self.write(".omg/team-status.json", json.dumps(status))
        with self.assertRaises(AssertionError):
            self.run_case("team-push")
        status["lock_hash"] = self.state["hash"]
        self.write(".omg/team-status.json", json.dumps(status))
        self.run_case("team-push")
        ORACLE.poison_team_status(self.root)
        self.output.write_text("Environment is in sync with team!")
        with self.assertRaises(AssertionError):
            self.run_case("team-pull")
        with self.assertRaises(AssertionError):
            self.run_case("team-status")
        status["members"][0].update(env_hash=self.state["hash"], in_sync=True,
                                    drift_summary=None)
        self.write(".omg/team-status.json", json.dumps(status))
        self.run_case("team-pull")
        self.output.write_text("[Team Status] 1/1 members in sync")
        self.run_case("team-status")


if __name__ == "__main__":
    unittest.main()

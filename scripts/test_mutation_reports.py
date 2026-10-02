"""Behavioral acceptance tests for complete cargo-mutants shard receipts."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check-mutation-results.py")
SOURCE = "a" * 40
COUNTERS = {"CaughtMutant": "caught", "MissedMutant": "missed",
            "Timeout": "timeout", "Unviable": "unviable"}
FILES = ["src/core/archive.rs", "src/core/runtime_resolver.rs", "src/core/http.rs",
         "src/core/security/validation.rs", "src/core/security/policy.rs",
         "src/core/security/secrets.rs"]


def mutant(index):
    return {"name": f"src/core/http.rs:{index + 1}:1: replace true with false",
            "package": "omg", "file": "src/core/http.rs", "function": None,
            "span": {"start": {"line": index + 1, "column": 1},
                     "end": {"line": index + 1, "column": 5}},
            "replacement": "false", "genre": "BinaryOperator"}


def outcome(record, summary):
    phases = []
    for phase in ("Build", "Test"):
        status = "Success"
        if summary == "Unviable" and phase == "Build":
            status = {"Failure": 101}
        if summary == "CaughtMutant" and phase == "Test":
            status = {"Failure": 101}
        if summary == "Timeout" and phase == "Test":
            status = "Timeout"
        argv = ["/toolchain/bin/cargo", "test", "--verbose", "--package=omg@0.1.224",
                "--no-default-features", "--features=pgp,license", "--locked"]
        if phase == "Build":
            argv.append("--no-run")
        phases.append({"phase": phase, "duration": 1.0, "process_status": status,
                       "argv": argv})
        if summary == "Unviable":
            break
    return {"scenario": "Baseline" if record is None else {"Mutant": record},
            "summary": summary, "phase_results": phases}


class MutationReportsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = [mutant(i) for i in range(4)]
        self.make_reports(["CaughtMutant"] * 3 + ["MissedMutant"])

    def make_reports(self, summaries, shards=2):
        self.shards = shards
        width = (len(self.manifest) + shards - 1) // shards
        for index in range(shards):
            directory = self.root / f"shard-{index}"
            directory.mkdir(exist_ok=True)
            selected = self.manifest[index * width:(index + 1) * width]
            metadata = {"source_sha": SOURCE, "run_id": "123", "run_attempt": "1",
                        "shard_index": index, "shard_count": shards,
                        "cargo_mutants_version": "27.1.0", "files": FILES,
                        "test_timeout_seconds": 60, "jobs": 2,
                        "job_timeout_minutes": 120, "baseline": "run",
                        "no_default_features": True, "features": ["pgp", "license"],
                        "shuffling": False, "sharding": "slice"}
            self.write(directory / "metadata.json", metadata)
            self.write(directory / "expected-mutants.json", self.manifest)
            report = directory / "mutants.out"
            report.mkdir(exist_ok=True)
            self.write(report / "mutants.json", selected)
            outcomes = [outcome(None, "Success")]
            counters = dict(total_mutants=len(selected), caught=0, missed=0,
                            timeout=0, unviable=0, success=0)
            texts = {key: [] for key in COUNTERS.values()}
            for offset, record in enumerate(selected):
                summary = summaries[index * width + offset]
                outcomes.append(outcome(record, summary))
                counter = COUNTERS[summary]
                counters[counter] += 1
                texts[counter].append(record["name"])
            self.write(report / "outcomes.json", dict(
                outcomes=outcomes, start_time="2026-10-02T16:00:00Z",
                end_time="2026-10-02T16:01:00Z", cargo_mutants_version="27.1.0",
                **counters))
            for key, names in texts.items():
                (report / f"{key}.txt").write_text("".join(n + "\n" for n in names))

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def change(self, relative, edit):
        path = self.root / relative
        value = json.loads(path.read_text())
        edit(value)
        self.write(path, value)

    def run_gate(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root),
                               "--source-sha", SOURCE, "--run-id", "123",
                               "--run-attempt", "1", "--shards", str(self.shards)],
                              text=True, capture_output=True, timeout=10)

    def assert_rejected(self, message):
        result = self.run_gate()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_complete_partition_accepts_original_global_75_percent_floor(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("75% (3/4", result.stdout)

    def test_recorded_metadata_round_trips_through_real_cli(self):
        directory = self.root / "shard-0"
        (directory / "metadata.json").unlink()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(directory), "--source-sha", SOURCE,
             "--run-id", "123", "--run-attempt", "1", "--shards", "2", "--record-shard", "0"],
            text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.run_gate().returncode, 0)

    def test_original_75_percent_floor_does_not_round_up_74_percent(self):
        self.manifest = [mutant(i) for i in range(100)]
        self.make_reports(["CaughtMutant"] * 74 + ["MissedMutant"] * 26)
        self.assert_rejected("below 75%")

    def test_complete_sixteen_shard_union_is_required(self):
        self.manifest = [mutant(i) for i in range(32)]
        self.make_reports(["CaughtMutant"] * 32, shards=16)
        self.assertEqual(self.run_gate().returncode, 0)
        self.change("shard-15/mutants.out/outcomes.json", lambda v: v["outcomes"].pop())
        self.assert_rejected("missing mutant")

    def test_complete_report_below_floor_is_rejected(self):
        self.make_reports(["CaughtMutant"] * 2 + ["MissedMutant"] * 2)
        self.assert_rejected("below 75%")

    def test_completed_timeout_counts_against_score(self):
        self.make_reports(["CaughtMutant"] * 3 + ["Timeout"])
        self.assertEqual(self.run_gate().returncode, 0)

    def test_zero_viable_mutants_is_rejected(self):
        self.make_reports(["Unviable"] * 4)
        self.assert_rejected("zero viable")

    def test_interrupted_high_score_is_rejected(self):
        self.change("shard-0/mutants.out/outcomes.json", lambda v: v.update(end_time=None))
        self.assert_rejected("incomplete")

    def test_missing_shard_is_rejected(self):
        (self.root / "shard-1/metadata.json").unlink()
        self.assert_rejected("metadata")

    def test_metadata_revisions_run_attempt_and_limits_are_bound(self):
        changes = {"source_sha": "b" * 40, "run_id": "124", "run_attempt": "2",
                   "shard_index": 1, "shard_count": 3, "baseline": "skip",
                   "jobs": 3, "test_timeout_seconds": 61, "job_timeout_minutes": 121,
                   "files": FILES[:-1], "features": ["pgp"], "shuffling": True,
                   "sharding": "round-robin", "cargo_mutants_version": "28.0.0"}
        path = self.root / "shard-0/metadata.json"
        original = json.loads(path.read_text())
        for key, value in changes.items():
            with self.subTest(key=key):
                self.write(path, dict(original, **{key: value}))
                self.assert_rejected("metadata")
        self.write(path, original)

    def test_missing_duplicate_and_unknown_outcomes_are_rejected(self):
        path = self.root / "shard-0/mutants.out/outcomes.json"
        original = json.loads(path.read_text())
        for mode in ("missing", "duplicate", "unknown"):
            with self.subTest(mode=mode):
                changed = copy.deepcopy(original)
                if mode == "missing":
                    changed["outcomes"].pop()
                elif mode == "duplicate":
                    changed["outcomes"].append(copy.deepcopy(changed["outcomes"][-1]))
                else:
                    changed["outcomes"][-1]["scenario"]["Mutant"] = mutant(100)
                self.write(path, changed)
                self.assert_rejected("mutant")
        self.write(path, original)

    def test_baseline_must_exist_and_succeed(self):
        path = self.root / "shard-0/mutants.out/outcomes.json"
        original = json.loads(path.read_text())
        for mode in ("missing", "duplicate", "failed"):
            with self.subTest(mode=mode):
                changed = copy.deepcopy(original)
                if mode == "missing":
                    changed["outcomes"].pop(0)
                elif mode == "duplicate":
                    changed["outcomes"].append(copy.deepcopy(changed["outcomes"][0]))
                else:
                    changed["outcomes"][0]["summary"] = "Failure"
                self.write(path, changed)
                self.assert_rejected("baseline")
        self.write(path, original)

    def test_narrowed_baseline_and_mutant_commands_are_rejected(self):
        path = self.root / "shard-0/mutants.out/outcomes.json"
        original = json.loads(path.read_text())
        for scenario in (0, 1):
            for flag in ("--lib", "--all-targets", "--test=one", "filter", "--", "--ignored"):
                with self.subTest(scenario=scenario, flag=flag):
                    changed = copy.deepcopy(original)
                    changed["outcomes"][scenario]["phase_results"][-1]["argv"].append(flag)
                    self.write(path, changed)
                    self.assert_rejected("full portable cargo test")
        self.write(path, original)

    def test_manifests_counters_and_text_must_agree(self):
        cases = [
            ("shard-0/expected-mutants.json", lambda v: v.pop(), "manifest"),
            ("shard-0/mutants.out/mutants.json", lambda v: v.pop(), "manifest"),
            ("shard-0/mutants.out/outcomes.json", lambda v: v.update(caught=99), "counter"),
            ("shard-0/mutants.out/outcomes.json", lambda v: v.update(total_mutants=99), "counter"),
            ("shard-0/mutants.out/outcomes.json", lambda v: v.update(cargo_mutants_version="28"), "version"),
        ]
        for relative, edit, message in cases:
            with self.subTest(relative=relative, message=message):
                path = self.root / relative
                original = path.read_bytes()
                self.change(relative, edit)
                self.assert_rejected(message)
                path.write_bytes(original)
        (self.root / "shard-0/mutants.out/caught.txt").write_text("")
        self.assert_rejected("text report")

    def test_outcome_summary_must_match_phase_status(self):
        self.change("shard-0/mutants.out/outcomes.json", lambda v:
                    v["outcomes"][1]["phase_results"][-1].update(process_status="Success"))
        self.assert_rejected("phase")

    def test_malformed_json_fails_closed(self):
        (self.root / "shard-0/metadata.json").write_text("{")
        self.assert_rejected("metadata")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Admit only complete, source-bound cargo-mutants 27.1.0 shard reports.

Protocol: https://github.com/sourcefrog/cargo-mutants/blob/v27.1.0/src/outcome.rs
Partition: https://github.com/sourcefrog/cargo-mutants/blob/v27.1.0/src/shard.rs
"""
import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re
import sys

FILES = ["src/core/archive.rs", "src/core/runtime_resolver.rs", "src/core/http.rs",
         "src/core/security/validation.rs", "src/core/security/policy.rs",
         "src/core/security/secrets.rs"]
VERSION = "27.1.0"
COUNTERS = {"CaughtMutant": "caught", "MissedMutant": "missed",
            "Timeout": "timeout", "Unviable": "unviable"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(f"cannot read {path}: {error}") from error


def metadata(args, index):
    return dict(source_sha=args.source_sha, run_id=args.run_id,
                run_attempt=args.run_attempt, shard_index=index, shard_count=args.shards,
                cargo_mutants_version=VERSION, files=FILES, test_timeout_seconds=120,
                jobs=2, job_timeout_minutes=120, baseline="run", no_default_features=True,
                features=["pgp", "license"], shuffling=False, sharding="slice")


def records(manifest):
    require(isinstance(manifest, list) and manifest, "empty or invalid mutant manifest")
    result = {}
    for record in manifest:
        require(isinstance(record, dict) and isinstance(record.get("name"), str),
                "invalid mutant manifest record")
        name = record["name"]
        require(name and name not in result, "duplicate mutant manifest identity")
        require(record.get("package") == "omg" and record.get("file") in FILES,
                "unexpected package or file in mutant manifest")
        result[name] = {key: value for key, value in record.items() if key != "diff"}
    return result


def full_test(phase):
    argv = phase.get("argv", [])
    require(isinstance(argv, list) and len(argv) >= 2
            and Path(argv[0]).name == "cargo" and argv[1] == "test",
            "phase must run full portable cargo test")
    args = argv[2:]
    package = [arg for arg in args if isinstance(arg, str)
               and re.fullmatch(r"--package=omg@[^= ]+", arg)]
    expected = ["--verbose", "--no-default-features", "--features=pgp,license", "--locked"]
    if phase["phase"] == "Build":
        expected.append("--no-run")
    require(len(package) == 1 and Counter(args) == Counter(expected + package),
            "phase must run full portable cargo test without test filters or skipped targets")


def verify_phases(outcome, baseline=False):
    phases = outcome.get("phase_results", [])
    summary = outcome.get("summary")
    require(isinstance(phases, list) and phases, "missing phase results")
    names = [p.get("phase") for p in phases]
    statuses = [p.get("process_status") for p in phases]
    for phase in phases:
        full_test(phase)
        duration = phase.get("duration")
        require(isinstance(duration, (int, float)) and 0 <= duration < float("inf"),
                "invalid phase duration")
    failure = lambda status: (isinstance(status, dict) and set(status) == {"Failure"}
                              and type(status["Failure"]) is int and status["Failure"] > 0)
    if baseline:
        require(summary == "Success" and names == ["Build", "Test"]
                and statuses == ["Success", "Success"], "baseline failed or incomplete")
    elif summary in ("CaughtMutant", "MissedMutant"):
        require(names == ["Build", "Test"] and statuses[0] == "Success"
                and (failure(statuses[1]) if summary == "CaughtMutant"
                     else statuses[1] == "Success"), "mutant summary contradicts phase results")
    elif summary == "Unviable":
        require(names == ["Build"] and failure(statuses[0]),
                "unviable mutant contradicts phase results")
    elif summary == "Timeout":
        require((names == ["Build"] and statuses == ["Timeout"])
                or (names == ["Build", "Test"] and statuses == ["Success", "Timeout"]),
                "timeout mutant contradicts phase results")
    else:
        raise ValueError(f"unexpected mutant phase summary: {summary}")


def check_reports(args):
    directories = sorted(args.directory.glob("*/metadata.json"))
    require(len(directories) == args.shards, "missing or unexpected shard metadata")
    expected_manifest = None
    seen_shards = set()
    seen_mutants = set()
    totals = Counter()
    for path in directories:
        directory = path.parent
        meta = read_json(path)
        index = meta.get("shard_index")
        require(type(index) is int and 0 <= index < args.shards
                and index not in seen_shards, "duplicate or invalid shard metadata index")
        require(directory.name == f"shard-{index}" and meta == metadata(args, index),
                "shard metadata differs from required directory/source/run/limits")
        seen_shards.add(index)
        manifest = read_json(directory / "expected-mutants.json")
        expected = records(manifest)
        if expected_manifest is None:
            expected_manifest = manifest
        require(manifest == expected_manifest, "full mutant manifests differ across shards")
        width = (len(manifest) + args.shards - 1) // args.shards
        selected = records(manifest[index * width:(index + 1) * width])
        report_dir = directory / "mutants.out"
        reported = records(read_json(report_dir / "mutants.json"))
        require(reported == selected, "shard mutant manifest differs from complete slice partition")
        report = read_json(report_dir / "outcomes.json")
        require(report.get("cargo_mutants_version") == VERSION, "cargo-mutants version differs")
        require(report.get("end_time") is not None, "incomplete mutation report (no end_time)")
        start = datetime.fromisoformat(report["start_time"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(report["end_time"].replace("Z", "+00:00"))
        require(end >= start, "incomplete or invalid report timestamps")
        outcomes = report.get("outcomes", [])
        baselines = [o for o in outcomes if o.get("scenario") == "Baseline"]
        require(len(baselines) == 1, "each shard requires exactly one complete successful baseline")
        verify_phases(baselines[0], baseline=True)
        actual = {}
        texts = {key: [] for key in COUNTERS.values()}
        counts = Counter()
        for outcome in outcomes:
            if outcome.get("scenario") == "Baseline":
                continue
            scenario = outcome.get("scenario")
            require(isinstance(scenario, dict) and set(scenario) == {"Mutant"},
                    "unexpected mutant scenario")
            record = scenario["Mutant"]
            name = record.get("name")
            require(name in selected and record == selected[name] and name not in actual
                    and name not in seen_mutants, "missing, duplicate, or unexpected mutant outcome")
            verify_phases(outcome)
            actual[name] = record
            seen_mutants.add(name)
            counter = COUNTERS[outcome["summary"]]
            counts[counter] += 1
            texts[counter].append(name)
        require(actual == selected, "missing mutant outcomes from completed report")
        for key in COUNTERS.values():
            require(type(report.get(key)) is int and report[key] == counts[key],
                    f"inconsistent {key} counter")
            text_path = report_dir / f"{key}.txt"
            require(Counter(text_path.read_text(encoding="utf-8").splitlines()) == Counter(texts[key]),
                    f"inconsistent {key} text report")
        require(type(report.get("total_mutants")) is int and report["total_mutants"] == len(actual)
                and type(report.get("success")) is int and report["success"] == 0,
                "inconsistent total/success counter")
        totals.update(counts)
    require(seen_mutants == set(records(expected_manifest)), "incomplete aggregate mutant union")
    viable = totals["caught"] + totals["missed"] + totals["timeout"]
    require(viable > 0, "mutation run tested zero viable mutants")
    score = totals["caught"] * 100 // viable
    require(score >= 75, f"mutation score {score}% is below 75%")
    print(f"Complete mutation score: {score}% ({totals['caught']}/{viable} viable mutants caught; "
          f"{totals['missed']} missed; {totals['timeout']} timed out; {totals['unviable']} unviable; "
          f"{len(seen_mutants)} generated mutants accounted for across {args.shards} shards)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--shards", type=int, default=16)
    parser.add_argument("--record-shard", type=int)
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha) and args.shards > 0,
                "invalid source SHA or shard count")
        if args.record_shard is not None:
            require(0 <= args.record_shard < args.shards, "invalid shard index")
            args.directory.mkdir(parents=True, exist_ok=True)
            (args.directory / "metadata.json").write_text(
                json.dumps(metadata(args, args.record_shard), indent=2) + "\n", encoding="utf-8")
        else:
            check_reports(args)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Mutation admission failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

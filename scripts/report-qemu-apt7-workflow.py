#!/usr/bin/env python3
"""File bounded pilot failure issues from trusted workflow_run job metadata."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


PILOT_PATH = ".github/workflows/qemu-apt7.yml"
PILOT_NAME = "QEMU APT 7 pilot"
FAILED = {"failure", "timed_out", "action_required"}
GUEST_JOB = re.compile(r"^APT 7 guest \((debian13|ubuntu2604)\)(?: / |$)")


def api(path):
    with tempfile.TemporaryFile() as output:
        subprocess.run(["gh", "api", path], stdout=output, check=True, timeout=60)
        if output.tell() > 1024 * 1024:
            raise ValueError("GitHub response exceeds reporting limit")
        output.seek(0)
        return json.load(output)


def identity(event, live, repository):
    original = event["workflow_run"]
    if (event["repository"]["full_name"] != repository
            or live["repository"]["full_name"] != repository
            or type(live["id"]) is not int or live["id"] != original["id"]
            or type(live["run_attempt"]) is not int or live["run_attempt"] < 1
            or live["run_attempt"] != original["run_attempt"]
            or live["head_sha"] != original["head_sha"]
            or live["workflow_id"] != original["workflow_id"]
            or live.get("name") != PILOT_NAME or live.get("path") != PILOT_PATH
            or live.get("event") != "workflow_dispatch"
            or live.get("head_branch") != "main"
            or live.get("status") != "completed"
            or not re.fullmatch(r"[0-9a-f]{40}", live["head_sha"])):
        raise ValueError("pilot workflow identity or attempt mismatch")
    return live


def failed_cases(jobs, conclusion):
    if not isinstance(jobs, list) or len(jobs) > 100:
        raise ValueError("invalid pilot jobs")
    guests = set()
    for job in jobs:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            raise ValueError("invalid pilot job")
        if job.get("conclusion") in FAILED:
            if match := GUEST_JOB.match(job["name"]):
                guests.add(match.group(1))
    if conclusion in ("cancelled", "skipped", "success"):
        return []
    if conclusion not in FAILED:
        raise ValueError("unexpected pilot conclusion")
    if guests:
        return [dict(case_id=f"qemu-{guest}-lifecycle", distro=guest,
                     result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)
                for guest in sorted(guests)]
    # Build, setup, checkout, and result failures have no guest receipt.
    return [dict(case_id="qemu-apt7-workflow", distro="matrix",
                 result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0)]


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    run_id = event["workflow_run"]["id"]
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("invalid run ID")
    run = identity(event, api(f"repos/{repository}/actions/runs/{run_id}"), repository)
    if run["conclusion"] in ("cancelled", "skipped", "success"):
        print("Pilot succeeded or was cancelled; no failure issue generated")
        return 0
    listing = api(f"repos/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs?per_page=100")
    if type(listing.get("total_count")) is not int or listing["total_count"] > 100:
        raise ValueError("pilot job count exceeds reporting limit")
    rows = failed_cases(listing.get("jobs"), run["conclusion"])
    # Reject stale workflow_run deliveries after a rerun supersedes this attempt.
    identity(event, api(f"repos/{repository}/actions/runs/{run_id}"), repository)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        results = root / "results.json"
        results.write_text(json.dumps(rows) + "\n")
        for row in rows:
            evidence = root / f"{row['distro']}-{row['case_id']}"
            evidence.mkdir()
            evidence.joinpath("transcript.txt").write_text(
                f"Commit: {run['head_sha']}\nAttempt: {run['run_attempt']}\n"
                "The pilot job failed. Its exit status does not establish the root cause.\n"
                "Inspect the linked run's job logs and uploaded guest evidence.\n")
        run_url = f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}"
        subprocess.run(["bash", "scripts/qa-file-issue.sh", str(results),
                        "--repo", repository, "--source", "qemu-apt7",
                        "--run-url", run_url, "--evidence-dir", directory,
                        "--failures-only"], check=True, timeout=180)
    print(f"Reported pilot run {run_id}, attempt {run['run_attempt']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Download and compare coverage evidence for the exact current/base commits."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

REPOSITORY = "omg-cli/omg"
WORKFLOW = ".github/workflows/coverage.yml"
MAX_REPORT = 128 * 1024 * 1024


def api(endpoint, *, binary=False):
    limit = MAX_REPORT if binary else 1024 * 1024
    with tempfile.TemporaryFile() as output:
        subprocess.run(["gh", "api", endpoint], check=True, stdout=output, timeout=180 if binary else 60)
        if output.tell() > limit:
            raise ValueError("Coverage GitHub response exceeds limit")
        output.seek(0)
        content = output.read(limit + 1)
    return content if binary else json.loads(content)


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("Missing or invalid coverage commit identity")
    if value == "0" * 40:
        raise ValueError("Coverage base does not exist")
    return value


def identities(event_name, event, checkout_sha):
    if event_name == "pull_request":
        return sha(event["pull_request"]["base"]["sha"]), sha(event["pull_request"]["head"]["sha"])
    if event_name == "merge_group":
        return sha(event["merge_group"]["base_sha"]), sha(event["merge_group"]["head_sha"])
    if event_name == "push":
        return sha(event["before"]), sha(checkout_sha)
    if event_name == "workflow_dispatch":
        parent = subprocess.run(["git", "rev-parse", "HEAD^"], check=True,
                                capture_output=True, text=True, timeout=30).stdout.strip()
        return sha(parent), sha(checkout_sha)
    raise ValueError("Unsupported coverage event")


def validate_run(run, commit, event_name, workflow_id, base=False):
    if (run.get("head_sha") != commit or run.get("event") != event_name
            or run.get("path") != WORKFLOW or run.get("workflow_id") != workflow_id
            or run.get("repository", {}).get("full_name") != REPOSITORY):
        raise ValueError("Coverage run identity does not match expected source/workflow")
    if base and (run.get("head_branch") != "main" or run.get("status") != "completed"
                 or run.get("conclusion") != "success"):
        raise ValueError("Base coverage must come from a successful main push")


def validate_artifact(artifacts, run_id, commit, name="coverage-lcov"):
    selected = [a for a in artifacts if a.get("name") == name]
    if len(selected) != 1:
        raise ValueError(f"Expected exactly one {name} artifact")
    artifact = selected[0]
    identity = artifact.get("workflow_run", {})
    if (artifact.get("expired") is not False or identity.get("id") != run_id
            or identity.get("head_sha") != commit):
        raise ValueError("Expired or mismatched coverage artifact identity")
    return artifact


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", value):
        raise ValueError("Missing or invalid coverage ownership timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def complete_listing(endpoint, field):
    rows, seen, total, page = [], set(), None, 1
    while True:
        listing = api(endpoint if page == 1 else f"{endpoint}&page={page}")
        batch, count = listing.get(field), listing.get("total_count")
        if (not isinstance(batch, list) or type(count) is not int or count < 0
                or (total is not None and count != total) or len(batch) > 100
                or (not batch and len(rows) != count)):
            raise ValueError(f"Coverage {field} listing is incomplete or changed")
        total = count
        for row in batch:
            identity = row.get("id")
            if type(identity) is not int or identity <= 0 or identity in seen:
                raise ValueError(f"Coverage {field} listing has invalid or duplicate IDs")
            seen.add(identity)
        rows.extend(batch)
        if len(rows) == total:
            return rows
        if len(rows) > total:
            raise ValueError(f"Coverage {field} listing is incomplete or changed")
        page += 1


def coverage_producer(run, commit):
    attempt = run.get("run_attempt")
    if type(attempt) is not int or attempt <= 0:
        raise ValueError("Missing or invalid coverage run attempt")

    def owner(number):
        jobs = complete_listing(
            f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{number}/jobs?per_page=100", "jobs")
        selected = [job for job in jobs if job.get("name") == "Instrumented coverage tests"]
        if len(selected) != 1:
            raise ValueError("Expected exactly one instrumented coverage producer")
        job = selected[0]
        if (job.get("run_id") != run["id"] or job.get("head_sha") != commit
                or type(job.get("id")) is not int):
            raise ValueError("Coverage producer identity mismatch")
        return job

    producer = owner(attempt)
    if producer.get("status") != "completed" or producer.get("conclusion") != "success":
        raise ValueError("Latest coverage producer did not complete successfully")
    start, finish = timestamp(producer.get("started_at")), timestamp(producer.get("completed_at"))
    if start >= finish:
        raise ValueError("Invalid coverage producer interval")
    # Carried jobs retain their execution interval even when GitHub relabels
    # their attempt and ID. A new execution starts within its attempt's window.
    snapshot = run
    while start < timestamp(snapshot.get("run_started_at")):
        if attempt == 1:
            raise ValueError("Coverage producer predates its workflow run")
        attempt -= 1
        snapshot = api(f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{attempt}")
        if (snapshot.get("id") != run["id"] or snapshot.get("head_sha") != commit
                or snapshot.get("run_attempt") != attempt):
            raise ValueError("Coverage producer attempt identity mismatch")
        previous = owner(attempt)
        if (previous.get("started_at"), previous.get("completed_at")) != (
                producer["started_at"], producer["completed_at"]):
            raise ValueError("Carried coverage producer execution changed")
        if previous.get("status") != "completed" or previous.get("conclusion") != "success":
            raise ValueError("Carried coverage producer was not successful")
        producer = previous
    return attempt, producer


def coverage_artifacts(run, commit):
    attempt, producer = coverage_producer(run, commit)
    start, finish = timestamp(producer["started_at"]), timestamp(producer["completed_at"])
    artifacts = complete_listing(
        f"repos/{REPOSITORY}/actions/runs/{run['id']}/artifacts?per_page=100", "artifacts")
    pair = {}
    for kind in ("coverage-lcov", "coverage-regions"):
        selected = [artifact for artifact in artifacts
                    if re.fullmatch(kind + r"(?:-\d+-\d+)?", artifact.get("name", ""))
                    and start <= timestamp(artifact.get("created_at")) <= finish]
        expected = f"{kind}-{run['id']}-{attempt}"
        if len(selected) != 1 or selected[0]["name"] not in (kind, expected):
            raise ValueError(f"Expected exactly one {kind} artifact from the effective producer")
        artifact = validate_artifact(selected, run["id"], commit, selected[0]["name"])
        if (type(artifact.get("id")) is not int or artifact["id"] <= 0
                or type(artifact.get("size_in_bytes")) is not int
                or not 0 < artifact["size_in_bytes"] <= MAX_REPORT):
            raise ValueError("Invalid coverage artifact ID or size")
        pair[kind] = artifact
    if pair["coverage-lcov"]["id"] == pair["coverage-regions"]["id"]:
        raise ValueError("Coverage evidence pair has duplicate IDs")
    if (pair["coverage-lcov"]["name"] == "coverage-lcov") != (
            pair["coverage-regions"]["name"] == "coverage-regions"):
        raise ValueError("Coverage evidence pair mixes legacy and qualified names")
    return pair, attempt, producer["id"]


def download(run, commit, destination, name="coverage-lcov", *, artifact=None):
    if name not in ("coverage-lcov", "coverage-regions"):
        raise ValueError("Unsupported coverage artifact kind")
    if artifact is None:
        pair, _, _ = coverage_artifacts(run, commit)
        artifact = pair[name]
    content = api(f"repos/{REPOSITORY}/actions/artifacts/{artifact['id']}/zip", binary=True)
    if len(content) != artifact["size_in_bytes"]:
        raise ValueError("GitHub coverage artifact size mismatch")
    if artifact.get("digest") != "sha256:" + hashlib.sha256(content).hexdigest():
        raise ValueError("GitHub coverage artifact digest missing or mismatched")
    leaf = "lcov.info" if name == "coverage-lcov" else "coverage-regions.json.gz"
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if (len(members) != 1 or members[0].filename != leaf
                    or members[0].is_dir() or not 0 < members[0].file_size <= MAX_REPORT
                    or stat.S_IFMT(members[0].external_attr >> 16) not in (0, stat.S_IFREG)):
                raise ValueError("Coverage artifact must contain one bounded lcov.info report")
            payload = archive.read(members[0])
    except (zipfile.BadZipFile, RuntimeError) as error:
        raise ValueError("Invalid coverage artifact archive") from error
    refreshed = api(f"repos/{REPOSITORY}/actions/runs/{run['id']}")
    if any(refreshed.get(key) != run.get(key) for key in ("id", "head_sha", "run_attempt")):
        raise ValueError("Coverage producer attempt changed during download")
    destination.mkdir(parents=True, exist_ok=False)
    report = destination / leaf
    report.write_bytes(payload)
    return artifact, report


def ensure_source_commit(repo, commit):
    commit = sha(commit)
    command = ["git", "-C", str(repo)]
    present = subprocess.run(command + ["cat-file", "-e", commit + "^{commit}"],
                             capture_output=True, timeout=30)
    if present.returncode != 0:
        subprocess.run(["git", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", str(repo),
                        "fetch", "--no-auto-maintenance", "--no-tags", "--depth=1", "origin", commit],
                       check=True, capture_output=True, timeout=180)
    resolved = subprocess.run(command + ["rev-parse", "--verify", commit + "^{commit}"],
                              check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    if resolved != commit:
        raise ValueError("Acquired source commit identity mismatch")


def main():
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY:
        raise ValueError("Unexpected coverage repository")
    event_name = os.environ["GITHUB_EVENT_NAME"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    base_sha, head_sha = identities(event_name, event, os.environ["GITHUB_SHA"])
    ensure_source_commit(Path.cwd(), base_sha)
    ensure_source_commit(Path.cwd(), head_sha)
    current_id = int(os.environ["GITHUB_RUN_ID"])
    current = api(f"repos/{REPOSITORY}/actions/runs/{current_id}")
    if (current.get("id") != current_id
            or current.get("run_attempt") != int(os.environ["GITHUB_RUN_ATTEMPT"])):
        raise ValueError("Current coverage run attempt no longer matches this job")
    workflow_id = api(f"repos/{REPOSITORY}/actions/workflows/coverage.yml")["id"]
    validate_run(current, head_sha, event_name, workflow_id)
    runs = api(f"repos/{REPOSITORY}/actions/workflows/coverage.yml/runs"
               f"?head_sha={base_sha}&event=push&status=success&per_page=100")["workflow_runs"]
    if not runs:
        raise ValueError("No successful main coverage run for the exact base commit")
    base = max(runs, key=lambda run: run["id"])
    validate_run(base, base_sha, "push", workflow_id, base=True)
    root = Path("coverage-comparison")
    root.mkdir(exist_ok=False)
    base_pair, base_attempt, base_job = coverage_artifacts(base, base_sha)
    head_pair, head_attempt, head_job = coverage_artifacts(current, head_sha)
    base_artifact, base_report = download(base, base_sha, root / "base", artifact=base_pair["coverage-lcov"])
    head_artifact, head_report = download(current, head_sha, root / "head", artifact=head_pair["coverage-lcov"])
    base_regions_artifact, base_regions = download(base, base_sha, root / "base-regions", "coverage-regions",
                                                  artifact=base_pair["coverage-regions"])
    head_regions_artifact, head_regions = download(current, head_sha, root / "head-regions", "coverage-regions",
                                                  artifact=head_pair["coverage-regions"])
    receipt = {"base_producer_attempt": base_attempt, "head_producer_attempt": head_attempt,
               "base_producer_job": base_job, "head_producer_job": head_job,
               "base_regions_artifact": base_regions_artifact["id"],
               "head_regions_artifact": head_regions_artifact["id"],
               "base_sha": base_sha, "head_sha": head_sha,
               "base_run": base["id"], "head_run": current_id,
               "base_artifact": base_artifact["id"], "head_artifact": head_artifact["id"]}
    (root / "identity.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("check-line-coverage.py")),
                             "--base", str(base_report), "--head", str(head_report),
                             "--base-regions", str(base_regions), "--head-regions", str(head_regions),
                             "--source-repo", str(Path.cwd()), "--base-sha", base_sha, "--head-sha", head_sha],
                            capture_output=True, text=True, timeout=60)
    (root / "comparison.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    result.check_returncode()


if __name__ == "__main__":
    main()

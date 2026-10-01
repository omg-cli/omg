#!/usr/bin/env python3
"""Download and compare coverage evidence for the exact current/base commits."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = "omg-cli/omg"
WORKFLOW = ".github/workflows/coverage.yml"


def api(endpoint):
    result = subprocess.run(["gh", "api", endpoint], check=True,
                            capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


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


def validate_artifact(artifacts, run_id, commit):
    selected = [a for a in artifacts if a.get("name") == "coverage-lcov"]
    if len(selected) != 1:
        raise ValueError("Expected exactly one coverage-lcov artifact")
    artifact = selected[0]
    identity = artifact.get("workflow_run", {})
    if (artifact.get("expired") is not False or identity.get("id") != run_id
            or identity.get("head_sha") != commit):
        raise ValueError("Expired or mismatched coverage artifact identity")
    return artifact


def download(run, commit, destination):
    artifacts = api(f"repos/{REPOSITORY}/actions/runs/{run['id']}/artifacts?per_page=100")
    if artifacts["total_count"] != len(artifacts["artifacts"]):
        raise ValueError("Coverage artifact listing is incomplete")
    artifact = validate_artifact(artifacts["artifacts"], run["id"], commit)
    destination.mkdir(parents=True, exist_ok=False)
    subprocess.run(["gh", "run", "download", str(run["id"]), "--repo", REPOSITORY,
                    "--name", "coverage-lcov", "--dir", str(destination)],
                   check=True, timeout=180)
    report = destination / "lcov.info"
    if (not report.is_file() or report.is_symlink()
            or list(destination.iterdir()) != [report] or report.stat().st_size > 128 * 1024 * 1024):
        raise ValueError("Coverage artifact must contain one bounded lcov.info report")
    return artifact, report


def main():
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY:
        raise ValueError("Unexpected coverage repository")
    event_name = os.environ["GITHUB_EVENT_NAME"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    base_sha, head_sha = identities(event_name, event, os.environ["GITHUB_SHA"])
    current_id = int(os.environ["GITHUB_RUN_ID"])
    current = api(f"repos/{REPOSITORY}/actions/runs/{current_id}")
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
    base_artifact, base_report = download(base, base_sha, root / "base")
    head_artifact, head_report = download(current, head_sha, root / "head")
    receipt = {"base_sha": base_sha, "head_sha": head_sha,
               "base_run": base["id"], "head_run": current_id,
               "base_artifact": base_artifact["id"], "head_artifact": head_artifact["id"]}
    (root / "identity.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("check-line-coverage.py")),
                             "--base", str(base_report), "--head", str(head_report)],
                            capture_output=True, text=True, timeout=60)
    (root / "comparison.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(json.dumps(receipt, sort_keys=True))
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    result.check_returncode()


if __name__ == "__main__":
    main()

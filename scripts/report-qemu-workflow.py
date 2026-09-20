#!/usr/bin/env python3
"""Report QEMU evidence from a trusted workflow_run job without executing it."""
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile

MAX_DOWNLOAD = 16 * 1024 * 1024
FAILURES = {"FAIL", "PRODUCT_FAIL", "HARNESS_ERROR", "BLOCKED"}
DISTROS = ("arch", "debian", "ubuntu", "fedora")


def api(path, limit=1024 * 1024):
    with tempfile.TemporaryFile() as output:
        subprocess.run(["gh", "api", path], stdout=output, check=True, timeout=60)
        if output.tell() > limit:
            raise ValueError("GitHub response exceeds reporting limit")
        output.seek(0)
        return output.read(limit + 1)


def identity(event, live, repository):
    run = event["workflow_run"]
    if (event["repository"]["full_name"] != repository
            or live["repository"]["full_name"] != repository
            or live["id"] != run["id"] or live["run_attempt"] != run["run_attempt"]
            or live["head_sha"] != run["head_sha"]
            or live["workflow_id"] != run["workflow_id"]
            or live["path"] != ".github/workflows/qemu-matrix.yml"
            or live["status"] != "completed"
            or live["event"] not in ("push", "workflow_dispatch", "schedule")
            or not re.fullmatch(r"[0-9a-f]{40}", live["head_sha"])):
        raise ValueError("workflow identity or attempt mismatch")
    return live


def canonical_case_ids(policy):
    inventories = policy.get("inventories") if isinstance(policy, dict) else None
    if not isinstance(inventories, dict) or not inventories:
        raise ValueError("invalid inventory policy")
    identifiers = set()
    for snapshot in inventories.values():
        cases = snapshot.get("cases") if isinstance(snapshot, dict) else None
        if not isinstance(cases, list):
            raise ValueError("invalid inventory policy cases")
        for case in cases:
            case_id = case.get("id") if isinstance(case, dict) else None
            if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,120}", case_id):
                raise ValueError("invalid inventory policy case")
            identifiers.update(f"qemu-{distro}-{case_id}" for distro in DISTROS)
    identifiers.update(f"qemu-{distro}-lifecycle" for distro in DISTROS)
    identifiers.update(f"qemu-{distro}-aarch64-lifecycle" for distro in DISTROS)
    identifiers.add("qemu-matrix-workflow")
    return identifiers


def archive_rows(content, allowed_cases):
    if len(content) > MAX_DOWNLOAD:
        raise ValueError("artifact download exceeds limit")
    rows = []
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        if len(members) > 5000 or sum(member.file_size for member in members) > 256 * 1024 * 1024:
            raise ValueError("artifact expansion exceeds limit")
        seen = set()
        for member in members:
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (path.is_absolute() or ".." in path.parts or "\\" in member.filename
                    or stat.S_ISLNK(mode) or member.filename in seen):
                raise ValueError("unsafe artifact member")
            seen.add(member.filename)
            # Transaction trials use their own `results.json` schema (`id`,
            # `operation`, ...). They are checked by the guest verifier; this
            # reporter only consumes lifecycle and inventory case rows.
            if path.name != "results.json" or path.parent.name == "transactions":
                continue
            if member.file_size > 1024 * 1024:
                raise ValueError("result exceeds limit")
            payload = json.loads(archive.read(member))
            if not isinstance(payload, list) or len(payload) > 1000:
                raise ValueError("invalid result collection")
            for row in payload:
                if (not isinstance(row, dict)
                        or not isinstance(row.get("case_id"), str)
                        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", row["case_id"])
                        or row["case_id"] not in allowed_cases
                        or row.get("distro") not in ("arch", "debian", "ubuntu", "fedora")
                        or row.get("result") not in FAILURES | {"PASS", "SKIPPED"}
                        or type(row.get("exit_code")) is not int
                        or not -1 <= row["exit_code"] <= 255
                        or type(row.get("elapsed_seconds")) not in (int, float)
                        or not 0 <= row["elapsed_seconds"] <= 86400):
                    raise ValueError("invalid result row")
                rows.append({key: row[key] for key in ("case_id", "distro", "result", "exit_code", "elapsed_seconds")})
    return rows


def projection(rows, successful_main):
    selected = {}
    for row in rows:
        key = row["case_id"], row["distro"]
        if row["result"] in FAILURES:
            # The existing issue helper treats BLOCKED as context rather than
            # an issue. A failed prerequisite still needs a tracked diagnosis.
            selected[key] = dict(row, result="HARNESS_ERROR" if row["result"] == "BLOCKED" else row["result"])
        elif successful_main and row["result"] == "PASS" and key not in selected:
            selected[key] = row
    # The matrix job emits an aggregate receipt whenever a lane fails. Once
    # detailed evidence identifies that failure, filing both adds no diagnosis.
    # Keep the aggregate when it is the only failure (and keep PASS closures).
    if any(row["case_id"] != "qemu-matrix-workflow" and row["result"] in FAILURES
           for row in selected.values()):
        selected = {key: row for key, row in selected.items()
                    if row["case_id"] != "qemu-matrix-workflow" or row["result"] not in FAILURES}
    if sum(row["result"] in FAILURES for row in selected.values()) > 25:
        raise ValueError("more than 25 failing cases; report workflow aggregate")
    return list(selected.values())


def main():
    repository = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid repository")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    run_id = event["workflow_run"]["id"]
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("invalid run ID")
    run = identity(event, json.loads(api(f"repos/{repository}/actions/runs/{run_id}")), repository)
    allowed_cases = canonical_case_ids(json.loads(
        Path("tests/qemu-inventory-policy.json").read_text()
    ))
    # Superseding an interactive run is not itself a product failure.
    if run["conclusion"] in ("cancelled", "skipped"):
        print("Cancelled/skipped run retained in Actions; no failure issue generated")
        return 0
    successful_main = False
    if run["conclusion"] == "success" and run["event"] == "push" and run["head_branch"] == "main":
        main_ref = json.loads(api(f"repos/{repository}/git/ref/heads/main"))
        successful_main = main_ref["object"]["sha"] == run["head_sha"]
    rows = []
    evidence_error = False
    try:
        listing = json.loads(api(f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"))
        if listing["total_count"] > 100:
            raise ValueError("too many artifacts")
        for artifact in listing["artifacts"]:
            if not re.fullmatch(r"qemu-(?:arm-)?evidence-(?:arch|debian|ubuntu|fedora)|qemu-workflow-report", artifact["name"]):
                continue
            # Reruns keep their run ID. Reject older-attempt artifacts rather
            # than using stale success to close a current failure.
            if artifact["created_at"] < run["run_started_at"] or artifact["expired"]:
                raise ValueError("stale or expired artifact")
            if type(artifact["id"]) is not int or artifact["size_in_bytes"] > MAX_DOWNLOAD:
                raise ValueError("invalid artifact identity or size")
            rows.extend(archive_rows(
                api(f"repos/{repository}/actions/artifacts/{artifact['id']}/zip", MAX_DOWNLOAD),
                allowed_cases,
            ))
        selected = projection(rows, successful_main)
    except (ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError):
        selected = []
        evidence_error = True
    if evidence_error or (run["conclusion"] != "success" and not any(row["result"] in FAILURES for row in selected)):
        selected.append(dict(case_id="qemu-matrix-workflow", distro="ubuntu", result="HARNESS_ERROR", exit_code=1, elapsed_seconds=0))
    if not selected:
        print("No authoritative case updates to report")
        return 0
    # Recheck after downloads: an operator may have rerun this ID meanwhile.
    identity(event, json.loads(api(f"repos/{repository}/actions/runs/{run_id}")), repository)
    if successful_main:
        current = json.loads(api(f"repos/{repository}/git/ref/heads/main"))
        if current["object"]["sha"] != run["head_sha"]:
            selected = [row for row in selected if row["result"] != "PASS"]
        elif not evidence_error:
            selected.append(dict(case_id="qemu-matrix-workflow", distro="ubuntu", result="PASS", exit_code=0, elapsed_seconds=0))
    jobs = json.loads(api(f"repos/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}/jobs?per_page=100"))
    details = []
    for job in jobs["jobs"][:100]:
        if job["conclusion"] not in ("success", "skipped"):
            name = re.sub(r"[^A-Za-z0-9 ._()/:-]", "?", job["name"])[:120]
            details.append(f"Job {job['id']}: {name} ({job['conclusion']})")
            for step in job.get("steps", [])[:100]:
                if step["conclusion"] not in ("success", "skipped"):
                    name = re.sub(r"[^A-Za-z0-9 ._()/:-]", "?", step["name"])[:120]
                    details.append(f"  Step {step['number']}: {name} ({step['conclusion']})")
    with tempfile.TemporaryDirectory() as directory:
        results = Path(directory) / "results.json"
        results.write_text(json.dumps(selected) + "\n")
        for row in selected:
            if row["result"] in FAILURES:
                evidence = Path(directory) / f"{row['distro']}-{row['case_id']}"
                evidence.mkdir()
                evidence.joinpath("transcript.txt").write_text(
                    f"Commit: {run['head_sha']}\nEvent: {run['event']}\nAttempt: {run['run_attempt']}\n"
                    f"Observed: {row['result']}, exit {row['exit_code']}, elapsed {row['elapsed_seconds']}s\n"
                    f"Evidence invalid/unavailable: {evidence_error}\n"
                    "Exit status alone does not establish the root cause. Inspect the linked run's logs and artifacts.\n"
                    + "\n".join(details[:24]) + "\n")
        run_url = f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{run['run_attempt']}"
        subprocess.run(["bash", "scripts/qa-file-issue.sh", str(results), "--repo", repository,
                        "--source", "qemu-matrix", "--run-url", run_url], check=True, timeout=180)
        if run["event"] == "pull_request" or evidence_error:
            subprocess.run(["bash", "scripts/report-smoke-sentry.sh", str(results)], check=True, timeout=20)
    print(f"Reported run {run_id}, attempt {run['run_attempt']}, commit {run['head_sha']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

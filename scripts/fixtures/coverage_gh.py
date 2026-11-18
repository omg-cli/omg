import hashlib
from datetime import datetime, timedelta
import io
import json
import os
import struct
import sys
import zipfile


PAYLOAD = b"SF:/fixture/src/shared.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"


def timestamp(minutes):
    return (datetime(2026, 11, 10) + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def archive(name, extra=False, symlink=False):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zipped:
        member = zipfile.ZipInfo(name)
        if symlink:
            member.create_system = 3
            member.external_attr = 0o120777 << 16
        zipped.writestr(member, PAYLOAD)
        if extra:
            zipped.writestr(zipfile.ZipInfo("unexpected.txt"), b"unexpected\n")
    return output.getvalue()


def main():
    config = json.loads(os.environ.get("COVERAGE_GH_SCENARIO", "{}"))
    attempt = config.get("attempt", 2)
    producer = config.get("producer_attempt", attempt)
    prefix = "repos/omg-cli/omg/actions/"
    def run_snapshot(number):
        return {"id": 101, "head_sha": "a" * 40, "run_attempt": number,
                "run_started_at": timestamp(number * 10 - 1)}
    run = run_snapshot(attempt)
    artifacts, archives = [], {}
    for generation in ([1, producer] if config.get("old_artifacts") else [producer]):
        for offset, kind, leaf in [(0, "coverage-lcov", "lcov.info"),
                                   (1, "coverage-regions", "coverage-regions.json.gz")]:
            selected = generation - 1 if config.get("mixed_regions") and offset else generation
            artifact_id = generation * 10 + offset + 102
            content = archive(leaf, config.get("extra", False), config.get("symlink", False))
            if config.get("invalid_archive"):
                content = b"not a zip"
            if config.get("oversize_member"):
                content = bytearray(content)
                struct.pack_into("<I", content, content.index(b"PK\x01\x02") + 24, 128 * 1024 * 1024 + 1)
                content = bytes(content)
            archives[artifact_id] = content
            artifacts.append({
                "id": artifact_id,
                "name": kind if config.get("legacy", False) else f"{kind}-101-{selected}",
                "expired": False,
                "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                "size_in_bytes": len(content),
                "created_at": timestamp(selected * 10 + 2),
                "workflow_run": {"id": 101, "head_sha": "a" * 40},
            })
    if config.get("duplicate"):
        artifacts.append(dict(artifacts[-1], id=999))
    if config.get("bad_digest"):
        artifacts[0]["digest"] = "sha256:" + "0" * 64
    if config.get("missing_digest"):
        artifacts[0].pop("digest")
    if config.get("wrong_source"):
        artifacts[0]["workflow_run"]["head_sha"] = "b" * 40
    if config.get("wrong_name"):
        artifacts[0]["name"] = "coverage-lcov-999-2"
    if config.get("outside"):
        artifacts[0]["created_at"] = "2026-11-10T00:00:00Z"
    if config.get("mixed_names"):
        artifacts[0]["name"] = "coverage-lcov"
    if config.get("bad_size"):
        artifacts[0]["size_in_bytes"] += 1
    if config.get("boolean_size"):
        artifacts[0]["size_in_bytes"] = True
    if config.get("string_size"):
        artifacts[0]["size_in_bytes"] = str(artifacts[0]["size_in_bytes"])
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "api":
        endpoint = args[1].split("&page=", 1)[0]
        page = int(args[1].split("&page=", 1)[1]) if "&page=" in args[1] else 1
        if endpoint == prefix + "runs/101/artifacts?per_page=100":
            response = {"total_count": len(artifacts) + int(config.get("incomplete", False)),
                        "artifacts": artifacts}
        elif endpoint == prefix + "runs/101":
            response = dict(run, run_attempt=attempt + int(config.get("attempt_changed", False)))
        elif endpoint.startswith(prefix + "runs/101/attempts/") and not endpoint.endswith("/jobs?per_page=100"):
            response = run_snapshot(int(endpoint.rsplit("/", 1)[1]))
        elif endpoint.startswith(prefix + "runs/101/attempts/") and endpoint.endswith("/jobs?per_page=100"):
            requested = int(endpoint.split("/attempts/")[1].split("/")[0])
            actual = min(producer, requested)
            owner = {"id": 500 + requested, "name": "Instrumented coverage tests",
                     "run_id": 101, "head_sha": "a" * 40, "run_attempt": requested,
                     "status": config.get("status", "completed"), "conclusion": config.get("conclusion", "success"),
                     "started_at": timestamp(actual * 10),
                     "completed_at": timestamp(actual * 10 + 5)}
            if config.get("wrong_owner"):
                owner["name"] = "Unrelated tests"
            if config.get("wrong_job_source"):
                owner["head_sha"] = "b" * 40
            if config.get("wrong_job_run"):
                owner["run_id"] = 999
            if config.get("changed_carried_owner") and requested < attempt:
                owner["started_at"] = timestamp(actual * 10 - 1)
            jobs = [] if config.get("missing_previous") and requested < attempt else [owner]
            response = {"total_count": len(jobs) + int(config.get("incomplete_jobs", False)), "jobs": jobs}
        elif endpoint.startswith(prefix + "artifacts/") and endpoint.endswith("/zip"):
            artifact_id = int(endpoint.split("/artifacts/")[1].split("/")[0])
            sys.stdout.buffer.write(archives[artifact_id])
            return
        else:
            raise SystemExit("Undeclared endpoint: " + endpoint)
        if "artifacts" in response and (config.get("paginate") or config.get("changing_total")
                                        or config.get("duplicate_page")):
            response["artifacts"] = artifacts[:1] if page == 1 or config.get("duplicate_page") else artifacts[1:]
            if config.get("changing_total") and page > 1:
                response["total_count"] += 1
        elif page > 1:
            response["artifacts" if "artifacts" in response else "jobs"] = []
        print(json.dumps(response))
        return
    raise SystemExit("Undeclared gh argv: " + repr(args))


if __name__ == "__main__":
    main()

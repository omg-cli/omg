"""Admit the settled OMG container target before starting expensive cloud CI."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import tomllib
import urllib.error
import urllib.request

ACCOUNT = "f1e95b3e1b502cf366dfc81a863695fa"
APPLICATION = "a03f931a-ff51-44cb-b808-de83537d368f"
REGISTRY = f"registry.cloudflare.com/{ACCOUNT}/omg-cloud-ci@"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def admit(application, rollouts, expected_digest):
    require(isinstance(expected_digest, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest),
            "Invalid expected image digest")
    require(isinstance(application, dict) and application.get("id") == APPLICATION,
            "Wrong OMG application")
    version = application.get("version")
    require(type(version) is int and version > 0, "Missing application version")
    image = REGISTRY + expected_digest
    require(application.get("configuration", {}).get("image") == image,
            "Application image differs from expected deployment")
    require(application.get("health", {}).get("errors") == [], "Application reports health errors")
    require(isinstance(rollouts, list) and all(isinstance(row, dict) for row in rollouts),
            "Missing rollout inventory")
    selected = [row for row in rollouts if row.get("target_version") == version]
    require(len(selected) == 1, "Missing or ambiguous target rollout")
    rollout = selected[0]
    for row in rollouts:
        target = row.get("target_version")
        require(type(target) is int and 0 < target <= version, "Superseding or invalid rollout")
        require(row.get("status") in {"completed", "replaced", "cancelled"}, "Rollout is not settled")
    require(rollout.get("status") == "completed", "Target rollout has not completed")
    require(rollout.get("target_configuration", {}).get("image") == image,
            "Rollout image differs from expected deployment")
    steps = rollout.get("steps")
    require(isinstance(steps, list) and steps and all(
        isinstance(step, dict) and step.get("status") == "completed"
        and isinstance(step.get("completed_at"), str) and step["completed_at"] for step in steps),
        "Rollout steps are incomplete")
    progress = rollout.get("progress", {})
    distribution = progress.get("version_distribution", {})
    require(distribution.get("target_version_percentage") == 100
            and distribution.get("current_version_instances") == 0,
            "Container fleet still contains the prior version")
    updated, total = progress.get("updated_instances"), progress.get("total_instances")
    require(type(updated) is int and type(total) is int and total > 0 and updated >= total,
            "Container replacement is incomplete")
    require(distribution.get("target_version_instances") == total, "Target instance count differs")
    require(isinstance(rollout.get("id"), str) and rollout["id"], "Missing rollout identity")
    return {"state": "ADMITTED", "applicationId": APPLICATION, "version": version,
            "image": image, "rolloutId": rollout["id"],
            "completedAt": max(step["completed_at"] for step in steps)}


def readiness(fetch, expected_digest):
    app_path = f"/applications/{APPLICATION}"
    rollout_path = app_path + "/rollouts?limit=10"
    before = admit(fetch(app_path), fetch(rollout_path), expected_digest)
    after = admit(fetch(app_path), fetch(rollout_path), expected_digest)
    require(before == after, "Deployment changed during readiness readback")
    return after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--wrangler-auth-file", type=Path)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=300)
    args = parser.parse_args()
    require(0 <= args.wait_seconds <= 600, "Wait must be bounded between zero and 600 seconds")
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token and args.wrangler_auth_file:
        token = tomllib.loads(args.wrangler_auth_file.read_text(encoding="utf-8"))["oauth_token"]
    require(isinstance(token, str) and re.fullmatch(r"[^\s]{32,512}", token),
            "Supply existing Cloudflare authentication")
    reads = []

    def fetch(path):
        request = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/containers{path}",
            headers={"Authorization": "Bearer " + token, "User-Agent": "omg-ci-courier/1.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(1_048_577)
        require(len(body) <= 1_048_576, "Cloudflare response exceeds evidence budget")
        value = json.loads(body)
        require(isinstance(value, dict) and value.get("success") is True, "Cloudflare API rejected readback")
        reads.append({"path": path, "sha256": hashlib.sha256(body).hexdigest()})
        return value.get("result")

    deadline = time.monotonic() + args.wait_seconds
    result = {"state": "HOLD"}
    attempts = 0
    while True:
        attempts += 1
        try:
            result = readiness(fetch, args.image_digest)
            break
        except (ValueError, urllib.error.URLError) as error:
            result["reason"] = f"Cloudflare HTTP {error.code}" if isinstance(error, urllib.error.HTTPError) else str(error)
            if isinstance(error, urllib.error.HTTPError) and error.code not in {429, 500, 502, 503, 504}:
                break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(5, remaining))
    now = datetime.now(timezone.utc)
    result.update(observedUtc=now.isoformat(), attempts=attempts, authenticatedReads=reads)
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    receipt = args.evidence_dir / ("rollout-admission-" + now.strftime("%Y%m%dT%H%M%S.%fZ") + ".json")
    receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**result, "receipt": str(receipt)}))
    return 0 if result["state"] == "ADMITTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

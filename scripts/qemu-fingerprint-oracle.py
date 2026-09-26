#!/usr/bin/env python3
"""Guest-side, native-package-backed artifact oracle for fingerprint commands."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def regular(path):
    require(path.is_file() and not path.is_symlink(), f"missing regular artifact: {path}")
    return path


def native_packages(distro):
    if distro == "arch":
        command = ["pacman", "-Qqe"]
    elif distro in ("debian", "ubuntu"):
        command = ["apt-mark", "showmanual"]
    elif distro == "fedora":
        command = ["dnf", "--cacheonly", "--disable-repo=*",
                   "--setopt=disable_excludes=*", "repoquery", "--userinstalled",
                   "--qf", "%{name}\n"]
    else:
        raise AssertionError(f"unknown distro: {distro}")
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    names = set(result.stdout.splitlines())
    require(bool(names) and all(name and name == name.strip() for name in names),
            "native explicit package query was empty or malformed")
    return names


def package_state(state, expected):
    require(state.get("schema_version") == 1, "wrong fingerprint schema")
    packages = state.get("packages")
    require(isinstance(packages, list) and packages == sorted(expected),
            "fingerprint packages differ from native explicit inventory")
    runtimes = state.get("runtimes")
    require(isinstance(runtimes, dict), "missing runtime map")
    digest = hashlib.sha256()
    for name, version in sorted(runtimes.items()):
        require(isinstance(name, str) and isinstance(version, str), "invalid runtime entry")
        digest.update(f"{name.strip()}:{version.strip()};".encode())
    for name in packages:
        digest.update(f"{name};".encode())
    require(state.get("hash") == digest.hexdigest(), "fingerprint hash does not bind its state")
    return state["hash"]


def lock(root, expected):
    state = tomllib.loads(regular(root / "omg.lock").read_text())
    return package_state(state, expected)


def output_contains(output, *markers):
    for marker in markers:
        require(marker in output, f"command output lacks {marker!r}")


def main():
    case, distro, root_arg, output_arg = sys.argv[1:]
    root = Path(root_arg)
    output = regular(Path(output_arg)).read_text()
    expected = native_packages(distro)
    if case == "snapshot-create":
        directory = Path(os.environ["OMG_DATA_DIR"]) / "snapshots"
        index = json.loads(regular(directory / "index.json").read_text())
        snapshots = index.get("snapshots")
        require(isinstance(snapshots, list) and len(snapshots) == 1,
                "snapshot index must contain exactly the new snapshot")
        meta = snapshots[0]
        identifier = meta["id"]
        snapshot = json.loads(regular(directory / f"{identifier}.json").read_text())
        require(snapshot["id"] == identifier and snapshot["message"] == meta["message"] == "smoke",
                "snapshot identity/message mismatch")
        digest = package_state(snapshot["state"], expected)
        require(meta["hash"] == digest, "snapshot index hash differs from artifact")
        output_contains(output, "Snapshot created!", identifier, f"Packages: {len(expected)}")
    elif case == "migrate-export":
        manifest = json.loads(regular(root / "manifest.json").read_text())
        packages = manifest.get("packages")
        require(manifest.get("version") == "1.0" and manifest.get("source_distro") == distro,
                "migration source/version mismatch")
        require(isinstance(packages, list) and
                {item["original_name"] for item in packages} == expected and
                len(packages) == len(expected), "migration omitted native explicit packages")
        output_contains(output, "Exported to", f"Packages: {len(expected)}")
    elif case == "migrate-import":
        manifest = json.loads(regular(root / "manifest.json").read_text())
        require({item["original_name"] for item in manifest["packages"]} == expected,
                "import prerequisite manifest lacks native explicit packages")
        output_contains(output, "Previewing", f"{len(expected)} packages",
                        f"Mutation summary: {len(expected)} package installation(s)",
                        "No changes made (dry run)")
    elif case == "env-capture":
        digest = lock(root, expected)
        output_contains(output, "Environment state captured", digest[:16],
                        f"Packages: {len(expected)}")
    elif case == "env-check":
        lock(root, expected)
        output_contains(output, "Environment is in sync", "No drift detected")
    elif case in ("team-status", "team-push", "team-pull"):
        digest = lock(root, expected)
        config = tomllib.loads(regular(root / ".omg/team.toml").read_text())
        status = json.loads(regular(root / ".omg/team-status.json").read_text())
        require(config["team_id"] == "smoke/team" and status["config"]["team_id"] == "smoke/team",
                "team state belongs to the wrong workspace")
        members = status.get("members")
        require(status["lock_hash"] == digest and isinstance(members, list) and
                any(member.get("env_hash") == digest and member.get("in_sync") for member in members),
                "team state does not match native-backed lock")
        marker = {"team-status": "members in sync", "team-push": "Team lock updated!",
                  "team-pull": "Environment is in sync"}[case]
        output_contains(output, marker)
    else:
        raise AssertionError(f"unhandled fingerprint case: {case}")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"assertion failed: fingerprint oracle: {error}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Check the official Rust ALPM family's manifest/lock agreement offline."""

from pathlib import Path
import re
import tomllib

FAMILY = {"alpm-types", "alpm-srcinfo", "alpm-db", "alpm-repo-db", "alpm-mtree"}
UPSTREAM = "https://gitlab.archlinux.org/archlinux/alpm/alpm.git"


def validate(manifest, lock):
    dependencies = manifest["dependencies"]
    pins = {name: dependencies[name] for name in FAMILY}
    revisions = {pin["rev"] for pin in pins.values()}
    if len(revisions) != 1 or not re.fullmatch(r"[0-9a-f]{40}", next(iter(revisions))):
        raise ValueError("All direct Rust ALPM dependencies must share a full immutable commit")
    revision = next(iter(revisions))
    expected_source = f"git+{UPSTREAM}?rev={revision}#{revision}"
    for name, pin in pins.items():
        if pin["git"] != UPSTREAM or not pin["version"].startswith("="):
            raise ValueError(f"{name} needs the official repository and an exact version")
        matches = [package for package in lock["package"] if package["name"] == name]
        if len(matches) != 1 or matches[0]["version"] != pin["version"][1:]:
            raise ValueError(f"{name} has a duplicate or mismatched locked version")
        if matches[0].get("source") != expected_source:
            raise ValueError(f"{name} lockfile source differs from its manifest commit")
    for package in lock["package"]:
        source = package.get("source", "")
        if source.startswith(f"git+{UPSTREAM}") and source != expected_source:
            raise ValueError(f"Mixed Rust ALPM monorepo snapshots: {package['name']}")
    return revision, {name: pins[name]["version"][1:] for name in sorted(pins)}


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    with (root / "Cargo.toml").open("rb") as stream:
        manifest = tomllib.load(stream)
    with (root / "Cargo.lock").open("rb") as stream:
        lock = tomllib.load(stream)
    revision, versions = validate(manifest, lock)
    print(f"Rust ALPM snapshot: {revision}")
    for name, version in versions.items():
        print(f"{name} {version}")

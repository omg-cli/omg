#!/usr/bin/env python3
"""Check the Rust ALPM pin and prepare its exact Cargo source for CI."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

FAMILY = {"alpm-types", "alpm-srcinfo", "alpm-db", "alpm-repo-db", "alpm-mtree"}
UPSTREAM = "https://gitlab.archlinux.org/archlinux/alpm/alpm.git"
MIRROR = "https://github.com/archlinux/alpm.git"


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


def prepare_cargo_source(destination, revision, locked_versions, *, source=MIRROR):
    destination = destination.resolve()
    destination.mkdir(mode=0o700)
    snapshot = destination / "source"
    snapshot.mkdir()
    with tempfile.TemporaryDirectory(prefix="fetch-", dir=destination) as temporary:
        repo = Path(temporary) / "repo"
        subprocess.run(["git", "init", "--quiet", "--bare", str(repo)], check=True, timeout=15)
        git = ["git", "-C", str(repo), "--work-tree", str(snapshot), "-c", "core.autocrlf=false"]
        subprocess.run([*git, "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules",
                        source, revision], check=True, timeout=120)
        fetched = subprocess.check_output([*git, "rev-parse", "FETCH_HEAD"], text=True, timeout=15)
        if fetched.strip() != revision:
            raise ValueError("ALPM mirror returned a different commit")
        # Git materializes the pinned files without populating the website theme gitlink.
        subprocess.run([*git, "read-tree", revision], check=True, timeout=15)
        subprocess.run([*git, "checkout-index", "--all"], check=True, timeout=30)

    prepared = {}
    for manifest in sorted(snapshot.glob("*/Cargo.toml")):
        package = tomllib.loads(manifest.read_text(encoding="utf-8")).get("package", {})
        name = package.get("name")
        if name is None:
            continue
        if name in locked_versions:
            if name in prepared or package["version"] != locked_versions[name]:
                raise ValueError(f"ALPM snapshot has a duplicate or mismatched package: {name}")
            prepared[name] = package["version"]
        crate = manifest.parent
        checksums = {file.relative_to(crate).as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
                     for file in crate.rglob("*") if file.is_file()}
        (crate / ".cargo-checksum.json").write_text(
            json.dumps({"package": None, "files": checksums}, sort_keys=True), encoding="utf-8",
        )
    if prepared != locked_versions:
        raise ValueError(f"ALPM snapshot is missing locked packages: {sorted(locked_versions.keys() - prepared.keys())}")

    (destination / "cargo-config.toml").write_text(
        f"[source.alpm-pin]\ngit = {json.dumps(UPSTREAM)}\nrev = {json.dumps(revision)}\n"
        'replace-with = "alpm-verified"\n[source.alpm-verified]\n'
        f"directory = {json.dumps(str(snapshot), ensure_ascii=False)}\n", encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-cargo-source", type=Path, metavar="DIRECTORY")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    with (root / "Cargo.toml").open("rb") as stream:
        manifest = tomllib.load(stream)
    with (root / "Cargo.lock").open("rb") as stream:
        lock = tomllib.load(stream)
    revision, versions = validate(manifest, lock)
    print(f"Rust ALPM snapshot: {revision}")
    for name, version in versions.items():
        print(f"{name} {version}")
    if args.prepare_cargo_source:
        expected_source = f"git+{UPSTREAM}?rev={revision}#{revision}"
        locked = {package["name"]: package["version"] for package in lock["package"]
                  if package.get("source") == expected_source}
        prepare_cargo_source(args.prepare_cargo_source, revision, locked)

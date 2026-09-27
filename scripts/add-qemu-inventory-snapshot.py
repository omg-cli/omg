#!/usr/bin/env python3
"""Add one reviewed inventory snapshot without rewriting historical policy files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from qemu_inventory_policy import (LIMIT, all_snapshots, read_bounded, read_json,
                                   snapshot_directory, validate_snapshot,
                                   verify_inventory_cases)


def add(policy, inventory, candidate):
    index, _ = all_snapshots(policy)
    inventory_bytes = read_bounded(inventory)
    digest = hashlib.sha256(inventory_bytes).hexdigest()
    if digest in index["inventories"]:
        raise ValueError("inventory digest already reviewed")
    snapshot = validate_snapshot(read_json(candidate))
    verify_inventory_cases(snapshot, inventory_bytes)
    content = (json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(content) > LIMIT:
        raise ValueError("inventory snapshot exceeds limit")
    destination = snapshot_directory(policy) / (digest + ".json")
    with destination.open("xb") as output:
        output.write(content)
    index["inventories"][digest] = hashlib.sha256(content).hexdigest()
    index_bytes = (json.dumps(index, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(index_bytes) > LIMIT:
        destination.unlink()
        raise ValueError("inventory index exceeds limit")
    try:
        with tempfile.NamedTemporaryFile(dir=Path(policy).parent, delete=False) as output:
            temporary = Path(output.name)
            output.write(index_bytes)
        try:
            os.chmod(temporary, Path(policy).stat().st_mode & 0o777)
            os.replace(temporary, policy)
        finally:
            temporary.unlink(missing_ok=True)
    except OSError:
        destination.unlink()
        raise
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--snapshot", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(add(args.policy, args.inventory, args.snapshot))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"inventory snapshot not added: {error}\n")


if __name__ == "__main__":
    main()

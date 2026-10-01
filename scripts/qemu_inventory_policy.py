"""Load reviewed QEMU inventory snapshots with bounded, exact file identities."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIMIT = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CASE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,120}\Z")
TIERS = {"hermetic", "container", "qemu", "network", "credentialed", "pty", "nested-container"}
DISTROS = {"arch", "debian", "ubuntu", "fedora"}
HEADER = "case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory policy key")
        result[key] = value
    return result


def read_descriptor(descriptor):
    with os.fdopen(descriptor, "rb") as stream:
        details = os.fstat(stream.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_size > LIMIT:
            raise ValueError("invalid inventory evidence file")
        content = stream.read(LIMIT + 1)
    if len(content) > LIMIT:
        raise ValueError("inventory evidence exceeded limit")
    return content


def read_bounded(path):
    path = Path(path)
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("symlinked inventory evidence file")
    # A FIFO can block in open before fstat gets a chance to reject it.
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    return read_descriptor(os.open(path, flags))


def read_json(path):
    return json.loads(read_bounded(path), object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def reject_constant(value):
    raise ValueError("invalid inventory policy constant")


def snapshot_directory(policy):
    policy = Path(policy)
    directory = policy.with_name(policy.stem + ".d")
    if directory.is_symlink() or (hasattr(directory, "is_junction") and directory.is_junction()) or not directory.is_dir():
        raise ValueError("invalid inventory snapshot directory")
    return directory


def read_snapshot_file(directory, digest):
    filename = digest + ".json"
    path = directory / filename
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("symlinked inventory snapshot")
    if os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
        # Relative open against a no-follow directory descriptor prevents a
        # swapped directory or final component from redirecting the read.
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory_fd)
            return read_descriptor(descriptor)
        finally:
            os.close(directory_fd)
    return read_bounded(path)


def load_index(policy):
    index = read_json(policy)
    if (not isinstance(index, dict) or index.get("schema_version") != 2
            or not isinstance(index.get("profiles"), dict)
            or not isinstance(index.get("inventories"), dict)
            or not index["profiles"] or not index["inventories"]):
        raise ValueError("invalid inventory policy index")
    for digest, file_hash in index["inventories"].items():
        if (not SHA256.fullmatch(digest) or not isinstance(file_hash, str)
                or not SHA256.fullmatch(file_hash)):
            raise ValueError("invalid inventory snapshot identity")
    for profile in index["profiles"].values():
        if (not isinstance(profile, list) or not profile
                or not all(isinstance(tier, str) for tier in profile)
                or len(profile) != len(set(profile))
                or not set(profile) <= TIERS):
            raise ValueError("invalid inventory profile")
    return index


def validate_snapshot(snapshot):
    if (not isinstance(snapshot, dict) or not isinstance(snapshot.get("cases"), list)
            or not snapshot["cases"] or not isinstance(snapshot.get("releases"), list)
            or not all(isinstance(release, str) for release in snapshot["releases"])):
        raise ValueError("invalid inventory snapshot")
    seen = set()
    for case in snapshot["cases"]:
        if (not isinstance(case, dict) or not isinstance(case.get("id"), str)
                or not CASE_ID.fullmatch(case["id"]) or case["id"] in seen
                or not isinstance(case.get("tiers"), list)
                or not case["tiers"]
                or not all(isinstance(tier, str) for tier in case["tiers"])
                or len(case["tiers"]) != len(set(case["tiers"]))
                or not set(case["tiers"]) <= TIERS
                or not isinstance(case.get("allowed_skips"), dict)
                or any(distro not in DISTROS or not isinstance(reason, str) or not reason
                       for distro, reason in case["allowed_skips"].items())
                or case.get("network_scope") not in ("offline", "network")):
            raise ValueError("invalid inventory snapshot case")
        seen.add(case["id"])
    return snapshot


def load_snapshot(policy, index, digest):
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ValueError("invalid inventory digest")
    expected_hash = index["inventories"][digest]
    content = read_snapshot_file(snapshot_directory(policy), digest)
    if hashlib.sha256(content).hexdigest() != expected_hash:
        raise ValueError("inventory snapshot hash mismatch")
    return validate_snapshot(json.loads(content, object_pairs_hook=unique_object,
                                        parse_constant=reject_constant))


def verify_inventory_cases(snapshot, content):
    lines = content.decode("utf-8").split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != HEADER:
        raise ValueError("invalid inventory header")
    reviewed = {case["id"]: set(case["tiers"]) for case in snapshot["cases"]}
    seen = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 10 or any(not field for field in fields):
            raise ValueError("invalid inventory row")
        case_id = fields[0]
        tiers = fields[6].split(",")
        if (not CASE_ID.fullmatch(case_id) or case_id in seen
                or len(tiers) != len(set(tiers)) or not set(tiers) <= TIERS
                or reviewed.get(case_id) != set(tiers)):
            raise ValueError("inventory cases or tiers differ from reviewed snapshot")
        seen.add(case_id)
    if seen != set(reviewed):
        raise ValueError("inventory cases or tiers differ from reviewed snapshot")


def selected_snapshot(policy, inventory):
    inventory_bytes = read_bounded(inventory)
    digest = hashlib.sha256(inventory_bytes).hexdigest()
    index = load_index(policy)
    snapshot = load_snapshot(policy, index, digest)
    verify_inventory_cases(snapshot, inventory_bytes)
    return index, digest, snapshot, inventory_bytes


def all_snapshots(policy):
    index = load_index(policy)
    return index, {digest: load_snapshot(policy, index, digest)
                   for digest in index["inventories"]}


def network_scopes(policy, inventory):
    _, digest, snapshot, _ = selected_snapshot(policy, inventory)
    return {"inventory_sha256": digest,
            "scopes": {case["id"]: case["network_scope"] for case in snapshot["cases"]}}

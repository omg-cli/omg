#!/usr/bin/env python3
"""Replay positive OSV evidence bound to the admitted native archive and helper."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("osv_oracle", Path(__file__).with_name("qemu-osv-positive-oracle.py"))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
HASH = re.compile(r"[0-9a-f]{64}\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate evidence key")
        result[key] = value
    return result


def read_text(directory, name):
    path = directory / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence must be a bounded regular file")
    data = path.read_bytes()
    if len(data) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence exceeds limit")
    return data.decode("utf-8")


def digest_file(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("identity requires a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def archive_binary_hashes(archive, distro):
    hashes = {}
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[-1] not in ("omg", "omgd"):
                continue
            if (len(parts) != 2 or not re.fullmatch(r"omg-v[0-9]+\.[0-9]+\.[0-9]+-(?:x86_64|aarch64)-linux-" + distro, parts[0])
                    or not member.isfile() or member.size > 128 * 1024 * 1024 or parts[-1] in hashes):
                raise ValueError("invalid native release pair")
            digest = hashlib.sha256()
            stream = source.extractfile(member)
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
            hashes[parts[-1]] = digest.hexdigest()
    if set(hashes) != {"omg", "omgd"}:
        raise ValueError("missing native release pair")
    return hashes


def validate_evidence(directory, archive, fixture, distro):
    try:
        receipt = json.loads(read_text(directory, "receipt.json"), object_pairs_hook=unique_object)
        if (receipt.get("schema_version") != 1 or receipt.get("accepted") is not True
                or receipt.get("isolated_vm_mount_and_network") is not True
                or type(receipt.get("ordinary_user_uid")) is not int or receipt["ordinary_user_uid"] <= 0
                or receipt.get("fixture_id") != oracle.FIXTURE_ID or receipt.get("expected_score") != 9.8
                or receipt.get("native_archive_sha256") != digest_file(archive)
                or receipt.get("fixture_sha256") != digest_file(fixture)
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", receipt.get("boot_id", ""))):
            raise ValueError("incomplete or mismatched OSV evidence identity")
        system_files = receipt.get("original_system_files")
        if (not isinstance(system_files, dict)
                or set(system_files) != {"/etc/hosts", "/etc/ssl/certs/ca-certificates.crt"}
                or any(not isinstance(value, str) or not HASH.fullmatch(value) for value in system_files.values())):
            raise ValueError("missing parent guest trust identity")
        for phase in ("before", "after"):
            lines = read_text(directory, "parent-system-" + phase + ".sha256").splitlines()
            actual = {}
            for line in lines:
                match = re.fullmatch(r"([0-9a-f]{64})  (/etc/hosts|/etc/ssl/certs/ca-certificates\.crt)", line)
                if match is None or match[2] in actual:
                    raise ValueError("invalid parent guest trust receipt")
                actual[match[2]] = match[1]
            if actual != system_files:
                raise ValueError("parent guest hosts or trust changed")
        hashes = archive_binary_hashes(archive, distro)
        if any(receipt.get(name + "_sha256") != digest for name, digest in hashes.items()):
            raise ValueError("guest binaries differ from native release archive")
        before, after = receipt.get("native_state_before"), receipt.get("native_state_after")
        if (receipt.get("native_state_unchanged") is not True or not isinstance(before, dict)
                or before != after or "/var/lib/dpkg/status" not in before
                or not set(before) <= {"/var/lib/dpkg/status", "/var/lib/apt/extended_states"}
                or any(not isinstance(value, str) or not HASH.fullmatch(value) for value in before.values())):
            raise ValueError("native package or reason state changed or missing")
        rows = [line.split("\t") for line in read_text(directory, "native-query.tsv").splitlines()]
        if not rows or any(len(row) != 4 for row in rows):
            raise ValueError("invalid native source query")
        installed = [row for row in rows if row[3] == "installed"]
        if not installed or any(not all(row[:3]) for row in installed):
            raise ValueError("missing installed native identities")
        identities = {(row[1], row[2]) for row in installed}
        targets = sorted(row[0] for row in installed if row[1] == "glibc")
        if len(targets) < 2 or receipt.get("affected_binaries") != targets or type(receipt.get("source_identities")) is not int or receipt["source_identities"] != len(identities):
            raise ValueError("native source/binary mapping incomplete")
        release = dict(line.split("=", 1) for line in read_text(directory, "os-release").splitlines() if "=" in line)
        release = {key: value.strip('"') for key, value in release.items()}
        if release.get("ID") != distro or not release.get("VERSION_ID"):
            raise ValueError("native distro mismatch")
        ecosystem = ("Debian:" if distro == "debian" else "Ubuntu:") + release["VERSION_ID"]
        if distro == "ubuntu" and "LTS" in release.get("VERSION", ""):
            ecosystem += ":LTS"
        if receipt.get("ecosystem") != ecosystem:
            raise ValueError("native OSV ecosystem mismatch")
        phases = receipt.get("product_results")
        expected_phases = {"untrusted-tls", "direct-plain", "direct-findings", "daemon-plain", "daemon-findings", "daemon-before", "daemon-after"}
        if not isinstance(phases, dict) or set(phases) != expected_phases:
            raise ValueError("missing actual product outcomes")
        for phase in expected_phases:
            expected = 1 if phase == "untrusted-tls" or phase.endswith("findings") else 0
            argv = ["metrics"] if phase in {"daemon-before", "daemon-after"} else ["audit", "scan"] + (["--fail-on-findings"] if phase.endswith("findings") else [])
            if phases[phase] != {"argv": argv, "exit_code": expected}:
                raise ValueError("product command or actual exit status mismatch")
            result = SimpleNamespace(stdout=read_text(directory, phase + ".stdout"), stderr=read_text(directory, phase + ".stderr"), returncode=phases[phase]["exit_code"])
            if phase.startswith(("direct-", "daemon-p", "daemon-f")):
                oracle.verify_result(result, targets, phase.endswith("findings"))
        untrusted_stdout = read_text(directory, "untrusted-tls.stdout")
        untrusted_stderr = read_text(directory, "untrusted-tls.stderr")
        if "Failed to scan package" not in untrusted_stderr or "No vulnerabilities found" in untrusted_stdout or "Vulnerability scan found" in untrusted_stderr:
            raise ValueError("untrusted TLS did not fail closed")
        events = json.loads(read_text(directory, "fixture-events.json"), object_pairs_hook=unique_object)
        if not isinstance(events, list) or not events or events[0].get("kind") != "tls-error":
            raise ValueError("missing TLS refusal evidence")
        first_request = next(index for index, event in enumerate(events) if event.get("kind") == "request")
        if any(event.get("kind") != "tls-error" for event in events[:first_request]) or any(event.get("kind") != "request" for event in events[first_request:]):
            raise ValueError("unexpected TLS/request phase evidence")
        requests = events[first_request:]
        count = len(identities)
        if len(requests) != 3 * count:
            raise ValueError("incomplete or repeated native source queries")
        for index, field in enumerate(("direct-plain_requests", "direct-findings_requests", "daemon_fixture_requests")):
            if type(receipt.get(field)) is not int or receipt[field] != count:
                raise ValueError("native query counter mismatch")
            oracle.verify_requests(requests[index * count:(index + 1) * count], identities, ecosystem)
        counters = []
        for phase in ("daemon-before", "daemon-after"):
            values = re.findall(r"^omg_security_audit_requests_total (\d+)$", read_text(directory, phase + ".stdout"), re.M)
            if len(values) != 1 or read_text(directory, phase + ".stderr").strip():
                raise ValueError("missing daemon audit counter")
            counters.append(int(values[0]))
        if counters[1] - counters[0] != 2 or receipt.get("daemon_requests_delta") != 2:
            raise ValueError("audit queries did not use the daemon twice")
        return receipt
    except (AssertionError, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, StopIteration, tarfile.TarError) as error:
        raise ValueError("positive OSV evidence rejected: " + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--distro", required=True, choices=("debian", "ubuntu"))
    args = parser.parse_args()
    try:
        validate_evidence(args.evidence_dir, args.archive, Path(__file__).with_name("qemu-osv-positive-oracle.py"), args.distro)
    except ValueError as error:
        parser.exit(1, str(error) + "\n")
    print("Complete archive-bound positive OSV evidence accepted")


if __name__ == "__main__":
    main()

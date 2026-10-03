#!/usr/bin/env python3
"""Replay native Arch advisory outcomes and transport against the admitted archive."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


oracle = module("arch_oracle", "qemu-arch-advisory-oracle.py")
bound = module("advisory_bounds", "qemu-osv-evidence.py")


def validate_evidence(directory, archive, fixture):
    def text(name):
        return bound.read_text(directory, name)

    def data(name):
        return json.loads(text(name), object_pairs_hook=bound.unique_object)

    try:
        receipt = data("receipt.json")
        if (receipt.get("schema_version") != 1 or receipt.get("accepted") is not True
                or receipt.get("isolated_vm_mount_and_network") is not True
                or type(receipt.get("ordinary_user_uid")) is not int or receipt["ordinary_user_uid"] <= 0
                or receipt.get("fixture_id") != "AVG-OMG-QEMU-616" or receipt.get("expected_native_severity") != "Critical"
                or receipt.get("native_archive_sha256") != bound.digest_file(archive)
                or receipt.get("fixture_sha256") != bound.digest_file(fixture)
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", receipt.get("boot_id", ""))):
            raise ValueError("incomplete native Arch evidence identity")
        hashes = bound.archive_binary_hashes(archive, "arch")
        if any(receipt.get(name + "_sha256") != digest for name, digest in hashes.items()):
            raise ValueError("native Arch binary pair mismatch")
        system = receipt.get("original_system_files")
        expected_paths = {"/etc/hosts", "/etc/ssl/certs/ca-certificates.crt", "/etc/nsswitch.conf"}
        if (not isinstance(system, dict) or set(system) != expected_paths
                or any(not isinstance(value, str) or not bound.HASH.fullmatch(value) for value in system.values())):
            raise ValueError("missing parent namespace trust/NSS identity")
        for phase in ("before", "after"):
            actual = {}
            for line in text("parent-system-" + phase + ".sha256").splitlines():
                digest, path = line.split("  ", 1)
                if path not in expected_paths or path in actual or not bound.HASH.fullmatch(digest):
                    raise ValueError("invalid parent namespace hash record")
                actual[path] = digest
            if actual != system:
                raise ValueError("parent hosts, trust or NSS changed")
        original_nss = text("native-nss-before.conf")
        if (bound.hashlib.sha256(original_nss.encode()).hexdigest() != system["/etc/nsswitch.conf"]
                or text("private-nss.conf") != oracle.private_hosts_nss(original_nss)):
            raise ValueError("private NSS altered services beyond hostname resolution")
        hosts_rows = [line for line in text("private-nss.conf").splitlines() if line.startswith("hosts:")]
        if hosts_rows != ["hosts: files"] or data("dns-isolation.json").get("resolved_addresses") != ["127.0.0.1"]:
            raise ValueError("advisory resolution escapes isolated guest hosts")
        release = dict(line.split("=", 1) for line in text("os-release").splitlines() if "=" in line)
        if release.get("ID", "").strip('"') != "arch":
            raise ValueError("native distro mismatch")
        native = text("native-query.tsv")
        rows = [line.split(" ", 1) for line in native.splitlines()]
        if not rows or any(len(row) != 2 or not all(row) for row in rows) or len({row[0] for row in rows}) != len(rows):
            raise ValueError("invalid native installed package query")
        packages = dict(rows); version = packages["glibc"]
        if receipt.get("native_glibc_version") != version or receipt.get("affected_binaries") != ["glibc"]:
            raise ValueError("native glibc advisory identity mismatch")
        before = receipt.get("native_state_before")
        if (receipt.get("native_state_unchanged") is not True or not isinstance(before, dict)
                or set(before) != {"installed", "explicit", "database_sha256"}
                or before != receipt.get("native_state_after") or before["installed"] != native):
            raise ValueError("native package/reason state changed or incomplete")
        explicit = [line.split(" ", 1) for line in before["explicit"].splitlines()]
        if any(len(row) != 2 or packages.get(row[0]) != row[1] for row in explicit):
            raise ValueError("invalid native install reasons")
        db = before["database_sha256"]
        if (not isinstance(db, dict) or "glibc-" + version + "/desc" not in db or "glibc-" + version + "/files" not in db
                or any((name != "ALPM_DB_VERSION" and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._+@:-]*/(?:desc|files|mtree|install)", name))
                       or not isinstance(value, str) or not bound.HASH.fullmatch(value) for name, value in db.items())):
            raise ValueError("native database identity incomplete")
        if data("native-feed.json") != oracle.arch_feed(version):
            raise ValueError("native advisory feed differs from exact installed identity")
        phases = receipt.get("product_results")
        expected = {"untrusted-tls", "direct-plain", "direct-findings", "daemon-plain", "daemon-findings", "daemon-before", "daemon-after"}
        if not isinstance(phases, dict) or set(phases) != expected:
            raise ValueError("native audit outcomes incomplete")
        for phase in expected:
            finding = phase.endswith("findings"); metrics = phase in {"daemon-before", "daemon-after"}
            argv = ["metrics"] if metrics else ["audit", "scan"] + (["--fail-on-findings"] if finding else [])
            code = int(finding or phase == "untrusted-tls")
            if phases[phase] != {"argv": argv, "exit_code": code}:
                raise ValueError("native audit actual exit/command mismatch")
            if phase in {"direct-plain", "direct-findings", "daemon-plain", "daemon-findings"}:
                oracle.verify_native_result(SimpleNamespace(returncode=code, stdout=text(phase + ".stdout"), stderr=text(phase + ".stderr")), finding)
        if ("Failed to query native security advisories" not in text("untrusted-tls.stderr")
                or "Vulnerability scan found" in text("untrusted-tls.stderr") or "No vulnerabilities found" in text("untrusted-tls.stdout")):
            raise ValueError("native untrusted TLS did not fail closed")
        events = data("fixture-events.json")
        if not isinstance(events, list) or not events or events[0].get("kind") != "tls-error":
            raise ValueError("native TLS refusal evidence missing")
        first = next(index for index, event in enumerate(events) if event.get("kind") == "request")
        if any(event.get("kind") != "tls-error" for event in events[:first]):
            raise ValueError("invalid native TLS phase")
        requests = events[first:]; count = receipt.get("daemon_fixture_requests")
        if (type(count) is not int or count not in (2, 3) or len(requests) != count + 2
                or receipt.get("direct-plain_requests") != 1 or receipt.get("direct-findings_requests") != 1):
            raise ValueError("native feed request phases incomplete")
        for start, minimum, maximum in ((0, 1, 1), (1, 1, 1), (2, 2, 3)):
            oracle.verify_arch_requests(requests[start:start + 1] if start < 2 else requests[start:], version, minimum, maximum)
        counters = []
        for phase in ("daemon-before", "daemon-after"):
            values = re.findall(r"^omg_security_audit_requests_total (\d+)$", text(phase + ".stdout"), re.M)
            if len(values) != 1 or text(phase + ".stderr").strip():
                raise ValueError("native daemon counter missing")
            counters.append(int(values[0]))
        if counters[1] - counters[0] != 2 or receipt.get("daemon_requests_delta") != 2:
            raise ValueError("native audits did not reach daemon twice")
        return receipt
    except (AssertionError, OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, StopIteration, bound.tarfile.TarError) as error:
        raise ValueError("native Arch advisory evidence rejected: " + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate_evidence(args.evidence_dir, args.archive, Path(__file__).with_name("qemu-arch-advisory-oracle.py"))
    except ValueError as error:
        parser.exit(1, str(error) + "\n")
    print("Complete archive-bound native Arch advisory evidence accepted")


if __name__ == "__main__":
    main()

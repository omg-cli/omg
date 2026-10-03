#!/usr/bin/env python3
"""Admit an exact inventory selection against a separately reviewed skip policy."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_inventory_policy import HEADER, network_scopes, read_bounded, selected_snapshot, unique_object

DISTROS = {"arch", "debian", "ubuntu", "fedora"}
EXIT = re.compile(r"(?:0|[1-9][0-9]{0,2})\Z")
MAPPED_EXIT = re.compile(r"(arch|debian|ubuntu|fedora):(0|[1-9][0-9]{0,2})\Z")


def resolve_exit(cell, distro):
    if EXIT.fullmatch(cell):
        value = int(cell)
        if value <= 255:
            return value
    entries = cell.split(",")
    if len(entries) != 4:
        raise ValueError("invalid expected exit")
    values = {}
    for entry in entries:
        match = MAPPED_EXIT.fullmatch(entry)
        if not match or match[1] in values or int(match[2]) > 255:
            raise ValueError("invalid per-distro expected exit")
        values[match[1]] = int(match[2])
    if set(values) != DISTROS:
        raise ValueError("incomplete per-distro expected exit")
    return values[distro]


def inventory_exits(content, distro):
    lines = content.decode("utf-8").replace("\r\n", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != HEADER:
        raise ValueError("invalid inventory header")
    exits = {}
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 10 or any(not field for field in fields):
            raise ValueError("invalid inventory row")
        case, cell, ux = fields[0], fields[3], fields[4]
        if case in exits or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", case):
            raise ValueError("duplicate or invalid inventory case")
        if ux not in ("pass", "declared"):
            raise ValueError("invalid expected UX")
        exits[case] = None if ux == "declared" else resolve_exit(cell, distro)
    return exits


def admit_live_doctor(results, distro):
    """Bind a live PASS to the trusted host oracle and its exported raw report."""
    helper = Path(__file__).with_name("qemu-doctor-live-oracle.py")
    expected_hash = hashlib.sha256(read_bounded(helper)).hexdigest()
    evidence = Path(results).parent
    owners = []
    for line in read_bounded(evidence / "input-sha256.txt").decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError("invalid inventory input provenance")
        if Path(match[2]).name == helper.name:
            owners.append(match[1])
    if owners != [expected_hash]:
        raise ValueError("live Doctor owner differs from trusted source")
    streams = evidence / "rows"
    stderr = read_bounded(streams / "doctor-network-live.stderr.log")
    proof_lines = [line for line in stderr.splitlines() if line.startswith(b"{")]
    if len(proof_lines) != 1:
        raise ValueError("live Doctor requires one raw proof")
    proof = json.loads(proof_lines[0], object_pairs_hook=unique_object)
    fields = {"schema_version", "kind", "complete", "distro", "network_scope", "exit_code",
              "baseline_exit_code", "baseline_issues", "health_issues", "network_issues",
              "http_positive", "dns_positive", "mirror_targets", "dns_targets",
              "oracle_sha256", "report_sha256"}
    if not isinstance(proof, dict) or set(proof) != fields:
        raise ValueError("invalid live Doctor proof schema")
    if (type(proof["schema_version"]) is not int or proof["schema_version"] != 1
            or proof["kind"] != "doctor-live-network" or proof["complete"] is not True
            or proof["distro"] != distro or proof["network_scope"] != "network"
            or type(proof["exit_code"]) is not int or proof["exit_code"] != 1
            or type(proof["baseline_exit_code"]) is not int or proof["baseline_exit_code"] != 1
            or proof["oracle_sha256"] != expected_hash):
        raise ValueError("live Doctor proof identity differs")
    mirrors = ["Arch Linux", "Kernel.org", "GitHub", "AUR"] if distro == "arch" else ["Kernel.org", "GitHub"]
    hosts = ["archlinux.org", "aur.archlinux.org", "github.com"] if distro == "arch" else ["kernel.org", "github.com"]
    numbers = ("baseline_issues", "health_issues", "network_issues", "http_positive", "dns_positive")
    if (any(type(proof[key]) is not int for key in numbers)
            or proof["mirror_targets"] != mirrors or proof["dns_targets"] != hosts
            or proof["baseline_issues"] < 1
            or not 1 <= proof["http_positive"] <= len(mirrors)
            or not 1 <= proof["dns_positive"] <= len(hosts)
            or proof["network_issues"] != len(mirrors) + len(hosts) - proof["http_positive"] - proof["dns_positive"]
            or proof["health_issues"] != proof["baseline_issues"] + proof["network_issues"]):
        raise ValueError("live Doctor observations disagree")
    stdout = read_bounded(streams / "doctor-network-live.stdout.log")
    trailer = b"\nOMG_QEMU_RECEIPT:product:1:0\n"
    if not stdout.endswith(trailer) or stdout.count(b"OMG_QEMU_RECEIPT:") != 1:
        raise ValueError("live Doctor lacks its sole terminal product receipt")
    if proof["report_sha256"] != hashlib.sha256(stdout[:-len(trailer)]).hexdigest():
        raise ValueError("live Doctor report differs from its proof")
    report = stdout[:-len(trailer)].decode("utf-8")
    if (report.count("Network Diagnostics\n") != 1 or report.count("DNS Resolution:\n") != 1
            or report.index("Network Diagnostics\n") > report.index("DNS Resolution:\n")):
        raise ValueError("live Doctor report sections differ")
    sections = report.split("Network Diagnostics\n", 1)[1].split("DNS Resolution:\n", 1)
    mirror_rows = [re.fullmatch(r"  ([✓✗⚠]) (.+?) \((.+)\)", line)
                   for line in sections[0].splitlines() if line.strip()]
    dns_rows = [re.fullmatch(r"    ([✓✗]) (\S+) \((.+)\)", line)
                for line in sections[1].splitlines() if line.startswith("    ")]
    health_counts = re.findall(rb"^Error: doctor found ([1-9][0-9]*) health issue\(s\)$", stderr, re.MULTILINE)
    if (any(row is None for row in mirror_rows + dns_rows)
            or [row[2] for row in mirror_rows] != mirrors or [row[2] for row in dns_rows] != hosts
            or sum(row[1] == "✓" for row in mirror_rows) != proof["http_positive"]
            or sum(row[1] == "✓" for row in dns_rows) != proof["dns_positive"]
            or len(health_counts) < 2
            or [int(value) for value in health_counts[-2:]] != [proof["baseline_issues"], proof["health_issues"]]):
        raise ValueError("live Doctor proof differs from raw observations")


def admit(policy, inventory, results, summary, distro, tiers):
    rules, digest, selection, inventory_bytes = selected_snapshot(policy, inventory)
    exits = inventory_exits(inventory_bytes, distro)
    profile = rules["profiles"][tiers]
    expected = {"qemu-" + distro + "-" + row["id"]: row
                for row in selection["cases"] if set(row["tiers"]) & set(profile)}
    rows = json.loads(read_bounded(results), object_pairs_hook=unique_object)
    completion = json.loads(read_bounded(summary), object_pairs_hook=unique_object)
    if not isinstance(rows, list) or not rows or len(rows) != len(expected):
        raise ValueError("missing or extra selected cases")
    counts = dict(selected=len(expected), executed=0, passed=0, failed=0,
                  blocked=0, harness_error=0, skipped=0)
    seen = set()
    skips = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("invalid case result")
        case = row.get("case_id")
        if not isinstance(case, str) or case not in expected or case in seen:
            raise ValueError("duplicate, substituted or unknown case")
        seen.add(case)
        if row.get("distro") != distro or row.get("artifact_source") != "inventory":
            raise ValueError("foreign case identity")
        verdict = row.get("result")
        code = row.get("exit_code")
        if type(code) is not int or not -1 <= code <= 255:
            raise ValueError("invalid exit code")
        if verdict == "SKIPPED":
            reason = expected[case]["allowed_skips"].get(distro)
            if not reason or code != -1:
                raise ValueError("unapproved skip")
            skips[case] = reason
            counts["skipped"] += 1
        elif verdict in ("PASS", "FAIL"):
            if code < 0:
                raise ValueError("executed case lacks an exit code")
            if verdict == "PASS" and code != exits[case.removeprefix("qemu-" + distro + "-")]:
                raise ValueError("PASS exit disagrees with inventory")
            scope = expected[case]["network_scope"]
            if scope not in ("offline", "network") or row.get("network_scope") != scope:
                raise ValueError("case did not run in its required network scope")
            if verdict == "PASS" and case == "qemu-" + distro + "-doctor-network-live":
                admit_live_doctor(results, distro)
            counts["executed"] += 1
            counts["passed" if verdict == "PASS" else "failed"] += 1
        elif verdict in ("BLOCKED", "HARNESS_ERROR"):
            counts["blocked" if verdict == "BLOCKED" else "harness_error"] += 1
        else:
            raise ValueError("unknown verdict")
    if not isinstance(completion, dict) or completion.get("complete") is not True:
        raise ValueError("incomplete inventory execution")
    expected_summary = {"pass": counts["passed"], "skipped": counts["skipped"],
                        "fail": counts["failed"] + counts["blocked"] + counts["harness_error"]}
    if any(type(completion.get(key)) is not int or completion[key] != value
           for key, value in expected_summary.items()):
        raise ValueError("inventory summary disagrees with case evidence")
    return {"schema_version": 1, "inventory_sha256": digest, "counts": counts,
            "allowed_skips": skips, "passed": counts["executed"] > 0 and expected_summary["fail"] == 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("policy", "inventory"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("results", "summary"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--distro", choices=("arch", "debian", "ubuntu", "fedora"))
    parser.add_argument("--tiers")
    parser.add_argument("--network-scopes", action="store_true")
    args = parser.parse_args()
    try:
        if args.network_scopes:
            if any((args.results, args.summary, args.distro, args.tiers)):
                raise ValueError("network scope mode accepts only policy and inventory")
            print(json.dumps(network_scopes(args.policy, args.inventory), separators=(",", ":")))
            return 0
        if not all((args.results, args.summary, args.distro, args.tiers)):
            raise ValueError("missing inventory admission input")
        receipt = admit(args.policy, args.inventory, args.results, args.summary, args.distro, args.tiers)
        print(json.dumps(receipt, indent=2))
        return 0 if receipt["passed"] else 1
    except (ValueError, OSError, KeyError, TypeError):
        print('{"schema_version":1,"passed":false,"error":"inventory policy admission failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

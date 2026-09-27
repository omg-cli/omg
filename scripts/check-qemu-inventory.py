#!/usr/bin/env python3
"""Admit an exact inventory selection against a separately reviewed skip policy."""
import argparse
import hashlib
import json
import re
from pathlib import Path

LIMIT = 1024 * 1024
HEADER = "case\targs_json\tsafety\texpected_exit\texpected_ux\trequires\ttier\ttargets\tassertions\tcleanup"
DISTROS = {"arch", "debian", "ubuntu", "fedora"}
EXIT = re.compile(r"(?:0|[1-9][0-9]{0,2})\Z")
MAPPED_EXIT = re.compile(r"(arch|debian|ubuntu|fedora):(0|[1-9][0-9]{0,2})\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory evidence key")
        result[key] = value
    return result


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError("invalid inventory evidence file")
    with path.open("rb") as stream:
        content = stream.read(LIMIT + 1)
    if len(content) > LIMIT:
        raise ValueError("inventory evidence exceeded limit")
    return content


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
    lines = content.decode("utf-8").split("\n")
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


def admit_contents(policy_bytes, inventory_bytes, results_bytes, summary_bytes, distro, tiers):
    rules = json.loads(policy_bytes, object_pairs_hook=unique_object)
    digest = hashlib.sha256(inventory_bytes).hexdigest()
    selection = rules["inventories"][digest]
    exits = inventory_exits(inventory_bytes, distro)
    profile = rules["profiles"][tiers]
    expected = {"qemu-" + distro + "-" + row["id"]: row
                for row in selection["cases"] if set(row["tiers"]) & set(profile)}
    if any(case.removeprefix("qemu-" + distro + "-") not in exits for case in expected):
        raise ValueError("selected case absent from inventory")
    rows = json.loads(results_bytes, object_pairs_hook=unique_object)
    completion = json.loads(summary_bytes, object_pairs_hook=unique_object)
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


def admit(policy, inventory, results, summary, distro, tiers):
    return admit_contents(read(policy), read(inventory), read(results), read(summary), distro, tiers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("policy", "inventory", "results", "summary"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--distro", required=True, choices=("arch", "debian", "ubuntu", "fedora"))
    parser.add_argument("--tiers", required=True)
    args = parser.parse_args()
    try:
        receipt = admit(args.policy, args.inventory, args.results, args.summary, args.distro, args.tiers)
        print(json.dumps(receipt, indent=2))
        return 0 if receipt["passed"] else 1
    except (ValueError, OSError, KeyError, TypeError):
        print('{"schema_version":1,"passed":false,"error":"inventory policy admission failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Compare OMG license reports with the guest's installed ALPM database.

ALPM local desc field semantics: https://man.archlinux.org/man/alpm-db-desc.5.en
Independent installed-state query: https://man.archlinux.org/man/pacman.8.en
"""

import csv
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import struct
import sys
from collections import Counter


LOCAL_DB = Path("/var/lib/pacman/local")
CATEGORIES = {"Permissive", "Copyleft", "StrongCopyleft", "Proprietary", "Unknown"}
CSV_HEADER = ["Package", "Version", "License", "Category"]
MAX_FILE_BYTES = 8 * 1024 * 1024
REJECT_POLICY = "LicenseRef-QemuNoInstalledLicense"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def regular(path, private=False):
    require(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    metadata = path.stat()
    require(metadata.st_size <= MAX_FILE_BYTES, f"file exceeds license evidence limit: {path}")
    if private:
        require(stat.S_IMODE(metadata.st_mode) == 0o600,
                f"license export is not owner-only (0600): {path}")
    return path


def read_desc(path):
    lines = regular(path).read_text(encoding="utf-8").splitlines()
    fields = {}
    index = 0
    while index < len(lines):
        header = lines[index]
        require(re.fullmatch(r"%[A-Z][A-Z0-9]*%", header) is not None,
                f"invalid ALPM desc section in {path}")
        key = header[1:-1]
        require(key not in fields, f"duplicate ALPM desc section {key} in {path}")
        index += 1
        values = []
        while index < len(lines) and lines[index]:
            values.append(lines[index])
            index += 1
        fields[key] = values
        index += 1
    for key in ("NAME", "VERSION"):
        require(len(fields.get(key, [])) == 1 and fields[key][0].strip() == fields[key][0],
                f"missing or malformed ALPM desc {key} in {path}")
    licenses = fields.get("LICENSE", [])
    require(all(value and value.strip() == value for value in licenses),
            f"malformed ALPM licenses in {path}")
    return fields["NAME"][0], fields["VERSION"][0], licenses


def native_packages(db=LOCAL_DB):
    require(db.is_dir() and not db.is_symlink(), "ALPM local database is unavailable")
    packages = {}
    for entry in db.iterdir():
        if not entry.is_dir():
            continue  # ALPM_DB_VERSION is a regular file.
        require(not entry.is_symlink(), f"symlinked ALPM package entry: {entry}")
        name, version, licenses = read_desc(entry / "desc")
        require(name not in packages, f"duplicate installed ALPM package: {name}")
        packages[name] = (version, licenses)
    require(bool(packages), "ALPM local database is empty")

    env = dict(os.environ, LC_ALL="C")
    result = subprocess.run(["pacman", "-Q"], check=True, capture_output=True,
                            text=True, timeout=30, env=env)
    pacman = {}
    for line in result.stdout.splitlines():
        parts = line.rsplit(" ", 1)
        require(len(parts) == 2 and all(parts) and parts[0] not in pacman,
                "malformed or duplicate pacman -Q row")
        pacman[parts[0]] = parts[1]
    require({name: version for name, (version, _) in packages.items()} == pacman,
            "ALPM desc inventory disagrees with pacman -Q")
    return packages


def spreadsheet_safe(value):
    return "'" + value if value.startswith(("=", "+", "-", "@")) else value


# Independent advisory contract literals, not values extracted from OMG output.
# Unknown/custom identifiers and exception legal effects remain unresolved.
FAMILY_IDS = {
    "StrongCopyleft": frozenset("AGPL AGPL1 AGPL3 AGPL-1.0 AGPL-1.0-only AGPL-1.0-or-later "
                               "AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later".upper().split()),
    "Copyleft": frozenset("GPL GPL1 GPL2 GPL3 LGPL LGPL2 LGPL3 LGPL2.1 "
                         "GPL-1.0 GPL-1.0-only GPL-1.0-or-later "
                         "GPL-2.0 GPL-2.0-only GPL-2.0-or-later "
                         "GPL-3.0 GPL-3.0-only GPL-3.0-or-later "
                         "LGPL-2.0 LGPL-2.0-only LGPL-2.0-or-later "
                         "LGPL-2.1 LGPL-2.1-only LGPL-2.1-or-later "
                         "LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later "
                         "MPL MPL-1.0 MPL-1.1 MPL-2.0 MPL-2.0-no-copyleft-exception".upper().split()),
    "Permissive": frozenset("MIT MIT-0 ISC Unlicense CC0 CC0-1.0 0BSD BSD "
                           "BSD-2-Clause BSD-3-Clause BSD-4-Clause Apache Apache-1.0 "
                           "Apache-1.1 Apache-2.0".upper().split()),
    "Proprietary": frozenset(("PROPRIETARY", "COMMERCIAL")),
}
CATEGORY_ORDER = ["Unknown", "Proprietary", "Permissive", "Copyleft", "StrongCopyleft"]


def advisory_category(expression):
    """Bounded syntax with explicit family IDs; AND/OR keep the strongest family."""
    if len(expression.encode("utf-8")) > 4096 or re.search(r"[^A-Za-z0-9.\-+:() \t\r\n\v\f]", expression):
        return "Unknown"
    tokens = re.findall(r"[A-Za-z0-9.\-+:]+|[()]", expression.upper())
    if not tokens or len(tokens) > 256:
        return "Unknown"
    depth = 0
    for token in tokens:
        if token == "(":
            depth += 1
            if depth > 32:
                return "Unknown"
        elif token == ")":
            depth -= 1
            if depth < 0:
                return "Unknown"
        elif token not in ("AND", "OR", "WITH"):
            pattern = (r"DOCUMENTREF-[A-Z0-9.\-]+:LICENSEREF-[A-Z0-9.\-]+" if ":" in token
                       else r"[A-Z0-9.\-]+\+?")
            if re.fullmatch(pattern, token) is None:
                return "Unknown"
    if depth:
        return "Unknown"
    position = 0

    def atom():
        nonlocal position
        require(position < len(tokens), "missing expression operand")
        token = tokens[position]
        position += 1
        if token == "(":
            category = chain()
            require(position < len(tokens) and tokens[position] == ")", "missing close")
            position += 1
            return category
        require(token not in ("AND", "OR", "WITH", ")"), "invalid expression operand")
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            require(position < len(tokens) and tokens[position] not in
                    ("AND", "OR", "WITH", "(", ")"), "missing exception")
            position += 1  # Exception text is not a base license family.
        identifier = token.removesuffix("+")
        return next((category for category, ids in FAMILY_IDS.items() if identifier in ids),
                    "Unknown")

    def chain():
        nonlocal position
        category = atom()
        while position < len(tokens) and tokens[position] != ")":
            if tokens[position] in ("AND", "OR"):
                position += 1
            right = atom()  # Whitespace juxtaposition preserves legacy alternatives.
            category = max((category, right), key=CATEGORY_ORDER.index)
        return category

    try:
        category = chain()
        require(position == len(tokens), "trailing expression token")
        return category
    except AssertionError:
        return "Unknown"


def known_category(licenses):
    if not licenses:
        return "Unknown"
    # Native assignments are cumulative. Commas are display-only separators.
    return advisory_category(" AND ".join(f"({value})" for value in licenses))


def expected_audit(packages, mit_only=False, csv_safe=False):
    rows = {}
    for name, (version, licenses) in packages.items():
        if mit_only:
            tokens = re.split(r"[^A-Za-z0-9.+-]+", ", ".join(licenses).lower())
            if not any(token == "mit" or token == "mit+" or token.startswith("mit-")
                       for token in tokens):
                continue
        license_value = ", ".join(licenses) if licenses else "Unknown"
        if csv_safe:
            rows[spreadsheet_safe(name)] = (spreadsheet_safe(version),
                                            spreadsheet_safe(license_value),
                                            known_category(licenses))
        else:
            rows[name] = (version, license_value, known_category(licenses))
    return rows


def compare_audit_rows(rows, expected):
    require(isinstance(rows, list), "license report must be an array")
    observed = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"name", "version", "license", "category"},
                "license report row schema is wrong")
        name, version, license_value, category = (
            row[key] for key in ("name", "version", "license", "category"))
        require(all(isinstance(value, str) and value for value in
                    (name, version, license_value, category)) and category in CATEGORIES,
                "license report row has invalid values")
        require(name not in observed, f"duplicate license report package: {name}")
        expected_row = expected.get(name)
        require(expected_row is not None, f"unexpected license report package: {name}")
        if expected_row[2] is not None:
            require(category == expected_row[2], f"wrong license category for {name}")
        observed[name] = (version, license_value)
    require(observed == {name: row[:2] for name, row in expected.items()},
            "license report differs from native installed inventory")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate license JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def expected_enterprise(packages):
    counts = Counter()
    unknown = []
    violations = []
    for name, (_, licenses) in packages.items():
        if not licenses:
            unknown.append(name)
        for license_value in licenses:
            counts[license_value] += 1
            # Each assignment is classified independently for enterprise review.
            category = advisory_category(license_value)
            if category == "StrongCopyleft":
                violations.append((name, license_value,
                                   "Strong copyleft license (AGPL) requires legal review"))
            elif category == "Copyleft":
                violations.append((name, license_value,
                                   "Copyleft license requires legal review"))
    return counts, sorted(unknown), sorted(violations)


def assignment_percentage(count, assignments):
    # The renderer calculates in f32 and formats with zero decimal places.
    # Reproduce only those arithmetic/rounding rules, never rendered output.
    def f32(value):
        return struct.unpack("f", struct.pack("f", value))[0]
    return str(round(f32(f32(f32(count) / f32(assignments)) * 100))) if assignments else "0"


def check_enterprise_text(report, packages):
    counts, unknown, violations = expected_enterprise(packages)
    lines = report.splitlines()
    summary = f"[License Compliance Scan] {len(packages)} total packages"
    require(lines.count(summary) == 1, "enterprise license summary lacks native package total")
    sections = {}
    current = None
    titles = {"License Inventory", "Policy Violations", "Unknown Licenses"}
    for line in lines:
        if not line.strip() or line == summary:
            continue
        if set(line.strip()) <= set("─━═┌┐└┘├┤┬┴┼╭╮╰╯╞╡╪╤╧╒╕╘╛+|- "):
            continue  # Table border, not report content.
        value = line.strip().strip("│|").strip()
        if value in titles:
            require(value not in sections, f"duplicate enterprise section: {value}")
            sections[value] = []
            current = value
        else:
            require(current is not None and line.lstrip().startswith(("│", "|")),
                    "unexpected enterprise text outside a card")
            sections[current].append(value)
    require("License Inventory" in sections, "missing enterprise license inventory")
    assignments = sum(counts.values())
    inventory = [f"{value}: {count} assignments ({assignment_percentage(count, assignments)}%)"
                 for value, count in counts.items()]
    inventory.sort()
    expected_inventory = inventory[:20]
    if len(inventory) > 20:
        expected_inventory.append(f"... and {len(inventory) - 20} more")
    require(sections["License Inventory"] == expected_inventory,
            "enterprise displayed license counts or percentages differ from native data")

    def limited_members(title, expected, limit):
        if not expected:
            require(title not in sections, f"unexpected enterprise section: {title}")
            return
        require(title in sections, f"missing enterprise section: {title}")
        observed = list(sections[title])
        if len(expected) > limit:
            require(bool(observed) and observed[-1] == f"... and {len(expected) - limit} more",
                    f"wrong enterprise truncation: {title}")
            observed.pop()
        require(len(observed) == min(limit, len(expected)), f"wrong enterprise row count: {title}")
        actual, full = Counter(observed), Counter(expected)
        # Native package iteration order is unspecified. Check exact rows when
        # complete, otherwise the displayed multiset must be a valid subset.
        require(all(count <= full[row] for row, count in actual.items()),
                f"extra or duplicate enterprise rows: {title}")
        if len(expected) <= limit:
            require(actual == full, f"missing enterprise rows: {title}")

    limited_members("Policy Violations", [f"{name} - {reason}" for name, _, reason in violations], 20)
    limited_members("Unknown Licenses", unknown, 5)


def check(mode, path, packages, stderr=None):
    regular(path, private=mode in ("audit-csv", "enterprise-json"))
    if mode in ("audit-json", "audit-mit-json"):
        compare_audit_rows(read_json(path),
                           expected_audit(packages, mit_only=mode == "audit-mit-json"))
        if mode == "audit-mit-json":
            require(stderr is not None, "policy rejection stderr evidence is missing")
            regular(stderr)
            require(all(REJECT_POLICY.casefold() not in value.casefold()
                        for _, licenses in packages.values() for value in licenses),
                    "impossible policy license marker matches native inventory")
            expected = f"Error: License policy check found {len(packages)} violation(s)"
            require(stderr.read_text(encoding="utf-8").strip() == expected,
                    "license policy did not reject every installed package")
    elif mode == "audit-csv":
        with path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            require(reader.fieldnames == CSV_HEADER, "license CSV header differs")
            rows = []
            for item in reader:
                require(None not in item and None not in item.values(), "malformed license CSV row")
                rows.append(dict(name=item["Package"], version=item["Version"],
                                 license=item["License"], category=item["Category"]))
        compare_audit_rows(rows, expected_audit(packages, csv_safe=True))
    elif mode == "enterprise-json":
        report = read_json(path)
        require(isinstance(report, dict) and
                set(report) == {"total", "by_license", "violations", "unknown"},
                "enterprise license export schema differs")
        counts, unknown, violations = expected_enterprise(packages)
        require(type(report["total"]) is int and report["total"] == len(packages),
                "enterprise package total differs from native inventory")
        require(isinstance(report["by_license"], dict) and
                all(type(value) is int and value > 0 for value in report["by_license"].values())
                and report["by_license"] == dict(counts),
                "enterprise license assignments differ from native inventory")
        require(isinstance(report["unknown"], list) and sorted(report["unknown"]) == unknown,
                "enterprise unknown packages differ from native inventory")
        observed_violations = report["violations"]
        require(isinstance(observed_violations, list) and all(
            isinstance(row, dict) and set(row) == {"package", "license", "reason"}
            for row in observed_violations), "enterprise violations have wrong schema")
        observed = sorted((row["package"], row["license"], row["reason"])
                          for row in observed_violations)
        require(observed == violations, "enterprise violations differ from native inventory")
    elif mode == "enterprise-text":
        report = path.read_text(encoding="utf-8")
        check_enterprise_text(report, packages)
    else:
        raise AssertionError(f"unknown license oracle mode: {mode}")


def main():
    require(len(sys.argv) == (4 if len(sys.argv) > 1 and sys.argv[1] == "audit-mit-json" else 3),
            "usage: qemu-license-oracle.py MODE PATH [PATH_STDERR for audit-mit-json]")
    check(sys.argv[1], Path(sys.argv[2]), native_packages(),
          Path(sys.argv[3]) if len(sys.argv) == 4 else None)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ValueError, json.JSONDecodeError, csv.Error,
            subprocess.SubprocessError) as error:
        print(f"assertion failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None

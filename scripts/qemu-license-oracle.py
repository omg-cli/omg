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


def known_category(licenses):
    """Assert only categories whose native license entries are unambiguous."""
    if not licenses:
        return "Unknown"
    upper = [value.upper() for value in licenses]
    tokens = [token for value in upper for token in
              re.split(r"[^A-Z0-9.+-]+", value) if token]
    if any(re.fullmatch(r"AGPL(?:[.+-][A-Z0-9.+-]+)?", token) for token in tokens):
        return "StrongCopyleft"
    if any(re.fullmatch(r"(?:LGPL|GPL|MPL)(?:[.+-][A-Z0-9.+-]+)?", token)
           for token in tokens):
        return "Copyleft"
    if all(re.fullmatch(r"MIT|ISC|0BSD|UNLICENSE|CC0(?:-1\.0)?|BSD(?:-[A-Z0-9.+-]+)?|"
                        r"APACHE(?:-[A-Z0-9.+-]+)?", value) for value in upper):
        return "Permissive"
    return None


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
            # Mirror the product's classifier (src/cli/enterprise.rs), which
            # uses the same SPDX-aware categories as `omg audit`. A bare
            # "GPL" substring test understated AGPL, missed MPL entirely, and
            # only caught LGPL by accident.
            category = known_category([license_value])
            if category == "StrongCopyleft":
                violations.append((name, license_value,
                                   "Strong copyleft license (AGPL) requires legal review"))
            elif category == "Copyleft":
                violations.append((name, license_value,
                                   "Copyleft license requires legal review"))
    return counts, sorted(unknown), sorted(violations)


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
        counts, _, _ = expected_enterprise(packages)
        require(re.search(r"(?m)^\[License Compliance Scan\] "
                          + re.escape(str(len(packages))) + r" total packages$", report)
                is not None and "License Inventory" in report,
                "enterprise license summary lacks native package total")
        rendered = re.findall(r"(?m)^[│|]\s*(.+?): ([0-9]+) assignments "
                              r"\([0-9]+%\)\s*[│|]?\s*$", report)
        require(len(rendered) == sum(" assignments (" in line for line in report.splitlines()),
                "malformed enterprise license assignment row")
        # The renderer sorts the complete "license: count assignments" strings.
        # A prefix license such as "Apache-2.0 OR MIT" sorts before the shorter
        # "Apache-2.0: ..." row because the space precedes the colon.
        expected = [(license_value, str(counts[license_value])) for license_value in
                    sorted(counts, key=lambda value: f"{value}: {counts[value]} assignments")[:20]]
        require(rendered == expected, "enterprise displayed license counts differ from native data")
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

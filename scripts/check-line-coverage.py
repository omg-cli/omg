#!/usr/bin/env python3
"""Require complete LCOV line coverage to meet the exact base report."""
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class Coverage:
    files: int
    found: int
    hit: int
    mapped: int
    mapped_hit: int
    sha256: str


def unsigned(text):
    if not re.fullmatch(r"[0-9]+", text):
        raise ValueError("Invalid LCOV nonnegative integer")
    return int(text)


def read_coverage(path):
    raw = Path(path).read_bytes()
    seen = set()
    source = None
    counts = {}
    summaries = {}
    found = hit = mapped = mapped_hit = 0
    for line in raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("SF:"):
            if source is not None:
                raise ValueError("Unterminated LCOV section")
            source = line[3:]
            if not source or source in seen:
                raise ValueError("Missing or duplicate LCOV source file")
            seen.add(source)
            counts = {}
            summaries = {}
        elif line == "end_of_record":
            if source is None or set(summaries) != {"LF", "LH"}:
                raise ValueError("Missing LCOV file section or line summaries")
            actual_hit = sum(count > 0 for count in counts.values())
            if summaries["LH"] > summaries["LF"]:
                raise ValueError("LCOV covered lines exceed instrumented lines")
            if summaries["LF"] > 0 and not counts:
                raise ValueError("LCOV report is missing mapped line data")
            # LLVM file summaries aggregate function instantiation groups;
            # DA records are the merged file mapping. They can legitimately
            # differ. Enforce both metrics, without dropping either surface.
            # llvm/tools/llvm-cov/{CoverageReport,CoverageExporterLcov}.cpp
            found += summaries["LF"]
            hit += summaries["LH"]
            mapped += len(counts)
            mapped_hit += actual_hit
            source = None
        elif line.startswith("DA:"):
            if source is None:
                raise ValueError("Line data outside LCOV section")
            fields = line[3:].split(",")
            if len(fields) not in (2, 3):
                raise ValueError("Invalid LCOV line record")
            number, count = map(unsigned, fields[:2])
            if number == 0 or number in counts:
                raise ValueError("Invalid or duplicate LCOV line number")
            counts[number] = count
        elif line.startswith(("LF:", "LH:")):
            key = line[:2]
            if source is None or key in summaries:
                raise ValueError("Misplaced or duplicate LCOV summary")
            summaries[key] = unsigned(line[3:])
        elif line.startswith("TN:"):
            if source is not None:
                raise ValueError("Test name inside LCOV section")
        elif line.startswith(("FN:", "FNDA:", "FNF:", "FNH:", "BRDA:",
                              "BRF:", "BRH:", "VER:")):
            if source is None:
                raise ValueError("Coverage record outside LCOV section")
        else:
            raise ValueError("Unknown LCOV record")
    if source is not None or not seen or found == 0 or mapped == 0:
        raise ValueError("Incomplete or empty LCOV report")
    return Coverage(len(seen), found, hit, mapped, mapped_hit,
                    hashlib.sha256(raw).hexdigest())


def require_no_regression(base, head):
    if head.hit * base.found < base.hit * head.found:
        raise ValueError(
            f"Line coverage decreased: base {base.hit}/{base.found}, "
            f"head {head.hit}/{head.found}")
    if head.mapped_hit * base.mapped < base.mapped_hit * head.mapped:
        raise ValueError(
            f"Mapped line coverage decreased: base {base.mapped_hit}/{base.mapped}, "
            f"head {head.mapped_hit}/{head.mapped}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--head", required=True, type=Path)
    args = parser.parse_args()
    base = read_coverage(args.base)
    head = read_coverage(args.head)
    print(json.dumps({"base": vars(base), "head": vars(head)}, sort_keys=True))
    require_no_regression(base, head)
    print("PASS: complete line coverage meets the exact base report")


if __name__ == "__main__":
    main()

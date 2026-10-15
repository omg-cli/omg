#!/usr/bin/env python3
"""Require complete LCOV line coverage to meet the exact base report."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import difflib
import gzip
import subprocess
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
    sections: dict | None = None


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
    sections = {}
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
            sections[source] = {"counts": counts, **summaries}
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
                    hashlib.sha256(raw).hexdigest(), sections)


def require_no_regression(base, head):
    for value in (base, head):
        if min(value.found, value.hit, value.mapped, value.mapped_hit) < 0 or value.hit > value.found or value.mapped_hit > value.mapped:
            raise ValueError("Invalid normalized coverage counts")
    if head.hit * base.found < base.hit * head.found:
        raise ValueError(
            f"Line coverage decreased: base {base.hit}/{base.found}, "
            f"head {head.hit}/{head.found}")
    if head.mapped_hit * base.mapped < base.mapped_hit * head.mapped:
        raise ValueError(
            f"Mapped line coverage decreased: base {base.mapped_hit}/{base.mapped}, "
            f"head {head.mapped_hit}/{head.mapped}")


def source_blobs(repo, commit):
    if not re.fullmatch(r"[0-9a-f]{40}", commit or "") or commit == "0" * 40:
        raise ValueError("Exact source commit required")
    listing = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "-z", commit],
                             check=True, capture_output=True, timeout=30)
    if not listing.stdout.endswith(b"\0"):
        raise ValueError("Incomplete source path listing")
    paths = [raw.decode("utf-8") for raw in listing.stdout.split(b"\0")[:-1]]
    if any("\n" in name or "\r" in name for name in paths):
        raise ValueError("Unsupported newline in source path")
    names = [name for name in paths if name.endswith(".rs")]
    batch = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch"],
        input="".join(commit + ":" + name + "\n" for name in names).encode(),
        check=True, capture_output=True, timeout=30).stdout
    blobs = {}; offset = 0
    for name in names:
        end = batch.index(b"\n", offset)
        _, kind, size = batch[offset:end].split()
        if kind != b"blob":
            raise ValueError("Exact source blob missing")
        size = int(size); start = end + 1
        blobs[name] = batch[start:start + size]
        if len(blobs[name]) != size or batch[start + size:start + size + 1] != b"\n":
            raise ValueError("Incomplete source blob batch")
        offset = start + size + 1
    if offset != len(batch):
        raise ValueError("Unexpected source blob batch tail")
    return blobs


def canonical_source(filename, sources):
    if not filename.startswith("/") or ".." in filename.split("/") or "\\" in filename:
        raise ValueError("Invalid coverage source path")
    matches = [name for name in sources if filename.endswith("/" + name)]
    if len(matches) != 1:
        raise ValueError("Ambiguous or missing coverage source identity")
    return matches[0]


def region_evidence(path, coverage, sources):
    raw = Path(path).read_bytes()
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError("Region archive exceeds bound")
    # Stream at most one bounded JSON payload; gzip bombs remain fatal.
    with gzip.open(path, "rb") as stream:
        decoded = stream.read(256 * 1024 * 1024 + 1)
    if len(decoded) > 256 * 1024 * 1024:
        raise ValueError("Region JSON exceeds bound")
    value = json.loads(decoded)
    if value.get("type") != "llvm.coverage.json.export" or value.get("version") != "3.1.0" or len(value.get("data", [])) != 1:
        raise ValueError("Unsupported region schema")
    data = value["data"][0]; files = {}
    for item in data["files"]:
        name = canonical_source(item["filename"], sources)
        if name in files:
            raise ValueError("Duplicate region source")
        files[name] = item["summary"]["lines"]
    sections = {canonical_source(name, sources): item for name, item in coverage.sections.items()}
    if len(sections) != len(coverage.sections) or files.keys() != sections.keys():
        raise ValueError("Region/LCOV source set mismatch")
    for name, item in sections.items():
        if (files[name]["count"], files[name]["covered"]) != (item["LF"], item["LH"]):
            raise ValueError("Region/LCOV summary mismatch")
    return data["functions"], sections


def require_source_no_regression(base, head, base_regions, head_regions, base_sources, head_sources):
    bf, bs = region_evidence(base_regions, base, base_sources)
    hf, hs = region_evidence(head_regions, head, head_sources)
    if bs.keys() != hs.keys():
        raise ValueError("Added or removed coverage file requires explicit review")
    removed = {}; deleted_mapped = deleted_hit = 0
    for name in bs:
        old = base_sources[name].decode("utf-8").splitlines()
        new = head_sources[name].decode("utf-8").splitlines()
        before, after = bs[name]["counts"], hs[name]["counts"]
        if any(line > len(old) for line in before) or any(line > len(new) for line in after):
            raise ValueError("Coverage line exceeds exact source blob")
        retained = {}; gone = set()
        for tag, a, b, c, d in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
            if tag == "equal":
                if old != new and any(before.get(line, 0) > 0 for line in range(a + 1, b + 1)):
                    block = "\n" + "\n".join(old[a:b]) + "\n"
                    anchored_suffix = b == len(old) and d == len(new)
                    if not anchored_suffix and (("\n" + "\n".join(old) + "\n").count(block) != 1 or
                                                ("\n" + "\n".join(new) + "\n").count(block) != 1):
                        raise ValueError("Ambiguous unchanged source correspondence")
                retained.update(zip(range(a + 1, b + 1), range(c + 1, d + 1)))
            elif tag == "delete":
                gone.update(range(a + 1, b + 1))
            # Replacement is not proven deletion. Its old counts stay in the
            # strict base ratios, and its new uncovered mappings are refused.
        for oldline, newline in retained.items():
            if oldline in before and before[oldline] > 0 and after.get(newline, 0) == 0:
                raise ValueError("Retained covered line lost coverage or mapping")
        retained_new = set(retained.values())
        if any(count == 0 and line not in retained_new for line, count in after.items()):
            raise ValueError("New uncovered instrumented line")
        removed[name] = gone
        deleted_mapped += sum(line in gone for line in before)
        deleted_hit += sum(line in gone and count > 0 for line, count in before.items())
    head_names = {f["name"] for f in hf}; deleted_found = deleted_summary_hit = 0
    base_name_counts = {}
    for function in bf:
        base_name_counts[function["name"]] = base_name_counts.get(function["name"], 0) + 1
    accounted = {name: set() for name in bs}
    deleted_summaries = {name: [0, 0] for name in bs}
    deleted_geometries = set()
    for function in bf:
        regions = function["regions"]; filenames = function["filenames"]
        touched = []
        for region in regions:
            if filenames[region[5]] not in base.sections:
                # LLVM JSON includes functions excluded from its file/LCOV surface.
                # They cannot authorize any subtraction from selected file summaries.
                continue
            name = canonical_source(filenames[region[5]], base_sources)
            if any(line in removed.get(name, set()) for line in range(region[0], region[2] + 1)):
                touched.append(region)
        if not touched:
            continue
        if base_name_counts[function["name"]] != 1 or function["name"] in head_names or len(filenames) != 1 or len(touched) != len(regions):
            raise ValueError("Deleted region has retained or ambiguous function owner")
        name = canonical_source(filenames[0], base_sources); counts = {}
        geometry = (name, tuple(sorted(tuple(region[:4] + region[5:]) for region in regions)))
        if geometry in deleted_geometries:
            raise ValueError("Duplicate deleted region owner geometry")
        deleted_geometries.add(geometry)
        for region in regions:
            if len(region) != 8 or region[0] != region[2] or region[7] != 0 or region[5] != 0 or region[6] != 0 or region[0] not in removed[name]:
                raise ValueError("Unsupported deleted region attribution")
            if type(region[4]) is not int or region[4] < 0:
                raise ValueError("Invalid region count")
            counts[region[0]] = max(counts.get(region[0], 0), region[4])
        deleted_found += len(counts); deleted_summary_hit += sum(count > 0 for count in counts.values())
        deleted_summaries[name][0] += len(counts)
        deleted_summaries[name][1] += sum(count > 0 for count in counts.values())
        accounted[name].update(counts)
    for name in bs:
        if any(line in removed[name] and line not in accounted[name] for line in bs[name]["counts"]):
            raise ValueError("Deleted mapped line lacks region attribution")
        found, hit = deleted_summaries[name]
        if found:
            before, after = bs[name], hs[name]
            if not (0 <= hit <= found <= before["LF"] and hit <= before["LH"]):
                raise ValueError("Deleted attribution exceeds original file counts")
            if (after["LF"], after["LH"]) != (before["LF"] - found, before["LH"] - hit):
                raise ValueError("Unexplained same-file summary movement during deletion")
            kept = {line: count for line, count in before["counts"].items() if line not in removed[name]}
            if (len(after["counts"]), sum(count > 0 for count in after["counts"].values())) != (len(kept), sum(count > 0 for count in kept.values())):
                raise ValueError("Unexplained same-file mapped movement during deletion")
    normalized = Coverage(base.files, base.found - deleted_found, base.hit - deleted_summary_hit,
                          base.mapped - deleted_mapped, base.mapped_hit - deleted_hit, base.sha256)
    if min(normalized.found, normalized.mapped) <= 0:
        raise ValueError("Deletion leaves no comparable coverage")
    require_no_regression(normalized, head)
    return {"deleted_summary_found": deleted_found, "deleted_summary_hit": deleted_summary_hit,
            "deleted_mapped": deleted_mapped, "deleted_mapped_hit": deleted_hit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--base-regions", type=Path)
    parser.add_argument("--head-regions", type=Path)
    parser.add_argument("--source-repo", type=Path)
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    args = parser.parse_args()
    base = read_coverage(args.base)
    head = read_coverage(args.head)
    print(json.dumps({"base": {k: v for k, v in vars(base).items() if k != "sections"},
                      "head": {k: v for k, v in vars(head).items() if k != "sections"}}, sort_keys=True))
    evidence = (args.base_regions, args.head_regions, args.source_repo, args.base_sha, args.head_sha)
    if any(evidence):
        if not all(evidence):
            raise ValueError("Complete exact source/region evidence required")
        receipt = require_source_no_regression(base, head, args.base_regions, args.head_regions,
            source_blobs(args.source_repo, args.base_sha), source_blobs(args.source_repo, args.head_sha))
        print(json.dumps(receipt, sort_keys=True))
    else:
        require_no_regression(base, head)
    print("PASS: complete line coverage meets the exact base report")


if __name__ == "__main__":
    main()

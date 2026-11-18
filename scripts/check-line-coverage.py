#!/usr/bin/env python3
"""Require complete LCOV line coverage to meet the exact base report."""
import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import difflib
import gzip
import subprocess
from pathlib import Path
import re

COUNTER_LIMIT = 2**63 - 1


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


def read_coverage(path, side=None):
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
            if count >= COUNTER_LIMIT:
                raise ValueError(f"Invalid LCOV coverage counter ({side or path}) at {source}:{number}: "
                                 f"{count}; wrapped or saturated count")
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


def region_evidence(path, coverage, sources, side=None):
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
    # LLVM's JSON exporter clamps uint64 counts to INT64_MAX. Saturation
    # cannot establish execution; an unsigned underflow also appears positive.
    # https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-cov/CoverageExporterJson.cpp
    for function in data["functions"]:
        for region in function["regions"]:
            if len(region) > 4 and type(region[4]) is int and region[4] >= COUNTER_LIMIT:
                file_id = region[5] if len(region) > 5 else None
                names = function["filenames"]
                filename = names[file_id] if type(file_id) is int and 0 <= file_id < len(names) else "<unknown>"
                raise ValueError(f"Invalid JSON region coverage counter ({side or path}) at {filename}:{region[0]}: "
                                 f"{region[4]}; wrapped or saturated count")
    return data["functions"], sections


def source_owner_span(owner, name, files, source):
    if (len(owner["filenames"]) != 1 or files.get(owner["filenames"][0]) != name
            or not owner["regions"]
            or any(len(region) != 8 or any(type(value) is not int for value in region)
                   or min(region[:4]) < 1 or region[0] > region[2]
                   or region[2] > len(source)
                   or region[1] > len(source[region[0] - 1].encode("utf-8")) + 1
                   or region[3] > len(source[region[2] - 1].encode("utf-8")) + 1
                   or (region[0] == region[2] and region[1] >= region[3])
                   or region[4] < 0 or region[5:] != [0, 0, 0]
                   for region in owner["regions"])):
        return None
    start, end = min(r[0] for r in owner["regions"]), max(r[2] for r in owner["regions"])
    declaration = source[start - 1]
    function = re.fullmatch(
        r"([ \t]*)(?:(?:pub(?:\([^()]*\))?|async|unsafe|const)\s+)*fn\s+[A-Za-z_]\w*[^{}]*\{\s*",
        declaration)
    header = declaration if function else None
    if not (function and source[end - 1].rstrip() == function[1] + "}"
            and any(r[2] == end and r[3] > len(function[1]) + 1 for r in owner["regions"])):
        declaration = None
    return start, end, declaration, header


def owner_covers_lines(regions, start, end):
    return all(any(region[0] <= line < region[2] or line == region[2] and region[3] > 1
                   for region in regions) for line in range(start, end + 1))


def source_opcodes(old, new, function_scopes, mapped):
    old_text, new_text = "\n" + "\n".join(old) + "\n", "\n" + "\n".join(new) + "\n"
    local = {}
    for tag, a, b, c, d in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        block = "\n" + "\n".join(old[a:b]) + "\n"
        suffix = b == len(old) and d == len(new)
        if tag != "equal":
            yield tag, a, b, c, d, block, suffix
            continue
        unique = old_text.count(block) == new_text.count(block) == 1
        source_words = any(line + 1 in mapped and re.search(r"\w", old[line])
                           for line in range(a, b))
        selected = [(scope, max(a, scope[0] - 1), min(b, scope[1])) for scope in function_scopes
                    if not suffix and max(a, scope[0] - 1) < min(b, scope[1])
                    and (not unique or not source_words and any(
                        line + 1 in mapped and not scope[2] - 1 <= c + line - a < scope[3]
                        for line in range(max(a, scope[0] - 1), min(b, scope[1]))))]
        # Unmapped text cannot authorize gray mappings; proven owner anchors still apply.
        weak_gray = old != new and not source_words
        if not selected and not weak_gray:
            # Unique global blocks retain ancestry through extraction and renaming.
            yield tag, a, b, c, d, block, suffix
            continue
        # A delimiter's uniqueness cannot prove a moved body against its function owner.
        masked = {line for _, start, end in selected for line in range(start, end)}
        run = None
        for offset in range(b - a + 1):
            available = (offset < b - a and a + offset not in masked
                         and (not weak_gray or mapped.get(a + offset + 1, 0) > 0))
            if available and run is None:
                run = offset
            if not available and run is not None:
                yield tag, a + run, a + offset, c + run, c + offset, block, suffix
                run = None
        for scope, low, high in selected:
            start, end, newstart, newend = scope
            if scope not in local:
                local_old, local_new = old[start - 1:end], new[newstart - 1:newend]
                local[scope] = difflib.SequenceMatcher(None, local_old, local_new, autojunk=False).get_opcodes()
            for local_tag, x, y, u, v in local[scope]:
                first, last = max(low, x + start - 1), min(high, y + start - 1)
                if local_tag == "equal" and first < last:
                    target = u + newstart - 1 + first - (x + start - 1)
                    # Local suffixes are not file EOF and local deletion earns no credit.
                    yield ("equal", first, last, target, target + last - first,
                           "\n" + "\n".join(old[x + start - 1:y + start - 1]) + "\n", False)


def retained_wrapper_paint(name, old, new, before, after, base, head, base_files, head_files, retained,
                          base_section, head_section):
    """Prove retained wrapper paint through identical fine-region hit states.

    Positive execution frequency may vary across async polls. Fine geometry and
    covered/uncovered states must match; coarse counters and baseline DA stay exact.
    LLVM groups owners by their first region and max-merges line coverage; adding
    serial can merge a synthetic wrapper's group into the unchanged body group.
    """
    names = [Counter(owner["name"] for owner in owners) for owners in (base, head)]

    def async_test(source, start):
        if not re.fullmatch(r"\s*async\s+fn\s+[A-Za-z_]\w*\s*\(\s*\)\s*(?:->[^{}]+)?\{\s*", source[start - 1]):
            return False
        attributes = []
        for line in reversed(source[:start - 1]):
            if not re.fullmatch(r"\s*#\[[^\n]+\]\s*", line):
                break
            attributes.append(line.strip())
        return len(attributes) == 2 and set(attributes) == {"#[tokio::test]", "#[serial_test::serial]"}

    def occurrences(source, block):
        return [n for n in range(len(source) - len(block) + 1) if source[n:n + len(block)] == block]

    def fingerprint(group):
        return tuple(region[:4] + (int(region[4] > 0),) + region[5:] for region in group)

    def project(owners, files, source, start, end, first_column, last_column, name_counts):
        groups = {}
        for owner in owners:
            if not any(files.get(path) == name for path in owner["filenames"]):
                continue
            if any(len(r) != 8 or any(type(v) is not int for v in r) for r in owner["regions"]):
                return None
            touched = [r for r in owner["regions"]
                       if (r[0], r[1]) < (end, last_column) and (r[2], r[3]) > (start, first_column)]
            if not touched:
                continue
            if name_counts[owner["name"]] != 1 or source_owner_span(owner, name, files, source) is None:
                return None
            if any((r[0], r[1]) < (start, first_column) or (r[2], r[3]) > (end, last_column)
                   for r in touched):
                return None
            group = tuple(sorted(tuple([r[0] - start, r[1], r[2] - start] + r[3:]) for r in touched))
            groups[id(owner)] = group
        return groups

    def line_counts(group):
        counts = {}
        for region in group:
            for line in range(region[0], region[2] + (region[3] > 1)):
                counts[line] = max(counts.get(line, 0), region[4])
        return counts

    result = []; elisions = []
    records = {id(owner): owner for owner in base + head}
    for coarse in base:
        span = source_owner_span(coarse, name, base_files, old)
        if span is None or span[2] is None or old.count(span[2]) != 1 or len(coarse['regions']) != 3:
            continue
        start, end = span[:2]; count = coarse.get('count')
        if (type(count) is not int or count <= 0 or
                new != old[:start - 1] + [re.match(r'\s*', old[start - 1])[0] + '#[serial_test::serial]'] + old[start - 1:] or
                not async_test(new, start + 1) or retained.get(end) != end + 1 or
                end + 1 in after or before.get(end) != count):
            continue
        header, tail, close = (line.encode('utf-8') for line in (old[start - 1], old[end - 2], old[end - 1]))
        brace = header.index(b'{') + 1
        row = lambda line, first, last: (line, first, line, last, count, 0, 0, 0)
        tail_row = row(end - start - 1, len(tail) - len(tail.lstrip()) + 1, len(tail) + 1)
        old_shape = (row(0, header.index(b'fn ') + 1, len(header[:-1].rstrip()) + 1), tail_row,
                     row(end - start, len(close) - len(close.lstrip()) + 1, len(close) + 1))
        new_shape = (row(0, brace, brace + 1), tail_row)
        bg = project(base, base_files, old, start, end, 1, len(close) + 1, names[0])
        hg = project(head, head_files, new, start + 1, end + 1, 1, len(close) + 1, names[1])
        if bg is None or hg is None or any(
                (records[key]['regions'][0][0] - origin, records[key]['regions'][0][1]) != group[0][:2]
                for groups, origin in ((bg, start), (hg, start + 1)) for key, group in groups.items()):
            continue
        if bg.pop(id(coarse), None) != old_shape:
            continue
        candidates = [key for key, group in hg.items() if group == new_shape and records[key].get('count') == count]
        if len(candidates) != 1:
            continue
        current = candidates[0]; hg.pop(current)
        old_key, new_key = coarse['regions'][0][:2], records[current]['regions'][0][:2]
        body = [group for key, group in hg.items() if records[key]['regions'][0][:2] == new_key]
        fine = Counter(fingerprint(group) for group in bg.values())
        if (not fine or fine != Counter(fingerprint(group) for group in hg.values()) or
                any(n != 1 for n in fine.values()) or len(body) != 1 or
                any(records[key]['regions'][0][:2] == old_key for key in bg)):
            continue
        old_lines, new_lines, body_lines = line_counts(old_shape), line_counts(new_shape), line_counts(body[0])
        exclusive = set(old_lines) - {line for group in bg.values() for line in line_counts(group)}
        if (exclusive != {end - start} or not set(new_lines) <= body_lines.keys() or
                any(body_lines[line] <= 0 for line in new_lines) or
                any(end - start in line_counts(group) for group in hg.values())):
            continue
        credit = [len(old_lines), sum(value > 0 for value in old_lines.values())]
        if ((base_section['LF'] - credit[0], base_section['LH'] - credit[1]) != (head_section['LF'], head_section['LH']) or
                (len(before) - len(exclusive), sum(value > 0 for value in before.values()) - len(exclusive)) !=
                (len(after), sum(value > 0 for value in after.values()))):
            continue
        elisions.append(dict(file=name, base_range=[start, end], head_range=[start + 1, end + 1],
            summary_credit=credit, mapped_pairs=[[end, end + 1]], fine_group_sizes=sorted(map(len, bg.values())),
            old_group_key=old_key, merged_group_key=new_key))
    for coarse in base:
        span = source_owner_span(coarse, name, base_files, old)
        if (span is None or span[3] is None or old.count(span[3]) != 1 or len(coarse["regions"]) != 2
                or names[0][coarse["name"]] != 1 or not async_test(old, span[0])):
            continue
        header, body = sorted(coarse["regions"])
        last = old[body[2] - 1]
        first_code_column = len(last[:len(last) - len(last.lstrip())].encode()) + 1
        if not (header[0] == header[2] == span[0] and header[3] == header[1] + 1
                and old[header[0] - 1].encode()[header[1] - 1:header[3] - 1] == b"{"
                and body[0] > header[0] and body[4] == header[4] > 0
                and body[3] > first_code_column):
            continue
        detailed = [owner for owner in base if owner is not coarse and len(owner["regions"]) > 2
                    and names[0][owner["name"]] == 1 and header in owner["regions"]
                    and (other := source_owner_span(owner, name, base_files, old)) is not None
                    and other[:2] == span[:2]]
        if len(detailed) != 1:
            continue
        start, end = body[0], body[2]
        block = old[start - 1:end]
        locations = occurrences(new, block)
        if occurrences(old, block) != [start - 1] or len(locations) != 1:
            continue
        target = locations[0] + 1
        bg = project(base, base_files, old, start, end, body[1], body[3], names[0])
        hg = project(head, head_files, new, target, target + end - start, body[1], body[3], names[1])
        if bg is None or hg is None or id(coarse) not in bg:
            continue
        coarse_group = bg.pop(id(coarse))
        expected_coarse = tuple([0, body[1], end - start] + body[3:])
        if coarse_group != (expected_coarse,) or id(detailed[0]) not in bg:
            continue
        before_groups = Counter(fingerprint(group) for group in bg.values())
        after_groups = Counter(fingerprint(group) for group in hg.values())
        if (not before_groups or before_groups != after_groups
                or any(count != 1 for count in before_groups.values())
                or fingerprint(coarse_group) in before_groups):
            continue
        fine = [region for group in bg.values() for region in group]
        pairs = []
        for line in range(start, end + 1):
            current = target + line - start
            # LCOV obligations cover whole lines, including bytes outside a partial boundary.
            if (not owner_covers_lines([body], line, line) or retained.get(line) != current
                    or line == start and body[1] != 1
                    or line == end and body[3] != len(old[line - 1].encode()) + 1
                    or before.get(line) != body[4] or after.get(current, 0) > 0):
                continue
            offset = line - start
            precise = max((r[4] for r in fine if r[0] <= offset < r[2]
                           or offset == r[2] and r[3] > 1), default=None)
            if precise in (None, 0) and after.get(current) == precise:
                pairs.append([line, current])
        if pairs:
            result.append(dict(file=name, base_range=[start, end], head_range=[target, target + end - start],
                precise_counter_equivalence="covered/uncovered",
                precise_group_sizes=sorted(len(group) for group in before_groups), pairs=pairs))
    return result, elisions


def require_source_no_regression(base, head, base_regions, head_regions, base_sources, head_sources):
    bf, bs = region_evidence(base_regions, base, base_sources, "base")
    hf, hs = region_evidence(head_regions, head, head_sources, "head")
    if bs.keys() != hs.keys():
        raise ValueError("Added or removed coverage file requires explicit review")
    base_files = {path: canonical_source(path, base_sources) for path in base.sections}
    head_files = {path: canonical_source(path, head_sources) for path in head.sections}
    head_owners = {}; head_owners_by_file = {}
    for function in hf:
        head_owners.setdefault(function["name"], []).append(function)
        for name in {head_files[path] for path in function["filenames"] if path in head_files}:
            head_owners_by_file.setdefault(name, []).append(function)
    head_names = set(head_owners)
    base_name_counts = {}
    owners_by_file = {}
    for function in bf:
        base_name_counts[function["name"]] = base_name_counts.get(function["name"], 0) + 1
        for name in {base_files[path] for path in function["filenames"] if path in base_files}:
            owners_by_file.setdefault(name, []).append(function)
    removed = {}; deleted_mapped = deleted_hit = 0; paint_receipts = []; serial_receipts = []; serial_removed = {}
    for name in bs:
        old = base_sources[name].decode("utf-8").splitlines()
        new = head_sources[name].decode("utf-8").splitlines()
        before, after = bs[name]["counts"], hs[name]["counts"]
        if any(line > len(old) for line in before) or any(line > len(new) for line in after):
            raise ValueError("Coverage line exceeds exact source blob")
        source_owners = []
        for functions, files, source in [(owners_by_file.get(name, []), base_files, old),
                                         (head_owners_by_file.get(name, []), head_files, new)]:
            spans = {}; declarations = {}; headers = {}
            for function in functions:
                span = source_owner_span(function, name, files, source)
                if span is not None:
                    spans[id(function)] = span
                    if span[2] is not None and source.count(span[2]) == 1:
                        declarations.setdefault(span[2], []).append(function)
                    if span[3] is not None and source.count(span[3]) == 1:
                        headers.setdefault(span[3], []).append(function)
            source_owners.append((spans, declarations, headers))
        (base_spans, base_declarations, base_headers), (head_spans, head_declarations, head_headers) = source_owners
        anchored = {}; owner_spans = []; function_scopes = []
        for owner in owners_by_file.get(name, []):
            span = base_spans.get(id(owner))
            if span is None or base_name_counts[owner["name"]] != 1:
                continue
            allow_anchors = True
            matches = head_declarations.get(span[2], []) if span[2] is not None else []
            if len(base_declarations.get(span[2], [])) != 1 or len(matches) != 1:
                matches = head_owners.get(owner["name"], [])
                raw_span = head_spans.get(id(matches[0])) if len(matches) == 1 else None
                if raw_span is None or (span[3] is None) != (raw_span[3] is None):
                    matches = head_headers.get(span[3], []) if span[3] is not None else []
                    if len(base_headers.get(span[3], [])) != 1:
                        matches = []
                    # Header identity proves positive candidates, not an unchanged body.
                    allow_anchors = False
            if len(matches) != 1 or len(head_owners[matches[0]["name"]]) != 1:
                continue
            current = matches[0]
            current_span = head_spans.get(id(current))
            if current_span is None or (span[3] is None) != (current_span[3] is None):
                continue
            if span[3] is not None and (span[2] is None or current_span[2] is None):
                allow_anchors = False
            start, end = span[:2]
            newstart, newend = current_span[:2]
            owner_spans.append((start, end, newstart, newend, owner["regions"], current["regions"]))
            if (span[2] is not None and span[2] == current_span[2]
                    and len(base_declarations.get(span[2], [])) == 1
                    and len(head_declarations.get(span[2], [])) == 1):
                function_scopes.append((start, end, newstart, newend))
            if not allow_anchors:
                continue
            if old[start - 1:end] == new[newstart - 1:newend]:
                pairs = zip(range(start, end + 1), range(newstart, newend + 1))
            elif (old[end - 1].strip() == new[newend - 1].strip() == "}"
                    and any(region[2] == end and region[3] > 1 for region in owner["regions"])
                    and any(region[2] == newend and region[3] > 1 for region in current["regions"])):
                pairs = [(end, newend)]
            else:
                continue
            for oldline, newline in pairs:
                if oldline in anchored and anchored[oldline] != newline:
                    raise ValueError("Ambiguous retained function owner")
                anchored[oldline] = newline
        function_scopes = [scope for scope in function_scopes if not any(
            scope != other and (max(scope[0], other[0]) <= min(scope[1], other[1])
                                or max(scope[2], other[2]) <= min(scope[3], other[3]))
            for other in function_scopes)]
        retained = {}; gone = set()
        for tag, a, b, c, d, block, anchored_suffix in source_opcodes(old, new, function_scopes, before):
            if tag == "equal":
                if old != new and any(before.get(line, 0) > 0 for line in range(a + 1, b + 1)):
                    if not anchored_suffix and (("\n" + "\n".join(old) + "\n").count(block) != 1 or
                                                ("\n" + "\n".join(new) + "\n").count(block) != 1):
                        pending = [line for line in range(a + 1, b + 1)
                                   if line in before and line not in anchored]
                        if pending:
                            scopes = [span for span in owner_spans
                                      if span[0] <= a + 1 <= b <= span[1]
                                      and span[2] <= c + 1 <= d <= span[3]
                                      and owner_covers_lines(span[4], a + 1, b)
                                      and owner_covers_lines(span[5], c + 1, d)]
                            starts = [offset for offset in range(scopes[0][2] - 1, scopes[0][3] - (b - a) + 1)
                                      if new[offset:offset + b - a] == old[a:b]] if len(scopes) == 1 else []
                            if (c not in starts or any(not owner_covers_lines(scopes[0][5], offset + 1, offset + b - a)
                                                     for offset in starts)
                                    or any(after.get(offset + line - a, 0) <= 0
                                           for offset in starts for line in pending)):
                                raise ValueError(
                                    f"Ambiguous unchanged source correspondence: {name}:{a + 1}-{b} -> {c + 1}-{d}")
                            retained.update((line, c + line - a) for line in pending)
                        # Repeated text is retained only through its proven function owner.
                        continue
                retained.update(zip(range(a + 1, b + 1), range(c + 1, d + 1)))
            elif tag == "delete":
                gone.update(range(a + 1, b + 1))
            # Replacement is not proven deletion. Its old counts stay in the
            # strict base ratios, and its new uncovered mappings are refused.
        gone.difference_update(anchored)
        anchored_new = set(anchored.values())
        paint = []
        final_pairs = {**retained, **anchored}
        if any(before.get(a, 0) > 0 and after.get(b, 0) == 0 for a, b in final_pairs.items()):
            paint, elisions = retained_wrapper_paint(name, old, new, before, after, bf, hf, base_files, head_files,
                                                     final_pairs, bs[name], hs[name])
            for witness in elisions:
                for oldline, newline in witness['mapped_pairs']:
                    retained.pop(oldline, None); anchored.pop(oldline, None)
                    serial_removed.setdefault(name, set()).add(oldline)
                    deleted_mapped += 1; deleted_hit += 1
            serial_receipts.extend(elisions)
        painted = {(a, b) for witness in paint for a, b in witness["pairs"]}
        paint_receipts.extend(paint)
        for oldline, newline in list(retained.items()):
            if oldline in anchored:
                continue
            displaced = newline in anchored_new
            lost = before.get(oldline, 0) > 0 and newline not in after and (oldline, newline) not in painted
            if displaced or lost:
                if old[oldline - 1].strip() == "}" and oldline - 1 in gone:
                    owners = [function for function in owners_by_file.get(name, []) if any(
                        base_files.get(function["filenames"][region[5]]) == name
                        and region[0] <= oldline <= region[2]
                        for region in function["regions"])]
                    if len(owners) == 1:
                        owner = owners[0]
                        if (base_name_counts[owner["name"]] == 1 and owner["name"] not in head_names
                                and len(owner["filenames"]) == 1 and all(
                                    len(region) == 8 and region[0] <= region[2]
                                    and (region[0] == region[2] or region[3] > 1)
                                    and region[5:] == [0, 0, 0]
                                    and type(region[4]) is int and region[4] >= 0
                                    and all(line in before and (line == oldline or line in gone)
                                            for line in range(region[0], region[2] + 1))
                                    for region in owner["regions"])):
                            gone.add(oldline)
                            del retained[oldline]
                            continue
                raise ValueError("Retained covered line lost coverage or mapping")
        retained.update(anchored)
        if len(set(retained.values())) != len(retained):
            raise ValueError("Ambiguous retained source correspondence")
        for oldline, newline in retained.items():
            if before.get(oldline, 0) > 0 and after.get(newline, 0) == 0 and (oldline, newline) not in painted:
                raise ValueError("Retained covered line lost coverage or mapping")
        retained_new = set(retained.values())
        uncovered = next((line for line, count in after.items()
                          if count == 0 and line not in retained_new), None)
        if uncovered is not None:
            raise ValueError(f"New uncovered instrumented line: {name}:{uncovered}")
        removed[name] = gone
        deleted_mapped += sum(line in gone for line in before)
        deleted_hit += sum(line in gone and count > 0 for line, count in before.items())
    paint_receipt = {"retained_wrapper_paint": paint_receipts} if paint_receipts else {}
    if serial_receipts:
        paint_receipt['serial_wrapper_elision'] = serial_receipts
    if (not serial_receipts and head.hit * base.found >= base.hit * head.found and
            head.mapped_hit * base.mapped >= base.mapped_hit * head.mapped):
        require_no_regression(base, head)
        return {"deleted_summary_found": 0, "deleted_summary_hit": 0,
                "deleted_mapped": 0, "deleted_mapped_hit": 0, **paint_receipt}
    deleted_found = sum(row['summary_credit'][0] for row in serial_receipts)
    deleted_summary_hit = sum(row['summary_credit'][1] for row in serial_receipts)
    accounted = {name: set() for name in bs}
    deleted_summaries = {name: [0, 0] for name in bs}
    for row in serial_receipts:
        deleted_summaries[row['file']] = row['summary_credit'].copy()
    deleted_geometries = set()
    for function in bf:
        regions = function["regions"]; filenames = function["filenames"]
        touched = []
        for region in regions:
            if filenames[region[5]] not in base.sections:
                # LLVM JSON includes functions excluded from its file/LCOV surface.
                # They cannot authorize any subtraction from selected file summaries.
                continue
            name = base_files[filenames[region[5]]]
            if any(line in removed.get(name, set()) for line in range(region[0], region[2] + 1)):
                touched.append(region)
        if not touched:
            continue
        if base_name_counts[function["name"]] != 1 or function["name"] in head_names or len(filenames) != 1 or len(touched) != len(regions):
            raise ValueError("Deleted region has retained or ambiguous function owner")
        name = base_files[filenames[0]]; counts = {}
        geometry = (name, tuple(sorted(tuple(region[:4] + region[5:]) for region in regions)))
        if geometry in deleted_geometries:
            raise ValueError("Duplicate deleted region owner geometry")
        deleted_geometries.add(geometry)
        for region in regions:
            if (len(region) != 8 or region[0] > region[2]
                    or (region[0] != region[2] and region[3] <= 1)
                    or region[5:] != [0, 0, 0]
                    or any(line not in removed[name] or line not in bs[name]["counts"]
                           for line in range(region[0], region[2] + 1))):
                raise ValueError("Unsupported deleted region attribution")
            if type(region[4]) is not int or region[4] < 0:
                raise ValueError("Invalid region count")
            for line in range(region[0], region[2] + 1):
                counts[line] = max(counts.get(line, 0), region[4])
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
            kept = {line: count for line, count in before["counts"].items()
                    if line not in removed[name] and line not in serial_removed.get(name, set())}
            if (len(after["counts"]), sum(count > 0 for count in after["counts"].values())) != (len(kept), sum(count > 0 for count in kept.values())):
                raise ValueError("Unexplained same-file mapped movement during deletion")
    normalized = Coverage(base.files, base.found - deleted_found, base.hit - deleted_summary_hit,
                          base.mapped - deleted_mapped, base.mapped_hit - deleted_hit, base.sha256)
    if min(normalized.found, normalized.mapped) <= 0:
        raise ValueError("Deletion leaves no comparable coverage")
    require_no_regression(normalized, head)
    return {"deleted_summary_found": deleted_found, "deleted_summary_hit": deleted_summary_hit,
            "deleted_mapped": deleted_mapped, "deleted_mapped_hit": deleted_hit, **paint_receipt}


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
    base = read_coverage(args.base, "base")
    head = read_coverage(args.head, "head")
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

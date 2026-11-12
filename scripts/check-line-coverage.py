#!/usr/bin/env python3
"""Require complete LCOV line coverage to meet the exact base report."""
import argparse
import ast
import bisect
from collections import Counter
from dataclasses import asdict, dataclass, fields, is_dataclass
import hashlib
import json
import difflib
import gzip
import subprocess
import sys
import tempfile
from pathlib import Path
import re
import shutil
from functools import lru_cache

COUNTER_LIMIT = 2**63 - 1
MAX_DIAGNOSTIC_BYTES = 64 * 1024 * 1024


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


def _read_region_document(path):
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
    return value["data"][0]


def region_evidence(path, coverage, sources, side=None):
    data = _read_region_document(path); files = {}; mappings = {}
    for item in data["files"]:
        name = canonical_source(item["filename"], sources)
        if name in files:
            raise ValueError("Duplicate region source")
        files[name] = item["summary"]["lines"]
        mappings[name] = item
    sections = {canonical_source(name, sources): dict(item) for name, item in coverage.sections.items()}
    if len(sections) != len(coverage.sections) or files.keys() != sections.keys():
        raise ValueError("Region/LCOV source set mismatch")
    for name, item in sections.items():
        if (files[name]["count"], files[name]["covered"]) != (item["LF"], item["LH"]):
            raise ValueError("Region/LCOV summary mismatch")
        item["segments"] = mappings[name].get("segments")
        item["expansions"] = mappings[name].get("expansions")
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


@dataclass(frozen=True)
class ObservedOwner:
    name: str
    count: int
    regions: tuple
    rows: tuple


@dataclass(frozen=True)
class ObservedFile:
    filename: str
    source_sha256: str
    inventory_sha256: str
    owners: tuple
    groups: tuple
    segments: tuple
    rows: tuple
    summary: tuple


class _ObserverWork:
    def __init__(self):
        self.remaining = 20_000_000

    def spend(self, units=1):
        self.remaining -= units
        if self.remaining < 0:
            raise ValueError('LLVM observer work bound exceeded')


def _llvm22_segments(regions, work):
    ordered = sorted((tuple(r[:2]), tuple(r[2:4]), r[4]) for r in regions)
    ordered.sort(key=lambda r: (r[0], -r[1][0], -r[1][1]))
    combined = []
    for region in ordered:
        work.spend()
        if combined and combined[-1][:2] == region[:2]:
            count = combined[-1][2] + region[2]
            if count >= COUNTER_LIMIT:
                raise ValueError('LLVM observer merged counter is saturated')
            combined[-1] = (region[0], region[1], count)
        else:
            combined.append(region)
    result = []; active = []

    def start(region, location, entry, skip=False):
        count, has_count = (0, False) if skip else (region[2], True)
        if (result and not entry and not skip and result[-1][3] == has_count
                and result[-1][2] == count and not result[-1][4]):
            return
        work.spend()
        result.append((location[0], location[1], count, has_count, entry, False))

    def complete(location, first):
        nonlocal active
        active[first:] = sorted(active[first:], key=lambda r: r[1])
        size = len(active)
        for index in range(first + 1, size):
            work.spend()
            previous, current = active[index - 1], active[index]
            at = previous[1]
            if location is not None and at == location:
                break
            if at == current[1]:
                continue
            for other in range(index + 1, size):
                work.spend()
                if current[1] == active[other][1]:
                    current = active[other]
            start(current, at, False)
        last = active[-1]
        if first and last[1] != location:
            start(active[first - 1], last[1], False)
        elif not first and (location is None or location != last[1]):
            start(last, last[1], False, True)
        active = active[:first]

    for index, region in enumerate(combined):
        work.spend(len(active) + 1)
        kept = [r for r in active if r[1] > region[0]]
        done = [r for r in active if r[1] <= region[0]]
        active = kept + done
        if done:
            complete(region[0], len(kept))
        if region[0] == region[1]:
            skipped = index + 1 == len(combined)
            start(active[-1] if active else region, region[0], True, skipped)
            if skipped and active:
                start(active[-1], region[0], False)
            continue
        if index + 1 == len(combined) or region[0] != combined[index + 1][0]:
            start(region, region[0], True)
        active.append(region)
    if active:
        complete(None, 0)
    return tuple(result)


def _llvm22_rows(segments, work):
    by_line = {}
    for segment in segments:
        by_line.setdefault(segment[0], []).append(segment)
    result = []; wrapped = None
    for line in range(1, max(by_line, default=0) + 1):
        current = by_line.get(line, ())
        work.spend(len(current) + 1)
        entries = [s for s in current if s[3] and s[4] and not s[5]]
        skipped = bool(current and not current[0][3] and current[0][4])
        mapped = ((not skipped and ((wrapped is not None and wrapped[3]) or entries))
                  or any(s[3] and s[4] for s in current))
        if mapped:
            result.append((line, max([wrapped[2] if wrapped else 0] + [s[2] for s in entries])))
        if current:
            wrapped = current[-1]
    return tuple(result)


def observe_llvm22_file(filename, source, functions, record, lcov):
    """Reconcile the bounded LLVM 22 kind-0 observer model, without source credit.

    The model follows rust-lang/llvm-project at
    1cb4e3833c1919c2e6fb579a23ac0e2b22587b7e. Its immutable result preserves
    every compiled copy. It does not establish retention, folding or deletion.
    """
    def require(condition, message):
        if not condition:
            raise ValueError('LLVM observer ' + message)

    require(type(source) is bytes and len(source) <= 1024 * 1024, 'source exceeds byte bound')
    try:
        text = source.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValueError('LLVM observer source is not UTF-8') from error
    require('\r' not in text, 'source must retain raw LF identity')
    lines = text.split('\n')
    require(len(lines) <= 65_536, 'source exceeds line bound')
    boundaries = []
    for line in lines:
        offset = 1; positions = {1}
        for character in line:
            offset += len(character.encode('utf-8')); positions.add(offset)
        boundaries.append(positions)

    def position(line, column):
        return (type(line) is int and type(column) is int and 1 <= line <= len(lines)
                and column in boundaries[line - 1])

    def counter(value):
        return type(value) is int and 0 <= value < COUNTER_LIMIT

    require(type(filename) is str and filename.startswith('/') and '\\' not in filename
            and '..' not in filename.split('/'), 'raw filename is invalid')
    require(type(record) is dict and record.get('filename') == filename, 'file identity mismatch')
    require(all(record.get(key) == [] for key in ('branches', 'mcdc_records', 'expansions')),
            'unsupported file schema')
    require(type(functions) is list and len(functions) <= 100_000, 'function inventory exceeds bound')
    selected = []; names = set(); region_total = 0
    for owner in functions:
        require(type(owner) is dict and type(owner.get('filenames')) is list
                and owner['filenames'] and all(type(path) is str for path in owner['filenames']),
                'invalid function filename inventory')
        if filename not in owner['filenames']:
            continue
        require(owner['filenames'] == [filename], 'unsupported cross-file owner')
        require(type(owner.get('name')) is str and owner['name'] and owner['name'] not in names,
                'duplicate or missing owner inventory identity')
        names.add(owner['name'])
        require(counter(owner.get('count')), 'invalid owner inventory counter')
        require(owner.get('branches') == [] and owner.get('mcdc_records') == [],
                'unsupported owner schema')
        regions = owner.get('regions')
        require(type(regions) is list and regions, 'empty owner inventory')
        region_total += len(regions)
        require(region_total <= 50_000, 'region inventory exceeds bound')
        for region in regions:
            require(type(region) is list and len(region) == 8
                    and all(type(value) is int for value in region), 'invalid region schema')
            require(position(region[0], region[1]) and position(region[2], region[3]),
                    'region source byte boundary mismatch')
            require(tuple(region[:2]) <= tuple(region[2:4]), 'reversed region geometry')
            require(counter(region[4]), 'invalid or saturated region counter')
            require(region[5:] == [0, 0, 0], 'unsupported region kind or filename relationship')
        selected.append(owner)
    require(selected, 'missing selected owner inventory')
    raw_segments = record.get('segments')
    require(type(raw_segments) is list and len(raw_segments) <= 100_000, 'segment inventory exceeds bound')
    for segment in raw_segments:
        require(type(segment) is list and len(segment) == 6
                and position(segment[0], segment[1]) and counter(segment[2])
                and all(type(flag) is bool for flag in segment[3:]), 'invalid segment schema')
    require(type(lcov) is dict and type(lcov.get('counts')) is dict, 'missing LCOV inventory')
    require(all(type(line) is int and 1 <= line <= len(lines) and counter(count)
                for line, count in lcov['counts'].items()), 'invalid LCOV row inventory')
    work = _ObserverWork(); owners = []; grouped = {}
    for owner in selected:
        rows = _llvm22_rows(_llvm22_segments(owner['regions'], work), work)
        owners.append(ObservedOwner(owner['name'], owner['count'],
                                    tuple(tuple(row) for row in owner['regions']), rows))
        grouped.setdefault(tuple(owner['regions'][0][:2]), []).append(len(owners) - 1)
    groups = tuple((key, tuple(indices)) for key, indices in sorted(grouped.items()))
    summaries = {
        'lines': tuple(sum(max((len(owners[i].rows), sum(count > 0 for _, count in owners[i].rows))[metric]
                                  for i in indices) for _, indices in groups) for metric in (0, 1)),
        'regions': tuple(sum(max((len(owners[i].regions), sum(row[4] > 0 for row in owners[i].regions))[metric]
                                    for i in indices) for _, indices in groups) for metric in (0, 1)),
        'functions': (len(groups), sum(any(owners[i].count > 0 for i in indices) for _, indices in groups)),
        'instantiations': (len(owners), sum(owner.count > 0 for owner in owners)),
    }
    require(type(record.get('summary')) is dict, 'missing summary inventory')
    for kind, expected in summaries.items():
        summary = record['summary'].get(kind, {})
        require(type(summary) is dict, f'invalid {kind} summary inventory')
        pair = (summary.get('count'), summary.get('covered'))
        require(all(counter(value) for value in pair) and pair == expected,
                f'{kind} summary reconciliation failed')
    require(counter(lcov.get('LF')) and counter(lcov.get('LH'))
            and (lcov['LF'], lcov['LH']) == summaries['lines'], 'LCOV summary reconciliation failed')
    segments = _llvm22_segments([row for owner in selected for row in owner['regions']], work)
    require(tuple(tuple(row) for row in raw_segments) == segments, 'complete segment reconciliation failed')
    rows = _llvm22_rows(segments, work)
    require(tuple(sorted(lcov['counts'].items())) == rows, 'every DA count reconciliation failed')
    digest = hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return ObservedFile(filename, hashlib.sha256(source).hexdigest(), digest, tuple(owners), groups,
                        segments, rows, summaries['lines'])


@dataclass(frozen=True)
class ObserverProjection:
    removed_groups: tuple
    removed_owners: tuple
    summary: tuple
    rows: tuple


def project_observer_groups(observed, removed_groups, *, _work=None):
    """Reconstruct a whole-group omission; this is not a source deletion proof."""
    if (not isinstance(observed, ObservedFile) or type(removed_groups) not in (tuple, list)
            or any(type(key) is not tuple or len(key) != 2
                   or any(type(value) is not int for value in key) for key in removed_groups)):
        raise ValueError('Projection requires exact whole observer group keys')
    selected = set(removed_groups)
    inventory = {key for key, _ in observed.groups}
    if len(selected) != len(removed_groups) or selected - inventory:
        raise ValueError('Projection requires unique existing whole observer group keys')
    removed = {index for key, indices in observed.groups if key in selected for index in indices}
    kept = [(key, indices) for key, indices in observed.groups if key not in selected]
    summary = tuple(sum(max((len(observed.owners[i].rows),
                             sum(count > 0 for _, count in observed.owners[i].rows))[metric]
                            for i in indices) for _, indices in kept) for metric in (0, 1))
    work = _ObserverWork() if _work is None else _work
    if not isinstance(work, _ObserverWork):
        raise ValueError('Projection requires a bounded observer work owner')
    segments = _llvm22_segments([row for index, owner in enumerate(observed.owners)
                                if index not in removed for row in owner.regions], work)
    return ObserverProjection(tuple(sorted(selected)),
                              tuple(owner.name for index, owner in enumerate(observed.owners)
                                    if index in removed), summary, _llvm22_rows(segments, work))


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


def require_rustfmt_syntax(excerpts):
    if any(len(source) > 64 * 1024 for source in excerpts):
        raise ValueError("Positive source correspondence exceeds 64 KiB syntax parser bound")
    with tempfile.TemporaryDirectory(prefix="omg-coverage-rustfmt-") as directory:
        root = Path(directory); work = root / "work"; work.mkdir()
        config = root / "rustfmt.toml"
        config.write_text('edition = "2024"\n', encoding="utf-8")
        try:
            resolved = subprocess.run(["rustup", "which", "--toolchain", "1.95.0", "rustfmt"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, cwd=work, timeout=10)
        except subprocess.TimeoutExpired as error:
            raise ValueError("Positive source correspondence rustfmt 1.95.0 lookup timed out") from error
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError("Positive source correspondence requires installed rustfmt 1.95.0") from error
        binary = Path(resolved.stdout.strip())
        if not binary.is_absolute() or not binary.is_file():
            raise ValueError("Positive source correspondence requires an absolute installed rustfmt 1.95.0 binary")
        for source in dict.fromkeys(excerpts):
            try:
                parsed = subprocess.run([str(binary), "--edition", "2024", "--emit", "stdout",
                    "--config-path", str(config)], input=source, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, cwd=work, timeout=10)
            except subprocess.TimeoutExpired as error:
                raise ValueError("Positive source correspondence rustfmt 1.95.0 syntax check timed out") from error
            except OSError as error:
                raise ValueError("Positive source correspondence could not execute rustfmt 1.95.0") from error
            if parsed.returncode != 0:
                raise ValueError("Ambiguous unchanged source correspondence: rustfmt 1.95.0 did not validate source syntax")


def _source_structural_map(source):
    """Find lexical brace pairs and names while ignoring comments and literals."""
    text = "\n".join(source)
    raw_literal = re.compile(r'(?:br|cr|r)(#*)"')
    character = re.compile(r"'(?:[^\\'\n]|\\(?:[\\'\"nrt0]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}))'")
    lifetime_name = re.compile(r"'[A-Za-z_]\w*")
    identifier = re.compile(r"(?:r#)?([A-Za-z_]\w*)")
    braces = {}; stack = []; names = Counter(); modules = []; previous = None; at = 0
    code = bytearray(len(text))
    while at < len(text):
        if text[at].isspace():
            at += 1
            continue
        if text.startswith("//", at):
            end = text.find("\n", at)
            at = len(text) if end < 0 else end + 1
            continue
        if text.startswith("/*", at):
            depth = 1; at += 2
            while depth and at < len(text):
                if text.startswith("/*", at):
                    depth += 1; at += 2
                elif text.startswith("*/", at):
                    depth -= 1; at += 2
                else:
                    at += 1
            if depth:
                return {}
            continue
        raw = raw_literal.match(text, at)
        if raw:
            ending = '"' + raw[1]
            end = text.find(ending, at + len(raw[0]))
            if end < 0:
                return {}
            at = end + len(ending); previous = None
            continue
        if text[at] == '"':
            at += 1
            while at < len(text) and text[at] != '"':
                at += 2 if text[at] == "\\" else 1
            if at >= len(text):
                return {}
            at += 1; previous = None
            continue
        if text[at] == "'":
            char = character.match(text, at)
            lifetime = lifetime_name.match(text, at)
            token = char or lifetime
            if token is None:
                return {}
            at += len(token[0]); previous = None
            continue
        word = identifier.match(text, at)
        if word:
            if previous == "fn":
                names[word[1]] += 1
            if word[1] == "mod":
                modules.append(at)
            previous = word[1]; at += len(word[0])
            continue
        code[at] = 1
        if text[at] in "([{":
            stack.append((text[at], at))
        elif text[at] in ")]}":
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[text[at]]:
                return {}
            _, opening = stack.pop()
            if text[at] == "}":
                braces[opening] = at
        previous = text[at]; at += 1
    if stack:
        return {}
    offsets = [0]
    for line in source:
        offsets.append(offsets[-1] + len(line) + 1)
    return braces, names, modules, offsets, code


def source_function_prefixes(source, spans):
    """Recognize bounded signatures and their actual lexical body boundaries."""
    structure = _source_structural_map(source)
    if not structure:
        return {}
    braces, names, modules, offsets, _ = structure
    result = {}
    for start, end in spans:
        body = "\n".join(source[start - 1:end])
        header = re.match(
            r"([ \t]*(?:(?:pub(?:\([^()]*\))?|async|unsafe|const)\s+)*fn\s+([A-Za-z_]\w*)\s*"
            r"\([^(){}]*\))\s*(?:->\s*[^{}]+?)?\{", body[:4097])
        if (header is None or len(header[0]) > 4096 or names[header[2]] != 1
                or any(offsets[start - 1] <= position < offsets[end] for position in modules)
                or re.search(r"\bwhere\b", header[0])
                or source[end - 1].strip() != "}"
                or braces.get(offsets[start - 1] + len(header[0]) - 1) !=
                offsets[start - 1] + len(body.rstrip()) - 1):
            continue
        result[start, end] = header[1]
    return result


def transparent_forwarder_groups(old, new, groups, fragments):
    """Recognize one structurally forwarded extraction without inferring runtime roles."""
    inventories = []
    for source, owners in zip((old, new), groups):
        code = _boolean_source(source)
        if code is None or 'no_implicit_prelude' in code.words:
            return {}
        root = [i for i in range(len(code.words)) if code.parents[i] is None]
        if any(code.words[i] in ('!', 'None') for i in root):
            return {}
        boundaries = [i for i, word in enumerate(code.words)
                      if word == ';' and code.parents[i] is None
                      or word == '}' and code.parents[code.pairs[i]] is None]
        for i in root:
            if code.words[i] == 'use':
                ending = next((j for j in boundaries if j > i and code.words[j] == ';'), None)
                if ending is None or any(word in ('*', 'None') for word in code.words[i:ending]):
                    return {}
        functions = {}
        names = Counter(code.words[i + 1] for i, word in enumerate(code.words[:-1]) if word == 'fn')
        by_line = {}
        for i in root:
            if code.words[i] == 'fn':
                by_line.setdefault(code.position(code.starts[i])[0], []).append(i)
        openings = [i for i in root if code.words[i] == '{']
        for prefix, group in owners.items():
            candidates = by_line.get(group[0], [])
            if len(candidates) != 1:
                continue
            declaration = candidates[0]
            previous = bisect.bisect_left(boundaries, declaration) - 1
            first = boundaries[previous] + 1 if previous >= 0 else 0
            visibility = code.words[first:declaration]
            if visibility not in ([], ['pub'], ['pub', '(', 'crate', ')']):
                continue
            args = declaration + 2
            if args >= len(code.words) or code.words[args] != '(':
                continue
            end_args = code.pairs[args]
            at = bisect.bisect_right(openings, end_args)
            if at == len(openings):
                continue
            opening = openings[at]
            closing = code.pairs[opening]
            if code.position(code.starts[closing])[0] != group[1]:
                continue
            parameters = []; chunk = []
            for word in code.words[args + 1:end_args] + [',']:
                if word == ',':
                    if chunk:
                        parameters.append(tuple(chunk))
                    chunk = []
                else:
                    chunk.append(word)
            if (any(len(row) < 3 or row[1] != ':' or not re.fullmatch(r'[A-Za-z_]\w*', row[0])
                    for row in parameters) or len({row[0] for row in parameters}) != len(parameters)):
                continue
            functions[prefix] = dict(name=code.words[declaration + 1], parameters=parameters,
                returns=code.words[end_args + 1:opening], body=code.words[opening + 1:closing],
                signature=code.words[first:opening], group=group)
        inventories.append((functions, names))
    base, base_names = inventories[0]; head, _ = inventories[1]
    by_name = {value['name']: (prefix, value) for prefix, value in head.items()}
    proposals = {}
    for prefix, origin in base.items():
        wrapper = head.get(prefix)
        if wrapper is None or origin['returns'] != wrapper['returns']:
            continue
        body = wrapper['body']
        if len(body) < 3 or body[1] != '(' or body[-1] != ')' or body[0] not in by_name:
            continue
        _, callee = by_name[body[0]]
        if (base_names[callee['name']] or callee['name'] in {row[0] for row in origin['parameters']}
                or callee['returns'] != origin['returns']
                or callee['parameters'][:len(origin['parameters'])] != origin['parameters']):
            continue
        arguments = []; chunk = []
        for word in body[2:-1] + [',']:
            if word == ',':
                if chunk:
                    arguments.append(chunk)
                chunk = []
            else:
                chunk.append(word)
        count = len(origin['parameters'])
        if (len(arguments) != len(callee['parameters'])
                or arguments[:count] != [[row[0]] for row in origin['parameters']]
                or any(arg not in (['None'], ['&', '[', ']']) for arg in arguments[count:])):
            continue
        proposals[prefix] = wrapper, callee, arguments
    claims = Counter(value[1]['name'] for value in proposals.values())
    result = {}
    for prefix, (wrapper, callee, arguments) in proposals.items():
        origin = base[prefix]['group']; target = callee['group']
        selected = [row for row in fragments if max(row[0] + 1, origin[0]) <= min(row[1], origin[1])]
        if (claims[callee['name']] != 1 or not selected
                or any(not (origin[0] <= a + 1 <= b <= origin[1]
                            and target[0] <= c + 1 <= d <= target[1]) for a, b, c, d, _ in selected)):
            continue
        proof = dict(wrapper_range=list(wrapper['group'][:2]), callee_range=list(target[:2]),
            wrapper_signature_sha256=hashlib.sha256(' '.join(wrapper['signature']).encode()).hexdigest(),
            callee_signature_sha256=hashlib.sha256(' '.join(callee['signature']).encode()).hexdigest(),
            forwarded_arguments=arguments, limitation='Structural forwarding only; no runtime-role inference')
        result[prefix] = target, proof
    return result


def compiled_hit_state_matching(before, after):
    """Assign each complete base hit vector to a distinct dominating head vector."""
    before, after = sorted(map(tuple, before)), sorted(map(tuple, after))
    if len(before) != len(after):
        return None
    if before == after:
        return list(range(len(before)))
    width = max((len(row) for row in before), default=0)
    if len(before) * len(after) * max(width, 1) > 2**20:
        return None
    edges = [[index for index, candidate in enumerate(after)
              if len(row) == len(candidate) and all(a <= b for a, b in zip(row, candidate))]
             for row in before]
    owners = [None] * len(after)
    work = 0
    for start in range(len(before)):
        pending, visited, previous = [start], {start}, {}
        found = False
        for row in pending:
            for target in edges[row]:
                work += 1
                if work > 2**20:
                    return None
                owner = owners[target]
                if owner is None:
                    while True:
                        owners[target] = row
                        if row == start:
                            break
                        row, target = previous[row]
                    found = True
                    break
                if owner not in visited:
                    visited.add(owner)
                    previous[owner] = row, target
                    pending.append(owner)
            if found:
                break
        if not found:
            return None
    matching = [None] * len(before)
    for target, row in enumerate(owners):
        matching[row] = target
    return matching


def plain_rust_function_symbol(symbol):
    """Recognize only complete ASCII v0 free-function paths without instantiating suffixes."""
    if type(symbol) is not str or len(symbol) > 4096:
        return None
    prefix = re.match(r'_RNv((?:Nt){0,16})C(?:s[0-9A-Za-z]{0,32}_)?', symbol)
    if prefix is None:
        return None
    modules = len(prefix[1]) // 2
    at = prefix.end(); identifiers = []
    for _ in range(modules + 2):
        length = re.match(r'[1-9][0-9]{0,3}', symbol[at:])
        if length is None:
            return None
        size = int(length[0]); at += len(length[0])
        if size > 1024:
            return None
        if symbol[at:at + 1] == '_':
            at += 1
        value = symbol[at:at + size]
        if len(value) != size or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value) is None:
            return None
        identifiers.append(value); at += size
    if at != len(symbol):
        return None
    return modules, identifiers


def direct_rust_callback_symbol(child, parent, modules):
    if type(child) is not str or len(child) > 4096:
        return False
    # v0 NC + Nv + Nt* places the crate at offset 4 + 2*modules after _R; base62 encodes offset-1.
    # https://doc.rust-lang.org/stable/rustc/symbol-mangling/v0.html#backref
    backref = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'[3 + 2 * modules]
    return re.fullmatch(re.escape('_RNC' + parent[2:])
                        + r'(?:s[0-9A-Za-z]{0,32}_)?0(?:B' + backref + r'_)?', child) is not None


@lru_cache(maxsize=64)
def demangle_plain_rust_callbacks(symbols):
    if (len(symbols) > 256 or len(set(symbols)) != len(symbols)
            or any(type(symbol) is not str or len(symbol) > 4096 for symbol in symbols)):
        raise ValueError('Unsupported callback symbol inventory')
    if sum(len(symbol) + 1 for symbol in symbols) > 64 * 1024:
        raise ValueError('Nested callback symbol inventory exceeds bound')
    parents = {symbol: plain_rust_function_symbol(symbol) for symbol in symbols}
    parents = {symbol: shape for symbol, shape in parents.items() if shape is not None}
    if not parents or any(symbol not in parents and sum(
            direct_rust_callback_symbol(symbol, parent, shape[0])
            for parent, shape in parents.items()) != 1 for symbol in symbols):
        raise ValueError('Unsupported raw Rust callback context')
    payload = ('\n'.join(symbols) + '\n').encode('ascii')
    if len(payload) > 64 * 1024:
        raise ValueError('Nested callback symbol inventory exceeds bound')
    executable = shutil.which('c++filt')
    if executable is None:
        raise ValueError('Nested callback ownership requires GNU c++filt with Rust support')
    executable = str(Path(executable).resolve())
    try:
        version = subprocess.run([executable, '--version'], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5, check=True).stdout
        result = subprocess.run([executable, '--format=rust', '--no-strip-underscore'],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('GNU Rust callback symbol decoding failed') from error
    if (len(result.stdout) > 256 * 1024 or len(version) > 4096
            or not version.startswith(b'GNU c++filt')):
        raise ValueError('Unsupported GNU callback symbol decoder output')
    try:
        decoded = result.stdout.decode('ascii').splitlines()
    except UnicodeDecodeError as error:
        raise ValueError('Unsupported non-ASCII callback identity') from error
    if len(decoded) != len(symbols) or any(raw == value for raw, value in zip(symbols, decoded)):
        raise ValueError('Unparsed Rust callback symbol inventory')
    return dict(zip(symbols, decoded)), dict(program=executable,
        program_sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        version=version.decode('ascii').splitlines()[0])


def nested_map_err_states(source, group, inventory, name_counts, first, last, code):
    """Prove direct callback ownership and construction syntax, not capture values or runtime roles."""
    if code is None:
        return None
    calls = []
    for i, word in enumerate(code.words):
        if (word != 'map_err' or i == 0 or code.words[i - 1] != '.'
                or i + 1 >= len(code.words) or code.words[i + 1] != '('):
            continue
        opening = i + 1; closing = code.pairs[opening]
        body = code.words[opening + 1:closing]
        if (len(body) != 13 or body[0] != '|' or body[2] != '|'
                or body[4:6] != ['(', '&'] or body[7:11] != [')', '.', 'unwrap_or', '(']
                or body[11] != body[1] or body[12] != ')'
                or any(re.fullmatch(r'[A-Za-z_]\w*', body[n]) is None for n in (1, 3, 6))):
            continue
        start = code.position(code.starts[opening + 1])[0]
        end = code.position(code.ends[closing - 1])[0]
        if first <= start <= end <= last:
            calls.append((i, opening, closing, body))
    if len(calls) != 1:
        return None
    call, opening, closing, body = calls[0]
    parameter, function, capture = body[1], body[3], body[6]
    block = code.parents[call]
    if block is None or code.words[block] != '{' or parameter == capture:
        return None
    roots = [i for i, word in enumerate(code.words) if word == 'fn'
             and i + 1 < len(code.words) and code.words[i + 1] == function]
    if len(roots) != 1 or code.parents[roots[0]] is not None:
        return None
    boundaries = [i for i, word in enumerate(code.words)
                  if word == ';' and code.parents[i] is None
                  or word == '}' and code.parents[code.pairs[i]] is None]
    previous = bisect.bisect_left(boundaries, roots[0]) - 1
    declaration = boundaries[previous] + 1 if previous >= 0 else 0
    if code.words[declaration:roots[0]] not in ([], ['pub'], ['pub', '(', 'crate', ')']):
        return None
    owners = [i for i, word in enumerate(code.words) if word == 'fn'
              and code.parents[i] is None and code.position(code.starts[i])[0] == group[0]]
    if len(owners) != 1:
        return None
    previous = bisect.bisect_left(boundaries, owners[0]) - 1
    declaration = boundaries[previous] + 1 if previous >= 0 else 0
    if code.words[declaration:owners[0]] not in ([], ['pub'], ['pub', '(', 'crate', ')']):
        return None
    for i, word in enumerate(code.words):
        if word == 'use' and code.parents[i] is None:
            ending = next((j for j in boundaries if j > i and code.words[j] == ';'), None)
            if ending is None or any(word in ('*', function) for word in code.words[i:ending]):
                return None
    begin = next((i for i, offset in enumerate(code.starts)
                  if code.position(offset)[0] >= group[0]), len(code.words))
    end = bisect.bisect_left(code.starts, code.offsets[group[1]] if group[1] < len(code.offsets)
                            else len(code.text))
    scopes = set(code.ancestors(call))
    items = {'use', 'const', 'static', 'fn', 'mod', 'struct', 'enum', 'type', 'trait', 'impl', 'extern'}
    if any(code.words[i] in items and code.parents[i] in scopes for i in range(begin, end)):
        return None
    for i in range(begin, end):
        if code.parents[i] not in scopes:
            continue
        if code.words[i] in ('#', 'macro_rules'):
            return None
        if (code.words[i] != '!' or i == 0 or i + 1 >= end
                or code.words[i + 1] not in ('(', '[', '{')
                or re.fullmatch(r'[A-Za-z_]\w*', code.words[i - 1]) is None):
            continue
        start = i - 1
        if (code.words[start] in ('if', 'while', 'match', 'return', 'break', 'else', 'let')
                and code.text[code.starts[start]:code.ends[start]] == code.words[start]):
            continue
        while start >= 2 and code.words[start - 1] == '::':
            start -= 2
        # Only these expression positions prevent an expansion from introducing
        # bindings/items in the caller's scope. Statement macros stay opaque.
        if start == 0 or code.words[start - 1] not in ('=', 'if'):
            return None
    if any(word == function and (i + 1 >= len(code.words) or code.words[i + 1] != '(')
           for i, word in enumerate(code.words[begin:end], begin)):
        return None
    markers = [i for i in range(block + 1, code.pairs[block])
               if code.parents[i] == block and code.words[i] in ('=', ';')]
    semicolons = [i for i in markers if code.words[i] == ';']
    capture_positions = [i for i, word in enumerate(code.words) if word == capture]
    bindings = []
    for i, word in enumerate(code.words):
        if word != 'let' or code.parents[i] != block:
            continue
        at = bisect.bisect_right(markers, i)
        if at == len(markers):
            return None
        equal = markers[at]
        captured = bisect.bisect_right(capture_positions, i)
        if captured == len(capture_positions) or capture_positions[captured] >= equal:
            continue
        at = bisect.bisect_right(semicolons, equal)
        if (equal != i + 2 or code.words[i + 1] != capture or code.words[equal] != '='
                or at == len(semicolons) or semicolons[at] >= call or bindings):
            return None
        bindings.append(tuple(code.words[equal + 1:semicolons[at]]))
    if len(bindings) != 1:
        return None
    body_start = code.position(code.starts[opening + 4])
    body_end = code.position(code.ends[closing - 1])
    members = group[2]
    if len(members) > 128:
        return None
    extras = [owner for owner in inventory if owner not in members and any(
        owner_covers_lines([region], line, line) for region in owner['regions']
        for line in range(first, last + 1))]
    if len(extras) != len(members):
        return None
    parents = []
    for owner in members:
        shape = plain_rust_function_symbol(owner['name'])
        declaration = re.search(r'\bfn\s+([A-Za-z_]\w*)', source[group[0] - 1])
        if shape is None or declaration is None or shape[1][-1] != declaration[1]:
            return None
        parents.append(shape)
    linked = []
    for owner, shape in zip(members, parents):
        children = [child for child in extras
                    if direct_rust_callback_symbol(child['name'], owner['name'], shape[0])]
        if len(children) != 1 or name_counts[children[0]['name']] != 1:
            return None
        child = children[0]
        if (child['filenames'] != owner['filenames']
                or type(child.get('count')) is not int or not 0 <= child['count'] < COUNTER_LIMIT
                or max(region[4] for region in child['regions']) != child['count']
                or any(not (body_start <= tuple(region[:2]) < tuple(region[2:4]) <= body_end)
                       for region in child['regions'])):
            return None
        linked.append(child)
    if len({id(child) for child in linked}) != len(extras):
        return None
    symbols = tuple(sorted(owner['name'] for owner in members + linked))
    decoded, tool = demangle_plain_rust_callbacks(symbols)
    parent_ids = [decoded[owner['name']] for owner in members]
    if len(set(parent_ids)) != len(members):
        return None
    for owner, child, shape in zip(members, linked, parents):
        parts = decoded[owner['name']].split('::')
        crate = re.fullmatch(r'([A-Za-z_]\w*)(?:\[[0-9a-f]+\])?', parts[0])
        if crate is None or [crate[1], *parts[1:]] != shape[1]:
            return None
        if re.fullmatch(re.escape(decoded[owner['name']]) + r'::\{closure#[0-9]+\}', decoded[child['name']]) is None:
            return None
    geometry = [tuple((region[0] - first, region[1], region[2] - first, region[3], *region[5:])
                      for region in sorted(child['regions'], key=lambda r: tuple(r[:4]))) for child in linked]
    if len(set(geometry)) != 1:
        return None
    states = [tuple(int(region[4] > 0) for region in sorted(child['regions'], key=lambda r: tuple(r[:4])))
              for child in linked]
    proof = dict(callback_body=[list(body_start), list(body_end)], capture=capture,
        construction_sha256=hashlib.sha256(' '.join(bindings[0]).encode()).hexdigest(),
        geometry=[list(row) for row in geometry[0]],
        owners=[dict(parent=owner['name'], child=child['name'], parent_identity=decoded[owner['name']],
                     child_identity=decoded[child['name']]) for owner, child in zip(members, linked)],
        decoder=tool, limitation='Structural callback ownership and construction syntax only; no value or runtime-role equivalence')
    return states, (tuple(body), bindings[0], geometry[0]), proof


def positive_source_fragments(name, old, new, before, after, base, head, base_files, head_files, fragments):
    """Prove only positive pairs, retaining every compiled copy and candidate."""
    if not fragments:
        return {}, []
    def refuse():
        a, b, c, d, _ = fragments[0]
        raise ValueError(f"Ambiguous unchanged source correspondence: {name}:{a + 1}-{b} -> {c + 1}-{d}")
    inventories = []; groups = []; inventory_names = []
    for owners, files, source in ((base, base_files, old), (head, head_files, new)):
        names = Counter(owner["name"] for owner in owners)
        inventory = [owner for owner in owners if any(
            files.get(path) == name or path.endswith("/" + name) for path in owner["filenames"])]
        by_span = {}
        for owner in inventory:
            span = source_owner_span(owner, name, files, source)
            if span is None:
                refuse()
            by_span.setdefault(span[:2], []).append(owner)
        prefixes = source_function_prefixes(source, by_span)
        valid = {}
        for span, prefix in prefixes.items():
            members = by_span[span]
            shapes = {tuple(sorted(tuple(r[:4] + r[5:]) for r in owner["regions"])) for owner in members}
            if (len(shapes) == 1 and all(names[owner["name"]] == 1 for owner in members)
                    and all(any(r[2] == span[1] and r[3] > len(source[span[1] - 1].rstrip().encode())
                                for r in owner["regions"]) for owner in members)):
                valid[prefix] = (*span, members)
        inventories.append(inventory); groups.append(valid); inventory_names.append(names)
    forwarders = transparent_forwarder_groups(old, new, groups, fragments)
    for prefix, (group, _) in forwarders.items():
        groups[1][prefix] = group
    claimed = {}; pairs = {}; excerpts = {}; callback_sources = {}; callback_work = 20_000_000
    for a, b, c, d, pending in fragments:
        candidates = [(prefix, group, groups[1][prefix]) for prefix, group in groups[0].items()
                      if prefix in groups[1] and group[0] <= a + 1 <= b <= group[1]
                      and groups[1][prefix][0] <= c + 1 <= d <= groups[1][prefix][1]]
        if (len(candidates) != 1 or old[a:b] != new[c:d]
                or any(before.get(line, 0) <= 0 for line in pending)):
            refuse()
        prefix, bg, hg = candidates[0]
        if len(bg[2]) != len(hg[2]):
            refuse()
        for side, source, group in ((0, old, bg), (1, new, hg)):
            excerpts[side, group[0], group[1]] = ("\n".join(source[group[0] - 1:group[1]]) + "\n").encode()
        entry = claimed.setdefault(prefix, {"states": [[[] for _ in group[2]] for group in (bg, hg)],
            "file": name, "base_range": list(bg[:2]), "head_range": list(hg[:2]),
            "instances": len(bg[2]), "pairs": [], "candidates": [],
            "source_prefix_sha256": hashlib.sha256(prefix.encode()).hexdigest()})
        if prefix in forwarders:
            entry['forwarder'] = forwarders[prefix][1]
            start, end = entry['forwarder']['wrapper_range']
            excerpts[1, start, end] = ('\n'.join(new[start - 1:end]) + '\n').encode()
        occurrences = []; callback_signature = None; callback_mode = None
        for side, source, counts, group, proposed in ((0, old, before, bg, a), (1, new, after, hg, c)):
            start, end, members = group
            starts = [offset for offset in range(start - 1, end - (b - a) + 1)
                      if source[offset:offset + b - a] == old[a:b]]
            if proposed not in starts:
                refuse()
            observed = None
            for offset in starts:
                lines = [offset + line - a for line in pending]
                if (any(counts.get(line, 0) <= 0 for line in lines)
                        or any(not owner_covers_lines(owner["regions"], offset + 1, offset + b - a)
                               for owner in members)):
                    refuse()
                touched = {id(owner) for owner in inventories[side] if any(
                    owner_covers_lines([region], line, line) for region in owner["regions"]
                    for line in range(offset + 1, offset + b - a + 1))}
                nested = touched != {id(owner) for owner in members}
                if callback_mode is not None and callback_mode != nested:
                    refuse()
                callback_mode = nested
                children = [()] * len(members)
                if nested:
                    if side not in callback_sources:
                        callback_sources[side] = _boolean_source(source)
                    code = callback_sources[side]
                    callback_work -= 8 * len(code.words) if code is not None else 0
                    if callback_work < 0:
                        refuse()
                    callback = nested_map_err_states(source, group, inventories[side],
                        inventory_names[side], offset + 1, offset + b - a, code)
                    if callback is None or callback_signature is not None and callback_signature != callback[1]:
                        refuse()
                    children, callback_signature, witness = callback
                    entry.setdefault('nested_callbacks', []).append(dict(side=side, candidate=offset + 1, **witness))
                states = tuple(tuple(int(any(region[4] > 0 and owner_covers_lines([region], line, line)
                                             for region in owner["regions"])) for line in lines) + tuple(child)
                               for owner, child in zip(members, children))
                if (any(not any(row[column] for row in states) for column in range(len(lines)))
                        or observed is not None and observed != states):
                    refuse()
                observed = states
            for row, states in zip(entry["states"][side], observed):
                row.extend(states)
            occurrences.append([[offset + 1, offset + b - a] for offset in starts])
        entry["candidates"].append({"base": occurrences[0], "head": occurrences[1]})
        for line in pending:
            target = c + line - a
            if line in pairs and pairs[line] != target:
                refuse()
            pairs[line] = target
            entry["pairs"].append([line, target])
    receipts = []
    for entry in claimed.values():
        states = entry.pop("states")
        matching = compiled_hit_state_matching(*states)
        if matching is None:
            refuse()
        entry["instance_states"] = sorted(states[0])
        entry["head_instance_states"] = sorted(states[1])
        entry["instance_matching"] = matching
        receipts.append(entry)
    require_rustfmt_syntax(excerpts.values())
    return pairs, receipts


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


def _data_argument_shape(expression):
    """Recognize identifiers, fields, immutable borrows and tuples only.

    Unary plus gives Python's AST parser the shape of a Rust borrow. The
    allowlist rejects calls and operators; rustfmt checks the actual Rust.
    """
    if (not expression.strip() or len(expression.encode()) > 4096
            or not re.fullmatch(r'[A-Za-z_0-9\s.,()&]+', expression)):
        return False
    try:
        tree = ast.parse(expression.strip().replace('&', '+'), mode='eval')
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    allowed = (ast.Expression, ast.Name, ast.Attribute, ast.Tuple, ast.UnaryOp, ast.UAdd, ast.Load)
    return all(type(node) in allowed for node in ast.walk(tree))


def retained_block_endpoint_paint(name, old, new, before, after, base, head, base_files, head_files, retained):
    """Prove LLVM paint equivalence for a retained, unmapped loop endpoint."""
    ident = r'[A-Za-z_][A-Za-z_0-9]*'
    loop_header = (r'\s*for\s+' + ident + r'\s+in\s+&?\s*' + ident
                   + r'(?:\s*\.\s*' + ident + r')*\s*\{\s*')
    if not any(before.get(a, 0) > 0 and b not in after and old[a - 1].strip() == '}'
               and new[b - 1].strip() == '}' for a, b in retained.items()):
        return []
    sides = ((old, base, base_files), (new, head, head_files))
    inventories = []
    for source, owners, files in sides:
        counts = Counter(owner['name'] for owner in owners)
        relevant = [owner for owner in owners if any(files.get(path) == name or path.endswith('/' + name)
                                                       for path in owner['filenames'])]
        if any(counts[owner['name']] != 1 or source_owner_span(owner, name, files, source) is None
               for owner in relevant):
            return []
        spans = {id(owner): source_owner_span(owner, name, files, source)[:2] for owner in relevant}
        prefixes = source_function_prefixes(source, set(spans.values()))
        structure = _source_structural_map(source)
        if not structure:
            return []
        inventories.append((relevant, spans, prefixes, structure))

    def touch(region, start, end):
        return (region[0], region[1]) < end and (region[2], region[3]) > start

    results = []
    for oldline, newline in retained.items():
        if (before.get(oldline, 0) <= 0 or newline in after or old[oldline - 1].strip() != '}'
                or new[newline - 1].strip() != '}'):
            continue
        old_info, new_info = inventories
        candidates = [owner for owner in old_info[0] if any(touch(r, (oldline, 1), (oldline + 1, 1))
                                                               for r in owner['regions'])]
        if not candidates:
            continue
        span = old_info[1][id(candidates[0])]
        prefix = old_info[2].get(span)
        if not prefix or any(old_info[1][id(owner)] != span for owner in candidates):
            continue
        groups = [[owner for owner in info[0] if info[1][id(owner)] == target]
                  for info, target in ((old_info, span), (new_info, None))]
        matching_spans = [key for key, value in new_info[2].items() if value == prefix]
        if len(matching_spans) != 1:
            continue
        target = matching_spans[0]
        groups[1] = [owner for owner in new_info[0] if new_info[1][id(owner)] == target]
        if len(groups[0]) != len(groups[1]) or not groups[1]:
            continue
        if any(len({tuple(tuple(r[:4] + r[5:]) for r in owner['regions']) for owner in group}) != 1
               for group in groups):
            continue
        positions = []
        valid = True
        for source, line, info, bounds in ((old, oldline, old_info, span), (new, newline, new_info, target)):
            braces, _, _, offsets, _ = info[3]
            closing = offsets[line - 1] + source[line - 1].index('}')
            openings = [opening for opening, end in braces.items() if end == closing]
            if len(openings) != 1:
                valid = False; break
            opening = openings[0]
            start_line = next((i + 1 for i in range(len(source)) if offsets[i] <= opening < offsets[i + 1]), None)
            if start_line is None or not bounds[0] < start_line < line < bounds[1]:
                valid = False; break
            header = source[start_line - 1]
            if len(header.encode()) > 4096 or not re.fullmatch(loop_header, header):
                valid = False; break
            if sum(text == header for text in source[bounds[0] - 1:bounds[1]]) != 1:
                valid = False; break
            ancestors = sorted((a, b) for a, b in braces.items() if a < opening < closing < b)
            path = []
            for a, b in ancestors:
                line_index = next(i for i in range(len(source)) if offsets[i] <= a < offsets[i + 1])
                if bounds[0] - 1 <= line_index < start_line - 1 and b < offsets[bounds[1] - 1]:
                    path.append(source[line_index].strip())
            positions.append((opening, closing, start_line, header, path, offsets))
        if not valid or positions[0][3:5] != positions[1][3:5]:
            continue
        opening, closing, start_line, _, _, offsets = positions[0]
        open_col = len(old[start_line - 1][:opening - offsets[start_line - 1]].encode()) + 1
        end_col = len(old[oldline - 1].encode()) + 1
        expected = (start_line, open_col, oldline, end_col)
        if any([tuple(r[:4]) for r in owner['regions'] if touch(r, (oldline, 1), (oldline + 1, 1))] != [expected]
               for owner in groups[0]) or set(map(id, candidates)) != set(map(id, groups[0])):
            continue
        if any(touch(r, (newline, 1), (newline + 1, 1)) for owner in new_info[0] for r in owner['regions']):
            continue
        opening, closing, _, _, _, offsets = positions[1]
        text = "\n".join(new)
        braces, _, _, _, code = new_info[3]
        semicolons = [i for i in range(opening + 1, closing) if text[i] == ';' and code[i]]
        tail_end = semicolons[-1] if semicolons else -1
        if tail_end < 0 or text[tail_end + 1:closing].strip():
            continue
        cursor = opening + 1; boundary = cursor; depth = 0
        while cursor < tail_end:
            if cursor in braces:
                cursor = braces[cursor] + 1
                if depth == 0:
                    boundary = cursor
                continue
            if code[cursor]:
                if text[cursor] in '([':
                    depth += 1
                elif text[cursor] in ')]':
                    depth -= 1
                elif text[cursor] == ';' and depth == 0:
                    boundary = cursor + 1
            cursor += 1
        if depth:
            continue
        raw_statement = text[boundary:tail_end + 1]
        statement = raw_statement.strip()
        if (not re.fullmatch(r'[A-Za-z_0-9\s.,()&;]+', statement)
                or re.search(r'\b(?:return|break|continue|yield|await|for|while|if|else|match|loop|let|async|move|unsafe)\b', statement)):
            continue
        root = re.match(ident, statement)
        if root is None:
            continue
        cursor = root.end(); methods = 0; last_args = ''; arguments_valid = True
        while cursor < len(statement):
            method_match = re.match(r'\s*\.\s*' + ident + r'\s*\(', statement[cursor:])
            if method_match is None:
                break
            cursor += method_match.end(); arg_start = cursor; depth = 1
            while cursor < len(statement) and depth:
                depth += (statement[cursor] == '(') - (statement[cursor] == ')')
                cursor += 1
            if depth:
                break
            last_args = statement[arg_start:cursor - 1]
            if last_args.strip() and not _data_argument_shape(last_args):
                arguments_valid = False
                break
            methods += 1
        if not arguments_valid or not methods or not last_args.strip() or statement[cursor:].strip() != ';':
            continue
        terminal = re.fullmatch(r'\s*\.(' + ident + r')\((.+)\);\s*', new[newline - 2])
        if not terminal or not _data_argument_shape(terminal[2]):
            continue
        row = new[newline - 2]
        method = (newline - 1, len(row[:terminal.start(1)].encode()) + 1,
                  newline - 1, len(row[:terminal.end(1)].encode()) + 1)
        argument = (newline - 1, len(row[:terminal.start(2)].encode()) + 1,
                    newline - 1, len(row[:terminal.end(2)].encode()) + 1)
        statement_start = boundary + len(raw_statement) - len(raw_statement.lstrip())
        witness_line = next(i + 1 for i in range(len(new)) if offsets[i] <= statement_start < offsets[i + 1])
        witness_column = len(new[witness_line - 1][:statement_start - offsets[witness_line - 1]].encode()) + 1
        witness_start, witness_end = (witness_line, witness_column), (newline, 1)
        if any(id(owner) not in {id(o) for o in groups[1]} and any(touch(r, witness_start, witness_end)
               for r in owner['regions']) for owner in new_info[0]):
            continue
        base_counts = [next(r[4] for r in owner['regions'] if tuple(r[:4]) == expected) for owner in groups[0]]
        if before[oldline] != max(base_counts):
            continue
        base_states, head_states = [], []
        for owner in groups[0]:
            base_states.append(next(r[4] > 0 for r in owner['regions'] if tuple(r[:4]) == expected))
        for owner in groups[1]:
            method_rows = [r for r in owner['regions'] if tuple(r[:4]) == method]
            arg_rows = [r for r in owner['regions'] if tuple(r[:4]) == argument]
            if len(method_rows) != 1 or len(arg_rows) != 1 or (method_rows[0][4] > 0) != (arg_rows[0][4] > 0):
                break
            head_states.append(method_rows[0][4] > 0)
        if len(head_states) != len(groups[1]) or Counter(base_states) != Counter(head_states):
            continue
        require_rustfmt_syntax(['\n'.join(source[bounds[0] - 1:bounds[1]]).encode()
                                for source, bounds in ((old, span), (new, target))])
        results.append(dict(file=name, pairs=[[oldline, newline]], equivalence='LLVM paint-equivalence',
                            limitation='Block-entry paint; no independent brace counter. The final method may panic or diverge.',
                            base_range=list(span), head_range=list(target), instances=len(groups[0]),
                            source_prefix_sha256=hashlib.sha256(prefix.encode()).hexdigest(),
                            loop_header_sha256=hashlib.sha256(positions[0][3].encode()).hexdigest(),
                            base_body_region=list(expected), head_terminal_regions=[list(method), list(argument)],
                            base_copy_states=sorted(map(int, base_states)),
                            head_copy_states=sorted(map(int, head_states))))
    return results


@dataclass(frozen=True)
class _BooleanSource:
    text: str
    words: list
    starts: list
    ends: list
    parents: list
    pairs: dict
    offsets: list

    def position(self, offset):
        line = bisect.bisect_right(self.offsets, offset) - 1
        return line + 1, len(self.text[self.offsets[line]:offset].encode()) + 1

    def region(self, first, last):
        return (*self.position(self.starts[first]), *self.position(self.ends[last]))

    def ancestors(self, index):
        result = []
        parent = self.parents[index]
        while parent is not None:
            result.append(parent)
            parent = self.parents[parent]
        return result


def _boolean_source(source):
    """Bounded Rust token boundaries, retaining every delimiter and source byte."""
    text = '\n'.join(source)
    if len(text.encode()) > 1024 * 1024:
        return None
    words = []; starts = []; ends = []; parents = []; pairs = {}; stack = []; at = 0
    raw_literal = re.compile(r'(?:br|cr|r)(#*)"')
    token = re.compile(r'''(?:[bc]?"(?:\\[\s\S]|[^"\\])*"|'(?:[^'\\\n]|\\(?:[\\'"nrt0]|x[\da-fA-F]{2}|u\{[\da-fA-F_]+\}))'|'[A-Za-z_]\w*|(?:r\#)?[A-Za-z_]\w*|[0-9][A-Za-z_0-9.]*|::|->|=>|&&|\|\||[^\s])''')
    while at < len(text):
        if text[at].isspace():
            at += 1; continue
        if text.startswith('//', at):
            end = text.find('\n', at)
            at = len(text) if end < 0 else end + 1
            continue
        if text.startswith('/*', at):
            depth = 1; at += 2
            while depth and at < len(text):
                if text.startswith('/*', at):
                    depth += 1; at += 2
                    if depth > 32:
                        return None
                elif text.startswith('*/', at):
                    depth -= 1; at += 2
                else:
                    at += 1
            if depth:
                return None
            continue
        raw = raw_literal.match(text, at)
        if raw:
            end = text.find('"' + raw[1], at + len(raw[0]))
            if end < 0:
                return None
            end += len(raw[1]) + 1
        else:
            match = token.match(text, at)
            if match is None:
                return None
            end = match.end()
        word = text[at:end]
        if word in ('"', "'"):
            return None
        if re.fullmatch(r'r#[A-Za-z_]\w*', word):
            word = word[2:]
        index = len(words)
        words.append(word); starts.append(at); ends.append(end)
        parents.append(stack[-1] if stack else None)
        if word in ('(', '[', '{'):
            stack.append(index)
            if len(stack) > 32:
                return None
        elif word in (')', ']', '}'):
            if not stack or words[stack[-1]] != {')': '(', ']': '[', '}': '{'}[word]:
                return None
            opening = stack.pop(); pairs[opening] = index; pairs[index] = opening
        if len(words) > 131072:
            return None
        at = end
    if stack:
        return None
    offsets = [0]
    for line in source[:-1]:
        offsets.append(offsets[-1] + len(line) + 1)
    return _BooleanSource(text, words, starts, ends, parents, pairs, offsets)


@dataclass(frozen=True)
class SourceAtom:
    line: int
    text: str
    count: int
    endpoint: tuple | None


@dataclass(frozen=True)
class SourceObligation:
    old_line: int
    role: str
    head_line: int | None
    head_candidates: tuple
    reason: str


@dataclass(frozen=True)
class SourceLedger:
    base_atoms: tuple
    head_atoms: tuple
    obligations: tuple
    additions: tuple

    def require_resolved(self):
        """Check source classification only, without a coverage or deletion verdict."""
        pending = [item.old_line for item in self.obligations
                   if item.role not in ('Retained', 'Moved')]
        if pending:
            raise ValueError(f'Ledger has unresolved source obligations: {pending}')


def _ledger_lexical_inventory(source):
    code = _boolean_source(source)
    if code is None:
        raise ValueError('Unsupported bounded source ledger syntax')
    frames = {}; functions = []; remaining = 20_000_000
    for opening in sorted(index for index, word in enumerate(code.words) if word == '{'):
        parent = code.parents[opening]
        first = parent + 1 if parent is not None else 0
        for index in range(opening - 1, first - 1, -1):
            remaining -= 1
            if remaining < 0:
                raise ValueError('Source ledger lexical work bound exceeded')
            if (code.words[index] == ';' and code.parents[index] == parent
                    or code.words[index] == '}' and code.parents[code.pairs[index]] == parent):
                first = index + 1
                break
        prefix = code.words[first:opening]
        remaining -= 8 * (opening - first) + (code.pairs[opening] - opening)
        if remaining < 0:
            raise ValueError('Source ledger lexical work bound exceeded')
        direct = [index for index in range(first, opening) if code.parents[index] == parent]
        fn = [index for index in direct if code.words[index] == 'fn']
        ancestors = tuple(frames[index]['local_identity'] for index in reversed(code.ancestors(opening))
                          if index in frames)
        supported = all(frames[index]['supported'] for index in code.ancestors(opening) if index in frames)
        for index in range(first, opening):
            if code.words[index] != '#':
                continue
            if index + 1 >= opening or code.words[index + 1] != '[':
                supported = False
                continue
            end_attribute = code.pairs[index + 1]
            attribute = code.words[index + 2:end_attribute]
            if attribute not in (['cfg', '(', 'test', ')'], ['test']):
                supported = False
        kind = 'block'; identity = ('block', ancestors, tuple(prefix)); declaration = first
        if len(fn) == 1:
            declaration = fn[0]
            args = declaration + 2
            if (args < opening and code.words[args] == '('
                    and re.fullmatch(r'[A-Za-z_]\w*', code.words[declaration + 1])):
                kind = 'function'
                identity = ('function', ancestors, code.words[declaration + 1],
                            tuple(code.words[args:code.pairs[args] + 1]))
            else:
                kind = 'unsupported'; identity = ('unsupported', ancestors, tuple(prefix))
        elif prefix and prefix[-1] == '!':
            kind = 'macro'; identity = ('macro', ancestors, tuple(prefix))
        else:
            for keyword in ('struct', 'enum', 'union', 'impl', 'mod', 'trait'):
                selected = [index for index in direct if code.words[index] == keyword]
                if len(selected) == 1:
                    kind = keyword
                    identity = (kind, ancestors, tuple(code.words[selected[0]:opening]))
                    break
        end = code.pairs[opening]
        frames[opening] = dict(kind=kind, identity=identity,
                               local_identity=(identity[0], *identity[2:]), opening=opening, end=end,
                               supported=supported and kind not in ('macro', 'unsupported'),
                               first_line=code.position(code.starts[declaration])[0],
                               last_line=code.position(code.starts[end])[0],
                               body=tuple(code.words[opening:end + 1]))
        if kind == 'function':
            functions.append(frames[opening])
    endpoints = {}; by_line = {}
    for index, word in enumerate(code.words):
        by_line.setdefault(code.position(code.starts[index])[0], []).append(index)
    for line, indices in by_line.items():
        if [code.words[index] for index in indices] not in (['}'], ['}', ';']):
            continue
        opening = code.pairs[indices[0]]
        if opening in frames:
            endpoints[line] = frames[opening]
    if len(source) * len(functions) > 20_000_000:
        raise ValueError('Source ledger context inventory work bound exceeded')
    contexts = {}
    for line in range(1, len(source) + 1):
        matches = [frame for frame in functions if frame['first_line'] <= line <= frame['last_line']]
        if matches:
            narrowest = min(frame['last_line'] - frame['first_line'] for frame in matches)
            matches = [frame for frame in matches if frame['last_line'] - frame['first_line'] == narrowest]
            if len(matches) == 1:
                contexts[line] = matches[0]['identity']
    if len(source) * len(frames) > 20_000_000:
        raise ValueError('Source ledger scope inventory work bound exceeded')
    eligible = {line for line in range(1, len(source) + 1)
                if all(frame['supported'] for frame in frames.values()
                       if frame['first_line'] <= line <= frame['last_line'])}
    return endpoints, contexts, functions, eligible


def source_obligation_ledger(old_blob, new_blob, before, after):
    """Inventory line obligations without granting execution or deletion credit.

    Source candidates are selected before counts. Replacements and rejected
    endpoints remain old obligations. This operation is not a coverage verdict.
    """
    sources = []
    for blob, counts in ((old_blob, before), (new_blob, after)):
        if type(blob) is not bytes or len(blob) > 1024 * 1024 or b'\r' in blob:
            raise ValueError('Unsupported exact source ledger blob')
        try:
            text = blob.decode('utf-8')
            lines = text.split('\n')
            if lines[-1] == '':
                lines.pop()
        except UnicodeDecodeError as error:
            raise ValueError('Source ledger blob is not UTF-8') from error
        if (type(counts) is not dict or len(lines) > 65_536
                or any(type(line) is not int or not 1 <= line <= len(lines)
                       or type(count) is not int or not 0 <= count < COUNTER_LIMIT
                       for line, count in counts.items())):
            raise ValueError('Invalid mapped source ledger inventory')
        sources.append(lines)
    old, new = sources
    if len(old) * len(new) > 32_000_000:
        raise ValueError('Source ledger alignment work bound exceeded')
    be, bc, bfunctions, beligible = _ledger_lexical_inventory(old)
    he, hc, hfunctions, heligible = _ledger_lexical_inventory(new)
    atoms = tuple(SourceAtom(line, old[line - 1], count,
                             be[line]['identity'] if line in be else None)
                  for line, count in sorted(before.items()))
    head_atoms = tuple(SourceAtom(line, new[line - 1], count,
                                  he[line]['identity'] if line in he else None)
                       for line, count in sorted(after.items()))
    proposals = {}
    for tag, a, b, c, d in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        for line in range(a + 1, b + 1):
            proposals[line] = (tag, c + line - a if tag == 'equal' else None)
    rows = []
    for atom in atoms:
        line = atom.line; endpoint = be.get(line)
        role = 'Retained'; reason = 'exact unchanged source'; candidates = ()
        if old_blob == new_blob:
            candidates = (line,)
        elif endpoint is not None:
            candidates = tuple(number for number, frame in sorted(he.items())
                               if frame['identity'] == endpoint['identity']
                               and frame['kind'] != 'unsupported')
            reason = 'complete compatible lexical endpoint inventory'
            if not candidates and endpoint['kind'] == 'function':
                old_matches = [frame for frame in bfunctions if frame['supported'] and frame['body'] == endpoint['body']
                               and frame['identity'][3] == endpoint['identity'][3]]
                new_matches = [frame for frame in hfunctions if frame['supported'] and frame['body'] == endpoint['body']
                               and frame['identity'][3] == endpoint['identity'][3]]
                if len(old_matches) == len(new_matches) == 1:
                    candidates = (new_matches[0]['last_line'],)
                    role = 'Moved'; reason = 'unique complete function body extraction'
        else:
            context = bc.get(line)
            candidates = tuple(number for number, text in enumerate(new, 1)
                               if text == atom.text and context is not None and hc.get(number) == context)
            old_candidates = [number for number, text in enumerate(old, 1)
                              if text == atom.text and context is not None and bc.get(number) == context]
            if len(old_candidates) != 1:
                candidates = ()
            reason = 'complete lexical expression inventory'
            if not candidates:
                tag, target = proposals[line]
                text = '\n' + '\n'.join(old) + '\n'
                other = '\n' + '\n'.join(new) + '\n'
                block = '\n' + atom.text + '\n'
                if (tag == 'equal' and re.search(r'\w', atom.text)
                        and text.count(block) == other.count(block) == 1):
                    candidates = (target,)
                    reason = 'unique global source line candidate'
        if len(candidates) == 1 and line in beligible and candidates[0] in heligible:
            rows.append(SourceObligation(line, role, candidates[0], candidates, reason))
        else:
            tag, _ = proposals[line]
            role = 'Replaced' if tag == 'replace' and endpoint is None else 'Unresolved'
            rows.append(SourceObligation(line, role, None, candidates,
                        reason + '; source attribution remains unresolved'))
    usage = Counter(item.head_line for item in rows if item.head_line is not None)
    rows = tuple(SourceObligation(item.old_line, 'Unresolved', None, item.head_candidates,
                                 'non-injective source correspondence remains unresolved')
                 if item.head_line is not None and usage[item.head_line] != 1 else item for item in rows)
    retained = {item.head_line for item in rows if item.head_line is not None}
    return SourceLedger(atoms, head_atoms, rows,
                        tuple(atom.line for atom in head_atoms if atom.line not in retained))


def _diagnostic_size(value):
    """Bound expanded JSON before copying a shared diagnostic object graph."""
    memo = {}; active = set(); remaining = 20_000_000

    def size(item, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            raise ValueError('Diagnostic serialization work bound exceeded')
        if depth > 64:
            raise ValueError('Diagnostic serialization nesting bound exceeded')
        identity = id(item)
        if identity in memo:
            count, height = memo[identity]
            if depth + height > 64:
                raise ValueError('Diagnostic serialization nesting bound exceeded')
            return count, height
        if identity in active:
            raise ValueError('Diagnostic serialization contains a cycle')
        active.add(identity)
        height = 0
        if type(item) is str:
            remaining -= len(item)
            if remaining < 0:
                raise ValueError('Diagnostic serialization work bound exceeded')
            count = 2 + sum(2 if char in '\\"\b\f\n\r\t' else
                            1 if 0x20 <= ord(char) <= 0x7e else
                            6 if ord(char) <= 0xffff else 12 for char in item)
        elif item is None:
            count = 4
        elif type(item) is bool:
            count = 4 if item else 5
        elif type(item) is int:
            count = len(str(item))
        elif is_dataclass(item) or type(item) is dict:
            pairs = ((field.name, getattr(item, field.name)) for field in fields(item)) \
                if is_dataclass(item) else item.items()
            count = 2
            for index, (key, child) in enumerate(pairs):
                if type(key) is not str:
                    raise ValueError('Diagnostic serialization requires string keys')
                key_size, key_height = size(key, depth + 1)
                child_size, child_height = size(child, depth + 1)
                count += key_size + child_size + 2 + (2 if index else 0)
                height = max(height, key_height + 1, child_height + 1)
                if count > MAX_DIAGNOSTIC_BYTES:
                    raise ValueError('Diagnostic output exceeds 64 MiB bound')
        elif type(item) in (tuple, list):
            count = 2
            for index, child in enumerate(item):
                child_size, child_height = size(child, depth + 1)
                count += child_size + (2 if index else 0)
                height = max(height, child_height + 1)
                if count > MAX_DIAGNOSTIC_BYTES:
                    raise ValueError('Diagnostic output exceeds 64 MiB bound')
        else:
            raise ValueError('Unsupported diagnostic serialization value')
        if count > MAX_DIAGNOSTIC_BYTES:
            raise ValueError('Diagnostic output exceeds 64 MiB bound')
        active.remove(identity)
        memo[identity] = count, height
        return count, height

    return size(value, 0)[0]


def _diagnostic_plain_value(value):
    _diagnostic_size(value)

    def plain(item):
        if is_dataclass(item):
            return asdict(item)
        if type(item) is dict:
            return {key: plain(child) for key, child in item.items()}
        if type(item) is tuple:
            return tuple(plain(child) for child in item)
        if type(item) is list:
            return [plain(child) for child in item]
        return item

    return plain(value)


def source_pair_diagnostics(base, head, base_regions, head_regions, base_sources, head_sources, names):
    """Report bounded observer and source inventories without changing comparison."""
    if (not names or len(names) > 8 or len(set(names)) != len(names)
            or any(type(name) is not str or name not in base_sources or name not in head_sources
                   for name in names)):
        raise ValueError('Diagnostic requires one to eight distinct common source files')
    result = {'schema': 'omg.coverage.source-diagnostic.v1', 'acceptance': False,
              'deletion_credit': None, 'folded_credit': None, 'files': []}
    snapshots = []
    for side, coverage, archive, sources in [('base', base, base_regions, base_sources),
                                              ('head', head, head_regions, head_sources)]:
        data = _read_region_document(archive)
        sections = {canonical_source(path, sources): (path, section)
                    for path, section in coverage.sections.items()}
        if len(sections) != len(coverage.sections):
            raise ValueError('Diagnostic LCOV source inventory is ambiguous')
        result[side] = {'lcov_sha256': coverage.sha256,
                        'regions_sha256': hashlib.sha256(Path(archive).read_bytes()).hexdigest()}
        snapshots.append((data, sections, sources))
    for name in names:
        row = {'file': name}; observed = []
        for side, (data, sections, sources) in zip(('base', 'head'), snapshots):
            if name not in sections:
                raise ValueError(f'Diagnostic source has no mapped section: {name}')
            filename, section = sections[name]
            text = sources[name].decode('utf-8').split('\n')
            row[side] = {'source_sha256': hashlib.sha256(sources[name]).hexdigest(),
                         'summary': [section['LF'], section['LH']],
                         'atoms': [dict(line=line, text=text[line - 1] if line <= len(text) else None,
                                        count=count) for line, count in sorted(section['counts'].items())]}
            try:
                records = [item for item in data['files'] if type(item) is dict
                           and item.get('filename') == filename]
                if len(records) != 1:
                    raise ValueError('Diagnostic needs exactly one raw filename record')
                value = observe_llvm22_file(filename, sources[name], data['functions'], records[0], section)
                row[side]['observer'] = {'status': 'reconciled', **vars(value)}
                observed.append(value)
            except (ValueError, TypeError, KeyError, IndexError) as error:
                row[side]['observer'] = {'status': 'unsupported', 'reason': str(error)}
                observed.append(None)
        try:
            ledger = source_obligation_ledger(base_sources[name], head_sources[name],
                        snapshots[0][1][name][1]['counts'], snapshots[1][1][name][1]['counts'])
            row['source_obligations'] = {'status': 'inventoried', **vars(ledger)}
        except (ValueError, TypeError, KeyError, IndexError) as error:
            ledger = None
            row['source_obligations'] = {'status': 'unsupported', 'reason': str(error),
                'old_obligations': [dict(old_line=item['line'], role='Unresolved') for item in row['base']['atoms']]}
        if ledger is not None and observed[0] is not None:
            roles = {item.old_line: item.role for item in ledger.obligations}
            candidates = [key for key, indices in observed[0].groups
                          if all(roles.get(line) in ('Unresolved', 'Replaced')
                                 for index in indices for line, _ in observed[0].owners[index].rows)]
            omissions = []; work = _ObserverWork()
            for key in candidates:
                try:
                    if work.remaining < 0:
                        raise ValueError('LLVM observer work bound exceeded')
                    projection = project_observer_groups(observed[0], (key,), _work=work)
                    omissions.append({'status': 'observed-only', 'source_credit': 'unproved',
                        'removed_groups': projection.removed_groups, 'removed_owners': projection.removed_owners,
                        'summary_without': projection.summary, 'mapped_without': len(projection.rows),
                        'mapped_hit_without': sum(count > 0 for _, count in projection.rows),
                        'rows_sha256': hashlib.sha256(json.dumps(projection.rows).encode()).hexdigest()})
                except ValueError as error:
                    omissions.append({'status': 'unsupported', 'removed_groups': [key], 'reason': str(error)})
            row['group_omissions'] = {'status': 'diagnostic-only', 'candidate_groups': candidates,
                'groups': omissions, 'unprojected_groups': [dict(group=key,
                    reason='partial or retained source owner; attribution remains unsupported')
                    for key, _ in observed[0].groups if key not in candidates]}
        result['files'].append(row)
    return _diagnostic_plain_value(result)


def _boolean_attributes(code, index):
    attributes = []
    cursor = index - 1
    while cursor >= 0 and code.words[cursor] == ']':
        opening = code.pairs[cursor]
        if opening == 0 or code.words[opening - 1] != '#':
            return None
        attributes.append(code.words[opening + 1:cursor])
        cursor = opening - 2
    if cursor >= 0 and code.words[cursor] not in (';', '}', '{'):
        return None
    return attributes


def _boolean_items(code):
    items = []
    for index, word in enumerate(code.words[:-2]):
        if word != 'fn' or not re.fullmatch(r'[A-Za-z_]\w*', code.words[index + 1]) or code.words[index + 2] != '(':
            continue
        args_end = code.pairs[index + 2]
        cursor = args_end + 1
        while cursor < len(code.words) and code.words[cursor] not in ('{', ';', '}'):
            cursor += 1
        if (cursor == len(code.words) or code.words[cursor] != '{'
                or len(code.text[code.starts[index]:code.ends[cursor]].encode()) > 4096):
            continue
        end = code.pairs[cursor]
        if len(code.text[code.starts[index]:code.ends[end]].encode()) > 64 * 1024:
            continue
        items.append(dict(name=code.words[index + 1], start=index, body=cursor, end=end,
                          arguments=(index + 2, args_end), parent=code.parents[index],
                          span=(code.position(code.starts[index])[0], code.position(code.ends[end])[0])))
    return items


def _boolean_module(code, item):
    path = []; gates = []; scopes = []
    for opening in reversed(code.ancestors(item['start'])):
        if opening < 2 or code.words[opening - 2] != 'mod' or not re.fullmatch(r'[A-Za-z_]\w*', code.words[opening - 1]):
            return None
        attributes = _boolean_attributes(code, opening - 2)
        if attributes is None or any(attribute != ['cfg', '(', 'test', ')'] for attribute in attributes):
            return None
        path.append(code.words[opening - 1]); scopes.append(opening)
        if attributes:
            gates.append('::'.join(path))
    return path, gates, scopes


def _boolean_arguments(code, opening):
    end = code.pairs[opening]; cursor = opening + 1; start = cursor; result = []
    while cursor < end:
        if code.words[cursor] == ',' and code.parents[cursor] == opening:
            if cursor == start:
                return None
            result.append((start, cursor)); start = cursor + 1
        if code.words[cursor] in ('(', '[', '{'):
            cursor = code.pairs[cursor]
        cursor += 1
    if start < end:
        result.append((start, end))
    return result if result and len(result) <= 32 else None


def _boolean_leaf(words):
    keywords = {'as', 'async', 'await', 'break', 'const', 'continue', 'else', 'enum', 'extern', 'fn',
                'for', 'if', 'impl', 'in', 'let', 'loop', 'match', 'mod', 'move', 'mut', 'pub',
                'ref', 'return', 'static', 'struct', 'trait', 'type', 'unsafe', 'use', 'where', 'yield'}
    if len(words) == 1:
        return words[0] not in keywords and bool(re.fullmatch(
            r'(?:[A-Za-z_]\w*|[0-9]+|"(?:\\.|[^"\\])*")', words[0]))
    return (len(words) % 2 == 1 and words[1::2] == ['::'] * (len(words) // 2)
            and all(word not in keywords and re.fullmatch(r'[A-Za-z_]\w*', word) for word in words[::2]))


def _boolean_call_context(code, line, head):
    literal = re.fullmatch(r'\s*(true|false)\s*,?\s*', code.text.splitlines()[line - 1])
    if literal is None:
        return None
    tokens = [i for i, word in enumerate(code.words) if word == literal[1] and code.position(code.starts[i])[0] == line]
    items = _boolean_items(code)
    callers = [item for item in items if tokens and item['body'] < tokens[0] < item['end']]
    if len(tokens) != 1 or len(callers) != 1:
        return None
    caller = callers[0]; token = tokens[0]; opening = code.parents[token]
    if opening is None or code.words[opening] != '(' or opening == 0:
        return None
    call = opening - 1; name = code.words[call]
    definitions = [item for item in items if item['name'] == name]
    if len(definitions) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', name):
        return None
    callee = definitions[0]
    module = _boolean_module(code, caller)
    if (module is None or _boolean_module(code, callee) != module or callee['parent'] != caller['parent']
            or _boolean_attributes(code, callee['start']) != []
            or _boolean_attributes(code, caller['start']) not in ([], [['test']])):
        return None
    parameters = _boolean_arguments(code, callee['arguments'][0])
    arguments = _boolean_arguments(code, opening)
    if parameters is None or arguments is None or len(parameters) != len(arguments):
        return None
    ordinals = [i for i, (start, end) in enumerate(arguments) if (start, end) == (token, token + 1)]
    if len(ordinals) != 1:
        return None
    ordinal = ordinals[0]
    # Local items shadow module globs. Explicit imports/declarations of this
    # name, and generators at the module boundary, still make proof impossible.
    module_parent = caller['parent']
    item_bodies = {item['body'] for item in items}
    for index, word in enumerate(code.words):
        enclosing = code.ancestors(index)
        at_module = code.parents[index] == module_parent
        inside_item = any(opening in item_bodies for opening in enclosing)
        in_module = (module_parent is None or module_parent in enclosing)
        if in_module and not inside_item and word == name and index != callee['start'] + 1:
            return None
        if at_module and word == '!':
            return None
        if at_module and word == '#' and index + 1 < len(code.words) and code.words[index + 1] == '[':
            attr = code.words[index + 2:code.pairs[index + 1]]
            if not attr or attr[0] not in ('cfg', 'test'):
                return None
    occurrences = []; selected = None
    enclosing_blocks = {i for i in code.ancestors(call) if code.words[i] == '{'}
    for ancestor in code.ancestors(call):
        if ancestor > 0 and code.words[ancestor - 1] == '!':
            if head or ancestor < 2 or code.words[ancestor - 2] not in ('assert', 'assert_eq', 'assert_ne'):
                return None
    for index in range(caller['start'], caller['end']):
        word = code.words[index]
        if (index != caller['start'] and code.parents[index] in enclosing_blocks
                and word in ('use', 'extern', 'mod', 'struct', 'enum', 'union', 'type', 'static', 'const', 'fn', '#')):
            return None
        if word in ('|', '||', 'async', 'await'):
            return None
        if word == '!' and code.parents[index] in enclosing_blocks:
            # Only the base's assertion macro is supported; its execution is
            # established separately by the literal's ordinary region.
            if head or index == 0 or code.words[index - 1] not in ('assert', 'assert_eq', 'assert_ne'):
                return None
        if word != name:
            continue
        if (index + 1 >= len(code.words) or code.words[index + 1] != '('
                or index > 0 and code.words[index - 1] in ('.', '::', 'fn')):
            return None
        args = _boolean_arguments(code, index + 1)
        if args is None or len(code.text[code.starts[index]:code.ends[code.pairs[index + 1]]].encode()) > 4096:
            return None
        leaves = all(_boolean_leaf(code.words[a:b]) for a, b in args)
        eligible = (leaves and len(args) == len(arguments)
                    and code.words[args[ordinal][0]:args[ordinal][1]] == [literal[1]])
        occurrences.append(dict(region=list(code.region(index, code.pairs[index + 1])), eligible=eligible,
                                reason='safe leaves' if leaves else 'non-leaf argument'))
        if eligible:
            selected = index
        if len(occurrences) > 256:
            return None
    if sum(row['eligible'] for row in occurrences) != 1 or selected != call:
        return None
    continuation = None
    if head:
        # The call is the first statement of the function or of each enclosing
        # ordinary for body. This excludes labels, joins, lazy scopes and bypasses.
        blocks = list(reversed([i for i in code.ancestors(call) if code.words[i] == '{']))
        if caller['body'] not in blocks:
            return None
        blocks = blocks[blocks.index(caller['body']):]
        boundary = caller['body'] + 1
        for block in blocks[1:]:
            if (code.words[boundary] != 'for' or not re.fullmatch(r'[A-Za-z_]\w*', code.words[boundary + 1])
                    or code.words[boundary + 2] != 'in' or code.words[boundary + 3] != '['
                    or code.pairs[boundary + 3] != block - 1):
                return None
            boundary = block + 1
        prefix = code.words[boundary:call]
        if not (len(prefix) in (3, 4) and prefix[0] == 'let' and prefix[-1] == '='
                and re.fullmatch(r'[A-Za-z_]\w*', prefix[-2])
                and (len(prefix) == 3 or prefix[1] == 'mut')):
            return None
        end = code.pairs[opening]
        tail = code.words[end + 1:]
        if (len(tail) < 6 or tail[0:2] != [';', 'for']
                or not re.fullmatch(r'[A-Za-z_]\w*', tail[2]) or tail[3:5] != ['in', '[']):
            return None
        iterator = end + 5; iterator_end = code.pairs[iterator]
        if code.words[iterator_end + 1] != '{' or code.parents[iterator] != code.parents[call]:
            return None
        if any(word in ('!', '|', '||', 'async', 'await', 'return', 'break', 'continue', 'if', 'match', '?')
               for word in code.words[iterator:iterator_end + 1]):
            return None
        continuation = code.region(iterator, iterator_end)
    return dict(caller=caller, callee=callee, module=module, ordinal=ordinal, arity=len(arguments),
                occurrences=occurrences, literal=code.region(token, token),
                call=code.region(call, call), continuation=continuation)


def _boolean_segments(segments, source):
    if not isinstance(segments, list) or not segments or len(segments) > 131072:
        return False
    previous = (0, 0); encoded = [line.encode() for line in source]
    for row in segments:
        if (not isinstance(row, list) or len(row) != 6 or any(type(v) is not int for v in row[:3])
                or any(type(v) is not bool for v in row[3:]) or not 1 <= row[0] <= len(source)
                or not 1 <= row[1] <= len(encoded[row[0] - 1]) + 1
                or not 0 <= row[2] < COUNTER_LIMIT or tuple(row[:2]) <= previous
                or not row[3] and (row[2] != 0 or row[4] or row[5])):
            return False
        if row[1] <= len(encoded[row[0] - 1]) and encoded[row[0] - 1][row[1] - 1] & 0xC0 == 0x80:
            return False
        previous = tuple(row[:2])
    return not segments[-1][3]


def retained_boolean_argument_paint(name, old, new, before, after, base, head, base_files, head_files,
                                    retained, base_segments=None, head_segments=None):
    """Prove only an existing, unmapped eager boolean argument; grant no credit."""
    candidates = [(a, b) for a, b in retained.items() if before.get(a, 0) > 0 and b not in after
                  and re.fullmatch(r'\s*(?:true|false)\s*,?\s*', old[a - 1])
                  and old[a - 1].strip() == new[b - 1].strip()]
    if not candidates or len(candidates) > 256:
        return []
    codes = [_boolean_source(source) for source in (old, new)]
    if not all(codes) or not all(_boolean_segments(segments, source)
                                for segments, source in ((base_segments, old), (head_segments, new))):
        return []
    if sum(len(code.words) for code in codes) * len(candidates) > 262144:
        return []
    inventories = []
    for source, owners, files in ((old, base, base_files), (new, head, head_files)):
        names = Counter(owner['name'] for owner in owners)
        relevant = [owner for owner in owners if any(files.get(path) == name or path.endswith('/' + name)
                                                    for path in owner['filenames'])]
        boundaries = []
        for line in source:
            column = 1; columns = {1}
            for character in line:
                column += len(character.encode()); columns.add(column)
            boundaries.append(columns)
        if len(relevant) > 4096 or any(names[owner['name']] != 1 or source_owner_span(owner, name, files, source) is None
                                    for owner in relevant):
            return []
        if any(row[4] >= COUNTER_LIMIT or row[1] not in boundaries[row[0] - 1]
               or row[3] not in boundaries[row[2] - 1] for owner in relevant for row in owner['regions']):
            return []
        inventories.append(relevant)

    def touches(row, start, end):
        return tuple(row[:2]) < end and tuple(row[2:4]) > start

    def segment_rows(segments, start, end):
        return [row for index, row in enumerate(segments)
                if tuple(row[:2]) < end and (index + 1 == len(segments) or tuple(segments[index + 1][:2]) > start)]

    results = []
    for oldline, newline in candidates:
        contexts = [_boolean_call_context(code, line, is_head) for code, line, is_head in
                    ((codes[0], oldline, False), (codes[1], newline, True))]
        if not all(contexts):
            continue
        bc, hc = contexts
        if (bc['module'][:2] != hc['module'][:2] or (bc['ordinal'], bc['arity']) != (hc['ordinal'], hc['arity'])):
            continue
        callee_sources = [code.text[code.starts[context['callee']['start']]:code.ends[context['callee']['end']]]
                          for code, context in zip(codes, contexts)]
        if callee_sources[0] != callee_sources[1]:
            continue
        groups = []
        for source, owners, files, context in zip((old, new), inventories, (base_files, head_files), contexts):
            groups.append([[owner for owner in owners if source_owner_span(owner, name, files, source)[:2] == context[kind]['span']]
                           for kind in ('caller', 'callee')])
        if any(len(group) != 1 for side in groups for group in side):
            continue
        if any(not any(row[4] > 0 and touches(row, code.region(context['callee']['start'] + 1,
                       context['callee']['start'] + 1)[:2], code.region(context['callee']['start'] + 1,
                       context['callee']['start'] + 1)[2:]) for row in side[1][0]['regions'])
               for code, context, side in zip(codes, contexts, groups)):
            continue
        if any(any(owner is not group[0] and any(touches(row, (context[kind]['span'][0], 1),
                        (context[kind]['span'][1] + 1, 1)) for row in owner['regions']) for owner in owners)
               for context, owners, side in zip(contexts, inventories, groups)
               for kind, group in zip(('caller', 'callee'), side)):
            continue
        bo, ho = groups[0][0][0], groups[1][0][0]
        base_line_rows = [(owner, row) for owner in inventories[0] for row in owner['regions']
                          if touches(row, (oldline, 1), (oldline + 1, 1))]
        if len(base_line_rows) != 1 or base_line_rows[0][0] is not bo:
            continue
        region = base_line_rows[0][1]
        if (tuple(region[:2]) > bc['literal'][:2] or tuple(region[2:4]) < bc['literal'][2:]
                or region[4] != before[oldline]):
            continue
        if any(touches(row, (newline, 1), (newline + 1, 1)) for owner in inventories[1] for row in owner['regions']):
            continue
        base_segment_rows = segment_rows(base_segments, (oldline, 1), (oldline + 1, 1))
        base_token_rows = segment_rows(base_segments, bc['literal'][:2], bc['literal'][2:])
        head_segment_rows = segment_rows(head_segments, (newline, 1), (newline + 1, 1))
        if (not base_segment_rows or max((row[2] for row in base_segment_rows if row[3] and not row[5]), default=0) != before[oldline]
                or not base_token_rows or any(not row[3] or row[5] or row[2] != before[oldline] for row in base_token_rows)
                or any(row[5] for row in base_segment_rows) or not head_segment_rows
                or any(row[3] or row[4] or row[5] for row in head_segment_rows)):
            continue
        witnesses = []
        for owners, owner, shape in ((inventories[0], bo, bc['call']), (inventories[1], ho, hc['call']),
                                    (inventories[1], ho, hc['continuation'])):
            rows = [row for row in owner['regions'] if tuple(row[:4]) == shape]
            if (len(rows) != 1 or rows[0][4] <= 0 or any(
                    touches(row, shape[:2], shape[2:]) and row[4] != rows[0][4] for row in owner['regions'])
                    or any(other is not owner and any(
                    touches(row, shape[:2], shape[2:]) for row in other['regions']) for other in owners)):
                break
            witnesses.append(rows[0])
        if len(witnesses) != 3 or witnesses[1][4] != witnesses[2][4]:
            continue
        witness_segments = [segment_rows(segments, shape[:2], shape[2:])
                            for segments, shape in ((base_segments, bc['call']), (head_segments, hc['call']),
                                                     (head_segments, hc['continuation']))]
        if any(not rows or tuple(rows[0][:2]) != shape[:2] or not rows[0][4]
               or any(not row[3] or row[5] or row[2] != witness[4] for row in rows)
               for rows, shape, witness in zip(witness_segments, (bc['call'], hc['call'], hc['continuation']), witnesses)):
            continue
        excerpts = [code.text[code.starts[context['caller']['start']]:code.ends[context['caller']['end']]].encode()
                    for code, context in zip(codes, contexts)]
        require_rustfmt_syntax(excerpts + [callee_sources[0].encode()])
        results.append(dict(file=name, pairs=[[oldline, newline]], argument_ordinal=bc['ordinal'] + 1, arity=bc['arity'],
            claim='eager boolean evaluation only; no caller ancestry or independent literal counter',
            module_path=bc['module'][0], test_gates=bc['module'][1],
            source_lines_sha256=[hashlib.sha256(code.text.encode()).hexdigest() for code in codes],
            callee_source_sha256=hashlib.sha256(callee_sources[0].encode()).hexdigest(),
            base_occurrences=bc['occurrences'], head_occurrences=hc['occurrences'],
            owner_inventories=[[dict(role=role, name=group[0]['name'], regions=group[0]['regions'])
                                for role, group in zip(('caller', 'callee'), side)] for side in groups],
            base_literal_region=region, base_call_region=witnesses[0], head_call_region=witnesses[1],
            head_continuation_region=witnesses[2], base_literal_segments=base_segment_rows,
            base_literal_token_segments=base_token_rows,
            head_literal_segments=head_segment_rows,
            base_call_segments=witness_segments[0], head_witness_segments=witness_segments[1:]))
    return results


def require_source_no_regression(base, head, base_regions, head_regions, base_sources, head_sources):
    bf, bs = region_evidence(base_regions, base, base_sources, "base")
    hf, hs = region_evidence(head_regions, head, head_sources, "head")
    if bs.keys() - hs.keys():
        raise ValueError("Removed coverage file requires explicit review")
    added_receipt = []
    for name in sorted(hs.keys() - bs.keys()):
        if name in base_sources:
            raise ValueError(f"Added coverage file already exists in base source: {name}")
        section = hs[name]
        counts = section["counts"]
        source = head_sources[name].decode("utf-8").splitlines()
        if any(line > len(source) for line in counts):
            raise ValueError(f"Coverage line exceeds exact source blob: {name}")
        if section["LF"] == 0 or not counts:
            raise ValueError(f"Empty added coverage evidence: {name}")
        if section["LH"] != section["LF"]:
            raise ValueError(f"Added file summary is not fully covered: {name}")
        for line, count in sorted(counts.items()):
            if count == 0:
                raise ValueError(f"Added file has uncovered mapped line: {name}:{line}")
        added_receipt.append({"file": name, "summary_found": section["LF"],
                              "summary_hit": section["LH"], "mapped": len(counts),
                              "mapped_hit": sum(count > 0 for count in counts.values())})
    common_head = Coverage(len(bs), sum(hs[name]["LF"] for name in bs),
                           sum(hs[name]["LH"] for name in bs),
                           sum(len(hs[name]["counts"]) for name in bs),
                           sum(sum(count > 0 for count in hs[name]["counts"].values()) for name in bs),
                           head.sha256)
    if min(common_head.found, common_head.mapped) <= 0:
        raise ValueError("No comparable common head coverage")
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
    positive_receipts = []; endpoint_receipts = []; boolean_receipts = []
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
        retained = {}; gone = set(); unresolved_fragments = []
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
                                unresolved_fragments.append((a, b, c, d, pending))
                                continue
                            retained.update((line, c + line - a) for line in pending)
                        # Repeated text is retained only through its proven function owner.
                        continue
                retained.update(zip(range(a + 1, b + 1), range(c + 1, d + 1)))
            elif tag == "delete":
                gone.update(range(a + 1, b + 1))
            # Replacement is not proven deletion. Its old counts stay in the
            # strict base ratios, and its new uncovered mappings are refused.
        positive, receipts = positive_source_fragments(
            name, old, new, before, after, bf, hf, base_files, head_files, unresolved_fragments)
        retained.update(positive)
        positive_receipts.extend(receipts)
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
        endpoint = retained_block_endpoint_paint(name, old, new, before, after, bf, hf, base_files, head_files, final_pairs)
        endpoint_receipts.extend(endpoint)
        raw_sources = (base_sources[name], head_sources[name])
        line_sources = tuple('\n'.join(source).encode() for source in (old, new))
        boolean = (retained_boolean_argument_paint(name, old, new, before, after, bf, hf, base_files, head_files,
                                                   final_pairs, bs[name]['segments'], hs[name]['segments'])
                   if bs[name]['expansions'] == hs[name]['expansions'] == []
                   and all(raw in (lines, lines + b'\n') for raw, lines in zip(raw_sources, line_sources)) else [])
        for witness in boolean:
            witness['source_blob_sha256'] = [hashlib.sha256(raw).hexdigest() for raw in raw_sources]
        boolean_receipts.extend(boolean)
        painted = {(a, b) for witness in paint + endpoint + boolean for a, b in witness["pairs"]}
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
    if endpoint_receipts:
        paint_receipt["retained_block_endpoint_paint"] = endpoint_receipts
    if boolean_receipts:
        paint_receipt['retained_boolean_argument_paint'] = boolean_receipts
    if positive_receipts:
        paint_receipt["positive_source_fragments"] = positive_receipts
    if added_receipt:
        paint_receipt["added_files"] = added_receipt
    if serial_receipts:
        paint_receipt['serial_wrapper_elision'] = serial_receipts
    if (not serial_receipts and common_head.hit * base.found >= base.hit * common_head.found and
            common_head.mapped_hit * base.mapped >= base.mapped_hit * common_head.mapped):
        require_no_regression(base, common_head)
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
    require_no_regression(normalized, common_head)
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
    parser.add_argument('--diagnostic-output', type=Path)
    parser.add_argument('--diagnostic-file', action='append', default=[])
    args = parser.parse_args()
    base = read_coverage(args.base, "base")
    head = read_coverage(args.head, "head")
    print(json.dumps({"base": {k: v for k, v in vars(base).items() if k != "sections"},
                      "head": {k: v for k, v in vars(head).items() if k != "sections"}}, sort_keys=True))
    evidence = (args.base_regions, args.head_regions, args.source_repo, args.base_sha, args.head_sha)
    if bool(args.diagnostic_output) != bool(args.diagnostic_file):
        parser.error('Diagnostic output and source file selections are required together')
    if args.diagnostic_output and not all(evidence):
        parser.error('Diagnostic output requires complete exact source/region evidence')
    if any(evidence):
        if not all(evidence):
            raise ValueError("Complete exact source/region evidence required")
        base_sources = source_blobs(args.source_repo, args.base_sha)
        head_sources = source_blobs(args.source_repo, args.head_sha)
        if args.diagnostic_output:
            try:
                report = source_pair_diagnostics(base, head, args.base_regions, args.head_regions,
                                                base_sources, head_sources, args.diagnostic_file)
                report['source_commits'] = {'base': args.base_sha, 'head': args.head_sha}
                if _diagnostic_size(report) + 1 > MAX_DIAGNOSTIC_BYTES:
                    raise ValueError('Diagnostic output exceeds 64 MiB bound')
                raw = json.dumps(report, sort_keys=True).encode('utf-8') + b'\n'
                if len(raw) > MAX_DIAGNOSTIC_BYTES:
                    raise ValueError('Diagnostic output exceeds 64 MiB bound')
                with args.diagnostic_output.open('xb') as stream:
                    stream.write(raw)
            except (ValueError, OSError, TypeError, KeyError, IndexError) as error:
                print(f'Diagnostic unavailable; strict comparison unchanged: {error}', file=sys.stderr)
        receipt = require_source_no_regression(base, head, args.base_regions, args.head_regions,
            base_sources, head_sources)
        print(json.dumps(receipt, sort_keys=True))
    else:
        require_no_regression(base, head)
    print("PASS: complete line coverage meets the exact base report")


if __name__ == "__main__":
    main()

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
SOURCE_CONSTRUCT_WORK_CAPACITY = 64_000_000
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
    def __init__(self, shared=None):
        self.remaining = 20_000_000
        self.shared = shared

    def spend(self, units=1):
        if self.shared is not None:
            _construct_charge(self.shared, units)
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
            or not owner["regions"]):
        return None
    start = len(source) + 1; endpoint = (0, 0)
    for region in owner['regions']:
        if (len(region) != 8 or any(type(value) is not int for value in region)
                or min(region[:4]) < 1 or region[0] > region[2] or region[2] > len(source)
                or region[1] > len(source[region[0] - 1].encode('utf-8')) + 1
                or region[3] > len(source[region[2] - 1].encode('utf-8')) + 1
                or (region[0] == region[2] and region[1] >= region[3])
                or region[4] < 0 or region[5:] != [0, 0, 0]):
            return None
        start = min(start, region[0]); endpoint = max(endpoint, (region[2], region[3]))
    end, end_column = endpoint
    declaration = source[start - 1]
    function = re.fullmatch(
        r"([ \t]*)(?:(?:pub(?:\([^()]*\))?|async|unsafe|const)\s+)*fn\s+[A-Za-z_]\w*[^{}]*\{\s*",
        declaration)
    header = declaration if function else None
    if not (function and source[end - 1].rstrip() == function[1] + "}"
            and end_column > len(function[1]) + 1):
        declaration = None
    return start, end, declaration, header


def owner_covers_lines(regions, start, end):
    return all(any(region[0] <= line < region[2] or line == region[2] and region[3] > 1
                   for region in regions) for line in range(start, end + 1))


def region_overlaps_observed_lines(region, line_ends):
    start_line, start_column, end_line, end_column = region[:4]
    index = bisect.bisect_left(line_ends, (start_line, 0))
    if index < len(line_ends):
        line, width = line_ends[index]
        if line == start_line and start_column >= width:
            index += 1
    return index < len(line_ends) and (line_ends[index][0], 1) < (end_line, end_column)


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


@dataclass(frozen=True)
class SourceStructure:
    braces: dict
    names: Counter
    modules: list
    offsets: list
    code: bytearray
    text: str
    function_positions: dict | None = None


def _source_structural_map(source):
    """Find lexical brace pairs and names while ignoring comments and literals."""
    text = "\n".join(source)
    raw_literal = re.compile(r'(?:br|cr|r)(#*)"')
    character = re.compile(r"'(?:[^\\'\n]|\\(?:[\\'\"nrt0]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}))'")
    lifetime_name = re.compile(r"'[A-Za-z_]\w*")
    identifier = re.compile(r"(?:r#)?([A-Za-z_]\w*)")
    braces = {}; stack = []; names = Counter(); modules = []; functions = {}; previous = None; at = 0
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
                functions.setdefault(word[1], []).append(at)
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
    return SourceStructure(braces, names, modules, offsets, code, text, functions)


def _source_function_candidates(source, spans, work=None, structure=None):
    """Recognize bounded signatures and their actual lexical body boundaries."""
    structure = _source_structural_map(source) if structure is None else structure
    if not structure:
        return {}
    braces = structure.braces
    modules, offsets, text = structure.modules, structure.offsets, structure.text
    if work is not None:
        _construct_charge(work, len(braces) * (len(braces).bit_length() + 1))
    openings = sorted(braces)
    result = {}
    for start, end in spans:
        at = offsets[start - 1]
        opening = bisect.bisect_left(openings, at)
        limit = min(offsets[end] - 1, at + 4097,
                    openings[opening] + 1 if opening < len(openings) else len(text))
        if work is not None:
            _construct_charge(work, limit - at + 1)
        header = re.match(
            r"([ \t]*(?:(?:pub(?:\([^()]*\))?|async|unsafe|const)\s+)*fn\s+([A-Za-z_]\w*)\s*"
            r"(?:<\s*'[A-Za-z_]\w*(?:\s*,\s*'[A-Za-z_]\w*)*\s*,?\s*>\s*)?"
            r"\([^(){}]*\))\s*(?:->\s*[^{}]+?)?\{", text[at:limit])
        if (header is None or len(header[0]) > 4096
                or bisect.bisect_left(modules, offsets[start - 1]) != bisect.bisect_left(modules, offsets[end])
                or re.search(r"\bwhere\b", header[0])
                or source[end - 1].strip() != "}"
                or braces.get(offsets[start - 1] + len(header[0]) - 1) !=
                offsets[end - 1] + len(source[end - 1].rstrip()) - 1):
            continue
        result[start, end] = (header[1], header[2])
    return result


def source_function_prefixes(source, spans, work=None, structure=None):
    """Recognize unique bounded signatures and their actual lexical boundaries."""
    structure = _source_structural_map(source) if structure is None else structure
    if not structure:
        return {}
    candidates = _source_function_candidates(source, spans, work, structure)
    return {span: prefix for span, (prefix, name) in candidates.items() if structure.names[name] == 1}


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


def compiled_hit_state_matching(before, after, copy_identities=None):
    """Assign each complete base hit vector to a distinct dominating head vector."""
    if len(before) != len(after):
        return None
    fixed_before = fixed_after = None
    if copy_identities is not None:
        shared = set(copy_identities[0]) & set(copy_identities[1])
        if shared:
            ordered = [sorted(zip(map(tuple, rows), keys, strict=True), key=lambda pair: pair[0])
                       for rows, keys in zip((before, after), copy_identities, strict=True)]
            fixed_before, fixed_after = [[key if key in shared else None for _, key in rows]
                                         for rows in ordered]
    before, after = sorted(map(tuple, before)), sorted(map(tuple, after))
    if before == after and fixed_before == fixed_after:
        return list(range(len(before)))
    width = max((len(row) for row in before), default=0)
    if len(before) * len(after) * max(width, 1) > 2**20:
        return None
    edges = [[index for index, candidate in enumerate(after)
              if (fixed_before is None or fixed_before[base_index] == fixed_after[index])
              and len(row) == len(candidate) and all(a <= b for a, b in zip(row, candidate))]
             for base_index, row in enumerate(before)]
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


@dataclass(frozen=True)
class RustFunctionPath:
    modules: int
    identifiers: tuple[str, ...]
    disambiguators: tuple[str, ...]

    @property
    def identity(self):
        return tuple(zip(self.identifiers, self.disambiguators))


@dataclass(frozen=True)
class CallbackCapsule:
    preceding: str
    tokens: tuple[str, ...]
    context: tuple
    namespace: tuple
    function_disambiguator: str


def plain_rust_function_symbol(symbol):
    """Recognize only complete ASCII v0 free-function paths without instantiating suffixes."""
    if type(symbol) is not str or len(symbol) > 4096:
        return None
    prefix = re.match(r'_RNv((?:Nt){0,16})C(?:s[0-9A-Za-z]{0,32}_)?', symbol)
    if prefix is None:
        return None
    modules = len(prefix[1]) // 2
    at = prefix.end(); identifiers = []; disambiguators = []
    for index in range(modules + 2):
        discriminator = re.match(r's[0-9A-Za-z]{0,32}_', symbol[at:]) if index else None
        disambiguators.append(discriminator[0] if discriminator else '')
        if discriminator:
            at += len(discriminator[0])
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
    return RustFunctionPath(modules, tuple(identifiers), tuple(disambiguators))


def rust_same_crate_backref(modules, depth):
    # Each NC adds two bytes; the crate backreference encodes its offset minus one.
    # https://doc.rust-lang.org/stable/rustc/symbol-mangling/v0.html#backref
    return 'B' + '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'[1 + 2 * depth + 2 * modules] + '_'


def direct_rust_callback_symbol(child, parent, modules, depth=1):
    if type(child) is not str or len(child) > 4096 or not 1 <= depth <= 8:
        return False
    backref = rust_same_crate_backref(modules,depth)
    return re.fullmatch(re.escape('_R' + 'NC' * depth + parent[2:])
                        + r'(?:(?:s[0-9A-Za-z]{0,32}_)?0){' + str(depth) + '}'
                        + '(?:' + backref + ')?', child) is not None


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
            direct_rust_callback_symbol(symbol, parent, shape.modules)
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
        if shape is None or declaration is None or shape.identifiers[-1] != declaration[1]:
            return None
        parents.append(shape)
    linked = []
    for owner, shape in zip(members, parents):
        children = [child for child in extras
                    if direct_rust_callback_symbol(child['name'], owner['name'], shape.modules)]
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
        if crate is None or (crate[1], *parts[1:]) != shape.identifiers:
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
    disambiguators = {parent.disambiguators for parent in parents}
    if len(disambiguators) != 1:
        return None
    proof['parent_disambiguators'] = list(parents[0].disambiguators)
    return states, (tuple(body), bindings[0], geometry[0], parents[0].disambiguators), proof


def closed_pgp_checksum_prefixes(name, source, inventory, files, spans, structure, work):
    """Qualify the Node checksum method from complete copies of its active declaration."""
    if (name != 'src/runtimes/node.rs' or not structure
            or structure.names['fetch_checksum'] != 2 or structure.function_positions is None):
        return {}
    positions = structure.function_positions.get('fetch_checksum', ())
    if len(positions) != 2:
        return {}
    markers = {'#[cfg(feature = "pgp")]': True, '#[cfg(not(feature = "pgp"))]': False}
    offsets, braces = structure.offsets, structure.braces
    _construct_charge(work, len(braces) * (len(braces).bit_length() + 1))
    openings = sorted(braces)
    alternatives = {}
    for position in positions:
        line = bisect.bisect_right(offsets, position)
        start = offsets[line - 1]
        if line < 2 or source[line - 2].strip() not in markers:
            return {}
        active = markers[source[line - 2].strip()]
        if active in alternatives:
            return {}

        cursor = offsets[line - 2] - 1
        steps = 0
        while cursor >= 0 and not structure.code[cursor]:
            _construct_charge(work, 1)
            cursor -= 1
            steps += 1
            if steps > 4096:
                return {}
        if cursor >= 0 and structure.text[cursor] == ']':
            return {}

        at = bisect.bisect_left(openings, start)
        if at == len(openings) or openings[at] - start > 4096:
            return {}
        opening = openings[at]
        last = bisect.bisect_right(offsets, braces[opening])
        candidate = _source_function_candidates(source, [(line, last)], work, structure).get((line, last))
        if candidate is None or candidate[1] != 'fetch_checksum':
            return {}
        _construct_charge(work, 2 * len(braces))
        parents = [parent for parent, end in braces.items() if parent < start < end]
        if len(parents) != 1:
            return {}
        parent, = parents
        parent_line = bisect.bisect_right(offsets, parent)
        if source[parent_line - 1].strip() != 'impl NodeManager {':
            return {}

        header = structure.text[start:opening]
        _construct_charge(work, len(header) + 1)
        if active:
            pattern = r'\s*async fn fetch_checksum\(&self, [A-Za-z_]\w*: &str, [A-Za-z_]\w*: &str\) -> Result<String>\s*'
        else:
            pattern = (r'\s*fn fetch_checksum\(\s*&self,\s*_[A-Za-z_]\w*: &str,'
                       r'\s*_[A-Za-z_]\w*: &str,?\s*\) -> std::future::Ready<Result<String>>\s*')
        if re.fullmatch(pattern, header, re.ASCII) is None:
            return {}
        alternatives[active] = (line, last, parent, opening, candidate[0])

    first, last, parent, opening, prefix = alternatives[True]
    inactive_first, inactive_last, inactive_parent, _, _ = alternatives[False]
    if parent != inactive_parent or (first, last) not in spans:
        return {}
    if not (source[first - 1].isascii() and source[last - 1].isascii()):
        return {}
    low = first, len(source[first - 1]) - len(source[first - 1].lstrip()) + 1
    high = last, len(source[last - 1].rstrip()) + 1
    opening_point = first, opening - offsets[first - 1] + 1
    if opening_point[1] > len(source[first - 1]):
        return {}

    namespace = ('type', ('type', ('crate', 'omg_lib'), ('runtimes', '')), ('node', ''))
    self_type = 'type', namespace, ('NodeManager', '')
    _construct_charge(work, sum(len(owner['regions']) + len(owner['name']) + 1 for owner in inventory))
    copies = {}
    for owner in inventory:
        regions = owner['regions']
        first_region = min(row[0] for row in regions)
        last_region = max(row[2] for row in regions)
        if max(first_region, inactive_first) <= min(last_region, inactive_last):
            return {}
        if max(first_region, first) > min(last_region, last):
            continue
        shape = nominal_method_path(owner['name'])
        if (shape is None or shape.kind != 'M' or shape.namespace != namespace or shape.self_type != self_type
                or shape.trait is not None or shape.type_argument is not None
                or shape.method != ('fetch_checksum', '') or shape.callbacks not in ((), ('',))
                or len(owner['filenames']) != 1 or files.get(owner['filenames'][0]) != name
                or owner.get('branches') or owner.get('mcdc_records')
                or any(len(row) != 8 or row[5:] != [0, 0, 0]
                       or not low <= tuple(row[:2]) < tuple(row[2:4]) <= high for row in regions)):
            return {}
        members = copies.setdefault(shape.copy_identity, {})
        if shape.callbacks in members:
            return {}
        members[shape.callbacks] = owner
    if not copies:
        return {}
    for members in copies.values():
        if set(members) != {(), ('',)}:
            return {}
        constructor, body = members[()], members[('',)]
        quantity = constructor.get('count')
        expected = [first, low[1], first, len(source[first - 1].split('{')[0].rstrip()) + 1, quantity, 0, 0, 0]
        if (type(quantity) is not int or not 0 <= quantity < COUNTER_LIMIT
                or type(body.get('count')) is not int or body['count'] != quantity
                or constructor['regions'] != [expected]
                or [row[4] for row in body['regions'] if tuple(row[:4]) ==
                    (*opening_point, opening_point[0], opening_point[1] + 1)] != [quantity]
                or [row[4] for row in body['regions'] if tuple(row[:4]) ==
                    (last, high[1] - 1, *high)] != [quantity]):
            return {}
    return {(first, last): prefix}

def _compiled_function_groups(name, owners, files, source, work=None, source_structure=None,
                              validated_spans=None, shared_prefixes=None):
    if work is not None:
        _construct_charge(work, len(source) + len(owners))
        if source_structure is None:
            _construct_charge(work, sum(len(line) + 1 for line in source))
        _construct_charge(work, sum(len(owner['filenames']) for owner in owners))
    names = Counter(owner['name'] for owner in owners)
    inventory = [owner for owner in owners if any(
        files.get(path) == name or path.endswith('/' + name) for path in owner['filenames'])]
    by_span = {}
    for owner in inventory:
        if work is not None and validated_spans is None:
            _construct_charge(work, len(owner['regions']))
        span = (source_owner_span(owner, name, files, source) if validated_spans is None
                else validated_spans.get(id(owner)))
        if span is None:
            return None
        by_span.setdefault(span[:2], []).append(owner)
    if shared_prefixes is None:
        if source_structure is None:source_structure=_source_structural_map(source)
        prefixes = source_function_prefixes(source, by_span, work, source_structure)
        if work is not None:
            qualified=closed_pgp_checksum_prefixes(name,source,inventory,files,by_span,source_structure,work)
            if any(span in prefixes and prefixes[span]!=prefix for span,prefix in qualified.items()):raise ValueError('Conflicting conditional method qualification')
            prefixes.update(qualified)
    else:
        if work is not None:
            _construct_charge(work,len(by_span))
        prefixes = {span:shared_prefixes[span] for span in by_span if span in shared_prefixes}

    def reaches_end(owner, end, column):
        for region in reversed(owner['regions']):
            if work is not None:
                _construct_charge(work, 1)
            if region[2] == end and region[3] > column:
                return True
        return False

    valid = {}
    for span, prefix in prefixes.items():
        members = by_span[span]
        end = span[1]
        closing = source[end - 1].rstrip()
        if work is not None:
            _construct_charge(work, len(members) + len(source[end - 1]) + 1)
        if not all(names[owner['name']] == 1 for owner in members):
            continue
        if len(members) > 1:
            if work is not None:
                _construct_charge(work, sum(len(owner['regions']) for owner in members))
            shapes = {tuple(sorted(tuple(row[:4] + row[5:]) for row in owner['regions']))
                      for owner in members}
            if len(shapes) != 1:
                continue
        column = len(closing.encode())
        if all(reaches_end(owner, end, column) for owner in members):
            valid[prefix] = (*span, members)
    return inventory, valid, names


@dataclass(frozen=True)
class AsyncCompiledCopy:
    constructor: dict
    body: dict
    identity: tuple | None = None


@dataclass(frozen=True)
class AsyncFunctionGroup:
    declaration: str
    span: tuple[int, int]
    copies: tuple[AsyncCompiledCopy, ...]
    closing_kinds: dict[int, str]
    source_context: tuple = ()


def guarded_async_context(code, row, modules, work):
    """Bind explicit module scopes and pure cfg guards before the async header."""
    # shortcut: cfg(test) module gates and simple test/feature function gates only; extend with phase fixtures.
    header = row['header']; _construct_charge(work, len(header) + 1)
    fn = header.index('fn')
    if fn == 0 or header[fn - 1] != 'async':
        return None
    start = row['first'] + fn - 1
    if fn > 1 and header[fn - 2] == 'pub':
        start -= 1
    attributes = _boolean_attributes(code, start)
    if attributes is None or any(attribute != ['cfg', '(', 'test', ')'] and not (
            len(attribute) == 6 and attribute[:3] == ['cfg', '(', 'feature']
            and attribute[3] == '=' and attribute[5] == ')'
            and re.fullmatch(r'"[A-Za-z_][A-Za-z0-9_-]{0,63}"', attribute[4])) for attribute in attributes):
        return None
    ancestors = _construct_ancestors(code, start, work)
    if any(opening not in modules for opening in ancestors):
        return None
    _construct_charge(work, sum(len(modules[opening]['header']) + 1 for opening in ancestors))
    scope = _boolean_module(code, {'start': start})
    if scope is None:
        return None
    path, _, _ = scope
    return start, (tuple(path), tuple(tuple(modules[opening]['header']) for opening in reversed(ancestors)),
                   tuple(tuple(attribute) for attribute in attributes))


def inherent_async_type(code, row, implementations):
    implementation = implementations.get(code.parents[row['opening']])
    header = row['header']; fn = header.index('fn')
    if (implementation is None or len(implementation['header']) != 2
            or code.parents[implementation['opening']] is not None
            or _boolean_attributes(code, implementation['first']) != []
            or _boolean_attributes(code, row['first']) != []
            or header[:fn] not in (('async',), ('pub', 'async'))
            or header[fn + 2:fn + 3] != ('(',) or 'where' in header):
        return None
    type_name = implementation['header'][1]
    return type_name if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', type_name) else None


def compiled_async_function_groups(name, owners, files, source, work=None, inventory=None,
                                   owner_counts=None, inherent_lines=(), compiled_groups=None):
    """Bind separate v0 constructor/body owners without merging their counters."""
    work = [20_000_000] if work is None else work
    inventory = _construct_inventory(source, work) if inventory is None else inventory
    if inventory is None:
        return {}
    code = inventory[0]
    result = {}; declarations = []
    closing_kinds = {}
    _construct_charge(work, len(inventory[1]))
    modules = {row['opening']: row for row in inventory[1] if row['kind'] == 'mod'}
    implementations = {}
    if inherent_lines:
        _construct_charge(work, len(inventory[1]))
        implementations = {row['opening']: row for row in inventory[1] if row['kind'] == 'impl'}
    for line, rows in inventory[2].items():
        if len(rows) == 1 and rows[0]['supported']:
            row = rows[0]
            if code.words[row['opening'] - 1] == 'else':
                closing_kinds[line] = 'else'
            elif row['kind'] in ('if', 'for', 'while', 'loop', 'match', 'fn'):
                closing_kinds[line] = row['kind']
    for row in inventory[1]:
        header = row.get('header', ())
        if row['kind'] != 'fn' or 'async' not in header or 'fn' not in header:
            continue
        context = (); start = row['first']
        inherent = None
        if code.parents[row['opening']] in implementations:
            _construct_charge(work, len(header) + len(inherent_lines) + 1)
            first_line = code.position(code.starts[start])[0]
            last_line = code.position(code.ends[row['end']])[0]
            if any(first_line <= line <= last_line for line in inherent_lines):
                inherent = inherent_async_type(code, row, implementations)
        if inherent is not None:
            context = (inherent, tuple(header))
        elif header[0] == '#' or not row['supported'] or code.parents[row['opening']] is not None:
            scoped = guarded_async_context(code, row, modules, work)
            if scoped is None:
                continue
            start, context = scoped
        declaration = header[header.index('fn') + 1]
        first = code.position(code.starts[start])
        opening = code.position(code.starts[row['opening']])
        closing = code.position(code.ends[row['end']])
        span = first[0], closing[0]
        declarations.append((declaration, first, opening, closing, span, context, inherent))
    if not declarations:
        return {}
    spans = [row[4] for row in declarations]
    prefixes = {}
    if compiled_groups is not None:
        if compiled_groups[0] is not owners:
            return {}
        _construct_charge(work,len(spans)+len(compiled_groups[1]))
        compiled_prefixes = {group[:2]:prefix for prefix,group in compiled_groups[1].items()}
        prefixes = {span:compiled_prefixes[span] for span in spans if span in compiled_prefixes}
        spans = [span for span in spans if span not in prefixes]
    if spans:
        prefixes.update(source_function_prefixes(source, spans, work))
    if not prefixes:
        return {}
    if owner_counts is None:
        _construct_charge(work, len(owners))
        owner_counts = Counter(owner['name'] for owner in owners)
    constructors = {}; bodies = {}
    for owner in owners:
        regions = owner['regions']
        _construct_charge(work, 2 * len(regions))
        if compiled_groups is None:
            _construct_charge(work, len(owner['filenames']) + len(regions))
            if source_owner_span(owner, name, files, source) is None:
                continue
        if len(regions) == 1:
            constructors.setdefault(tuple(regions[0][:4]), []).append(owner)
        first = min(tuple(region[:2]) for region in regions)
        last = max(tuple(region[2:4]) for region in regions)
        bodies.setdefault((first, last), []).append(owner)
    for declaration, first, opening, closing, span, context, inherent in declarations:
        if span not in prefixes:
            continue
        parents = []; module_path = context[0] if context and inherent is None else ()
        qualified_name = (*module_path, declaration)
        constructor_candidates = constructors.get((*first, opening[0], opening[1] - 1), ())
        body_candidates = bodies.get((opening, closing), ())
        for owner in constructor_candidates:
            _construct_charge(work, len(owner['name']))
            if inherent is None:
                shape = plain_rust_function_symbol(owner['name'])
                if shape is not None and shape.identifiers[-len(qualified_name):] == qualified_name:
                    parents.append((owner, shape, shape.identity))
            else:
                shape = nominal_method_path(owner['name'])
                count = owner.get('count')
                if (shape is not None and shape.kind == 'M' and not shape.callbacks
                        and shape.method[0] == declaration and shape.self_type[0] == 'type'
                        and shape.self_type[-1][0] == inherent
                        and shape.self_type[1] == shape.namespace
                        and type(count) is int and 0 <= count < COUNTER_LIMIT
                        and owner['regions'][0][4:] == [count, 0, 0, 0]):
                    parents.append((owner, shape, (shape.parent_scope, shape.method)))
        identities = {identity for _, _, identity in parents}
        if len(identities) != 1:
            continue
        if inherent is not None:
            copy_identities = {shape.copy_identity for _, shape, _ in parents}
            if not len(copy_identities) == len(parents) == len(constructor_candidates) == len(body_candidates):
                continue
        copies = []
        for parent, shape, _ in parents:
            children = []
            for owner in body_candidates:
                _construct_charge(work, len(owner['name']) + len(owner['regions']))
                if inherent is None:
                    if not direct_rust_callback_symbol(owner['name'], parent['name'], shape.modules):
                        continue
                else:
                    child = nominal_method_path(owner['name'])
                    count = owner.get('count')
                    if (child is None or child.callbacks != ('',) or child.copy_identity != shape.copy_identity
                            or owner['filenames'] != parent['filenames']
                            or type(count) is not int or not 0 <= count < COUNTER_LIMIT
                            or any(region[5:] != [0, 0, 0] for region in owner['regions'])
                            or sum(tuple(region[:4]) == (closing[0], closing[1] - 1, *closing)
                                   and region[4] == count for region in owner['regions']) != 1
                            or sum(tuple(region[:4]) == (*opening, opening[0], opening[1] + 1)
                                   and region[4] == count for region in owner['regions']) != 1):
                        continue
                if sum(tuple(region[:4]) == (*opening, opening[0], opening[1] + 1)
                       for region in owner['regions']) == 1:
                    children.append(owner)
            if (len(children) != 1 or owner_counts[parent['name']] != 1
                    or owner_counts[children[0]['name']] != 1):
                copies = []
                break
            copies.append(AsyncCompiledCopy(parent, children[0],
                                            shape.copy_identity if inherent is not None else None))
        if not copies:
            continue
        geometry = {tuple(sorted(tuple(region[:4] + region[5:]) for region in copy.body['regions']))
                    for copy in copies}
        if len(geometry) != 1:
            continue
        key = 'async:' + repr((parents[0][2], context))
        if key in result:
            return {}
        result[key] = AsyncFunctionGroup(prefixes[span], span, tuple(copies), closing_kinds, context)
    return result


def fragment_region_states(owner, first, last, source, work):
    """Clip raw regions to identical source bytes, preserving every region state."""
    low, high = (first, 1), (last, len(source[last - 1].encode()) + 1)
    regions = owner['regions']
    _construct_charge(work, len(regions) * (len(regions).bit_length() + 3))
    pieces = []
    for region in regions:
        start, end = max(tuple(region[:2]), low), min(tuple(region[2:4]), high)
        if start < end:
            pieces.append(((start[0] - first, start[1], end[0] - first, end[1], *region[5:]),
                           int(region[4] > 0)))
    pieces.sort()
    return tuple(shape for shape, _ in pieces), tuple(state for _, state in pieces)


def awaited_zero_arg_method(code, line, work):
    if code is None or line < 2:
        return None
    _construct_charge(work, 2 * len(code.starts).bit_length() + 6)
    previous = bisect.bisect_left(code.starts, code.offsets[line - 2])
    current = bisect.bisect_left(code.starts, code.offsets[line - 1])
    if current - previous != 4:
        return None
    words = code.words[previous:current + 2]
    if (len(words) != 6 or words[0] != '.'
            or words[2:] != ['(', ')', '.', 'await']
            or code.position(code.starts[current])[0] != line
            or code.pairs[previous + 2] != previous + 3
            or code.parents[previous] != code.parents[current]
            or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', words[1])):
        return None
    return words[1]


@dataclass(frozen=True)
class CallbackFragmentEvidence:
    states: tuple
    line_states: tuple
    signature: tuple
    witness: dict


@dataclass(frozen=True)
class DeferredSourceFragment:
    target: int
    kind: str
    function_prefix: str


def fixture_callback_forest(source, group, owners, names, counts, inventory, work, loop_cache):
    """Observe one complete fixture call and its closed nested async forest."""
    if inventory is None or len(group[2]) != 1:
        return None
    root, = group[2]
    shape = plain_rust_function_symbol(root['name'])
    if shape is None or shape.identifiers[:-1] != ('omg_lib','cli','tool','tests'):
        return None
    code, rows = inventory[:2]
    _construct_charge(work,2*len(rows))
    definitions = [row for row in rows if row['kind']=='fn' and 'fn' in row['header']
                   and code.position(code.starts[row['first']+row['header'].index('fn')])[0]==group[0]
                   and code.position(code.ends[row['end']])[0]==group[1]]
    if len(definitions) != 1:
        return None
    function, = definitions; header = function['header']; fn = header.index('fn')
    context = _boolean_module(code,{'start':function['first']})
    if header[fn+1] != shape.identifiers[-1] or context is None or context[0] != ['tests'] or 'async' in header:
        return None
    args = ['with_managed_fixture_environment','(','&','path',',','||','{']
    calls = [row for row in rows if row['kind']=='statement' and row['supported']
             and function['opening']<row['first']<=row['end']<function['end']
             and code.parents[row['first']]==function['opening']
             and code.words[row['first']:row['first']+len(args)]==args]
    if len(calls) != 1:
        return None
    call, = calls; opening = call['first']; end = call['end']; brace = opening+6
    _construct_charge(work,len(rows))
    previous = [row for row in rows if row['kind']=='statement' and row['end']==opening-1
                and code.parents[row['first']]==function['opening']]
    if (code.pairs[opening+1]!=end-1 or code.pairs[brace]!=end-2 or len(previous)!=1
            or code.words[previous[0]['first']:opening] != ['let','path','=','std','::','env','::','join_paths',
                    '(','paths',')','.','expect','(','"fixture PATH"',')',';']):
        return None
    box = code.region(opening,end); low, high = box[:2],box[2:]
    _construct_charge(work,end-opening+1)
    lex = {code.region(at,code.pairs[at]):at for at in range(brace,end)
           if code.words[at]=='{' and (at==brace or code.words[at-1]=='async')}
    if len(lex)<2:
        return None
    valid = {}; observed = []
    root_slots = [code.region(opening,opening),code.region(opening+2,opening+3)]
    _construct_charge(work,len(owners))
    typed_root = root['name'][2:]
    for owner in owners:
        symbol = owner['name']; regions = owner['regions']
        _construct_charge(work,len(regions)+len(symbol)+1)
        touching = [row for row in regions if tuple(row[:2])<high and low<tuple(row[2:4])]
        if owner is root:
            role = ()
            if [tuple(row[:4]) for row in touching] != root_slots:
                return None
        else:
            raw_root = plain_rust_function_symbol(symbol) if symbol.endswith(shape.identifiers[-1]) else None
            if raw_root is not None and raw_root.identity==shape.identity:
                return None
            depth = re.match(r'_R((?:NC){1,8})',symbol) if typed_root in symbol else None
            if depth is None or not direct_rust_callback_symbol(symbol,root['name'],shape.modules,len(depth[1])//2):
                if touching:
                    return None
                continue
            if not touching or len(touching)!=len(regions):
                return None
            suffix = symbol[len('_R'+depth[1]+typed_root):]
            role = tuple(re.findall(r'(s[0-9A-Za-z]{0,32}_)?0',suffix)[:len(depth[1])//2])
        count = owner.get('count')
        if (role in valid or names[symbol]!=1 or owner['filenames']!=root['filenames']
                or len(owner['filenames'])!=1 or owner.get('branches') or owner.get('mcdc_records')
                or type(count) is not int or not 0<=count<COUNTER_LIMIT
                or any(len(row)!=8 or row[5:]!=[0,0,0] or type(row[4]) is not int or not 0<=row[4]<COUNTER_LIMIT
                       or not low<=tuple(row[:2])<tuple(row[2:4])<=high for row in touching)):
            return None
        phase = None
        if role:
            phase = (*min(tuple(row[:2]) for row in touching), *max(tuple(row[2:4]) for row in touching))
            if phase not in lex:
                return None
            start, column, last, close_column = phase
            markers = ((start,column,start,column+1),(last,close_column-1,last,close_column))
            if any([row[4] for row in touching if tuple(row[:4])==marker]!=[count] for marker in markers):
                return None
        valid[role] = phase,symbol,count,touching
        observed.extend(touching)
    if () not in valid or len(valid)!=len(lex)+1 or {entry[0] for role,entry in valid.items() if role}!=lex.keys():
        return None
    lexical_roles = {lex[entry[0]]:role for role,entry in valid.items() if role}
    for index,role in lexical_roles.items():
        ancestor = next((lexical_roles[parent] for parent in _construct_ancestors(code,index,work)
                         if parent in lexical_roles),())
        if ancestor != role[:-1]:
            return None
    _construct_charge(work,high[0]-low[0]+1)
    measured = {line:counts[line] for line in range(low[0],high[0]+1) if line in counts}
    if _owner_line_counts({'regions':observed},_ObserverWork(work))!=measured:
        return None
    layout = []; states = []; evidence = []
    for role,(phase,symbol,count,regions) in sorted(valid.items()):
        layout.append((role,tuple((r[0]-low[0],r[1],r[2]-low[0],r[3],*r[5:]) for r in regions)))
        states.extend((int(count>0),*(int(r[4]>0) for r in regions)))
        evidence.append(dict(path=role,name=symbol,count=count,regions=len(regions)))
    bindings = []; mapped_bindings = {}; binding_states = []
    outer_role = lexical_roles[brace]
    statements = {row['first']:row for row in rows if row['kind']=='statement'}
    _construct_charge(work,len(rows))
    ident = re.compile(r'[A-Za-z_]\w*',re.ASCII)
    def retain_statements(parent, *, role=outer_role, ignored=None, iterations=None):
        owned = {id(r) for r in valid[role][3]}
        _construct_charge(work,len(owned))
        binding = parent+1
        while binding in statements and code.parents[binding]==parent:
            row = statements[binding]; last = row['end']
            _construct_charge(work,last-binding+1+len(observed))
            words = code.words[binding:last]
            slot = 1+int(words[1:2]==['mut'])
            local = (len(words)>slot+2 and words[0]=='let' and ident.fullmatch(words[slot])
                     and words[slot+1]=='=')
            direct = (ignored is not None and len(words)>4 and words[1]=='::' and words[3]=='('
                      and ident.fullmatch(words[0]) and ident.fullmatch(words[2]))
            if (not row['supported'] or code.words[last]!=';' or not (local or direct)
                    or {'{','?','!',ignored}.intersection(words)):
                break
            start, column, end_line, end_column = code.region(binding,last)
            raw = [r for r in observed if tuple(r[:2])<(end_line,end_column) and (start,column)<tuple(r[2:4])]
            _construct_charge(work,len(raw)+end_line-start+1)
            if (not raw or any(id(r) not in owned or tuple(r[:2])<(start,column)
                               or tuple(r[2:4])>(end_line,end_column) or iterations is not None and r[4]!=iterations
                               for r in raw)
                    or source[start-1][:column-1].strip() or source[end_line-1][end_column-1:].strip()):
                break
            line_counts = {line:measured[line] for line in range(start,end_line+1) if line in measured}
            if _owner_line_counts({'regions':raw},_ObserverWork(work))!=line_counts:
                break
            bindings.append((row['digest'],tuple(source[start-1:end_line]),
                tuple((r[0]-low[0],r[1],r[2]-low[0],r[3],*r[5:]) for r in raw)))
            mapped_bindings.update((line-low[0],int(value>0)) for line,value in line_counts.items())
            binding_states.extend(int(r[4]>0) for r in raw)
            binding = last+1
        return binding
    next_statement = retain_statements(brace)
    iteration_shape = None
    footer = None
    _construct_charge(work,len(rows))
    loop = next((row for row in rows if row['first']==next_statement and row['kind']=='for'
                 and code.parents[row['opening']]==brace),None)
    if loop is not None:
        line = code.position(code.starts[next_statement])[0]
        authority = literal_pair_loop_fragment(source,group,owners,names,line,line,inventory,work,
                                               normalize_second=True,cache=loop_cache)
        if authority is not None and [item['child'] for item in authority.witness['owners']]==[valid[outer_role][1]]:
            loop_shape = authority.signature
            loop_states = authority.states[0]
            iterations = authority.witness['owners'][0]['binding_counts'][0]
            ignored = loop['header'][4]
            size = len(bindings)
            entry = retain_statements(loop['opening'],ignored=ignored,iterations=iterations)
            phase = entry+5
            child_role = lexical_roles.get(phase)
            async_context = None
            if (child_role is not None and child_role[:-1]==outer_role
                    and code.words[entry+1:phase+1]==['.','block_on','(','async','{']):
                line = code.position(code.starts[entry])[0]
                entry_proof = nested_async_call_entry_fragment(source,group,owners,names,line,line,
                                                               inventory,work,loop_cache=loop_cache)
                if (entry_proof is not None and entry_proof.witness['kind']=='literal-pair-loop-async-call-entry'
                        and [item['child'] for item in entry_proof.witness['owners']]==[valid[child_role][1]]):
                    prior = len(bindings)
                    retain_statements(phase,role=child_role,ignored=ignored,iterations=iterations)
                    if len(bindings)>prior:
                        async_context = entry_proof.signature
                        binding_states.extend(entry_proof.states[0])
            if len(bindings)>size:
                iteration_shape = loop_shape,size,async_context
                binding_states.extend(loop_states)
            tail = statements.get(loop['end']+1)
            if tail is not None and tail['end']==code.pairs[brace]-1:
                at,end_tail = tail['first'],tail['end']
                words = code.words[at:end_tail+1]; _construct_charge(work,len(words)+len(observed))
                if (tail['supported'] and code.parents[at]==brace and len(words) in (12,13)
                        and words[:3]==['assert','!','('] and ident.fullmatch(words[3])
                        and words[4:9]==['.','is_empty','(',')',','] and words[9].startswith('"')
                        and words[10:] in ([')',';'],[',',')',';'])):
                    first,col,last,tail_col = code.region(at,end_tail)
                    close = code.pairs[brace]
                    close_line = code.position(code.starts[close])[0]
                    rows = [r for r in observed if r[0]<=close_line and r[2]>=first]
                    slots = [code.region(at,at+1),code.region(at+3,at+3),code.region(at+5,at+5),code.region(close,close)]
                    owned = {id(r) for r in valid[outer_role][3]}
                    _construct_charge(work,len(owned)+sum(len(text)+1 for text in source[first-1:close_line]))
                    if (len(rows)==len(slots) and {tuple(r[:4]) for r in rows}==set(slots)
                            and all(id(r) in owned and r[4]==valid[outer_role][2] for r in rows)
                            and not source[first-1][:col-1].strip() and not source[last-1][tail_col-1:].strip()
                            and source[close_line-1].strip()=='});'):
                        mapped = {n:measured[n] for n in range(first,close_line+1) if n in measured}
                        if _owner_line_counts({'regions':rows},_ObserverWork(work))==mapped:
                            footer = (first,close_line), (loop_shape,tuple(source[first-1:close_line]),
                                tuple((a-first,b,c-first,d) for a,b,c,d in slots)),loop_states,{
                                    n-first:int(hits>0) for n,hits in mapped.items()}
    entry_signature = (shape.identity,header,previous[0]['digest'],source[low[0]-1],tuple(sorted(valid)),
                       outer_role,iteration_shape)
    entry_states = tuple(int(valid[role][2]>0) for role in sorted(valid))
    prelude = (entry_signature,tuple(bindings)), (*entry_states,*binding_states), mapped_bindings
    if footer is not None:
        span, footer_context, footer_states, mapped = footer
        footer = span, (entry_signature[:-1],footer_context), (*entry_states,*footer_states), mapped
    signature = (shape.identity,header,previous[0]['digest'],call['digest'],
                 tuple(source[low[0]-1:high[0]]),tuple(layout))
    return signature,(low[0],high[0]),tuple(states),{n-low[0]:int(v>0) for n,v in measured.items()},evidence,prelude,footer


_INHERENT_LEAF = re.compile(r'\s*(?:let [A-Za-z_]\w* = async \{|\.with_context\(\|\| format!\(.+\)\)\?)', re.ASCII)


def inherent_async_leaf_entry(source, inventory, phase, owners, names, line, count, work):
    """Bind local entry slots to an inherent async body and its direct child."""
    if inventory is None or not phase.span[0] < line < phase.span[1]:
        return None
    code = inventory[0]
    start = bisect.bisect_left(code.starts,code.offsets[line-1])
    stop = bisect.bisect_left(code.starts,code.offsets[line])
    words = code.words[start:stop]
    _construct_charge(work, phase.span[1]-phase.span[0]+len(words)+1)
    if (not words or sum(text == source[line-1] for text in source[phase.span[0]-1:phase.span[1]]) != 1
            or any(copy.identity is None for copy in phase.copies)):
        return None
    parent = code.parents[start]
    if parent is None or code.words[parent] != '{':
        return None
    outer = code.position(code.starts[parent])
    if (len(words) == 5 and words[0] == 'let' and words[2:] == ['=','async','{']
            and re.fullmatch(r'[A-Za-z_]\w*',words[1],re.ASCII) and code.parents[start+4] == parent):
        end = code.pairs[start+4]
        if code.words[end+1:end+4] != ['.','await',';']:
            return None
        role = 'assigned-async-entry'
        parent_slots = (code.region(start+1,start+1),)
        child_slot = code.region(start+4,start+4)
        child_end = code.position(code.ends[end])
    elif (len(words) == 11 and words[:7] == ['.','with_context','(','||','format','!','(']
          and words[7].startswith('"') and words[7].endswith('"') and words[8:] == [')',')','?']
          and phase.span[0] < line-1 < line+1 < phase.span[1]
          and source[line-2].strip() == '.error_for_status()'
          and source[line].strip().removesuffix(';') == '.bounded_json()'):
        role = 'status-context-entry'
        parent_slots = (code.region(start+1,start+1),code.region(start+10,start+10))
        child_slot = code.region(start+4,start+5)
        child_end = child_slot[2:]
    else:
        return None
    slots = {}; identities = {}; touched = set()
    for owner in owners:
        regions = owner['regions']; _construct_charge(work,len(regions)+1)
        painting = [row for row in regions if owner_covers_lines([row],line,line)]
        if not painting:
            continue
        symbol = owner['name']; _construct_charge(work,len(symbol)+1)
        shape = nominal_method_path(symbol)
        if (shape is None or names[symbol] != 1 or owner.get('branches') or owner.get('mcdc_records')
                or any(row[5:] != [0,0,0] or type(row[4]) is not int or not 0 <= row[4] < COUNTER_LIMIT
                       for row in painting)):
            return None
        slots[id(owner)] = painting
        identities.setdefault(shape.copy_identity,[]).append((owner,shape.callbacks))
    observations = []; states = []; copy_ids = []; ordinals = set(); projected = 0
    for copy in phase.copies:
        body = copy.body
        if min(tuple(row[:2]) for row in body['regions']) != outer:
            return None
        related = identities.get(copy.identity,())
        if len(related) != 2 or id(body) not in slots:
            return None
        (child, ordinal), = ((owner,path) for owner,path in related if owner is not body)
        parent_rows = slots[id(body)]; child_rows = slots[id(child)]
        child_count = child.get('count'); child_regions = child['regions']
        _construct_charge(work,len(body['regions'])+3*len(child_regions)+len(parent_rows)+1)
        if (ordinal[:1] != ('',) or len(ordinal) != 2 or child['filenames'] != body['filenames']
                or type(child_count) is not int or not 0 <= child_count < COUNTER_LIMIT
                or [tuple(row[:4]) for row in parent_rows] != list(parent_slots)
                or child_rows != [[*child_slot,child_count,0,0,0]]
                or any(not child_slot[:2] <= tuple(row[:2]) < tuple(row[2:4]) <= child_end
                       or len(row)!=8 or row[5:] != [0,0,0] for row in child_regions)
                or (role == 'assigned-async-entry' and [row[4] for row in child_regions
                       if tuple(row[:4]) == (child_end[0],child_end[1]-1,*child_end)] != [child_count])):
            return None
        touched.update((id(body),id(child))); ordinals.add(ordinal)
        hits = [row[4] for row in parent_rows+child_rows]
        projected += max(hits)
        states.append(tuple(int(value>0) for value in (copy.constructor['count'],body['count'],child_count,*hits)))
        copy_ids.append(copy.identity)
        observations.append(dict(constructor=copy.constructor['name'],body=body['name'],child=child['name'],hits=hits))
    if touched != slots.keys() or len(ordinals) != 1 or projected != count:
        return None
    geometry = (role, next(iter(ordinals)), tuple(row[1::2] for row in parent_slots), child_slot[1::2])
    return geometry, states, copy_ids, observations


_RESULT_TEST_SIGNATURE = ('#','[','test',']','fn','<declaration>','(',')','->',
    'anyhow','::','Result','<','(',')','>')
_RESULT_CLOSURE = ('||','->','anyhow','::','Result','<','(',')','>')


def environment_result_callback(code, function, callback):
    opening = callback['opening']
    parent = code.parents[opening]
    return (parent is not None and code.words[parent]=='('
        and code.parents[parent]==function['opening']
        and code.words[parent-3:parent]==['temp_env','::','with_var']
        and tuple(code.words[opening-len(_RESULT_CLOSURE):opening])==_RESULT_CLOSURE
        and code.words[callback['end']+1:function['end']]==[',',')'])


def zero_arg_callback_fragment(source, group, owners, name_counts, first, last, inventory, work,
                               *, caller_entry=False, single_binding=False, phase_cache=None,
                               environment_test=False):
    """Prove fragment execution through a uniquely source-bound direct callback."""
    if single_binding and caller_entry or environment_test and (caller_entry or single_binding):
        return None
    if inventory is None:
        return None
    code = inventory[0]
    cache = {} if phase_cache is None else phase_cache
    source_key = ('callback-source', id(code), *group[:2])
    _construct_charge(work, 1)
    if source_key not in cache:
        _construct_charge(work, len(inventory[1]))
        cache[source_key] = [
            row for row in inventory[1] if row['kind'] == 'fn' and 'fn' in row['header']
            and code.position(code.starts[row['first'] + row['header'].index('fn')])[0] == group[0]
            and code.position(code.ends[row['end']])[0] == group[1]
        ]
    functions = cache[source_key]
    if len(functions) != 1:
        return None
    function = functions[0]; header = function['header']; fn = header.index('fn')
    if environment_test:
        if ((*header[:fn+1],'<declaration>',*header[fn+2:])!=_RESULT_TEST_SIGNATURE
                or (context:=_boolean_module(code,{'start':function['first']})) is None
                or context[:2]!=(['tests'],['tests'])):
            return None
    caller_scope = None
    if caller_entry:
        if first != last or list(header[fn:]) != ['fn', header[fn + 1], '(', ')']:
            return None
        attributes = _boolean_attributes(code, function['first'] + fn)
        scope = _boolean_module(code, {'start': function['first'] + fn})
        if (attributes is None or ['test'] not in attributes or scope is None
                or any(attribute not in (['test'], ['cfg', '(', 'unix', ')']) for attribute in attributes)):
            return None
        line = source[first - 1]
        _construct_charge(work, group[1] - group[0] + 1)
        _construct_charge(work, len(line) + sum(len(value) + 1 for value in source[group[0]-1:group[1]]))
        call = re.fullmatch(r'[ \t]*(?P<callee>[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)'
                           r'\([ \t]*(?P<argument>&[A-Za-z_][A-Za-z0-9_]*)[ \t]*,[ \t]*\|\|[ \t]*\{[ \t]*', line)
        if call is None or sum(value == line for value in source[group[0]-1:group[1]]) != 1:
            return None
        entry_slots = tuple((first, call.start(part) + 1, first, call.end(part) + 1)
                            for part in ('callee', 'argument'))
        caller_scope = (tuple(scope[0]), tuple(scope[1]), tuple(tuple(value) for value in attributes))
    elif list(header[:fn]) not in ([], ['pub'], ['pub', '(', 'crate', ')'], ['#', '[', 'test', ']']):
        return None
    callbacks_key = ('callback-openings', id(code), function['opening'], single_binding, environment_test)
    if callbacks_key not in cache:
        _construct_charge(work, len(inventory[1]))
        cache[callbacks_key] = [
            (code.position(code.starts[row['opening']])[0], code.position(code.ends[row['end']])[0], row)
            for row in inventory[1] if row['opening'] is not None
            and function['opening'] < row['opening'] < row['end'] < function['end']
            and (environment_result_callback(code,function,row) if environment_test else
                 code.words[row['opening'] - 1] == '||' if not single_binding else
                 row['opening'] >= 3
                 and code.words[row['opening'] - 3] == code.words[row['opening'] - 1] == '|'
                 and re.fullmatch(r'[A-Za-z_]\w*', code.words[row['opening'] - 2]) is not None)
            and code.parents[row['opening']] is not None
            and code.words[code.parents[row['opening']]] == '('
        ]
    _construct_charge(work, len(cache[callbacks_key]) + 1)
    candidates = [row for low, high, row in cache[callbacks_key] if low <= first <= last <= high]
    if len(candidates) != 1:
        return None
    callback = candidates[0]
    if caller_entry:
        call_parent = code.parents[callback['opening']]
        if code.parents[call_parent] != function['opening']:
            return None
    argument = callback['opening'] - (len(_RESULT_CLOSURE) if environment_test else 3 if single_binding else 1)
    if single_binding:
        if code.parents[code.parents[callback['opening']]] != function['opening']:
            return None
        entry_only = first == last == code.position(code.starts[callback['opening']])[0]
        control = []; fragment_tokens = ()
        if not entry_only:
            _construct_charge(work,len(inventory[1]))
            fragment_rows = [row for row in inventory[1] if row['kind']=='statement'
                and code.position(code.starts[row['first']])[0] == first
                and code.position(code.starts[row['end']])[0] == last
                and callback['opening'] < row['first'] <= row['end'] < callback['end']]
            if len(fragment_rows) != 1:
                return None
            _construct_charge(work,len(inventory[1]))
            by_opening = {row['opening']:row for row in inventory[1] if row['opening'] is not None}
            for opening_token in _construct_ancestors(code, fragment_rows[0]['first'], work):
                if opening_token == callback['opening']:
                    break
                construct = by_opening.get(opening_token)
                if construct is None:
                    return None
                control.append(tuple(construct['header']))
            else:
                return None
            fragment_tokens = tuple(code.words[fragment_rows[0]['first']:fragment_rows[0]['end']+1])
        _construct_charge(work, len(fragment_tokens)+sum(len(value) for value in control))
    if argument > 0 and code.words[argument - 1] == 'move':
        argument -= 1
    # A closure starts an argument; boolean OR does not.
    if argument == 0 or code.words[argument - 1] not in ('(', ','):
        return None
    if code.parents[argument] != code.parents[callback['opening']]:
        return None
    if caller_entry:
        _construct_charge(work, 2 * (len(code.starts).bit_length() + 1))
        start = bisect.bisect_left(code.starts, code.offsets[first - 1])
        prefix = tuple(code.words[start:callback['opening'] + 1])
    else:
        prefix = tuple(code.words[function['opening'] + 1:callback['opening']])
    _construct_charge(work, len(prefix) + len(header))
    if not caller_entry and any(word in ('!', '#') for word in prefix):
        if not environment_test:
            return None
        assertion = ('assert','!','(','!','crate','::','core','::','privilege','::','is_root','(',')',')',';')
        occurrences = [at for at in range(len(prefix)) if prefix[at:at+len(assertion)]==assertion]
        _construct_charge(work,len(prefix)*len(assertion))
        if (len(occurrences)!=1 or prefix.count('!')!=2 or '#' in prefix
                or code.parents[function['opening']+1+occurrences[0]]!=function['opening']):
            return None
    opening = code.position(code.starts[callback['opening']])
    closing = code.position(code.ends[callback['end']])
    body_opening = code.position(code.starts[function['opening']])
    header_end = code.position(code.ends[function['opening'] - 1])
    leading = len(source[group[0] - 1]) - len(source[group[0] - 1].lstrip()) + 1
    function_start = group[0], leading
    assertion_slot = None
    if environment_test:
        if first != last:
            return None
        if source[first-1].strip()=='assert!(':
            _construct_charge(work,len(code.starts).bit_length()+3)
            token = bisect.bisect_left(code.starts,code.offsets[first-1])
            if (code.words[token:token+3]!=['assert','!','(']
                    or code.parents[token]!=callback['opening']
                    or code.pairs[token+2]+1>=callback['end']
                    or code.words[code.pairs[token+2]+1]!=';'):
                return None
            assertion_slot = (*code.position(code.starts[token]),*code.position(code.ends[token+1]))
        elif opening[0]!=first or source[first-1].strip()!='|| -> anyhow::Result<()> {':
            return None
    states = []; line_states = []; identities = []; geometries = []; witnesses = []
    bound = {id(parent) for parent in group[2]}; children_bound = set()
    for parent in group[2]:
        shape = plain_rust_function_symbol(parent['name'])
        if shape is None or shape.identifiers[-1] != header[fn + 1] or name_counts[parent['name']] != 1:
            return None
        if caller_entry and tuple(shape.identifiers[-len(caller_scope[0])-1:]) != (*caller_scope[0], header[fn+1]):
            return None
        parent_entries = [row for row in parent['regions']
                          if tuple(row[:2]) == function_start
                          and tuple(row[2:4]) in (header_end, body_opening)]
        if (type(parent.get('count')) is not int or not 0 <= parent['count'] < COUNTER_LIMIT
                or len(parent_entries) != 1 or parent_entries[0][4] != parent['count']):
            return None
        candidate_key = (id(code), id(owners), parent['name'], shape.modules, opening, closing)
        if phase_cache is None or candidate_key not in cache:
            children = []
            candidates = owners
            if phase_cache is not None:
                boundary_key = ('owner-boundaries',id(owners))
                if boundary_key not in cache:
                    boundaries = {}
                    _construct_charge(work,len(owners))
                    for owner in owners:
                        _construct_charge(work,2*len(owner['regions'])+1)
                        span=(min(tuple(row[:2]) for row in owner['regions']),
                              max(tuple(row[2:4]) for row in owner['regions']))
                        boundaries.setdefault(span,[]).append(owner)
                    cache[boundary_key] = boundaries
                candidates = cache[boundary_key].get((opening,closing),())
            for owner in candidates:
                _construct_charge(work, len(owner['name']) + len(owner['regions']))
                if (direct_rust_callback_symbol(owner['name'], parent['name'], shape.modules)
                        and min(tuple(row[:2]) for row in owner['regions']) == opening
                        and max(tuple(row[2:4]) for row in owner['regions']) == closing):
                    children.append(owner)
            if phase_cache is not None:
                cache[candidate_key] = tuple(children)
        else:
            _construct_charge(work,len(parent['name'])+1)
            children = cache[candidate_key]
        if len(children) != 1:
            return None
        child = children[0]
        entries = [row for row in child['regions']
                   if tuple(row[:4]) == (*opening, opening[0], opening[1] + 1)]
        if (child['filenames'] != parent['filenames'] or name_counts[child['name']] != 1
                or id(child) in children_bound or type(child.get('count')) is not int
                or not 0 <= child['count'] < COUNTER_LIMIT
                or len(entries) != 1 or entries[0][4] != child['count']):
            return None
        if environment_test and any(owner.get('branches') or owner.get('mcdc_records')
                                    for owner in (parent,child)):
            return None
        children_bound.add(id(child)); bound.add(id(child)); identities.append(shape.identity)
        parent_geometry, parent_states = fragment_region_states(parent, first, last, source, work)
        child_geometry, child_states = fragment_region_states(child, first, last, source, work)
        if caller_entry:
            context_geometry, context_states = (), ()
            _construct_charge(work, len(parent['regions']) + len(child['regions']))
            overlaps = [row for row in parent['regions'] if owner_covers_lines([row], first, first)]
            if (len(overlaps) != 2 or {tuple(row[:4]) for row in overlaps} != set(entry_slots)
                    or any(len(row) != 8 or list(row[5:]) != [0, 0, 0] for row in overlaps)
                    or len(entries[0]) != 8 or list(entries[0][5:]) != [0, 0, 0]
                    or any(owner_covers_lines([row], first, first) and row is not entries[0]
                           for row in child['regions'])):
                return None
        else:
            context_geometry, context_states = fragment_region_states(parent, group[0], opening[0], source, work)
        if not child_geometry:
            return None
        if assertion_slot is not None and (parent_geometry or child_geometry!=(
                (0,assertion_slot[1],0,assertion_slot[3],0,0,0),)):
            return None
        geometries.append((parent_geometry, child_geometry, context_geometry))
        states.append((int(parent['count'] > 0), int(child['count'] > 0),
                       *context_states, *parent_states, *child_states))
        _construct_charge(work, (last - first + 1) * (len(parent['regions']) + len(child['regions'])))
        line_states.append(tuple(int(any(row[4] > 0 and owner_covers_lines([row], line, line)
            for owner in (parent, child) for row in owner['regions'])) for line in range(first, last + 1)))
        witnesses.append(dict(parent=parent['name'], child=child['name'],
                              parent_entry=int(parent['count'] > 0), child_entry=int(child['count'] > 0)))
    if len(set(identities)) != 1 or len(set(geometries)) != 1:
        return None
    if phase_cache is not None:
        footprint_key = ('owner-line-footprints', id(owners))
        if footprint_key not in phase_cache:
            footprint = {}
            _construct_charge(work,len(owners))
            for owner in owners:
                for row in owner['regions']:
                    _construct_charge(work,row[2]-row[0]+2)
                    for line in range(row[0],row[2]+1):
                        if owner_covers_lines([row],line,line):
                            footprint.setdefault(line,set()).add(id(owner))
            phase_cache[footprint_key] = footprint
        footprint = phase_cache[footprint_key]
        _construct_charge(work,last-first+1+sum(len(footprint.get(line,())) for line in range(first,last+1)))
        if any(footprint.get(line,set()) - bound for line in range(first,last+1)):
            return None
    else:
        _construct_charge(work, sum(len(owner['regions']) for owner in owners) * (last - first + 1))
        if any(id(owner) not in bound and any(owner_covers_lines([row], line, line)
               for row in owner['regions'] for line in range(first, last + 1)) for owner in owners):
            return None
    kind = 'zero-arg-callback-call-entry' if caller_entry else 'zero-arg-callback-fragment'
    if single_binding:
        kind = 'single-bound-callback-entry' if entry_only else 'single-bound-callback-fragment'
    signature = (kind, identities[0], tuple(header), prefix, geometries[0])
    if single_binding:
        signature += (tuple(control), fragment_tokens)
    if caller_entry:
        signature += (caller_scope,)
    witness = dict(kind=kind, owners=witnesses,
        callback_span=[list(opening), list(closing)],
        context_sha256=hashlib.sha256(repr(signature if caller_entry or single_binding else signature[:-1]).encode()).hexdigest(),
        parent_geometry=[list(row) for row in geometries[0][0]],
        child_geometry=[list(row) for row in geometries[0][1]],
        parent_context_geometry=[list(row) for row in geometries[0][2]],
        limitation='Fragment execution only; no argument-value or callee-semantic equivalence')
    if caller_entry:
        witness['caller_scope'] = caller_scope
        witness['parent_entry_slots'] = entry_slots
    return CallbackFragmentEvidence(tuple(states), tuple(line_states), signature, witness)


def nested_async_call_entry_fragment(source, group, owners, name_counts, first, last, inventory, work,
                                     *, loop_cache=None):
    """Prove one direct async method-call entry inside a proved test callback."""
    if inventory is None or first != last:
        return None
    code, rows = inventory[:2]
    _construct_charge(work, len(source[first-1]))
    call = re.fullmatch(r'[ \t]*(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\.'
                       r'(?P<method>[A-Za-z_][A-Za-z0-9_]*)\([ \t]*async[ \t]*\{[ \t]*',
                       source[first-1])
    if call is None:
        return None
    _construct_charge(work, len(rows) * (2 * len(source).bit_length() + 4))
    outers = [row for row in rows if row['opening'] is not None
              and code.words[row['opening']-1] == '||'
              and code.position(code.starts[row['opening']])[0] < first
              <= code.position(code.ends[row['end']])[0]]
    if len(outers) != 1:
        return None
    outer = outers[0]
    outer_line = code.position(code.starts[outer['opening']])[0]
    _construct_charge(work, len(rows) * (len(source).bit_length() + 4))
    phases = [row for row in rows if row['opening'] is not None
              and code.words[row['opening']-1] == 'async'
              and code.position(code.starts[row['opening']])[0] == first
              and outer['opening'] < row['opening'] < row['end'] < outer['end']]
    if len(phases) != 1:
        return None
    phase = phases[0]; paren = code.parents[phase['opening']]
    if (paren is None or code.words[paren] != '('
            or tuple(code.words[paren+1:phase['opening']]) != ('async',)):
        return None
    # Resolve the direct lexical container before spending authority work.
    inside_literal_loop = code.parents[paren] != outer['opening']
    container = outer
    if inside_literal_loop:
        loops = [row for row in rows if row['kind'] == 'for' and row['opening'] is not None
                 and outer['opening'] < row['opening'] < phase['opening']
                     < phase['end'] < row['end'] < outer['end']]
        if len(loops) != 1:
            return None
        container = loops[0]
        loop_line = code.position(code.starts[container['first']])[0]
        authority = literal_pair_loop_fragment(source, group, owners, name_counts,
            loop_line, loop_line, inventory, work, normalize_second=True, cache=loop_cache)
    else:
        authority = zero_arg_callback_fragment(source, group, owners, name_counts,
            outer_line, outer_line, inventory, work, caller_entry=True)
    if authority is None:
        return None
    if code.parents[paren] != container['opening']:
        return None
    _construct_charge(work, outer['end'] - outer['opening'] + 1)
    low = code.position(code.starts[outer['opening']])[0]
    high = code.position(code.ends[outer['end']])[0]
    _construct_charge(work, high-low+1)
    _construct_charge(work, sum(len(value)+1 for value in source[low-1:high]))
    if sum(value == source[first-1] for value in source[low-1:high]) != 1:
        return None
    opening = code.position(code.starts[phase['opening']])
    closing = code.position(code.ends[phase['end']])
    if opening != (first, source[first-1].index('{') + 1):
        return None
    slots = tuple((first, call.start(part)+1, first, call.end(part)+1)
                  for part in ('receiver', 'method'))
    _construct_charge(work, len(owners))
    by_name = {owner['name']: owner for owner in owners}
    bound = set(); nested_bound = set(); geometries = []; states = []; lines = []; witnesses = []
    for index, witness in enumerate(authority.witness['owners']):
        root = by_name[witness['parent']]; parent = by_name[witness['child']]
        shape = plain_rust_function_symbol(root['name'])
        children = []
        for owner in owners:
            _construct_charge(work, len(owner['name']) + len(owner['regions']))
            if (direct_rust_callback_symbol(owner['name'], root['name'], shape.modules, 2)
                    and min(tuple(row[:2]) for row in owner['regions']) == opening
                    and max(tuple(row[2:4]) for row in owner['regions']) == closing):
                children.append(owner)
        if len(children) != 1:
            return None
        child = children[0]
        _construct_charge(work, len(child['regions']) + len(parent['regions']) + len(root['regions']))
        if any(owner_covers_lines([row], first, first) for row in root['regions']):
            return None
        entries = [row for row in child['regions'] if owner_covers_lines([row], first, first)]
        painted = [row for row in parent['regions'] if owner_covers_lines([row], first, first)]
        if (child['filenames'] != parent['filenames'] or name_counts[child['name']] != 1
                or id(child) in nested_bound or type(child.get('count')) is not int
                or not 0 <= child['count'] < COUNTER_LIMIT or len(entries) != 1
                or tuple(entries[0][:4]) != (*opening, first, opening[1]+1)
                or entries[0][4] != child['count'] or len(entries[0]) != 8
                or list(entries[0][5:]) != [0, 0, 0]
                or len(painted) != 2 or {tuple(row[:4]) for row in painted} != set(slots)
                or any(len(row) != 8 or list(row[5:]) != [0, 0, 0] for row in painted)):
            return None
        if inside_literal_loop and (child['count'] != witness['binding_counts'][0]
                or any(row[4] != child['count'] for row in painted)):
            return None
        nested_bound.add(id(child)); bound.update((id(root), id(parent), id(child)))
        parent_geometry, parent_states = fragment_region_states(parent, first, last, source, work)
        child_geometry, child_states = fragment_region_states(child, first, last, source, work)
        geometries.append((parent_geometry, child_geometry))
        states.append((*authority.states[index], int(child['count'] > 0), *parent_states, *child_states))
        lines.append((int(any(row[4] > 0 for row in (*painted, *entries))),))
        witnesses.append(dict(parent=root['name'], outer=parent['name'], child=child['name'],
                              async_entry=int(child['count'] > 0)))
    if len(set(geometries)) != 1:
        return None
    _construct_charge(work, len(owners))
    _construct_charge(work, sum(len(owner['regions']) for owner in owners))
    if any(id(owner) not in bound and any(owner_covers_lines([row], first, first)
           for row in owner['regions']) for owner in owners):
        return None
    kind = 'literal-pair-loop-async-call-entry' if inside_literal_loop else 'nested-async-call-entry'
    signature = (kind, authority.signature,
                 call.group('receiver'), call.group('method'), geometries[0])
    witness = dict(kind=kind, owners=witnesses,
        outer_entry=authority.witness, async_span=[list(opening), list(closing)],
        context_sha256=hashlib.sha256(repr(signature).encode()).hexdigest(),
        parent_geometry=geometries[0][0], child_geometry=geometries[0][1],
        limitation='Caller entry only; no setup, argument-value, callee or async-body equivalence')
    return CallbackFragmentEvidence(tuple(states), tuple(lines), signature, witness)



def literal_pair_loop_fragment(source, group, owners, name_counts, first, last, inventory, work,
                               *, normalize_second=False, cache=None):
    """Prove only literal pair-array evaluation and bindings in a direct test callback."""
    if inventory is None or not 1 <= first <= last <= len(source) or last-first > 65 or type(normalize_second) is not bool:
        return None
    code, rows = inventory[:2]
    _construct_charge(work, len(rows))
    loops = [row for row in rows if row['kind'] == 'for' and row['opening'] is not None
             and code.position(code.starts[row['first']])[0] <= first <= last
                 <= code.position(code.ends[row['opening']-1])[0]]
    if len(loops) != 1:
        return None
    loop = loops[0]
    cache = {} if cache is None else cache
    _construct_charge(work, len(group[2]) + 1)
    key = (id(code), id(owners), id(name_counts), group[:2], tuple(id(owner) for owner in group[2]),
           loop['opening'], normalize_second)
    if key not in cache:
        cache[key] = literal_pair_loop_authority(source, group, owners, name_counts, inventory,
                                                 loop, work, normalize_second)
    prepared = cache[key]
    if prepared is None:
        return None
    states, context, evidence = prepared
    header_first = evidence['header_range'][0]
    signature = (*context, (first-header_first, last-header_first))
    roles = [copy['raw_roles'] for copy in evidence['owners']]
    _construct_charge(work, (last-first+1) * sum(len(rows) for rows in roles))
    line_states = tuple(tuple(int(any(row[4] > 0 and owner_covers_lines([row], line, line)
        for row in rows)) for line in range(first, last+1)) for rows in roles)
    witness = dict(evidence, fragment_range=[first, last],
        context_sha256=hashlib.sha256(repr(signature).encode()).hexdigest())
    return CallbackFragmentEvidence(states, line_states, signature, witness)


def literal_pair_loop_authority(source, group, owners, name_counts, inventory, loop, work, normalize_second):
    code, rows = inventory[:2]
    header = loop['header']
    header_first = code.position(code.starts[loop['first']])[0]
    line = source[header_first-1]
    _construct_charge(work, len(line))
    header_line = re.fullmatch(r'[ \t]*for[ \t]+\((?P<left>[A-Za-z][A-Za-z0-9_]*),[ \t]*'
        r'(?P<right>[A-Za-z][A-Za-z0-9_]*)\)[ \t]+in[ \t]+(?P<array>\[)[ \t]*', line)
    if header_line is None or header_line['left'] == header_line['right']:
        return None
    if (header[:8] != ('for', '(', header_line['left'], ',', header_line['right'], ')', 'in', '[')
            or header[-1:] != (']',) or not 6 <= len(header)-9 <= 64*6
            or (len(header)-9) % 6):
        return None
    pairs = []
    for at in range(8, len(header)-1, 6):
        item = header[at:at+6]
        _construct_charge(work, sum(len(word)+1 for word in item))
        literal = r'"[\x20-\x21\x23-\x5b\x5d-\x7e]{0,256}"'
        if (item[0] != '(' or item[2] != ',' or item[4:] != (')', ',')
                or re.fullmatch(literal, item[1]) is None
                or re.fullmatch(literal, item[3]) is None):
            return None
        pairs.append((item[1], item[3]))
    outers = [row for row in rows if row['opening'] is not None
              and code.words[row['opening']-1] == '||'
              and row['opening'] < loop['first'] < loop['end'] < row['end']]
    if len(outers) != 1:
        return None
    outer = outers[0]
    if code.parents[loop['first']] != outer['opening'] or code.parents[loop['opening']] != outer['opening']:
        return None
    outer_line = code.position(code.starts[outer['opening']])[0]
    outer_end = code.position(code.ends[outer['end']])[0]
    _construct_charge(work, outer_end-outer_line+1)
    if sum(value == line for value in source[outer_line-1:outer_end]) != 1:
        return None
    authority = zero_arg_callback_fragment(source, group, owners, name_counts,
        outer_line, outer_line, inventory, work, caller_entry=True)
    if authority is None:
        return None
    start = code.position(code.starts[loop['first']])
    array_end = code.position(code.ends[loop['opening']-1])
    expected = ((header_first, header_line.start('left')+1, header_first, header_line.end('left')+1),
                (header_first, header_line.start('right')+1, header_first, header_line.end('right')+1),
                (header_first, header_line.start('array')+1, *array_end))
    tuple_spans = []
    for index in range(len(pairs)):
        opening = loop['first']+8+6*index
        low = code.position(code.starts[opening])
        high = code.position(code.ends[opening+4])
        if low[0] != header_first+index+1 or high[0] != low[0]:
            return None
        tuple_spans.append((*low, *high))
    if array_end[0] != header_first+len(pairs)+1:
        return None
    # LLVM22 paints all but the final tuple separately under the array region.
    expected += tuple(tuple_spans[:-1])
    for token, role in ((loop['first']+2, expected[0]), (loop['first']+4, expected[1])):
        if (*code.position(code.starts[token]), *code.position(code.ends[token])) != role:
            return None
    if (code.position(code.starts[loop['first']+7]) != expected[2][:2]
            or code.words[loop['opening']-1] != ']' or array_end[0] <= header_first):
        return None
    closing_line = source[array_end[0]-1]
    _construct_charge(work, len(closing_line))
    if re.fullmatch(r'[ \t]*\][ \t]*\{[ \t]*', closing_line) is None:
        return None
    header_limit = array_end[0], len(closing_line.encode())+1
    def overlaps(row):
        return tuple(row[:2]) < header_limit and start < tuple(row[2:4])
    _construct_charge(work, len(owners))
    by_name = {owner['name']: owner for owner in owners}
    allowed = set(); states = []; geometries = []; copies = []
    for index, witness in enumerate(authority.witness['owners']):
        parent = by_name[witness['parent']]; child = by_name[witness['child']]
        _construct_charge(work, len(child['regions']) + len(parent['regions']))
        if any(overlaps(row) for row in parent['regions']):
            return None
        selected = [row for row in child['regions'] if overlaps(row)]
        if (len(selected) != len(expected) or {tuple(row[:4]) for row in selected} != set(expected)
                or any(len(row) != 8 or row[5:] != [0, 0, 0]
                       or type(row[4]) is not int or not 0 <= row[4] < COUNTER_LIMIT for row in selected)):
            return None
        roles = [next(row for row in selected if tuple(row[:4]) == span) for span in expected]
        if (roles[0][4] != roles[1][4] or roles[0][4] != len(pairs)*roles[2][4]
                or roles[2][4] > child['count']
                or any(row[4] != roles[2][4] for row in roles[3:])):
            return None
        geometry = tuple((row[0]-header_first, row[1], row[2]-header_first,
            row[3] - (len(pairs[index-3][1])-2 if normalize_second and index >= 3 else 0),
            *row[5:]) for index, row in enumerate(roles))
        geometries.append(geometry); allowed.add(id(child))
        bits = tuple(int(row[4] > 0) for row in roles)
        states.append((*authority.states[index], *bits))
        copies.append(dict(parent=parent['name'], child=child['name'],
                           binding_counts=[roles[0][4], roles[1][4]], array_count=roles[2][4],
                           raw_roles=roles))
    _construct_charge(work, sum(len(owner['regions']) for owner in owners))
    if (not geometries or len(set(geometries)) != 1 or any(id(owner) not in allowed
            and any(overlaps(row) for row in owner['regions']) for owner in owners)):
        return None
    first_values = tuple(item[0] for item in pairs)
    second_values = tuple('<inert-second-literal>' if normalize_second else item[1] for item in pairs)
    signature = ('literal-pair-loop-header', authority.signature,
                 header_line['left'], header_line['right'], first_values, second_values, geometries[0])
    witness = dict(kind='literal-pair-loop-header', owners=copies, outer_entry=authority.witness,
        header_range=[header_first, array_end[0]], first_literals=first_values,
        second_literals=[item[1] for item in pairs], normalized_inert_second_literals=normalize_second,
        geometry=geometries[0],
        limitation='Literal pair-array/tuple evaluation and exact bindings only; no callback-body, string-value use or manager-operation equivalence')
    return tuple(states), signature, witness



def biased_join_result_fragment(source, group, owners, name_counts, first, last, inventory, work,
                                *, expansions=None, loop_cache=None, cache=None):
    """Bind completed results or exact timer states, never expanded join internals."""
    if (inventory is None or not 1<=first<=last<=len(source) or last-first>7
            or type(expansions) is not list or expansions):
        return None
    code, rows = inventory[:2]
    _construct_charge(work, len(source[first-1])+len(group[2])+1)
    pattern = re.compile(r'[ \t]*let[ \t]+\((?P<left>[A-Za-z_][A-Za-z0-9_]*),[ \t]*'
        r'(?P<right>[A-Za-z_][A-Za-z0-9_]*)\)[ \t]*=[ \t]*(?P<macro>tokio::join!)\([ \t]*')
    cache = {} if cache is None else cache
    identity=(id(code),id(owners),id(name_counts),group[:2],tuple(id(owner) for owner in group[2]))
    _construct_charge(work,len(cache)*(len(group[2])+5))
    ready=[value for key,value in cache.items() if key[:-1]==identity and value is not None
           and value.witness['timer_source_range'][0]<=first<=last<=value.witness['timer_source_range'][1]]
    if len(ready)>1:
        return None
    if ready:
        prepared=ready[0]; macro_first=prepared.witness['header_source_line']
    else:
        if first == last and (source[first-1].lstrip().startswith('if ') or source[first-1].strip()=='}'):
            return joined_async_condition(source, owners, first, inventory, work,
                [value for key,value in cache.items() if key[:-1]==identity and value is not None])
        if first == last and source[first-1].strip()=='});':
            return joined_async_phase_completion(source,owners,first,work,
                [value for key,value in cache.items() if key[:-1]==identity and value is not None])
        header=pattern.fullmatch(source[first-1]);macro_first=first
        if header is None:
            _construct_charge(work,len(rows))
            candidates=[row for row in rows if row['kind']=='statement'
                and code.position(code.starts[row['first']])[0]<=first<=last<=code.position(code.ends[row['end']])[0]
                and pattern.fullmatch(source[code.position(code.starts[row['first']])[0]-1])]
            if len(candidates)!=1:
                return joined_async_statement(source,owners,first,last,inventory,work,
                    [value for key,value in cache.items() if key[:-1]==identity and value is not None])
            macro_first=code.position(code.starts[candidates[0]['first']])[0]
            header=pattern.fullmatch(source[macro_first-1])
        if header['left']==header['right']:
            return None
        key=(*identity,macro_first)
        if key not in cache:
            # Inputs are immutable and authenticated for this comparison; no global cache.
            cache[key]=biased_join_result_authority(source,group,owners,name_counts,macro_first,inventory,
                                                    work,header,loop_cache)
        prepared=cache[key]
    if prepared is None:
        return None
    if first==last==macro_first:
        return prepared
    timer_first,timer_last=prepared.witness['timer_source_range']
    if not timer_first<=first<=last<=timer_last:
        return None
    timer_rows=[copy['timer_regions'] for copy in prepared.witness['owners']]
    _construct_charge(work,(last-first+1)*sum(len(rows) for rows in timer_rows))
    line_states=tuple(tuple(int(any(row[4]>0 and owner_covers_lines([row],line,line)
        for row in rows)) for line in range(first,last+1)) for rows in timer_rows)
    signature=(*prepared.signature,'unchanged-owned-timer',(first-timer_first,last-timer_first))
    witness=dict(prepared.witness,kind='biased-join-owned-timer-fragment',fragment_range=[first,last],
        context_sha256=hashlib.sha256(repr(signature).encode()).hexdigest())
    return CallbackFragmentEvidence(prepared.states,line_states,signature,witness)


def joined_async_phase_completion(source, owners, line, work, authorities):
    column = source[line-1].index('}')+1
    _construct_charge(work,len(authorities)+len(source[line-1]))
    matches = [proof for proof in authorities if proof.witness['phase_entry']['async_span'][1]==[line,column+1]
               and proof.witness['timer_source_range'][1]+1<line]
    if len(matches)!=1:
        return None
    authority, = matches
    phases = {copy['phase'] for copy in authority.witness['owners']}
    _construct_charge(work,sum(len(owner['regions'])+1 for owner in owners))
    touching = [(owner,rows) for owner in owners
                if (rows := [r for r in owner['regions'] if owner_covers_lines([r],line,line)])]
    by_name = {owner['name']:(owner,rows) for owner,rows in touching}
    if len(touching)!=len(phases) or by_name.keys()!=phases:
        return None
    states = []; lines = []; regions = []
    for copy, state in zip(authority.witness['owners'],authority.states,strict=True):
        owner, selected = by_name[copy['phase']]
        if selected!=[[line,column,line,column+1,owner['count'],0,0,0]]:
            return None
        bit = int(owner['count']>0)
        states.append((*state,bit));lines.append((bit,));regions.append([owner['name'],selected[0]])
    signature = ('joined-async-phase-completion',authority.signature,column)
    return CallbackFragmentEvidence(tuple(states),tuple(lines),signature,
        dict(kind=signature[0],regions=regions,scope=authority.witness['phase_entry']['async_span']))


def joined_async_statement(source, owners, first, last, inventory, work, authorities):
    """Match a complete direct statement executed in an authenticated post-join phase."""
    if not authorities:
        return None
    code, rows = inventory[:2]
    _construct_charge(work,len(rows)+len(authorities))
    choices = []
    for row in rows:
        if row['kind']!='statement' or not row['supported'] or code.words[row['end']]!=';':
            continue
        low, high = code.position(code.starts[row['first']])[0], code.position(code.ends[row['end']])[0]
        if not low<=first<=last<=high:
            continue
        parent = code.parents[row['first']]
        if parent is None:
            continue
        span = [list(code.position(code.starts[parent])),list(code.position(code.ends[code.pairs[parent]]))]
        _construct_charge(work,len(authorities))
        choices.extend((row,low,high,proof) for proof in authorities
            if proof.witness['phase_entry']['async_span']==span and proof.witness['timer_source_range'][1]+1<low)
    if len(choices)!=1:
        return None
    statement, low, high, authority = choices[0]
    start, end = statement['first'], statement['end']
    _construct_charge(work,end-start+1+len(owners)+len(rows))
    if any(row is not statement and row['kind']=='statement' and row['digest']==statement['digest']
           and code.parents[row['first']]==code.parents[start] for row in rows):
        return None
    words = code.words[start:end]
    macro = words[:1] in (['assert'],['assert_eq'],['eprintln']) and words[1:3]==['!','(']
    if (not (macro or words[:1]==['let'] or words[1:2]==['::'])
            or {'#','{','?','unsafe','async','await','return','break','continue','|','||'}.intersection(words)
            or words.count('!')!=int(macro)):
        return None
    start_pos = code.position(code.starts[start]); end_pos = code.position(code.ends[end])
    if source[low-1][:start_pos[1]-1].strip() or source[high-1][end_pos[1]-1:].strip():
        return None
    phases = {copy['phase'] for copy in authority.witness['owners']}
    _construct_charge(work,sum(len(owner['regions'])+1 for owner in owners))
    touching = [(owner,regions) for owner in owners
                if (regions := [row for row in owner['regions'] if row[0]<=high and row[2]>=low])]
    by_name = {owner['name']:(owner,regions) for owner,regions in touching}
    if len(touching)!=len(phases) or by_name.keys()!=phases:
        return None
    states = []; line_states = []; proofs = []; geometries = set(); observer = _ObserverWork(work)
    for copy, state in zip(authority.witness['owners'],authority.states,strict=True):
        owner, selected = by_name[copy['phase']]
        _construct_charge(work,len(selected)+len(owner.get('branches',())))
        if (any(row[5:]!=[0,0,0] or row[4]!=owner['count'] or tuple(row[:2])<start_pos
                or tuple(row[2:4])>end_pos for row in selected)
                or any(row[0]<=high and row[2]>=low for row in owner.get('branches',()))
                or owner.get('mcdc_records')):
            return None
        shape,bits = fragment_region_states(dict(regions=selected),low,high,source,work)
        geometries.add(shape); states.append((*state,*bits))
        projected = _owner_line_counts({'regions':selected},observer)
        line_states.append(tuple(int(projected.get(line,0)>0) for line in range(first,last+1)))
        proofs.append(dict(owner=owner['name'],region_states=bits,regions=selected))
    if len(geometries)!=1:
        return None
    signature = ('joined-async-statement',authority.signature,statement['digest'],next(iter(geometries)),
                 tuple(source[low-1:high]),(first-low,last-low))
    witness = dict(kind='joined-async-statement',statement_span=[low,high],owners=proofs,
                   context_sha256=hashlib.sha256(repr(signature).encode()).hexdigest())
    return CallbackFragmentEvidence(tuple(states),tuple(line_states),signature,witness)


def joined_async_condition(source, owners, line, inventory, work, authorities):
    """Carry a complete direct conditional under an already bound async owner."""
    code, rows = inventory[:2]
    _construct_charge(work, len(rows) + len(authorities))
    endpoint_only = source[line-1].strip()=='}'
    guards = [row for row in rows if row['kind'] == 'if' and row['supported']
              and row['header'][:1] == ('if',) and row['opening'] > row['first'] + 1
              and code.position(code.starts[row['first']])[0]==code.position(code.starts[row['opening']])[0]
              and code.position(code.starts[row['end'] if endpoint_only else row['first']])[0]==line]
    if len(guards) != 1:
        return None
    guard = guards[0]
    opening, closing = guard['opening'], guard['end']
    first = code.position(code.starts[guard['first']])[0]
    parent = code.parents[opening]
    if parent is None or code.words[parent] != '{' or code.words[closing+1:closing+2] == ['else']:
        return None
    parent_span = [list(code.position(code.starts[parent])), list(code.position(code.ends[code.pairs[parent]]))]
    matches = [proof for proof in authorities if proof.witness['phase_entry']['async_span'] == parent_span
               and proof.witness['timer_source_range'][1]+1 < first]
    if len(matches) != 1:
        return None
    prepared = matches[0]
    _construct_charge(work, closing - guard['first'] + 1)
    if any(word in ('!', '#', 'unsafe', 'async', '||', 'else') for word in code.words[guard['first']:closing+1]):
        return None
    _construct_charge(work,len(rows))
    if any(row is not guard and row['kind']=='if' and row['digest']==guard['digest']
           and code.parents[row['opening']]==parent for row in rows):
        return None
    expression = code.region(guard['first']+1, opening-1)
    body = code.region(opening, closing)
    endpoint = code.region(closing, closing)
    last = body[2]
    _construct_charge(work, sum(len(owner['regions'])+1 for owner in owners))
    by_name = {owner['name']: owner for owner in owners}
    phase_names = {copy['phase'] for copy in prepared.witness['owners']}
    def touches(region):
        return region[0] <= last and region[2] >= first
    if any(owner['name'] not in phase_names and any(touches(region) for region in owner['regions'])
           for owner in owners):
        return None
    states = []; witnesses = []; geometries = set()
    for copy, state in zip(prepared.witness['owners'], prepared.states, strict=True):
        owner = by_name[copy['phase']]
        _construct_charge(work, len(owner['regions']) + len(owner.get('branches', ())))
        selected = [region for region in owner['regions'] if touches(region)]
        roles = {tuple(region[:4]): region[4] for region in selected}
        if (len(roles) != len(selected) or not {expression,body,endpoint} <= roles.keys()
                or any(region[5:] != [0,0,0] for region in selected)
                or any(touches(branch) for branch in owner.get('branches', ()))
                or owner.get('mcdc_records') or not 0 <= roles[body] <= roles[expression] == owner['count']
                or roles[endpoint] != roles[expression]
                or any(not (body[:2] <= region[:2] < region[2:] <= body[2:] and 0 <= count <= roles[body])
                       for region,count in roles.items() if region not in (expression,body,endpoint))):
            return None
        geometry, bits = fragment_region_states(dict(regions=selected), first, last, source, work)
        geometries.add(geometry)
        states.append((*state,*bits))
        witnesses.append(dict(owner=owner['name'],condition=roles[expression],body=roles[body],
                              completion=roles[endpoint],regions=selected))
    if len(geometries) != 1:
        return None
    kind = 'joined-async-condition-completion' if endpoint_only else 'joined-async-condition'
    signature = (kind,prepared.signature,guard['digest'],next(iter(geometries)))
    witness = dict(kind=kind,condition_span=[first,last],owners=witnesses,
                   context_sha256=hashlib.sha256(repr(signature).encode()).hexdigest())
    slot = 'completion' if endpoint_only else 'condition'
    return CallbackFragmentEvidence(tuple(states),tuple((int(row[slot]>0),) for row in witnesses),
                                    signature,witness)


def biased_join_result_authority(source, group, owners, name_counts, first, inventory, work, header, loop_cache):
    code, rows = inventory[:2]
    _construct_charge(work, len(rows))
    statements = [row for row in rows if row['kind'] == 'statement'
                  and code.position(code.starts[row['first']])[0] == first]
    if len(statements) != 1:
        return None
    statement = statements[0]; start = statement['first']; words = code.words
    if tuple(words[start:start+12]) != ('let','(',header['left'],',',header['right'],')','=',
                                      'tokio','::','join','!','('):
        return None
    macro_open = start+11; macro_end = code.pairs[macro_open]
    if (macro_end+1 != statement['end'] or words[statement['end']] != ';'
            or tuple(words[macro_open+1:macro_open+3]) != ('biased',';')):
        return None
    callee = macro_open+3; call_open = callee+1
    if (not _boolean_leaf([words[callee]]) or re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',words[callee]) is None
            or words[call_open] != '(' or code.parents[call_open] != macro_open):
        return None
    call_end = code.pairs[call_open]; args = _boolean_arguments(code,call_open)
    if args is None or len(args) != 5:
        return None
    values = [tuple(words[a:b]) for a,b in args]
    if any(not (_boolean_leaf(list(value)) or len(value)==2 and value[0]=='&'
            and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',value[1])) for value in values):
        return None
    if words[call_end+1] != ',' or tuple(words[call_end+2:call_end+4]) != ('async','{'):
        return None
    timer_open = call_end+3; timer_end = code.pairs[timer_open]
    if code.parents[timer_open] != macro_open or tuple(words[timer_end+1:macro_end]) != (',',):
        return None
    timer_words = tuple(words[timer_open+1:timer_end])
    timer_prefix = ('tokio','::','time','::','sleep','(','Duration','::','from_millis','(','50',')',')','.','await',';')
    if (len(timer_words) != 21 or timer_words[:16] != timer_prefix
            or not _boolean_leaf([timer_words[16]]) or timer_words[17:] != ('.','elapsed','(',')')):
        return None
    phases = [row for row in rows if row['opening'] is not None
              and words[row['opening']-1] == 'async' and row['opening'] < start < statement['end'] < row['end']
              and code.parents[start] == row['opening']]
    if len(phases) != 1:
        return None
    phase = phases[0]; phase_line = code.position(code.starts[phase['opening']])[0]
    loops = [row for row in rows if row['kind']=='for' and row['opening'] is not None
             and row['opening'] < phase['opening'] < phase['end'] < row['end']]
    if len(loops) != 1 or values[0] != (loops[0]['header'][2],):
        return None
    authority = nested_async_call_entry_fragment(source,group,owners,name_counts,phase_line,phase_line,
        inventory,work,loop_cache=loop_cache)
    if authority is None or authority.witness['kind'] != 'literal-pair-loop-async-call-entry':
        return None
    token_span = lambda a,b: (*code.position(code.starts[a]),*code.position(code.ends[b]))
    expected_header = tuple((first,header.start(name)+1,first,header.end(name)+1)
                            for name in ('left','right','macro'))
    if (token_span(start+2,start+2) != expected_header[0]
            or token_span(start+4,start+4) != expected_header[1]
            or token_span(start+7,start+10) != expected_header[2]):
        return None
    first_call_roles = (token_span(callee,callee),*(token_span(a,b-1) for a,b in args))
    opening = code.position(code.starts[timer_open]); closing = code.position(code.ends[timer_end])
    if (opening[0] != first+3 or closing[0] != first+6
            or code.position(code.starts[callee])[0] != first+2
            or code.position(code.ends[macro_end])[0] != first+7):
        return None
    expected_timer = ((*opening,opening[0],opening[1]+1),
        token_span(timer_open+1,timer_open+5),token_span(timer_open+1,timer_open+15),
        token_span(timer_open+17,timer_open+17),token_span(timer_open+19,timer_open+19),
        (*code.position(code.starts[timer_end]),*closing))
    _construct_charge(work, statement['end']-start+sum(len(source[i])+1 for i in range(first-1,first+7)))
    low = code.position(code.starts[start]); high = code.position(code.ends[statement['end']])
    def overlaps(row):
        return tuple(row[:2]) < high and low < tuple(row[2:4])
    by_name = {owner['name']:owner for owner in owners}
    states=[]; line_states=[]; geometries=[]; copies=[]; allowed=set()
    for index, parent_proof in enumerate(authority.witness['owners']):
        root=by_name[parent_proof['parent']]; current=by_name[parent_proof['child']]
        shape=plain_rust_function_symbol(root['name'])
        _construct_charge(work,sum(len(owner['name'])+len(owner['regions']) for owner in owners))
        children=[owner for owner in owners if direct_rust_callback_symbol(owner['name'],root['name'],shape.modules,3)
            and min(tuple(row[:2]) for row in owner['regions'])==opening
            and max(tuple(row[2:4]) for row in owner['regions'])==closing]
        if len(children)!=1:
            return None
        child=children[0]
        if (child['filenames']!=current['filenames'] or name_counts[child['name']]!=1
                or child['count']!=current['count'] or id(child) in allowed):
            return None
        expected_parent=(*expected_header,*first_call_roles)
        prepared=[]
        for owner,expected in ((current,expected_parent),(child,expected_timer)):
            _construct_charge(work,len(owner['regions']))
            selected=[row for row in owner['regions'] if overlaps(row)]
            if (len(selected)!=len(expected) or {tuple(row[:4]) for row in selected}!=set(expected)
                    or any(len(row)!=8 or row[5:]!=[0,0,0] or type(row[4]) is not int
                        or not 0<=row[4]<COUNTER_LIMIT or row[4]!=current['count'] for row in selected)):
                return None
            prepared.append([next(row for row in selected if tuple(row[:4])==span) for span in expected])
            allowed.add(id(owner))
        parent_rows,timer_rows=prepared
        if len(child['regions'])!=len(expected_timer):
            return None
        geometry=(tuple((r[0]-first,r[1],r[2]-first,r[3],*r[5:]) for r in parent_rows[:3]),
                  tuple((r[0]-opening[0],r[1],r[2]-opening[0],r[3],*r[5:]) for r in timer_rows))
        geometries.append(geometry)
        bits=tuple(int(row[4]>0) for row in (*parent_rows,*timer_rows))
        states.append((*authority.states[index],*bits));line_states.append((int(any(row[4]>0 for row in parent_rows[:3])),))
        copies.append(dict(parent=root['name'],phase=current['name'],timer=child['name'],
                           result_roles=parent_rows[:3],unclaimed_first_call_roles=parent_rows[3:],timer_regions=timer_rows))
    _construct_charge(work,sum(len(owner['regions']) for owner in owners))
    if (not geometries or len(set(geometries))!=1 or any(id(owner) not in allowed
            and any(overlaps(row) for row in owner['regions']) for owner in owners)):
        return None
    signature=('biased-join-result-binding',authority.signature,header['left'],header['right'],
               tuple(values[i] for i in (0,2,3,4)),timer_words,geometries[0])
    witness=dict(kind='biased-join-result-binding',owners=copies,phase_entry=authority.witness,
        empty_expansion_metadata=True,header_source_line=first,timer_source_range=[opening[0],closing[0]],
        first_callee_unclaimed=words[callee],first_argument_value_unclaimed=values[1],
        header_geometry=geometries[0][0],timer_geometry=geometries[0][1],
        context_sha256=hashlib.sha256(repr(signature).encode()).hexdigest(),
        limitation='Completed tuple bindings and unchanged owned timer states only; changed first callee/value and expanded join internals are unclaimed')
    return CallbackFragmentEvidence(tuple(states),tuple(line_states),signature,witness)


def nominal_phase_fragment(source, group, owners, name_counts, first, last, inventory, work, cache):
    """Bind a nongeneric impl method's complete lexical phase tree to compiled copies."""
    if inventory is None:
        return None
    _construct_charge(work, len(group[2])+1)
    if any(not owner['name'].startswith(('_RNvM', '_RNvX')) for owner in group[2]):
        return None
    code, rows = inventory[:2]
    key = id(code), group[:2], tuple(id(owner) for owner in group[2])
    if key not in cache:
        cache[key] = None
        _construct_charge(work, len(rows) + len(owners))
        functions = [row for row in rows if row['kind'] == 'fn' and 'fn' in row['header']
            and code.position(code.starts[row['first'] + row['header'].index('fn')])[0] == group[0]
            and code.position(code.ends[row['end']])[0] == group[1]]
        if len(functions) != 1:
            return None
        function = functions[0]; header = function['header']; fn = header.index('fn')
        if header[:fn] not in ((), ('pub',)):
            return None
        by_opening = {row['opening']: row for row in rows if row['opening'] is not None}
        enclosing = [by_opening.get(index) for index in _construct_ancestors(code, function['opening'], work)]
        if (not enclosing or enclosing[0] is None or enclosing[0]['kind'] != 'impl'
                or any(row is None or row['kind'] not in ('impl', 'mod') for row in enclosing)):
            return None
        implementation = enclosing[0]['header']
        if len(implementation) not in (2, 4) or implementation[0] != 'impl':
            return None
        if len(implementation) == 4 and implementation[2] != 'for':
            return None
        phases = []
        for row in rows:
            opening = row['opening']
            if opening is None or not function['opening'] < opening < row['end'] < function['end']:
                continue
            # shortcut: argument-position zero-arg closures and async blocks only; add other forms with phase fixtures.
            if code.words[opening-1] not in ('||', 'async', 'move'):
                continue
            parent = code.parents[opening]
            if parent is None or code.words[parent] != '(':
                continue
            argument = opening - 1
            while argument > parent:
                _construct_charge(work, 1)
                if code.parents[argument] == parent and code.words[argument] == ',':
                    break
                argument -= 1
            _construct_charge(work, opening - argument)
            if tuple(code.words[argument+1:opening]) not in (
                    ('||',), ('move', '||'), ('async',), ('async', 'move')):
                continue
            phases.append(row)
        _construct_charge(work, len(phases) * (len(phases).bit_length() + 1))
        phases.sort(key=lambda row: row['opening'])
        if not phases:
            return None
        phase_indices = {row['opening']: index for index, row in enumerate(phases)}
        contexts = []; ancestors = []
        for row in phases:
            chain = _construct_ancestors(code, row['opening'], work)
            if function['opening'] not in chain:
                return None
            chain = chain[:chain.index(function['opening'])+1]
            ancestors.append(next((phase_indices[index] for index in chain if index in phase_indices), None))
            context = []; child = row['opening']
            for parent in chain:
                start = parent + 1
                if code.words[parent] == '{':
                    cursor = child - 1
                    while cursor > parent:
                        _construct_charge(work, 1)
                        if (code.parents[cursor] == parent and code.words[cursor] == ';'
                                or code.words[cursor] == '}' and code.parents[code.pairs[cursor]] == parent):
                            start = cursor + 1; break
                        cursor -= 1
                _construct_charge(work, child - start + 1)
                context.append((code.words[parent], tuple(code.words[start:child])))
                child = parent
            contexts.append(tuple(context))
        start = (group[0], len(source[group[0]-1]) - len(source[group[0]-1].lstrip()) + 1)
        header_ends = (code.position(code.starts[function['opening']]),
                       code.position(code.ends[function['opening']-1]))
        bounds = [(code.position(code.starts[row['opening']]), code.position(code.ends[row['end']]))
                  for row in phases]
        identity_work = sum(len(owner['name'])+1 for owner in owners)
        _construct_charge(work, len(phases) + identity_work)
        decoded = {id(owner): nominal_method_path(owner['name']) for owner in owners}
        copies = []; identities = []; bound = set()
        for root in group[2]:
            shape = decoded.get(id(root))
            if (shape is None or shape.callbacks or shape.method[0] != header[fn+1]
                    or shape.kind not in ('M', 'X') or shape.self_type[0] != 'type'
                    or shape.self_type[-1][0] != implementation[-1]
                    or (shape.kind == 'X') != (len(implementation) == 4)
                    or shape.kind == 'X' and (shape.trait[0] != 'type' or shape.trait[-1][0] != implementation[1])):
                return None
            identities.append((shape.parent_scope, shape.method))
            _construct_charge(work, identity_work)
            members = [owner for owner in owners if decoded[id(owner)] is not None
                       and decoded[id(owner)].copy_identity == shape.copy_identity]
            _construct_charge(work, len(members) + len(phases))
            if len(members) != len(phases) + 1:
                return None
            by_start = {}
            for owner in members:
                _construct_charge(work, len(owner['regions'])+1)
                by_start.setdefault(min(tuple(region[:2]) for region in owner['regions']), []).append(owner)
            ordered = [root]
            for low, high in bounds:
                choices = by_start.get(low, ())
                if len(choices) != 1 or choices[0] is root:
                    return None
                ordered.append(choices[0])
            if len({id(owner) for owner in ordered}) != len(ordered):
                return None
            for index, owner in enumerate(ordered):
                _construct_charge(work, 2 * len(owner['regions']) + 1)
                count = owner.get('count')
                if (type(count) is not int or not 0 <= count < COUNTER_LIMIT or name_counts[owner['name']] != 1
                        or owner['filenames'] != root['filenames'] or len(owner['filenames']) != 1
                        or any(region[5:] != [0, 0, 0] for region in owner['regions'])):
                    return None
                if index == 0:
                    entries = [region for region in owner['regions']
                               if tuple(region[:2]) == start and tuple(region[2:4]) in header_ends]
                    closing = code.position(code.starts[function['end']]), code.position(code.ends[function['end']])
                else:
                    low, high = bounds[index-1]
                    entries = [region for region in owner['regions']
                               if tuple(region[:4]) == (*low, low[0], low[1]+1)]
                    closing = (high[0], high[1]-1), high
                    parent = ordered[0 if ancestors[index-1] is None else ancestors[index-1]+1]
                    if (decoded[id(owner)].callbacks[:-1] != decoded[id(parent)].callbacks
                            or len(decoded[id(owner)].callbacks) != len(decoded[id(parent)].callbacks)+1
                            or any(not low <= tuple(region[:2]) < tuple(region[2:4]) <= high
                                   for region in owner['regions'])):
                        return None
                completions = [region for region in owner['regions']
                               if tuple(region[:4]) == (*closing[0], *closing[1])]
                if (len(entries) != 1 or entries[0][4] != count or len(completions) != 1
                        or completions[0][4] != count):
                    return None
            bound.update(map(id, ordered)); copies.append(ordered)
        if len(set(identities)) != 1:
            return None
        low = code.position(code.starts[function['first']]); high = code.position(code.ends[function['end']])
        _construct_charge(work, sum(len(owner['regions']) for owner in owners))
        if any(id(owner) not in bound and any(tuple(region[:2]) < high and tuple(region[2:4]) > low
               for region in owner['regions']) for owner in owners):
            return None
        topology = [tuple(decoded[id(owner)].callbacks for owner in ordered) for ordered in copies]
        if len(set(topology)) != 1:
            return None
        cache[key] = copies, (identities[0], tuple(header), implementation, tuple(contexts), topology[0]), bounds
    prepared = cache[key]
    if prepared is None:
        return None
    copies, context, bounds = prepared
    states = []; line_states = []; geometries = []
    for members in copies:
        pieces = [fragment_region_states(owner, first, last, source, work) for owner in members]
        prefix = fragment_region_states(members[0], group[0], bounds[0][0][0], source, work)
        geometry = tuple(piece[0] for piece in pieces), prefix[0]
        geometries.append(geometry)
        states.append(tuple(int(owner['count'] > 0) for owner in members)
                      + prefix[1] + tuple(value for piece in pieces for value in piece[1]))
        _construct_charge(work, (last-first+1) * sum(len(owner['regions']) for owner in members))
        line_states.append(tuple(int(any(region[4] > 0 and owner_covers_lines([region], line, line)
            for owner in members for region in owner['regions'])) for line in range(first, last+1)))
    if len(set(geometries)) != 1:
        return None
    signature = 'nominal-phase-tree-fragment', context, geometries[0]
    return CallbackFragmentEvidence(tuple(states), tuple(line_states), signature,
        dict(kind='nominal-phase-tree-fragment', source_phase_ranges=bounds,
             owners=[[owner['name'] for owner in members] for members in copies],
             context_sha256=hashlib.sha256(repr(context).encode()).hexdigest(),
             geometry=geometries[0],
             limitation='Same lexical phase tree and compiled-copy execution; no callee-semantic equivalence'))


@dataclass(frozen=True)
class CompiledOwnerSourceIndex:
    owners: list
    files: dict
    owner_count: int
    file_count: int
    inventories: dict
    name_counts: Counter
    source_names: frozenset | None
    declaration_ends: dict | None = None


def index_compiled_owner_sources(owners, files, work, source_names=None, *, index_declaration_ends=False):
    """Index the exact canonical-or-literal-suffix predicate once per owner set."""
    _construct_charge(work, len(owners))
    if source_names is not None:
        _construct_charge(work, len(source_names))
        _construct_charge(work, sum(len(name) for name in source_names))
        source_names = frozenset(source_names)
    aliases = {}; inventories = {}; names = Counter()
    declaration_ends = {} if index_declaration_ends else None
    for owner in owners:
        symbol = owner['name']; names[symbol] += 1
        if declaration_ends is not None:
            _construct_charge(work, 1)
            if symbol[3:4] == 'v':
                _construct_charge(work, 3)
                declaration_ends.setdefault(symbol[-2:], []).append(symbol)
        targets = set()
        _construct_charge(work, len(owner['filenames']))
        for path in owner['filenames']:
            if path not in aliases:
                _construct_charge(work, len(path))
                matches = ({files[path]} if path in files
                           and (source_names is None or files[path] in source_names) else set())
                for position, character in enumerate(path):
                    if character == '/':
                        _construct_charge(work, len(path) - position)
                        suffix = path[position + 1:]
                        if source_names is None or suffix in source_names:
                            matches.add(suffix)
                aliases[path] = matches
            _construct_charge(work, len(aliases[path]))
            targets.update(aliases[path])
        _construct_charge(work, len(targets))
        for target in targets:
            inventories.setdefault(target, []).append(owner)
    _construct_charge(work, len(inventories))
    _construct_charge(work, sum(len(rows) for rows in inventories.values()))
    return CompiledOwnerSourceIndex(owners, files, len(owners), len(files),
        {name: tuple(rows) for name, rows in inventories.items()}, names, source_names, declaration_ends)


def qualified_function_completion(sides, work):
    """Bind only the closing brace of a free function after its parameters change."""
    witnesses = []
    for side, (source, groups, inventory, line) in enumerate(sides):
        if source[line - 1] != '}':
            return None
        _construct_charge(work, len(groups))
        if side == 0:
            choices = [group for group in groups.values() if group[1] == line]
        else:
            _construct_charge(work, len(inventory))
            _construct_charge(work, sum(len(owner['name']) + 1 for owner in inventory))
            logical_owners = {id(owner) for owner in inventory
                              if (path := plain_rust_function_symbol(owner['name'])) is not None
                              and path.identity == witnesses[0][0]}
            _construct_charge(work, sum(len(group[2]) + 1 for group in groups.values()))
            choices = [group for group in groups.values()
                       if logical_owners and {id(owner) for owner in group[2]} == logical_owners]
        if len(choices) != 1:
            return None
        start, end, owners = choices[0]
        line = end
        if source[line - 1] != '}':
            return None
        header = source[start - 1]
        _construct_charge(work, len(header) + sum(len(owner['name']) + 1 for owner in owners))
        declaration = re.fullmatch(r'fn ([A-Za-z_]\w*)\(([^(){}]*)\)([^{}]*)\{\s*', header)
        paths = [plain_rust_function_symbol(owner['name']) for owner in owners]
        if declaration is None or any(path is None or path.identifiers[-1] != declaration[1]
                                      for path in paths):
            return None
        identities = {path.identity for path in paths}
        if len(identities) != 1:
            return None
        _construct_charge(work, len(inventory) + sum(len(owner['regions']) for owner in inventory))
        touching = {id(owner): [region for region in owner['regions']
                                if tuple(region[:2]) < (line, 2) and tuple(region[2:4]) > (line, 1)]
                    for owner in inventory}
        touching = {key: rows for key, rows in touching.items() if rows}
        if set(touching) != {id(owner) for owner in owners}:
            return None
        if any(len(rows) != 1 or rows[0][:4] != [line, 1, line, 2]
               for rows in touching.values()):
            return None
        states = [[int(touching[id(owner)][0][4] > 0)] for owner in owners]
        if not any(row[0] for row in states):
            return None
        witnesses.append((next(iter(identities)), declaration[2], declaration[3].strip(),
                          states, [owner['name'] for owner in owners], (start, end)))
    left, right = witnesses
    if left[0] != right[0] or left[1] == right[1] or left[2] != right[2]:
        return None
    _construct_charge(work, len(left[3]) + len(right[3]) + len(left[3]) * len(right[3]))
    matching = compiled_hit_state_matching(left[3], right[3])
    if matching is None:
        return None
    return dict(kind='qualified-function-completion', owners=[left[4], right[4]],
                base_range=list(left[5]), head_range=list(right[5]),
                instance_states=sorted(left[3]), head_instance_states=sorted(right[3]),
                instance_matching=matching)


_MATCH_PARAMETER_BINDING = re.compile(r'[ \t]*let ([A-Za-z_]\w*) = match ([A-Za-z_]\w*) \{',re.ASCII)
_MATCH_DEFAULT_REFUSAL = re.compile(r'[ \t]*_ => false,',re.ASCII)


def ensure_entry_source(name, source, inventory, line, work):
    if source[line-1].strip()!='anyhow::ensure!(':
        return None
    code,rows = inventory[:2]
    _construct_charge(work,len(code.starts).bit_length()+len(rows))
    start=bisect.bisect_left(code.starts,code.offsets[line-1])
    if code.words[start:start+5]!=['anyhow','::','ensure','!','(']:
        return None
    opening=start+4; close=code.pairs[opening]
    if code.words[close+1:close+2]!=[';']:
        return None
    stop=close+1
    _construct_charge(work,stop-start+1)
    args=_boolean_arguments(code,opening)
    if args is None or len(args)<2 or args[1][1]-args[1][0]!=1:
        return None
    message=code.words[args[1][0]]
    if not message.startswith('"'):
        return None
    statements=inventory[3].get(line,())
    _construct_charge(work,len(statements))
    if sum(row['kind']=='statement' and row['supported'] and row['first']==start
           and row['end']==stop for row in statements)!=1:
        return None
    ancestry=_construct_ancestors(code,start,work)
    opening_set=set(ancestry)
    by_opening={row['opening']:row for row in rows if row['opening'] in opening_set}
    if by_opening.keys()!=opening_set:
        return None
    parents=[by_opening[at] for at in ancestry]
    function_at=next((i for i,row in enumerate(parents) if row['kind']=='fn'),None)
    if function_at is None or any(row['kind'] not in ('if','for','while','loop') or not row['supported']
                                  for row in parents[:function_at]):
        return None
    function=parents[function_at]
    scope=parents[function_at+1:]
    def fn_identity(row):
        header=row['header']
        if not row['supported'] or row['kind']!='fn' or header.count('fn')!=1:
            return None
        index=header.index('fn')
        if header[:index] not in ((),('pub','(','crate',')')):
            return None
        first=code.position(code.starts[row['first']+index])[0]
        last=code.position(code.ends[row['end']])[0]
        return header[index+1],(first,last)
    binding=fn_identity(function)
    if binding is None:
        return None
    function_name,span=binding
    _construct_charge(work,function['end']-function['opening']+1)
    messages=[token for token in range(function['opening']+1,function['end']) if code.words[token]==message]
    if len(messages)>1:
        _construct_charge(work,len(rows)+len(messages))
        blocks={row['opening']:row for row in rows if row['opening'] is not None}
        expected=tuple(row['header'] for row in parents[:function_at])
        for token in messages:
            if token==args[1][0]:
                continue
            chain=_construct_ancestors(code,token,work)
            if function['opening'] not in chain:
                return None
            local=[blocks.get(at) for at in chain[:chain.index(function['opening'])] if code.words[at]=='{']
            if (any(row is None or row['kind'] not in ('if','for','while','loop') or not row['supported']
                    for row in local) or tuple(row['header'] for row in local)==expected):
                return None
    modules=('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'))
    nominal_path=('crate',modules[0])
    for segment in modules[1:]:
        nominal_path=('type',nominal_path,(segment,''))
    method=None
    if scope:
        if len(scope)!=2 or scope[1]['kind']!='impl' or len(scope[1]['header'])!=2:
            return None
        parent=fn_identity(scope[0])
        if parent is None or scope[1]['header'][0]!='impl' or not scope[1]['supported']:
            return None
        nominal_type=scope[1]['header'][1]
        if re.fullmatch(r'[A-Za-z_]\w*',nominal_type,re.ASCII) is None:
            return None
        method=(parent,nominal_path,('type',nominal_path,(nominal_type,'')))
    syntax=(tuple(row['header'] for row in parents),message)
    condition_start,condition_end=args[0]
    condition_span=code.region(condition_start,condition_end-1)
    first,last=condition_span[0],condition_span[2]
    condition=None
    _construct_charge(work,len(source[first-1])+len(source[last-1]))
    first_text,last_text=source[first-1].encode('utf-8'),source[last-1].encode('utf-8')
    if (line<first<=last<code.position(code.starts[args[1][0]])[0]
            and code.words[condition_end]==','
            and code.position(code.starts[condition_end])[0]==last
            and not first_text[:condition_span[1]-1].strip()
            and last_text[condition_span[3]-1:].strip()==b','):
        _construct_charge(work,sum(len(text)+1 for text in source[first-1:last]))
        condition=condition_span,tuple(source[first-1:last])
    leading=None
    conjunct=condition_start+5
    if (condition is not None and conjunct<condition_end
            and code.words[condition_start+1]=='.'
            and code.words[condition_start+3:conjunct]==['(',')']
            and code.pairs.get(condition_start+3)==condition_start+4
            and code.words[conjunct]=='&&' and code.parents[conjunct]==opening
            and all(re.fullmatch(r'[A-Za-z_]\w*',code.words[token],re.ASCII) is not None
                    for token in (condition_start,condition_start+2))):
        prefix=code.region(condition_start,conjunct-1)
        _construct_charge(work,condition_end-condition_start)
        if (prefix[0]==prefix[2]<code.position(code.starts[conjunct])[0]
                and not first_text[prefix[3]-1:].strip()
                and not any(code.words[token]=='||' and code.parents[token]==opening
                            for token in range(conjunct+1,condition_end))):
            leading=prefix,(source[first-1],)
    trailing=None
    tail=['files','.','len','(',')','<','10_000']
    tail_start=condition_end-len(tail)
    if (name=='src/package_managers/aur/client.rs' and leading is not None
            and tail_start>conjunct and code.words[tail_start-1:condition_end]==['&&',*tail]
            and code.parents[tail_start-1]==opening and last>first
            and source[last-1].strip()=='&& files.len() < 10_000,'):
        trailing=code.region(tail_start,condition_end-1),(source[last-1],)
    repeatable=any(row['kind'] in ('for','while','loop') for row in parents[:function_at])
    return (syntax,span,code.region(start,stop),(code.region(start,start+3),),
            modules,function_name,method,(condition,leading,trailing),repeatable)


def ensure_condition_observation(source_condition, roots, counts, work):
    if source_condition is None:
        return None
    span,text=source_condition
    low,high=span[:2],span[2:]
    first,last=low[0],high[0]
    _construct_charge(work,last-first+1+sum(len(member[3]) for member in roots))
    mapped={line-first:bool(counts[line]) for line in range(first,last+1) if line in counts}
    if not mapped:
        return None
    vectors=[]
    regions=[]
    for _,_,_,statement,_ in roots:
        raw=[row for row in statement if row[0]<=last and (row[2]>first or row[2]==first and row[3]>1)]
        if not raw or any(not low<=tuple(row[:2])<tuple(row[2:4])<=high for row in raw):
            return None
        _construct_charge(work,len(raw)*(len(raw).bit_length()+1))
        vector=tuple(sorted((row[0]-first,row[1],row[2]-first,row[3],bool(row[4])) for row in raw))
        if len({r[:4] for r in vector})!=len(vector):
            return None
        regions.extend(raw)
        vectors.append(vector)
    projected=_owner_line_counts({'regions':regions},_ObserverWork(work))
    if projected!={line:counts[line] for line in range(first,last+1) if line in counts}:
        return None
    _construct_charge(work,sum(len(row) for row in vectors)*(len(vectors).bit_length()+1))
    return first,text,tuple(mapped),tuple(sorted(vectors)),tuple(mapped.values())


_MAP_CAPACITY_LINE = 'ahash::AHashMap::with_capacity(local_pkg_count);'
_ALPM_UPDATE_RECORD_LINE = 'updates.push(UpdateInfo {'
_ALPM_COLLECT_HEADER = ('pub', '(', 'crate', ')', 'fn', 'collect_updates', '(', 'alpm', ':', '&', 'alpm', '::', 'Alpm', ')', '->')


def map_capacity_entry_source(name, source, inventory, line, work):
    if name!='src/package_managers/alpm_ops.rs' or source[line-1].strip()!=_MAP_CAPACITY_LINE:
        return None
    code,rows=inventory[:2]
    _construct_charge(work,len(rows)+len(code.starts).bit_length())
    start=bisect.bisect_left(code.starts,code.offsets[line-1])
    call=('ahash','::','AHashMap','::','with_capacity','(','local_pkg_count',')',';')
    if tuple(code.words[start:start+len(call)])!=call:
        return None
    end=start+len(call)-1
    parent=code.parents[start]
    functions=[row for row in rows if row['kind']=='fn' and row['opening']==parent]
    statements=inventory[3].get(line,())
    _construct_charge(work,len(statements))
    bindings=[row for row in statements if row['kind']=='statement' and row['supported']
              and row['end']==end and code.parents[row['first']]==parent]
    if len(functions)!=1 or len(bindings)!=1:
        return None
    function,=functions; binding,=bindings
    signature = _ALPM_COLLECT_HEADER
    header=function['header']
    if (header[:len(signature)]!=signature or header[len(signature):] not in
            (('Vec','<','UpdateInfo','>'),('Result','<','Vec','<','UpdateInfo','>','>'))):
        return None
    _construct_charge(work,start-parent)
    if code.words[parent+1:binding['first']]!=[
            'let','localdb','=','alpm','.','localdb','(',')',';',
            'let','syncdbs','=','alpm','.','syncdbs','(',')',';',
            'let','local_pkg_count','=','localdb','.','pkgs','(',')','.','len','(',')',';']:
        return None
    types=tuple(code.words[binding['first']:start])
    before=('let','mut','sync_map',':','ahash','::','AHashMap','<','&','str',',','(','&')
    after=(',','&','str',')','>','=')
    if types[:len(before)]!=before or types[-len(after):]!=after or types[len(before):-len(after)] not in (
            ('str',),('alpm','::','Package')):
        return None
    span=(code.position(code.starts[function['first']+4])[0],code.position(code.ends[function['end']])[0])
    slots=tuple(code.region(a,b) for a,b in ((start,start+4),(start+6,start+6)))
    return (signature,span,code.region(binding['first'],end),slots,
            ('omg_lib','package_managers','alpm_ops'),'collect_updates',None,(None,None),False)


def alpm_update_record_entry_source(name, source, inventory, line, work):
    if name != 'src/package_managers/alpm_ops.rs' or source[line - 1].strip() != _ALPM_UPDATE_RECORD_LINE:
        return None
    code, rows = inventory[:2]
    _construct_charge(work, len(rows) + len(code.starts).bit_length())
    start = bisect.bisect_left(code.starts, code.offsets[line - 1])
    ancestors = _construct_ancestors(code, start, work)
    if len(ancestors) != 3:
        return None
    controls = {row['opening']: row for row in rows if row['opening'] in ancestors}
    if set(controls) != set(ancestors):
        return None
    branch, loop, function = (controls[opening] for opening in ancestors)
    header = function['header']
    results = (('Vec', '<', 'UpdateInfo', '>'), ('Result', '<', 'Vec', '<', 'UpdateInfo', '>', '>'))
    if (function['kind'] != 'fn' or header[:len(_ALPM_COLLECT_HEADER)] != _ALPM_COLLECT_HEADER
            or header[len(_ALPM_COLLECT_HEADER):] not in results
            or loop['kind'] != 'for' or loop['header'] != ('for', 'pkg', 'in', 'localdb', '.', 'pkgs', '(', ')')
            or branch['kind'] != 'if' or branch['opening'] + 1 != start):
        return None
    modern = header[len(_ALPM_COLLECT_HEADER):] == results[1]
    binding = 'sync_pkg' if modern else 'sync_ver_str'
    ignore = '! sync_pkg . should_ignore ( ) && ' if modern else ''
    publisher_version = 'sync_pkg . version ( )' if modern else binding
    comparison = f'{publisher_version} . as_str ( )' if modern else binding
    guard = (f'if let Some ( & ( {binding} , repo ) ) = sync_map . get ( name ) && '
             f'{ignore}alpm :: vercmp ( {comparison} , local_ver_str ) = = std :: cmp :: Ordering :: Greater')
    prelude = ('let name = pkg . name ( ) ; '
               'let local_ver_str = pkg . version ( ) . as_str ( ) ;')
    if modern:
        prelude = 'if pkg . should_ignore ( ) { continue ; } ' + prelude
    record = ('updates . push ( UpdateInfo { name : name . to_string ( ) , '
              'old_version : local_ver_str . to_string ( ) , '
              f'new_version : {publisher_version} . to_string ( ) , repo : repo . to_string ( ) , }} ) ;').split()
    _construct_charge(work, branch['end'] - loop['opening'] + 1)
    if (branch['header'] != tuple(guard.split())
            or code.words[loop['opening'] + 1:branch['first']] != prelude.split()
            or code.words[start:branch['end']] != record):
        return None
    span = (code.position(code.starts[function['first'] + 4])[0],
            code.position(code.ends[function['end']])[0])
    bounds = code.region(branch['opening'], branch['end'])
    slots = (bounds, code.region(start, start), code.region(start + 2, start + 2))
    field_offsets = {field: record.index(field) for field in ('name', 'old_version', 'new_version', 'repo')}
    regions = list(slots)
    for field in ('name', 'old_version', 'new_version'):
        value = field_offsets[field] + 2
        method = record.index('to_string', value)
        regions.extend((code.region(start + value, start + method - 2),
                        code.region(start + method, start + method)))
    regions.append(code.region(branch['end'], branch['end']))
    retained = (line, *(code.position(code.starts[start + field_offsets[field]])[0]
                         for field in ('name', 'old_version', 'repo')),
                code.position(code.starts[branch['end'] - 3])[0], bounds[2])
    changed = code.position(code.starts[start + field_offsets['new_version']])[0]
    if len(set(retained)) != len(retained) or changed in retained:
        return None
    return (_ALPM_COLLECT_HEADER, span, bounds, slots, ('omg_lib', 'package_managers', 'alpm_ops'),
            'collect_updates', None, (regions, retained), True)


def retained_ensure_entry(name, sides, indexes, work):
    return retained_observed_entry(name,sides,indexes,work,ensure_entry_source)


def retained_observed_entry(name, sides, indexes, work, source_observer):
    """Compare complete raw copy inventories for a source-owned entry."""
    map_initializer=source_observer is map_capacity_entry_source
    alpm_record = source_observer is alpm_update_record_entry_source
    identities=[]; receipts=[]; states=[]; conditions=[]
    for (source,inventory,spans,counts,line),index in zip(sides,indexes):
        observed=source_observer(name,source,inventory,line,work)
        if observed is None:
            return None
        syntax,span,statement,entry,modules,function,method,condition,repeatable=observed
        low,high=statement[:2],statement[2:]
        owners=index.inventories.get(name,())
        _construct_charge(work,len(owners))
        roots=[]; compiled_parents=[]
        for owner in owners:
            raw_span=spans.get(id(owner))
            if raw_span is not None and (raw_span[1]<low[0] or raw_span[0]>high[0]):
                continue
            _construct_charge(work,len(owner['regions']))
            touching=[row for row in owner['regions'] if tuple(row[:2])<high and low<tuple(row[2:4])]
            if not touching and (raw_span is None or raw_span[:2]!=span):
                if method is not None and raw_span is not None and raw_span[:2]==method[0][1]:
                    _construct_charge(work,len(owner['name'])+1)
                    shape=nominal_method_path(owner['name'])
                    if shape is None:
                        return None
                    compiled_parents.append((owner,shape))
                continue
            symbol=owner['name']
            _construct_charge(work,len(symbol)+len(touching)+1)
            if (not touching or raw_span is None or raw_span[:2]!=span
                    or index.name_counts[symbol]!=1 or owner.get('branches') or owner.get('mcdc_records')
                    or not 0<=owner['count']<COUNTER_LIMIT
                    or any(not low<=tuple(r[:2])<tuple(r[2:4])<=high or r[5:]!=[0,0,0]
                           or not 0<=r[4]<COUNTER_LIMIT for r in touching)):
                return None
            if method is None:
                shape=plain_rust_function_symbol(symbol)
                if shape is None or shape.identifiers!=(*modules,function):
                    return None
                identity=shape.identity
                copy=symbol
            else:
                decoded=nominal_method_path(symbol,local_function=True)
                if decoded is None:
                    return None
                shape,local=decoded
                if (shape.namespace!=method[1] or shape.self_type!=method[2]
                        or shape.method!=(method[0][0],'') or local!=(function,'')):
                    return None
                identity=shape.kind,shape.namespace,shape.self_type,shape.method,local
                copy=shape.copy_identity
            marker=[r for r in touching if r[0]<=line<=r[2]]
            if tuple(tuple(r[:4]) for r in marker)!=entry or len({r[4] for r in marker})!=1:
                return None
            hits=marker[0][4]
            if (hits and owner['count']==0 or not repeatable and hits>owner['count']
                    or map_initializer and hits!=owner['count']):
                return None
            if alpm_record and ([tuple(row[:4]) for row in touching] != condition[0]
                                or any(row[4] != hits for row in touching[:-1])
                                or bool(touching[-1][4]) != bool(hits)):
                return None
            roots.append((owner,identity,copy,touching,hits))
        _construct_charge(work,len(roots)+len(compiled_parents))
        if not 1<=len(roots)<=16 or len({r[1] for r in roots})!=1 or len({r[2] for r in roots})!=len(roots):
            return None
        if method is not None:
            if (len(compiled_parents)!=len(roots)
                    or {p.copy_identity for _,p in compiled_parents}!={r[2] for r in roots}
                    or any(index.name_counts[parent['name']]!=1 or parent.get('branches') or parent.get('mcdc_records')
                           for parent,_ in compiled_parents)):
                return None
        _construct_charge(work,high[0]-low[0]+1+sum(len(member[3]) for member in roots))
        projection=_owner_line_counts({'regions':[row for member in roots for row in member[3]]},
                                      _ObserverWork(work))
        if counts.get(line,0)<=0 or projection!={n:counts[n] for n in range(low[0],high[0]+1) if n in counts}:
            return None
        conditions.append((condition,roots,counts))
        identities.append((syntax,roots[0][1]))
        states.append(sorted(r[4]>0 for r in roots))
        receipts.append(dict(span=list(statement),entry=list(entry) if map_initializer or alpm_record else list(entry[0]),
                             owners=[dict(name=r[0]['name'], regions=r[3],entry_count=r[4]) for r in roots],
                             parents=[parent['name'] for parent,_ in compiled_parents]))
    if identities[0]!=identities[1] or len(states[0])!=len(states[1]):
        return None
    if alpm_record:
        if not all(states[1]):
            return None
    elif (any(left>right for left,right in zip(*states)) if map_initializer else states[0]!=states[1]):
        return None
    pairs=[[sides[0][-1],sides[1][-1]]]
    if alpm_record:
        old, new = (item[0][1] for item in conditions)
        pairs = [list(pair) for pair in zip(old, new, strict=True)]
        if any(sides[0][0][line - 1] != sides[1][0][target - 1]
               or sides[0][3].get(line, 0) <= 0 or sides[1][3].get(target, 0) <= 0
               for line, target in pairs):
            return None
        return dict(file=name, kind='retained-alpm-update-record-entry', pairs=pairs,
                    instance_states=states, observations=receipts)
    condition_pairs=[]
    for candidate in range(len(conditions[0][0])):
        old_source,new_source=(item[0][candidate] for item in conditions)
        if old_source is None or new_source is None or old_source[1]!=new_source[1]:
            continue
        projections=[ensure_condition_observation(item[0][candidate],item[1],item[2],work)
                     for item in conditions]
        if all(item is not None for item in projections) and projections[0][1:]==projections[1][1:]:
            old,new=[item[0] for item in projections]
            condition_pairs.extend([old+offset,new+offset] for offset in projections[0][2])
            if candidate==0:
                break
    pairs.extend(condition_pairs)
    kind = 'retained-map-capacity-entry' if map_initializer else 'retained-ensure-entry'
    return dict(file=name,kind=kind,pairs=pairs,condition_pairs=condition_pairs,
                instance_states=states,observations=receipts)


def policy_default_record_shape(code, rows, line, work):
    token=bisect.bisect_left(code.starts,code.offsets[line-1])
    parents=_construct_ancestors(code,token,work)
    if len(parents)!=3:
        return None
    _construct_charge(work,len(rows)+len(code.starts).bit_length())
    shapes={row['opening']:row for row in rows if row['opening'] in parents}
    if len(shapes)!=3:
        return None
    record,function,implementation=(shapes[token] for token in parents)
    if (record['header']!=('Self',) or function['header']!=('fn','default','(',')','->','Self')
            or implementation['header']!=('impl','Default','for','SecurityPolicy')
            or record['first']!=function['opening']+1 or record['end']+1!=function['end']):
        return None
    arguments=_boolean_arguments(code,record['opening'])
    if not arguments or len(arguments)>8:
        return None
    fields=[]
    for start,end in arguments:
        _construct_charge(work,end-start)
        words=tuple(code.words[start:end]); value=words[2:]
        if (len(words)<3 or words[1]!=':' or re.fullmatch(r'[A-Za-z_]\w*',words[0],re.ASCII) is None
                or code.words[end]!=','):
            return None
        if value not in (('true',),('false',)):
            path=value[:-2] if value[-3:]==('new','(',')') else value
            if (len(path)!=3 or path[1]!='::'
                    or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None for word in path[::2])):
                return None
        marker=code.region(start+2,end-3 if value[-2:]==('(',')') else end-1)
        field_line=code.position(code.starts[start])[0]
        if marker[0]!=field_line or marker[2]!=field_line:
            return None
        fields.append((words,field_line,marker))
    first=code.position(code.starts[function['first']])[0]
    last=code.position(code.ends[function['end']])[0]
    if (fields[0][1]!=line or len({item[0][0] for item in fields})!=len(fields)
            or [item[1] for item in fields]!=list(range(first+2,last-1))):
        return None
    anchors=(code.region(function['first'],function['opening']-1),
             code.region(record['first'],record['end']),code.region(function['end'],function['end']))
    return (first,last),fields,anchors


def retained_policy_default_record(name, sides, indexes, work):
    records=[]; copies=[]; states=[]; refinements=[]
    namespace=('type',('type',('type',('crate','omg_lib'),('core','')),('security','')),('policy',''))
    trait=('type',('type',('crate','core'),('default','')),('Default',''))
    for (_,inventory,spans,counts,line),index in zip(sides,indexes,strict=True):
        parsed=policy_default_record_shape(*inventory[:2],line,work)
        if parsed is None:
            return None
        (first,last),fields,anchors=parsed
        allowed={item[2]:n for n,item in enumerate(fields)}
        roots=[]
        owners=index.inventories.get(name,())
        _construct_charge(work,len(owners))
        for owner in owners:
            span=spans.get(id(owner))
            if span is not None and (span[1]<first or span[0]>last):
                continue
            raw=owner['regions']
            _construct_charge(work,len(raw))
            if not any(r[0]<=last and (r[2]>first or r[2]==first and r[3]>1) for r in raw):
                continue
            symbol=owner['name']; _construct_charge(work,len(symbol)+len(raw)+1)
            decoded=nominal_method_path(symbol,core_default_impl=True)
            hits=owner['count']
            if (span is None or span[:2]!=(first,last) or index.name_counts[symbol]!=1
                    or decoded is None or decoded.kind!='X' or decoded.namespace!=namespace
                    or decoded.self_type!=('type',namespace,('SecurityPolicy','')) or decoded.trait!=trait
                    or decoded.method!=('default','') or decoded.callbacks
                    or owner.get('branches') or owner.get('mcdc_records') or not 0<=hits<COUNTER_LIMIT
                    or any(r[5:]!=[0,0,0] or r[4]!=hits for r in raw)):
                return None
            geometry={tuple(r[:4]) for r in raw}
            direct=geometry-set(anchors)
            if len(geometry)!=len(raw) or not set(anchors)<=geometry or not direct<=allowed.keys():
                return None
            roots.append((owner,decoded,tuple(sorted(allowed[mark] for mark in direct))))
        if (not 1<=len(roots)<=16 or len({item[1].copy_identity for item in roots})!=len(roots)
                or len({item[1].parent_scope for item in roots})!=1 or len({item[2] for item in roots})!=1):
            return None
        _construct_charge(work,last-first+1+sum(len(item[0]['regions']) for item in roots))
        raw=[region for owner,_,_ in roots for region in owner['regions']]
        if _owner_line_counts({'regions':raw},_ObserverWork(work))!={
                n:counts[n] for n in range(first,last+1) if n in counts}:
            return None
        records.append(((first,last),fields,roots[0][1].parent_scope))
        copies.append([dict(name=owner['name'],count=owner['count'],regions=owner['regions']) for owner,_,_ in roots])
        states.append(sorted(item[0]['count']>0 for item in roots))
        refinements.append(roots[0][2])
    (old,left,old_scope),(new,right,new_scope)=records
    additions=(('advisory_requirement',':','AdvisoryRequirement','::','Optional'),
               ('arch_advisory_repositories',':','BTreeSet','::','new','(',')'))
    if (len(left)!=5 or len(right)!=7 or [item[0] for item in left]!=[item[0] for item in right[:5]]
            or tuple(item[0] for item in right[5:])!=additions or old_scope!=new_scope
            or states[0]!=states[1] or not any(states[0]) or not set(refinements[0])<=set(refinements[1])
            or any(sides[1][3].get(item[1],0)<=0 for item in right[5:])):
        return None
    pairs=[[line,new[0]+line-old[0]] for line in range(old[0],old[1]-1)]
    pairs.extend([[old[1]-1,new[1]-1],[old[1],new[1]]])
    return dict(file=name,kind='retained-policy-default-record',pairs=pairs,owners=copies,
                instance_states=states,direct_field_indices=refinements,added_lines=[item[1] for item in right[5:]])


def retained_match_selector(name, sides, indexes, work):
    """Bind a parameter selector or exact default refusal across every compiled root."""
    observed = []
    for (source,inventory,group,counts,line), index in zip(sides,indexes,strict=True):
        if inventory is None or line not in counts:
            return None
        default = _MATCH_DEFAULT_REFUSAL.fullmatch(source[line-1]) is not None
        if not default and _MATCH_PARAMETER_BINDING.fullmatch(source[line-1]) is None:
            return None
        code, rows = inventory[:2]
        _construct_charge(work,2*len(rows)+len(source[line-1]))
        functions = [row for row in rows if row['kind']=='fn' and row['supported']
                     and code.parents[row['opening']] is None
                     and code.position(code.starts[row['first']])[0]==group[0]
                     and code.position(code.ends[row['end']])[0]==group[1]]
        if len(functions)!=1:
            return None
        function, = functions
        scopes = [row for row in rows if row['kind']=='match' and row['supported']
                  and code.parents[row['first']]==function['opening']
                  and code.position(code.starts[row['end']-4 if default else row['first']])[0]==line]
        if len(scopes)!=1:
            return None
        scope, = scopes
        start = scope['first']; declaration = function['first']
        header = function['header']; _construct_charge(work,len(header)+start-function['opening'])
        selector_line = code.position(code.starts[start])[0]
        match = _MATCH_PARAMETER_BINDING.fullmatch(source[selector_line-1])
        if match is None:
            return None
        result, selector = match.groups()
        if (header[:1]!=('fn',) or header[2:3]!=('(',) or _boolean_attributes(code,declaration)!=[]
                or scope['header']!=('let',result,'=','match',selector)
                or code.position(code.starts[scope['opening']])[0]!=selector_line
                or selector in code.words[function['opening']+1:start]):
            return None
        arguments = _boolean_arguments(code,declaration+2)
        if arguments is None or sum(code.words[first:last]==[selector,':','&','str'] for first,last in arguments)!=1:
            return None
        labels = []
        if default:
            opening, closing = scope['opening'], scope['end']
            if code.words[closing-4:closing]!=['_','=>','false',',']:
                return None
            _construct_charge(work,closing-opening)
            for at in range(opening+1,closing-3):
                if code.words[at]!='=>' or code.parents[at]!=opening:
                    continue
                pattern = at-1
                while True:
                    _construct_charge(work,1)
                    if re.fullmatch(r'"[A-Za-z][A-Za-z0-9_-]*"',code.words[pattern]) is None:
                        return None
                    labels.append(code.words[pattern])
                    if code.words[pattern-1]!='|':
                        break
                    pattern -= 2
                boundary = pattern-1
                if boundary!=opening and not (code.words[boundary]==',' and code.parents[boundary]==opening
                        or code.words[boundary]=='}' and code.parents[code.pairs[boundary]]==opening):
                    return None
            if not labels or len(labels)!=len(set(labels)):
                return None
            slots = [code.region(closing-2,closing-2)]
        else:
            slots = [code.region(start+offset,start+offset) for offset in (1,4)]
        qualified = (*name.removeprefix('src/').removesuffix('.rs').split('/'),header[1])
        available = index.inventories.get(name,())
        _construct_charge(work,sum(len(owner['regions'])+1 for owner in available))
        touching = {id(owner):[row for row in owner['regions'] if owner_covers_lines([row],line,line)]
                    for owner in available}
        touching = {owner:raw for owner,raw in touching.items() if raw}
        if set(touching)!={id(owner) for owner in group[2]}:
            return None
        total = 0; states = []; names = []; scopes = set(); evidence = []
        for owner in group[2]:
            symbol = owner['name']; count = owner.get('count'); raw = touching[id(owner)]
            _construct_charge(work,len(symbol)+len(raw)+len(owner.get('branches',())))
            path = plain_rust_function_symbol(symbol)
            if (path is None or path.identifiers[1:]!=qualified or index.name_counts[symbol]!=1
                    or len(owner['filenames'])!=1 or index.files.get(owner['filenames'][0])!=name
                    or type(count) is not int or not 0<=count<COUNTER_LIMIT or owner.get('mcdc_records')
                    or any(branch[0]<=line<=branch[2] for branch in owner.get('branches',()))):
                return None
            hits = raw[0][4] if default else count
            if not 0<=hits<=count or raw!=[[*slot,hits,0,0,0] for slot in slots]:
                return None
            total += hits; names.append(symbol); scopes.add(path.identity)
            states.append((int(count>0),int(hits>0))); evidence.append(dict(symbol=symbol,count=count,regions=raw))
        if total!=counts[line] or len(scopes)!=1:
            return None
        signature = (header,next(iter(scopes)),tuple((slot[1],slot[3]) for slot in slots),source[line-1],
                     source[selector_line-1],tuple(sorted(labels)))
        observed.append((signature,states,names,evidence,line))
    left,right = observed
    if left[0]!=right[0]:
        return None
    _construct_charge(work,len(left[1])*len(right[1]))
    matching = compiled_hit_state_matching(left[1],right[1],(left[2],right[2]))
    if matching is None:
        return None
    return dict(kind='direct-match-default' if default else 'direct-match-selector',file=name,
                pairs=[[left[4],right[4]]],owners=[left[3],right[3]],
                instance_matching=matching)


_FIXTURE_WRITE_START = re.compile(r'[ \t]*fs::write\(',re.ASCII)


def fixture_write_loop(code,rows,function,statement,destination,owner,work):
    parent = code.parents[statement['first']]
    loops = [row for row in rows if row['kind']=='for' and row['supported'] and row['opening']==parent
             and code.parents[row['first']]==function['opening']]
    _construct_charge(work,len(rows)+len(owner['regions']))
    if len(loops)!=1:
        return None
    loop, = loops; header = loop['header']
    if len(header)<6 or header[0]!='for' or header[2:4]!=('in','[') or header[-1]!=']':
        return None
    binding = header[1]
    if re.fullmatch(r'[A-Za-z_]\w*',binding,re.ASCII) is None:
        return None
    array = loop['first']+3
    arguments = _boolean_arguments(code,array)
    if arguments is None or not 1<=len(arguments)<=8:
        return None
    keys = [code.words[first:last] for first,last in arguments]
    _construct_charge(work,len(header)+statement['first']-parent)
    setup = code.words[parent+1:statement['first']]
    if (any(len(key)!=1 or re.fullmatch(r'"[A-Za-z0-9_-]+"',key[0]) is None for key in keys)
            or len({key[0] for key in keys})!=len(keys)
            or len(setup)!=10 or setup[:3]!=['let',destination,'='] or setup[4:]!=['.','join','(',binding,')',';']
            or re.fullmatch(r'[A-Za-z_]\w*',setup[3],re.ASCII) is None):
        return None
    slots = (code.region(loop['first']+1,loop['first']+1),code.region(array,code.pairs[array]),
             code.region(parent,loop['end']))
    observations = [[r for r in owner['regions'] if tuple(r[:4])==slot] for slot in slots]
    if any(len(records)!=1 or records[0][5:]!=[0,0,0] for records in observations):
        return None
    binding_region,array_region,envelope = (records[0] for records in observations)
    hits = envelope[4]
    if not 0<array_region[4]<=owner['count'] or hits!=binding_region[4] or hits!=len(keys)*array_region[4]:
        return None
    return (header,tuple(setup)),envelope,hits


def retained_fixture_script_write(name,sides,indexes,work):
    """Bind the executed write and destination slots around one changed raw byte argument."""
    if name!='src/cli/tool.rs':
        return None
    observations = []
    for (source,inventory,group,counts,line), index in zip(sides,indexes,strict=True):
        if inventory is None or len(group[2])!=1 or counts.get(line,0)<=0:
            return None
        code, rows = inventory[:2]; root, = group[2]
        entry = root.get('count')
        if type(entry) is not int or not 0<entry<COUNTER_LIMIT:
            return None
        _construct_charge(work,2*len(rows)+len(root['name']))
        qualified = plain_rust_function_symbol(root['name'])
        if qualified is None or qualified.identifiers[:-1]!=('omg_lib','cli','tool','tests'):
            return None
        declaration = qualified.identifiers[-1]
        functions = [row for row in rows if row['kind']=='fn' and 'fn' in row['header']
                     and code.position(code.starts[row['first']+row['header'].index('fn')])[0]==group[0]
                     and code.position(code.ends[row['end']])[0]==group[1]]
        if len(functions)!=1:
            return None
        function, = functions
        fn = function['header'].index('fn'); fn_token = function['first']+fn
        context = _boolean_module(code,{'start':fn_token})
        if (function['header'][fn:]!=('fn',declaration,'(',')') or context is None or context[0]!=['tests']
                or _boolean_attributes(code,fn_token)!=[['test'],['cfg','(','unix',')']]):
            return None
        choices = [row for row in rows if row['kind']=='statement' and row['supported']
                   and function['opening']<row['first']<=row['end']<function['end']
                   and code.position(code.starts[row['first']])[0]==line]
        if len(choices)!=1:
            return None
        statement, = choices; start,end = statement['first'],statement['end']
        prefix = tuple(code.words[function['opening']+1:start]); words = code.words[start:end+1]
        _construct_charge(work,len(prefix)+sum(len(word)+1 for word in words))
        guard = ('if','crate','::','core','::','testing','::','run_isolated_test','(',
                 '"'+'::'.join(qualified.identifiers[1:])+'"',',',')','{','return',';','}')
        if (prefix[:len(guard)]!=guard or len(words)<16 or words[:5]!=['fs','::','write','(','&']
                or re.fullmatch(r'[A-Za-z_]\w*',words[5],re.ASCII) is None or words[6]!=','
                or words[-8:-3]!=[',',')','.','expect','('] or not words[-3].startswith('"')
                or words[-2:]!=[')',';'] or code.pairs.get(start+3)!=end-6
                or code.pairs.get(end-3)!=end-1):
            return None
        payload = words[7:-8]
        loop_context = None; extra = []; loop_hits = None
        if code.parents[start]==function['opening']:
            if len(payload)!=1 or re.match(r'br#+"',payload[0]) is None or '\n' not in payload[0]:
                return None
            setup = prefix
        else:
            loop = fixture_write_loop(code,rows,function,statement,words[5],root,work)
            if loop is None:
                return None
            loop_context,envelope,loop_hits = loop
            setup = guard
            extra.append(envelope)
            if payload[:3]==['format','!','('] and len(payload)==5 and payload[3].startswith('"') and payload[4]==')':
                extra.append([*code.region(start+7,start+8),loop_hits,0,0,0])
            elif len(payload)!=1 or not payload[0].startswith('b"'):
                return None
        slots = [code.region(a,b) for a,b in ((start,start+2),(start+4,start+5),(end-4,end-4),(end-2,end-2))]
        last = code.position(code.ends[end])[0]
        available = index.inventories.get(name,())
        _construct_charge(work,sum(len(owner['regions'])+1 for owner in available))
        touching = [(owner,raw) for owner in available
                    if (raw := [r for r in owner['regions'] if r[0]<=last and r[2]>=line])]
        if len(touching)!=1 or touching[0][0] is not root:
            return None
        raw = touching[0][1]; count = raw[0][4] if loop_hits is None else loop_hits
        if (index.name_counts[root['name']]!=1 or len(root['filenames'])!=1
                or index.files.get(root['filenames'][0])!=name or len(raw)!=len(extra)+len(slots)
                or not 0<count<COUNTER_LIMIT or loop_hits is None and count>entry
                or sorted(raw)!=sorted([*extra,*[[*slot,count,0,0,0] for slot in slots]])
                or root.get('mcdc_records') or any(r[0]<=last and r[2]>=line for r in root.get('branches',()))):
            return None
        measured = {n:counts[n] for n in range(line,last+1) if n in counts}
        _construct_charge(work,last-line+1+len(root.get('branches',())))
        projected = _owner_line_counts({'regions':raw},_ObserverWork(work))
        _construct_charge(work,len(projected))
        if {n:hits for n,hits in projected.items() if line<=n<=last}!=measured:
            return None
        payload_start = code.position(code.starts[start+7])[0]
        payload_end = code.position(code.ends[end-8])[0]
        mapped = [n for n in sorted(measured) if not payload_start<=n<=payload_end]
        signature = (qualified.identity,context[:2],setup,loop_context,words[:7]+words[-8:],
                     tuple((slot[1],slot[3]) for slot in slots),tuple(source[n-1] for n in mapped))
        observations.append((signature,mapped,payload,dict(symbol=root['name'],regions=raw,entry=entry)))
    old,new = observations
    if old[0]!=new[0] or old[2]==new[2]:
        return None
    return dict(kind='retained-fixture-script-write',file=name,pairs=[list(pair) for pair in zip(old[1],new[1],strict=True)],
                owners=[old[3],new[3]],claim='Write call, destination and result handling only')


def retained_test_queue_expectation(name, source, line, mapped, group, owners, names, files, inventory, work):
    """Bind a direct queue expectation using both the loop and its executed successor."""
    code, rows = inventory[:2]
    first, last, roots = group
    if len(roots) != 1 or mapped.get(line, 0) <= 0:
        return None
    root = roots[0]
    symbol = root['name']
    _construct_charge(work,len(symbol)+len(name)+1)
    shape = plain_rust_function_symbol(symbol)
    modules = tuple(name.removeprefix('src/').removesuffix('.rs').split('/'))
    if (shape is None or shape.identifiers[1:-1] != (*modules,'tests')
            or names[symbol] != 1 or root['count'] != 1 or root.get('branches') or root.get('mcdc_records')):
        return None
    _construct_charge(work,len(rows))
    def line_at(token):
        return code.position(code.starts[token])[0]
    enclosing = [row for row in rows if row['opening'] is not None
                 and line_at(row['first'])<=line<=line_at(row['end'])]
    loops = [row for row in enclosing if row['kind']=='for']
    functions = [row for row in enclosing if row['kind']=='fn']
    tests = [row for row in enclosing if row['kind']=='mod']
    if len(loops)!=1 or len(functions)!=1 or len(tests)!=1:
        return None
    loop, = loops
    function, = functions
    module, = tests
    if (module['header']!=('#','[','cfg','(','test',')',']','mod','tests')
            or function['header']!=('#','[','test',']','fn',shape.identifiers[-1],'(',')')
            or line_at(function['first']+4)!=first or line_at(function['end'])!=last
            or code.parents[function['opening']]!=module['opening']
            or code.parents[loop['opening']]!=function['opening']):
        return None
    header = loop['header']
    if len(header)!=4 or header[0]!='for' or header[2]!='in':
        return None
    literal = re.fullmatch(r'0\.\.([1-9][0-9]{0,17})', header[3], re.ASCII)
    if literal is None or re.fullmatch(r'[A-Za-z_]\w*',header[1],re.ASCII) is None:
        return None
    iterations = int(literal[1])
    start,stop = [bisect.bisect_left(code.starts,code.offsets[number-1]) for number in (line,line+1)]
    previous = bisect.bisect_left(code.starts,code.offsets[line-2])
    opening, closing = loop['opening'],loop['end']
    successor = closing+1
    following=['let','(','reply',',','_response',')','=','oneshot','::','channel','(',')',';']
    _construct_charge(work,closing-opening+len(following)+1)
    if (code.words[start:start+3]!=['.','expect','('] or stop-start!=6
            or not code.words[start+3].startswith('"') or code.words[start+4:stop]!=[')',';']
            or code.words[previous:previous+4]!=['tx','.','try_send','(']
            or code.pairs.get(previous+3)!=start-1
            or code.parents[previous]!=opening or code.parents[start]!=opening or stop!=closing
            or code.words[opening+1:previous]!=following
            or code.words[successor:successor+len(following)]!=following
            or code.parents[successor]!=function['opening']):
        return None
    payload=code.words[previous+4:start-1]
    if (payload!=['reply'] and (len(payload)!=12 or payload[1]!='::'
            or payload[3:]!=['(',header[1],'.','to_string','(',')',',','reply',')']
            or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None for word in payload[::2][:2]))):
        return None
    preceding=[row for row in inventory[3].get(line_at(loop['first'])-1, ())
               if row['end']+1==loop['first'] and code.parents[row['first']]==function['opening']]
    _construct_charge(work,len(preceding)+len(root['regions'])*(last-first+2))
    if len(preceding)!=1:
        return None
    assignment=code.words[preceding[0]['first']:preceding[0]['end']+1]
    if (assignment[:4]!=['let','(','tx',','] or assignment[-6:]!=[')','=','request_channel','(',')',';']
            or len(assignment) not in (11,12) or len(assignment)==12 and assignment[4]!='mut'
            or re.fullmatch(r'[A-Za-z_]\w*',assignment[-7],re.ASCII) is None):
        return None
    _construct_charge(work,sum(len(owner['regions'])+1 for owner in owners))
    if (source_owner_span(root,name,files,source) is None
            or [id(owner) for owner in owners if any(r[0]<=last and r[2]>=first for r in owner['regions'])]!=[id(root)]):
        return None
    envelope=code.region(opening,closing)
    receiver=code.region(previous,previous)
    call=code.region(previous+2,previous+2)
    after_loop=code.region(successor+7,successor+11)
    geometry={tuple(r[:4]):r[4] for r in root['regions']}
    if (len(geometry)!=len(root['regions'])
            or [geometry.get(span) for span in (envelope,receiver,call,after_loop)]!=[iterations]*3+[1]
            or [r for r in root['regions'] if r[0]<=line<=r[2]]!=[[*envelope,iterations,0,0,0]]
            or _owner_line_counts(root,_ObserverWork(work))!={n:mapped[n] for n in range(first,last+1) if n in mapped}):
        return None
    return shape.identity, iterations, dict(owner=symbol,loop_region=envelope,
        sender_region=receiver,send_region=call,successor_region=after_loop,counts=[iterations]*3+[1])


_INITIAL_TEST_RECORD = re.compile(r'[ \t]*let ([A-Za-z_]\w*) = ([A-Z]\w*) \{', re.ASCII)
_QUALIFIED_FIELD = re.compile(r'[ \t]*[A-Za-z_]\w*: (?:[A-Za-z_]\w*::)+[A-Za-z_]\w*,', re.ASCII)
_TEST_EXPECTED_ERROR = re.compile(r'[ \t]*\.expect_err\("[A-Za-z_0-9 -]{1,120}"\);', re.ASCII)


def async_test_fragment_owners(name, group, owners, names, inventory, first, last, work,
                               *, result_alias=False, runtime_helper=False):
    if inventory is None or len(group[2])!=1:
        return None
    code, rows = inventory[:2]
    _construct_charge(work,len(rows)+4)
    functions = [row for row in rows if row['kind']=='fn' and 'async' in row['header']
                 and code.position(code.starts[row['first']+row['header'].index('async')])[0]==group[0]
                 and code.position(code.ends[row['end']])[0]==group[1]]
    if len(functions)!=1:
        return None
    fn, = functions; words=fn['header']; scope=_boolean_module(code,{'start':fn['first']})
    if scope is None and result_alias and name=='src/runtimes/rust.rs':
        enclosing = code.ancestors(fn['first'])
        if len(enclosing)==1:
            module, = enclosing
            if (code.words[module-2:module]==['mod','tests']
                    and _boolean_attributes(code,module-2)==[
                        ['expect','(','clippy','::','unwrap_used',')'], ['cfg','(','test',')']]):
                scope = ['tests'],['tests'],[module]
    declaration = words.index('fn')
    tokio_test = ('#','[','tokio','::','test',']','async','fn')
    headers = (tokio_test, ('#','[','cfg','(','unix',')',']')+tokio_test) if result_alias else (tokio_test,)
    result = ('(',')','->','Result','<','(',')','>') if result_alias else _RESULT_TEST_SIGNATURE[6:]
    runtime_header=(runtime_helper and result_alias and name=='src/runtimes/rust.rs'
                    and words[:declaration+1]==('async','fn'))
    helper = (runtime_header and words[declaration+2:]==('(','corrupt',':','bool',',','missing_launcher',':',
                  'Option','<','&','str','>',')','->','Result','<','(',')','>'))
    enum_binding=None
    if (runtime_header and scope is not None and words[declaration+2:]==(
            '(','incremental',':','bool',',','selection',':','SourceSelection',')','->','Result','<','(',')','>')):
        module=code.parents[fn['first']]
        header=('#','[','derive','(','Clone',',','Copy',',','Debug',')',']','enum','SourceSelection')
        variants=('Wildcard',',','HostPreferred',',','Unavailable',',','Missing',',')
        _construct_charge(work,len(rows)+len(code.words)+1)
        enums=[row for row in rows if row['kind']=='enum' and row.get('header')==header
               and code.parents[row['first']]==module]
        bindings=[i for i,word in enumerate(code.words) if i and word=='SourceSelection'
                  and code.parents[i]==module and code.words[i-1] in ('enum','struct','type','trait','union','mod','fn')]
        if (len(enums)==len(bindings)==1
                and tuple(code.words[enums[0]['opening']+1:enums[0]['end']])==variants):
            enum_binding=(tuple(scope[0]),header,variants)
            helper=True
    if ((not helper and (words[:declaration+1] not in headers or words[declaration+2:]!=result))
            or scope is None or scope[:2]!=(['tests'],['tests'])):
        return None
    root, = group[2]; shape=plain_rust_function_symbol(root['name']); expected_body=None
    path = ('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'),'tests',words[declaration+1])
    open_at = code.position(code.starts[fn['opening']]); close_at = code.position(code.ends[fn['end']])
    entry = (*code.position(code.starts[fn['first']+(0 if helper else declaration)]),*code.position(code.ends[fn['opening']-1]))
    if helper and shape is None:
        expected_body=root
        _construct_charge(work,len(owners)+1)
        constructors=[owner for owner in owners if len(owner['regions'])==1
                      and tuple(owner['regions'][0][:4])==entry]
        if len(constructors)!=1:
            return None
        root,=constructors;shape=plain_rust_function_symbol(root['name'])
        if (shape is None or len(root['filenames'])!=1 or root['filenames']!=expected_body['filenames']
                or not direct_rust_callback_symbol(expected_body['name'],root['name'],shape.modules)):
            return None
    if (shape is None or shape.identifiers!=path or names[root['name']]!=1
            or type(root.get('count')) is not int or not 0<root['count']<COUNTER_LIMIT
            or [r[4] for r in root['regions'] if tuple(r[:4])==entry and r[5:]==[0,0,0]]!=[root['count']]):
        return None
    _construct_charge(work,sum(4*len(owner['regions'])+len(owner['name'])+1 for owner in owners))
    touching = [(owner,[r for r in owner['regions'] if r[0]<=last and (r[2]>first or r[2]==first and r[3]>1)]) for owner in owners]
    affected = [(owner,raw) for owner,raw in touching if raw]
    if len(affected)!=1:
        return None
    child, raw = affected[0]
    if expected_body is not None and child is not expected_body:
        return None
    body_entry = (*open_at,open_at[0],open_at[1]+1)
    children = [owner for owner in owners if direct_rust_callback_symbol(owner['name'],root['name'],shape.modules)]
    if (len(children)!=1 or children[0] is not child
            or names[child['name']]!=1 or child['filenames']!=root['filenames']
            or any(owner.get('branches') or owner.get('mcdc_records') for owner in (root,child))
            or type(child.get('count')) is not int or not 0<child['count']<=root['count']
            or [r[4] for r in child['regions'] if tuple(r[:4])==body_entry and r[5:]==[0,0,0]]!=[child['count']]
            or any(not open_at<=tuple(r[:2])<tuple(r[2:4])<=close_at for r in child['regions'])):
        return None
    identity=(shape.identity,words)
    witness=dict(root=root['name'],body=child['name'],regions=raw,entry=body_entry)
    if enum_binding is not None:
        identity=(*identity,enum_binding)
        witness['enum_parameter_source']=enum_binding
    return fn, identity, witness, child['count']


def initial_async_test_record(name, source, counts, group, owners, names, inventory, first, last, work):
    """Bind an unchanged eager record to its independently observed async body entry."""
    if last-first!=3:
        return None
    header = _INITIAL_TEST_RECORD.fullmatch(source[first-1]); field = source[first]
    if (header is None or _QUALIFIED_FIELD.fullmatch(field) is None
            or source[first+1].strip()!=f'..{header[2]}::default()' or source[last-1].strip()!='};'):
        return None
    scope = async_test_fragment_owners(name,group,owners,names,inventory,first,last,work)
    if scope is None:
        return None
    fn, identity, witness, hits = scope
    code, rows = inventory[:2]
    _construct_charge(work,len(rows))
    records = [row for row in rows if row.get('header')==('let',header[1],'=',header[2])
               and code.parents[row['first']]==fn['opening']
               and code.position(code.starts[row['first']])[0]==first
               and code.position(code.ends[row['end']])[0]==last]
    if len(records)!=1:
        return None
    record, = records
    start = record['first']; end = record['end']
    prefix = code.words[fn['opening']+1:start]
    _construct_charge(work,len(prefix)+end-start+1)
    if prefix and (prefix[0]!='use' or prefix[-1]!=';' or len(prefix)%2!=1
            or any(re.fullmatch(r'[A-Za-z_]\w*',part,re.ASCII) is None for part in prefix[1:-1:2])
            or any(part!='::' for part in prefix[2:-1:2])
            or prefix[-2] in code.words[start:end+1]):
        return None
    slots = [code.region(start+1,start+1),code.region(start+3,end)]
    if (witness['regions']!=[[*slot,hits,0,0,0] for slot in slots]
            or any(counts.get(line)!=hits for line in range(first,last+1))):
        return None
    return identity,witness


def async_test_expected_error(name, source, counts, group, owners, names, inventory, first, last, work):
    if first!=last or _TEST_EXPECTED_ERROR.fullmatch(source[first-1]) is None:
        return None
    scope = async_test_fragment_owners(name,group,owners,names,inventory,first,last,work)
    if scope is None:
        return None
    fn, identity, witness, hits = scope
    code, rows = inventory[:2]
    _construct_charge(work,len(rows)+len(code.starts).bit_length()+1)
    start = bisect.bisect_left(code.starts,code.offsets[first-1])
    if (code.parents[start]!=fn['opening']
            or code.words[start:start+3]!=['.','expect_err','(']
            or code.words[start+4:start+6]!=[')',';']):
        return None
    statements = [row for row in rows if row['kind']=='statement' and row['end']==start+5
                  and code.parents[row['first']]==fn['opening']]
    if len(statements)!=1:
        return None
    beginning = statements[0]['first']
    binder = code.words[beginning:beginning+3]
    if (len(binder)!=3 or binder[0]!='let' or binder[2]!='='
            or re.fullmatch(r'[A-Za-z_]\w*',binder[1],re.ASCII) is None):
        return None
    slot = code.words[start+3]
    _construct_charge(work,fn['end']-fn['opening'])
    if code.words[fn['opening']+1:fn['end']].count(slot)!=1:
        return None
    spans = [code.region(start+1,start+1),code.region(start+3,start+3)]
    if counts.get(first)!=hits or witness['regions']!=[[*span,hits,0,0,0] for span in spans]:
        return None
    return (*identity,tuple(binder),slot),witness


def sync_runtime_fragment_owners(name, group, owners, names, inventory, first, last, work):
    """Observe one exact synchronous Result test owner without inventing a future."""
    if inventory is None or len(group[2])!=1 or name not in ('src/runtimes/java.rs','src/runtimes/rust.rs'):
        return None
    code,rows=inventory[:2]
    _construct_charge(work,len(rows)+1)
    functions=[row for row in rows if row['kind']=='fn' and 'fn' in row['header'] and 'async' not in row['header']
               and code.position(code.starts[row['first']+row['header'].index('fn')])[0]==group[0]
               and code.position(code.ends[row['end']])[0]==group[1]]
    if len(functions)!=1:
        return None
    fn,=functions;words=fn['header'];at=words.index('fn')
    test=('#','[','test',']');unix=('#','[','cfg','(','unix',')',']')
    if (words[:at] not in (test,test+unix,unix+test)
            or words[at+2:] not in (('(',')'),('(',')','->','Result','<','(',')','>'))):
        return None
    scope=_boolean_module(code,{'start':fn['first']})
    if scope is None and name=='src/runtimes/rust.rs':
        enclosing=code.ancestors(fn['first'])
        if len(enclosing)==1:
            module,=enclosing
            if (code.words[module-2:module]==['mod','tests'] and _boolean_attributes(code,module-2)==[
                    ['expect','(','clippy','::','unwrap_used',')'],['cfg','(','test',')']]):
                scope=['tests'],['tests'],[module]
    if scope is None or scope[:2]!=(['tests'],['tests']):
        return None
    root,=group[2];shape=plain_rust_function_symbol(root['name']);hits=root.get('count')
    path=('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'),'tests',words[at+1])
    entry=code.region(fn['first']+at,fn['opening']-1);terminal=code.region(fn['end'],fn['end'])
    if (shape is None or shape.identifiers!=path or names[root['name']]!=1
            or type(hits) is not int or not 0<hits<COUNTER_LIMIT or len(root['filenames'])!=1
            or not root['filenames'][0].endswith('/'+name) or root.get('branches') or root.get('mcdc_records')
            or [r[4] for r in root['regions'] if tuple(r[:4])==entry and r[5:]==[0,0,0]]!=[hits]
            or [r[4] for r in root['regions'] if tuple(r[:4])==terminal and r[5:]==[0,0,0]]!=[hits]):
        return None
    records=[row for row in rows if row['opening'] is not None
             and code.position(code.starts[row['first']])[0]==first
             and code.position(code.ends[row['end']])[0]==last]
    if len(records)!=1:
        return None
    lo,hi=code.region(records[0]['first'],records[0]['end'])[:2],code.region(records[0]['first'],records[0]['end'])[2:]
    _construct_charge(work,sum(len(owner['regions'])+1 for owner in owners))
    touching=[(owner,[r for r in owner['regions'] if tuple(r[:2])<hi and lo<tuple(r[2:4])]) for owner in owners]
    affected=[(owner,raw) for owner,raw in touching if raw]
    if (len(affected)!=1 or affected[0][0] is not root
            or any(r[5:]!=[0,0,0] or type(r[4]) is not int or not 0<=r[4]<=hits
                   or not lo<=tuple(r[:2])<tuple(r[2:4])<=hi for r in affected[0][1])):
        return None
    return fn,(shape.identity,words),dict(root=root['name'],regions=affected[0][1],entry=entry,synchronous=True),hits


def async_runtime_fixture_record(name, source, counts, group, owners, names, inventory, first, last, work):
    """Project a fixture record through the addition of its eager security field."""
    managers = {'src/runtimes/java.rs':'JavaManager', 'src/runtimes/rust.rs':'RustManager'}
    manager = managers.get(name)
    if (manager is None or inventory is None or first!=last
            or source[first-1].strip()!=f'let manager = {manager} {{'):
        return None
    code, rows = inventory[:2]
    _construct_charge(work,len(rows))
    candidates = [row for row in rows if row.get('header')==('let','manager','=',manager)
                  and code.position(code.starts[row['first']])[0]==first]
    if len(candidates)!=1:
        return None
    record, = candidates
    closing = code.position(code.ends[record['end']])[0]
    if closing-first not in (3,4) or source[closing-1].strip()!='};':
        return None
    synchronous=source[group[0]-1].lstrip().startswith('fn ')
    if synchronous:
        bound=sync_runtime_fragment_owners(name,group,owners,names,inventory,first,closing,work)
    else:
        bound = async_test_fragment_owners(name,group,owners,names,inventory,first,closing,work,
                                           result_alias=True,runtime_helper=True)
    if bound is None:
        return None
    function, identity, witness, entry_hits = bound
    if (synchronous or identity[1][:2]==('async','fn')) and any(row[4]>entry_hits for row in witness['regions']):
        return None
    if code.parents[record['first']]!=function['opening'] or counts.get(first,0)<=0:
        return None
    initializer = 'crate::runtimes::security::RuntimeSecurity::fixture'
    insertion = closing-first==4
    added = first+1
    if insertion and source[added-1].strip()!=f'security: {initializer}(),':
        return None
    source_rows = source[first-1:closing]
    _construct_charge(work,sum(len(text)+1 for text in source_rows)+len(witness['regions']))
    if insertion:
        extra = source_rows.pop(1)
        start = extra.index(initializer)+1
        slot = (added,start,added,start+len(initializer))
    def relative(line):
        return line-first-int(insertion and line>added)
    region_states = []; additions = []
    for row in witness['regions']:
        if row[5:]!=[0,0,0]:
            return None
        if insertion and tuple(row[:4])==slot:
            additions.append(row)
            continue
        if insertion and added in (row[0],row[2]):
            return None
        region_states.append((relative(row[0]),row[1],relative(row[2]),row[3],row[4]>0))
    if insertion and (len(additions)!=1 or additions[0][4]!=entry_hits or counts.get(added,0)<=0):
        return None
    observed = _owner_line_counts({'regions':witness['regions']},_ObserverWork(work))
    if observed!={line:counts[line] for line in range(first,closing+1) if line in counts}:
        return None
    witness.update(record_span=[first,closing],security_initializer=additions)
    return (identity,tuple(source_rows),tuple(sorted(region_states))),witness


def async_runtime_inventory_assertion(name, source, counts, group, owners, names, inventory, first, last, work):
    """Keep one closed published-artifact assertion while separately observing its new security terms."""
    if name!='src/runtimes/rust.rs' or inventory is None or first!=last or first<1 or first+2>len(source):
        return None
    _construct_charge(work,sum(len(line)+1 for line in source[first-1:first+2])+1)
    if [line.strip() for line in source[first-1:first+2]]!=['assert_eq!(','names,','BTreeSet::from([']:
        return None
    code,rows=inventory[:2]
    start=bisect.bisect_left(code.starts,code.offsets[first-1])
    if code.words[start:start+3]!=['assert_eq','!','(']:
        return None
    end=code.pairs.get(start+2)
    if end is None or code.words[end+1:end+2]!=[';']:
        return None
    closing=code.position(code.ends[end+1])[0]
    insertion=closing-first==9
    if closing-first not in (7,9):
        return None
    text=source[first-1:closing]
    _construct_charge(work,sum(len(line)+1 for line in text)+1)
    if insertion:
        if [line.strip() for line in text[4:6]]!=[
            'format!(".admission-{}.lock", toolchain.name()).into(),','".security".into(),']:
            return None
        text=text[:4]+text[6:]
    if [line.strip() for line in text]!=['assert_eq!(','names,','BTreeSet::from([',
            '".mutation.lock".into(),','"current".into(),','toolchain.name().into()','])',');']:
        return None
    bound=async_test_fragment_owners(name,group,owners,names,inventory,first,closing,work,
                                     result_alias=True,runtime_helper=True)
    if bound is None or bound[1][1][:2]!=('async','fn'):
        return None
    function,identity,witness,body_hits=bound
    if code.parents[start]!=function['opening']:
        return None
    _construct_charge(work,3*len(rows)+end-start+1)
    statements=[row for row in rows if row['kind']=='statement'
                and code.parents[row['first']]==function['opening'] and row['end']<start]
    preceding=[row for row in statements if row['end']==start-1]
    declarations=[row for row in statements if code.words[row['first']:row['first']+2]==['let','versions']]
    pipeline=('let','names',':','BTreeSet','<','_','>','=','fs','::','read_dir','(','versions','.',
        'path','(',')',')','?','.','map','(','|','entry','|','entry','.','map','(','|','item','|','item','.',
        'file_name','(',')',')',')','.','collect','::','<','std','::','io','::','Result','<','_','>','>',
        '(',')','?',';')
    version_source=('let','versions','=','TempDir','::','new','(',')','?',';')
    if (len(preceding)!=1 or len(declarations)!=1
            or tuple(code.words[preceding[0]['first']:start])!=pipeline
            or tuple(code.words[declarations[0]['first']:declarations[0]['end']+1])!=version_source):
        return None
    raw=witness['regions'];entry=code.region(start,start+1)
    hits=[row[4] for row in raw if tuple(row[:4])==entry]
    if (len(hits)!=1 or not 0<hits[0]<=body_hits
            or any(row[5:]!=[0,0,0] or type(row[4]) is not int or row[4]!=hits[0] for row in raw)):
        return None
    additions=[];slots=[]
    if insertion:
        for added,markers in ((first+4,((0,1),(5,5),(7,7),(12,12))),
                               (first+5,((0,0),(2,2)))):
            token=bisect.bisect_left(code.starts,code.offsets[added-1])
            slots.extend(code.region(token+a,token+b) for a,b in markers)
    def relative(line):
        return line-first-int(insertion and line>first+4)-int(insertion and line>first+5)
    geometry=[]
    for row in raw:
        if tuple(row[:4]) in slots:
            additions.append(row);continue
        if insertion and (row[0] in (first+4,first+5) or row[2] in (first+4,first+5)):
            return None
        geometry.append((relative(row[0]),row[1],relative(row[2]),row[3],row[4]>0))
    if sorted(tuple(row[:4]) for row in additions)!=sorted(slots):
        return None
    observed=_owner_line_counts({'regions':raw},_ObserverWork(work))
    if observed!={line:counts[line] for line in range(first,closing+1) if line in counts}:
        return None
    witness.update(record_span=[first,closing],security_terms=additions,shift_after=first+3)
    return ((identity,pipeline,version_source),tuple(text),tuple(sorted(geometry))),witness


def async_policy_unavailable_assertion(name, source, counts, group, owners, names, inventory, first, last, work):
    """Keep the executed terminal assertion entry when the advisory test driver changes."""
    code, rows=inventory[:2]
    if first!=last or source[first-1].strip()!='assert!(':
        return None
    _construct_charge(work,len(code.starts).bit_length())
    start=bisect.bisect_left(code.starts,code.offsets[first-1])
    if code.words[start:start+3]!=['assert','!','(']:
        return None
    close=code.pairs[start+2]
    if code.words[close+1:close+2]!=[';']:
        return None
    last=code.position(code.ends[close+1])[0]
    old_call=('check_prepared_with_source','(','&','policy',',','package','(','false',')',',',
              '&','FailingVulns',')','.','await','.','is_err','(',')')
    new_check=('matches','!','(','error','.','downcast_ref','::','<','VulnerabilityError','>','(',')',',',
               'Some','(','VulnerabilityError','::','Unavailable','{','reason','}',')',
               'if','reason','=','=','"osv unavailable"',')')
    _construct_charge(work,close-start)
    body=tuple(code.words[start+3:close])
    head=body==new_check
    if not head and body!=old_call:
        return None
    low=first
    argument=start+3
    if head:
        _construct_charge(work,len(rows))
        preceding={row['end']:row for row in rows if row['kind']=='statement'
                  and row['supported'] and code.parents[row['first']]==code.parents[start]}
        call=preceding.get(start-1)
        fixture=preceding.get(call['first']-1) if call is not None else None
        if (fixture is None or code.words[call['first']:start]!=[
                'let','error','=','service','.','update','(',')','.','await','.','expect_err','(',
                '"review must preserve unavailable evidence"',')',';']
                or code.words[fixture['first']:call['first']]!=[
                    'let','service','=','update_service','(','SecurityPolicy','{',
                    'advisory_requirement',':','AdvisoryRequirement','::','Review',',','.','.','policy','}',',',
                    'std','::','sync','::','Arc','::','new','(','FailingVulns',')',',',')','.',
                    'expect','(','"construct the fake package-service fixture"',')',';']):
            return None
        low=code.position(code.starts[fixture['first']])[0]
        supply=fixture['first']+code.words[fixture['first']:call['first']].index('std')
        update=call['first']
        required=[code.region(supply,supply+9),code.region(update+3,update+9),
                  code.region(update+11,update+11),code.region(argument+5,argument+5)]
    else:
        required=[code.region(argument+a,argument+b) for a,b in ((0,0),(10,11),(14,14),(16,16))]
    scope=async_test_fragment_owners(name,group,owners,names,inventory,low,last,work)
    if scope is None:
        return None
    fn,identity,witness,hits=scope
    if (code.parents[start]!=fn['opening'] or code.words[close+2:fn['end']]!=['Ok','(','(',')',')']):
        return None
    _construct_charge(work,fn['end']-fn['opening']+sum(len(owner['regions']) for owner in owners))
    if code.words[fn['opening']+1:fn['end']].count('FailingVulns')!=1:
        return None
    entry=code.region(start,start+1)
    data=witness['regions']
    _construct_charge(work,2*len(data))
    geometries={tuple(r[:4]) for r in data}
    if ([r for r in data if r[0]<=first<=r[2]]!=[[*entry,hits,0,0,0]]
            or not set(required)<=geometries or counts.get(first)!=hits
            or any(r[5:]!=[0,0,0] or r[4]!=hits for r in data)
            or _owner_line_counts({'regions':data},_ObserverWork(work))!={
                line:counts[line] for line in range(low,last+1) if line in counts}):
        return None
    tail=code.region(close+2,fn['end']-1)
    tail_line=tail[0]
    completion=[(owner['name'],r) for owner in owners for r in owner['regions']
                if r[0]<=tail_line and (r[2]>tail_line or r[2]==tail_line and r[3]>1)]
    if (len(completion)!=2 or {symbol for symbol,_ in completion}!={witness['root'],witness['body']}
            or any(r!=[*tail,hits,0,0,0] for _,r in completion) or counts.get(tail_line)!=2*hits):
        return None
    return identity,dict(witness,entry=list(entry),terminal=list(tail),typed=head)


def async_test_expected_variant(name, source, counts, group, owners, names, inventory, first, last, work):
    """Observe the assertion entry after an independently executed test error binding."""
    if first!=last or not 1<first<len(source) or _TEST_EXPECTED_ERROR.fullmatch(source[first-2]) is None:
        return None
    code = inventory[0]
    _construct_charge(work,2*len(code.starts).bit_length()+1)
    start = bisect.bisect_left(code.starts,code.offsets[first-1])
    before = bisect.bisect_left(code.starts,code.offsets[first-2])
    if (code.words[start:start+6]!=['assert','!','(','matches','!','(']
            or code.words[before:before+3]!=['.','expect_err','(']
            or before+6!=start or code.words[before+4:start]!=[')',';']
            or code.parents[start]!=code.parents[before]):
        return None
    close = code.pairs[start+5]
    if code.pairs[start+2]!=close+1 or code.words[close+2]!=';':
        return None
    final = code.position(code.ends[close+2])[0]
    if not 0<final-first<=7:
        return None
    _construct_charge(work,4*(close-start+3))
    args = _boolean_arguments(code,start+5)
    if args is None or len(args)!=2:
        return None
    (value,value_end),(pattern,pattern_end) = args
    named = code.words[pattern:pattern_end]
    wrapped = named[:2]==['Some','('] and code.pairs[pattern+1]==pattern_end-1
    if wrapped:
        named=named[2:-1]
    if (len(named)!=13 or tuple(named[i] for i in (1,3,5,7,9,10,11,12))!=('::','{',':','::',',','.','.','}')
            or any(re.fullmatch(r'[A-Za-z_]\w*',named[i],re.ASCII) is None for i in (0,2,4,6,8))):
        return None
    tail = ['.','downcast_ref','::','<',named[0],'>','(',')'] if wrapped else []
    if code.words[value+1:value_end]!=tail:
        return None
    expected_statements = inventory[3].get(first-1,())
    assertion_statements = inventory[3].get(first,())
    _construct_charge(work,len(expected_statements)+len(assertion_statements))
    bindings = [row for row in expected_statements if row['kind']=='statement'
                and row['supported'] and row['end']==start-1 and code.parents[row['first']]==code.parents[start]
                and code.words[row['first']:row['first']+3]==['let',code.words[value],'=']]
    if len(bindings)!=1 or not any(row['kind']=='statement' and row['supported']
                                   and row['first']==start and row['end']==close+2 for row in assertion_statements):
        return None
    scope = async_test_fragment_owners(name,group,owners,names,inventory,first-1,final,work)
    if scope is None:
        return None
    function, identity, witness, hits = scope
    message = code.words[before+3]
    _construct_charge(work,function['end']-function['opening'])
    if (code.parents[start]!=function['opening']
            or code.words[function['opening']+1:function['end']].count(message)!=1):
        return None
    slots = [(code.region(before+1,before+1),hits),(code.region(before+3,before+3),hits),
             (code.region(start,start+1),hits),(code.region(start+3,start+4),0),(code.region(value,value),hits)]
    if wrapped:
        slots.append((code.region(value+2,value+2),hits))
    if (witness['regions']!=[[*slot,count,0,0,0] for slot,count in slots]
            or _owner_line_counts({'regions':witness['regions']},_ObserverWork(work))!={
                line:counts[line] for line in range(first-1,final+1) if line in counts}):
        return None
    return (*identity,code.words[value],message,tuple(named)), dict(witness,wrapped=wrapped)


def direct_assertion_anchor(code, start, stop, work):
    """Identify one direct assertion by a stable condition role or expected value."""
    macro = code.words[start]
    if (macro not in ('assert', 'assert_eq') or code.words[start+1:start+3]!=['!','(']
            or code.pairs.get(start+2)!=stop-1 or code.words[stop]!=';'):
        return None
    _construct_charge(work,4*(stop-start+1))
    args = _boolean_arguments(code,start+2)
    if args is None or len(args)!=2:
        return None
    (left,end),(right,last) = args
    if last-right!=1 or not code.words[right].startswith('"'):
        return None
    if macro=='assert_eq':
        closing = code.pairs.get(left+1)
        if (not re.fullmatch(r'[A-Za-z_]\w*',code.words[left],re.ASCII)
                or code.words[left+1]!='(' or closing is None or closing+5!=end
                or code.words[closing+1:end]!=['.','unwrap','(',')']
                or any(word in ('!','?','{','[','return','break','continue','await','yield')
                       for word in code.words[left+2:closing])):
            return None
        return (macro,code.words[left],code.words[right]), (), (
            code.region(left,left),code.region(closing+2,closing+2))
    if (code.words[left:left+3]!=['matches','!','('] or code.pairs.get(left+2)!=end-1):
        return None
    nested = _boolean_arguments(code,left+2)
    if nested is None or len(nested)!=2:
        return None
    (value,value_end),(pattern,pattern_end) = nested
    if any(word in ('!','?','{','[','return','break','continue','await','yield')
           for word in code.words[value:value_end]):
        return None
    if (code.words[pattern:pattern+2]==['Err','('] and code.pairs.get(pattern+1)==pattern_end-1):
        pattern+=2; pattern_end-=1
    path = code.words[pattern:pattern_end-3]
    if (len(path)<3 or len(path)%2==0 or path[1::2]!=['::']*(len(path)//2)
            or code.words[pattern_end-3:pattern_end]!=['(','_',')']
            or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None for word in path[::2])):
        return None
    return (macro,*path), (code.region(left,left+1),), ()


def retained_direct_unit_assertion(name, source, line, mapped, group, owners, names, files, inventory, work):
    """Prove the direct assertion entry and stable subentry in a single test root."""
    code,rows = inventory[:2]
    first,last,roots = group
    if len(roots)!=1 or not first<line<last:
        return None
    root, = roots
    symbol=root['name']
    _construct_charge(work,len(symbol)+len(name)+1)
    shape=plain_rust_function_symbol(symbol)
    modules=tuple(name.removeprefix('src/').removesuffix('.rs').split('/'))
    if (shape is None or shape.identifiers[:-1]!=('omg_lib',*modules,'tests')
            or names[symbol]!=1 or root['count']!=1 or root.get('branches') or root.get('mcdc_records')):
        return None
    line_start = bisect.bisect_left(code.starts,code.offsets[line-1])
    line_end = bisect.bisect_left(code.starts,code.offsets[line])
    if code.words[line_start:line_end] not in (['assert','!','('],['assert_eq','!','(']):
        return None
    function_open=code.parents[line_start]
    test_open=code.parents[function_open] if function_open is not None else None
    _construct_charge(work,2*len(rows))
    expected=[('fn',function_open,('#','[','test',']','fn',shape.identifiers[-1],'(',')')),
              ('mod',test_open,('#','[','cfg','(','test',')',']','mod','tests'))]
    if (any(opening is None for _,opening,_ in expected)
            or sum((row['kind'],row['opening'],row.get('header')) in expected for row in rows)!=2):
        return None
    statement = [(row,anchor) for row in rows
                 if row['kind']=='statement' and row['supported'] and code.parents[row['first']]==function_open
                 and code.words[row['first']]==code.words[line_start]
                 and (anchor:=direct_assertion_anchor(code,row['first'],row['end'],work)) is not None]
    current = [(row,anchor) for row,anchor in statement if row['first']==line_start]
    if len(current)!=1:
        return None
    (row,(anchor,markers,entries)), = current
    _construct_charge(work,len(statement))
    if sum(candidate[0]==anchor for _,candidate in statement)!=1:
        return None
    if anchor[0]=='assert' and len(anchor)==4:
        imports=[]
        _construct_charge(work,len(rows))
        for declaration in rows:
            start, end = declaration['first'], declaration['end']
            if (declaration['kind']!='statement' or not declaration['supported']
                    or code.parents[start]!=function_open or code.words[start]!='use'
                    or code.words[end-1:end+1]!=[anchor[1],';']):
                continue
            _construct_charge(work,end-start+1)
            path=code.words[start+1:end]
            if (len(path)<3 or len(path)%2==0 or path[1::2]!=['::']*(len(path)//2)
                    or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None for word in path[::2])):
                return None
            imports.append(path)
        if len(imports)!=1:
            return None
        anchor=('assert',*imports[0],*anchor[2:])
    low,high = code.region(line_start,row['end'])[:2],code.region(line_start,row['end'])[2:]
    expected_entry = code.region(line_start,line_start+1)
    _construct_charge(work,sum(len(owner['regions'])+1 for owner in owners)+len(root['regions'])*(last-first+2))
    owner_span = source_owner_span(root,name,files,source)
    if owner_span is None or owner_span[:2]!=(first,last):
        return None
    scope=[]
    for owner in owners:
        touching=[region for region in owner['regions'] if tuple(region[:2])<high and low<tuple(region[2:4])]
        if not touching:
            continue
        if (owner is not root or any(not low<=tuple(region[:2])<tuple(region[2:4])<=high
                                     or not 0<=region[4]<COUNTER_LIMIT for region in touching)):
            return None
        scope.extend(touching)
    _construct_charge(work,3*len(scope)+high[0]-low[0]+1)
    observed={tuple(r[:4]):r[4] for r in scope}
    if (len(observed)!=len(scope) or observed.get(expected_entry)!=root['count']
            or [tuple(r[:4]) for r in scope if r[0]<=line<=r[2]]!=[expected_entry]
            or any(slot not in observed for slot in (*markers,*entries))
            or any(not count and region not in markers for region,count in observed.items())
            or _owner_line_counts({'regions':scope},_ObserverWork(work))!={
                n:mapped[n] for n in range(low[0],high[0]+1) if n in mapped}):
        return None
    return (shape.identity,anchor,tuple(bool(observed[slot]) for slot in (*markers,*entries)),
            dict(owner=symbol,span=[*low,*high],entry=list(expected_entry),regions=scope))


_ALPM_REPLACE_ANCHOR = ('alpm','::','Question','::','Replace','(','q',')','=>')
_ALPM_CALLBACK_CAPTURE = (
    ('Arc','::','clone','(','refusals',')',',','|','question',',','refusals','|'),
    ('(','Arc','::','clone','(','refusals',')',',','policy',')',',',
     '|','question',',','(','refusals',',','policy',')','|'),
)


def alpm_replacement_scope(source, inventory, groups, first, last, side, work):
    code,rows=inventory[:2]
    _construct_charge(work,len(rows)+len(code.starts).bit_length())
    start=bisect.bisect_left(code.starts,code.offsets[first-1])
    branch=('let','confirmed','=','if','auto_accept','{','true','}','else')
    if tuple(code.words[start:start+len(branch)])!=branch or code.position(code.starts[start+6])[0]!=last:
        return None
    arm,match,opening,arguments,function_open,*extra=_construct_ancestors(code,start,work)+[None]*5
    if None in (arm,match,opening,arguments,function_open) or any(item is not None for item in extra):
        return None
    candidates={row['opening']:row for row in rows if row['opening'] in (arm,match,function_open)}
    if len(candidates)!=3:
        return None
    function=candidates[function_open]
    if (candidates[arm]['header']!=_ALPM_REPLACE_ANCHOR
            or candidates[match]['header']!=('match','question','.','question','(',')')
            or function['kind']!='fn' or function['header'][0]!='fn'):
        return None
    call=arguments-3; close=code.pairs[opening]
    if (code.words[call:arguments+1]!=['alpm','.','set_question_cb','(']
            or tuple(code.words[arguments+1:opening])!=_ALPM_CALLBACK_CAPTURE[side]
            or code.pairs[arguments]!=close+1 or code.words[close+1:close+3]!=[')',';']):
        return None
    header=function['header']
    if header[2:9]!=('(','alpm',':','&','alpm','::','Alpm'):
        return None
    root_span=(code.position(code.starts[function['first']])[0],code.position(code.ends[function['end']])[0])
    _construct_charge(work,len(groups)+function['end']-function_open+1)
    roots=[group for group in groups.values() if group[:2]==root_span]
    if len(roots)!=1:
        return None
    scopes=[]; nest=('.','map','(','|','package','|','package','.','name','(',')','.','to_string','(',')',')')
    for token in range(opening+1,close):
        if code.words[token:token+3]==['.','map','('] and tuple(code.words[token:token+len(nest)])==nest:
            scopes.append([code.region(token+6,token+10),code.region(token+12,token+12)])
    if len(scopes)!=2:
        return None
    wrapper=None
    if side:
        _construct_charge(work,len(rows))
        witnesses=[row for row in rows if row['kind']=='fn' and row['header'][:8]==
                   ('#','[','cfg','(','test',')',']','fn') and code.parents[row['opening']] is None
                   and code.words[row['opening']+1:row['end']]==[
                       header[1],'(','alpm',',','refusals',',','TransactionPolicy','::','Standard',')']]
        if len(witnesses)!=1 or header[-7:]!=('policy',':','TransactionPolicy',',',')','->','ProgressTask'):
            return None
        wrapper=witnesses[0]['header'][7:]
        if (header[0],wrapper[1],*header[2:-7],*header[-3:])!=wrapper:
            return None
    return (header,wrapper,roots[0],code.region(call,close+2),code.region(opening,close),
            [code.region(call,call),code.region(call+2,call+2)],scopes,
            [code.region(token,token) for token in (start+1,start+4,start+6)])


def retained_alpm_replace_branch(sides, inventories, names, groups, work):
    source_claims=[]; copy_receipts=[]; copy_states=[]
    for side,(source,inventory,counts,first,last) in enumerate(sides):
        claim=alpm_replacement_scope(source,inventory,groups[side],first,last,side,work)
        if claim is None:
            return None
        header,wrapper,group,statement,closure,registrations,nesting,slots=claim
        low,high=statement[:2],statement[2:]
        source_claims.append((header,wrapper,group[:2]))
        owners=inventories[side]; _construct_charge(work,len(owners))
        touching={}
        for owner in owners:
            _construct_charge(work,len(owner['regions']))
            selected=[r for r in owner['regions'] if tuple(r[:2])<high and low<tuple(r[2:4])]
            if selected:
                _construct_charge(work,len(owner['name'])+len(selected))
                if (names[side][owner['name']]!=1 or owner.get('branches') or owner.get('mcdc_records')
                        or any(r[5:]!=[0,0,0] or not low<=tuple(r[:2])<tuple(r[2:4])<=high
                               or not 0<=r[4]<COUNTER_LIMIT for r in selected)):
                    return None
                touching[owner['name']]=owner,selected
        vectors=[]; raw=[]; copy_evidence=[]
        if not 1<=len(group[2])<=16:
            return None
        for root in group[2]:
            symbol=root['name']; shape=plain_rust_function_symbol(symbol)
            prefix='_RNC'+symbol[2:]
            _construct_charge(work,4*len(symbol)+1)
            if (shape is None or shape.identifiers!=('omg_lib','package_managers','alpm_ops',header[1])
                    or not 0<=root['count']<COUNTER_LIMIT):
                return None
            member=touching.pop(symbol,None)
            if member is None or member[0] is not root:
                return None
            root_slots=member[1]
            _construct_charge(work,3*len(root_slots))
            if (any([r[4] for r in root_slots if tuple(r[:4])==marker]!=[root['count']] for marker in registrations)
                    or any(r[0]<=last and (r[2]>first or r[2]==first and r[3]>1) for r in root_slots)):
                return None
            child_key=prefix+'0'+rust_same_crate_backref(shape.modules,1)
            member=touching.pop(child_key,None)
            if member is None or not direct_rust_callback_symbol(child_key,symbol,shape.modules):
                return None
            child,child_slots=member
            _construct_charge(work,3*len(child_slots))
            if (len(child_slots)!=len(child['regions']) or child['filenames']!=root['filenames']
                    or not 0<=child['count']<COUNTER_LIMIT
                    or (*min(tuple(r[:2]) for r in child_slots),*max(tuple(r[2:4]) for r in child_slots))!=closure):
                return None
            entry=(*closure[:2],closure[0],closure[1]+1)
            observed=[r for r in child_slots if r[0]<=last and (r[2]>first or r[2]==first and r[3]>1)]
            if ([r[4] for r in child_slots if tuple(r[:4])==entry]!=[child['count']]
                    or [tuple(r[:4]) for r in observed]!=slots):
                return None
            descendants=[]
            for ordinal,expected in zip(('00','0s_0'),nesting):
                key='_RNCNC'+symbol[2:]+ordinal+rust_same_crate_backref(shape.modules,2)
                member=touching.pop(key,None)
                if member is None or not direct_rust_callback_symbol(key,symbol,shape.modules,2):
                    return None
                nested,cells=member
                if (nested['filenames']!=root['filenames'] or len(cells)!=len(nested['regions'])
                        or [tuple(r[:4]) for r in cells]!=expected
                        or any(r[0]<=last and (r[2]>first or r[2]==first and r[3]>1) for r in cells)):
                    return None
                descendants.append(key)
            raw.extend(observed)
            vectors.append(tuple(bool(row[4]) for row in observed))
            copy_evidence.append(dict(root=symbol,child=child_key,descendants=descendants,regions=observed))
        if touching or _owner_line_counts({'regions':raw},_ObserverWork(work))!={
                line:counts[line] for line in range(first,last+1) if line in counts}:
            return None
        copy_receipts.append(copy_evidence); copy_states.append(sorted(vectors))
    if source_claims[0][0]!=source_claims[1][1] or copy_states[0]!=copy_states[1]:
        return None
    return source_claims,copy_receipts,copy_states


def policy_license_fixture_assertions(name, source, counts, group, owners, names, files, inventory, line, work):
    """Observe the three license tests across explicit distribution-origin admission."""
    code,rows=inventory[:2]
    first,last,roots=group
    if len(roots)!=1:
        return None
    root,=roots
    symbol=root['name']
    _construct_charge(work,len(symbol)+len(rows))
    shape=plain_rust_function_symbol(symbol)
    if (shape is None or shape.identifiers[:-1]!=('omg_lib','core','security','policy','tests')
            or names[symbol]!=1 or root['count']!=1 or root.get('branches') or root.get('mcdc_records')):
        return None
    header=('#','[','test',']','fn',shape.identifiers[-1],'(',')')
    functions=[row for row in rows if row['kind']=='fn' and row['header']==header
               and code.position(code.starts[row['first']+4])[0]==first
               and code.position(code.ends[row['end']])[0]==last]
    if len(functions)!=1:
        return None
    function,=functions
    context=_boolean_module(code,{'start':function['first']})
    if context is None or context[:2]!=(['tests'],['tests']):
        return None
    _construct_charge(work,len(rows)+function['end']-function['opening'])
    statements=sorted((row['first'],row['end']) for row in rows if row['kind']=='statement' and row['supported']
                      and code.parents[row['first']]==function['opening'])
    if len(statements)!=8:
        return None
    terminal,terminal_end=statements[-1]
    empty=('assert','!','(','combined_license_expression','(','std','::','iter','::','empty','(',')',')',
           '.','is_none','(',')',')',';')
    if tuple(code.words[terminal:terminal_end+1])!=empty or terminal_end+1!=function['end']:
        return None
    setup,end_setup=statements[0]
    expected_setup=('let','policy','=','SecurityPolicy','{','allowed_licenses',':','vec','!','[',
                    '"MIT"','.','into','(',')',']',',','.','.','SecurityPolicy','::','default','(',')','}',';')
    if tuple(code.words[setup:end_setup+1])!=expected_setup:
        return None
    _construct_charge(work,len(owners)+sum(len(owner['regions']) for owner in owners))
    if [id(owner) for owner in owners if any(r[0]<=last and (r[2]>first or r[2]==first and r[3]>1)
            for r in owner['regions'])]!=[id(root)]:
        return None
    span=source_owner_span(root,name,files,source)
    raw=root['regions']
    if (span is None or span[:2]!=(first,last) or any(r[4]!=1 for r in raw)
            or _owner_line_counts(root,_ObserverWork(work))!={n:counts[n] for n in range(first,last+1) if n in counts}):
        return None
    chosen=[]; modern=[]; proof=[]
    expected_cases=(('"multi"',('"MIT"',',','"GPL-3.0"'),'is_err'),
                    ('"multi"',('"MIT OR Apache-2.0"',',','"GPL-3.0"'),'is_err'),
                    ('"single"',('"MIT"',),'is_ok'))
    for index,(package,values,result) in enumerate(expected_cases):
        (binding,end_binding),(assertion,end_assertion)=statements[1+2*index:3+2*index]
        variable=code.words[binding+1]
        lexical=('let',variable,'=','combined_license_expression','(','[',*values,']',')',';')
        if (tuple(code.words[binding:end_binding+1])!=lexical or end_binding+1!=assertion
                or code.words[assertion:assertion+7]!=['assert','!','(','policy','.','check_source','(']):
            return None
        opening=assertion+6
        arguments=_boolean_arguments(code,opening)
        if arguments is None or len(arguments)!=3:
            return None
        destination,origin,input_=arguments
        origin_tokens=tuple(code.words[slice(*origin)])
        modern.append(origin_tokens==('&','SecurityOrigin','::','DistributionPackage'))
        if (not modern[-1] and origin_tokens!=('false',)
                or code.words[slice(*destination)]!=[package]
                or code.words[slice(*input_)]!=[variable,'.','as_deref','(',')']):
            return None
        close=code.pairs[opening]
        if code.words[close+1:end_assertion+1]!=['.',result,'(',')',')',';']:
            return None
        bindings=[code.region(binding+1,binding+1),code.region(binding+3,binding+3),
                  code.region(binding+5,end_binding-2)]
        slots=[code.region(assertion,assertion+1),code.region(assertion+3,assertion+3),
               code.region(assertion+3,close),code.region(assertion+5,assertion+5),
               code.region(destination[0],destination[1]-1)]
        if modern[-1]:
            slots.append(code.region(origin[0],origin[1]-1))
        slots.append(code.region(close+2,close+2))
        low,high=code.region(binding,end_assertion)[:2],code.region(binding,end_assertion)[2:]
        _construct_charge(work,len(raw))
        seen=[row for row in raw if tuple(row[:2])<high and low<tuple(row[2:4])]
        if seen!=[[*coordinates,1,0,0,0] for coordinates in (*bindings,*slots)]:
            return None
        chosen.extend([bindings[0][0],slots[0][0],slots[1][0],slots[-1][0]])
        proof.append(dict(input=variable,regions=seen))
    if len(set(modern))!=1 or chosen[1]!=line or len(set(chosen))!=len(chosen):
        return None
    return shape.identity,chosen,dict(owner=symbol,modern=modern[0],assertions=proof)


def prepared_policy_file_steps(code, rows, opening, closing, raw, hits, modern, work):
    path=('let','path','=','directory','.','path','(',')','.','join','(','"policy.toml"',')',';')
    write=('fs','::','write','(','&','path',',','&','bytes',')','?',';')
    readback=('assert_eq','!','(','fs','::','read_to_string','(','&','path',')','?',',','bytes',')',';')
    reason=('"osv unavailable"' if modern else
            '"OSV has no configured ecosystem for the running package backend"')
    verify=('assert','!','(','matches','!','(','error','.','downcast_ref','::','<','VulnerabilityError','>','(',')',',',
            'Some','(','VulnerabilityError','::','Unavailable','{','reason','}',')',
            'if','reason','=','=',reason,')',')',';')
    preceding=('let','error','=','runtime','.','block_on','(','service','.','update','(',')',')') if modern else (
        'let','error','=','check_prepared_packages','(','package','(',')',')')
    message=('"explicit policy requires available advisory evidence even when all legacy fields have their default values"'
             if modern else '"explicit policy requires available advisory evidence even when all fields have their default values"')
    error=(*preceding,'.','expect_err','(',message,')',';')
    content=('legacy',) if modern else ('SecurityPolicy','::','default','(',')')
    serialize=('let','bytes','=','toml','::','to_string','(','&',*content,')','?',';')
    shapes=(path,serialize,write,error,verify,readback)
    _construct_charge(work,len(rows))
    by_shape={}
    for row in rows:
        if row['kind']!='statement' or not row['supported'] or code.parents[row['first']]!=opening:
            continue
        start,end=row['first'],row['end']
        _construct_charge(work,len(shapes)+end-start+1)
        words=tuple(code.words[start:end+1])
        if words in shapes:
            if words in by_shape:
                return None
            by_shape[words]=(start,end)
    if by_shape.keys()!=set(shapes):
        return None
    matches=[by_shape[shape] for shape in shapes]
    (path_at,_),_,_,(_,error_end),(assert_at,assert_end),(read_at,read_end)=matches
    if (matches!=sorted(matches) or error_end+1!=assert_at or assert_end+1!=read_at
            or code.words[read_end+1:closing]!=['Ok','(','(',')',')']):
        return None
    exclusive=code.words[path_at:closing]
    _construct_charge(work,3*len(exclusive)+len(raw))
    if exclusive.count('path')!=4 or exclusive.count('bytes')!=3 or exclusive.count('error')!=2:
        return None
    bound_reason=verify.index('reason')
    observed_geometry={tuple(r[:4]):r[4] for r in raw}
    guard_reason=verify.index('reason',bound_reason+1)
    typed_slots=((3,4),(8,8),(bound_reason,bound_reason),(guard_reason,guard_reason))
    if any(observed_geometry.get(code.region(assert_at+a,assert_at+b))!=hits for a,b in typed_slots):
        return None
    _,_,(write_at,_),_,_,_=matches
    tail=read_end+1
    roles=(
        ('path',path_at,((1,1,hits),(3,7,hits),(9,9,hits))),
        ('write',write_at,((0,2,hits),(4,5,hits),(7,8,hits),(10,10,0))),
        ('typed-error',assert_at,((0,1,hits),)),
        ('readback',read_at,((0,1,hits),(3,5,hits),(7,8,hits),(10,10,0))),
        ('return',tail,((0,4,hits),)),
        ('close',closing,((0,0,hits),)),
    )
    results=[]
    _construct_charge(work,len(raw)*len(roles))
    for role,token,slots in roles:
        line=code.position(code.starts[token])[0]
        observed=[r for r in raw if r[0]<=line and (r[2]>line or r[2]==line and r[3]>1)]
        expected=[[*code.region(token+a,token+b),count,0,0,0] for a,b,count in slots]
        if observed!=expected:
            return None
        results.append(dict(role=role,line=line,regions=observed))
    return results


def prepared_policy_environment_entry(name, source, counts, group, owners, names, inventory, line, work):
    code,rows=inventory[:2]
    _construct_charge(work,len(rows)+len(code.starts).bit_length())
    start=bisect.bisect_left(code.starts,code.offsets[line-1])
    single=code.words[start:start+4]==['temp_env','::','with_var','(']
    if single:
        argument=start+3
        key=argument+1
        value=key+2
        start=value+9
        if code.words[key:start]!=['"OMG_CONFIG_DIR"',',','Some','(','directory','.','path','(',')',')',',']:
            return None
        argument_slot=code.region(value,start-2)
    opening=start+len(_RESULT_CLOSURE)
    if tuple(code.words[start:opening])!=_RESULT_CLOSURE or code.words[opening:opening+1]!=['{']:
        return None
    closing=code.pairs[opening];argument=code.parents[opening]
    if argument is None or code.words[argument-3:argument+1]!=[
            'temp_env','::','with_var' if single else 'with_vars','(']:
        return None
    body=code.parents[argument]
    functions=[row for row in rows if row['kind']=='fn' and row['opening']==body]
    if len(functions)!=1 or len(group[2])!=1:
        return None
    fn,=functions
    header=fn['header'];fn_at=header.index('fn')
    expected=_RESULT_TEST_SIGNATURE if single else ('#','[','cfg','(','debug_assertions',')',']')+_RESULT_TEST_SIGNATURE
    if ((*header[:fn_at+1],'<declaration>',*header[fn_at+2:])!=expected
            or code.words[closing+1:fn['end']]!=[',',')']
            or (context:=_boolean_module(code,{'start':fn['first']})) is None
            or context[:2]!=(['tests'],['tests'])):
        return None
    if single:
        if not environment_result_callback(code,fn,dict(opening=opening,end=closing)):
            return None
        modern=None
    else:
        array=argument+1
        if code.words[array:array+1]!=['['] or code.pairs[array]+2!=start:
            return None
        arguments=_boolean_arguments(code,array)
        if arguments is None or len(arguments)!=3:
            return None
        _construct_charge(work,start-body)
        values={code.words[begin+1]:tuple(code.words[begin:end])
                for begin,end in arguments if code.words[begin]=='(' and code.pairs[begin]==end-1}
        config=('(','"OMG_CONFIG_DIR"',',','Some','(','directory','.','path','(',')','.','as_os_str','(',')',')',')')
        test_mode=('(','"OMG_TEST_MODE"',',','Some','(','std','::','ffi','::','OsStr','::','new','(','"1"',')',')',')')
        data=('(','"OMG_DATA_DIR"',',','Some','(','data_dir','.','as_os_str','(',')',')',')')
        distro=('(','"OMG_TEST_DISTRO"',',','Some','(','std','::','ffi','::','OsStr','::','new','(','"fedora"',')',')',')')
        if values.get('"OMG_CONFIG_DIR"')!=config or values.get('"OMG_TEST_MODE"')!=test_mode:
            return None
        modern=values.get('"OMG_DATA_DIR"')==data
        if not modern and values.get('"OMG_TEST_DISTRO"')!=distro:
            return None
        argument_slot=code.region(array,code.pairs[array])
    call=argument-3
    _construct_charge(work,call-body)
    prefix=code.words[body+1:call]
    added=['let','data_dir','=','directory','.','path','(',')','.','join','(','"data"',')',';']
    tempdir=['let','directory','=','tempfile','::','tempdir','(',')','?',';']
    if modern and prefix[-len(added):]!=added:
        return None
    if modern:
        prefix=prefix[:-len(added)]
    if prefix[-len(tempdir):]!=tempdir:
        return None
    last_setup=code.position(code.ends[body+len(prefix)])[0]
    tail=('assert_eq','!','(','fs','::','read_to_string','(','&','path',')','?',',','bytes',')',';',
          'Ok','(','(',')',')')
    tail=tail[-5:] if single else tail
    if tuple(code.words[closing-len(tail):closing])!=tail:
        return None
    tokens=code.words[opening+1:closing]
    _construct_charge(work,3*len(tokens))
    nested_pattern=['let','package','=','||','{']
    factories=[opening+1+i+4 for i in range(len(tokens)) if tokens[i:i+5]==nested_pattern]
    if len(factories)!=int(modern is False):
        return None
    if modern:
        for requirement in (['.','remove','(','"advisory_requirement"',')'],
                ['assert_eq','!','(','loaded','.','advisory_requirement',',','AdvisoryRequirement','::','Review',')']):
            if not any(tokens[i:i+len(requirement)]==requirement for i in range(len(tokens))):
                return None
    root,=group[2]; symbol=root['name']; shape=plain_rust_function_symbol(symbol)
    modules=('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'),'tests')
    if (shape is None or len(root['filenames'])!=1 or shape.identifiers!=(*modules,header[fn_at+1])
            or not 0<root['count']<COUNTER_LIMIT):
        return None
    child_key='_RNC'+symbol[2:]+'0'+rust_same_crate_backref(shape.modules,1)
    nested_key='_RNCNC'+symbol[2:]+'00'+rust_same_crate_backref(shape.modules,2)
    expected={symbol,child_key} | ({nested_key} if factories else set())
    low,high=code.region(call,closing+2)[:2],code.region(call,closing+2)[2:]
    observed={}
    _construct_charge(work,len(owners))
    for owner in owners:
        _construct_charge(work,len(owner['regions']))
        touching=[r for r in owner['regions'] if tuple(r[:2])<high and low<tuple(r[2:4])]
        if not touching:
            continue
        key=owner['name']
        _construct_charge(work,len(key)+len(touching))
        if (key not in expected or names[key]!=1 or owner['filenames']!=root['filenames']
                or owner.get('branches') or owner.get('mcdc_records')
                or any(r[5:]!=[0,0,0] or not 0<=r[4]<COUNTER_LIMIT
                       or not low<=tuple(r[:2])<tuple(r[2:4])<=high for r in touching)):
            return None
        observed[key]=owner,touching
    if observed.keys()!=expected or observed[symbol][0] is not root:
        return None
    child,raw=observed[child_key]; hits=child['count']
    opener=code.region(opening,opening); closer=code.region(closing,closing)
    opener_line=opener[0]
    if (not 0<hits<=root['count'] or len(raw)!=len(child['regions'])
            or not direct_rust_callback_symbol(child_key,symbol,shape.modules)
            or any(not opener[:2]<=tuple(r[:2])<tuple(r[2:4])<=closer[2:] for r in raw)
            or [r for r in raw if r[0]<=opener_line<=r[2]]!=[[*opener,hits,0,0,0]]
            or [r for r in raw if tuple(r[:4])==closer]!=[[*closer,hits,0,0,0]]):
        return None
    root_raw=observed[symbol][1]
    call_slot=code.region(call,call+2)
    if single and len(root_raw)!=2:
        return None
    for slot in (call_slot,argument_slot):
        if [r[4] for r in root_raw if tuple(r[:4])==slot]!=[hits]:
            return None
    if any(tuple(row[2:4])>opener[:2] for row in root_raw):
        return None
    if factories:
        nested,raw_nested=observed[nested_key]
        factory,=factories; bounds=code.region(factory,code.pairs[factory])
        if (not direct_rust_callback_symbol(nested_key,symbol,shape.modules,2)
                or len(raw_nested)!=len(nested['regions']) or not 0<nested['count']<COUNTER_LIMIT
                or (*min(tuple(r[:2]) for r in raw_nested),*max(tuple(r[2:4]) for r in raw_nested))!=bounds):
            return None
    whole=[row for _,rows in observed.values() for row in rows]
    if (_owner_line_counts({'regions':whole},_ObserverWork(work))!={
            n:counts[n] for n in range(low[0],high[0]+1) if n in counts} or counts.get(line)!=hits):
        return None
    setup=fragment_region_states(root,group[0],last_setup,source,work)
    identity=(shape.identity,header,tuple(prefix),setup,root['count'],hits,opener[1::2])
    if single:
        entry=[line,argument_slot[0],opener_line,closer[0]]
        return (*identity,call_slot[1::2],argument_slot[1::2]),dict(
            parent=symbol,child=child_key,span=[*low,*high],entry=list(opener),
            nested=[],modern=None,file_steps=None,observed_lines=entry)
    steps=prepared_policy_file_steps(code,rows,opening,closing,raw,hits,modern,work)
    return identity,dict(parent=symbol,child=child_key,span=[*low,*high],entry=list(opener),
                         nested=[nested_key] if factories else [],modern=modern,file_steps=steps)


def positive_source_fragments(name, old, new, before, after, base, head, base_files, head_files,
                              fragments, work=None, construct_inventories=None, compiled_groups=None,
                              callback_functions=(), owner_indexes=None, inherent_async_lines=((), ()), macro_expansions=(None, None)):
    """Prove positive head pairs, retaining every base state, copy and candidate."""
    if not fragments:
        return {}, []
    work = [20_000_000] if work is None else work
    current_fragment = fragments[0]
    def refuse():
        a, b, c, d, _ = current_fragment
        raise ValueError(f"Ambiguous unchanged source correspondence: {name}:{a + 1}-{b} -> {c + 1}-{d}")
    inventories = []; groups = []; inventory_names = []; async_groups = []
    for side, (owners, files, source) in enumerate(((base, base_files, old), (head, head_files, new))):
        grouped = (_compiled_function_groups(name, owners, files, source, work)
                   if compiled_groups is None else compiled_groups[side])
        if grouped is None:
            refuse()
        inventory, valid, names = grouped
        if compiled_groups is not None:
            if owner_indexes is None:
                _construct_charge(work, len(owners) + sum(len(owner['filenames']) for owner in owners))
                expected_inventory = [owner for owner in owners if any(
                    files.get(path) == name or path.endswith('/' + name) for path in owner['filenames'])]
                names = Counter(owner['name'] for owner in owners)
            else:
                indexed = owner_indexes[side]
                if (indexed.owners is not owners or indexed.files is not files
                        or indexed.owner_count != len(owners) or indexed.file_count != len(files)
                        or indexed.source_names is not None and name not in indexed.source_names):
                    refuse()
                expected_inventory = indexed.inventories.get(name, ())
                names = indexed.name_counts
                _construct_charge(work, len(inventory) + len(expected_inventory))
            if {id(owner) for owner in inventory} != {id(owner) for owner in expected_inventory}:
                refuse()
            valid = {prefix: group for prefix, group in valid.items()
                     if all(names[owner['name']] == 1 for owner in group[2])}
        valid = dict(valid)
        phases = compiled_async_function_groups(name, inventory, files, source, work,
                    None if construct_inventories is None else construct_inventories[side], names,
                    inherent_async_lines[side],grouped)
        phase_bodies = {id(copy.body) for group in phases.values() for copy in group.copies}
        valid = {key: group for key, group in valid.items()
                 if not any(id(owner) in phase_bodies for owner in group[2])}
        valid.update({key: (*group.span, tuple(copy.body for copy in group.copies))
                      for key, group in phases.items()})
        async_groups.append(phases)
        inventories.append(inventory); groups.append(valid); inventory_names.append(names)
    forwarders = transparent_forwarder_groups(old, new, groups, fragments)
    for prefix, (group, _) in forwarders.items():
        groups[1][prefix] = group
    claimed = {}; pairs = {}; excerpts = {}; callback_sources = {}; callback_inventories = {}; callback_work = 20_000_000
    receipts = []
    nominal_phase_cache = {}; literal_loop_cache = {}; join_cache = {}; callback_phase_cache = {}
    fixture_forests = {}; fixture_receipts = {}
    preproved_callback_pairs = {}
    leaf_inventories = None
    for a, b, c, d, pending in fragments:
        current_fragment = (a, b, c, d, pending)
        if pending and all(preproved_callback_pairs.get(line)==line+c-a for line in pending):
            continue
        candidates = [(prefix, group, groups[1][prefix]) for prefix, group in groups[0].items()
                      if prefix in groups[1] and group[0] <= a + 1 <= b <= group[1]
                      and groups[1][prefix][0] <= c + 1 <= d <= groups[1][prefix][1]]
        if (len(candidates)==1 and a+1==b and c+1==d and tuple(pending)==(b,)
                and before.get(b)==0 and after.get(d,0)>0
                and b in inherent_async_lines[0] and d in inherent_async_lines[1]):
            prefix = candidates[0][0]
            _construct_charge(work,len(old[a])+len(new[c]))
            if (old[a]==new[c] and _INHERENT_LEAF.fullmatch(old[a]) and
                    all(prefix in groups for groups in async_groups)):
                if leaf_inventories is None:
                    leaf_inventories = (construct_inventories if construct_inventories is not None
                        else tuple(_construct_inventory(source,work) for source in (old,new)))
                scoped = tuple(groups[prefix] for groups in async_groups)
                observations = [inherent_async_leaf_entry(source,leaf_inventories[side],scoped[side],
                      inventories[side],inventory_names[side],line,mapped[line],work)
                      for side,(source,line,mapped) in enumerate(((old,b,before),(new,d,after)))]
                if all(value is not None for value in observations) and observations[0][0] == observations[1][0]:
                    _construct_charge(work,len(observations[0][1])*len(observations[1][1])*len(observations[0][1][0]))
                    matching = compiled_hit_state_matching(*(value[1] for value in observations),
                                                           tuple(value[2] for value in observations))
                    if matching is not None:
                        if b in pairs and pairs[b] != d:
                            refuse()
                        pairs[b] = d
                        for side, (source, scope) in enumerate(zip((old,new),scoped)):
                            start, end = scope.span
                            _construct_charge(work,sum(len(line)+1 for line in source[start-1:end]))
                            excerpts[side,start,end] = ('\n'.join(source[start-1:end])+'\n').encode()
                        receipts.append(dict(file=name,kind='inherent-async-leaf-entry',pairs=[[b,d]],
                            geometry=observations[0][0],instance_matching=matching,
                            instance_states=sorted(observations[0][1]),head_instance_states=sorted(observations[1][1]),
                            async_fragment_regions=[dict(base_range=[b,b],head_range=[d,d],geometry=observations[0][0])],
                            async_copies=dict(base=observations[0][3],head=observations[1][3])))
                        continue
        if (not candidates and b == a + 1 and d == c + 1 and pending == [b]
                and before.get(b, 0) > 0):
            witness = qualified_function_completion(
                zip((old, new), groups, inventories, (b, d)), work)
            if witness is not None:
                target = witness['head_range'][1]
                if after.get(target, 0) <= 0 or b in pairs and pairs[b] != target:
                    refuse()
                pairs[b] = target
                receipts.append(dict(file=name, pairs=[[b, target]], **witness))
                for side, (source, span) in enumerate(zip((old, new),
                        (witness['base_range'], witness['head_range']))):
                    start, end = span
                    _construct_charge(work, sum(len(text) + 1 for text in source[start - 1:end]))
                    excerpts[side, start, end] = ('\n'.join(source[start - 1:end]) + '\n').encode()
                continue
        if (name=='src/package_managers/alpm_ops.rs' and construct_inventories is not None
                and macro_expansions==([],[]) and b-a==d-c==2 and tuple(pending)==(a+1,b)
                and old[a:b]==new[c:d] and old[a].strip()=='let confirmed = if auto_accept {'
                and old[b-1].strip()=='true'):
            sides=((old,construct_inventories[0],before,a+1,b),(new,construct_inventories[1],after,c+1,d))
            registered=retained_alpm_replace_branch(sides,inventories,inventory_names,groups,work)
            if registered is not None:
                scopes,owners,states=registered
                matched=[[a+1,c+1],[b,d]]
                if any(line in pairs and pairs[line]!=target for line,target in matched):
                    refuse()
                pairs.update(matched)
                for side,(source,(_,_,scope)) in enumerate(zip((old,new),scopes)):
                    first,last=scope
                    _construct_charge(work,sum(len(text)+1 for text in source[first-1:last]))
                    excerpts[side,first,last]=('\n'.join(source[first-1:last])+'\n').encode()
                receipts.append(dict(file=name,kind='retained-alpm-replace-branch',pairs=matched,
                    instance_states=states,owners=owners,
                    callback_fragments=[dict(pairs=matched,base_range=[a+1,b],head_range=[c+1,d])]))
                continue
        environment=(name=='src/core/security/policy.rs' and a+1==b and c+1==d
                     and tuple(pending)==(b,) and old[a]==new[c]
                     and old[a].strip()=='temp_env::with_var(')
        if (name=='src/core/security/policy.rs' and construct_inventories is not None
                and macro_expansions==([],[]) and len(candidates)==1
                and (environment or (b-a==d-c==1 and tuple(pending)==(b,)
                    and old[a]==new[c] and old[a].strip()=='|| -> anyhow::Result<()> {'))):
            single=environment
            _,bg,hg=candidates[0]
            observations=[prepared_policy_environment_entry(name,source,counts,group,inventories[side],
                            inventory_names[side],construct_inventories[side],line,work)
                          for side,(source,counts,group,line) in enumerate(((old,before,bg,b),(new,after,hg,d)))]
            if (all(observations) and observations[0][0]==observations[1][0]
                    and [entry[1]['modern'] for entry in observations]==([None,None] if single else [False,True])):
                witnesses=[entry[1] for entry in observations]
                matched=[[b,d]]
                if single:
                    matched=[list(pair) for pair in zip(*(item['observed_lines'] for item in witnesses),strict=True)]
                    if (not all([line,line+c-a] in matched for line in pending)
                            or any(old[line-1]!=new[target-1] for line,target in matched)):
                        refuse()
                steps=[entry[1]['file_steps'] for entry in observations]
                if all(steps):
                    matched.extend([previous['line'],current['line']]
                                   for previous,current in zip(*steps,strict=True))
                if any(line in pairs and pairs[line]!=target for line,target in matched):
                    refuse()
                pairs.update(matched)
                preproved_callback_pairs.update(matched)
                for side,(source,group) in enumerate(((old,bg),(new,hg))):
                    first,last=group[:2]
                    _construct_charge(work,sum(len(text)+1 for text in source[first-1:last]))
                    excerpts[side,first,last]=('\n'.join(source[first-1:last])+'\n').encode()
                receipts.append(dict(file=name,kind='prepared-policy-environment-entry',pairs=matched,
                    owners=witnesses,
                    callback_fragments=[dict(pairs=[[line,target]],base_range=[line,line],head_range=[target,target])
                                        for line,target in matched]))
                continue
        if (name=='src/core/security/policy.rs' and construct_inventories is not None
                and macro_expansions==([],[]) and len(candidates)==1 and b-a==d-c==1
                and tuple(pending)==(b,) and old[a]==new[c] and old[a].strip()=='assert!('
                and a>0 and old[a-1].strip().startswith('let licenses = combined_license_expression(')):
            _,bg,hg=candidates[0]
            observations=[policy_license_fixture_assertions(name,source,counts,group,inventories[side],
                            inventory_names[side],files,construct_inventories[side],line,work)
                          for side,(source,counts,group,files,line) in enumerate(
                              ((old,before,bg,base_files,b),(new,after,hg,head_files,d)))]
            if (all(observations) and observations[0][0]==observations[1][0]
                    and [entry[2]['modern'] for entry in observations]==[False,True]):
                matched=[list(pair) for pair in zip(observations[0][1],observations[1][1],strict=True)]
                if any(line in pairs and pairs[line]!=target for line,target in matched):
                    refuse()
                pairs.update(matched)
                preproved_callback_pairs.update(matched)
                for side,(source,group) in enumerate(((old,bg),(new,hg))):
                    first,last=group[:2]
                    _construct_charge(work,sum(len(text)+1 for text in source[first-1:last]))
                    excerpts[side,first,last]=('\n'.join(source[first-1:last])+'\n').encode()
                receipts.append(dict(file=name,kind='policy-license-fixture-assertions',pairs=matched,
                    owners=[entry[2] for entry in observations],
                    callback_fragments=[dict(pairs=[[line,target]],base_range=[line,line],head_range=[target,target])
                                        for line,target in matched]))
                continue
        if (len(candidates) != 1 or old[a:b] != new[c:d]
                or any(line not in before for line in pending)):
            refuse()
        prefix, bg, hg = candidates[0]
        if len(bg[2]) != len(hg[2]):
            refuse()
        async_fragment = None
        if b-a==4 and _INITIAL_TEST_RECORD.fullmatch(old[a]):
            async_fragment = initial_async_test_record
        elif b-a==1 and _TEST_EXPECTED_ERROR.fullmatch(old[a]):
            async_fragment = async_test_expected_error
        elif b-a==1 and tuple(pending)==(b,) and old[a].strip()=='assert!(matches!(':
            async_fragment = async_test_expected_variant
        elif (name=='src/core/security/policy.rs' and b-a==1 and tuple(pending)==(b,)
              and b<len(old) and old[a].strip()=='assert!(' and '&FailingVulns)' in old[b]):
            async_fragment = async_policy_unavailable_assertion
        elif b-a==1 and old[a].strip() in ('let manager = JavaManager {','let manager = RustManager {'):
            async_fragment = async_runtime_fixture_record
        elif name=='src/runtimes/rust.rs' and b-a==1 and tuple(pending)==(b,) and old[a].strip()=='assert_eq!(':
            async_fragment = async_runtime_inventory_assertion
        if async_fragment is not None and macro_expansions==([],[]) and construct_inventories is not None:
            observations = [async_fragment(name,source,counts,group,inventories[side],
                inventory_names[side],construct_inventories[side],first,last,work)
                for side,(source,counts,group,first,last) in enumerate(((old,before,bg,a+1,b),(new,after,hg,c+1,d)))]
            if (all(observations) and observations[0][0]==observations[1][0]
                and (async_fragment is not async_test_expected_variant or
                         [entry[1]['wrapped'] for entry in observations]==[True,False])
                    and (async_fragment is not async_policy_unavailable_assertion or
                         [entry[1]['typed'] for entry in observations]==[False,True])
                and (async_fragment is not async_runtime_fixture_record or
                         [bool(entry[1]['security_initializer']) for entry in observations]==[False,True])
                    and (async_fragment is not async_runtime_inventory_assertion or
                         [bool(entry[1]['security_terms']) for entry in observations]==[False,True])):
                matched = [(line,line+c-a) for line in pending]
                if async_fragment in (async_runtime_fixture_record,async_runtime_inventory_assertion):
                    old_first,old_last = observations[0][1]['record_span']
                    new_first = observations[1][1]['record_span'][0]
                    shift_after=observations[0][1].get('shift_after',old_first)
                    shift_count=2 if async_fragment is async_runtime_inventory_assertion else 1
                    matched = [(line,line+new_first-old_first+shift_count*int(line>shift_after))
                               for line in range(old_first,old_last+1) if line in before]
                    _construct_charge(work,len(matched))
                    if any(target not in after for _,target in matched):
                        refuse()
                    preproved_callback_pairs.update(matched)
                if any(line in pairs and pairs[line]!=target for line,target in matched):
                    refuse()
                pairs.update(matched)
                for side,(source,group) in enumerate(((old,bg),(new,hg))):
                    first,last=group[:2]
                    _construct_charge(work,sum(len(line)+1 for line in source[first-1:last]))
                    excerpts[side,first,last]=('\n'.join(source[first-1:last])+'\n').encode()
                synchronous_record=(async_fragment is async_runtime_fixture_record
                                    and any(owner['synchronous'] for _,owner in observations if 'synchronous' in owner))
                if synchronous_record and not all(owner.get('synchronous') for _,owner in observations):
                    refuse()
                kind = {initial_async_test_record:'initial-async-test-record',
                        async_test_expected_error:'async-test-expected-error-call',
                        async_test_expected_variant:'async-test-expected-variant-entry',
                        async_policy_unavailable_assertion:'async-policy-unavailable-assertion-entry',
                        async_runtime_fixture_record:'async-runtime-fixture-record',
                        async_runtime_inventory_assertion:'async-runtime-inventory-assertion'}[async_fragment]
                if synchronous_record:
                    kind='sync-runtime-fixture-record'
                evidence = [observation[1] for observation in observations]
                receipt = dict(kind=kind,file=name,pairs=matched,owners=evidence)
                if synchronous_record:
                    receipt['callback_fragments'] = [dict(pairs=matched,
                        base_range=evidence[0]['record_span'],head_range=evidence[1]['record_span'])]
                else:
                    receipt['async_copies'] = {side:[dict(constructor=owner['root'],body=owner['body'],
                        constructor_state=1,body_state=1)] for side,owner in zip(('base','head'),evidence)}
                    if async_fragment in (async_runtime_fixture_record,async_runtime_inventory_assertion):
                        fragment = dict(base_range=evidence[0]['record_span'],head_range=evidence[1]['record_span'],
                                        geometry=observations[0][0][2])
                    else:
                        fragment = dict(base_range=[a+1,b],head_range=[c+1,d],
                                        regions=[owner['regions'] for owner in evidence])
                    receipt['async_fragment_regions'] = [fragment]
                receipts.append(receipt)
                continue
        if (construct_inventories is not None and macro_expansions==([],[]) and prefix in callback_functions
                and a and c and a+1==b and c+1==d and tuple(pending)==(b,)
                and old[a].lstrip().startswith('.expect(')
                and old[a-1].lstrip().startswith('tx.try_send(') and new[c-1].lstrip().startswith('tx.try_send(')):
            queue=[retained_test_queue_expectation(name,source,number,mapped,group,inventories[side],
                       inventory_names[side],files,construct_inventories[side],work)
                   for side,(source,number,mapped,group,files) in enumerate(
                       ((old,b,before,bg,base_files),(new,d,after,hg,head_files)))]
            if all(queue) and queue[0][:2]==queue[1][:2]:
                if b in pairs and pairs[b]!=d:
                    refuse()
                pairs[b]=d
                receipts.append(dict(file=name,kind='retained-test-queue-expectation',
                    pairs=[[b,d]],iterations=queue[0][1],owners=[value[2] for value in queue],
                    callback_fragments=[dict(pairs=[[b,d]],base_range=[b,b],head_range=[d,d])]))
                for side,(source,group) in enumerate(((old,bg),(new,hg))):
                    first,last=group[:2]
                    _construct_charge(work,sum(len(text)+1 for text in source[first-1:last]))
                    excerpts[side,first,last]=('\n'.join(source[first-1:last])+'\n').encode()
                continue
        if (construct_inventories is not None and macro_expansions==([],[])
                and a+1==b and c+1==d and tuple(pending)==(b,)
                and old[a].strip() in ('assert!(','assert_eq!(')):
            assertion=[retained_direct_unit_assertion(name,source,line,mapped,group,inventories[side],
                       inventory_names[side],files,construct_inventories[side],work)
                   for side,(source,line,mapped,group,files) in enumerate(
                       ((old,b,before,bg,base_files),(new,d,after,hg,head_files)))]
            if all(assertion) and assertion[0][:3]==assertion[1][:3]:
                if b in pairs and pairs[b]!=d:
                    refuse()
                pairs[b]=d
                receipts.append(dict(file=name,kind='retained-direct-unit-assertion',pairs=[[b,d]],
                    anchor=assertion[0][1],states=assertion[0][2],owners=[value[3] for value in assertion],
                    callback_fragments=[dict(pairs=[[b,d]],base_range=[b,b],head_range=[d,d])]))
                for side,(source,group) in enumerate(((old,bg),(new,hg))):
                    first,last=group[:2]
                    _construct_charge(work,sum(len(text)+1 for text in source[first-1:last]))
                    excerpts[side,first,last]=('\n'.join(source[first-1:last])+'\n').encode()
                continue
        if name=='src/cli/tool.rs' and macro_expansions==([],[]) and prefix in callback_functions:
            if prefix not in fixture_forests:
                scopes = []
                for side,(source,group,mapped) in enumerate(((old,bg,before),(new,hg,after))):
                    inventory = (construct_inventories[side] if construct_inventories is not None
                                 else _construct_inventory(source,work))
                    scopes.append(fixture_callback_forest(source,group,inventories[side],inventory_names[side],
                                                          mapped,inventory,work,literal_loop_cache))
                first,second = scopes
                qualified = []
                if first is not None and second is not None:
                    variants = [('intact-fixture-callback-forest', [scope[1:2]+scope[:1]+scope[2:4] for scope in scopes]),
                                ('retained-fixture-bindings', [scope[1:2]+scope[5] for scope in scopes])]
                    if first[6] is not None and second[6] is not None:
                        variants.append(('retained-fixture-loop-completion',[scope[6] for scope in scopes]))
                    for mode, ((left,*previous),(right,*current)) in variants:
                        _construct_charge(work,len(previous[1])+len(previous[2]))
                        if (previous[0]==current[0] and previous[2] and len(previous[1])==len(current[1])
                                and all(x<=y for x,y in zip(previous[1],current[1]))
                                and previous[2].keys()==current[2].keys()
                                and all(previous[2][n]<=current[2][n] for n in previous[2])):
                            qualified.append((mode,left,right,previous,current,first[4],second[4]))
                fixture_forests[prefix] = qualified
            for mode,left,right,previous,current,base_evidence,head_evidence in fixture_forests[prefix]:
                if (left[0]<=a+1<=b<=left[1] and right[0]<=c+1<=d<=right[1]
                        and c-a==right[0]-left[0] and all(line-left[0] in previous[2] for line in pending)):
                    key = prefix,mode
                    if key not in fixture_receipts:
                        receipt = dict(file=name,kind=mode,pairs=[],
                            base_range=list(left),head_range=list(right),
                            callback_fragments=[],owners=dict(base=base_evidence,head=head_evidence),
                            instance_states=[previous[1]],head_instance_states=[current[1]])
                        fixture_receipts[key] = receipt
                        receipts.append(receipt)
                        for side,(source,group) in enumerate(((old,bg),(new,hg))):
                            start,end = group[:2]
                            _construct_charge(work,sum(len(text)+1 for text in source[start-1:end]))
                            excerpts[side,start,end] = ('\n'.join(source[start-1:end])+'\n').encode()
                    receipt = fixture_receipts[key]
                    observed = []
                    for line in pending:
                        target = c+line-a
                        if line in pairs and pairs[line]!=target:
                            refuse()
                        pairs[line] = target; observed.append([line,target])
                    receipt['pairs'].extend(observed)
                    receipt['callback_fragments'].append(dict(pairs=observed,base_range=[a+1,b],head_range=[c+1,d]))
                    break
            else:
                mode = None
            if mode is not None:
                continue
        for side, source, group in ((0, old, bg), (1, new, hg)):
            excerpts[side, group[0], group[1]] = ("\n".join(source[group[0] - 1:group[1]]) + "\n").encode()
        entry = claimed.setdefault(prefix, {"states": [[[] for _ in group[2]] for group in (bg, hg)],
            "file": name, "base_range": list(bg[:2]), "head_range": list(hg[:2]),
            "instances": len(bg[2]), "pairs": [], "candidates": [],
            "source_prefix_sha256": hashlib.sha256(prefix.encode()).hexdigest()})
        if prefix in async_groups[0] or prefix in async_groups[1]:
            if prefix not in async_groups[0] or prefix not in async_groups[1]:
                refuse()
            if 'async_copies' not in entry:
                entry.pop('source_prefix_sha256')
                entry['async_owner_namespace_sha256'] = hashlib.sha256(prefix.encode()).hexdigest()
                entry['async_declarations_sha256'] = [hashlib.sha256(
                    side[prefix].declaration.encode()).hexdigest() for side in async_groups]
                entry['async_source_contexts'] = [side[prefix].source_context for side in async_groups]
                entry['async_copies'] = {}
                for side, label in enumerate(('base', 'head')):
                    phase = async_groups[side][prefix]
                    rows = []
                    for state, copy in zip(entry['states'][side], phase.copies):
                        constructor = int(copy.constructor['regions'][0][4] > 0)
                        start = min(tuple(region[:2]) for region in copy.body['regions'])
                        body = int(any(region[4] > 0
                                       and tuple(region[:4]) == (*start, start[0], start[1] + 1)
                                       for region in copy.body['regions']))
                        state.extend((constructor, body))
                        rows.append(dict(constructor=copy.constructor['name'], body=copy.body['name'],
                                         constructor_state=constructor, body_state=body))
                    entry['async_copies'][label] = rows
        if prefix in forwarders:
            entry['forwarder'] = forwarders[prefix][1]
            start, end = entry['forwarder']['wrapper_range']
            excerpts[1, start, end] = ('\n'.join(new[start - 1:end]) + '\n').encode()
        endpoint_kind = None
        await_method = None
        if prefix in async_groups[0] and b == a + 1 and old[a].strip() == '}':
            endpoint_kind = async_groups[0][prefix].closing_kinds.get(a + 1)
            if endpoint_kind is None or endpoint_kind != async_groups[1][prefix].closing_kinds.get(c + 1):
                refuse()
        elif prefix in async_groups[0] and b == a + 1 and old[a].strip() == '.await':
            for side, source in enumerate((old, new)):
                if side not in callback_sources:
                    if construct_inventories is not None and construct_inventories[side] is not None:
                        callback_sources[side] = construct_inventories[side][0]
                    else:
                        _construct_charge(work, sum(len(value) + 1 for value in source))
                        callback_sources[side] = _boolean_source(source)
            await_method = awaited_zero_arg_method(callback_sources[0], a + 1, work)
        nominal_fragments = {}; nominal_signature = None
        _construct_charge(work, len(bg[2][0]['name']) + 1)
        if prefix in callback_functions and nominal_method_path(bg[2][0]['name']) is not None:
            if 0 not in callback_inventories:
                callback_inventories[0] = (_construct_inventory(old, work)
                    if construct_inventories is None else construct_inventories[0])
            nominal = nominal_phase_fragment(old, bg, inventories[0], inventory_names[0],
                a+1, b, callback_inventories[0], work, nominal_phase_cache)
            if nominal is not None:
                nominal_fragments[0, a] = nominal
                nominal_signature = nominal.signature
        joined_statements = []
        if (join_cache and prefix in callback_functions and construct_inventories is not None
                and macro_expansions==([],[])):
            for side, source, group, first, last in ((0,old,bg,a+1,b),(1,new,hg,c+1,d)):
                proof = biased_join_result_fragment(source,group,inventories[side],inventory_names[side],
                    first,last,construct_inventories[side],work,expansions=[],loop_cache=literal_loop_cache,
                    cache=join_cache)
                if proof is None or proof.witness['kind'] not in (
                        'joined-async-statement','joined-async-condition-completion','joined-async-phase-completion'):
                    break
                joined_statements.append(proof)
        if len(joined_statements)!=2 or joined_statements[0].signature!=joined_statements[1].signature:
            joined_statements.clear()
        occurrences = []; callback_signature = None; callback_mode = None; precise_signature = None; scoped_callback = False
        for side, source, counts, group, proposed in ((0, old, before, bg, a), (1, new, after, hg, c)):
            start, end, members = group
            starts = [proposed] if joined_statements else [offset for offset in range(start - 1, end - (b - a) + 1)
                      if source[offset:offset + b - a] == old[a:b]]
            if nominal_signature is not None:
                if side not in callback_inventories:
                    callback_inventories[side] = (_construct_inventory(source, work)
                        if construct_inventories is None else construct_inventories[side])
                scoped_starts = []
                for offset in starts:
                    key = side, offset
                    if key not in nominal_fragments:
                        nominal_fragments[key] = nominal_phase_fragment(source, group, inventories[side],
                            inventory_names[side], offset+1, offset+b-a,
                            callback_inventories[side], work, nominal_phase_cache)
                    evidence = nominal_fragments[key]
                    if evidence is None:
                        refuse()
                    matched = evidence.signature == nominal_signature
                    entry.setdefault('nominal_phase_candidates', []).append(dict(
                        side=side, source_range=[offset+1, offset+b-a],
                        matches_base_context=matched, geometry=evidence.witness['geometry'],
                        context_sha256=evidence.witness['context_sha256']))
                    if matched:
                        scoped_starts.append(offset)
                starts = scoped_starts
            if endpoint_kind is not None:
                kinds = async_groups[side][prefix].closing_kinds
                if any(offset + 1 not in kinds for offset in starts):
                    refuse()
                entry.setdefault('async_endpoint_contexts', []).append(dict(
                    side=side, kind=endpoint_kind,
                    candidates=[[offset + 1, kinds[offset + 1]] for offset in starts]))
                starts = [offset for offset in starts if kinds[offset + 1] == endpoint_kind]
            if await_method is not None:
                context = [(offset, awaited_zero_arg_method(callback_sources[side], offset + 1, work))
                           for offset in starts]
                if any(method is None for _, method in context):
                    refuse()
                entry.setdefault('async_await_contexts', []).append(dict(side=side, method=await_method,
                    candidates=[[offset + 1, method] for offset, method in context]))
                starts = [offset for offset, method in context if method == await_method]
            if proposed not in starts:
                refuse()
            observed = None; precise_observed = None
            for offset in starts:
                lines = [offset + line - a for line in pending]
                if (any(line not in counts or (side == 1 and counts[line] <= 0)
                        or (side == 0 and (counts[line] > 0) != (before[original] > 0))
                        for original, line in zip(pending, lines))):
                    refuse()
                parents_cover = all(owner_covers_lines(owner['regions'], line, line)
                                    for owner in members for line in range(offset + 1, offset + b - a + 1)
                                    if line in counts)
                touched = {id(owner) for owner in inventories[side] if any(
                    owner_covers_lines([region], line, line) for region in owner["regions"]
                    for line in range(offset + 1, offset + b - a + 1))}
                nested = touched != {id(owner) for owner in members}
                if callback_mode is not None and callback_mode != nested:
                    refuse()
                callback_mode = nested
                children = [()] * len(members); callback_lines = None
                if nested:
                    if side not in callback_sources:
                        callback_sources[side] = _boolean_source(source)
                    code = callback_sources[side]
                    callback_work -= 8 * len(code.words) if code is not None else 0
                    if callback_work < 0:
                        refuse()
                    callback = (nested_map_err_states(source, group, inventories[side],
                        inventory_names[side], offset + 1, offset + b - a, code) if parents_cover else None)
                    if callback is not None:
                        if callback_signature is not None and callback_signature != callback[1]:
                            refuse()
                        children, callback_signature, witness = callback
                        entry.setdefault('nested_callbacks', []).append(dict(side=side, candidate=offset + 1, **witness))
                    else:
                        if prefix not in callback_functions:
                            refuse()
                        if side not in callback_inventories:
                            callback_inventories[side] = (_construct_inventory(source, work)
                                if construct_inventories is None else construct_inventories[side])
                        callback = joined_statements[side] if joined_statements else zero_arg_callback_fragment(
                            source, group, inventories[side], inventory_names[side], offset + 1, offset + b - a,
                            callback_inventories[side], work, phase_cache=callback_phase_cache)
                        if callback is None:
                            callback = zero_arg_callback_fragment(source, group, inventories[side],
                                inventory_names[side], offset + 1, offset + b - a,
                                callback_inventories[side], work, caller_entry=True,
                                phase_cache=callback_phase_cache)
                        if (callback is None and macro_expansions==([],[]) and b==a+1
                                and old[a].strip() in ('|| -> anyhow::Result<()> {','assert!(')):
                            callback = zero_arg_callback_fragment(source,group,inventories[side],
                                inventory_names[side],offset+1,offset+b-a,callback_inventories[side],work,
                                phase_cache=callback_phase_cache,environment_test=True)
                        if callback is None:
                            callback = nested_async_call_entry_fragment(source, group, inventories[side],
                                inventory_names[side], offset + 1, offset + b - a,
                                callback_inventories[side], work, loop_cache=literal_loop_cache)
                        if callback is None:
                            callback = literal_pair_loop_fragment(source, group, inventories[side],
                                inventory_names[side], offset + 1, offset + b - a,
                                callback_inventories[side], work, normalize_second=True, cache=literal_loop_cache)
                        if (callback is None and type(macro_expansions) in (tuple,list)
                                and len(macro_expansions)==2):
                            callback = biased_join_result_fragment(source,group,inventories[side],
                                inventory_names[side],offset+1,offset+b-a,callback_inventories[side],work,
                                expansions=macro_expansions[side],loop_cache=literal_loop_cache,cache=join_cache)
                        if callback is None:
                            callback = nominal_fragments.get((side, offset))
                            if callback is None:
                                callback = nominal_phase_fragment(source, group, inventories[side],
                                    inventory_names[side], offset + 1, offset + b - a,
                                    callback_inventories[side], work, nominal_phase_cache)
                        if callback is None or callback_signature is not None and callback_signature != callback.signature:
                            refuse()
                        children = callback.states; callback_lines = callback.line_states
                        callback_signature = callback.signature; scoped_callback = True
                        entry.setdefault('callback_owners', []).append(dict(side=side, candidate=offset + 1, **callback.witness))
                        if callback.witness['kind'] == 'nominal-phase-tree-fragment':
                            entry.setdefault('nominal_phase_fragments', []).append(dict(
                                side=side, candidate=offset+1, **callback.witness))
                elif not parents_cover:
                    refuse()
                parent_lines = tuple(tuple(int(any(region[4] > 0 and owner_covers_lines([region], line, line)
                                             for region in owner["regions"])) for line in lines) + tuple(child)
                               for owner, child in zip(members, children))
                states = (parent_lines if callback_lines is None else tuple(
                    tuple(row[line - offset - 1] for line in lines) + tuple(child)
                    for row, child in zip(callback_lines, children)))
                if (any(bool(counts[line]) != any(row[column] for row in states)
                        for column, line in enumerate(lines))
                        or observed is not None and observed != states):
                    refuse()
                observed = states
                if prefix in async_groups[side]:
                    pieces = [fragment_region_states(owner, offset + 1, offset + b - a, source, work)
                              for owner in members]
                    geometry = pieces[0][0]
                    if (not geometry or any(piece[0] != geometry for piece in pieces)
                            or precise_signature is not None and precise_signature != geometry):
                        refuse()
                    precise_signature = geometry
                    precise = tuple(piece[1] for piece in pieces)
                    if precise_observed is not None and precise_observed != precise:
                        refuse()
                    precise_observed = precise
            for row, states in zip(entry["states"][side], observed):
                row.extend(states)
            if precise_observed is not None:
                for row, states in zip(entry['states'][side], precise_observed):
                    row.extend(states)
            occurrences.append([[offset + 1, offset + b - a] for offset in starts])
        if scoped_callback:
            entry.setdefault('callback_fragments', []).append(dict(
                pairs=[[line, c + line - a] for line in pending],
                base_range=[a + 1, b], head_range=[c + 1, d]))
        if precise_signature is not None:
            entry.setdefault('async_fragment_regions', []).append(dict(
                base_range=[a + 1, b], head_range=[c + 1, d],
                geometry=[list(shape) for shape in precise_signature]))
        entry["candidates"].append({"base": occurrences[0], "head": occurrences[1]})
        for line in pending:
            target = c + line - a
            if line in pairs and pairs[line] != target:
                refuse()
            pairs[line] = target
            entry["pairs"].append([line, target])
    for prefix, entry in claimed.items():
        states = entry.pop("states")
        identities = None
        if prefix in async_groups[0] and async_groups[0][prefix].copies[0].identity is not None:
            identities = [tuple(copy.identity for copy in side[prefix].copies) for side in async_groups]
        matching = compiled_hit_state_matching(*states, identities)
        if matching is None:
            refuse()
        entry["instance_states"] = sorted(states[0])
        entry["head_instance_states"] = sorted(states[1])
        entry["instance_matching"] = matching
        receipts.append(entry)
    require_rustfmt_syntax(excerpts.values())
    return pairs, receipts


def _construct_charge(work, amount):
    work[0] -= amount
    if work[0] < 0:
        raise ValueError('Source construct work bound exceeded')


def _construct_ancestors(code, index, work):
    _construct_charge(work, 32)
    if type(index) is not int or not 0 <= index < len(code.words):
        raise ValueError('Invalid construct ancestry index')
    result = []; visited = set(); parent = code.parents[index]
    while parent is not None:
        if (type(parent) is not int or not 0 <= parent < len(code.words)
                or parent in visited or len(result) == 32):
            raise ValueError('Invalid or excessive construct ancestry')
        visited.add(parent); result.append(parent); parent = code.parents[parent]
    return result


def _construct_inventory(source, work):
    _construct_charge(work, len(source) + 1)
    code = _boolean_source(source)
    if code is None:
        return None
    _construct_charge(work, len(code.words) + len(code.module_tokens))
    siblings = {}
    for i, word in enumerate(code.words):
        parent = code.parents[code.pairs[i]] if word in (')', ']', '}') else code.parents[i]
        siblings.setdefault(parent, []).append(i)
    boundaries = {parent: [i for i in indices if code.words[i] == ';' or code.words[i] == '}'
                          and (i + 1 == len(code.words) or code.words[i + 1] not in (';', ')', ']', '?', '.', ',', 'else'))]
                  for parent, indices in siblings.items()}
    def beginning(index, parent):
        rows = boundaries.get(parent, [])
        at = bisect.bisect_left(rows, index)
        return rows[at - 1] + 1 if at else (parent + 1 if parent is not None else 0)
    def digest(first, last):
        _construct_charge(work, last - first + 1)
        return hashlib.sha256(repr(tuple(code.words[first:last + 1])).encode()).hexdigest()
    def index_statement(row, first, last):
        _construct_charge(work, last - first + 1)
        for line in range(first, last + 1):
            statements.setdefault(line, []).append(row)
    constructs = []; endings = {}; statements = {}; bodies = set(); statement_hashes = set()
    for i, word in enumerate(code.words):
        if word != '{':
            continue
        parent = code.parents[i]; first = beginning(i, parent); end = code.pairs[i]
        _construct_charge(work, i - first)
        prefix = code.words[first:i]
        kind = next((word for word in ('fn', 'struct', 'enum', 'impl', 'trait', 'mod', 'if', 'for', 'while', 'loop', 'match')
                     if word in prefix), 'expression')
        complete = digest(first, end)
        row = dict(first=first, opening=i, end=end, kind=kind, header=tuple(prefix),
                   digest=complete, body=complete if first == i else digest(i, end), supported='#' not in prefix)
        bodies.add(row['body']); constructs.append(row)
        line = code.position(code.starts[end])[0]
        endings.setdefault(line, []).append(row)
        if kind == 'match' and prefix[-2:] == ['.', 'await'] and prefix[0] == 'match':
            expression = dict(first=first + 1, opening=None, end=i - 1, kind='statement',
                              digest=digest(first + 1, i - 1), body=None, supported='#' not in prefix)
            constructs.append(expression); statement_hashes.add(expression['digest'])
            index_statement(expression, code.position(code.starts[first + 1])[0],
                            code.position(code.starts[i - 1])[0])
    for parent, indices in siblings.items():
        if parent is None or code.words[parent] != '{':
            continue
        _construct_charge(work, 2 * len(indices))
        terminal = code.pairs[parent]
        ends = [(end, end) for end in indices if code.words[end] == ';']
        if beginning(terminal, parent) < terminal:
            ends.append((terminal, terminal - 1))
        for boundary, end in ends:
            first = beginning(boundary, parent)
            if first >= end:
                continue
            row = dict(first=first, opening=None, end=end, kind='statement',
                       digest=digest(first, end), body=None, supported='#' not in code.words[first:end])
            constructs.append(row); statement_hashes.add(row['digest'])
            index_statement(row, code.position(code.starts[first])[0], code.position(code.starts[end])[0])
    return code, constructs, endings, statements, bodies, statement_hashes


@dataclass(frozen=True)
class RustNominalMethodPath:
    impl_scope: str
    namespace: tuple
    self_type: tuple
    trait: tuple | None
    method: tuple[str, str]
    callbacks: tuple[str, ...]
    kind: str
    crate_graph: tuple[tuple[str, str], ...]
    instantiating_crate: tuple[str, str]
    type_argument: tuple | None = None

    @property
    def parent_scope(self):
        return self.kind, self.impl_scope, self.namespace, self.self_type, self.trait

    @property
    def copy_identity(self):
        return self.parent_scope, self.method, self.crate_graph, self.instantiating_crate, self.type_argument


_NOMINAL_METHOD_PREFIX = re.compile(r'_R((?:NC){0,8})Nv([MXY])')
_PATH_REFERENCE_METHOD_PREFIX = re.compile(r'_RI()Nv(M)')
_LOCAL_MEMBER_FUNCTION_PREFIX = re.compile(r'_R()NvNv(M)')
_NOMINAL_METHOD_PREFIX_WORK = len('_R' + 'NC' * 8 + 'NvX') + 1


@lru_cache(maxsize=4096)
def nominal_method_path(symbol, *, inventory=False, path_reference=False, local_scope=False, local_function=False, core_default_impl=False):
    """Decode bounded nominal v0 inherent, trait-impl and default-trait methods.

    Replacement identity omits crate disambiguators; callback ownership retains
    every crate copy and the instantiating crate. Backreferences require a complete earlier path.
    Inventory mode includes suffixes conservatively, never for execution proof.
    """
    if type(symbol) is not str or len(symbol) > 4096:
        return None
    if local_function and (inventory or path_reference or local_scope):
        return None
    pattern = (_LOCAL_MEMBER_FUNCTION_PREFIX if local_function else
               _PATH_REFERENCE_METHOD_PREFIX if path_reference else _NOMINAL_METHOD_PREFIX)
    prefix = pattern.match(symbol)
    if prefix is None:
        return None
    depth = len(prefix[1]) // 2
    kind = prefix[2]
    if core_default_impl and (kind!='X' or depth or inventory or path_reference or local_scope or local_function):
        return None
    at = prefix.end(); paths = {}; work = 256; crate = None; crates = {}
    def disambiguator():
        nonlocal at
        match = re.match(r's[0-9A-Za-z]{0,32}_', symbol[at:])
        if match:
            at += len(match[0])
        return match[0] if match else ''
    def identifier():
        nonlocal at
        scope = disambiguator()
        length = re.match(r'[1-9][0-9]{0,3}', symbol[at:])
        if length is None:
            raise ValueError('missing identifier length')
        size = int(length[0]); at += len(length[0])
        if size > 1024:
            raise ValueError('identifier exceeds bound')
        if symbol[at:at + 1] == '_':
            at += 1
        value = symbol[at:at + size]; at += size
        if len(value) != size or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', value) is None:
            raise ValueError('unsupported identifier')
        return value, scope
    def path(depth=0, *, external=False):
        nonlocal at, work, crate
        work -= 1
        if depth > 16 or work < 0 or at >= len(symbol):
            raise ValueError('path exceeds bound')
        first = at; tag = symbol[at]; at += 1
        if tag == 'C':
            value, scope = identifier()
            if crate is None:
                crate = value, scope
            elif kind != 'Y' and not external and crate != (value, scope):
                raise ValueError('external crate identity is unsupported')
            if value in crates and crates[value] != scope:
                raise ValueError('ambiguous nominal crate copy')
            crates[value] = scope
            result = ('crate', value)
        elif tag == 'N' and symbol[at:at + 1] == 't':
            at += 1
            parent = path(depth + 1, external=external)
            result = ('type', parent, identifier())
        elif local_scope and tag == 'N' and symbol[at:at+1] in ('v','C'):
            namespace = symbol[at]; at += 1
            parent = path(depth+1,external=external)
            if namespace == 'v':
                result = ('value',parent,identifier())
            else:
                scope = disambiguator()
                if symbol[at:at+1] != '0':
                    raise ValueError('unsupported local closure identifier')
                at += 1
                result = ('closure',parent,scope)
        elif tag == 'B':
            encoded = re.match(r'([0-9A-Za-z]{0,4})_', symbol[at:])
            if encoded is None:
                raise ValueError('invalid backreference')
            offset = 0
            for digit in encoded[1]:
                offset = offset * 62 + '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.index(digit)
            offset = (offset + 1 if encoded[1] else 0) + 2
            at += len(encoded[0])
            if offset >= first or offset not in paths:
                raise ValueError('backreference is not a complete earlier path')
            result = paths[offset]
        else:
            raise ValueError('unsupported nominal path')
        paths[first] = result
        return result
    try:
        if kind == 'Y':
            impl_scope = ''; namespace = ()
            self_type = path(); trait = path()
        else:
            impl_scope = disambiguator()
            namespace = path(); self_type = path()
            trait = path(external=core_default_impl) if kind == 'X' else None
        if core_default_impl and trait!=('type',('type',('crate','core'),('default','')),('Default','')):
            return None
        method, item_scope = identifier()
        local = identifier() if local_function else None
        callbacks = []
        for _ in range(depth):
            callbacks.append(disambiguator())
            if symbol[at:at + 1] != '0':
                return None
            at += 1
        argument = None
        if path_reference:
            tag = symbol[at:at + 1]
            at += 1
            if tag == 'R':
                reference = path(external=True)
                if reference not in (('type', ('type', ('crate', 'std'), ('path', '')), (item, ''))
                                     for item in ('Path', 'PathBuf')):
                    return None
                argument = ('reference', reference[-1][0], crates['std'])
            elif tag == 'p':
                argument = ('placeholder',)
            else:
                return None
            if symbol[at:at + 1] != 'E':
                return None
            at += 1
        instance = None
        if (path_reference or depth and symbol[at:at + 1] == 'B'
                or kind == 'Y' and symbol[at:at + 1] in ('B', 'C')):
            root = path(external=path_reference)
            if root[0] != 'crate':
                return None
            instance = root[1], crates[root[1]]
        if path_reference and (argument == ('placeholder',) and instance != crate or instance[0] == 'std'):
            return None
        if kind == 'Y' and len(crates) > 1 and instance is None and not inventory:
            return None
        if not inventory and at != len(symbol):
            return None
        shape = RustNominalMethodPath(impl_scope, namespace, self_type, trait,
            (method, item_scope), tuple(callbacks), kind,
            tuple(sorted(crates.items())), instance or crate, argument)
        return (shape,local) if local_function else shape
    except ValueError:
        return None


def nominal_method_parent(symbol, declaration=None, *, inventory=False):
    shape = nominal_method_path(symbol, inventory=inventory)
    if (shape is None or not inventory and shape.callbacks
            or declaration is not None and shape.method[0] != declaration):
        return None
    return ('method:' + repr((*shape.parent_scope, shape.method[1])), 'method:' + repr(shape.parent_scope))


def compiled_method_parent_files(owners, files, work):
    _construct_charge(work, len(owners))
    scopes = {}; unknown = set()
    for owner in owners:
        name = owner['name']
        _construct_charge(work, min(len(name) + 1, _NOMINAL_METHOD_PREFIX_WORK))
        parent = None
        if _NOMINAL_METHOD_PREFIX.match(name) is not None:
            _construct_charge(work, len(name) + 1)
            parent = nominal_method_parent(name, inventory=True)
        if parent is None and name.startswith(('_R', '_ZN')):
            continue
        _construct_charge(work, len(owner['filenames']))
        locations = unknown if parent is None else scopes.setdefault(parent[1], set())
        locations.update(files.get(path, '<unattributed source>') for path in owner['filenames'])
    return scopes, unknown


_PLAIN_PARENT_ANCHOR = re.compile(r'(?=([0-9][A-Za-z_][A-Za-z0-9_]))')


def compiled_plain_parent_files(owners, files, work):
    """Prefilter literal scope searches without interpreting the raw owner names."""
    _construct_charge(work, len(owners))
    anchors = {}
    unknown = set()
    for owner in owners:
        name = owner['name']
        _construct_charge(work, len(name) + 1)
        if not name.startswith(('_R', '_ZN')):
            _construct_charge(work, len(owner['filenames']))
            unknown.update(files.get(path, '<unattributed source>') for path in owner['filenames'])
            continue
        occurrences = _PLAIN_PARENT_ANCHOR.findall(name)
        _construct_charge(work, len(occurrences))
        keys = set(occurrences)
        _construct_charge(work, len(keys))
        for key in keys:
            anchors.setdefault(key, []).append(owner)

    def locations(scope):
        _construct_charge(work, len(scope) + 1)
        keys = _PLAIN_PARENT_ANCHOR.findall(scope)
        _construct_charge(work, len(keys))
        if keys:
            key = min(keys, key=lambda value: (len(anchors.get(value, ())), value))
            candidates = anchors.get(key, ())
            _construct_charge(work, len(unknown))
            matches = set(unknown)
        else:
            candidates = owners
            matches = set()
        _construct_charge(work, len(candidates))
        for owner in candidates:
            name = owner['name']
            _construct_charge(work, len(name) + 1)
            if scope in name or not name.startswith(('_R', '_ZN')):
                _construct_charge(work, len(owner['filenames']))
                matches.update(files.get(path, '<unattributed source>') for path in owner['filenames'])
        return matches

    return locations


def replacement_raw_parent(symbol, declaration=None):
    if type(symbol) is not str or len(symbol) > 4096:
        return None
    prefix = re.match(r'_RNv((?:Nt){0,16})C(?:s[0-9A-Za-z]{0,32}_)?', symbol)
    if prefix is None:
        return nominal_method_parent(symbol, declaration)
    at = prefix.end(); parts = []
    for index in range(len(prefix[1]) // 2 + 2):
        first = at
        disambiguator = re.match(r's[0-9A-Za-z]{0,32}_', symbol[at:]) if index else None
        if disambiguator:
            at += len(disambiguator[0])
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
        at += size
        parts.append((symbol[first:at], value, first))
    if at != len(symbol) or declaration is not None and parts[-1][1] != declaration:
        return None
    final = parts[-1][0]
    terminal = re.match(r's[0-9A-Za-z]{0,32}_', final)
    scope = ''.join(part[0] for part in parts[:-1])
    return ('_RNv' + prefix[1] + 'C' + scope + (terminal[0] if terminal else ''), scope)


def fully_covered_replacement(name, old, new, before, after, descriptors, grouped,
                              selected, equal_rows, work, local_impl_members=((),())):
    """Certify correspondence only when every region in both owner trees is covered."""
    witnesses = []
    for counts, descriptor, compiled, local_members in zip((before, after), descriptors, grouped,local_impl_members):
        first, last, parents = descriptor['group']
        _construct_charge(work, last - first + len(compiled[0]) + len(counts))
        if any(count <= 0 for line, count in counts.items() if first <= line <= last):
            return None
        parent_names = {owner['name'] for owner in parents}
        method_shapes = {parent: nominal_method_path(parent) for parent in parent_names}
        plain_shapes = {parent: plain_rust_function_symbol(parent) for parent in parent_names}
        if any((method is None or method.callbacks) and plain_shapes[parent] is None
               for parent, method in method_shapes.items()):
            return None
        parent_paths = {shape.copy_identity for shape in method_shapes.values() if shape is not None}
        async_bodies = {parent: [] for parent in parent_names}
        owners = []; regions = []
        for owner in compiled[0]:
            name_length = len(owner['name'])
            _construct_charge(work, 2 * len(owner['regions']) + 1)
            span = min(row[0] for row in owner['regions']), max(row[2] for row in owner['regions'])
            if span[1] < first or span[0] > last:
                continue
            _construct_charge(work, name_length * (1 + 8 * len(parent_names)))
            shape = nominal_method_path(owner['name'])
            child = (any(owner is member for member in local_members)
                     or shape is not None and shape.callbacks and shape.copy_identity in parent_paths
                     or any(plain is not None and any(direct_rust_callback_symbol(
                         owner['name'], parent, plain.modules, depth) for depth in range(1, 9))
                            for parent, plain in plain_shapes.items()))
            if span[0] == first:
                for parent, plain in plain_shapes.items():
                    if plain is not None and direct_rust_callback_symbol(owner['name'], parent, plain.modules):
                        async_bodies[parent].append(owner['name'])
            if (not first <= span[0] <= span[1] <= last
                    or compiled[2][owner['name']] != 1
                    or owner['name'] not in parent_names and not child
                    or type(owner.get('count')) is not int or not 0 < owner['count'] < COUNTER_LIMIT
                    or any(not 0 < row[4] < COUNTER_LIMIT for row in owner['regions'])):
                return None
            owners.append(dict(name=owner['name'], count=owner['count'], range=list(span),
                regions_sha256=hashlib.sha256(repr(owner['regions']).encode()).hexdigest()))
            regions.extend(owner['regions'])
        if not parent_names.issubset({owner['name'] for owner in owners}):
            return None
        if (descriptor['attributes'] == ['#', '[', 'tokio', '::', 'test', ']', 'async']
                and any(len(bodies) != 1 for bodies in async_bodies.values())):
            return None
        _construct_charge(work, (last - first + 1) * len(regions))
        if any(not owner_covers_lines(regions, line, line)
               for line in counts if first <= line <= last):
            return None
        witnesses.append(owners)
    pairs = {}
    _construct_charge(work, len(equal_rows) + len(selected))
    for line, target in equal_rows:
        if (descriptors[0]['group'][0] <= line <= descriptors[0]['group'][1]
                and descriptors[1]['group'][0] <= target <= descriptors[1]['group'][1]
                and line in before and target in after):
            pairs[line] = target
    for row in selected:
        line, target = row['base_line'], row['head_line']
        if (row.get('residual') and line in before and target in after
                and old[line - 1] == new[target - 1]):
            if line in pairs and pairs[line] != target:
                return None
            pairs[line] = target
    if not pairs or len(set(pairs.values())) != len(pairs):
        return None
    return pairs, dict(file=name, pairs=[list(pair) for pair in sorted(pairs.items())],
        fully_covered_replacement_owners=witnesses,
        base_range=list(descriptors[0]['group'][:2]), head_range=list(descriptors[1]['group'][:2]),
        claim='Every raw region and owner entry is positive on both sides; no deletion or semantic-equivalence claim',
        summary_credit=[0, 0], mapped_credit=[0, 0])


def eager_call_prefix_obligations(name, sources, counts, descriptors, inventories, grouped, work):
    """Prove only initial direct-call evaluation before a changed continuation."""
    codes = [inventory[0] for inventory in inventories]
    functions = [descriptor['row'] for descriptor in descriptors]
    if any('async' in function['header'] for function in functions):
        return None
    bodies = []
    for code, function in zip(codes, functions):
        _construct_charge(work, function['end'] - function['opening'])
        bodies.append(code.words[function['opening'] + 1:function['end']])
    common = 0
    while common < min(map(len, bodies)) and bodies[0][common] == bodies[1][common]:
        _construct_charge(work, len(bodies[0][common]) + 1)
        common += 1
    forbidden = {'|', '||', '&&', 'async', 'await', '!', '?', '#',
                 'match', 'loop', 'while', 'for', 'return', 'break',
                 'continue', 'yield', 'fn', 'use', 'const', 'static', 'type', 'mod',
                 'struct', 'enum', 'impl', 'trait', 'extern', 'macro_rules'}
    if (not common or common == min(map(len, bodies)) or bodies[0][common - 1] != ')'
            or {bodies[0][common], bodies[1][common]} != {';', '.'}
            or forbidden.intersection(bodies[0][:common])):
        return None
    ends = [function['opening'] + common for function in functions]
    for code, function, end in zip(codes, functions, ends):
        opening = code.pairs[end]
        if code.parents[opening] != function['opening']:
            return None
        if code.words[end + 1] == '.' and (re.fullmatch(r'[A-Za-z_]\w*', code.words[end + 2]) is None
                or code.words[end + 3] != '('):
            return None
    bounds = [(code.position(code.starts[function['opening'] + 1])[0],
               code.position(code.ends[end])[0]) for code, function, end in zip(codes, functions, ends)]
    positions = [[code.position(code.starts[function['opening'] + 1 + offset])[0]
                  for offset in range(common)] for code, function in zip(codes, functions)]
    line_targets = {}; target_lines = {}
    _construct_charge(work, common * 3)
    for line, target in zip(*positions):
        line_targets.setdefault(line, set()).add(target)
        target_lines.setdefault(target, set()).add(line)
    mapped = []
    for line, targets in line_targets.items():
        if len(targets) != 1:
            continue
        target, = targets
        if target_lines[target] != {line}:
            continue
        _construct_charge(work, len(sources[0][line - 1]) + len(sources[1][target - 1]))
        if sources[0][line - 1] != sources[1][target - 1]:
            continue
        if line in counts[0] or target in counts[1]:
            if line not in counts[0] or target not in counts[1]:
                return None
            mapped.append((line, target))
    if not mapped:
        return None
    geometries = []; vectors = []
    for side, (source, descriptor, compiled) in enumerate(zip(sources, descriptors, grouped)):
        members = descriptor['group'][2]; shapes = []; states = []; observed = set()
        member_ids = {id(owner) for owner in members}
        for owner in compiled[0]:
            _construct_charge(work, len(mapped) * (len(owner['regions']) + 1))
            if id(owner) not in member_ids and any(
                    tuple(region[:2]) < (pair[side], len(source[pair[side] - 1].encode()) + 1)
                    and (pair[side], 1) < tuple(region[2:4])
                    for pair in mapped for region in owner['regions']):
                return None
        for owner in members:
            pieces = []
            for ordinal, pair in enumerate(mapped):
                line = pair[side]; text = source[line - 1]
                low, high = (line, 1), (line, len(text.encode()) + 1)
                _construct_charge(work, len(owner['regions']))
                clipped = []
                for region in owner['regions']:
                    start, end = max(tuple(region[:2]), low), min(tuple(region[2:4]), high)
                    if start < end:
                        clipped.append(((ordinal, start[1], end[1], *region[5:]), int(region[4] > 0)))
                        if region[4] > 0:
                            observed.add(ordinal)
                if not clipped:
                    return None
                pieces.extend(clipped)
            _construct_charge(work, len(pieces) * (len(pieces).bit_length() + 3))
            pieces.sort()
            shapes.append(tuple(shape for shape, state in pieces))
            states.append(tuple(state for shape, state in pieces))
        _construct_charge(work, len(mapped))
        if any(bool(counts[side][pair[side]]) != (ordinal in observed)
               for ordinal, pair in enumerate(mapped)):
            return None
        geometries.append(shapes); vectors.append(states)
    if len(vectors[0]) != len(vectors[1]) or not vectors[0]:
        return None
    raw_regions = None
    if any(shape != geometries[0][0] for side in geometries for shape in side):
        normalized = homogeneous_clipped_regions(geometries, vectors, work)
        if normalized is None:
            return None
        raw_regions = dict(geometry=geometries, instance_states=vectors)
        geometries, vectors = normalized
        if any(shape != geometries[0][0] for side in geometries for shape in side):
            return None
    _construct_charge(work, (len(vectors[0]) * len(vectors[1]) + 1) * len(vectors[0][0]))
    matching = compiled_hit_state_matching(*vectors)
    if matching is None:
        raise ValueError('Eager call prefix lost compiled-copy coverage')
    _construct_charge(work, len(repr(descriptors[0]['context'])) + len(repr(descriptors[0]['signature'])))
    receipt = dict(file=name, pairs=mapped,
        eager_call_prefix=dict(base_range=list(bounds[0]), head_range=list(bounds[1]),
            source_sha256=hashlib.sha256(repr(bodies[0][:common]).encode()).hexdigest(),
            context_sha256=hashlib.sha256(repr(descriptors[0]['context']).encode()).hexdigest(),
            declaration_sha256=hashlib.sha256(repr(descriptors[0]['signature']).encode()).hexdigest()),
        geometry=geometries[0][0], base_instance_states=vectors[0], head_instance_states=vectors[1],
        instance_matching=matching, claim='Complete-copy initial direct-call evaluation only')
    if raw_regions is not None:
        receipt['homogeneous_clipped_regions'] = raw_regions
    return dict(mapped), receipt


def qualified_test_retained_statements(sources, descriptors, inventories, grouped, file_counts,
                                       selected, seeds, full_receipt, work):
    """Reconcile retained statement regions only after complete positive owner proof."""
    _construct_charge(work, len(seeds) + len(selected))
    required = {row['digest'] for row, target in seeds}
    retained_sets = {id(row['retained_statements']): row['retained_statements']
                     for row in selected if row.get('retained_statements')}
    _construct_charge(work, sum(len(values) for values in retained_sets.values()))
    for values in retained_sets.values():
        required.update(values)
    _construct_charge(work, len(required) * (len(required).bit_length() + 1))
    pairs = {}; statements = []
    for digest in sorted(required):
        rows = [descriptor['statements'].get(digest, []) for descriptor in descriptors]
        if any(len(side) != 1 or counts[digest] != 1 for side, counts in zip(rows, file_counts)):
            return None
        evidence = []; shapes = []; states = []; lines = []; texts = []
        for side, (source, inventory, compiled, matches) in enumerate(zip(sources, inventories, grouped, rows)):
            row, = matches; code = inventory[0]
            first = code.position(code.starts[row['first']]); end = code.position(code.ends[row['end']])
            if row['kind'] != 'statement' or not row['supported'] or first[0] != end[0]:
                return None
            line = first[0]; text = source[line - 1]; indent = len(text) - len(text.lstrip())
            if first[1] != len(text[:indent].encode()) + 1 or end[1] != len(text.rstrip().encode()) + 1:
                return None
            low, high = first, end
            allowed = {owner['name'] for owner in full_receipt['fully_covered_replacement_owners'][side]}
            contributors = []; geometry = []; vectors = []
            _construct_charge(work, len(text) + sum(len(owner['regions']) + 1 for owner in compiled[0]))
            for owner in compiled[0]:
                regions = [region for region in owner['regions']
                           if tuple(region[:2]) < high and low < tuple(region[2:4])]
                if not regions:
                    continue
                if (owner['name'] not in allowed or not 0 < owner.get('count', 0) < COUNTER_LIMIT
                        or any(not 0 < region[4] < COUNTER_LIMIT for region in regions)):
                    return None
                clipped = [(max(tuple(region[:2]), low)[1] - low[1],
                            min(tuple(region[2:4]), high)[1] - low[1], *region[5:]) for region in regions]
                if any(start >= finish for start, finish, *flags in clipped):
                    return None
                _construct_charge(work, len(clipped) * (len(clipped).bit_length() + 3))
                geometry.append(tuple(sorted(clipped)))
                vectors.append(tuple(1 for region in regions))
                contributors.append(dict(name=owner['name'], count=owner['count'], regions=regions))
            if not contributors:
                return None
            lines.append(line); texts.append(text.strip()); evidence.append(contributors)
            shapes.append(geometry); states.append(vectors)
        if (texts[0] != texts[1] or len(shapes[0]) != len(shapes[1])
                or any(shape != shapes[0][0] for side in shapes for shape in side)):
            return None
        _construct_charge(work, len(states[0]) * len(states[1]) * len(states[0][0]))
        matching = compiled_hit_state_matching(*states)
        if matching is None:
            return None
        if lines[0] in pairs and pairs[lines[0]] != lines[1]:
            return None
        pairs[lines[0]] = lines[1]
        statements.append(dict(digest=digest, pair=lines, owners=evidence, geometry=shapes[0][0],
            base_instance_states=states[0], head_instance_states=states[1], instance_matching=matching))
    return pairs, statements


def test_declaration_header_obligations(name, sources, counts, descriptors, inventories, grouped, work):
    """Bind unchanged test declaration lines to the same closed entry projection."""
    left, right = descriptors
    guard = ('#', '[', 'cfg', '(', 'test', ')', ']')
    if (left['context'] != right['context'] or left['attributes'] != right['attributes']
            or not any(tuple(header[:len(guard)]) == guard for header in left['context'][0])):
        return None
    parents = [{nominal_method_parent(owner['name'], descriptor['declaration'])
                for owner in descriptor['group'][2]} for descriptor in descriptors]
    if None in parents[0] or len(parents[0]) != 1 or parents[0] != parents[1]:
        return None
    lines = []; geometry = []; states = []; witnesses = []; headers = []; entry_geometry = []
    for source, mapped, descriptor, inventory, compiled in zip(sources, counts, descriptors, inventories, grouped):
        first, last, members = descriptor['group']
        header = descriptor['row']['header']
        _construct_charge(work, len(header) + len(members) + 1)
        opening = next((index for index, token in enumerate(header) if token == '('), None)
        if opening is None:
            return None
        receiver = []
        for token in header[opening + 1:]:
            receiver.append(token)
            if token == ',':
                break
        if re.fullmatch(r"&(?:'[A-Za-z_]\w*)?(?:mut)?self,", ''.join(receiver)) is None:
            return None
        code = inventory[0]
        tokens = code.words[descriptor['row']['first']:descriptor['row']['opening']]
        punctuation = {'<', '>', '(', ')', '[', ']', '&', '*', ',', ':', '::', '+', '=', '->'}
        forbidden = {'const', 'where', 'unsafe', 'extern', 'impl', 'for'}
        if (tokens.count('fn') != 1 or tokens.count('(') != 1 or tokens.count(')') != 1
                or any(token in forbidden or token not in punctuation
                       and re.fullmatch(r"(?:'[A-Za-z_]\w*|[A-Za-z_]\w*)", token) is None for token in tokens)):
            return None
        opening_line = code.position(code.starts[descriptor['row']['opening']])[0]
        levels = {}; depth = 0
        for index in range(descriptor['row']['first'], descriptor['row']['opening']):
            number = code.position(code.starts[index])[0]
            levels.setdefault(number, [depth, depth])
            depth += int(code.words[index] == '<') - int(code.words[index] == '>')
            if depth < 0:
                return None
            levels[number][1] = depth
        if depth:
            return None
        start = descriptor['row']['first'] + opening + 1
        end = start + len(receiver) - 1
        line = code.position(code.starts[start])[0]
        if (code.position(code.ends[end])[0] != line or not first < line < last
                or re.fullmatch(r"\s*&\s*(?:'[A-Za-z_]\w*\s+)?(?:mut\s+)?self\s*,\s*", source[line - 1]) is None):
            return None
        if line not in mapped or mapped[line] <= 0:
            return None
        text = source[line - 1]
        low = (line, len(text[:len(text) - len(text.lstrip())].encode()) + 1)
        high = (line, len(text.rstrip().encode()) + 1)
        allowed = {id(owner) for owner in members}
        _construct_charge(work, sum(len(owner['regions']) + 1 for owner in compiled[0]))
        if any(tuple(region[:2]) < high and low < tuple(region[2:4])
               for owner in compiled[0] if id(owner) not in allowed for region in owner['regions']):
            return None
        shapes = []; vectors = []; evidence = []; entries = []
        for owner in members:
            regions = [region for region in owner['regions']
                       if tuple(region[:2]) < high and low < tuple(region[2:4])]
            # The containing region must start at this method's declaration,
            # rather than a nested callback or a coincidentally painted line.
            if (len(regions) != 1 or regions[0][0] != first
                    or not tuple(regions[0][:2]) <= low or not high <= tuple(regions[0][2:4])
                    or type(owner.get('count')) is not int or not 0 < owner['count'] < COUNTER_LIMIT
                    or not 0 < regions[0][4] < COUNTER_LIMIT):
                return None
            region, = regions
            shapes.append((low[1], high[1], *region[5:]))
            vectors.append((int(region[4] > 0),))
            evidence.append(dict(name=owner['name'], count=owner['count'], region=region))
            entries.append((region[0] - first, region[1], region[2] - first, region[3], *region[5:]))
        lines.append(line); geometry.append(shapes); states.append(vectors); witnesses.append(evidence)
        headers.append((first, opening_line, levels)); entry_geometry.append(entries)
    if (sources[0][lines[0] - 1] != sources[1][lines[1] - 1] or not states[0]
            or len(states[0]) != len(states[1]) or geometry[0] != geometry[1]):
        return None
    _construct_charge(work, len(states[0]) * len(states[1]) + sum(len(repr(d['context'])) for d in descriptors))
    matching = compiled_hit_state_matching(*states)
    if matching is None:
        return None
    pairs = {lines[0]: lines[1]}
    header_compatible = (entry_geometry[0] == entry_geometry[1]
        and headers[0][1] - headers[0][0] == headers[1][1] - headers[1][0])
    _construct_charge(work, headers[0][1] - headers[0][0])
    for offset in range(headers[0][1] - headers[0][0] if header_compatible else 0):
        pair = [header[0] + offset for header in headers]
        if (sources[0][pair[0] - 1] != sources[1][pair[1] - 1]
                or not sources[0][pair[0] - 1].strip()
                or headers[0][2].get(pair[0]) != headers[1][2].get(pair[1])
                or any(mapped.get(line, 0) <= 0 for mapped, line in zip(counts, pair))):
            continue
        valid = True
        for side, (source, descriptor, compiled, number) in enumerate(zip(sources, descriptors, grouped, pair)):
            text = source[number - 1]
            low = (number, len(text[:len(text) - len(text.lstrip())].encode()) + 1)
            high = (number, len(text.rstrip().encode()) + 1)
            members = descriptor['group'][2]; allowed = {id(owner) for owner in members}
            _construct_charge(work, len(text) + sum(len(owner['regions']) + 1 for owner in compiled[0]))
            if any(tuple(region[:2]) < high and low < tuple(region[2:4])
                   for owner in compiled[0] if id(owner) not in allowed for region in owner['regions']):
                valid = False; break
            for owner, witness in zip(members, witnesses[side]):
                overlaps = [region for region in owner['regions']
                            if tuple(region[:2]) < high and low < tuple(region[2:4])]
                if (overlaps != [witness['region']] or not tuple(overlaps[0][:2]) <= low
                        or not high <= tuple(overlaps[0][2:4])):
                    valid = False; break
            if not valid:
                break
        if valid:
            pairs[pair[0]] = pair[1]
    if pairs.get(lines[0]) != lines[1]:
        return None
    return pairs, dict(file=name, pairs=[list(pair) for pair in sorted(pairs.items())],
        test_declaration_header=dict(context_sha256=hashlib.sha256(repr(left['context']).encode()).hexdigest(),
            owners=witnesses, geometry=geometry[0], base_instance_states=states[0], head_instance_states=states[1],
            instance_matching=matching, entry_geometry=entry_geometry[0],
            header_ranges=[list(header[:2]) for header in headers]), summary_credit=[0, 0], mapped_credit=[0, 0],
        claim='Byte-identical test declaration lines at unique relative token-depth coordinates only; no changed type, body, callback or deletion credit')


def one_bound_phase_obligations(name, sources, counts, descriptors, inventories, grouped, replacements, work):
    pairs = {}; receipts = []; proved = set(); phase_cache = {}; all_targets = {}
    direct_phases = []
    for inventory in inventories:
        code = inventory[0]; roots = set()
        _construct_charge(work,3*len(inventory[1]))
        for row in inventory[1]:
            opening = row['opening']
            if opening is None or len(row['header']) != 3 or row['header'][::2] != ('|','|'):
                continue
            parent = code.parents[opening]
            if parent is not None and code.words[parent] == '(':
                roots.add(code.parents[parent])
        direct_phases.append(roots)
    for prefix, left in descriptors[0].items():
        _construct_charge(work,1)
        right = descriptors[1].get(prefix)
        if (right is None or left['row']['opening'] not in direct_phases[0]
                or right['row']['opening'] not in direct_phases[1]
                or any(left[key] != right[key] for key in ('signature','context','attributes'))):
            continue
        groups = left['group'], right['group']
        if len(groups[0][2]) != len(groups[1][2]):
            continue
        _construct_charge(work,len(replacements))
        # A whole old-function proof may not silently omit an overlapping
        # retained obligation whose target escaped the paired head function.
        selected = [r for r in replacements.values() if r.get('retained_statements')
            and r['base_range'][0] <= groups[0][1] and groups[0][0] <= r['base_range'][1]]
        if any(not (groups[0][0] <= r['base_range'][0] <= r['base_line'] <= r['base_range'][1] <= groups[0][1]
                    and groups[1][0] <= r['head_range'][0] <= r['head_line'] <= r['head_range'][1] <= groups[1][1])
               for r in selected):
            continue
        _construct_charge(work,sum(len(r.get('retained_statements',()))+1 for r in selected))
        needed = set().union(*(set(r.get('retained_statements',())) for r in selected)) if selected else set()
        if not needed:
            continue
        required = set(); mapped = {}; targets_owned = {}; all_proofs = []; failed = False
        _construct_charge(work,len(needed))
        if any(not left['statements'].get(digest) for digest in needed):
            continue
        for digest in needed:
            _construct_charge(work,len(left['statements'].get(digest,())))
            for row in left['statements'].get(digest,()):
                code=inventories[0][0]
                low=code.position(code.starts[row['first']])[0]
                high=code.position(code.starts[row['end']])[0]
                _construct_charge(work,high-low+1)
                required.update(range(low,high+1))
        _construct_charge(work,len(left['statements'])+sum(len(rows) for rows in left['statements'].values()))
        for digest,rows in left['statements'].items():
            for row in rows:
                code=inventories[0][0]
                low=code.position(code.starts[row['first']])[0]
                high=code.position(code.starts[row['end']])[0]
                _construct_charge(work,high-low+1)
                if not required.intersection(range(low,high+1)) or set(range(low,high+1)) <= set(mapped):
                    continue
                a=zero_arg_callback_fragment(sources[0],groups[0],grouped[0][0],grouped[0][2],low,high,inventories[0],work,single_binding=True,phase_cache=phase_cache)
                if a is None:
                    continue
                targets=[]
                _construct_charge(work,len(right['statements'].get(digest,())))
                for target in right['statements'].get(digest,()):
                    other=inventories[1][0]
                    lo=other.position(other.starts[target['first']])[0]
                    hi=other.position(other.starts[target['end']])[0]
                    _construct_charge(work,sum(len(line)+1 for source,first,last in ((sources[0],low,high),(sources[1],lo,hi)) for line in source[first-1:last]))
                    if high-low != hi-lo or sources[0][low-1:high] != sources[1][lo-1:hi]:
                        continue
                    b=zero_arg_callback_fragment(sources[1],groups[1],grouped[1][0],grouped[1][2],lo,hi,inventories[1],work,single_binding=True,phase_cache=phase_cache)
                    if b is not None and a.signature==b.signature:
                        targets.append((lo,hi,b))
                if len(targets)!=1:
                    continue
                lo,hi,b=targets[0]
                _construct_charge(work,high-low+1)
                for number in range(low,high+1):
                    target=number+lo-low
                    if (number in mapped and mapped[number]!=target
                            or target in targets_owned and targets_owned[target]!=number):
                        failed=True;break
                    mapped[number]=target;targets_owned[target]=number
                if failed:break
                all_proofs.append((low,high,a,lo,hi,b))
            if failed:break
        if failed or not all_proofs or not required <= set(mapped):
            continue
        # Bind the unchanged phase construction header separately. This proves
        # only construction/entry; it does not paint the changed callback body.
        first_proof = all_proofs[0]
        old_entry = first_proof[2].witness['callback_span'][0][0]
        new_entry = first_proof[5].witness['callback_span'][0][0]
        a=zero_arg_callback_fragment(sources[0],groups[0],grouped[0][0],grouped[0][2],old_entry,old_entry,inventories[0],work,single_binding=True,phase_cache=phase_cache)
        b=zero_arg_callback_fragment(sources[1],groups[1],grouped[1][0],grouped[1][2],new_entry,new_entry,inventories[1],work,single_binding=True,phase_cache=phase_cache)
        if a is None or b is None or a.signature!=b.signature or sources[0][old_entry-1]!=sources[1][new_entry-1]:
            continue
        all_proofs.append((old_entry,old_entry,a,new_entry,new_entry,b))
        if (old_entry in mapped and mapped[old_entry]!=new_entry
                or new_entry in targets_owned and targets_owned[new_entry]!=old_entry):
            continue
        mapped[old_entry]=new_entry;targets_owned[new_entry]=old_entry
        _construct_charge(work,len(mapped))
        if any(line in counts[0] and target not in counts[1] for line,target in mapped.items()):
            continue
        _construct_charge(work,len(all_proofs)*(len(all_proofs).bit_length()+1))
        all_proofs.sort(key=lambda row:(row[0],row[1]))
        states=[[],[]]
        for side in (0,1):
            for index in range(len(groups[side][2])):
                vector=[]
                for proof in all_proofs:
                    _construct_charge(work,len(proof[2 if side==0 else 5].states[index]))
                    vector.extend(proof[2 if side==0 else 5].states[index])
                states[side].append(tuple(vector))
        _construct_charge(work,(len(states[0])*len(states[1])+1)*len(states[0][0]))
        matching=compiled_hit_state_matching(*states)
        if matching is None:
            raise ValueError('Single-bound callback phase lost compiled-copy coverage')
        _construct_charge(work,len(mapped))
        executable={line:target for line,target in mapped.items() if line in counts[0] and target in counts[1]}
        if any(line in pairs and pairs[line]!=target for line,target in executable.items()):
            raise ValueError('Ambiguous single-bound callback phase correspondence')
        if any(target in all_targets and all_targets[target]!=line for line,target in executable.items()):
            raise ValueError('Non-injective single-bound callback phase correspondence')
        all_targets.update((target,line) for line,target in executable.items())
        pairs.update(executable);proved.add(groups[0][:2])
        receipts.append(dict(file=name,kind='single-bound-callback-retained-statements',
            base_range=list(groups[0][:2]),head_range=list(groups[1][:2]),
            pairs=[list(row) for row in sorted(executable.items())],
            statement_witnesses=[dict(base=[r[0],r[1]],head=[r[3],r[4]],
                signature_sha256=hashlib.sha256(repr(r[2].signature).encode()).hexdigest(),
                base_phase=r[2].witness,head_phase=r[5].witness) for r in all_proofs],
            base_instance_states=states[0],head_instance_states=states[1],instance_matching=matching,
            claim='Exact local retained statements only, all root and phase copies; no changed sibling or callee equivalence'))
    return pairs,receipts,proved


_TEST_TAIL_RECORD_HEADER = ('#', '[', 'cfg', '(', 'test', ')', ']', 'fn')


def tail_record_parameters(signature, work):
    """Recognize nullary public or explicitly test-only typed constructors."""
    if signature == ('pub', 'fn', '<declaration>', '(', ')', '->', 'Self'):
        return ()
    if (signature[:8] != _TEST_TAIL_RECORD_HEADER or signature[9:10] != ('(',)
            or signature[-3:] != (')', '->', 'Self')):
        return None
    tokens = signature[10:-3]
    _construct_charge(work, sum(len(token)+1 for token in tokens)+1)
    if not tokens or len(tokens) % 4 != 3:
        return None
    parameters = []
    for offset in range(0, len(tokens), 4):
        name, colon, type_name = tokens[offset:offset+3]
        if (colon != ':' or tokens[offset+3:offset+4] not in ((), (',',))
                or any(re.fullmatch(r'[A-Za-z_]\w*', word, re.ASCII) is None for word in (name, type_name))):
            return None
        parameters.append((name,type_name))
    return tuple(parameters)


def tail_record_value_spans(code, function, record, source, parameters, work):
    """Bind a single tail record with one direct initializer per source line."""
    if (record['header'] != ('Self',)
            or record['first'] != function['opening'] + 1 or record['end'] + 1 != function['end']):
        return None
    first = code.position(code.starts[record['opening']])[0]
    last = code.position(code.starts[record['end']])[0]
    _construct_charge(work,len(source[first-1])+len(source[last-1])+2)
    if source[first-1].strip() != 'Self {' or source[last-1].strip() != '}':
        return None
    identifier = r'[A-Za-z_][A-Za-z0-9_]*'
    path = r'(?:'+identifier+r'::)*'+identifier
    pattern = re.compile(r'[ \t]*('+identifier+r'): (?P<value>'+path+r'\(\)|'
        +path+r'\.'+identifier+r'\("[A-Za-z0-9_./-]+"\)),[ \t]*', re.ASCII)
    shorthand = re.compile(r'[ \t]*('+identifier+r'),[ \t]*', re.ASCII)
    values = set(); fields = set(); roots = {type_name for _,type_name in parameters}
    bound = []; first_slot = None
    for number in range(first+1,last):
        line = source[number-1]; _construct_charge(work, len(line)+1)
        slot = shorthand.fullmatch(line) if parameters else None
        if slot is not None:
            field = slot[1]
            if field in fields:
                return None
            span = (number,slot.start(1)+1,number,slot.end(1)+1)
            if not bound:
                first_slot = span
            bound.append(field);fields.add(field)
            values.add(span)
            continue
        parsed = pattern.fullmatch(line)
        if parsed is None or parsed[1] in fields:
            return None
        fields.add(parsed[1])
        start = parsed.start('value')+1
        # LLVM paints the callee path for a direct nullary call.
        values.add((number,start,number,start+len(parsed['value'].removesuffix('()'))))
        roots.add(re.match(identifier,parsed['value'])[0])
    return (values,roots,first_slot) if values and bound == [name for name,_ in parameters] else None


def tail_record_import_context(before, after, referenced, work):
    """Ensure changed ordinary imports cannot replace a directly referenced binding."""
    if before == after:
        return True
    _construct_charge(work,2*sum(len(clause)+1 for clauses in (before,after) for clause in clauses))
    old, new = Counter(before), Counter(after)
    for clause in (old-new).keys() | (new-old).keys():
        if (clause[:1] != ('use',) or clause[-1:] != (';',)
                or any(word in ('as','self') or word in referenced or (
                    word not in ('::','{','}',',') and re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None)
                    for word in clause[1:-1])):
            return False
    return True


def retained_record_field_obligations(name, sources, counts, descriptors, inventories, grouped,
                                      replacements, work, indexes_factory, expansions):
    """Retain a closed forest across one observed record initializer change.

    The added initializer stays in the head ratios. This proves execution of retained source.
    """
    if indexes_factory is None or expansions != ([], []):
        return {}, [], set()
    pairs = {}; target_owners = {}; receipts = []; proved = set(); indexes = None
    identifier = r'[A-Za-z_][A-Za-z0-9_]*'
    addition_pattern = re.compile(r'[ \t]*(?P<field>'+identifier+r')[ \t]*:[ \t]*'
        r'(?P<value>(?:'+identifier+r'::)+'+identifier+r'(?P<call>\(\))?)[ \t]*,[ \t]*', re.ASCII)
    update_pattern = re.compile(r'[ \t]*\.\.(?P<type>[A-Z][A-Za-z_0-9]*)::default\(\)[ \t]*', re.ASCII)
    literal_field = re.compile(r'[ \t]*'+identifier+r': vec!\[(?P<value>"[A-Za-z_0-9.-]+")\.into\(\)\],[ \t]*', re.ASCII)
    unit_literal_field = re.compile(r'[ \t]*'+identifier+r': vec!\[(?P<value>"[A-Za-z_0-9.-]+")\.to_string\(\)\],[ \t]*', re.ASCII)
    module_path = name.removeprefix('src/').removesuffix('.rs').split('/')
    for prefix, left in descriptors[0].items():
        _construct_charge(work, 1)
        right = descriptors[1].get(prefix)
        if right is None or any(left[key] != right[key] for key in ('signature','attributes')):
            continue
        supported = all(row['row']['supported'] for row in (left,right))
        unit_update = left['signature'] == _RESULT_TEST_SIGNATURE[:8]
        update_test = unit_update or left['signature'] == _RESULT_TEST_SIGNATURE
        if not supported and not update_test and left['signature'][:8] != _TEST_TAIL_RECORD_HEADER:
            continue
        contexts_match = left['context'] == right['context']
        parameters = tail_record_parameters(left['signature'],work) if not contexts_match else None
        if not contexts_match and parameters is None and not update_test:
            continue
        groups = left['group'], right['group']; spans = [group[:2] for group in groups]
        if spans[1][1]-spans[1][0] != spans[0][1]-spans[0][0]+1:
            continue
        bodies = [source[first-1:last] for source,(first,last) in zip(sources,spans)]
        _construct_charge(work, 3*sum(len(line)+1 for body in bodies for line in body))
        if any(not line.isascii() for body in bodies for line in body):
            continue
        position = 0
        while position < len(bodies[0]) and bodies[0][position] == bodies[1][position]:
            position += 1
        if position >= len(bodies[1]) or bodies[0][position:] != bodies[1][position+1:]:
            continue
        if bodies[1][position] in bodies[0][max(0,position-1):position+1]:
            continue
        match = addition_pattern.fullmatch(bodies[1][position])
        update = update_pattern.fullmatch(bodies[1][position]) if match is None and update_test else None
        if update is None and (match is None or (unit_update and (not supported
                or (not contexts_match and parameters is None)))):
            continue
        added = spans[1][0]+position
        refinement = None
        if update:
            if any(descriptor['context'][0]!=(('#','[','cfg','(','test',')',']','mod','tests'),)
                   for descriptor in (left,right)):
                continue
            imports = [Counter(descriptor['context'][1]) for descriptor in (left,right)]
            changed = (imports[0]-imports[1]).keys() | (imports[1]-imports[0]).keys()
            if any(len(clause)<3 or re.fullmatch(r'use (?:'+identifier+r' :: )*'+identifier+r' ;',
                                               ' '.join(clause)) is None for clause in changed):
                continue
            referenced = {clause[-2] for clause in changed}
            if position == 0:
                continue
            last_value = (unit_literal_field if unit_update else literal_field).fullmatch(bodies[1][position-1])
            if last_value is None:
                continue
            refinement = (added-1,last_value.start('value')+1,added-1,last_value.end('value')+1)
        _construct_charge(work,len(replacements))
        related = [r for r in replacements.values() if r.get('retained_statements')
            and r['base_range'][0] <= spans[0][1] and spans[0][0] <= r['base_range'][1]]
        if (any(not (spans[0][0] <= r['base_range'][0] <= r['base_line'] <= r['base_range'][1] <= spans[0][1]
                and spans[1][0] <= r['head_range'][0] <= r['head_line'] <= r['head_range'][1] <= spans[1][1]) for r in related)):
            continue
        field = match['field'] if match else None
        records = []; phases = []; references = []; valid = True
        call = match is not None and match['call'] is not None
        if match:
            value_end = (match.start('call') if call else match.end('value'))+1
            addition = (added,match.start('value')+1,added,value_end)
        if not call and not update and (not supported or not contexts_match):
            continue
        tail_values = []; shorthand_entries = []; initializer_roots = set(); implementation = None
        if call:
            if contexts_match:
                parameters = tail_record_parameters(left['signature'],work)
            scopes = left['context'][0]
            _construct_charge(work,len(name)+len(scopes)+1)
            if (parameters is None or scopes!=right['context'][0] or len(scopes)!=1 or len(scopes[0])!=2
                    or scopes[0][0]!='impl' or any(re.fullmatch(identifier, part) is None for part in module_path)):
                continue
            implementation = scopes[0][1]
        for side,(inventory,descriptor) in enumerate(zip(inventories,(left,right))):
            code,rows = inventory[:2]; function = descriptor['row']
            _construct_charge(work, 3*len(rows)+len(code.words).bit_length()+1)
            offset_line = added if side else spans[0][0]+position
            token = bisect.bisect_left(code.starts,code.offsets[offset_line-1])
            if update:
                if token >= len(code.words) or not side and code.words[token]!='}':
                    valid=False;break
                holding = code.parents[token] if side else code.pairs.get(token)
                words = code.words[function['first']:function['end']+1]
                _construct_charge(work,len(words))
                if referenced.intersection(words):
                    valid=False;break
            elif side:
                if token >= len(code.words) or code.words[token] != field:
                    valid=False;break
                holding=code.parents[token]
            else:
                # The first old field is now the second new field, so its
                # enclosing record has exactly the same retained source bytes.
                holding=code.parents[token] if token < len(code.words) else None
            candidates=[row for row in rows if row['opening']==holding and row['supported']]
            if len(candidates)!=1 or holding is None or code.words[holding]!='{':
                valid=False;break
            record=candidates[0];header=tuple(record['header'])
            if update and len(header)==4 and header[0]=='let' and header[2]=='=':
                type_path=header[3:]
            elif len(header)>=3 and header[0]==header[2]=='|' and re.fullmatch(identifier,header[1]):
                type_path=header[3:]
            else:
                type_path=header
            if (not type_path or len(type_path)%2!=1 or re.fullmatch(r'[A-Z][A-Za-z0-9_]*',type_path[-1]) is None
                    or any(re.fullmatch(identifier,word) is None for word in type_path[::2])
                    or any(word!='::' for word in type_path[1::2])
                    or not function['opening'] < holding < record['end'] < function['end']):
                valid=False;break
            _construct_charge(work,record['end']-holding+1)
            if update:
                if type_path!=(update['type'],) or (side and (
                        code.position(code.starts[record['end']])[0]!=added+1
                        or code.words[token:record['end']]!=['.','.',update['type'],'::','default','(',')'])):
                    valid=False;break
                opening = code.parents[holding]
                if unit_update:
                    if opening!=function['opening'] or len(header)!=4 or header[0]!='let' or header[2]!='=':
                        valid=False;break
                    records.append(record);phases.append([]);continue
                callback = next((row for row in rows if row['opening']==opening),None)
                if opening is None or callback is None or not environment_result_callback(code,function,callback):
                    valid=False;break
                records.append(record);phases.append([(callback,'block')]);continue
            if side and (code.position(code.starts[holding])[0]!=added-1 or token!=holding+1):
                valid=False;break
            if side and not call:
                line_end=code.offsets[added] if added < len(code.offsets) else len(code.text)
                stop=bisect.bisect_left(code.starts,line_end)
                if any(code.parents[i]!=holding for i in range(token,stop)):
                    valid=False;break
            if not side and field in code.words[holding+1:record['end']]:
                valid=False;break
            if call:
                if parameters:
                    guard_line=code.position(code.starts[function['first']])[0]
                    guard_text=sources[side][guard_line-1]
                    _construct_charge(work,len(guard_text)+1)
                    if guard_line!=spans[side][0]-1 or guard_text.strip()!='#[cfg(test)]':
                        valid=False;break
                values=tail_record_value_spans(code,function,record,sources[side],parameters,work)
                if values is None:
                    valid=False;break
                geometry, roots, first_slot = values
                _construct_charge(work,len(roots))
                tail_values.append(geometry);initializer_roots.update(roots)
                shorthand_entries.append(first_slot)
                records.append(record);phases.append([])
                continue
            if not side:
                first=holding+1;end=first
                while end < record['end'] and code.words[end]!=',':
                    _construct_charge(work,1);end+=1
                words=code.words[first:end]
                if len(words)>=3 and words[1]==':':
                    value=words[2:];start=first+2
                else:
                    value=words;start=first
                if (not (len(value)==1 and re.fullmatch(identifier,value[0])
                         or len(value)==3 and value[1]=='.' and all(re.fullmatch(identifier,w) for w in value[::2]))
                        or any(code.parents[i]!=holding for i in range(first,end+1))):
                    valid=False;break
                references.append((*code.position(code.starts[start]),*code.position(code.ends[end-1])))
            selected=[]
            for row in rows:
                opening=row['opening'];head=tuple(row.get('header',()))
                if opening is None or not function['opening'] < opening < row['end'] < function['end']:
                    continue
                kind=None
                if head in (('async',),('async','move')):
                    kind='async'
                elif len(head)>=3 and head[0]==head[2]=='|' and re.fullmatch(identifier,head[1]):
                    kind='block' if len(head)==3 else 'record'
                if kind is not None:
                    selected.append((row,kind))
            _construct_charge(work,len(selected)*(len(selected).bit_length()+1))
            selected.sort(key=lambda item:item[0]['opening'])
            if (len(selected)!=2 or not selected[0][0]['opening'] < selected[1][0]['opening'] < selected[1][0]['end'] < selected[0][0]['end']
                    or (selected[1][1]=='record' and selected[1][0]['opening']!=holding)
                    or (selected[1][1]=='block' and not selected[1][0]['opening']<holding<record['end']<selected[1][0]['end'])):
                valid=False;break
            records.append(record);phases.append(selected)
        if not valid or tuple(records[0]['header'])!=tuple(records[1]['header']):
            continue
        if call and not tail_record_import_context(left['context'][1],right['context'][1],
                (initializer_roots-{'super','crate','self'})|{implementation},work):
            continue
        def forward(line):
            return line+spans[1][0]-spans[0][0]+int(line>=spans[0][0]+position)
        if not call and not update:
            reference=references[0]
            references.append((forward(reference[0]),reference[1],forward(reference[2]),reference[3]))
        if indexes is None:
            indexes=indexes_factory()
        roles=[];forest_receipts=[]
        for side,(inventory,descriptor,index) in enumerate(zip(inventories,(left,right),indexes)):
            code=inventory[0];function=descriptor['row'];first,last=spans[side]
            available=index.inventories.get(name,())
            _construct_charge(work,sum(len(o['regions'])+1 for o in available))
            forest=[o for o in available if any(tuple(r[:2])<(last+1,1) and tuple(r[2:4])>(first,1) for r in o['regions'])]
            roots=groups[side][2];owned=set();copies=[]
            nominal={}; shapes={}
            for owner in forest:
                symbol=owner['name'];_construct_charge(work,len(symbol)+len(owner['regions'])+1)
                if (index.name_counts[symbol]!=1 or len(owner['filenames'])!=1
                        or index.files.get(owner['filenames'][0])!=name
                        or owner.get('branches',[]) or owner.get('mcdc_records',[])
                        or type(owner.get('count')) is not int or not 0<=owner['count']<COUNTER_LIMIT
                        or any(len(r)!=8 or r[5:]!=[0,0,0] for r in owner['regions'])):
                    valid=False;break
                shape=nominal_method_path(symbol)
                if shape is not None:
                    shapes[id(owner)]=shape
                    nominal.setdefault(shape.copy_identity,{})
                    depth=len(shape.callbacks)
                    if depth in nominal[shape.copy_identity]:
                        valid=False;break
                    nominal[shape.copy_identity][depth]=owner
            if not valid:break
            if update and unit_update and len(roots)!=1:
                valid=False;break
            for root in roots:
                plain=plain_rust_function_symbol(root['name']);nom=shapes.get(id(root))
                if call and nom is not None:
                    namespace=('crate',nom.instantiating_crate[0])
                    for module in module_path:
                        namespace=('type',namespace,(module,''))
                    _construct_charge(work,len(module_path)+1)
                    if (nom.kind!='M' or nom.impl_scope or nom.namespace!=namespace or nom.callbacks
                            or nom.method!=(descriptor['declaration'],'')
                            or nom.self_type!=('type',namespace,(implementation,''))):
                        valid=False;break
                    members=nominal[nom.copy_identity];role=nom.parent_scope,nom.method;identity=nom.copy_identity
                    if set(members)!={0}:
                        valid=False;break
                    ordinals=()
                elif update and plain is not None and plain.identifiers==(
                        'omg_lib',*module_path,'tests',descriptor['declaration']):
                    if unit_update:
                        members={0:root};role=('unit-test',plain.identity);identity=root['name'];ordinals=()
                    else:
                        if len(phases[side])!=1:
                            valid=False;break
                        candidates=[owner for owner in forest if direct_rust_callback_symbol(
                            owner['name'],root['name'],plain.modules)]
                        if len(candidates)!=1:
                            valid=False;break
                        members={0:root,1:candidates[0]};role=('result-test',plain.identity);identity=root['name']
                        ordinals=(members[1]['name'][len('_RNC'+root['name'][2:]):],)
                elif not call and plain is not None and plain.identifiers[-1]==descriptor['declaration']:
                    if tuple(kind for row,kind in phases[side])!=('block','block'):
                        valid=False;break
                    members={0:root};role=('free',plain.identity);identity=root['name']
                    for depth in (1,2):
                        _construct_charge(work,sum(len(o['name'])+1 for o in forest))
                        candidates=[o for o in forest if direct_rust_callback_symbol(o['name'],root['name'],plain.modules,depth)]
                        if len(candidates)!=1:
                            valid=False;break
                        members[depth]=candidates[0]
                    if not valid:break
                    ordinals=tuple(members[d]['name'][len('_R'+'NC'*d+root['name'][2:]):] for d in (1,2))
                elif not call and nom is not None and nom.kind=='Y' and not nom.callbacks and nom.method[0]==descriptor['declaration']:
                    trait_headers=[head for head in descriptor['context'][0] if 'trait' in head]
                    if (len(trait_headers)!=1 or nom.trait is None or nom.trait[-1][0]!=trait_headers[0][trait_headers[0].index('trait')+1]
                            or tuple(kind for row,kind in phases[side])!=('async','record')):
                        valid=False;break
                    members=nominal[nom.copy_identity];role=('Y',nom.parent_scope,nom.method,nom.instantiating_crate[0]);identity=nom.copy_identity
                    if set(members)!={0,1,2}:
                        valid=False;break
                    ordinals=tuple(shapes[id(members[d])].callbacks for d in (1,2))
                    if ordinals[1][:-1]!=ordinals[0]:
                        valid=False;break
                else:
                    valid=False;break
                if not valid:break
                geometry=[];states=[];extra=None
                for depth in range(len(members)):
                    owner=members[depth]
                    if id(owner) in owned:
                        valid=False;break
                    owned.add(id(owner));raw=owner['regions'];count=owner['count']
                    _construct_charge(work,10*len(raw)+(len(raw).bit_length()+1)*len(raw))
                    if depth==0:
                        declaration=function['first']
                        if update:
                            declaration+=_RESULT_TEST_SIGNATURE.index('fn')
                        elif call and parameters:
                            declaration+=len(_TEST_TAIL_RECORD_HEADER)-1
                        opening=code.position(code.starts[declaration]);closing=code.position(code.ends[function['end']])
                        ends=(code.position(code.ends[function['opening']-1]),code.position(code.starts[function['opening']]))
                        entries=[r for r in raw if tuple(r[:2])==opening and tuple(r[2:4]) in ends]
                    else:
                        phase,kind=phases[side][depth-1]
                        opening=code.position(code.starts[phase['opening']]);closing=code.position(code.ends[phase['end']])
                        if kind=='record':
                            opening=(added,match.start('value')+1) if side else tuple(references[0][:2])
                            entries=[r for r in raw if tuple(r[:2])==opening]
                        else:
                            entries=[r for r in raw if tuple(r[:4])==(*opening,opening[0],opening[1]+1)]
                    if (min(tuple(r[:2]) for r in raw)!=opening or max(tuple(r[2:4]) for r in raw)!=closing
                            or len(entries)!=1 or entries[0][4]!=count):
                        valid=False;break
                    if call:
                        record=records[side]
                        whole=(*code.position(code.starts[record['first']]),*code.position(code.ends[record['end']]))
                        ending=(*code.position(code.starts[function['end']]),*closing)
                        spans_seen={tuple(r[:4]) for r in raw}
                        required={tuple(entries[0][:4]),whole,ending}
                        if shorthand_entries[side] is not None:
                            required.add(shorthand_entries[side])
                        if (len(spans_seen)!=len(raw) or not required<=spans_seen
                                or spans_seen-required-tail_values[side] or any(r[4]!=count for r in raw)):
                            valid=False;break
                    projected=[]
                    for r in raw:
                        row=list(r)
                        if side:
                            if update and tuple(row[:4])==refinement:
                                if depth!=(0 if unit_update else 1) or extra is not None:
                                    valid=False;break
                                extra=row;continue
                            if not update and row[0]==row[2]==added:
                                if depth!=(0 if call else 2) or tuple(row[:4])!=addition or extra is not None:
                                    valid=False;break
                                extra=row;continue
                            if row[0]==added or row[2]==added:
                                valid=False;break
                            for at in (0,2):row[at]+=spans[0][0]-spans[1][0]-int(row[at]>added)
                        projected.append(row)
                    if not valid:break
                    projected.sort(key=lambda r:tuple(r[:4]+r[5:]))
                    geometry.append(tuple(tuple(r[:4]+r[5:]) for r in projected))
                    states.extend((int(count>0),*[int(r[4]>0) for r in projected]))
                if not valid:break
                if update:
                    record=records[side]
                    envelope=(*code.position(code.starts[record['first']+3]),*code.position(code.ends[record['end']]))
                    retained=[r for r in members[0 if unit_update else 1]['regions'] if tuple(r[:4])==envelope]
                    if len(retained)!=1 or retained[0][4]<=0:
                        valid=False;break
                    construction=retained[0][4]
                elif call:
                    construction=root['count']
                else:
                    reference_rows=[r for r in members[2]['regions'] if tuple(r[:4])==references[side]]
                    if len(reference_rows)!=1:
                        valid=False;break
                    construction=reference_rows[0][4]
                if not call and not update and phases[side][1][1]=='block':
                    record=records[side];start=code.position(code.starts[record['opening']]);end=code.position(code.ends[record['end']])
                    envelopes=[r for r in members[2]['regions'] if r[0]==start[0] and r[2]==end[0]
                               and tuple(r[:2])<=start and tuple(r[2:4])>=end]
                    if len(envelopes)!=1 or envelopes[0][4]!=construction:
                        valid=False;break
                elif not call and not update and construction!=members[2]['count']:
                    valid=False;break
                if side and (extra is None or extra[4]!=construction):
                    valid=False;break
                copies.append(dict(role=role,identity=identity,geometry=tuple(geometry),states=tuple(states),
                    ordinals=ordinals,names=[members[d]['name'] for d in range(len(members))],construction=construction,extra=extra))
            if not valid or owned!={id(o) for o in forest}:
                valid=False;break
            observer=_ObserverWork(work)
            observed=dict(_llvm22_rows(_llvm22_segments([r for o in forest for r in o['regions']],observer),observer))
            summary={line:counts[side][line] for line in range(first,last+1) if line in counts[side]}
            _construct_charge(work,last-first+1)
            if observed!=summary:
                valid=False;break
            roles.append(copies);forest_receipts.append([dict(names=r['names'],identity=repr(r['identity']),
                role=repr(r['role']),states=r['states'],construction=r['construction'],extra_field=r['extra']) for r in copies])
        if not valid or not counts[1].get(added,0):
            continue
        _construct_charge(work,sum(len(side) for side in roles))
        before_roles={r['role'] for r in roles[0]};after_roles={r['role'] for r in roles[1]}
        if before_roles!=after_roles:
            continue
        matches=[]
        for role in before_roles:
            _construct_charge(work,sum(len(side) for side in roles))
            previous=[r for r in roles[0] if r['role']==role];current=[r for r in roles[1] if r['role']==role]
            if (len(previous)!=len(current) or len({r['identity'] for r in previous})!=len(previous)
                    or len({r['identity'] for r in current})!=len(current)
                    or any(r['geometry']!=previous[0]['geometry'] or r['ordinals']!=previous[0]['ordinals'] for r in previous+current)):
                valid=False;break
            vectors=[tuple(r['states'] for r in rows) for rows in (previous,current)]
            identities=[tuple(r['identity'] for r in rows) for rows in (previous,current)]
            _construct_charge(work,(len(previous)*len(current)+1)*len(vectors[0][0]))
            matching=compiled_hit_state_matching(*vectors,identities)
            if matching is None:
                raise ValueError('Retained record field lost complete-copy coverage')
            matches.append(dict(role=repr(role),matching=matching))
        if not valid:continue
        mapped={line:forward(line) for line in range(spans[0][0],spans[0][1]+1) if line in counts[0]}
        _construct_charge(work,len(mapped))
        if any(target not in counts[1] for target in mapped.values()):continue
        if (len(set(mapped.values()))!=len(mapped)
                or any(line in pairs and pairs[line]!=target or target in target_owners and target_owners[target]!=line for line,target in mapped.items())):
            raise ValueError('Ambiguous retained record field correspondence')
        pairs.update(mapped);target_owners.update((target,line) for line,target in mapped.items());proved.add(spans[0])
        receipt = dict(kind='retained-record-update-forest' if update else 'retained-record-field-forest',
            file=name,base_range=list(spans[0]),head_range=list(spans[1]),
            pairs=[list(row) for row in sorted(mapped.items())],field=field,added_line=added,
            **({'record_type':update['type']} if update else {'initializer' if call else 'scalar_value':match['value']}),
            forests=forest_receipts,role_matching=matches,source_sha256=[hashlib.sha256(('\n'.join(body)+'\n').encode()).hexdigest() for body in bodies],
            claim='Complete retained-source forest only; added field counter kept separately; zero deletion credit')
        if call and parameters:
            receipt.update(typed_parameter_slots=parameters,first_shorthand_spans=shorthand_entries)
        receipts.append(receipt)
    return pairs,receipts,proved


def retained_inline_callback_source(descriptor, inventory, source, work, *, direct_loop=False):
    """Bind a public free function ending in one single-argument block closure."""
    code=inventory[0];fn=descriptor['row'];first,last=descriptor['group'][:2]
    expected=['pub'] if direct_loop else ['#','[','inline',']','pub']
    if (descriptor['attributes']!=expected or descriptor['context'][0]
            or not direct_loop and (first<2 or source[first-2]!='#[inline]')):
        return None
    declaration=fn['first']+len(expected)-1; start=fn['opening']+1
    _construct_charge(work,fn['end']-start+1)
    if (fn['end']-start<8 or code.words[declaration:declaration+2]!=['pub','fn']
            or code.position(code.starts[declaration])[0]!=first
            or code.words[start+1:start+6]!=['(','|',code.words[start+3],'|','{']
            or re.fullmatch(r'[A-Za-z_]\w*',code.words[start],re.ASCII) is None
            or re.fullmatch(r'[A-Za-z_]\w*',code.words[start+3],re.ASCII) is None
            or code.pairs.get(start+1)!=fn['end']-1 or code.pairs.get(start+5)!=fn['end']-2):
        return None
    def span(a,b):
        return (*code.position(code.starts[a]),*code.position(code.ends[b]))
    opener=start+5;closer=code.pairs[opener]
    body=range(opener+1,closer)
    pipes=[i for i in body if code.words[i]=='|' or not direct_loop and code.words[i]=='||']
    inner=None
    if pipes:
        if len(pipes)!=2 or pipes[1]!=pipes[0]+2:
            return None
        token=pipes[0];parent=code.parents[token]
        argument=code.words[token+1]
        if parent is None or token!=parent+1:
            return None
        if direct_loop:
            nested=code.words[token+3:token+9]
            if (code.words[parent-2:parent+1]!=['.','is_some_and','(']
                    or code.pairs.get(parent)!=token+9 or len(nested)!=6
                    or nested[1:4]!=['(',argument,','] or nested[5]!=')'
                    or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None
                           for word in (argument,nested[0],nested[4]))):
                return None
            inner=tuple(span(token+i,token+i) for i in (3,5,7))
        else:
            nested=code.words[token+3:token+12]
            if (code.words[parent-2:parent+1]!=['.','map','(']
                    or code.pairs.get(parent)!=token+12 or len(nested)!=9
                    or nested[0]!=argument or nested[1:2]!=['.'] or nested[3:6]!=['(',')','.']
                    or nested[7:]!=['(',')'] or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None
                    for word in (argument,nested[2],nested[6]))):
                return None
            inner=tuple(span(token+i,token+i) for i in (3,5,9))
    return (span(declaration,fn['opening']-1),span(start,start),span(fn['end'],fn['end']),
            span(opener,opener),span(closer,closer),inner)


def retained_loop_insertion(inventories, sides, spans, operations, work):
    """Observe a complete direct loop header followed by one nested statement insertion."""
    changes=[op for op in operations if op[0]!='equal']
    if len(changes)!=1 or changes[0][0]!='insert':
        return None
    _,begin,_,new_begin,new_end=changes[0]
    if not begin or begin!=new_begin:
        return None
    slots=[]
    for inventory, side, bounds in zip(inventories,sides,spans):
        code=inventory[0];number=bounds[0]+begin-1
        token=bisect.bisect_left(code.starts,code.offsets[number-1])
        end=bisect.bisect_left(code.starts,code.offsets[number])
        words=code.words[token:end]
        _construct_charge(work,sum(len(word)+1 for word in words))
        parent=code.parents[token]
        if (len(words)!=9 or words[0]!='for' or words[2]!='in' or words[4]!='.'
                or words[6:]!=['(',')','{'] or parent is None or parent<2
                or code.position(code.starts[parent])!=side[3][:2] or words[3]!=code.words[parent-2]
                or any(re.fullmatch(r'[A-Za-z_]\w*',words[i],re.ASCII) is None for i in (1,3,5))):
            return None
        slots.append(tuple(code.region(token+i,token+i) for i in (1,3,5)))
    first=spans[1][0]+new_begin; last=spans[1][0]+new_end-1
    low=bisect.bisect_left(code.starts,code.offsets[first-1]);high=bisect.bisect_left(code.starts,code.offsets[last])
    brace=end-1; excluded={'let','use','extern','impl','mod','enum','struct','const','static','type',
                         'trait','union','macro_rules','macro','fn','async','move','#','|','||'}
    _construct_charge(work,2*(high-low)+1)
    if (token+8!=brace or code.pairs.get(brace,0)<high or low>=high
            or any(code.words[i] in excluded or code.words[i]=='!' and code.words[i+1] in ('(','{','[')
                   or (i in code.pairs and not low<=code.pairs[i]<high)
                   or (code.parents[i]!=brace and (code.parents[i] is None or not low<=code.parents[i]<high))
                   for i in range(low,high))):
        return None
    return slots,list(range(first,last+1))


def retained_inline_callback_obligations(name,sources,counts,descriptors,inventories,selected,
                                         indexes,head_counts,work):
    """Match byte-identical rows and closed raw owners around independently checked edits."""
    direct_loop=descriptors[0]['attributes']==['pub']
    if (not direct_loop and head_counts is None) or descriptors[0]['context']!=descriptors[1]['context']:
        return None
    if any(d['signature']!=descriptors[0]['signature'] for d in descriptors):
        return None
    roots=[d['group'] for d in descriptors];spans=[r[:2] for r in roots]
    if direct_loop:
        if spans[1][1]-spans[1][0]<=spans[0][1]-spans[0][0]:
            return None
    elif not any(r.get('retained_statements') and r['base_range']==[spans[0][0]+1,spans[0][1]-1]
                 and r['head_range']==[spans[1][0]+1,spans[1][1]-1] for r in selected):
        return None
    sides=[retained_inline_callback_source(d,i,s,work,direct_loop=direct_loop)
           for d,i,s in zip(descriptors,inventories,sources)]
    if any(side is None for side in sides) or sides[0][-1] is None or (sides[1][-1] is not None)!=direct_loop:
        return None
    bodies=[s[first-1:last] for s,(first,last) in zip(sources,spans)]
    _construct_charge(work,len(bodies[0])*len(bodies[1])+3*sum(len(t)+1 for b in bodies for t in b))
    if any(not line.isascii() for body in bodies for line in body):
        return None
    a,b=spans[0][0],spans[1][0]
    operations=difflib.SequenceMatcher(None,*bodies,autojunk=False).get_opcodes()
    mapped={a+i:b+c+i-lo for tag,lo,hi,c,d in operations if tag=='equal' for i in range(lo,hi)}
    reverse={target:line for line,target in mapped.items()}
    nested_line=sides[0][-1][0][0]
    inserted=None
    if direct_loop:
        inserted=retained_loop_insertion(inventories,sides,spans,operations,work)
        if inserted is None:
            return None
    else:
        statements=inventories[0][3].get(nested_line,())
        _construct_charge(work,len(statements))
        code=inventories[0][0]
        retired=[row for row in statements if row['supported']
                 and all(code.position(code.starts[row[k]])[0]==nested_line for k in ('first','end'))]
        if (nested_line in mapped or len({r[0] for r in sides[0][-1]})!=1 or len(retired)!=1
                or head_counts.get(retired[0]['digest'],0)):
            return None
    lexical=[];forests=[]
    qualified=tuple(name.removeprefix('src/').removesuffix('.rs').split('/'))
    for side,(source,inventory,index,group,expected,da) in enumerate(zip(
            sources,inventories,indexes,roots,sides,counts)):
        code=inventory[0];first,last=spans[side]; translation=mapped if not side else reverse
        role_lines={line:line if not side else reverse[line] for line in translation}
        available=index.inventories.get(name,())
        _construct_charge(work,sum(len(o['regions'])+1 for o in available))
        touching=[o for o in available if any(r[0]<=last and r[2]>=first for r in o['regions'])]
        symbols={o['name']:o for o in touching}; owners=set();copies=[]
        _construct_charge(work,len(touching)+sum(len(o['name'])+1 for o in touching))
        if len(symbols)!=len(touching):
            return None
        for root in group[2]:
            symbol=root['name'];stem=symbol if direct_loop else symbol[:-3];path=plain_rust_function_symbol(stem)
            if (path is None or path.identifiers[1:]!=(*qualified,descriptors[side]['declaration'])
                    or not direct_loop and symbol!=stem+rust_same_crate_backref(path.modules,0)):
                return None
            parts=[root];depths=2 if direct_loop or not side else 1
            for depth in range(1,depths+1):
                child='_R'+'NC'*depth+stem[2:]+'0'*depth+rust_same_crate_backref(path.modules,depth)
                if child not in symbols or not direct_rust_callback_symbol(child,stem,path.modules,depth):
                    return None
                parts.append(symbols[child])
            geometry=[];states=[]
            for depth,owner in enumerate(parts):
                rows=owner['regions'];quantity=owner.get('count')
                _construct_charge(work,len(rows)*8+1)
                if (id(owner) in owners or symbols.get(owner['name']) is not owner
                        or index.name_counts[owner['name']]!=1 or owner.get('branches') or owner.get('mcdc_records')
                        or type(quantity) is not int or not 0<=quantity<COUNTER_LIMIT
                        or source_owner_span(owner,name,index.files,source) is None
                        or any(r[4]>=COUNTER_LIMIT for r in rows)):
                    return None
                owners.add(id(owner));present={tuple(r[:4]):r[4] for r in rows}
                need=expected[:3] if depth==0 else expected[3:5] if depth==1 else expected[-1]
                if len(present)!=len(rows) or any(present.get(span)!=quantity for span in need):
                    return None
                if depth!=1 and len(rows)!=len(need) or depth==1 and quantity!=root['count']:
                    return None
                if direct_loop and depth==1:
                    slots=inserted[0][side];line=slots[0][0]
                    if {tuple(r[:4]) for r in rows if r[0]<=line<=r[2]}!=set(slots):
                        return None
                    if side and not any(inserted[1][0]<=r[0]<=r[2]<=inserted[1][-1] for r in rows):
                        return None
                if depth==2 and not direct_loop:
                    continue
                limits=(need[0][:2],need[-1][2:])
                facts=[]
                for r in rows:
                    begin,end=r[0],r[2]
                    _construct_charge(work,end-begin+1)
                    if tuple(r[:2])<limits[0] or tuple(r[2:4])>limits[1]:
                        return None
                    aligned=[role_lines.get(line) for line in range(begin,end+1)]
                    if all(line is None for line in aligned):
                        continue
                    if aligned[0] is None or aligned!=list(range(aligned[0],aligned[0]+len(aligned))):
                        return None
                    facts.append(((depth,aligned[0],r[1],aligned[-1],r[3]),int(r[4]>0)))
                _construct_charge(work,len(facts)*(len(facts).bit_length()+1))
                facts.sort()
                geometry.extend(key for key,_ in facts);states.extend(hit for _,hit in facts)
            copies.append((path.identity,symbol,tuple(geometry),tuple(states),[o['name'] for o in parts]))
        if owners!={id(o) for o in touching}:
            return None
        observer=_ObserverWork(work)
        total=dict(_llvm22_rows(_llvm22_segments([r for o in touching for r in o['regions']],observer),observer))
        _construct_charge(work,last-first+1)
        if total!={n:da[n] for n in range(first,last+1) if n in da}:
            return None
        fn=descriptors[side]['row'];tokens=[];line_roles={}
        for token in range(fn['first'],fn['end']+1):
            number,col=code.position(code.starts[token])
            parent=code.parents[token]
            _construct_charge(work,len(code.words[token])+1)
            if number not in line_roles:
                text=source[number-1]
                _construct_charge(work,len(text)+1)
                line_roles[number]=(text,parent)
            if number not in role_lines:
                continue
            if parent is None:
                context=None
            else:
                pline,pcol=code.position(code.starts[parent])
                if pline not in role_lines:
                    return None
                context=(role_lines[pline],pcol)
            tokens.append((role_lines[number],col,code.words[token],context))
        _construct_charge(work,len(line_roles)+len(da.keys() & role_lines.keys()))
        occurrences=Counter(line_roles.values())
        if any(occurrences[line_roles[line]]!=1 for line in da.keys() & role_lines.keys() & line_roles.keys()):
            return None
        lexical.append(tokens);forests.append(copies)
    if lexical[0]!=lexical[1] or not forests[0] or not forests[1]:
        return None
    base,head=forests
    signatures={(o[0],o[2]) for o in base+head}
    if len(signatures)!=1:
        return None
    vectors=[[o[3] for o in members] for members in forests]
    if sorted(vectors[0])!=sorted(vectors[1]):
        return None
    _construct_charge(work,len(base)*len(head)*max(1,len(vectors[0][0])))
    fitting=compiled_hit_state_matching(*vectors,tuple([o[1] for o in side] for side in forests))
    if fitting is None:
        return None
    pairs={line:target for line,target in mapped.items() if line in counts[0] and target in counts[1]}
    leftovers=[line for line in range(spans[0][0],spans[0][1]+1) if line in counts[0] and line not in pairs]
    return pairs,dict(kind='retained-for-callback-regions' if direct_loop else 'retained-inline-callback-regions',
        file=name,base_range=list(spans[0]),head_range=list(spans[1]),pairs=[list(row) for row in sorted(pairs.items())],
        preserved_base_mapped=leftovers,
        **(dict(inserted_loop_lines=inserted[1],loop_slots=inserted[0]) if direct_loop
           else dict(removed_nested_callback_line=nested_line)),
        compiled_forests=[[o[4] for o in side] for side in forests],instance_matching=fitting,
        claim='Exact retained source only. Every unpaired base line remains in the ratios.')


def retained_context_entry(source, descriptor, inventory, line, work):
    """Bind a format-only direct error callback in its original loop statement."""
    code = inventory[0]
    function = descriptor['row']
    start = bisect.bisect_left(code.starts, code.offsets[line-1])
    end = bisect.bisect_left(code.starts, code.offsets[line])
    _construct_charge(work, end-start+1)
    if code.words[start:end] != ['.', 'with_context', '(', '||', '{']:
        return None
    closure = end-1
    closing = code.pairs[closure]
    terminator = code.position(code.starts[closing])[0]
    if (source[terminator-1].strip() != '})?;' or code.pairs[closure-2] != closing+1
            or code.words[closing+1:closing+4] != [')', '?', ';']):
        return None
    holder = code.parents[start]
    _construct_charge(work, len(inventory[1])+closing-closure)
    loops = [row for row in inventory[1] if row['opening']==holder and row['kind']=='for']
    if len(loops)!=1 or not loops[0]['supported'] or code.parents[holder]!=function['opening']:
        return None
    header=loops[0]['header']
    if (len(header)<4 or header[0]!='for' or header[2]!='in'
            or re.fullmatch(r'[A-Za-z_]\w*',header[1],re.ASCII) is None):
        return None
    binding=header[1]
    words = code.words[closure+1:closing]
    if len(words)==10 and words[-2]==',':
        words=words[:-2]+[')']
    if (len(words)!=9 or words[:3]!=['format','!','('] or not words[3].startswith('"')
            or words[4:7]!=[',',binding,'.'] or words[-1]!=')'
            or re.fullmatch(r'[A-Za-z_]\w*',words[7],re.ASCII) is None):
        return None
    receiver=bisect.bisect_left(code.starts,code.offsets[line-2])
    if code.parents[receiver]!=holder:
        return None
    parent=(code.region(start+1,start+1),code.region(closing+2,closing+2))
    child=(code.region(closure,closure), code.region(closure+1,closure+2), code.region(closing,closing))
    root=(code.region(function['first'],function['opening']-1),code.region(function['end'],function['end']))
    return terminator,binding,parent,child,root


def retained_context_assignment_obligations(name,sources,counts,descriptors,inventories,indexes_factory,work):
    """Bind retained source around a new result binding and its sole follow-up."""
    if (descriptors[0]['attributes']!=['pub','(','crate',')']
            or any(descriptors[0][key]!=descriptors[1][key] for key in ('signature','attributes','context'))):
        return None
    groups = [d['group'] for d in descriptors]
    old_first,old_last=groups[0][:2]
    new_first,new_last=groups[1][:2]
    if new_last-new_first!=old_last-old_first+1 or descriptors[0]['context'][0]:
        return None
    old,new=(source[group[0]-1:group[1]] for source,group in zip(sources,groups))
    _construct_charge(work,4*sum(len(line)+1 for line in old+new))
    if any(not line.isascii() for line in old+new):
        return None
    at = next((i for i,(a,b) in enumerate(zip(old,new)) if a!=b),len(old))
    if not 0<at<len(old)-2:
        return None
    receiver = re.fullmatch(r'([ \t]*)([A-Za-z_]\w*\.[A-Za-z_]\w*\([A-Za-z_0-9.,() ]*\))',old[at],re.ASCII)
    binding = re.fullmatch(r'([ \t]*)let (?P<name>[A-Za-z_]\w*) = (.+)',new[at],re.ASCII)
    if (receiver is None or binding is None or receiver.group(1)!=binding.group(1)
            or receiver.group(2)!=binding.group(3)):
        return None
    entries=[retained_context_entry(source,d,inventory,group[0]+at+1,work)
             for source,d,inventory,group in zip(sources,descriptors,inventories,groups)]
    if any(entry is None for entry in entries):
        return None
    index=entries[0][0]-old_first
    if (index!=entries[1][0]-new_first or entries[0][1]!=entries[1][1]
            or old[at+1:index+1]!=new[at+1:index+1] or old[index+1:]!=new[index+2:]):
        return None
    variable=binding['name'];loop_variable=entries[0][1];added=new_first+index+1
    statement=re.fullmatch(r'[ \t]*(?P<receiver>'+re.escape(variable)+r')\.[A-Za-z_]\w*\('
        +re.escape(loop_variable)+r'\.[A-Za-z_]\w*\.[A-Za-z_]\w*\(\)\)\?;',new[index+1],re.ASCII)
    if statement is None or not counts[1].get(added,0):
        return None
    old_line,new_line=old_first+at,new_first+at
    function=descriptors[0]['row']
    _construct_charge(work,function['end']-function['first']+1)
    if (old_line not in counts[0] or new_line not in counts[1]
            or variable in inventories[0][0].words[function['first']:function['end']+1]):
        return None
    shift=binding.start(3)-receiver.start(2)
    binding_slot=(new_line,binding.start('name')+1,new_line,binding.end('name')+1)
    follow_slot=(added,statement.start('receiver')+1,added,statement.end('receiver')+1)
    indexes=indexes_factory()
    signatures=[];vectors=[];identities=[];forest_names=[]
    qualified=tuple(name.removeprefix('src/').removesuffix('.rs').split('/'))
    for side,(source,group,index,entry,mapped) in enumerate(zip(sources,groups,indexes,entries,counts)):
        first,last,roots=group
        available=index.inventories.get(name,())
        _construct_charge(work,sum(len(o['regions'])+1 for o in available))
        forest=[o for o in available if any(r[0]<=last and r[2]>=first for r in o['regions'])]
        by_name={o['name']:o for o in forest}
        _construct_charge(work,len(forest)+sum(len(o['name'])+len(o['regions'])+1 for o in forest))
        if len(forest)!=2*len(roots) or len(by_name)!=len(forest):
            return None
        owned=set();states=[];ids=[];copy_names=[]
        for root in roots:
            symbol=root['name'];shape=plain_rust_function_symbol(symbol)
            if shape is None or shape.identifiers[1:]!=(*qualified,descriptors[side]['declaration']):
                return None
            child_symbol='_RNC'+symbol[2:]+'0'+rust_same_crate_backref(shape.modules,1)
            child=by_name.get(child_symbol)
            if child is None or not direct_rust_callback_symbol(child_symbol,symbol,shape.modules):
                return None
            projected=[];counts_by_role=[]
            for depth,owner in enumerate((root,child)):
                raw=owner['regions'];count=owner.get('count')
                _construct_charge(work,8*len(raw)+len(owner['name'])+1)
                if (id(owner) in owned or by_name.get(owner['name']) is not owner
                        or index.name_counts[owner['name']]!=1 or owner.get('branches') or owner.get('mcdc_records')
                        or type(count) is not int or not 0<=count<COUNTER_LIMIT
                        or source_owner_span(owner,name,index.files,source) is None or any(r[4]>=COUNTER_LIMIT for r in raw)):
                    return None
                owned.add(id(owner));region_counts={tuple(r[:4]):r[4] for r in raw}
                if len(region_counts)!=len(raw):
                    return None
                slots=entry[3] if depth else entry[4]
                if any(region_counts.get(slot)!=count for slot in slots) or depth and len(raw)!=len(slots):
                    return None
                if depth==0:
                    low,high=entry[3][0][:2],entry[3][-1][2:]
                    touching={tuple(r[:4]) for r in raw if tuple(r[:2])<high and low<tuple(r[2:4])}
                    # Only the parent dispatch before and the error propagation after the body.
                    if touching or any(slot not in region_counts for slot in entry[2]):
                        return None
                    if region_counts[entry[2][1]]!=child['count']:
                        return None
                    if side and (binding_slot not in region_counts
                            or region_counts.get(follow_slot)!=region_counts[binding_slot]
                            or region_counts[entry[2][0]]!=region_counts[binding_slot]+child['count']):
                        return None
                rows=[]
                for r in raw:
                    if not first<=r[0]<=r[2]<=last:
                        return None
                    if side and (r[0]<=added<=r[2] or tuple(r[:4])==binding_slot):
                        if depth or r[0]!=r[2]:
                            return None
                        continue
                    begin,col,end,endcol=r[:4]
                    if side:
                        if (begin==new_line)!=(end==new_line):
                            return None
                        if begin==new_line:
                            if col<binding.start(3)+1:
                                return None
                            col-=shift;endcol-=shift
                        begin-=int(begin>added);end-=int(end>added)
                    rows.append(((begin-first,col,end-first,endcol),int(r[4]>0)))
                _construct_charge(work,len(rows)*(len(rows).bit_length()+1))
                rows.sort()
                projected.append(tuple(r[0] for r in rows))
                counts_by_role.extend((int(count>0),*(r[1] for r in rows)))
            signatures.append((shape.identity,tuple(projected)))
            states.append(tuple(counts_by_role));ids.append(symbol);copy_names.append((symbol,child_symbol))
        if owned!={id(o) for o in forest}:
            return None
        observer=_ObserverWork(work)
        observed=dict(_llvm22_rows(_llvm22_segments([r for o in forest for r in o['regions']],observer),observer))
        _construct_charge(work,last-first+1)
        if observed!={n:mapped[n] for n in range(first,last+1) if n in mapped}:
            return None
        vectors.append(states);identities.append(ids);forest_names.append(copy_names)
    if len(set(signatures))!=1 or sorted(vectors[0])!=sorted(vectors[1]):
        return None
    _construct_charge(work,len(vectors[0])*len(vectors[1])*len(vectors[0][0]))
    matching=compiled_hit_state_matching(*vectors,identities)
    if matching is None:
        return None
    pairs={line:line+new_first-old_first+int(line>entries[0][0])
           for line in range(old_first,old_last+1) if line in counts[0] and line!=old_line}
    if any(target not in counts[1] for target in pairs.values()):
        return None
    return pairs,dict(kind='retained-context-assignment',file=name,base_range=[old_first,old_last],
        head_range=[new_first,new_last],pairs=[list(pair) for pair in sorted(pairs.items())],
        preserved_base_mapped=[old_line],added_head_lines=[new_line,added],compiled_forests=forest_names,
        parent_slots=[entry[2] for entry in entries],child_slots=[entry[3] for entry in entries],
        instance_matching=matching,claim='Unchanged dispatch and callback only. Changed work remains in coverage.')


def callback_island_import_context(name, contexts, words, blobs, work):
    """Allow one additional imported enum, never a changed method-providing trait."""
    if contexts[0] == contexts[1]:
        return True
    if contexts[0][0] != contexts[1][0] or blobs is None:
        return False
    old, new = (Counter(context[1]) for context in contexts)
    removed, added = list((old-new).elements()), list((new-old).elements())
    if len(removed) != 1 or len(added) != 1:
        return False
    parsed = []
    for clause in (removed[0], added[0]):
        _construct_charge(work,len(clause)+1)
        if (len(clause)<8 or clause[0]!='use' or clause[-2:]!=('}',';')
                or clause.count('{')!=1 or clause.count('}')!=1):
            return False
        opening=clause.index('{'); prefix=clause[1:opening]
        if (not prefix or prefix[-1]!='::' or len(prefix)%2!=0
                or any(word!='::' for word in prefix[1::2])
                or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None for word in prefix[::2])):
            return False
        fields=clause[opening+1:-2]
        fields=fields[:-1] if fields[-1:]==(',',) else fields
        if (not fields or len(fields)%2!=1 or any(word!=',' for word in fields[1::2])
                or any(re.fullmatch(r'[A-Za-z_]\w*',word,re.ASCII) is None for word in fields[::2])):
            return False
        parsed.append((prefix,list(fields[::2])))
    if parsed[0][0]!=parsed[1][0]:
        return False
    before,after=(row[1] for row in parsed)
    if len(after)!=len(before)+1 or len(set(after))!=len(after):
        return False
    extra=list((Counter(after)-Counter(before)).elements())
    if len(extra)!=1 or [word for word in after if word!=extra[0]]!=before or extra[0] in words:
        return False
    path=list(parsed[0][0][::2]); modules=name.removeprefix('src/').removesuffix('.rs').split('/')
    if path[0]=='crate':
        modules=[];path=path[1:]
    elif path[0]=='self':
        path=path[1:]
    elif path[0]!='super':
        return False
    while path[:1]==['super']:
        if not modules:return False
        modules.pop();path=path[1:]
    if not path:return False
    target='src/'+'/'.join(modules+path)+'.rs'; blob=blobs[1].get(target)
    if blob is None or len(blob)>2**20:return False
    _construct_charge(work,len(blob)+1)
    try: code=_boolean_source(blob.decode('utf-8').splitlines())
    except UnicodeDecodeError:return False
    if code is None:return False
    found=[]
    for at,word in enumerate(code.words):
        _construct_charge(work,1)
        if word!=extra[0] or code.parents[at] is not None:continue
        if at>0 and code.words[at-1] in ('enum','trait','struct','type','union','mod','fn'):
            found.append((code.words[at-1],at))
    return len(found)==1 and found[0][0]=='enum'


def retained_callback_island_obligations(name, sources, counts, descriptors, inventories,
                                        replacements, work, indexes_factory, expansions, blobs=None):
    """Bind an unchanged iterator callback and every overlapping compiled child."""
    if indexes_factory is None or expansions!=([],[]):
        return {},[]
    candidate_sets=[]
    for side,(inventory,functions) in enumerate(zip(inventories,descriptors)):
        code,rows=inventory[:2]; candidates={}
        _construct_charge(work,len(rows)+len(functions))
        by_opening={r['opening']:r for r in rows if r['opening'] is not None}
        selected=[]
        for descriptor in functions.values():
            group=descriptor['group'];first,last=group[:2]
            _construct_charge(work,len(replacements))
            if any(r.get('retained_statements') and max(first,r['base_range' if side==0 else 'head_range'][0])
                   <=min(last,r['base_range' if side==0 else 'head_range'][1]) for r in replacements.values()):
                selected.append(descriptor)
        if not selected:
            candidate_sets.append(candidates);continue
        for row in rows:
            header=row.get('header',());opening=row['opening']
            if (row['kind']!='expression' or not row['supported'] or opening is None
                    or len(header)<3 or header[0]!='|' or header[2]!='|'
                    or re.fullmatch(r'[A-Za-z_]\w*',header[1],re.ASCII) is None):
                continue
            parent=code.parents[row['first']]
            if (parent is None or parent<2 or code.words[parent-2:parent]!=['.','map']
                    or code.words[parent]!='(' or code.pairs[parent]!=row['end']+1):
                continue
            parents=[d for d in selected if d['row']['opening']<row['first']<row['end']<d['row']['end']]
            _construct_charge(work,len(selected)+row['end']-row['first']+1)
            if len(parents)!=1:continue
            descriptor=parents[0];scope=code.parents[parent]
            if scope is None:continue
            # Bind the receiver/record-field slot in its direct lexical scope.
            start=scope+1
            for at in range(scope+1,parent):
                _construct_charge(work,1)
                if code.parents[at]==scope and code.words[at] in (';',','):
                    start=at+1
            prefix=list(code.words[start:parent-2]);filters=[];normalized=[];at=0
            while at<len(prefix):
                _construct_charge(work,1)
                if prefix[at:at+3]==['.','filter','(']:
                    actual=start+at;finish=code.pairs.get(actual+2)
                    if finish is None or finish>=parent-2:break
                    callback=next((r for r in rows if r['first']==actual+3 and r.get('header')==('|',header[1],'|')),None)
                    _construct_charge(work,len(rows))
                    if callback is None or callback['end']+1!=finish:break
                    filters.append(callback);at=finish-start+1
                else:
                    normalized.append(prefix[at]);at+=1
            if at!=len(prefix) or len(filters)>1 or not normalized:continue
            ancestors=[];valid=True
            for ancestor in [scope]+_construct_ancestors(code,scope,work):
                if ancestor==descriptor['row']['opening']:break
                if code.words[ancestor]!='{':continue
                holding=by_opening.get(ancestor)
                if holding is None or not holding['supported']:
                    valid=False;break
                ancestors.append(tuple(holding.get('header',())))
            if not valid:continue
            first,last=code.position(code.starts[row['first']])[0],code.position(code.ends[row['end']])[0]
            body=tuple(sources[side][first-1:last]);_construct_charge(work,sum(len(line)+1 for line in body))
            if any(not line.isascii() for line in body):continue
            key=(descriptor['declaration'],descriptor['signature'],tuple(descriptor['attributes']),tuple(ancestors),
                 tuple(normalized),tuple(header),body)
            candidates.setdefault(key,[]).append((descriptor,row,filters))
        candidate_sets.append(candidates)
    common=candidate_sets[0].keys()&candidate_sets[1].keys()
    pairs={};targets={};receipts=[];indexes=None
    for key in common:
        _construct_charge(work,len(key[-1])+1)
        choices=[candidates[key] for candidates in candidate_sets]
        if any(len(rows)!=1 for rows in choices):continue
        selected=[rows[0] for rows in choices]
        if selected[0][2] or len(selected[1][2])>1:continue
        if not callback_island_import_context(name,[r[0]['context'] for r in selected],key[4]+key[5]+tuple(
                word for word in inventories[0][0].words[selected[0][1]['first']:selected[0][1]['end']+1]),blobs,work):continue
        if indexes is None:indexes=indexes_factory()
        sides=[];valid=True
        for side,((descriptor,callback,filters),inventory,index) in enumerate(zip(selected,inventories,indexes)):
            code=inventory[0];opening,closing=code.region(callback['opening'],callback['end'])[:2],code.region(callback['opening'],callback['end'])[2:]
            available=index.inventories.get(name,());_construct_charge(work,sum(len(o['regions'])+1 for o in available))
            forest=[o for o in available if any(tuple(r[:2])<closing and opening<tuple(r[2:4]) for r in o['regions'])]
            # Expression children must occupy unique complete closure argument slots.
            slots=[];at=callback['opening']+1
            while at<callback['end']:
                _construct_charge(work,1)
                nullary=code.words[at]=='||';unary=(code.words[at]=='|' and at+2<callback['end'] and code.words[at+2]=='|')
                if not (nullary or unary):at+=1;continue
                call=code.parents[at];body=at+(1 if nullary else 3)
                if (call is None or code.words[call]!='(' or body>=code.pairs[call]
                        or code.words[body] in ('{','async','move')):
                    valid=False;break
                end=code.pairs[call]-1
                slots.append((code.region(body,end),
                    (*code.position(code.starts[body]),*code.position(code.ends[body+int(code.words[body+1]=='!')]))))
                at=end+1
            if not valid or len(slots)>8:valid=False;break
            roles=[];owned=set();filter_owned=set();filter_evidence=[]
            filter_touching=[]
            if filters:
                low,high=code.region(filters[0]['opening'],filters[0]['end'])[:2],code.region(filters[0]['opening'],filters[0]['end'])[2:]
                _construct_charge(work,sum(len(owner['regions'])+1 for owner in available))
                filter_touching=[owner for owner in available if any(
                    tuple(region[:2])<high and low<tuple(region[2:4]) for region in owner['regions'])]
            for root in descriptor['group'][2]:
                shape=plain_rust_function_symbol(root['name'])
                if (shape is None or index.name_counts[root['name']]!=1 or len(root['filenames'])!=1
                        or index.files.get(root['filenames'][0])!=name
                        or type(root.get('count')) is not int or not 0<=root['count']<COUNTER_LIMIT
                        or shape.identifiers[-1]!=descriptor['declaration']
                        or name.startswith('src/') and shape.identifiers[:-1] !=
                            ('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'))):
                    valid=False;break
                related={}
                for owner in forest:
                    symbol=owner['name'];_construct_charge(work,len(symbol)+len(owner['regions'])+1)
                    depths=[depth for depth in (1,2) if direct_rust_callback_symbol(symbol,root['name'],shape.modules,depth)]
                    if len(depths)!=1:continue
                    depth=depths[0];suffix=symbol[len('_R'+'NC'*depth+root['name'][2:]):]
                    ordinals=tuple(re.findall(r'(s[0-9A-Za-z]{0,32}_)?0',suffix)[:depth])
                    if len(ordinals)!=depth or ordinals in related:
                        valid=False;break
                    related[ordinals]=owner
                if not valid:break
                direct=[(path,o) for path,o in related.items() if len(path)==1]
                if len(direct)!=1:valid=False;break
                outer_path,mapper=direct[0];members={():mapper}
                if type(mapper.get('count')) is not int or not 0<=mapper['count']<COUNTER_LIMIT or (
                        mapper['count']>0 and root['count']==0):valid=False;break
                if filters:
                    _construct_charge(work,len(filter_touching)+sum(len(o['name']) for o in filter_touching))
                    owned_filters=[o for o in filter_touching if direct_rust_callback_symbol(o['name'],root['name'],shape.modules)]
                    if len(owned_filters)!=1:
                        valid=False;break
                    filter_owner=owned_filters[0];raw=filter_owner['regions'];entry=filter_owner.get('count')
                    _construct_charge(work,len(raw))
                    if (filter_owner is mapper or index.name_counts[filter_owner['name']]!=1
                            or filter_owner['filenames']!=root['filenames'] or filter_owner.get('branches') or filter_owner.get('mcdc_records')
                            or type(entry) is not int or not 0<=mapper['count']<=entry<COUNTER_LIMIT
                            or any(len(r)!=8 or r[5:]!=[0,0,0] or r[4]!=entry or not low<=tuple(r[:2])<tuple(r[2:4])<=high for r in raw)
                            or [r[4] for r in raw if tuple(r[:4])==(*low,low[0],low[1]+1)]!=[entry]
                            or [r[4] for r in raw if tuple(r[:4])==(*high[:1],high[1]-1,*high)]!=[entry]):
                        valid=False;break
                    same_root=[o for o in filter_touching if any(direct_rust_callback_symbol(o['name'],root['name'],shape.modules,d) for d in (1,2))]
                    if same_root!=owned_filters:
                        valid=False;break
                    filter_owned.add(id(filter_owner));filter_evidence.append(dict(name=filter_owner['name'],count=entry))
                for path,owner in related.items():
                    if len(path)==1:continue
                    if path[:1]!=outer_path:valid=False;break
                    matches=[number for number,(bounds,_) in enumerate(slots)
                        if all(tuple(bounds[:2])<=tuple(r[:2])<tuple(r[2:4])<=tuple(bounds[2:]) for r in owner['regions'])]
                    if len(matches)!=1 or matches[0] in members:valid=False;break
                    members[matches[0]]=owner
                if not valid or len(members)!=len(slots)+1:valid=False;break
                geometry=[];states=[int(root['count']>0)];names=[];nested_ordinals=[]
                for role in [()]+list(range(len(slots))):
                    owner=members[role];symbol=owner['name'];raw=owner['regions'];entry=owner['count']
                    if (id(owner) in owned or index.name_counts[symbol]!=1 or len(owner['filenames'])!=1
                            or index.files.get(owner['filenames'][0])!=name or owner.get('branches') or owner.get('mcdc_records')
                            or type(entry) is not int or not 0<=entry<COUNTER_LIMIT
                            or any(len(r)!=8 or r[5:]!=[0,0,0] or not opening<=tuple(r[:2])<tuple(r[2:4])<=closing for r in raw)):
                        valid=False;break
                    if role==():
                        terminal=(*closing[:1],closing[1]-1,*closing)
                        if [r[4] for r in raw if tuple(r[:4])==terminal]!=[entry]:valid=False;break
                        if len(callback['header'])==3:
                            marker=(*opening,opening[0],opening[1]+1)
                            if [r[4] for r in raw if tuple(r[:4])==marker]!=[entry]:valid=False;break
                        elif any(r[4]!=entry for r in raw):valid=False;break
                    else:
                        suffix=symbol[len('_RNCNC'+root['name'][2:]):]
                        nested_ordinals.append(tuple(re.findall(r'(s[0-9A-Za-z]{0,32}_)?0',suffix)[:2])[1])
                        bounds,marker=slots[role]
                        if (min(tuple(r[:2]) for r in raw)!=tuple(bounds[:2])
                                or [r[4] for r in raw if tuple(r[:4])==marker]!=[entry]):valid=False;break
                    owned.add(id(owner));names.append(symbol)
                    ordered=sorted(raw,key=lambda r:tuple(r[:4]+r[5:]));_construct_charge(work,len(raw)*(len(raw).bit_length()+1))
                    geometry.append(tuple((r[0]-opening[0],r[1],r[2]-opening[0],r[3],*r[5:]) for r in ordered))
                    states.extend([int(entry>0),*[int(r[4]>0) for r in ordered]])
                if not valid:break
                roles.append(dict(role=shape.identity,identity=root['name'],geometry=tuple(geometry),states=tuple(states),
                    nested_ordinals=tuple(nested_ordinals),names=names))
            if (not valid or owned!={id(o) for o in forest}
                    or filters and filter_owned!={id(o) for o in filter_touching}):valid=False;break
            observer=_ObserverWork(work);observed=dict(_llvm22_rows(_llvm22_segments([r for o in forest for r in o['regions']],observer),observer))
            if not observed:valid=False;break
            first,last=min(observed),max(observed);_construct_charge(work,last-first+1)
            measured={line:counts[side][line] for line in range(first,last+1) if line in counts[side]}
            if observed!=measured:valid=False;break
            sides.append((roles,observed,opening,filter_evidence))
        if not valid:continue
        roles={r['role'] for r in sides[0][0]}
        if roles!={r['role'] for r in sides[1][0]}:continue
        matches=[]
        for role in roles:
            vectors=[[r for r in side[0] if r['role']==role] for side in sides]
            if len(vectors[0])!=len(vectors[1]) or any(r['geometry']!=vectors[0][0]['geometry']
                    or r['nested_ordinals']!=vectors[0][0]['nested_ordinals'] for rows in vectors for r in rows):
                valid=False;break
            _construct_charge(work,(len(vectors[0])*len(vectors[1])+1)*len(vectors[0][0]['states']))
            matching=compiled_hit_state_matching(*[tuple(r['states'] for r in rows) for rows in vectors],
                [tuple(r['identity'] for r in rows) for rows in vectors])
            if matching is None:raise ValueError('Retained callback island lost complete-copy coverage')
            matches.append(dict(role=repr(role),matching=matching))
        if not valid:continue
        offset=sides[1][2][0]-sides[0][2][0]
        mapped={line:line+offset for line in sides[0][1]}
        if set(mapped.values())!=set(sides[1][1]):continue
        if any(line in pairs and pairs[line]!=target or target in targets and targets[target]!=line for line,target in mapped.items()):
            raise ValueError('Ambiguous callback island correspondence')
        pairs.update(mapped);targets.update((target,line) for line,target in mapped.items())
        receipts.append(dict(kind='closed-retained-callback-island',file=name,
            base_range=list(selected[0][0]['group'][:2]),head_range=list(selected[1][0]['group'][:2]),pairs=[list(row) for row in sorted(mapped.items())],
            forest_names=[[r['names'] for r in side[0]] for side in sides],added_filter=sides[1][3],role_matching=matches,
            source_sha256=hashlib.sha256(('\n'.join(key[-1])+'\n').encode()).hexdigest(),
            claim='Only unchanged callback lines; complete overlapping forest and cold roles; zero deletion credit'))
    return pairs,receipts


def projected_iterator_source(left, right, inventories, sources, work):
    """Bind one wildcard tuple input to an exact terminal borrowed-item projection."""
    codes=[i[0] for i in inventories];functions=[d['row'] for d in (left,right)]
    if (left['attributes'] or right['attributes'] or left['signature']!=right['signature']
            or left['context'][0] or right['context'][0]):return None
    _construct_charge(work,sum(r['end']-r['first']+1 for r in functions))
    tokens=[c.words[r['first']:r['end']+1] for c,r in zip(codes,functions)]
    if len(tokens[1])!=len(tokens[0])+4:return None
    at=next((n for n,(a,b) in enumerate(zip(*tokens)) if a!=b),None)
    if at is None or at<4:return None
    variable=tokens[0][at]
    if (re.fullmatch(r'[A-Za-z_]\w*',variable,re.ASCII) is None
            or tokens[0][at-4:at]!=['.','filter_map','(','|']
            or tokens[0][at+1:at+3]!=['|','{']
            or tokens[1][at:at+5]!=['(','_',',',variable,')']
            or tokens[0]!=tokens[1][:at]+[variable]+tokens[1][at+5:]):return None
    # The callback is the first chain on a single direct free-function call.
    body_start=functions[0]['opening']+1
    prefix=codes[0].words[body_start:functions[0]['first']+at-4]
    if (len(prefix)!=13 or prefix[:2]!=['let','mut'] or prefix[3:9]!=[':','Vec','<','_','>','=']
            or prefix[10]!='(' or prefix[12]!=')'
            or any(re.fullmatch(r'[A-Za-z_]\w*',prefix[n],re.ASCII) is None for n in (2,9,11))):return None
    producer=prefix[9]
    if tokens[0].count(producer)!=1:return None
    contexts=[d['context'][1] for d in (left,right)]
    _construct_charge(work,sum(len(clause)+1 for context in contexts for clause in context))
    if contexts[0]!=contexts[1]:
        old,new=map(Counter,contexts);added=list((new-old).elements())
        if (old-new or added!=[('use','std','::','collections','::','BTreeMap',';')]
                or 'BTreeMap' in tokens[0]):return None
    producers=[]
    for inventory,function in zip(inventories,functions):
        code,rows=inventory[:2];_construct_charge(work,len(rows))
        found=[r for r in rows if r['kind']=='fn' and r['header'][:2]==('fn',producer)
            and code.parents[r['first']] is None]
        if len(found)!=1:return None
        row=found[0];opening=row['first']+2;closing=code.pairs.get(opening)
        if (closing is None or code.words[opening]!='(' or row['opening'] is None
                or code.parents[function['first']] is not None):return None
        args=code.words[opening+1:closing];args=args[:-1] if args[-1:]==[','] else args
        returned=code.words[closing+1:row['opening']]
        body=code.words[row['opening']+1:row['end']]
        _construct_charge(work,len(args)+len(returned)+len(body)+1)
        producers.append((row,tuple(args),returned,body))
    old,new=producers
    if old[1]!=new[1] or old[2][:5]!=['->','impl','Iterator','<','Item'] or old[2][5:6]!=['='] or old[2][-1:]!=['>']:return None
    item=old[2][6:-1]
    if (not item or item[0]!='&' or len(item)%2!=0
            or any(t!='::' for t in item[2::2])
            or any(re.fullmatch(r'[A-Za-z_]\w*',t,re.ASCII) is None for t in item[1::2])
            or new[2]!=old[2][:6]+['(']+item+[',']+item+[')', '>']):return None
    added=[n for n in range(len(new[3])) if new[3][n:n+7]==['.','map','(','move','|',variable,'|']]
    if len(added)!=1:return None
    offset=added[0];term=new[3][offset:offset+13]
    if (len(term)!=13 or term[:7]!=['.','map','(','move','|',variable,'|']
            or term[7]!='(' or term[9:13]!=[',',variable,')',')']
            or re.fullmatch(r'[A-Za-z_]\w*',term[8],re.ASCII) is None
            or old[3]!=new[3][:offset]+new[3][offset+13:]):return None
    if (item!=['&','serde_json','::','Value'] or len(old[1])!=6
            or old[1][1:]!=(':','&','serde_json','::','Value')):return None
    keys=[old[3][n+3] for n in range(len(old[3])-4) if old[3][n:n+3]==['.','get','('] and old[3][n+4]==')']
    if len(keys)!=3 or any(re.fullmatch(r'"[A-Za-z_]\w*"',key,re.ASCII) is None for key in keys):return None
    argument=old[1][0];capture=term[8]
    template=(f'{argument}.get({keys[0]}).and_then(serde_json::Value::as_array).into_iter().flatten().flat_map(|{capture}| {{ '
        f'{capture}.get({keys[1]}).into_iter().chain({capture}.get({keys[2]}).and_then(serde_json::Value::as_array).into_iter().flatten(),) }})')
    _construct_charge(work,len(template)+1);expected=_boolean_source([template])
    if expected is None or expected.words!=old[3]:return None
    code=codes[1];row=new[0];actual=row['opening']+1+offset;scope=code.parents[actual]
    if (scope is None or code.words[scope]!='{' or code.words[actual+13:code.pairs[scope]]
            or code.words[scope-3:scope]!=['|',term[8],'|']
            or code.words[scope-6:scope-3]!=['.','flat_map','(']):return None
    starts=[c.position(c.starts[r['first']])[0] for c,r in zip(codes,functions)]
    ends=[c.position(c.ends[r['end']])[0] for c,r in zip(codes,functions)]
    bodies=[s[a-1:b] for s,a,b in zip(sources,starts,ends)]
    if len(bodies[0])!=len(bodies[1]) or any(not line.isascii() for body in bodies for line in body):return None
    changes=[n for n,(a,b) in enumerate(zip(*bodies)) if a!=b]
    if len(changes)!=1:return None
    line=changes[0];oldline,newline=bodies[0][line],bodies[1][line]
    needle='|'+variable+'|';positions=[m.start() for m in re.finditer(re.escape(needle),oldline)]
    if len(positions)!=1:return None
    first=positions[0]+1
    if newline!=oldline[:first]+'(_, '+variable+')'+oldline[first+len(variable):]:return None
    return starts,ends,line,first+1,len(variable),producer


def retained_projected_iterator_obligations(name,sources,counts,descriptors,inventories,
                                            replacements,work,indexes_factory,expansions):
    """Preserve every raw copy across a proven borrowed-item tuple projection."""
    if indexes_factory is None or expansions!=([],[]):return {},[],set()
    candidates=[]
    _construct_charge(work,len(descriptors[0]))
    for prefix,left in descriptors[0].items():
        right=descriptors[1].get(prefix)
        if (right is None or left['attributes'] or left['context'][0]
                or left['signature'][-4:-2]!=('Vec','<')
                or right['group'][1]-right['group'][0]!=left['group'][1]-left['group'][0]):continue
        _construct_charge(work,len(replacements))
        related=[r for r in replacements.values() if r.get('retained_statements') and max(r['base_range'][0],left['group'][0])<=min(r['base_range'][1],left['group'][1])]
        if any(not (left['group'][0]<=r['base_range'][0]<=r['base_line']<=r['base_range'][1]<=left['group'][1]
                and right['group'][0]<=r['head_range'][0]<=r['head_line']<=r['head_range'][1]<=right['group'][1]) for r in related):continue
        proof=projected_iterator_source(left,right,inventories,sources,work)
        if proof is not None:candidates.append((left,right,proof))
    if not candidates:return {},[],set()
    indexes=indexes_factory();pairs={};receipts=[];proved=set();targets={}
    for left,right,(starts,ends,edit,binding,width,producer) in candidates:
        sides=[];valid=True
        for side,(descriptor,index,source,da) in enumerate(zip((left,right),indexes,sources,counts)):
            low=(starts[side],1);high=(ends[side],len(source[ends[side]-1])+1)
            available=index.inventories.get(name,());_construct_charge(work,sum(len(o['regions'])+1 for o in available))
            touching=[o for o in available if any(tuple(r[:2])<high and low<tuple(r[2:4]) for r in o['regions'])]
            symbols={o['name']:o for o in touching};owned=set();copies=[]
            if len(symbols)!=len(touching):valid=False;break
            def point(line,column):
                relative=line-starts[side]
                if side and relative==edit:
                    if column>=binding+width+5:column-=5
                    elif binding+4<=column<=binding+4+width:column-=4
                    elif column!=binding and column>binding:return None
                return relative,column
            for root in descriptor['group'][2]:
                shape=plain_rust_function_symbol(root['name'])
                if (shape is None or shape.identifiers[-1]!=descriptor['declaration']
                        or name.startswith('src/') and shape.identifiers[:-1]!=(
                            'omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'))):valid=False;break
                members={():root}
                for owner in touching:
                    _construct_charge(work,len(owner['name'])*8+1)
                    depths=[d for d in range(1,9) if direct_rust_callback_symbol(owner['name'],root['name'],shape.modules,d)]
                    if not depths:continue
                    if len(depths)!=1:valid=False;break
                    depth=depths[0];suffix=owner['name'][len('_R'+'NC'*depth+root['name'][2:]):]
                    path=tuple(re.findall(r'(s[0-9A-Za-z]{0,32}_)?0',suffix)[:depth])
                    if len(path)!=depth or path in members:valid=False;break
                    members[path]=owner
                if not valid or any(role[:-1] not in members for role in members if len(role)>1):valid=False;break
                geometry=[];states=[];names=[]
                for role,owner in sorted(members.items()):
                    raw=owner['regions'];quantity=owner.get('count');symbol=owner['name']
                    _construct_charge(work,len(raw)*10+1)
                    if (id(owner) in owned or index.name_counts[symbol]!=1 or len(owner['filenames'])!=1
                            or index.files.get(owner['filenames'][0])!=name or owner.get('branches') or owner.get('mcdc_records')
                            or type(quantity) is not int or not 0<=quantity<COUNTER_LIMIT
                            or any(len(r)!=8 or r[5:]!=[0,0,0] or not low<=tuple(r[:2])<tuple(r[2:4])<=high
                                or not 0<=r[4]<COUNTER_LIMIT for r in raw)):valid=False;break
                    if role==():
                        code=inventories[side][0];fn=descriptor['row'];entry=code.region(fn['first'],fn['opening']-1);closing=code.region(fn['end'],fn['end'])
                        if any([r[4] for r in raw if tuple(r[:4])==slot]!=[quantity] for slot in (entry,closing)):valid=False;break
                    facts=[]
                    for r in raw:
                        begin,end=point(*r[:2]),point(*r[2:4])
                        if begin is None or end is None or begin>=end:valid=False;break
                        facts.append(((*begin,*end,*r[5:]),int(r[4]>0)))
                    if not valid:break
                    _construct_charge(work,len(facts)*(len(facts).bit_length()+1));facts.sort()
                    geometry.append((role,tuple(k for k,v in facts)));states.extend([int(quantity>0),*[v for k,v in facts]])
                    owned.add(id(owner));names.append(symbol)
                if not valid:break
                copies.append((shape.identity,root['name'],tuple(geometry),tuple(states),names))
            if not valid or not copies or owned!={id(o) for o in touching}:valid=False;break
            observer=_ObserverWork(work);observed=dict(_llvm22_rows(_llvm22_segments([r for o in touching for r in o['regions']],observer),observer))
            _construct_charge(work,ends[side]-starts[side]+1)
            if observed!={n:da[n] for n in range(starts[side],ends[side]+1) if n in da}:valid=False;break
            sides.append((copies,observed))
        if not valid:continue
        copies=[s[0] for s in sides];roles={r[0] for group in copies for r in group}
        if len(roles)!=1 or len(copies[0])!=len(copies[1]) or any(r[2]!=copies[0][0][2] for group in copies for r in group):continue
        vectors=[[r[3] for r in group] for group in copies]
        if sorted(vectors[0])!=sorted(vectors[1]):continue
        _construct_charge(work,(len(copies[0])*len(copies[1])+1)*len(vectors[0][0]))
        matching=compiled_hit_state_matching(*vectors,[tuple(r[1] for r in group) for group in copies])
        if matching is None:continue
        offset=starts[1]-starts[0];mapped={n:n+offset for n in sides[0][1]}
        if set(mapped.values())!=set(sides[1][1]):continue
        if any(n in pairs and pairs[n]!=t or t in targets and targets[t]!=n for n,t in mapped.items()):raise ValueError('Ambiguous projected iterator correspondence')
        pairs.update(mapped);targets.update((t,n) for n,t in mapped.items());proved.add(left['group'][:2])
        receipts.append(dict(kind='projected-iterator-input',file=name,base_range=list(left['group'][:2]),head_range=list(right['group'][:2]),
            pairs=[list(v) for v in sorted(mapped.items())],forest_names=[[symbol for r in group for symbol in r[4]] for group in copies],
            compiled_forests=[[r[4] for r in group] for group in copies],role_matching=matching,producer=producer,
            summary_credit=[0,0],mapped_credit=[0,0],claim='Borrowed iterator second input retained; complete raw geometry/copies/cold roles; no producer or first tuple value execution claim'))
    return pairs,receipts,proved


def sync_record_factory_header(code, opening):
    if opening < 10:
        return None
    let, binding, equals, bar, parameter, colon, borrow, kind, closing, record = code.words[opening-10:opening]
    if ((let,equals,bar,colon,borrow,kind,closing)!=('let','=','|',':','&','str','|')
            or any(re.fullmatch(r'[A-Za-z_]\w*',name,re.ASCII) is None for name in (binding,parameter,record))
            or code.words[opening]!='{' or code.words[code.pairs[opening]+1:code.pairs[opening]+2]!=[';']):
        return None
    return binding,parameter,record


def positive_sync_fixture_change(descriptors,inventories,work):
    """Admit only one pure local fixture field addition before owner indexing."""
    codes=[i[0] for i in inventories];functions=[d['row'] for d in descriptors]
    if any(r['end']-r['first']>2048 for r in functions):return None
    _construct_charge(work,sum(r['end']-r['first']+1 for r in functions))
    words=[c.words[r['first']:r['end']+1] for c,r in zip(codes,functions)]
    if len(words[1])==len(words[0])+6:
        at=next((n for n,(a,b) in enumerate(zip(*words)) if a!=b),None)
        if at is not None:
            added=words[1][at:at+6]
            if (added[1::2]==[':','::',','] and all(re.fullmatch(r'[A-Za-z_]\w*',added[n],re.ASCII) for n in (0,2,4))
                    and words[0]==words[1][:at]+words[1][at+6:]):
                parents=[c.parents[r['first']+at] for c,r in zip(codes,functions)]
                if all(parent is not None and c.parents[parent]==fn['opening']
                       and sync_record_factory_header(c,parent)
                       for c,parent,fn in zip(codes,parents,functions)):
                    return 'scalar-record-factory-field'
                def record_let(code,opening):
                    if opening is None or code.words[opening]!='{' or opening<5:
                        return False
                    record=opening-1
                    enclosing=code.parents[opening]
                    if (enclosing==record-1 and code.words[enclosing]=='['
                            and code.pairs[enclosing]==code.pairs[opening]+1):
                        record=enclosing
                    return (code.words[record-1]=='='
                            and re.fullmatch(r'[A-Za-z_]\w*',code.words[opening-1],re.ASCII)
                            and (code.words[record-3]=='let' or code.words[record-4:record-2]==['let','mut']))
                if all(record_let(code,opening) for code,opening in zip(codes,parents)):
                    return 'scalar-record-field'
    values=[];bindings=[]
    def unique_fields(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate fixture key')
            value[key]=item
        return value
    for code,fn in zip(codes,functions):
        first=fn['opening']+1;prefix=code.words[first:first+8]
        if (len(prefix)!=8 or prefix[0]!='let' or prefix[2:]!=['=','serde_json','::','json','!','(']
                or re.fullmatch(r'[A-Za-z_]\w*',prefix[1],re.ASCII) is None):return None
        opening=first+7;closing=code.pairs[opening]
        if code.words[closing+1]!=';':return None
        text=code.text[code.ends[opening]:code.starts[closing]]
        if len(text)>8192:return None
        _construct_charge(work,len(text)+1)
        try:value=json.loads(text,object_pairs_hook=unique_fields)
        except (ValueError,RecursionError):return None
        pending=[(value,0)];nodes=0
        while pending:
            item,depth=pending.pop();nodes+=1;_construct_charge(work,1)
            if nodes>128 or depth>16:return None
            if type(item) is dict:pending.extend((v,depth+1) for v in item.values())
            elif type(item) is list:pending.extend((v,depth+1) for v in item)
            elif type(item) not in (str,int,bool,type(None)):return None
        bindings.append(prefix[1]);values.append(value)
    if bindings[0]!=bindings[1]:return None
    added=0;pending=[tuple(values)]
    while pending:
        old,new=pending.pop();_construct_charge(work,1)
        if type(old) is not type(new):return None
        if type(old) is dict:
            if not old.keys()<=new.keys():return None
            added+=len(new.keys()-old.keys());pending.extend((v,new[k]) for k,v in old.items())
        elif type(old) is list:
            if len(old)!=len(new):return None
            pending.extend(zip(old,new))
        elif old!=new:return None
    return 'literal-json-field' if added==1 else None


def positive_sync_test_slots(descriptor,inventory,source,work):
    """Recognize a small sync unit routine with direct expression callbacks or a record factory."""
    code=inventory[0];fn=descriptor['row'];first,last=fn['opening']+1,fn['end']
    if last-first>2048:return None
    _construct_charge(work,last-first+1)
    words=code.words[first:last]
    if any(w in ('fn','struct','enum','impl','trait','mod','type','union','unsafe','async','move','||') for w in words):return None
    low,high=code.position(code.starts[fn['first']])[0],code.position(code.ends[fn['end']])[0]
    _construct_charge(work,sum(len(line)+1 for line in source[low-1:high]))
    if any(not line.isascii() for line in source[low-1:high]):return None
    slots=[];at=first
    while at<last:
        _construct_charge(work,1)
        if code.words[at]!='|':at+=1;continue
        call=code.parents[at]
        opening=at+7
        if (call==fn['opening'] and opening<last and code.words[opening]=='{'
                and (header:=sync_record_factory_header(code,opening)) is not None
                and re.fullmatch(r'[A-Za-z_]\w*',code.words[opening+1],re.ASCII)
                and code.words[opening+2]==':'):
            end=code.pairs[opening]
            _construct_charge(work,end-opening+1)
            if any(word in ('|','||','async','move') for word in code.words[opening+1:end]):
                return None
            begin=code.position(code.starts[opening+3]);finish=code.position(code.ends[end])
            slots.append((begin,finish,'record-factory',header))
            if len(slots)>2:return None
            at=end+1;continue
        if (call is None or code.words[call]!='(' or code.words[call-2]!='.'
                or code.words[call-1] not in ('map','any','find') or call+1!=at):return None
        if code.words[at+2:at+3]==['|']:
            variable=code.words[at+1];body=at+3
        elif code.words[at+1:at+4]==['(','_',','] and code.words[at+5:at+7]==[')','|']:
            variable=code.words[at+4];body=at+7
        else:return None
        if re.fullmatch(r'[A-Za-z_]\w*',variable,re.ASCII) is None:return None
        end=code.pairs[call]-1
        if (not body<=end<last or end-body>64 or any(w in ('{','}','|','||','async','!') for w in code.words[body:end+1])
                or any(code.parents[n]==call and code.words[n]==',' for n in range(body,end+1))):return None
        begin,finish=code.position(code.starts[body]),code.position(code.ends[end])
        if begin[0]!=finish[0]:return None
        slots.append((begin,finish,code.words[call-1],tuple(code.words[at:body])))
        if len(slots)>2:return None
        _construct_charge(work,end-body+1);at=end+1
    return tuple(slots)


def positive_sync_callback_members(root,forest,slots,work):
    """Close every direct expression callback to one exact source argument slot."""
    shape=plain_rust_function_symbol(root['name'])
    if shape is None:return None
    _construct_charge(work,sum(len(o['name'])+len(o['regions'])+1 for o in forest))
    children=[o for o in forest if direct_rust_callback_symbol(o['name'],root['name'],shape.modules)]
    if len(children)!=len(slots):return None
    selected=[];roles=[]
    for first,last,method,header in slots:
        _construct_charge(work,sum(len(o['regions'])+1 for o in children))
        matches=[o for o in children if all(first<=tuple(r[:2])<tuple(r[2:4])<=last for r in o['regions'])]
        if len(matches)!=1:return None
        owner=matches[0];quantity=owner.get('count')
        if (any(owner is other for other in selected)
                or type(quantity) is not int or not 0<quantity<COUNTER_LIMIT
                or min(tuple(r[:2]) for r in owner['regions'])!=first
                or method=='record-factory' and max(tuple(r[2:4]) for r in owner['regions'])!=last
                or any(r[4]!=quantity for r in owner['regions'])):return None
        selected.append(owner);roles.append((method,header,first,last,owner['name']))
    return selected,tuple(roles)


def positive_local_impl_members(descriptor, root, forest, inventory, work):
    """Bind source-local trait methods to their enclosing async test copy."""
    code,rows=inventory[:2];function=descriptor['row'];plain=plain_rust_function_symbol(root['name'])
    if plain is None:return None
    namespace=('crate',plain.identifiers[0])
    for position,(value,scope) in enumerate(zip(plain.identifiers[1:],plain.disambiguators[1:]),1):
        namespace=('value' if position==len(plain.identifiers)-1 else 'type',namespace,(value,scope))
    namespace=('closure',namespace,'')
    crate=re.match(r'_RNv(?:Nt)*C(s[0-9A-Za-z]{0,32}_)?',root['name'])
    if crate is None:return None
    copy=(plain.identifiers[0],crate[1] or '')
    _construct_charge(work,len(rows)+sum(len(o['name'])+1 for o in forest))
    implementations=[r for r in rows if r['kind']=='impl' and r['supported'] and code.parents[r['first']]==function['opening']]
    members=[];roles=[]
    for implementation in implementations:
        _construct_charge(work,2*len(rows)+sum(len(o['name'])+4 for o in forest))
        header=tuple(implementation['header'])
        if (len(header)!=4 or header[0]!='impl' or header[2]!='for'
                or any(re.fullmatch(r'[A-Za-z_]\w*',value,re.ASCII) is None for value in (header[1],header[3]))):return None
        declarations=[at for at in range(function['opening']+1,implementation['first'])
            if code.words[at:at+2]==['struct',header[3]] and code.parents[at]==function['opening']]
        _construct_charge(work,implementation['first']-function['opening'])
        if len(declarations)!=1:return None
        methods=[r for r in rows if r['kind']=='fn' and code.parents[r['first']]==implementation['opening']]
        if len(methods)!=1 or methods[0]['header'][:1]!=('fn',):return None
        method=methods[0];name=method['header'][1]
        blocks=[r for r in rows if r['kind']=='expression' and r.get('header') in (('async',),('async','move'))
                and method['opening']<r['opening']<r['end']<method['end']]
        if len(blocks)!=1:return None
        block=blocks[0];candidates=[]
        for owner in forest:
            shape=nominal_method_path(owner['name'],local_scope=True)
            if shape is not None and shape.namespace==namespace and shape.self_type==('type',namespace,(header[3],'')):
                candidates.append((shape,owner))
        constructors=[(shape,owner) for shape,owner in candidates if not shape.callbacks]
        if len(constructors)!=1:return None
        shape,constructor=constructors[0]
        if (shape.kind!='X' or shape.impl_scope or shape.method!=(name,'') or shape.trait is None
                or shape.trait[-1]!=(header[1],'') or shape.instantiating_crate!=copy or shape.crate_graph!=(copy,)):
            return None
        bodies=[owner for other,owner in candidates if other.copy_identity==shape.copy_identity and other.callbacks==('',)]
        if len(candidates)!=2 or len(bodies)!=1:return None
        body=bodies[0];count=constructor.get('count')
        entry=code.region(method['first'],method['opening']-1);end=code.region(method['end'],method['end'])
        first=code.position(code.starts[block['opening']]);last=code.position(code.ends[block['end']])
        if (body.get('count')!=count or [r[4] for r in constructor['regions'] if tuple(r[:4])==entry]!=[count]
                or [r[4] for r in constructor['regions'] if tuple(r[:4])==end]!=[count]
                or [r[4] for r in body['regions'] if tuple(r[:4])==(*first,first[0],first[1]+1)]!=[count]
                or [r[4] for r in body['regions'] if tuple(r[:4])==(last[0],last[1]-1,*last)]!=[count]
                or any(not first<=tuple(r[:2])<tuple(r[2:4])<=last for r in body['regions'])):return None
        members.extend((constructor,body));roles.append((header[3],shape.trait))
    return members,tuple(roles)


def same_qualified_positive_test_obligations(name, sources, counts, descriptors, inventories, grouped,
                                              replacements, equal_rows, work, indexes_factory, expansions):
    """Retain source only through a complete positive forest of the same test."""
    if indexes_factory is None or expansions!=([],[]):return {},[],set()
    allowed=(('#','[','test',']'),('#','[','tokio','::','test',']','async'))
    candidates=[];sync_shapes={}
    _construct_charge(work,sum(len(d) for d in descriptors))
    digests=[{} for _ in descriptors]
    for side,functions in enumerate(descriptors):
        for d in functions.values():digests[side].setdefault(d['declaration'],set()).add(d['row']['digest'])
    for side,(inventory,functions) in enumerate(zip(inventories,descriptors)):
        code=inventory[0];chosen={};_construct_charge(work,len(functions))
        for descriptor in functions.values():
            row=descriptor['row'];header=tuple(row['header']);at=header.index('fn');declaration=header[at+1]
            if (header[:at] not in allowed or header[at:]!=('fn',declaration,'(',')')):continue
            if side==0 and header[:at]==allowed[0] and row['digest'] in digests[1].get(declaration,()):continue
            context=_boolean_module(code,{'start':row['first']})
            if context is None or context[:2]!=(['tests'],['tests']):continue
            chosen.setdefault(declaration,[]).append(descriptor)
        candidates.append(chosen)
    potential=[];sync_potential=[]
    for declaration,previous in candidates[0].items():
        current=candidates[1].get(declaration,[])
        if len(previous)!=1 or len(current)!=1:continue
        chosen=(previous[0],current[0])
        if chosen[0]['row']['digest']!=chosen[1]['row']['digest']:
            if tuple(chosen[0]['attributes'])==allowed[0]:
                if tuple(chosen[1]['attributes'])!=allowed[0]:continue
                fixture=positive_sync_fixture_change(chosen,inventories,work)
                if fixture is None:continue
                _construct_charge(work,sum(len(o['regions'])+1 for d in chosen for o in d['group'][2]))
                if any(type(o.get('count')) is not int or not 0<o['count']<COUNTER_LIMIT
                        or any(not 0<r[4]<COUNTER_LIMIT for r in o['regions']) for d in chosen for o in d['group'][2]):continue
                _construct_charge(work,sum(d['group'][1]-d['group'][0]+1 for d in chosen))
                if any(any(da.get(n,1)<=0 for n in range(d['group'][0],d['group'][1]+1)) for da,d in zip(counts,chosen)):continue
                slots=tuple(positive_sync_test_slots(d,i,s,work) for d,i,s in zip(chosen,inventories,sources))
                expected={'scalar-record-field':0,'scalar-record-factory-field':1,'literal-json-field':2}[fixture]
                if any(s is None or len(s)!=expected for s in slots):continue
                if any(sum(slot[2]=='record-factory' for slot in s)!=int(expected==1) for s in slots):continue
                sync_shapes[declaration]=slots;sync_potential.append((declaration,chosen))
            else:potential.append((declaration,chosen))
    if len(sync_potential)<=16:potential.extend(sync_potential)
    if not potential:return {},[],set()
    indexes=indexes_factory();buckets=[]
    for side,index in enumerate(indexes):
        spans=sorted((chosen[side]['group'][0],chosen[side]['group'][1],declaration) for declaration,chosen in potential)
        _construct_charge(work,len(spans)*(len(spans).bit_length()+1))
        if any(left[1]>=right[0] for left,right in zip(spans,spans[1:])):return {},[],set()
        starts=[row[0] for row in spans];ends=[row[1] for row in spans];result={row[2]:[] for row in spans}
        available=index.inventories.get(name,())
        _construct_charge(work,sum(3*len(o['regions'])+1 for o in available))
        for owner in available:
            low=min(r[0] for r in owner['regions']);high=max(r[2] for r in owner['regions'])
            _construct_charge(work,2*(len(spans).bit_length()+1))
            for position in range(bisect.bisect_left(ends,low),bisect.bisect_right(starts,high)):
                first,last,declaration=spans[position];_construct_charge(work,len(owner['regions'])+1)
                if declaration in sync_shapes or any(tuple(r[:2])<(last+1,1) and (first,1)<tuple(r[2:4]) for r in owner['regions']):
                    result[declaration].append(owner)
        buckets.append(result)
    pairs={};targets={};receipts=[];proved=set()
    for declaration,chosen in potential:
        groups=tuple(row['group'] for row in chosen)
        _construct_charge(work,len(replacements))
        related=[r for r in replacements.values() if r.get('retained_statements')
            and max(r['base_range'][0],groups[0][0])<=min(r['base_range'][1],groups[0][1])]
        lexical=[(inventory[0].position(inventory[0].starts[descriptor['row']['first']])[0],group[1])
            for inventory,descriptor,group in zip(inventories,chosen,groups)]
        if any(not (lexical[0][0]<=r['base_range'][0]<=r['base_line']<=r['base_range'][1]<=lexical[0][1]
            and lexical[1][0]<=r['head_range'][0]<=r['head_line']<=r['head_range'][1]<=lexical[1][1]) for r in related):continue
        roles=[];forests=[];local_forests=[];local_roles=[];sync_roles=[];scope_forests=[];valid=True
        for side,(descriptor,inventory,index,group) in enumerate(zip(chosen,inventories,indexes,groups)):
            code=inventory[0];function=descriptor['row'];first,last=group[:2]
            forest=buckets[side][declaration]
            _construct_charge(work,sum(len(o['name'])+len(o['regions'])+1 for o in forest))
            roots=group[2];owned=set();identities=[];copies=[];locals_for_side=[];roles_for_side=[];sync_for_side=[]
            for root in roots:
                shape=plain_rust_function_symbol(root['name'])
                if (shape is None or shape.identifiers[-2:]!=('tests',declaration)
                        or name.startswith('src/') and shape.identifiers[:-2] !=
                            ('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'))):
                    valid=False;break
                members=[root]
                if 'async' in descriptor['attributes']:
                    entry=code.position(code.starts[function['opening']])
                    children=[o for o in forest if direct_rust_callback_symbol(o['name'],root['name'],shape.modules)
                        and [r[4] for r in o['regions'] if tuple(r[:4])==(*entry,entry[0],entry[1]+1)]==[root['count']]]
                    if len(children)!=1:valid=False;break
                    members+=children
                local=([],()) if declaration in sync_shapes else positive_local_impl_members(descriptor,root,forest,inventory,work)
                if local is None:valid=False;break
                extra,local_role=local;members+=extra;locals_for_side.extend(extra);roles_for_side.append(local_role)
                if declaration in sync_shapes:
                    sync=positive_sync_callback_members(root,forest,sync_shapes[declaration][side],work)
                    if sync is None:valid=False;break
                    children,sync_role=sync;members+=children;locals_for_side.extend(children);sync_for_side.append(sync_role)
                for member in members:
                    if (id(member) in owned or index.name_counts[member['name']]!=1 or len(member['filenames'])!=1
                            or index.files.get(member['filenames'][0])!=name or member.get('branches') or member.get('mcdc_records')
                            or any(len(r)!=8 or r[5:]!=[0,0,0] for r in member['regions'])):
                        valid=False;break
                    owned.add(id(member))
                if not valid:break
                identities.append(shape.identity);copies.append([o['name'] for o in members])
            if not valid or not roots or owned!={id(o) for o in forest}:valid=False;break
            roles.append(Counter(identities));forests.append(copies);local_forests.append(tuple(locals_for_side));local_roles.append(tuple(roles_for_side));sync_roles.append(tuple(sync_for_side));scope_forests.append(forest)
        if not valid or roles[0]!=roles[1] or local_roles[0]!=local_roles[1]:continue
        selected=[r for r in replacements.values() if groups[0][0]<=r['base_line']<=groups[0][1]
                  and groups[1][0]<=r['head_line']<=groups[1][1]]
        proof_counts=counts;proof_groups=grouped;proof_equal=equal_rows
        if declaration in sync_shapes:
            # The complete overlap index above already closes these exact scopes.
            _construct_charge(work,len(equal_rows)+sum(g[1]-g[0]+1 for g in groups))
            proof_counts=tuple({n:da[n] for n in range(g[0],g[1]+1) if n in da} for da,g in zip(counts,groups))
            proof_groups=tuple((forest,{},Counter(o['name'] for o in forest)) for forest in scope_forests)
            proof_equal=[(n,m) for n,m in equal_rows if groups[0][0]<=n<=groups[0][1] and groups[1][0]<=m<=groups[1][1]]
        covered=fully_covered_replacement(name,*sources,*proof_counts,chosen,proof_groups,selected,proof_equal,work,tuple(local_forests))
        if covered is None:continue
        mapped,receipt=covered
        _construct_charge(work,len(mapped)+len(targets))
        if any(line in pairs and pairs[line]!=target or target in targets and targets[target]!=line for line,target in mapped.items()):
            raise ValueError('Ambiguous same-qualified test correspondence')
        pairs.update(mapped);targets.update((target,line) for line,target in mapped.items())
        receipt.update(kind='same-qualified-positive-test',declaration=declaration,phase_forests=forests,
            root_roles=[repr(role) for role in roles[0]],local_impl_roles=local_roles,sync_callback_roles=sync_roles,
            claim='Same qualified zero-arg test; every raw owner and region positive; changed calls not semantically equated; zero deletion credit')
        receipts.append(receipt);proved.add(groups[0][:2])
    return pairs,receipts,proved


def retained_replacement_obligations(name, old, new, before, after, inventories, grouped,
                                     replacements, work, head_counts=None, parent_files=None,
                                     record_indexes=None, record_expansions=(None,None), island_blobs=None,
                                     line_operations=None):
    if not replacements or any(value is None for value in tuple(inventories) + tuple(grouped)):
        return {}, [], set()
    descriptors = []; context_cache = {}; binding_indexes = {}
    for inventory, compiled in zip(inventories, grouped):
        code = inventory[0]
        _construct_charge(work, 3 * len(inventory[1]) + len(code.words))
        by_opening = {row['opening']: row for row in inventory[1] if row['opening'] is not None}
        function_rows = {}
        for row in inventory[1]:
            if row['kind'] == 'fn' and 'fn' in row['header']:
                span = (code.position(code.starts[row['first'] + row['header'].index('fn')])[0],
                        code.position(code.starts[row['end']])[0])
                function_rows.setdefault(span, []).append(row)
        _construct_charge(work, len(inventory[1]) * (len(inventory[1]).bit_length() + 1))
        statements = sorted((row for row in inventory[1] if row['kind'] == 'statement'), key=lambda row: row['first'])
        statement_starts = [row['first'] for row in statements]
        functions = {}
        for prefix, group in compiled[1].items():
            candidates = function_rows.get(group[:2], [])
            _construct_charge(work, 1)
            if len(candidates) != 1:
                continue
            row = candidates[0]; header = list(row['header']); fn = header.index('fn')
            declaration = header[fn + 1]
            attributes = header[:fn]
            _construct_charge(work, row['end'] - row['first'] + 1)
            if 'macro_rules' in code.words[row['opening'] + 1:row['end']]:
                continue
            scopes = _construct_ancestors(code, row['opening'], work)
            parents = [by_opening.get(opening) for opening in scopes if opening != row['opening']]
            if any(parent is None or parent['kind'] not in ('mod', 'impl', 'trait') for parent in parents):
                continue
            scope_key = tuple(tuple(parent['header']) for parent in parents)
            key = id(code), tuple(scopes)
            if id(code) not in binding_indexes:
                _construct_charge(work, len(code.words))
                bindings = {}
                for index, word in enumerate(code.words):
                    if (word not in ('use', 'macro_rules')
                            and not (word == 'extern' and code.words[index + 1:index + 2] == ['crate'])):
                        continue
                    end = index + 1
                    while end < len(code.words):
                        _construct_charge(work, 1)
                        if code.parents[end] == code.parents[index] and code.words[end] in (';', '{'):
                            if code.words[end] == '{' and word == 'macro_rules':
                                end = code.pairs[end]
                            elif code.words[end] != ';':
                                end += 1; continue
                            break
                        end += 1
                    _construct_charge(work, end - index + 3)
                    bindings.setdefault(code.parents[index], []).append((index, tuple(code.words[index:end + 1])))
                binding_indexes[id(code)] = bindings
            if key not in context_cache:
                _construct_charge(work, len(scopes) + 1)
                selected_bindings = []
                for parent in set(scopes) | {None}:
                    entries = binding_indexes[id(code)].get(parent, ())
                    _construct_charge(work, len(entries))
                    selected_bindings.extend(entries)
                _construct_charge(work, len(selected_bindings) * (len(selected_bindings).bit_length() + 2))
                selected_bindings.sort(key=lambda entry: entry[0])
                context_cache[key] = tuple(value for index, value in selected_bindings)
            header[fn + 1] = '<declaration>'
            parameter_opening = row['first'] + fn + 2
            parameter_signature = (tuple(header[:code.pairs[parameter_opening] - row['first'] + 1])
                if code.words[parameter_opening] == '(' else None)
            first = bisect.bisect_right(statement_starts, row['opening'])
            last = bisect.bisect_left(statement_starts, row['end'])
            _construct_charge(work, last - first)
            by_digest = {}
            for index in range(first, last):
                statement = statements[index]
                if statement['end'] >= row['end']:
                    continue
                by_digest.setdefault(statement['digest'], []).append(statement)
            functions[prefix] = dict(group=group, row=row, declaration=declaration,
                signature=tuple(header), attributes=attributes, context=(scope_key, context_cache[key]),
                parameter_signature=parameter_signature,
                statements=by_digest, constructs=by_opening)
        descriptors.append(functions)
    statement_contexts = {}; capsule_indexes = {}; callback_indexes = {}
    def statement_context(descriptor, code, row):
        key = id(code), row['first'], descriptor['row']['opening']
        if key not in statement_contexts:
            ancestors = _construct_ancestors(code, row['first'], work); context = []
            for opening in ancestors:
                if opening == descriptor['row']['opening']:
                    break
                parent = descriptor['constructs'].get(opening)
                if parent is None:
                    context = None; break
                _construct_charge(work, len(parent['header']))
                context.append(tuple(parent['header']))
            statement_contexts[key] = None if context is None else tuple(context)
        return statement_contexts[key]
    def callback_capsules(descriptor, code):
        key = id(code), descriptor['row']['opening']
        if key not in capsule_indexes:
            first, last = descriptor['row']['opening'], descriptor['row']['end']
            _construct_charge(work, len(code.pairs))
            index = {}; counts = Counter()
            for opening, closing in code.pairs.items():
                if not first < opening < closing < last:
                    continue
                _construct_charge(work, closing - opening + 1)
                ancestors = _construct_ancestors(code, opening, work)
                context = []
                for ancestor in ancestors:
                    if ancestor == first:
                        continue
                    construct = descriptor['constructs'].get(ancestor)
                    if construct is not None:
                        _construct_charge(work, len(construct['header']))
                        context.append(tuple(construct['header']))
                    else:
                        _construct_charge(work, code.pairs[ancestor] - ancestor + 1)
                        context.append(tuple(code.words[ancestor:code.pairs[ancestor] + 1]))
                value = (code.words[opening - 1], tuple(code.words[opening:closing + 1]), tuple(context))
                index[opening] = (closing, value); counts[value] += 1
            capsule_indexes[key] = index, counts
        return capsule_indexes[key]
    def indexed_callback_candidates(compiled, side, prefix):
        if side not in callback_indexes:
            _construct_charge(work, 4 * len(compiled[0]))
            owners = [owner for owner in compiled[0] if owner['name'].startswith('_RNC')]
            _construct_charge(work, (len(owners).bit_length() + 2)
                              * sum(len(owner['name']) + 1 for owner in owners))
            owners.sort(key=lambda owner: owner['name'])
            callback_indexes[side] = [owner['name'] for owner in owners], owners
        names, owners = callback_indexes[side]
        _construct_charge(work, (len(prefix) + 1) * (len(names).bit_length() + 1))
        for slot in range(bisect.bisect_left(names, prefix), len(names)):
            _construct_charge(work, len(prefix) + 1)
            if not names[slot].startswith(prefix):
                break
            yield owners[slot]
    def attached_callbacks(descriptor, code, compiled, ordered, side, source):
        index = counts = None
        result = []; all_children = set()
        for parent in descriptor['group'][2]:
            shape = plain_rust_function_symbol(parent['name']); children = {}
            prefix = '_RNC' + parent['name'][2:]
            candidates = () if shape is None else indexed_callback_candidates(compiled, side, prefix)
            for child in candidates:
                _construct_charge(work, len(prefix))
                if not direct_rust_callback_symbol(child['name'], parent['name'], shape.modules):
                    continue
                _construct_charge(work, len(child['regions']) * (len(ordered) + 1))
                if not any(tuple(region[:2]) < (pair[side], len(source[pair[side] - 1].encode()) + 1)
                           and tuple(region[2:4]) > (pair[side], 1)
                           for region in child['regions'] for pair in ordered):
                    continue
                if compiled[2][child['name']] != 1 or len(child['filenames']) != 1:
                    return None
                if index is None:
                    index, counts = callback_capsules(descriptor, code)
                low = min(tuple(region[:2]) for region in child['regions'])
                high = max(tuple(region[2:4]) for region in child['regions'])
                _construct_charge(work, len(index))
                enclosing = [(opening, closing, value) for opening, (closing, value) in index.items()
                    if code.position(code.starts[opening]) <= low
                    and high <= code.position(code.ends[closing])]
                if not enclosing:
                    return None
                opening, closing, value = min(enclosing, key=lambda row: row[1] - row[0])
                identity = CallbackCapsule(value[0], value[1], value[2],
                                          shape.identity[:-1], shape.disambiguators[-1])
                if (counts[value] != 1 or identity in children or value[0] in ('!', '#')
                        or any(word in ('!', '#') for word in value[1])):
                    return None
                children[identity] = (child, opening, closing)
                all_children.add(id(child))
            result.append(children)
        return result, all_children
    def source_syntax_without_regions(code, number, compiled, source, unmapped=False):
        _construct_charge(work, 2 * (len(code.words).bit_length() + 1))
        low = code.offsets[number - 1]
        high = code.offsets[number] if number < len(code.offsets) else len(code.text)
        token = bisect.bisect_right(code.ends, low)
        if token < len(code.starts) and code.starts[token] < high:
            last = bisect.bisect_left(code.starts, high)
            _construct_charge(work, last - token)
            if (not unmapped or any(word not in ('{', '}', '(', ')', '[', ']', ',', ';', 'else')
                                    for word in code.words[token:last])):
                return False
        _construct_charge(work, sum(len(owner['regions']) + 1 for owner in compiled[0]))
        span = (number, 1), (number, len(source[number - 1].encode()) + 1)
        return not any(tuple(region[:2]) < span[1] and span[0] < tuple(region[2:4])
                       for owner in compiled[0] for region in owner['regions'])
    def constant_record_field_without_regions(descriptor, code, number, compiled, source):
        _construct_charge(work, 2 * (len(code.words).bit_length() + 1))
        low = code.offsets[number - 1]
        high = code.offsets[number] if number < len(code.offsets) else len(code.text)
        first = bisect.bisect_right(code.ends, low)
        last = bisect.bisect_left(code.starts, high)
        words = code.words[first:last]
        if (len(words) != 4 or re.fullmatch(r'[A-Za-z_]\w*', words[0]) is None
                or words[1] != ':' or words[3] != ','
                or words[2] not in ('true', 'false')
                    and re.fullmatch(r'(?:0|[1-9][0-9]{0,19})', words[2]) is None):
            return False
        opening = code.parents[first]
        record = descriptor['constructs'].get(opening)
        if (record is None or record['header'] != ('Self',) or not record['supported']
                or code.parents[opening] != descriptor['row']['opening']
                or any(code.parents[index] != opening for index in range(first, last))):
            return False
        _construct_charge(work, sum(len(owner['regions']) + 1 for owner in compiled[0]))
        span = (number, 1), (number, len(source[number - 1].encode()) + 1)
        return not any(tuple(region[:2]) < span[1] and span[0] < tuple(region[2:4])
                       for owner in compiled[0] for region in owner['regions'])
    macro_paint_cache = {}
    def macro_literal_paint(descriptor, inventory, compiled, source, number, mapped_lines):
        code = inventory[0]
        _construct_charge(work, 2 * (len(code.words).bit_length() + 1))
        low = code.offsets[number - 1]
        token = bisect.bisect_right(code.ends, low)
        if token >= len(code.words):
            return None
        is_head = False
        end = token
        while end + 2 < len(code.words) and code.words[end + 1] == '::':
            _construct_charge(work, 1)
            end += 2
        if (end > token and code.words[end + 1:end + 3] == ['!', '(']
                and code.position(code.starts[token])[0] == number):
            token = end + 3; is_head = True
        key = id(code), token, descriptor['row']['opening']
        refusal = False if is_head else None
        if key not in macro_paint_cache:
            macro_paint_cache[key] = False
            word = code.words[token]; opening = code.parents[token]
            if (re.match(r'(?:"|r#*")', word) is None or opening is None
                    or code.words[opening] != '(' or opening < 4
                    or code.words[opening - 1] != '!'):
                return refusal
            closing = code.pairs[opening]
            if code.words[token + 1:closing] not in ([], [',']) or token != opening + 1:
                return refusal
            first = opening - 2
            while first >= 2 and code.words[first - 1] == '::':
                first -= 2
            path = tuple(code.words[first:opening - 1])
            if (len(path) < 3 or any(re.fullmatch(r'[A-Za-z_]\w*', value) is None
                    for value in path[::2]) or any(value != '::' for value in path[1::2])):
                return refusal
            row = descriptor['row']; scopes = set(_construct_ancestors(code, first, work))
            context = statement_context(descriptor, code, dict(first=first))
            if context is None or not row['opening'] < first < closing < row['end']:
                return refusal
            _construct_charge(work, len(code.words) + row['end'] - row['opening'])
            # A qualified path still needs a stable lexical root. Local items
            # and statement expansions cannot silently supply a replacement.
            items = {'use', 'const', 'static', 'fn', 'mod', 'struct', 'enum', 'type', 'trait', 'impl', 'extern'}
            for index in range(row['opening'] + 1, row['end']):
                if code.parents[index] in scopes and (code.words[index] in items | {'#', 'macro_rules'}
                        or index < first and code.words[index] == '!'):
                    return refusal
            for index, value in enumerate(code.words):
                if value == path[0] and index and code.words[index - 1] in (items - {'use'}) | {'crate'}:
                    return refusal
                if value in ('!', '#'):
                    ancestors = _construct_ancestors(code, index, work)
                    if not any(descriptor['constructs'].get(parent, {}).get('kind') == 'fn'
                               for parent in ancestors):
                        return refusal
            _construct_charge(work, len(word))
            body = re.sub(r'\\\n[ \t]*', '', word)
            captures = tuple(re.findall(r'\{([A-Za-z_]\w*)\}', body))
            remainder = re.sub(r'\{[A-Za-z_]\w*\}', '', body)
            if any(value in remainder for value in ('{', '}', '\\')):
                return refusal
            fn = row['first'] + list(row['header']).index('fn')
            parameters = fn + 2
            if code.words[parameters] != '(':
                return refusal
            parameter_names = {code.words[index] for index in range(parameters + 1, code.pairs[parameters])
                if code.parents[index] == parameters and code.words[index - 1] in ('(', ',')
                and index + 1 < code.pairs[parameters] and code.words[index + 1] == ':'}
            if not set(captures) <= parameter_names:
                return refusal
            preceding = []
            for rows in descriptor['statements'].values():
                _construct_charge(work, len(rows))
                for statement in rows:
                    if (row['opening'] < statement['first'] <= statement['end'] < first
                            and code.parents[statement['first']] in scopes):
                        _construct_charge(work, statement['end'] - statement['first'] + 1)
                        preceding.append((statement['first'], tuple(code.words[statement['first']:statement['end'] + 1])))
            _construct_charge(work, len(preceding) * (len(preceding).bit_length() + 1))
            preceding.sort()
            head = code.position(code.starts[first])[0]
            if head not in mapped_lines or code.position(code.ends[opening])[0] != head:
                return refusal
            span = code.position(code.starts[token]), code.position(code.ends[closing])
            _construct_charge(work, sum(len(owner['regions']) + 1 for owner in compiled[0]))
            if any(tuple(region[:2]) < span[1] and span[0] < tuple(region[2:4])
                   for owner in compiled[0] for region in owner['regions']):
                return refusal
            macro_paint_cache[key] = (head, path, captures, context, tuple(value for index, value in preceding))
        proof = macro_paint_cache[key]
        if proof is False:
            return refusal
        if is_head:
            return proof, False
        high = code.offsets[number] - 1 if number < len(code.offsets) else len(code.text)
        if not (code.starts[token] < high and low < code.ends[token]):
            return None
        outside = code.text[low:min(high, code.starts[token])] + code.text[max(low, code.ends[token]):high]
        return (proof, True) if not outside.strip() else None
    _construct_charge(work, sum(len(inventory[1]) for inventory in inventories))
    file_counts = [Counter(row['digest'] for row in inventory[1] if row['kind'] == 'statement')
                   for inventory in inventories]
    extra_pairs, extra_receipts, extra_proved = one_bound_phase_obligations(
        name, (old,new), (before,after), descriptors, inventories, grouped, replacements, work)
    record_pairs, record_receipts, record_proved = retained_record_field_obligations(
        name,(old,new),(before,after),descriptors,inventories,grouped,replacements,work,
        record_indexes,record_expansions)
    island_pairs, island_receipts = retained_callback_island_obligations(
        name,(old,new),(before,after),descriptors,inventories,replacements,work,
        record_indexes,record_expansions,island_blobs)
    _construct_charge(work,len(island_pairs)+len(record_pairs))
    record_targets={target:line for line,target in record_pairs.items()}
    if any(line in record_pairs and record_pairs[line]!=target
           or target in record_targets and record_targets[target]!=line for line,target in island_pairs.items()):
        raise ValueError('Ambiguous callback island and record correspondence')
    record_pairs.update(island_pairs);record_receipts.extend(island_receipts)
    _construct_charge(work,len(extra_pairs)+len(record_pairs))
    extra_targets={target:line for line,target in extra_pairs.items()}
    if any(line in extra_pairs and extra_pairs[line]!=target
           or target in extra_targets and extra_targets[target]!=line for line,target in record_pairs.items()):
        raise ValueError('Ambiguous record field and callback phase correspondence')
    extra_pairs.update(record_pairs);extra_receipts.extend(record_receipts);extra_proved.update(record_proved)
    if record_indexes is not None and record_expansions==([],[]):
        matched_targets={target:line for line,target in extra_pairs.items()}
        _construct_charge(work,len(matched_targets))
        for prefix,left in descriptors[0].items():
            _construct_charge(work,1)
            right=descriptors[1].get(prefix)
            if right is None or left['context'][0] or right['group'][1]-right['group'][0]<=left['group'][1]-left['group'][0]:
                continue
            if left['attributes']==['pub']:
                proved=retained_inline_callback_obligations(name,(old,new),(before,after),(left,right),
                    inventories,(),record_indexes(),head_counts,work)
            elif left['attributes']==['pub','(','crate',')']:
                proved=retained_context_assignment_obligations(name,(old,new),(before,after),(left,right),
                    inventories,record_indexes,work)
            else:
                continue
            if proved is None:
                continue
            mapped,receipt=proved
            _construct_charge(work,len(mapped))
            if any(line in extra_pairs and extra_pairs[line]!=target
                   or target in matched_targets and matched_targets[target]!=line for line,target in mapped.items()):
                raise ValueError('Ambiguous retained loop and callback correspondence')
            extra_pairs.update(mapped);extra_receipts.append(receipt)
            matched_targets.update((target,line) for line,target in mapped.items())
    projection_pairs,projection_receipts,projection_proved=retained_projected_iterator_obligations(
        name,(old,new),(before,after),descriptors,inventories,replacements,work,record_indexes,record_expansions)
    _construct_charge(work,len(extra_pairs)+len(projection_pairs));projection_targets={t:n for n,t in extra_pairs.items()}
    if any(n in extra_pairs and extra_pairs[n]!=t or t in projection_targets and projection_targets[t]!=n for n,t in projection_pairs.items()):
        raise ValueError('Ambiguous projected iterator and retained correspondence')
    extra_pairs.update(projection_pairs);extra_receipts.extend(projection_receipts);extra_proved.update(projection_proved)
    candidates = []; receiver_candidates = []
    previous, current = descriptors
    _construct_charge(work,len(current))
    added_functions = [(prefix, descriptor) for prefix, descriptor in current.items() if prefix not in previous]
    test_attributes = (['#', '[', 'test', ']'], ['#', '[', 'tokio', '::', 'test', ']', 'async'])
    for left_prefix, left in previous.items():
        if left['group'][:2] in extra_proved:
            continue
        same_function = current.get(left_prefix)
        right_candidates = [(left_prefix, same_function)] if same_function is not None else added_functions
        for right_prefix, right in right_candidates:
            _construct_charge(work, 1)
            method_migration = (left_prefix != right_prefix
                and all(nominal_method_parent(owner['name'], descriptor['declaration']) is not None
                        for descriptor in (left, right) for owner in descriptor['group'][2]))
            complete_test_rewrite = (left_prefix != right_prefix
                and left['attributes'] in test_attributes and right['attributes'] in test_attributes
                and left['context'][0] == right['context'][0]
                and (left['context'] != right['context'] or left['attributes'] != right['attributes']
                     or left['signature'] != right['signature']))
            prefix_only = (left_prefix == right_prefix and left['signature'] != right['signature']
                and left['parameter_signature'] is not None
                and left['parameter_signature'] == right['parameter_signature'])
            if (not complete_test_rewrite and (left['context'] != right['context']
                    or left['attributes'] != right['attributes']
                    or left['signature'] != right['signature'] and not method_migration and not prefix_only)):
                continue
            seeds = []; qualified_seeds = []; parent = None
            renamed = left_prefix != right_prefix
            if renamed:
                public_method = method_migration and left['attributes'] in (
                    ['pub'], ['pub', '(', 'crate', ')'])
                if (left['attributes'] not in ([], ['#', '[', 'test', ']'])
                        and not public_method and not complete_test_rewrite):
                    continue
                _construct_charge(work, sum(len(owner['name']) + 1 for descriptor in (left, right)
                                            for owner in descriptor['group'][2]))
                parents = [{replacement_raw_parent(owner['name'], descriptor['declaration'])
                            for owner in descriptor['group'][2]} for descriptor in (left, right)]
                if None in parents[0] or None in parents[1] or len(parents[0]) != 1 or parents[0] != parents[1]:
                    continue
                parent = next(iter(parents[0]))
                for digest, rows in left['statements'].items():
                    targets = right['statements'].get(digest, [])
                    tokens = inventories[0][0].words[rows[0]['first']:rows[0]['end'] + 1]
                    _construct_charge(work, len(tokens))
                    if (len(rows) == len(targets) == file_counts[0][digest] == file_counts[1][digest] == 1
                            and rows[0]['supported'] and targets[0]['supported']
                            and len(tokens) >= 12 and tokens[0] not in
                                ('let', 'Ok', 'Err', 'return', 'fn', 'struct', 'enum', 'impl', 'mod',
                                 'static', 'const', 'type', 'use', 'extern', '#')):
                        if head_counts is None or head_counts[digest] == 1:
                            seeds.append((rows[0], targets[0]))
                        elif (method_migration and parent_files is not None and head_counts[digest] > 1
                                and any(tuple(header[:7]) == ('#', '[', 'cfg', '(', 'test', ')', ']')
                                        for header in left['context'][0])
                                and statement_context(left, inventories[0][0], rows[0]) is not None
                                and statement_context(left, inventories[0][0], rows[0])
                                    == statement_context(right, inventories[1][0], targets[0])):
                            qualified_seeds.append((rows[0], targets[0]))
                if (not seeds and not method_migration
                        or parent_files is not None and parent_files(parent) != {name}):
                    continue
                if method_migration:
                    receiver_candidates.append((left_prefix, right_prefix, left, right))
                if not seeds and not qualified_seeds:
                    _construct_charge(work, sum(descriptor['row']['end'] - descriptor['row']['opening']
                        for descriptor in (left, right)))
                    if any(any(word in ('async', 'fn', '|', '||', '!') for word in
                            inventory[0].words[descriptor['row']['opening'] + 1:descriptor['row']['end']])
                            for descriptor, inventory in zip((left, right), inventories)):
                        continue
            candidates.append((left_prefix, right_prefix, left, right, seeds, parent, complete_test_rewrite,
                               prefix_only, qualified_seeds))
    left_counts = Counter(row[0] for row in candidates); right_counts = Counter(row[1] for row in candidates)
    pairs = dict(extra_pairs); receipts = list(extra_receipts); proved_functions = set(extra_proved); excerpts = []
    for receipt in extra_receipts:
        excerpts.extend(('\n'.join(source[receipt[side+'_range'][0]-1:receipt[side+'_range'][1]])+'\n').encode()
            for side,source in zip(('base','head'),(old,new)))
    receiver_left = Counter(row[0] for row in receiver_candidates)
    receiver_right = Counter(row[1] for row in receiver_candidates)
    for lp, rp, left, right in receiver_candidates:
        if receiver_left[lp] != 1 or receiver_right[rp] != 1:
            continue
        proof = test_declaration_header_obligations(name, (old, new), (before, after),
            (left, right), inventories, grouped, work)
        if proof is not None:
            mapped, receipt = proof
            pairs.update(mapped); receipts.append(receipt)
            excerpts.extend(('\n'.join(source[descriptor['group'][0] - 1:descriptor['group'][1]]) + '\n').encode()
                            for source, descriptor in zip((old, new), (left, right)))
    _construct_charge(work, 3 * (len(old) + len(new)))
    if line_operations is None:
        line_operations = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    equal_rows = [(line + 1, c + line - a + 1)
                  for tag, a, b, c, d in line_operations
                  if tag == 'equal' for line in range(a, b)]
    routine_pairs,routine_receipts,routine_proved=same_qualified_positive_test_obligations(
        name,(old,new),(before,after),descriptors,inventories,grouped,replacements,equal_rows,work,
        record_indexes,record_expansions)
    _construct_charge(work,len(pairs)+len(routine_pairs))
    routine_targets={target:line for line,target in pairs.items()}
    if any(line in pairs and pairs[line]!=target or target in routine_targets and routine_targets[target]!=line
           for line,target in routine_pairs.items()):
        raise ValueError('Ambiguous same-qualified test and retained source')
    pairs.update(routine_pairs);receipts.extend(routine_receipts);proved_functions.update(routine_proved)
    for receipt in routine_receipts:
        excerpts.extend(('\n'.join(source[receipt[side+'_range'][0]-2:receipt[side+'_range'][1]])+'\n').encode()
                        for side,source in zip(('base','head'),(old,new)))
    equal_positions = [row[0] for row in equal_rows]
    for left_prefix, right_prefix, left, right, seeds, parent, complete_test_rewrite, prefix_only, qualified_seeds in candidates:
        if left_counts[left_prefix] != 1 or right_counts[right_prefix] != 1:
            continue
        groups = left['group'], right['group']
        if len(groups[0][2]) != len(groups[1][2]):
            continue
        _construct_charge(work, len(replacements))
        selected = [row for row in replacements.values()
                    if groups[0][0] <= row['base_line'] <= groups[0][1]
                    and groups[1][0] <= row['head_line'] <= groups[1][1]]
        if not selected:
            continue
        if (left_prefix==right_prefix and left['attributes']==['#','[','inline',']','pub']
                and record_indexes is not None and record_expansions==([],[])):
            inline = retained_inline_callback_obligations(name,(old,new),(before,after),(left,right),
                inventories,selected,record_indexes(),head_counts,work)
            if inline is not None:
                mapped,receipt=inline
                if any(line in pairs and pairs[line]!=target for line,target in mapped.items()):
                    raise ValueError('Ambiguous inline callback correspondence')
                pairs.update(mapped);receipts.append(receipt)
                excerpts.extend(('\n'.join(source[group[0]-2:group[1]])+'\n').encode()
                                for source,group in zip((old,new),groups))
                continue
        if left_prefix == right_prefix:
            eager = eager_call_prefix_obligations(name, (old, new), (before, after),
                (left, right), inventories, grouped, work)
            if eager is not None:
                eager_pairs, eager_receipt = eager
                if any(line in pairs and pairs[line] != target for line, target in eager_pairs.items()):
                    raise ValueError('Ambiguous eager prefix correspondence')
                pairs.update(eager_pairs); receipts.append(eager_receipt)
                excerpts.extend(('\n'.join(source[group[0] - 1:group[1]]) + '\n').encode()
                                for source, group in zip((old, new), groups))
        if prefix_only:
            continue
        if (complete_test_rewrite or parent is not None and parent[0].startswith('method:')
                and (left['signature'] != right['signature'] or not seeds)):
            covered = fully_covered_replacement(name, old, new, before, after, (left, right),
                grouped, selected, equal_rows, work)
            if covered is not None and (seeds or qualified_seeds or all(len(owners) == len(group[2])
                    for owners, group in zip(covered[1]['fully_covered_replacement_owners'], groups))):
                mapped, receipt = covered
                if qualified_seeds and not seeds:
                    retained = qualified_test_retained_statements((old, new), (left, right), inventories,
                        grouped, file_counts, selected, qualified_seeds, receipt, work)
                    if retained is None:
                        continue
                    additional, statements = retained
                    if any(line in mapped and mapped[line] != target for line, target in additional.items()):
                        raise ValueError('Ambiguous qualified test statement correspondence')
                    mapped.update(additional)
                    receipt['pairs'] = [list(pair) for pair in sorted(mapped.items())]
                    receipt['qualified_test_statement'] = dict(parent=parent, statements=statements,
                        seed_digests=[row['digest'] for row, target in qualified_seeds],
                        global_head_occurrences=[head_counts[row['digest']] for row, target in qualified_seeds],
                        claim='Qualified identity only after complete positive owner trees; never partial proof')
                if any(line in pairs and pairs[line] != target for line, target in mapped.items()):
                    raise ValueError('Ambiguous fully covered replacement correspondence')
                pairs.update(mapped); receipts.append(receipt)
                proved_functions.add(groups[0][:2])
                excerpts.extend(('\n'.join(source[group[0] - 1:group[1]]) + '\n').encode()
                                for source, group in zip((old, new), groups))
                continue
            if complete_test_rewrite or not seeds:
                continue
        mapped = {}; spans = []; needed = set(); failed = False
        for old_row, new_row in seeds:
            needed.add(old_row['digest'])
        retained_sets = {id(candidate['retained_statements']): candidate['retained_statements']
                         for candidate in selected if candidate.get('retained_statements')}
        _construct_charge(work, len(selected) + sum(len(values) for values in retained_sets.values()))
        for values in retained_sets.values():
            needed.update(values)
        for candidate in selected:
            if candidate.get('residual'):
                mapped[candidate['base_line']] = candidate['head_line']
        for digest in needed:
            old_rows, new_rows = left['statements'].get(digest, []), right['statements'].get(digest, [])
            if len(old_rows) == len(new_rows) == 1:
                matched_rows = [(old_rows[0], new_rows[0])]
            else:
                if not old_rows or not new_rows:
                    failed = True; break
                contexts = []
                for descriptor, inventory, rows in zip((left, right), inventories, (old_rows, new_rows)):
                    _construct_charge(work, 3 * len(rows))
                    by_context = {}
                    for row in rows:
                        context = statement_context(descriptor, inventory[0], row)
                        by_context.setdefault(context, []).append(row)
                    contexts.append(by_context)
                if (None in contexts[0] or None in contexts[1] or contexts[0].keys() != contexts[1].keys()
                        or any(len(rows) != 1 for context in contexts for rows in context.values())):
                    failed = True; break
                _construct_charge(work, len(contexts[0]))
                matched_rows = [(rows[0], contexts[1][context][0]) for context, rows in contexts[0].items()]
            for rows in matched_rows:
                bounds = [(inventory[0].position(inventory[0].starts[row['first']])[0],
                           inventory[0].position(inventory[0].starts[row['end']])[0])
                          for inventory, row in zip(inventories, rows)]
                if bounds[0][1] - bounds[0][0] != bounds[1][1] - bounds[1][0]:
                    failed = True; break
                for number in range(bounds[0][0], bounds[0][1] + 1):
                    target = number + bounds[1][0] - bounds[0][0]
                    _construct_charge(work, len(old[number - 1]) + len(new[target - 1]) + 1)
                    if old[number - 1].strip() != new[target - 1].strip():
                        failed = True; break
                    if number in before and target in after:
                        mapped[number] = target
        if failed:
            continue
        first = bisect.bisect_left(equal_positions, groups[0][0])
        last = bisect.bisect_right(equal_positions, groups[0][1])
        _construct_charge(work, last - first)
        for index in range(first, last):
            line, target = equal_rows[index]
            _construct_charge(work, len(selected))
            if (groups[0][0] <= line <= groups[0][1] and groups[1][0] <= target <= groups[1][1]
                    and line in before and target in after and any(row['base_range'][0] <= line <= row['base_range'][1]
                   and row['head_range'][0] <= target <= row['head_range'][1] for row in selected)):
                _construct_charge(work, len(old[line - 1]))
                if re.search(r'\w', old[line - 1]):
                    mapped.setdefault(line, target)
        if seeds:
            if old[groups[0][1] - 1].strip() == new[groups[1][1] - 1].strip() == '}':
                mapped[groups[0][1]] = groups[1][1]
        if not mapped:
            continue
        _construct_charge(work, len(mapped) * (len(mapped).bit_length() + 3))
        non_executable = {line: target for line, target in mapped.items() if all(
            source_syntax_without_regions(inventory[0], number, compiled, source,
                                      line not in before and target not in after)
            or line not in before and target not in after
                and constant_record_field_without_regions(descriptor, inventory[0], number, compiled, source)
            for descriptor, inventory, number, compiled, source in zip(
                (left, right), inventories, (line, target), grouped, (old, new)))}
        macro_paint = {}; macro_bindings = {}
        mapped_sides = set(mapped), set(mapped.values())
        for line, target in mapped.items():
            if line in non_executable:
                continue
            proofs = [macro_literal_paint(descriptor, inventory, compiled, source, number, mapped_sides[side])
                      for side, (descriptor, inventory, compiled, source, number) in enumerate(
                          zip((left, right), inventories, grouped, (old, new), (line, target)))]
            if any(proof is False for proof in proofs):
                failed = True; break
            if proofs[0] is not None or proofs[1] is not None:
                if (any(proof is None for proof in proofs) or proofs[0][0][1:] != proofs[1][0][1:]
                        or proofs[0][1] != proofs[1][1] or mapped.get(proofs[0][0][0]) != proofs[1][0][0]):
                    failed = True; break
                macro_bindings[(proofs[0][0][0], proofs[1][0][0])] = proofs[0][0][1:]
                if proofs[0][1]:
                    macro_paint[line] = target
        if failed:
            continue
        non_executable.update(macro_paint)
        ordered = sorted((line, target) for line, target in mapped.items() if line not in non_executable)
        if not ordered:
            continue
        callbacks = [attached_callbacks(descriptor, inventory[0], compiled, ordered, side, source)
                     for side, (descriptor, inventory, compiled, source) in enumerate(
                         zip((left, right), inventories, grouped, (old, new)))]
        if any(value is None for value in callbacks):
            continue
        callback_keys = tuple(callbacks[0][0][0])
        if any(set(children) != set(callback_keys) for side, allowed in callbacks for children in side):
            continue
        vectors = []; geometries = []; valid = True
        for side, (source, compiled, group) in enumerate(zip((old, new), grouped, groups)):
            owners = group[2]; allowed = {id(owner) for owner in owners} | callbacks[side][1]
            states = []; shapes = []
            for instance, owner in enumerate(owners):
                vector = []; geometry = []
                for ordinal, row_pair in enumerate(ordered):
                    number = row_pair[side]; text = source[number - 1]
                    indent = len(text[:len(text) - len(text.lstrip())].encode())
                    low, high = (number, indent + 1), (number, len(text.encode()) + 1)
                    pieces = []
                    _construct_charge(work, len(owner['regions']))
                    for region in owner['regions']:
                        start, end = max(tuple(region[:2]), low), min(tuple(region[2:4]), high)
                        if start < end:
                            shape = (ordinal, start[1] - indent, end[1] - indent, *region[5:])
                            pieces.append((shape, int(region[4] > 0)))
                    if not pieces:
                        valid = False; break
                    _construct_charge(work, len(pieces) * (len(pieces).bit_length() + 3))
                    pieces.sort()
                    geometry.extend(shape for shape, state in pieces)
                    vector.extend(state for shape, state in pieces)
                for ordinal, key in enumerate(callback_keys, len(ordered)):
                    child, opening, closing = callbacks[side][0][instance][key]
                    code = inventories[side][0]
                    first = code.position(code.starts[opening])[0]
                    _construct_charge(work, len(child['regions']) * (len(child['regions']).bit_length() + 4))
                    pieces = []
                    for region in child['regions']:
                        normalized = []
                        for number, column in (region[:2], region[2:4]):
                            text = source[number - 1]
                            indent = len(text[:len(text) - len(text.lstrip())].encode())
                            normalized.extend((number - first, column - indent))
                        pieces.append(((ordinal, *normalized, *region[5:]), int(region[4] > 0)))
                    pieces.sort()
                    geometry.extend(shape for shape, state in pieces)
                    vector.extend(state for shape, state in pieces)
                shapes.append(tuple(geometry)); states.append(vector)
            target_lines = {row_pair[side] for row_pair in ordered}
            _construct_charge(work, len(ordered) + len(compiled[0])
                              + len(target_lines) * (len(target_lines).bit_length() + 1)
                              + sum(4 * len(source[line - 1]) + 1 for line in target_lines))
            line_ends = [(line, len(source[line - 1].encode('utf-8')) + 1)
                         for line in sorted(target_lines)]
            for owner in compiled[0]:
                if id(owner) in allowed:
                    continue
                _construct_charge(work, len(owner['regions']) * (len(line_ends).bit_length() + 1))
                if any(region_overlaps_observed_lines(region, line_ends) for region in owner['regions']):
                    valid = False
                    break
            vectors.append(states); geometries.append(shapes)
        if not valid:
            continue
        redundant_regions = None
        if any(shape != geometries[0][0] for side in geometries for shape in side):
            normalized = homogeneous_clipped_regions(geometries, vectors, work)
            if normalized is None:
                continue
            redundant_regions = dict(geometry=geometries, instance_states=vectors)
            geometries, vectors = normalized
            if any(shape != geometries[0][0] for side in geometries for shape in side):
                continue
        _construct_charge(work, (len(vectors[0]) * len(vectors[1]) + 1) * len(vectors[0][0]))
        matching = compiled_hit_state_matching(*vectors)
        if matching is None:
            raise ValueError('Replacement residual lost compiled-copy coverage')
        for line, target in mapped.items():
            if line in before and target in after:
                if line in pairs and pairs[line] != target:
                    raise ValueError('Ambiguous replacement residual correspondence')
                pairs[line] = target
        proved_functions.add((groups[0][0], groups[0][1]))
        _construct_charge(work, sum(sum(len(source[line]) + 1 for line in range(group[0] - 1, group[1]))
                                   for source, group in zip((old, new), groups)))
        excerpts.extend(('\n'.join(source[group[0] - 1:group[1]]) + '\n').encode()
                        for source, group in zip((old, new), groups))
        _construct_charge(work, sum(len(children) + 1 for side, allowed in callbacks for children in side))
        callback_receipt = [[dict(parent=parent['name'], children=[dict(name=child['name'],
            capsule_span=list(inventories[side][0].region(opening, closing)), regions=child['regions'])
            for child, opening, closing in children.values()])
            for parent, children in zip(group[2], callbacks[side][0])]
            for side, group in enumerate(groups)]
        _construct_charge(work, sum(4 * len(word) + 8 for key in callback_keys
                                   for part in ((key.preceding,), key.tokens, *key.context,
                                                *(tuple(value) for value in key.namespace),
                                                (key.function_disambiguator,)) for word in part))
        _construct_charge(work, sum(len(repr(binding)) for binding in macro_bindings.values()))
        receipt = dict(file=name, pairs=[[line, target] for line, target in mapped.items()
                                              if line in before and target in after],
            non_executable_rows=[[line, target] for line, target in non_executable.items()],
            macro_literal_rows=[[line, target] for line, target in macro_paint.items()],
            macro_literal_bindings=[dict(base_head_line=base_head, head_head_line=head_head,
                path=list(binding[0]), captures=list(binding[1]),
                context_sha256=hashlib.sha256(repr(binding).encode()).hexdigest())
                for (base_head, head_head), binding in macro_bindings.items()],
            callback_owners=callback_receipt,
            callback_capsule_sha256=[hashlib.sha256(repr(key).encode()).hexdigest() for key in callback_keys],
            base_range=list(groups[0][:2]), head_range=list(groups[1][:2]),
            capsule_sha256=[row[0]['digest'] for row in seeds],
            source_candidate=dict(raw_parent=parent[0] if parent else None,
                base_uniqueness='complete qualified-parent inventory' if parent_files is not None and parent else 'same function prefix',
                head_uniqueness='global complete-statement inventory' if head_counts is not None and parent else 'same function prefix'),
            geometry=[list(shape) for shape in geometries[0][0]],
            base_instance_states=vectors[0], head_instance_states=vectors[1], instance_matching=matching,
            claim='Complete-copy residual execution only; no unchanged-owner or deletion claim')
        if redundant_regions is not None:
            receipt['homogeneous_clipped_regions'] = redundant_regions
        receipts.append(receipt)
    if receipts:
        require_rustfmt_syntax(excerpts)
    return pairs, receipts, proved_functions


def homogeneous_clipped_regions(geometries, vectors, work):
    """Merge equivalent intervals only when every contributing state agrees.

    This operates inside each compiled owner after clipping to retained source.
    Added ancestry or subdivision does not change a completely hot or cold
    source slice. Mixed hot/cold slices cannot establish this equivalence.
    Nested callback regions retain their original geometry and states.
    """
    collapsed_shapes = []; collapsed_states = []
    for side_shapes, side_states in zip(geometries, vectors):
        shapes = []; states = []
        for geometry, vector in zip(side_shapes, side_states):
            _construct_charge(work, 2 * len(geometry) + 1)
            if len(geometry) != len(vector):
                return None
            projected = []; index = 0
            while index < len(geometry):
                end = index + 1
                while end < len(geometry) and geometry[end] == geometry[index]:
                    end += 1
                if len(geometry[index]) == 6 and all(state == vector[index] for state in vector[index:end]):
                    projected.append((geometry[index], vector[index]))
                else:
                    projected.extend(zip(geometry[index:end], vector[index:end]))
                index = end
            shapes.append(tuple(shape for shape, state in projected))
            states.append([state for shape, state in projected])
        collapsed_shapes.append(shapes); collapsed_states.append(states)
    if all(shape == collapsed_shapes[0][0] for side in collapsed_shapes for shape in side):
        return collapsed_shapes, collapsed_states
    geometries, vectors = collapsed_shapes, collapsed_states
    result_shapes = []; result_states = []
    for side_shapes, side_states in zip(geometries, vectors):
        shapes = []; states = []
        for geometry, vector in zip(side_shapes, side_states):
            _construct_charge(work, len(geometry) * (len(geometry).bit_length() + 5) + 1)
            if len(geometry) != len(vector):
                return None
            intervals = {}; projected = []
            for shape, state in zip(geometry, vector):
                if len(shape) == 6:
                    intervals.setdefault((shape[0], *shape[3:]), []).append((shape[1], shape[2], state))
                else:
                    projected.append((shape, state))
            for key, parts in intervals.items():
                state = parts[0][2]
                if any(part[2] != state for part in parts):
                    return None
                merged = []
                for first, last, _ in sorted(parts):
                    if merged and first <= merged[-1][1]:
                        merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
                    else:
                        merged.append((first, last))
                projected.extend(((key[0], first, last, *key[1:]), state) for first, last in merged)
            projected.sort()
            shapes.append(tuple(shape for shape, state in projected))
            states.append([state for shape, state in projected])
        result_shapes.append(shapes); result_states.append(states)
    return result_shapes, result_states


def _construct_replacements(old, new, work, head_inventory=None, compatible=None, inventories=None,
                            deferred=False, line_operations=None):
    if inventories is None:
        inventories = [_construct_inventory(source, work) for source in (old, new)]
    if any(value is None for value in inventories):
        return {}, inventories
    global_head = head_inventory() if head_inventory is not None else inventories[1][4:]
    if global_head is None:
        return {}, inventories
    all_bodies, all_statements = global_head
    functions = []; control_owners = []; control_excerpts = {}
    for inventory in inventories:
        rows = {}
        code = inventory[0]
        _construct_charge(work, 3 * len(inventory[1]) + sum(len(row['header'])
                          for row in inventory[1] if row['kind'] == 'fn'))
        by_opening = {row['opening']: row for row in inventory[1] if row['opening'] is not None}
        declarations = Counter(row['header'][row['header'].index('fn') + 1]
            for row in inventory[1] if row['kind'] == 'fn' and 'fn' in row['header']
            and row['header'].index('fn') + 1 < len(row['header']))
        identities = {}
        _construct_charge(work, len(inventory[1]))
        for row in inventory[1]:
            if row['kind'] == 'fn':
                first = inventory[0].position(inventory[0].starts[row['first']])[0]
                last = inventory[0].position(inventory[0].starts[row['end']])[0]
                _construct_charge(work, last - first + 1)
                for number in range(first, last + 1):
                    rows.setdefault(number, []).append(row)
                header = row['header']
                if not row['supported'] or 'fn' not in header:
                    continue
                at = header.index('fn')
                if at + 2 >= len(header):
                    continue
                declaration = header[at + 1]
                parameter_start = row['first'] + at + 2
                parameter_end = code.pairs.get(parameter_start)
                if (code.words[parameter_start] != '(' or parameter_end is None
                        or parameter_end >= row['opening']
                        or code.starts[row['opening']] - code.starts[row['first']] > 4096
                        or code.has_module_token(row['opening'], row['end'], work)):
                    continue
                parents = [by_opening.get(index) for index in _construct_ancestors(code, row['opening'], work)]
                _construct_charge(work, sum(4 * len(word) + 8 for parent in parents
                                           if parent is not None for word in parent['header']))
                if (declarations[declaration] == 1 and re.fullmatch(r'[A-Za-z_]\w*', declaration)
                        and all(parent is not None and parent['supported']
                                and parent['kind'] in ('mod', 'impl') for parent in parents)):
                    identities[id(row)] = (tuple(parent['header'] for parent in parents), header[:at], declaration,
                        tuple(code.words[parameter_start:parameter_end + 1]))
        functions.append(rows)
        control_owners.append(identities)
    _construct_charge(work, 3 * len(inventories[0][1]))
    statements = sorted((row for row in inventories[0][1] if row['kind'] == 'statement'), key=lambda row: row['first'])
    starts = [row['first'] for row in statements]
    base_digests = {row['digest'] for row in inventories[0][1]}
    nested_cache = {}
    def statement_at(inventory, number):
        rows = inventory[3].get(number, [])
        _construct_charge(work, 2 * len(rows))
        size = min((row['end'] - row['first'] for row in rows), default=-1)
        return [row for row in rows if row['end'] - row['first'] == size]
    proposals = {}
    if line_operations is None:
        line_operations = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    for tag, a, b, c, d in line_operations:
        if tag != 'equal':
            continue
        _construct_charge(work, b - a)
        for line in range(a + 1, b + 1):
            target = c + line - a
            _construct_charge(work, len(old[line - 1]))
            stripped = old[line - 1].strip()
            if stripped in ('}', '};', '})', '});'):
                pairs = [inventory[2].get(number, []) for inventory, number in zip(inventories, (line, target))]
                if all(len(rows) == 1 and rows[0]['kind'] == 'expression'
                       and rows[0]['header'][:1] in (('|',), ('||',)) for rows in pairs):
                    pairs = [statement_at(inventory, number) for inventory, number in zip(inventories, (line, target))]
            elif re.search(r'\w', stripped):
                pairs = [statement_at(inventory, number) for inventory, number in zip(inventories, (line, target))]
            else:
                pairs = [[], []]
            owner_replacement = (compatible is not None and compatible(line, target, 'owner')
                and (any(len(rows) != 1 for rows in pairs) or pairs[0][0]['kind'] == 'fn'
                     or pairs[0][0]['digest'] == pairs[1][0]['digest']))
            if owner_replacement:
                pairs = [rows.get(number, []) for rows, number in zip(functions, (line, target))]
            if any(len(rows) != 1 for rows in pairs):
                continue
            before, after = (rows[0] for rows in pairs)
            record = before.get('header') == after.get('header') == ('Self',)
            control = (stripped == '}' and before['kind'] in ('if', 'for', 'while', 'loop', 'match')
                and after['kind'] in ('if', 'for', 'while', 'loop', 'match')
                and before['header'] != after['header'] and before['body'] not in all_bodies
                and compatible is not None and compatible(line, target, 'control-endpoint'))
            control_functions = [rows.get(number, []) for rows, number in zip(functions, (line, target))]
            if control:
                keys = [identities.get(id(rows[0])) if len(rows) == 1 else None
                        for identities, rows in zip(control_owners, control_functions)]
                control = (keys[0] is not None and keys[1] is not None
                    and keys[0][:3] == keys[1][:3] and keys[0][3] != keys[1][3])
            if (not owner_replacement and (not before['supported']
                    or not after['supported'] and after['kind'] != 'struct')
                    or (before['kind'] == 'expression' or after['kind'] == 'expression') and not record
                    or before['digest'] == after['digest']
                    or (before['kind'] == after['kind'] and before['kind'] not in ('statement', 'fn') and not record and not control)
                    or before['kind'] == after['kind'] == 'fn'
                       and after['digest'] in base_digests):
                continue
            if not deferred and (before['body'] in all_bodies or before['digest'] in all_statements):
                continue
            key = before['first'], before['end'], owner_replacement
            if key not in nested_cache:
                first = bisect.bisect_left(starts, before['first'])
                last = bisect.bisect_right(starts, before['end'])
                _construct_charge(work, last - first)
                kept = {statements[index]['digest'] for index in range(first, last)
                    if statements[index]['end'] <= before['end'] and statements[index]['digest'] in all_statements}
                _construct_charge(work, len(kept) * (len(kept).bit_length() + 1))
                nested_cache[key] = tuple(sorted(kept))
            if control and nested_cache[key]:
                continue
            if nested_cache[key] and not deferred:
                if owner_replacement:
                    raise ValueError('Ambiguous unchanged work in replaced compiler owner')
                continue
            if compatible is not None and not owner_replacement and not control and not compatible(line, target, before['kind']):
                continue
            if control:
                for side, rows in enumerate(control_functions):
                    row = rows[0]; code = inventories[side][0]
                    start = code.position(code.starts[row['first']])[0]
                    end = code.position(code.starts[row['end']])[0]
                    excerpt_key = side, start, end
                    if excerpt_key not in control_excerpts:
                        source = (old, new)[side]
                        _construct_charge(work, sum(len(text) + 1 for text in source[start - 1:end]))
                        control_excerpts[excerpt_key] = ('\n'.join(source[start - 1:end]) + '\n').encode()
            proposals[line] = dict(base_line=line, head_line=target,
                base_construct=before['kind'], head_construct=after['kind'],
                base_construct_sha256=before['digest'], head_construct_sha256=after['digest'],
                base_range=[inventories[0][0].position(inventories[0][0].starts[before['first']])[0],
                            inventories[0][0].position(inventories[0][0].starts[before['end']])[0]],
                head_range=[inventories[1][0].position(inventories[1][0].starts[after['first']])[0],
                            inventories[1][0].position(inventories[1][0].starts[after['end']])[0]],
                residual=bool(re.search(r'\w', stripped)), retained_statements=nested_cache[key],
                claim='complete source replacement only; old counts remain in strict base ratios',
                summary_credit=[0, 0], mapped_credit=[0, 0])
            if control:
                proposals[line]['control_replacement'] = 'Same lexical function; complete old body and statements absent from head inventory'
                proposals[line]['control_owner_sha256'] = hashlib.sha256(repr(keys[0][:3]).encode()).hexdigest()
                proposals[line]['parameter_signatures_sha256'] = [hashlib.sha256(repr(key[3]).encode()).hexdigest() for key in keys]
    if control_excerpts:
        require_rustfmt_syntax(control_excerpts.values())
    return proposals, inventories


def _owner_line_counts(owner, work):
    work.spend(2 * len(owner['regions']))
    first = min(row[0] for row in owner['regions'])
    rows = [[row[0] - first + 1, row[1], row[2] - first + 1, *row[3:]]
            for row in owner['regions']]
    projected = _llvm22_rows(_llvm22_segments(rows, work), work)
    return {line + first - 1: count for line, count in projected}


def assertion_delimiter_source(name, source, inventory, line, work):
    if inventory is None or source[line-1].strip() != ');':
        return None
    file_scope = re.fullmatch(r'src/([A-Za-z_]\w*(?:/[A-Za-z_]\w*)*)\.rs',name,re.ASCII)
    if file_scope is None:
        return None
    code, rows = inventory[:2]
    first = bisect.bisect_left(code.starts,code.offsets[line-1])
    end = bisect.bisect_left(code.starts,code.offsets[line])
    if code.words[first:end] != [')',';']:
        return None
    paren = code.pairs[first]; macro = paren-2
    if (macro < 0 or code.words[macro] not in ('assert','assert_eq','assert_ne')
            or code.words[paren-1] != '!' or code.parents[macro] != code.parents[paren]
            or code.parents[macro] != code.parents[first+1]):
        return None
    _construct_charge(work,2*len(rows)+1)
    statements = [row for row in rows if row['kind']=='statement' and row['supported']
                  and row['first']==macro and row['end']==first+1]
    if len(statements) != 1:
        return None
    by_opening = {row['opening']:row for row in rows if row['opening'] is not None}
    enclosing = []
    for opening in _construct_ancestors(code,macro,work):
        container = by_opening.get(opening)
        if container is None:
            return None
        if container['kind'] == 'fn':
            header = container['header']; fn = header.index('fn')
            context = _boolean_module(code,{'start':container['first']})
            if context is None:
                return None
            start = code.position(code.starts[container['first']+fn])[0]
            final = code.position(code.ends[container['end']])[0]
            scope = ('omg_lib',*file_scope[1].split('/'),*context[0],header[fn+1])
            return (scope,(start,final),code.region(macro,first+1), statements[0]['digest'],
                    {*enclosing,code.region(container['opening'],container['end'])})
        if container['kind'] not in ('for','while','loop','if','match') or not container['supported']:
            return None
        enclosing.append(code.region(container['first'],container['end']))
    return None


def retired_async_test_constructor_delimiters(name, fragment, sources, counts, inventories,
                                                indexes, work, expansions):
    """Retire only redundant constructor paint on two source loop delimiters."""
    a,b,c,d,pending=fragment
    if (expansions!=([],[]) or b-a!=3 or d-c!=3 or pending!=list(range(a+1,b+1))
            or sources[0][a:b]!=sources[1][c:d]
            or any(line.strip()!='}' for line in sources[0][a:b])):
        return None
    observations=[]
    for side,(source,mapped,inventory,index,end) in enumerate(zip(sources,counts,inventories,indexes,(b,d))):
        code,rows=inventory[:2]
        _construct_charge(work,len(rows))
        functions=[r for r in rows if r['kind']=='fn' and code.position(code.ends[r['end']])[0]==end]
        if len(functions)!=1:return None
        function=functions[0];header=tuple(function['header']);at=header.index('fn');declaration=header[at+1]
        attrs=('#','[','tokio','::','test',']','async') if side==0 else ('#','[','test',']')
        if header[:at]!=attrs or header[at:]!=('fn',declaration,'(',')'):return None
        context=_boolean_module(code,{'start':function['first']})
        if context is None or context[:2]!=(['tests'],['tests']):return None
        _construct_charge(work,3*len(rows))
        loops=[];parent=function['opening'];last=function['end']
        for depth in range(2):
            choices=[r for r in rows if r['kind']=='for' and r['supported'] and code.parents[r['first']]==parent
                     and r['end']+1==last]
            if len(choices)!=1:return None
            loop=choices[0]
            if depth and loop['first']!=parent+1:return None
            words=tuple(loop['header'])
            if (len(words)<6 or words[0]!='for' or words[2:4]!=('in','[') or words[-1]!=']'
                    or re.fullmatch(r'[A-Za-z_]\w*',words[1],re.ASCII) is None):return None
            array=loop['first']+3;arguments=_boolean_arguments(code,array)
            if not arguments or len(arguments)>8:return None
            if depth and any(not _boolean_leaf(code.words[start:finish]) for start,finish in arguments):return None
            loops.append((loop,len(arguments),code.region(loop['first']+1,loop['first']+1),code.region(array,code.pairs[array])))
            parent=loop['opening'];last=loop['end']
        outer,inner=(row[0] for row in loops)
        if (code.position(code.ends[inner['end']])[0]!=end-2 or code.position(code.ends[outer['end']])[0]!=end-1
                or any(word in ('break','continue','return') for word in code.words[outer['opening']+1:outer['end']])):return None
        owners=index.inventories.get(name,())
        _construct_charge(work,sum(len(o['regions'])+len(o['name'])+1 for o in owners))
        names={};root_candidates=[]
        for owner in owners:
            shape=plain_rust_function_symbol(owner['name'])
            if shape is not None and shape.identifiers[-2:]==('tests',declaration):
                root_candidates.append((owner,shape))
        if not root_candidates:return None
        function_start=code.position(code.starts[function['first']+at]);body_start=code.position(code.starts[function['opening']])
        entry=(*function_start,*code.position(code.ends[function['opening']-1]));finish=code.region(function['end'],function['end'])
        whole=code.region(outer['first'],outer['end']);all_contributors=[];root_roles=[];closed=set()
        for root,shape in root_candidates:
            symbol=root['name'];value=root.get('count')
            if (index.name_counts[symbol]!=1 or len(root['filenames'])!=1 or index.files.get(root['filenames'][0])!=name
                    or type(value) is not int or not 0<value<COUNTER_LIMIT or root.get('branches') or root.get('mcdc_records')
                    or name.startswith('src/') and shape.identifiers[:-2] != ('omg_lib',*name.removeprefix('src/').removesuffix('.rs').split('/'))):return None
            if shape.identity in names:return None
            names[shape.identity]=True
            raw=root['regions']
            if any(len(r)!=8 or r[5:]!=[0,0,0] for r in raw):return None
            if ([r[4] for r in raw if tuple(r[:4])==entry]!=[value]
                    or [r[4] for r in raw if tuple(r[:4])==finish]!=[value]):return None
            if side==0:
                if len(raw)!=3 or {tuple(r[:4]) for r in raw}!={entry,whole,finish} or any(r[4]!=value for r in raw):return None
                bodies=[o for o in owners if direct_rust_callback_symbol(o['name'],symbol,shape.modules)
                        and any(tuple(r[:4])==(*body_start,body_start[0],body_start[1]+1) for r in o['regions'])]
                if len(bodies)!=1:return None
                body=bodies[0]
                if (index.name_counts[body['name']]!=1 or body['filenames']!=root['filenames']
                        or body.get('count')!=value or body.get('branches') or body.get('mcdc_records')
                        or any(r[5:]!=[0,0,0] for r in body['regions'])):return None
            else:body=root
            channels=[];expected=value
            for loop,size,binding,iterable in loops:
                if size<2:return None
                for bounds,target in ((binding,expected*size),(iterable,expected)):
                    matches=[r for r in body['regions'] if tuple(r[:4])==bounds]
                    if len(matches)!=1 or matches[0][4]!=target:return None
                    channels.append(matches[0])
                expected*=size
            closed.add(id(root));root_roles.append((shape.identity,(1,1),symbol))
            all_contributors.append(dict(root=symbol,count=value,entry=entry,completion=finish,
                constructor_raw=raw if side==0 else None,loop_channels=channels,
                unclaimed_body_regions_sha256=hashlib.sha256(repr(body['regions']).encode()).hexdigest(),
                unclaimed_body_cold_regions=[r[:4] for r in body['regions'] if r[4]==0]))
        if side==1:
            low=code.position(code.starts[function['first']]);high=code.position(code.ends[function['end']])
            if any(id(o) not in closed and any(tuple(r[:2])<high and low<tuple(r[2:4]) for r in o['regions']) for o in owners):return None
        retired=[]
        for number in (end-2,end-1,end):
            touching=[]
            for owner in owners:
                raw=[r for r in owner['regions'] if owner_covers_lines([r],number,number)]
                if raw:touching.append((owner,raw))
            if number==end:
                if {id(owner) for owner,raw in touching}!=closed or any(
                        raw!=[[*finish,owner['count'],0,0,0]] for owner,raw in touching):return None
                continue
            if side:
                if number in mapped or touching:return None
            else:
                if {id(owner) for owner,raw in touching}!=closed:return None
                if any(raw!=[[*whole,owner['count'],0,0,0]] for owner,raw in touching):return None
                if mapped.get(number)!=sum(owner['count'] for owner,raw in touching):return None
                retired.append(number)
        if mapped.get(end)!=sum(row['count'] for row in all_contributors):return None
        observations.append(dict(identity=tuple(names),roles=root_roles,owners=all_contributors,retired=retired,
            header=tuple(outer['header']),sizes=tuple(row[1] for row in loops),range=(function_start[0],end),
            source_sha256=hashlib.sha256(('\n'.join(source[function_start[0]-2:end])+'\n').encode()).hexdigest()))
    old,new=observations
    if old['identity']!=new['identity'] or old['header']!=new['header'] or old['sizes']!=new['sizes']:return None
    _construct_charge(work,len(old['roles'])*len(new['roles']))
    matching=compiled_hit_state_matching([row[1] for row in old['roles']],[row[1] for row in new['roles']])
    if matching is None:return None
    require_rustfmt_syntax([('\n'.join(source[row['range'][0]-2:row['range'][1]])+'\n').encode() for source,row in zip(sources,observations)])
    return dict(file=name,kind='retired-async-test-constructor-delimiters',retired_lines=old['retired'],pairs=[[b,d]],
        base_range=list(old['range']),head_range=list(new['range']),observations=observations,instance_matching=matching,
        summary_credit=[0,0],mapped_credit=[0,0],claim='Constructor-only delimiter paint retired; exact entry/completion and loop cardinalities retained; body and children unclaimed')


def retired_assertion_delimiter(name, line, target, sides, indexes, head_inventory, work):
    """Keep inherited assertion delimiter paint in the original baseline ratios."""
    before, after = (side[3] for side in sides)
    if (before.get(line,0) <= 0 or target in after or head_inventory is None
            or sides[0][0][line-1] != sides[1][0][target-1] or any(side[4] != [] for side in sides)):
        return None
    old = assertion_delimiter_source(name,*sides[0][:2],line,work)
    new = assertion_delimiter_source(name,*sides[1][:2],target,work)
    if old is None or new is None or old[0] != new[0] or old[3] in head_inventory[1]:
        return None
    old_scope,old_function,invocation,_,enclosing = old
    observed = []; total = 0; observer = _ObserverWork(work)
    for side, number in enumerate((line,target)):
        index = indexes[side]
        spans = sides[side][2]
        for owner in index.inventories.get(name, ()):
            regions = owner['regions']; _construct_charge(work,len(regions)+1)
            touching = [row for row in regions if owner_covers_lines([row],number,number)]
            if not touching:
                continue
            if side:
                return None
            symbol = owner['name']; _construct_charge(work,len(symbol)+len(touching))
            path = plain_rust_function_symbol(symbol)
            span = spans.get(id(owner))
            if (path is None or path.identifiers != old_scope or index.name_counts[symbol] != 1
                    or span is None or span[:2] != old_function or owner.get('branches') or owner.get('mcdc_records')
                    or any(row[5:] != [0,0,0] or tuple(row[:4]) not in enclosing
                           or not tuple(row[:2]) < invocation[:2] < invocation[2:] <= tuple(row[2:4])
                           for row in touching)):
                return None
            count = _owner_line_counts(owner,observer).get(line)
            if count is None:
                return None
            total += count
            observed.append(dict(owner=symbol,raw=touching,projected_count=count))
    if not observed or total != before[line]:
        return None
    return dict(file=name,kind='retired-assertion-delimiter',line=line,head_candidate=target,
                base_range=[invocation[0],invocation[2]],owners=observed,pairs=[],
                summary_credit=[0,0],mapped_credit=[0,0])


_DECLARATION_PARAMETER = re.compile(r"\s*(?:&\s*(?:'[A-Za-z_]\w*\s+)?(?:mut\s+)?self|"
                                    r"[A-Za-z_]\w*\s*:\s*[A-Za-z_]\w*)\s*,\s*", re.ASCII)


def declaration_signature_roles(code, args, opening, source, work):
    """Locate declaration-only lines by argument or return-type position."""
    close = code.pairs[args]
    args_line = code.position(code.starts[args])[0]
    return_line = code.position(code.starts[close])[0]
    body_line = code.position(code.starts[opening])[0]
    roles = {}
    _construct_charge(work, opening-args+body_line-args_line)
    for number in range(args_line+1, return_line):
        if _DECLARATION_PARAMETER.fullmatch(source[number-1]) is None:
            continue
        a = bisect.bisect_left(code.starts,code.offsets[number-1])
        b = bisect.bisect_left(code.starts,code.offsets[number])
        _construct_charge(work,b-a)
        if a < b and all(code.parents[token] == args for token in range(a,b)):
            roles['parameter',number-args_line,0,0] = number
    if code.words[close+1:close+2] != ['->']:
        return roles
    levels = {}; depth = 0
    for token in range(close+2,opening):
        word = code.words[token]
        if (word not in ('::','<','>',',','+','=')
                and (word in ('const','where','for','impl','extern','unsafe','async')
                     or re.fullmatch(r"'?[A-Za-z_]\w*",word,re.ASCII) is None)):
            return roles
        number = code.position(code.starts[token])[0]
        levels.setdefault(number,[depth,depth])
        depth += (word == '<') - (word == '>')
        if depth < 0:
            return roles
        levels[number][1] = depth
    if not depth:
        for number, (before,after) in levels.items():
            if number < body_line:
                roles['return-type',number-return_line,before,after] = number
    return roles


def retired_declaration_parameter(name, line, target, sides, indexes, head_names, work):
    """Discard a spurious parameter-line match while retaining all execution obligations."""
    file_scope = re.fullmatch(r'src/([A-Za-z_]\w*(?:/[A-Za-z_]\w*)*)\.rs', name, re.ASCII)
    if file_scope is None or indexes[1].declaration_ends is None:
        return None
    def nominal(parts):
        path = ('crate', parts[0])
        for part in parts[1:]:
            path = ('type', path, (part, ''))
        return path
    bindings = []
    for number, (source, inventory, spans, mapped), index in zip((line,target),sides,indexes,strict=True):
        if not 1 <= number < len(source):
            return None
        text = source[number-1]
        if (text != sides[0][0][line-1] or _DECLARATION_PARAMETER.fullmatch(text) is None
                or mapped.get(number, 0) <= 0 or inventory is None):
            return None
        code, rows = inventory[:2]
        first = bisect.bisect_left(code.starts,code.offsets[number-1])
        last = bisect.bisect_left(code.starts,code.offsets[number])
        _construct_charge(work, len(rows)+last-first+1)
        if first == last:
            return None
        args = code.parents[first]
        if (args is None or code.words[args] != '(' or code.words[last-1] != ','
                or any(code.parents[pos] != args for pos in range(first,last))):
            return None
        definitions = [row for row in rows if row['kind'] == 'fn' and row['supported']
                       and row['first'] < args < row['opening']]
        if len(definitions) != 1:
            return None
        definition, = definitions
        header = definition['header']; fn = header.index('fn'); method = header[fn+1]
        qualifiers = ' '.join(header[fn+2:args-definition['first']])
        if qualifiers and re.fullmatch(r"< '[A-Za-z_]\w*(?: , '[A-Za-z_]\w*)* >",qualifiers,re.ASCII) is None:
            return None
        begin = code.position(code.starts[definition['first']]); brace = code.position(code.starts[definition['opening']])
        end = code.position(code.ends[definition['end']]); entry = (*begin,brace[0],brace[1]-1)
        if not begin[0] < number < brace[0]:
            return None
        holding = code.parents[definition['opening']]
        crate = ('omg_lib', *file_scope[1].split('/'))
        trait = None; owner_type = None
        if holding is not None:
            _construct_charge(work, len(rows))
            implementations = [row for row in rows if row['opening'] == holding and row['kind'] == 'impl']
            if len(implementations) != 1:
                return None
            implementation, = implementations
            nominal_impl = ' '.join(implementation['header'])
            match = re.fullmatch(r'impl (super(?: :: super)* :: (?:[A-Za-z_]\w* :: )*[A-Za-z_]\w*) for ([A-Za-z_]\w*)',
                                 nominal_impl,re.ASCII)
            context = _boolean_module(code, {'start':implementation['first']})
            if match is None or context is None:
                return None
            path = tuple(match[1].split(' :: ')); supers = 0
            while supers < len(path) and path[supers] == 'super':
                supers += 1
            crate += tuple(context[0])
            if supers >= len(crate):
                return None
            trait = nominal((*crate[:-supers], *path[supers:])); owner_type = nominal((*crate,match[2]))
        low = code.position(code.starts[first]); high = code.position(code.ends[last-1]); roots = {}
        roles = declaration_signature_roles(code,args,definition['opening'],source,work)
        signature_low = (min(roles.values(),default=number),1)
        signature_high = (max(roles.values(),default=number)+1,1)
        exclusive = len(roles) > 1
        for owner in index.inventories.get(name, ()):
            symbol = owner['name']; regions = owner['regions']
            _construct_charge(work, (1+int(exclusive))*len(regions)+len(method)+1)
            touching = [r for r in regions if tuple(r[:2]) < high and low < tuple(r[2:4])]
            if not touching and not symbol.endswith(method):
                exclusive = exclusive and not any(tuple(r[:2]) < signature_high and signature_low < tuple(r[2:4])
                                                  for r in regions)
                continue
            _construct_charge(work, len(symbol))
            if trait is None:
                shape = plain_rust_function_symbol(symbol)
                matched = shape is not None and shape.identifiers == (*crate,method)
                identity = (shape.identity, re.match(r'_RNv(?:Nt)*C(s[0-9A-Za-z]{0,32}_)?',symbol)[1]) if matched else None
            else:
                shape = nominal_method_path(symbol)
                matched = (shape is not None and shape.kind == 'X' and not shape.callbacks
                           and shape.method == (method,'') and shape.namespace == nominal(crate)
                           and shape.trait == trait and shape.self_type == owner_type)
                identity = shape.copy_identity if matched else None
            if not matched and not touching:
                exclusive = exclusive and not any(tuple(r[:2]) < signature_high and signature_low < tuple(r[2:4])
                                                  for r in regions)
                continue
            count = owner.get('count'); span = spans.get(id(owner))
            if (not matched or identity in roots or index.name_counts[symbol] != 1 or span is None
                    or span[:2] != (begin[0],end[0]) or type(count) is not int or not 0 <= count < COUNTER_LIMIT
                    or any(owner.get(field) for field in ('branches','mcdc_records'))
                    or touching != [[*entry,count,0,0,0]] or not begin <= low < high <= entry[2:4]):
                return None
            roots[identity] = symbol,count
            exclusive = exclusive and [r for r in regions if tuple(r[:2]) < signature_high
                                      and signature_low < tuple(r[2:4])] == [[*entry,count,0,0,0]]
        total = sum(count for _,count in roots.values())
        if not roots or total != mapped[number]:
            return None
        covered_roles = ({role: slot for role,slot in roles.items() if mapped.get(slot) == total}
                         if exclusive else {})
        bindings.append((method,(begin[0],end[0]),roots,covered_roles))
    (method, old_range, old_roots, old_roles), (new_method, _, _, new_roles) = bindings
    if method == new_method or method in head_names or any(symbol in indexes[1].name_counts for symbol,_ in old_roots.values()):
        return None
    alternatives = indexes[1].declaration_ends.get(method[-2:],())
    _construct_charge(work, len(alternatives)*(len(method)+1))
    if any(symbol.endswith(method) for symbol in alternatives):
        return None
    candidates = {(old_roles[role],new_roles[role]):role[0] for role in old_roles.keys() & new_roles.keys()
                  if (old_roles[role],new_roles[role]) != (line,target)
                  and sides[0][0][old_roles[role]-1] == sides[1][0][new_roles[role]-1]}
    proof = dict(file=name, kind='retired-declaration-parameter', line=line, head_candidate=target,
                base_range=list(old_range), declaration=method, owners=sorted(old_roots.values()), pairs=[],
                summary_credit=[0,0], mapped_credit=[0,0])
    return proof,candidates


def retired_async_methods(name, probes, source, inventory, before, base_index, head_index,
                          head_inventory, head_declarations, work):
    """Prove the complete disappearance of a closed async owner with zero ratio credit."""
    if not probes or inventory is None or head_inventory is None:
        return []
    file_scope = re.fullmatch(r'src/([A-Za-z_]\w*(?:/[A-Za-z_]\w*)*)\.rs', name, re.ASCII)
    if file_scope is None:
        return []
    scope = ('crate', 'omg_lib')
    for part in file_scope[1].split('/'):
        scope = ('type', scope, (part, ''))
    owners = base_index.inventories.get(name, ())
    phases = compiled_async_function_groups(name, owners, base_index.files, source, work,
                                            inventory, base_index.name_counts, probes)
    code, rows = inventory[:2]
    head_owners = head_index.inventories.get(name, ())
    bodies, statements = head_inventory
    receipts = []
    for phase in phases.values():
        if phase.copies[0].identity is None:
            continue
        header = phase.source_context[1]
        method = header[header.index('fn') + 1]
        parent = nominal_method_path(phase.copies[0].constructor['name'])
        if method in head_declarations or parent.namespace != scope:
            continue
        first, last = phase.span
        _construct_charge(work, len(rows) + len(probes))
        candidates = [row for row in rows if row['kind'] == 'fn' and row['header'] == header
                      and code.position(code.starts[row['first']])[0] == first
                      and code.position(code.ends[row['end']])[0] == last]
        if len(candidates) != 1:
            continue
        row, = candidates
        opening = code.position(code.starts[row['opening']]); closing = code.position(code.ends[row['end']])
        if not any(first < line < opening[0] for line in probes) or row['body'] in bodies:
            continue
        _construct_charge(work, len(rows))
        descendants = [node for node in rows if row['opening'] <= node['first'] <= node['end'] < row['end']]
        _construct_charge(work, len(descendants))
        if (not descendants or any(node['kind'] not in ('if', 'for', 'while', 'loop', 'match', 'statement')
                or (node['body'] in bodies if node['body'] is not None else node['digest'] in statements)
                for node in descendants)):
            continue
        start = code.position(code.starts[row['first']]); touching = set()
        _construct_charge(work, len(owners))
        for owner in owners:
            _construct_charge(work, len(owner['regions']))
            if any(tuple(raw[:2]) < closing and start < tuple(raw[2:4]) for raw in owner['regions']):
                touching.add(id(owner))
        pairs = [(copy.constructor, copy.body) for copy in phase.copies]
        owned = [owner for pair in pairs for owner in pair]
        _construct_charge(work, len(owned) + len(touching))
        if touching != {id(owner) for owner in owned} or any(owner.get('branches') or owner.get('mcdc_records')
                or owner['name'] in head_index.name_counts for owner in owned):
            continue
        project = _ObserverWork(work); mapped = Counter()
        for constructor, body in pairs:
            mapped.update(_owner_line_counts({'regions': constructor['regions']+body['regions']}, project))
        _construct_charge(work, last-first+1)
        expected = {line: before[line] for line in range(first,last+1) if line in before}
        if not expected or mapped != expected:
            continue
        _construct_charge(work, sum(len(owner['name'])+1 for owner in head_owners))
        if any(method in owner['name'] for owner in head_owners):
            continue
        def comparable_name_survives():
            for symbol in head_index.name_counts:
                _construct_charge(work, min(len(symbol),8)+1)
                if symbol.startswith('_RNvM'):
                    _construct_charge(work, len(method)+1)
                    if symbol.endswith(method):
                        return True
                elif symbol.startswith('_RNCNvM'):
                    # A direct nominal callback adds up to 34 disambiguator bytes, one ordinal and six backreference bytes.
                    tail = symbol[-(len(method)+41):]
                    _construct_charge(work, len(tail)+1)
                    if method in tail:
                        return True
            return False
        if comparable_name_survives():
            continue
        receipts.append(dict(file=name, kind='retired-inherent-async-method', declaration=method,
            base_range=[first,last], owners=[[owner['name'] for owner in pair] for pair in pairs],
            mapped_rows=len(expected), summary_credit=[0,0], mapped_credit=[0,0]))
    return receipts


def retained_construct_anchors(name, old, new, before, after, base, head, base_files, head_files,
                               work=None, inventories=None, grouped=None):
    if old == new:
        return {}, []
    work = [20_000_000] if work is None else work
    _construct_charge(work, len(old) + len(new) + 1)
    if grouped is None:
        _construct_charge(work, len(base) + len(head))
        _construct_charge(work, sum(len(owner['regions']) + len(owner['filenames']) for owner in base + head))
        grouped = [_compiled_function_groups(name, owners, files, source, work) for owners, files, source in (
            (base, base_files, old), (head, head_files, new))]
    if any(value is None for value in grouped):
        return {}, []
    if inventories is None:
        inventories = [_construct_inventory(source, work) for source in (old, new)]
    if any(value is None for value in inventories):
        return {}, []
    projections = {}; observer_work = _ObserverWork(work); claims = {}; pairs = {}; excerpts = []
    declarations = {}; construct_rows = {}
    for inventory in inventories:
        code = inventory[0]
        _construct_charge(work, len(code.words))
        rows = {}
        for index, word in enumerate(code.words):
            if word == 'fn' and code.parents[index] is None:
                rows.setdefault(code.position(code.starts[index])[0], []).append(index)
        declarations[id(code)] = rows
        _construct_charge(work, len(inventory[1]) * (len(inventory[1]).bit_length() + 2))
        ordered = sorted(inventory[1], key=lambda row: row['first'])
        construct_rows[id(code)] = ordered, [code.position(code.starts[row['first']])[0] for row in ordered]
    def line_counts(side, owner):
        key = side, id(owner)
        if key not in projections:
            regions = owner['regions']
            _construct_charge(work, len(regions) + max(row[2] for row in regions) - min(row[0] for row in regions) + 1)
            projections[key] = _owner_line_counts(owner, observer_work)
        return projections[key]
    def plain_owner(code, group):
        positions = declarations[id(code)].get(group[0], [])
        if len(positions) != 1:
            return False
        at = positions[0] - 1
        while at >= 0 and code.words[at] not in (';', '}'):
            _construct_charge(work, 1)
            at -= 1
        return code.words[at + 1:positions[0]] in ([], ['pub'], ['pub', '(', 'crate', ')'])
    cleanup_function = 'install_managed_blocking'
    cleanup_signature = f'fn {cleanup_function}('
    cleanup_group = None
    if name == 'src/cli/tool.rs':
        matches = [group for prefix, group in grouped[1][1].items() if prefix.startswith(cleanup_signature)]
        if len(matches) == 1:
            cleanup_group = matches[0]
    for prefix, bg in grouped[0][1].items():
        hg = grouped[1][1].get(prefix)
        signature_changed = hg is None
        if signature_changed and prefix.startswith(cleanup_signature):
            hg = cleanup_group
        if hg is None or len(bg[2]) != len(hg[2]):
            continue
        groups = bg, hg
        if any(not plain_owner(inventory[0], group) for inventory, group in zip(inventories, groups)):
            continue
        selected = []
        for inventory, group in zip(inventories, groups):
            by_digest = {}
            code = inventory[0]
            rows, positions = construct_rows[id(code)]
            first = bisect.bisect_right(positions, group[0])
            last = bisect.bisect_left(positions, group[1])
            _construct_charge(work, last - first)
            for index in range(first, last):
                row = rows[index]
                if (row['kind'] in ('if', 'for', 'while', 'loop', 'match') and row['supported']
                        and group[0] < code.position(code.starts[row['first']])[0]
                        <= code.position(code.starts[row['end']])[0] < group[1]):
                    by_digest.setdefault(row['digest'], []).append(row)
            selected.append(by_digest)
        for digest, base_rows in selected[0].items():
            head_rows = selected[1].get(digest, [])
            if len(base_rows) != 1 or len(head_rows) != 1:
                continue
            capsules = base_rows[0], head_rows[0]
            ranges = [(inventory[0].position(inventory[0].starts[row['first']])[0],
                       inventory[0].position(inventory[0].starts[row['end']])[0])
                      for inventory, row in zip(inventories, capsules)]
            _construct_charge(work, 4 * sum(last - first + 1 for first, last in ranges))
            same_text = old[ranges[0][0]-1:ranges[0][1]]==new[ranges[1][0]-1:ranges[1][1]]
            result_cleanup = (same_text and hg is cleanup_group and prefix.startswith(cleanup_signature)
                              and all(row['header']==('if','let','Err','(','error',')','=','outcome')
                                      for row in capsules))
            if (before.get(ranges[0][1], 0) <= 0 or after.get(ranges[1][1], 0) <= 0
                    or ranges[0][1] - ranges[0][0] != ranges[1][1] - ranges[1][0]
                    or (same_text or signature_changed) and not result_cleanup
                    or [line.strip() for line in old[ranges[0][0] - 1:ranges[0][1]]]
                    != [line.strip() for line in new[ranges[1][0] - 1:ranges[1][1]]]):
                continue
            choices = []; shapes = []; symbols = set(); failed = False
            for side, (source, inventory, group, capsule, bounds) in enumerate(
                    zip((old, new), inventories, groups, capsules, ranges)):
                code = inventory[0]
                beginning = code.position(code.starts[capsule['first']])
                ending = code.position(code.ends[capsule['end']])
                if result_cleanup:
                    prefix_tokens = ['let','outcome',':','Result','<','(',')','>','=','run_install','(',')',';']
                    start = capsule['first']
                    holder = code.parents[start]
                    _construct_charge(work,len(prefix_tokens))
                    if (holder is None or code.parents[holder] is not None or start-len(prefix_tokens)<=holder
                            or code.words[start-len(prefix_tokens):start]!=prefix_tokens
                            or code.parents[start-len(prefix_tokens)]!=holder):
                        failed=True;break
                members = []; geometries = []; children = []
                def inside(owner):
                    _construct_charge(work, 2 * len(owner['regions']))
                    return [row for row in owner['regions']
                            if beginning <= tuple(row[:2]) < tuple(row[2:4]) <= ending]
                for parent in group[2]:
                    candidates = [parent] if any(owner_covers_lines([row], bounds[1], bounds[1])
                                                for row in inside(parent)) else []
                    shape = plain_rust_function_symbol(parent['name'])
                    if result_cleanup and (shape is None or shape.identifiers!=('omg_lib','cli','tool',cleanup_function)
                            or parent.get('branches') or parent.get('mcdc_records')
                            or any(tuple(row[:2])<ending and beginning<tuple(row[2:4])
                                   and not beginning<=tuple(row[:2])<tuple(row[2:4])<=ending for row in parent['regions'])):
                        failed=True;break
                    # This formatting-closure proof does not model disambiguated items.
                    if shape is not None and any(shape.disambiguators):
                        shape = None
                    _construct_charge(work, len(grouped[side][0]))
                    child_candidates = [] if shape is None or result_cleanup else [owner for owner in grouped[side][0]
                        if direct_rust_callback_symbol(owner['name'], parent['name'], shape.modules)
                        and any(owner_covers_lines([row], bounds[1], bounds[1]) for row in inside(owner))]
                    if len(candidates + child_candidates) != 1:
                        failed = True; break
                    owner = (candidates + child_candidates)[0]
                    if child_candidates:
                        _construct_charge(work, 3 * len(code.words) + 2 * len(owner['regions']))
                        lambdas = [opening for opening in _construct_ancestors(code, capsule['opening'], work)
                            if code.words[opening] == '{' and code.parents[opening] is not None
                            and code.words[code.parents[opening]] == '(']
                        lambdas = [opening for opening in lambdas
                            if code.words[code.parents[opening] + 1:opening]
                            == ['||', '->', 'std', '::', 'fmt', '::', 'Result']
                            and code.pairs[code.parents[opening]] == code.pairs[opening] + 1
                            and code.words[code.pairs[opening] + 1:code.pairs[opening] + 4] == [')', '(', ')']]
                        if len(lambdas) != 1 or type(owner.get('count')) is not int:
                            failed = True; break
                        opening = lambdas[0]
                        low = code.position(code.starts[code.parents[opening] + 1])
                        high = code.position(code.ends[code.pairs[opening]])
                        entry = (*code.position(code.starts[opening]), *code.position(code.ends[opening]))
                        entries = [row for row in owner['regions'] if tuple(row[:4]) == entry]
                        if (len(entries) != 1 or entries[0][4] != owner['count']
                                or any(not low <= tuple(row[:2]) < tuple(row[2:4]) <= high
                                       for row in owner['regions'])):
                            failed = True; break
                        symbols.update((parent['name'], owner['name'])); children.append(owner)
                    def normalize(position):
                        line, column = position
                        text = source[line - 1]
                        indent = len(text[:len(text) - len(text.lstrip())].encode())
                        return line - bounds[0], column - indent
                    geometries.append(tuple(sorted((*normalize(row[:2]), *normalize(row[2:4]), *row[5:])
                                                   for row in inside(owner))))
                    members.append(owner)
                if result_cleanup and not failed:
                    counts = before if side==0 else after
                    _construct_charge(work,(bounds[1]-bounds[0]+1)*len(members))
                    if any(sum(line_counts(side,owner).get(line,0) for owner in members)!=counts.get(line,0)
                           for line in range(bounds[0],bounds[1]+1)):
                        failed=True
                allowed = {id(owner) for owner in group[2] + children}
                _construct_charge(work, len(group[2]) + len(children) + sum(
                    len(owner['regions']) + 1 for owner in grouped[side][0]))
                if (failed or any(id(owner) not in allowed and any(
                        tuple(row[:2]) < ending and tuple(row[2:4]) > beginning for row in owner['regions'])
                        for owner in grouped[side][0])):
                    failed = True; break
                choices.append(members); shapes.append(geometries)
            if failed or not shapes or any(shape != shapes[0][0] for side in shapes for shape in side):
                continue
            decoder = None
            if symbols:
                decoded, decoder = demangle_plain_rust_callbacks(tuple(sorted(symbols)))
                for side, group in enumerate(groups):
                    for parent, owner in zip(group[2], choices[side]):
                        if owner is not parent and not re.fullmatch(
                                re.escape(decoded[parent['name']]) + r'::\{closure#[0-9]+\}', decoded[owner['name']]):
                            failed = True
                if failed:
                    continue
            _construct_charge(work, sum(len(group[2]) for group in groups))
            entry = claims.setdefault(prefix, dict(file=name, pairs=[], constructs=[],
                states=[[[] for _ in group[2]] for group in groups]))
            _construct_charge(work, (ranges[0][1] - ranges[0][0] + 1)
                              * (1 + sum(len(side) for side in choices)))
            mapped = [line for line in range(ranges[0][0], ranges[0][1] + 1)
                      if line in before and line + ranges[1][0] - ranges[0][0] in after]
            for line in mapped:
                target = line + ranges[1][0] - ranges[0][0]
                if line in pairs and pairs[line] != target:
                    raise ValueError('Ambiguous complete construct correspondence')
                pairs[line] = target; entry['pairs'].append([line, target])
                for side, number in ((0, line), (1, target)):
                    for state, owner in zip(entry['states'][side], choices[side]):
                        state.append(int(line_counts(side, owner).get(number, 0) > 0))
            entry['constructs'].append(dict(source_sha256=digest, base_range=list(ranges[0]),
                head_range=list(ranges[1]), decoder=decoder, geometry=[list(row) for row in shapes[0][0]]))
        if prefix in claims:
            _construct_charge(work, sum(sum(len(source[line]) + 1 for line in range(group[0] - 1, group[1]))
                                      for source, group in zip((old, new), groups)))
            excerpts.extend(('\n'.join(source[group[0] - 1:group[1]]) + '\n').encode()
                            for source, group in zip((old, new), groups))
    receipts = []
    for entry in claims.values():
        width = max((len(row) for side in entry['states'] for row in side), default=0)
        _construct_charge(work, (len(entry['states'][0]) * len(entry['states'][1]) + 1) * max(width, 1))
        states = [sorted(rows) for rows in entry.pop('states')]
        matching = compiled_hit_state_matching(*states)
        if matching is None:
            raise ValueError('Retained construct lost compiled-copy coverage')
        entry.update(base_instance_states=states[0], head_instance_states=states[1], instance_matching=matching)
        receipts.append(entry)
    if receipts:
        require_rustfmt_syntax(excerpts)
    return pairs, receipts


def source_opcodes(old, new, function_scopes, mapped, head_inventory=None, compatible=None,
                   work=None, inventories=None, replacements=None, line_operations=None):
    work = [20_000_000] if work is None else work
    if line_operations is None:
        line_operations = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    replacements = replacements if replacements is not None else ({} if old == new else _construct_replacements(
        old, new, work, head_inventory, compatible, inventories, line_operations=line_operations)[0])
    for row in _line_source_opcodes(old, new, function_scopes, mapped, line_operations):
        tag, a, b, c, d, block, suffix = row
        if tag != 'equal' or not any(line in replacements for line in range(a + 1, b + 1)):
            yield row
            continue
        first = a
        for index in range(a, b):
            if index + 1 not in replacements:
                continue
            if first < index:
                yield tag, first, index, c + first - a, c + index - a, block, suffix
            yield ('retain-obligation' if replacements[index + 1].get('residual') else 'replace-construct'), index, index + 1, c + index - a, c + index - a + 1, replacements[index + 1], False
            first = index + 1
        if first < b:
            yield tag, first, b, c + first - a, d, block, suffix


def _line_source_opcodes(old, new, function_scopes, mapped, line_operations):
    old_text, new_text = "\n" + "\n".join(old) + "\n", "\n" + "\n".join(new) + "\n"
    local = {}
    for tag, a, b, c, d in line_operations:
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
            braces, offsets = info[3].braces, info[3].offsets
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
        braces, code = new_info[3].braces, new_info[3].code
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
    module_tokens: tuple

    def has_module_token(self, start, end, work):
        _construct_charge(work, len(self.module_tokens).bit_length() + 1)
        index = bisect.bisect_left(self.module_tokens, start)
        return index < len(self.module_tokens) and self.module_tokens[index] < end

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
    module_tokens = []
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
        if word == 'mod':
            module_tokens.append(index)
        elif word in ('(', '[', '{'):
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
    return _BooleanSource(text, words, starts, ends, parents, pairs, offsets, tuple(module_tokens))


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
                call=code.region(call, call), continuation=continuation, arguments=arguments)


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
                                    retained, base_segments=None, head_segments=None, eager_peers=False, work=None):
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
        peers = []
        if eager_peers:
            for ordinal, arguments in enumerate(zip(bc['arguments'], hc['arguments'])):
                if work is not None:
                    _construct_charge(work, 2 + sum(end - start for start, end in arguments))
                token_values = [code.words[start:end] for code, (start, end) in zip(codes, arguments)]
                if token_values[0] != token_values[1] or not _boolean_leaf(token_values[0]):
                    continue
                observations = []; lines = []
                for code, source, counts, owner, segments, (start, end) in zip(
                        codes, (old, new), (before, after), (bo, ho),
                        (base_segments, head_segments), arguments):
                    if work is not None:
                        _construct_charge(work, len(owner['regions']) + len(segments) + end - start + 1)
                    span = code.region(start, end - 1)
                    line = span[0]
                    if line != span[2] or counts.get(line, 0) <= 0:
                        break
                    encoded = source[line - 1].encode()
                    if (encoded[:span[1] - 1].strip()
                            or re.fullmatch(rb'\s*,?\s*', encoded[span[3] - 1:]) is None):
                        break
                    rows = [row for row in owner['regions'] if touches(row, span[:2], span[2:])]
                    token_segments = segment_rows(segments, span[:2], span[2:])
                    if (not rows or any(row[4] <= 0 for row in rows)
                            or not any(tuple(row[:2]) <= span[:2] and tuple(row[2:4]) >= span[2:] for row in rows)
                            or not token_segments or any(not row[3] or row[5] or row[2] <= 0 for row in token_segments)
                            or max(row[2] for row in token_segments) != counts[line]):
                        break
                    lines.append(line)
                    observations.append(dict(source_span=span, regions=rows, segments=token_segments))
                if len(observations) == 2:
                    peers.append(dict(pairs=[lines], argument_ordinal=ordinal + 1,
                        base_observation=observations[0], head_observation=observations[1],
                        claim='Source-identical eager leaf evaluation with positive mapped observations only'))
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
            **({'eager_argument_peers': peers} if eager_peers else {}),
            base_call_segments=witness_segments[0], head_witness_segments=witness_segments[1:]))
    return results


def retained_specialization_additions(name, sides, indexes, work, *, path_reference=False):
    """Match every original specialization and observe additional consumers in full."""
    layouts = []; roles = []; spans = []; containers = []; summaries = []; source_bytes = []; compiled_methods = set()
    source_tokens = []; previous_source = None; inventory = None
    for (source, counts, candidates), index in zip(sides, indexes, strict=True):
        _construct_charge(work, sum(3*len(owner['regions'])+1 for owner in candidates))
        bounds = {source_owner_span(owner, name, index.files, source) for owner in candidates}
        if len(bounds) != 1 or None in bounds:
            return None
        (first, last, declaration, _), = bounds
        if declaration is None:
            return None
        spans.append((first, last)); source_bytes.append(source[first-1:last])
        _construct_charge(work,len(source))
        if source!=previous_source:
            _construct_charge(work, sum(len(line)+1 for line in source))
            inventory = _construct_inventory(source, work)
            previous_source = source
        if inventory is None:
            return None
        code, rows = inventory[:2]
        _construct_charge(work, 2*len(rows))
        methods = [row for row in rows if row['kind'] == 'fn' and row['supported']
                   and code.position(code.starts[row['first']])[0] == first
                   and code.position(code.ends[row['end']])[0] == last]
        if len(methods) != 1:
            return None
        method = methods[0]; holding = code.parents[method['opening']]
        if holding is None or code.parents[holding] is not None:
            return None
        enclosing = [row for row in rows if row['opening'] == holding]
        if len(enclosing) != 1:
            return None
        container = enclosing[0]['header']; header = method['header']
        if path_reference:
            if (enclosing[0]['kind'] != 'impl' or len(container) != 2 or container[0] != 'impl'
                    or header[:2] != ('pub', 'fn') or len(header) != 19
                    or header[3:6] != ('(', header[4], ':')
                    or header[6:10] != ('&', 'str', ',', header[9])
                    or header[10:] != (':', 'impl', 'AsRef', '<', 'Path', '>', ')', '->', 'Self')
                    or _boolean_attributes(code, enclosing[0]['first']) != []
                    or _boolean_attributes(code, method['first']) != []):
                return None
            method_name = header[2]
            source_tokens.append(code.words)
            _construct_charge(work, len(code.words))
        else:
            if (enclosing[0]['kind'] != 'trait' or len(container) < 3 or container[:2] != ('pub', 'trait')
                    or header[:1] != ('fn',) or header[2:6] != ('(', '&', 'self', ')')):
                return None
            method_name = header[1]
        owner_roles = {}; projections = Counter(); geometries = set()
        containers.append(container)
        entire_file = index.inventories.get(name, ())
        _construct_charge(work, sum(len(owner['regions'])+1 for owner in entire_file))
        touching = {id(owner) for owner in entire_file if any(
            region[0] <= last and region[2] >= first for region in owner['regions'])}
        if touching != {id(owner) for owner in candidates}:
            return None
        observer = _ObserverWork(work)
        for owner in candidates:
            symbol = owner['name']; regions = owner['regions']; count = owner.get('count')
            _construct_charge(work, len(symbol)+3*len(regions)+1)
            shape = nominal_method_path(symbol, path_reference=path_reference)
            if (shape is None or shape.callbacks or shape.method[0] != method_name
                    or index.name_counts[symbol] != 1 or type(count) is not int or not 0 <= count < COUNTER_LIMIT
                    or owner.get('branches') or owner.get('mcdc_records')):
                return None
            geometry, states = fragment_region_states(owner, first, last, source, work)
            if path_reference:
                namespace = shape.namespace
                for part in reversed(name.removeprefix('src/').removesuffix('.rs').split('/')):
                    if namespace[0] != 'type' or namespace[-1] != (part, ''):
                        return None
                    namespace = namespace[1]
                if (namespace[0] != 'crate'
                        or shape.self_type != ('type', shape.namespace, (container[1], ''))
                        or shape.type_argument == ('placeholder',) and (count or any(states))):
                    return None
                compiled_methods.add((shape.parent_scope, shape.method))
            else:
                if shape.kind != 'Y' or shape.trait[0] != 'type' or shape.trait[-1][0] != container[2]:
                    return None
                compiled_methods.add((shape.trait, shape.method))
            geometries.add(geometry)
            signature = (shape.parent_scope, shape.method, shape.instantiating_crate[0], shape.type_argument)
            owner_roles.setdefault(signature, []).append((shape.copy_identity, (int(count > 0), *states)))
            projections.update(_owner_line_counts(owner, observer))
        summary = {line: counts[line] for line in range(first,last+1) if line in counts}
        if len(geometries) != 1 or not summary or projections != summary:
            return None
        if any(len({identity for identity, _ in entries}) != len(entries) for entries in owner_roles.values()):
            return None
        summaries.append(summary); layouts.append(next(iter(geometries))); roles.append(owner_roles)
    if (source_bytes[0] != source_bytes[1] or containers[0] != containers[1]
            or layouts[0] != layouts[1] or len(compiled_methods) != 1
            or path_reference and source_tokens[0] != source_tokens[1]):
        return None
    base, head = roles
    added = head.keys() - base.keys()
    if not added or base.keys() - head.keys() or any(not all(states) for role in added for _, states in head[role]):
        return None
    if path_reference and {role[-1] for role in added} - {role[-1] for role in base}:
        return None
    for role, previous in base.items():
        current = head[role]
        before_ids, before_states = zip(*previous, strict=True)
        after_ids, after_states = zip(*current, strict=True)
        _construct_charge(work, len(before_states)*len(after_states)*len(before_states[0]))
        if compiled_hit_state_matching(before_states, after_states, (before_ids, after_ids)) is None:
            return None
    offset = spans[1][0] - spans[0][0]
    if summaries[1].keys() != {line+offset for line in summaries[0]}:
        return None
    return dict(file=name, base_range=spans[0], head_range=spans[1],
                pairs=[[line,line+offset] for line in summaries[0]],
                base_types=len(base), head_types=len(head), added_types=sorted(map(repr, added)))


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
    construct_work = [SOURCE_CONSTRUCT_WORK_CAPACITY]; complete_head = []; head_inventories = {}; head_capsule_counts = Counter()
    head_fn_names = set(); retirement_receipts = []; retired_declaration_receipts = []
    specialization_receipts = {}
    retired_assertion_receipts = []; retired_constructor_receipts = []
    parent_file_cache = {}; method_parent_files = None; plain_parent_files = None; owner_indexes = None
    def source_owner_indexes():
        nonlocal owner_indexes
        if owner_indexes is None:
            owner_indexes = (index_compiled_owner_sources(bf, base_files, construct_work, bs.keys()),
                             index_compiled_owner_sources(hf, head_files, construct_work, bs.keys(),
                                                          index_declaration_ends=True))
        return owner_indexes
    def parent_files(parent):
        nonlocal method_parent_files, plain_parent_files
        method_scope = parent[0].startswith('method:')
        key = method_scope, parent[1]
        if key not in parent_file_cache:
            if method_scope:
                if method_parent_files is None:
                    method_parent_files = compiled_method_parent_files(bf, base_files, construct_work)
                scopes, unknown = method_parent_files
                locations = scopes.get(parent[1], set())
                _construct_charge(construct_work, len(parent[1]) + len(locations) + len(unknown))
                parent_file_cache[key] = locations | unknown
            else:
                if plain_parent_files is None:
                    plain_parent_files = compiled_plain_parent_files(bf, base_files, construct_work)
                parent_file_cache[key] = plain_parent_files(parent[1])
        return parent_file_cache[key]
    def head_constructs(name):
        if name not in head_inventories:
            head_inventories[name] = _construct_inventory(
                head_sources[name].decode('utf-8').splitlines(), construct_work)
        return head_inventories[name]
    def head_construct_inventory():
        if not complete_head:
            bodies = set(); statements = set()
            for name in head_sources:
                inventory = head_constructs(name)
                if inventory is None:
                    complete_head.append(None)
                    break
                _construct_charge(construct_work, len(inventory[4]) + len(inventory[5]))
                bodies.update(inventory[4]); statements.update(inventory[5])
                _construct_charge(construct_work, len(inventory[1]))
                for row in inventory[1]:
                    if row['kind'] == 'statement':
                        head_capsule_counts[row['digest']] += 1
                    elif row['kind'] == 'fn':
                        header = row['header']; _construct_charge(construct_work, len(header))
                        at = header.index('fn')+1
                        if at < len(header):
                            head_fn_names.add(header[at].removeprefix('r#'))
            else:
                complete_head.append((bodies, statements))
        return complete_head[0]
    removed = {}; deleted_mapped = deleted_hit = 0; paint_receipts = []; serial_receipts = []; serial_removed = {}
    positive_receipts = []; endpoint_receipts = []; boolean_receipts = []
    replacement_receipts = []; construct_receipts = []; completion_receipts = []; obligation_receipts = []
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
            _construct_charge(construct_work, len(source) + sum(len(owner['regions']) + len(owner['filenames'])
                                                              for owner in functions))
            occurrences = Counter(source)
            for function in functions:
                span = source_owner_span(function, name, files, source)
                if span is not None:
                    spans[id(function)] = span
                    if span[2] is not None and occurrences[span[2]] == 1:
                        declarations.setdefault(span[2], []).append(function)
                    if span[3] is not None and occurrences[span[3]] == 1:
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
        source_structure = None
        shared_prefixes = None
        if base_sources[name] == head_sources[name]:
            _construct_charge(construct_work, sum(len(line) + 1 for line in old))
            source_structure = _source_structural_map(old)
            if source_structure is not None:
                _construct_charge(construct_work,len(base_spans)+len(head_spans))
                spans = dict.fromkeys(span[:2] for side in (base_spans,head_spans) for span in side.values())
                shared_prefixes = source_function_prefixes(old, spans, construct_work, source_structure)
        grouped = [_compiled_function_groups(name, owners, files, source, construct_work, source_structure,
                                             spans, shared_prefixes)
                   for owners, files, source, spans in ((owners_by_file.get(name, []), base_files, old, base_spans),
                                                       (head_owners_by_file.get(name, []), head_files, new, head_spans))]
        base_groups, head_groups = (value[1] if value is not None else {} for value in grouped)
        _construct_charge(construct_work, sum(len(group[2]) + 1
            for groups in (base_groups, head_groups) for group in groups.values()))
        closed = [{frozenset(id(owner) for owner in group[2]) for group in groups.values()}
                  for groups in (base_groups, head_groups)]
        for declaration in base_declarations.keys() & head_declarations.keys():
            previous, current = base_declarations[declaration], head_declarations[declaration]
            _construct_charge(construct_work, len(previous) + len(current) + 1)
            if frozenset(map(id, previous)) not in closed[0]:
                continue
            if len(previous) != len(current):
                if len(current) > len(previous) and frozenset(map(id, current)) in closed[1]:
                    candidates = (*previous, *current)
                    path_reference = all(owner['name'].startswith('_RINvM') for owner in candidates)
                    default_trait = all(owner['name'].startswith('_RNvY') for owner in candidates)
                    proof = retained_specialization_additions(name, ((old, before, previous), (new, after, current)),
                        source_owner_indexes(), construct_work, path_reference=path_reference) if (
                            path_reference or default_trait) else None
                    if proof is not None:
                        for line, target in proof['pairs']:
                            if line in anchored and anchored[line] != target:
                                raise ValueError('Ambiguous retained specialization owner')
                            anchored[line] = target
                        key = 'additive_path_reference_copies' if path_reference else 'additive_trait_copies'
                        specialization_receipts.setdefault(key, []).append(proof)
                        continue
                raise ValueError(f'Ambiguous unchanged source correspondence: {name}; '
                                 'Retained covered line requires a complete compiled-copy inventory')
            if frozenset(map(id, current)) not in closed[1]:
                raise ValueError(f'Ambiguous unchanged source correspondence: {name}; '
                                 'Retained covered line requires a closed compiled-owner layout')
        for prefix, group in base_groups.items():
            target = head_groups.get(prefix)
            if target is not None and len(group[2]) == len(target[2]):
                scope = (*group[:2], *target[:2])
                if scope not in function_scopes and not any(
                        scope != other and (max(scope[0], other[0]) <= min(scope[1], other[1])
                                             or max(scope[2], other[2]) <= min(scope[3], other[3]))
                        for other in function_scopes):
                    function_scopes.append(scope)
                if (len(group[2]) > 1 and before.get(group[1], 0) > 0 and after.get(target[1], 0) > 0
                        and old[group[1] - 1].strip() == new[target[1] - 1].strip() == '}'):
                    _construct_charge(construct_work, len(group[2]) + len(target[2])
                                      + len(group[2]) * len(target[2]))
                    work = _ObserverWork(construct_work)
                    states = [[[int(_owner_line_counts(owner, work).get(g[1], 0) > 0)]
                               for owner in g[2]] for g in (group, target)]
                    states = [sorted(rows) for rows in states]
                    matching = compiled_hit_state_matching(*states)
                    if matching is None:
                        raise ValueError(f'Function completion lost compiled-copy coverage: '
                            f'{name}:{group[1]} -> {target[1]}; '
                            f'base_states={states[0]} head_states={states[1]}')
                    anchored[group[1]] = target[1]
                    completion_receipts.append(dict(file=name, pairs=[[group[1], target[1]]],
                        source_prefix_sha256=hashlib.sha256(prefix.encode()).hexdigest(),
                        base_instance_states=states[0], head_instance_states=states[1], instance_matching=matching))
        inventories = None if old == new else (_construct_inventory(old, construct_work), head_constructs(name))
        construct_pairs, witnesses = retained_construct_anchors(name, old, new, before, after,
            bf, hf, base_files, head_files, construct_work, inventories, grouped)
        anchored.update(construct_pairs); construct_receipts.extend(witnesses)
        retained = {}; gone = set(); unresolved_fragments = []; deferred_fragments = {}; neutral_declarations = {}
        declaration_roles = {}
        record_states = {}; record_projections = {}; record_work = _ObserverWork(construct_work)
        _construct_charge(construct_work, len(base_groups) + len(head_groups))
        missing_prefixes = base_groups.keys() - head_groups.keys()
        head_functions = set()
        if missing_prefixes and old != new:
            _construct_charge(construct_work, sum(len(line) + 1 for line in new))
            head_functions.update(re.findall(r'(?=\bfn\s+(\w+)\b)', '\n'.join(new)))
        removed_prefixes = set()
        for prefix in missing_prefixes:
            _construct_charge(construct_work, len(prefix))
            if re.search(r'\bfn\s+(\w+)', prefix)[1] not in head_functions:
                removed_prefixes.add(prefix)
        partitions = []
        for groups in (base_groups, head_groups):
            rows = {}
            for prefix, group in groups.items():
                _construct_charge(construct_work, group[1] - group[0] + 1)
                for number in range(group[0], group[1] + 1):
                    rows[number] = (prefix, group) if number not in rows else None
            partitions.append(rows)
        def compatible_replacement(line, target, kind):
            if kind == 'control-endpoint':
                return before.get(line, 0) > 0 and target not in after
            left, right = partitions[0].get(line), partitions[1].get(target)
            if kind == 'owner':
                return (left is not None and right is not None and left[0] in removed_prefixes
                        and right[0] not in base_groups)
            if kind == 'fn':
                return left is not None and left[1][1] == line and left[0] in removed_prefixes
            scopes = ([(*left, right[1])] if left is not None and right is not None
                      and left[0] == right[0] and len(left[1][2]) == len(right[1][2]) else [])
            if kind == 'expression':
                if len(scopes) != 1:
                    return False
                prefix, bg, hg = scopes[0]
                _construct_charge(construct_work, len(bg[2]) + len(hg[2]))
                entry = record_states.setdefault(prefix, [[[] for _ in group[2]] for group in (bg, hg)])
                for side, group, number in ((0, bg, line), (1, hg, target)):
                    for state, owner in zip(entry[side], group[2]):
                        key = side, id(owner)
                        if key not in record_projections:
                            record_projections[key] = _owner_line_counts(owner, record_work)
                        state.append(int(record_projections[key].get(number, 0) > 0))
                return True
            _construct_charge(construct_work, len(function_scopes))
            return (any(start <= line <= end and newstart <= target <= newend
                        for start, end, newstart, newend in function_scopes)
                    or kind == 'statement' and left is not None and right is not None
                    and left[0] in removed_prefixes and len(left[1][2]) == len(right[1][2]))
        line_operations = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
        replacement_candidates = {} if old == new else _construct_replacements(
            old, new, construct_work, head_construct_inventory, compatible_replacement, inventories,
            deferred=True, line_operations=line_operations)[0]
        eager_witnesses = None
        eager_pairs = {row['base_line']: row['head_line'] for row in replacement_candidates.values()
                       if row.get('residual') and before.get(row['base_line'], 0) > 0
                       and row['head_line'] not in after
                       and re.fullmatch(r'\s*(?:true|false)\s*,?\s*', old[row['base_line'] - 1])
                       and old[row['base_line'] - 1].strip() == new[row['head_line'] - 1].strip()}
        if (eager_pairs and bs[name]['expansions'] == hs[name]['expansions'] == []
                and all(raw in (lines, lines + b'\n') for raw, lines in zip(
                    (base_sources[name], head_sources[name]),
                    tuple('\n'.join(source).encode() for source in (old, new))))):
            _construct_charge(construct_work, 8 * sum(len(inventory[0].words) for inventory in inventories)
                              * len(eager_pairs) + len(bf) + len(hf)
                              + sum(len(line) + 1 for line in old + new))
            eager_witnesses = retained_boolean_argument_paint(name, old, new, before, after, bf, hf,
                base_files, head_files, eager_pairs, bs[name]['segments'], hs[name]['segments'], eager_peers=True, work=construct_work)
            for witness in eager_witnesses:
                for peer in witness.get('eager_argument_peers', []):
                    for line, target in peer['pairs']:
                        if line in anchored and anchored[line] != target:
                            raise ValueError('Ambiguous eager argument correspondence')
                        anchored[line] = target
        proved_eager_pairs = {(line, target) for witness in eager_witnesses or []
                              for line, target in witness['pairs']}
        obligation_pairs, residual_receipts, proved_functions = retained_replacement_obligations(
            name, old, new, before, after, inventories, grouped, replacement_candidates,
            construct_work, head_capsule_counts, parent_files, record_indexes=source_owner_indexes,
            record_expansions=(bs[name]['expansions'],hs[name]['expansions']),island_blobs=(base_sources,head_sources),
            line_operations=line_operations) if inventories is not None else ({}, [], set())
        anchored.update(obligation_pairs); obligation_receipts.extend(residual_receipts)
        retained_statement_rows = {}
        def retire_declaration(line,target):
            if (line in anchored or line in deferred_fragments or inventories is None
                    or old[line-1] != new[target-1] or before.get(line,0) <= 0):
                return False
            if line in neutral_declarations:
                return target == neutral_declarations[line][0]
            candidate = declaration_roles.get((line,target))
            if candidate is not None:
                proof, role = candidate
                proof.setdefault('other_signature_lines', []).append(dict(line=line,head_candidate=target,role=role))
                neutral_declarations[line] = target,proof
                return True
            if _DECLARATION_PARAMETER.fullmatch(old[line-1]) is None or head_construct_inventory() is None:
                return False
            sides = ((old,inventories[0],base_spans,before),(new,inventories[1],head_spans,after))
            observed = retired_declaration_parameter(name,line,target,sides,source_owner_indexes(),head_fn_names,construct_work)
            if observed is None:
                return False
            proof, candidates = observed
            neutral_declarations[line] = target,proof
            _construct_charge(construct_work,len(candidates))
            for coordinates, role in candidates.items():
                declaration_roles[coordinates] = proof,role
            retired_declaration_receipts.append(proof)
            return True
        def retained_statement_lines(block):
            key = tuple(block['base_range']), tuple(block.get('retained_statements', ()))
            if key not in retained_statement_rows:
                start, end = key[0]
                _construct_charge(construct_work, end - start + 1 + len(key[1]))
                digests = set(key[1]); required = []
                for line in range(start, end + 1):
                    rows = inventories[0][3].get(line, [])
                    _construct_charge(construct_work, len(rows))
                    if line in before and any(row['digest'] in digests for row in rows):
                        required.append(line)
                retained_statement_rows[key] = required
            return retained_statement_rows[key]
        for tag, a, b, c, d, block, anchored_suffix in source_opcodes(
                old, new, function_scopes, before, head_construct_inventory, compatible_replacement,
                construct_work, inventories, replacement_candidates, line_operations=line_operations):
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
            elif tag == 'retain-obligation':
                line, target = block['base_line'], block['head_line']
                if line not in before:
                    continue
                if (line, target) in proved_eager_pairs:
                    retained[line] = target
                elif line not in anchored:
                    if (name=='src/core/security/policy.rs' and inventories is not None
                            and old[line-1]==new[target-1]
                            and old[line-1].strip()=='minimum_grade: SecurityGrade::Community,'
                            and (bs[name]['expansions'],hs[name]['expansions'])==([],[])):
                        sides=((old,inventories[0],base_spans,before,line),
                               (new,inventories[1],head_spans,after,target))
                        proof=retained_policy_default_record(name,sides,source_owner_indexes(),construct_work)
                        if proof is not None:
                            if any(n in anchored and anchored[n]!=t for n,t in proof['pairs']):
                                raise ValueError('Ambiguous policy default correspondence')
                            anchored.update(proof['pairs'])
                            obligation_receipts.append(proof)
                            continue
                    entry_source = None
                    entry_lines = (line,target)
                    if inventories is not None and old[line-1]==new[target-1]:
                        if old[line-1].strip()=='anyhow::ensure!(':
                            entry_source=ensure_entry_source
                        elif (name=='src/package_managers/aur/client.rs' and min(line,target)>3
                              and old[line-1].strip()=='&& files.len() < 10_000,'):
                            entry_source=ensure_entry_source
                            entry_lines=(line-3,target-3)
                        elif name=='src/package_managers/alpm_ops.rs' and old[line-1].strip()==_MAP_CAPACITY_LINE:
                            entry_source=map_capacity_entry_source
                        elif name == 'src/package_managers/alpm_ops.rs' and old[line - 1].strip() == _ALPM_UPDATE_RECORD_LINE:
                            entry_source = alpm_update_record_entry_source
                    if entry_source is not None and (bs[name]['expansions'],hs[name]['expansions'])==([],[]):
                        sides=((old,inventories[0],base_spans,before,entry_lines[0]),
                               (new,inventories[1],head_spans,after,entry_lines[1]))
                        proof=retained_observed_entry(name,sides,source_owner_indexes(),construct_work,entry_source)
                        if proof is not None and [line,target] in proof['pairs']:
                            if any(previous in anchored and anchored[previous] != current
                                   for previous, current in proof['pairs']):
                                raise ValueError('Ambiguous retained entry correspondence')
                            anchored.update(proof['pairs'])
                            obligation_receipts.append(proof)
                            continue
                    scopes = [prefix for prefix, group in base_groups.items()
                              if prefix in head_groups
                              and group[0] <= line <= group[1]
                              and head_groups[prefix][0] <= target <= head_groups[prefix][1]]
                    if (len(scopes) == 1 and after.get(target, 0) > 0
                            and old[line - 1] == new[target - 1]):
                        proof = None
                        if inventories is not None and (bs[name]['expansions'],hs[name]['expansions'])==([],[]):
                            prefix = scopes[0]
                            sides = ((old,inventories[0],base_groups[prefix],before,line),
                                     (new,inventories[1],head_groups[prefix],after,target))
                            if _MATCH_PARAMETER_BINDING.fullmatch(old[line-1]) or _MATCH_DEFAULT_REFUSAL.fullmatch(old[line-1]):
                                proof = retained_match_selector(name,sides,source_owner_indexes(),construct_work)
                            elif name=='src/cli/tool.rs' and _FIXTURE_WRITE_START.fullmatch(old[line-1]):
                                proof = retained_fixture_script_write(name,sides,source_owner_indexes(),construct_work)
                        if proof is not None:
                            if any(oldline in anchored and anchored[oldline]!=newline for oldline,newline in proof['pairs']):
                                raise ValueError('Ambiguous direct source correspondence')
                            anchored.update(proof['pairs'])
                            obligation_receipts.append(proof)
                            continue
                        kind = 'async' if re.search(r'\basync\s+fn\b', scopes[0]) else 'callback'
                        deferred_fragments[line] = DeferredSourceFragment(target, kind, scopes[0])
                        unresolved_fragments.append((line - 1, line, target - 1, target, [line]))
                    elif not retire_declaration(line,target):
                        raise ValueError(f'Unproved retained execution in replaced construct: '
                            f'{name}:{line} -> {target}; '
                            f'base_count={before.get(line)} head_count={after.get(target)}')
            elif tag == 'replace-construct':
                if (block.get('retained_statements') and not any(
                        start <= block['base_line'] <= end for start, end in proved_functions)
                        and any(line not in anchored and line not in deferred_fragments
                                for line in retained_statement_lines(block))):
                    raise ValueError('Ambiguous unchanged work in replaced compiler owner')
                replacement_receipts.append(dict(file=name, **block))
            # Replacement is not proven deletion. Its old counts stay in the
            # strict base ratios, and its new uncovered mappings are refused.
        for prefix, states in record_states.items():
            width = max((len(row) for side in states for row in side), default=0)
            _construct_charge(construct_work, (len(states[0]) * len(states[1]) + 1) * max(width, 1))
            if compiled_hit_state_matching(*states) is None:
                raise ValueError('Record completion lost compiled-copy coverage')
        _construct_charge(construct_work, len(replacement_receipts))
        replaced_functions = {tuple(receipt['base_range']) for receipt in replacement_receipts
                              if receipt['file'] == name and receipt['base_construct'] == 'fn'}
        for start, end in replaced_functions:
            _construct_charge(construct_work, end - start + 1)
            gone.difference_update(range(start, end + 1))
        for receipt in residual_receipts:
            protected=receipt.get('preserved_base_mapped',())
            _construct_charge(construct_work,len(protected))
            gone.difference_update(protected)
        callback_scopes = []
        callback_functions = {fragment.function_prefix for fragment in deferred_fragments.values()
                              if fragment.kind == 'callback'}
        if unresolved_fragments and inventories is not None and all(value is not None for value in inventories):
            _construct_charge(construct_work, len(base_groups) * (len(unresolved_fragments) + 1))
            for prefix, group in base_groups.items():
                current = head_groups.get(prefix)
                if current is None or prefix not in callback_functions:
                    continue
                if not any(group[0] <= a + 1 <= b <= group[1]
                           and current[0] <= c + 1 <= d <= current[1]
                           for a, b, c, d, _ in unresolved_fragments):
                    continue
                ranges = []
                for inventory, bounds in zip(inventories, (group, current)):
                    code = inventory[0]; _construct_charge(construct_work, len(inventory[1]))
                    ranges.append([(code.position(code.starts[row['opening']])[0],
                                    code.position(code.ends[row['end']])[0])
                        for row in inventory[1] if row['opening'] is not None
                        and code.words[row['opening'] - 1] == '||'
                        and code.parents[row['opening']] is not None
                        and code.words[code.parents[row['opening']]] == '('
                        and bounds[0] < code.position(code.starts[row['opening']])[0]
                            <= code.position(code.ends[row['end']])[0] < bounds[1]])
                if all(ranges):
                    callback_scopes.append((group, current, *ranges))
        if callback_scopes:
            proposals = []; seen_pairs = set()
            _construct_charge(construct_work, len(unresolved_fragments) * (len(callback_scopes) + 1)
                              + sum(len(pending) for _, _, _, _, pending in unresolved_fragments))
            for a, b, c, d, pending in unresolved_fragments:
                if any(bg[0] <= a + 1 <= b <= bg[1] and hg[0] <= c + 1 <= d <= hg[1]
                       for bg, hg, _, _ in callback_scopes):
                    for line in pending:
                        target = c + line - a
                        if (line, target) not in seen_pairs:
                            proposals.append((line - 1, line, target - 1, target, [line]))
                            seen_pairs.add((line, target))
                else:
                    proposals.append((a, b, c, d, pending))
            _construct_charge(construct_work, len(retained) * (len(callback_scopes) + 1))
            for line, target in retained.items():
                if (line in anchored or line not in before or after.get(target, 0) <= 0
                        or old[line - 1] != new[target - 1] or (line, target) in seen_pairs):
                    continue
                if any(bg[0] <= line <= bg[1] and hg[0] <= target <= hg[1]
                       and any(first <= line <= last for first, last in left)
                       and any(first <= target <= last for first, last in right)
                       for bg, hg, left, right in callback_scopes):
                    proposals.append((line - 1, line, target - 1, target, [line]))
                    seen_pairs.add((line, target))
            unresolved_fragments = proposals
        if unresolved_fragments:
            source_owner_indexes()
        if unresolved_fragments and inventories is not None:
            _construct_charge(construct_work, sum(len(pending) for *_, pending in unresolved_fragments))
            probes = {line for *_, pending in unresolved_fragments for line in pending
                      if re.fullmatch(r'\s*&(?:mut\s+)?self,\s*', old[line-1])}
            if probes:
                proofs = retired_async_methods(name, probes, old, inventories[0], before, *owner_indexes,
                    head_construct_inventory(), head_fn_names, construct_work)
                retired = set()
                for proof in proofs:
                    first, last = proof['base_range']
                    _construct_charge(construct_work, last-first+1)
                    lines = set(range(first,last+1))
                    if lines.intersection(anchored) or lines.intersection(deferred_fragments):
                        continue
                    retired.update(lines)
                    retirement_receipts.append(proof)
                if retired:
                    gone.difference_update(retired)
                    for line in retired:
                        retained.pop(line, None)
                    unresolved_fragments = [(*bounds, active) for *bounds, pending in unresolved_fragments
                        if (active := [line for line in pending if line not in retired])]
        if unresolved_fragments and inventories is not None:
            probes = set()
            for a, _, c, _, pending in unresolved_fragments:
                _construct_charge(construct_work,len(pending))
                probes.update((line,c+line-a) for line in pending if line not in deferred_fragments
                              and _DECLARATION_PARAMETER.fullmatch(old[line-1]) is not None)
            checked = Counter(line for line,_ in probes)
            for line,target in sorted(probes):
                if checked[line] == 1:
                    retire_declaration(line,target)
            if declaration_roles:
                targets = {}
                for a, _, c, _, pending in unresolved_fragments:
                    _construct_charge(construct_work,len(pending))
                    for line in pending:
                        targets.setdefault(line,set()).add(c+line-a)
                for line, choices in targets.items():
                    if (len(choices) != 1 or line in anchored or line in deferred_fragments
                            or line in neutral_declarations):
                        continue
                    target, = choices
                    if (line,target) in declaration_roles:
                        retire_declaration(line,target)
        if neutral_declarations:
            _construct_charge(construct_work,len(neutral_declarations))
            for first,last in {tuple(proof['base_range']) for _,proof in neutral_declarations.values()}:
                _construct_charge(construct_work,last-first+1)
                gone.difference_update(range(first,last+1))
            for line in neutral_declarations:
                retained.pop(line,None)
            unresolved_fragments = [(*bounds, active) for *bounds, pending in unresolved_fragments
                if (active := [line for line in pending if line not in neutral_declarations])]
        if unresolved_fragments and inventories is not None:
            _construct_charge(construct_work,len(unresolved_fragments))
            retired=set()
            for fragment in unresolved_fragments:
                a,b,c,d,pending=fragment
                if (b-a!=3 or d-c!=3 or any(line.strip()!='}' for line in old[a:b]+new[c:d])
                        or any(line in deferred_fragments for line in pending)):
                    continue
                proof=retired_async_test_constructor_delimiters(name,fragment,(old,new),(before,after),inventories,
                    source_owner_indexes(),construct_work,(bs[name]['expansions'],hs[name]['expansions']))
                if proof is None:continue
                for line,target in proof['pairs']:
                    if line in retained and retained[line]!=target:
                        raise ValueError('Ambiguous async constructor completion')
                    retained[line]=target;retired.add(line)
                retired.update(proof['retired_lines'])
                first,last=proof['base_range'];gone.difference_update(range(first,last+1))
                retired_constructor_receipts.append(proof)
            if retired:
                unresolved_fragments=[(*bounds,active) for *bounds,pending in unresolved_fragments
                    if (active:=[line for line in pending if line not in retired])]
        if unresolved_fragments and inventories is not None:
            _construct_charge(construct_work,len(unresolved_fragments))
            assertions = {(b,d) for a,b,c,d,pending in unresolved_fragments if a+1==b and c+1==d and tuple(pending)==(b,)
                          and old[a]==new[c] and old[a].strip()==');' and d not in after
                          and b not in anchored and b not in deferred_fragments and before.get(b,0)>0}
            if assertions:
                candidates = {line:set() for line,_ in assertions}
                for a,_,c,_,pending in unresolved_fragments:
                    _construct_charge(construct_work,len(pending))
                    for line in pending:
                        if line in candidates:
                            candidates[line].add(c+line-a)
                sides = ((old,inventories[0],base_spans,before,bs[name]['expansions']),
                         (new,inventories[1],head_spans,after,hs[name]['expansions']))
                retired = set()
                for line,target in sorted(assertions):
                    if candidates[line] != {target}:
                        continue
                    proof = retired_assertion_delimiter(name,line,target,sides,source_owner_indexes(),
                                                       head_construct_inventory(),construct_work)
                    if proof is not None:
                        first,last = proof['base_range']; _construct_charge(construct_work,last-first+1)
                        gone.difference_update(range(first,last+1))
                        retained.pop(line,None); retired.add(line)
                        retired_assertion_receipts.append(proof)
                if retired:
                    unresolved_fragments = [(*bounds,active) for *bounds,pending in unresolved_fragments
                        if (active := [line for line in pending if line not in retired])]
        async_obligations = [(line, fragment.target) for line, fragment in deferred_fragments.items()
                             if fragment.kind == 'async']
        _construct_charge(construct_work, len(deferred_fragments))
        positive, receipts = positive_source_fragments(
            name, old, new, before, after, bf, hf, base_files, head_files, unresolved_fragments,
            construct_work, inventories, grouped, callback_functions, owner_indexes,
            tuple(zip(*async_obligations)) if async_obligations else ((), ()),
            macro_expansions=(bs[name]['expansions'],hs[name]['expansions']))
        proof_pairs = {
            'async': {tuple(pair) for receipt in receipts
                      if 'async_copies' in receipt and 'async_fragment_regions' in receipt
                      for pair in receipt['pairs']},
            'callback': {tuple(pair) for receipt in receipts
                         for fragment in receipt.get('callback_fragments', []) for pair in fragment['pairs']},
        }
        for line, fragment in deferred_fragments.items():
            if (line, fragment.target) not in proof_pairs[fragment.kind]:
                raise ValueError('Unproved retained execution: complete callback/phase evidence required '
                                 f'at {name}:{line} -> {fragment.target} ({fragment.kind})')
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
        boolean = ([witness for witness in eager_witnesses
                    if all(final_pairs.get(line) == target for line, target in witness['pairs'])]
                   if eager_witnesses is not None else
                   retained_boolean_argument_paint(name, old, new, before, after, bf, hf, base_files, head_files,
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
                raise ValueError(f'Retained covered line lost coverage or mapping: '
                    f'{name}:{oldline} -> {newline}; '
                    f'base_count={before.get(oldline)} head_count={after.get(newline)}')
        retained.update(anchored)
        if len(set(retained.values())) != len(retained):
            raise ValueError("Ambiguous retained source correspondence")
        for oldline, newline in retained.items():
            if before.get(oldline, 0) > 0 and after.get(newline, 0) == 0 and (oldline, newline) not in painted:
                raise ValueError(f'Retained covered line lost coverage or mapping: '
                    f'{name}:{oldline} -> {newline}; '
                    f'base_count={before.get(oldline)} head_count={after.get(newline)}')
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
    if replacement_receipts:
        paint_receipt['source_replacements'] = replacement_receipts
    if retirement_receipts:
        paint_receipt['retired_async_methods'] = retirement_receipts
    if retired_declaration_receipts:
        paint_receipt['retired_declarations'] = retired_declaration_receipts
    if retired_constructor_receipts:
        paint_receipt['retired_async_test_constructor_delimiters']=retired_constructor_receipts
    if retired_assertion_receipts:
        paint_receipt['retired_assertion_delimiters'] = retired_assertion_receipts
    paint_receipt.update(specialization_receipts)
    if construct_receipts:
        paint_receipt['retained_constructs'] = construct_receipts
    if obligation_receipts:
        paint_receipt['retained_replacement_obligations'] = obligation_receipts
    if completion_receipts:
        paint_receipt['retained_function_completions'] = completion_receipts
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

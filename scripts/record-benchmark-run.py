#!/usr/bin/env python3
"""Archive a hyperfine run into benchmarks/records/ and refresh latest pointers.

Scratch JSON lives in benchmark_results/ (gitignored). This script copies the
full hyperfine exports plus host/git metadata into a timestamped record that
is meant to be committed.

Does not overwrite benchmarks/summary.json unless --update-gate is passed.
That file is the reviewed regression baseline and automated runs must not move it.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

SCENARIOS = ("search", "info", "status", "explicit", "update", "install", "remove")


def repo_root() -> Path:
    here = Path(__file__).resolve().parent.parent
    if (here / "Cargo.toml").is_file():
        return here
    return Path.cwd()


def git_capture(root: Path) -> dict:
    def run(args: list[str]) -> str:
        try:
            return subprocess.check_output(args, cwd=root, text=True).strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return ""

    status = run(["git", "status", "--porcelain"])
    return {
        "commit": run(["git", "rev-parse", "HEAD"]),
        "commit_short": run(["git", "rev-parse", "--short", "HEAD"]),
        "describe": run(["git", "describe", "--always", "--dirty"]),
        "branch": run(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "dirty": bool(status),
        "dirty_files": [line[3:] for line in status.splitlines() if line.strip()],
    }


def host_capture() -> dict:
    cpu = ""
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    mem_kib = 0
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2:
                    mem_kib = int(parts[1])
                break
    uname = os.uname()
    return {
        "sysname": uname.sysname,
        "release": uname.release,
        "machine": uname.machine,
        "cpu": cpu,
        "ram_gib": round(mem_kib / (1024 * 1024), 1) if mem_kib else None,
    }


def load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    with path.open() as handle:
        return json.load(handle)


def find_result(results: list[dict], name: str) -> dict | None:
    for result in results:
        if result.get("command") == name:
            return result
    return None


# benchmark-hyperfine.sh labels the timed OMG driver "OMG"; older records used
# "OMG (Daemon)". Accept both instead of hardcoding one.
DAEMON_LABELS = ("OMG", "OMG (Daemon)")


def daemon_result(payload: dict[str, object]) -> dict[str, object] | None:
    """Resolve the OMG driver under its current or legacy hyperfine label."""
    results = cast(dict[str, object], payload).get("results") or []
    for label in DAEMON_LABELS:
        found = find_result(cast(list[dict], results), label)
        if found:
            return found
    return None


def native_result(payload: dict[str, object]) -> dict[str, object] | None:
    """Resolve the native comparison run (pacman, apt-cache, dnf, ...)."""
    for result in cast(
        list[dict], cast(dict[str, object], payload).get("results") or []
    ):
        if result.get("command") not in DAEMON_LABELS:
            return result
    return None


def milliseconds(seconds: float) -> float:
    """Convert units without allowing a finite duration to become infinity."""
    return finite_duration(seconds * 1000.0)


def ms(result: dict[str, object], key: str = "mean") -> float:
    return milliseconds(finite_duration(result[key]))


def summarize_scenario(data: object) -> list[dict[str, object]]:
    """Render admitted samples without inventing labels or a desired outcome."""
    if not isinstance(data, dict):
        raise TypeError("scenario must be an object")
    results = cast(dict[str, object], data).get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("no measurements")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for result in cast(list[object], results):
        measurement = parse_measurement(result)
        if measurement.command in seen:
            raise ValueError(f"duplicate command label {measurement.command}")
        seen.add(measurement.command)
        if any(code != 0 for code in measurement.exit_codes):
            raise ValueError(f"{measurement.command}: non-zero exit in timed runs")
        samples = measurement.samples
        rows.append(
            {
                "command": measurement.command,
                "mean_ms": round(milliseconds(statistics.mean(samples)), 3),
                "stddev_ms": (
                    round(milliseconds(statistics.stdev(samples)), 3)
                    if len(samples) > 1
                    else None
                ),
                "median_ms": round(milliseconds(statistics.median(samples)), 3),
                "min_ms": round(milliseconds(min(samples)), 3),
                "max_ms": round(milliseconds(max(samples)), 3),
                "user_ms": round(milliseconds(measurement.user_seconds), 3),
                "system_ms": round(milliseconds(measurement.system_seconds), 3),
                "runs": len(samples),
                "nonzero_exits": 0,
            }
        )
    return rows


@dataclass(frozen=True, slots=True)
class Measurement:
    command: str
    samples: tuple[float, ...]
    exit_codes: tuple[int, ...]
    user_seconds: float
    system_seconds: float


def finite_duration(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("duration must be a number")
    try:
        duration = float(value)
    except OverflowError as error:
        raise ValueError("duration is outside the finite range") from error
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("duration must be finite and nonnegative")
    return duration


def parse_measurement(value: object) -> Measurement:
    """Admit samples and their receipts, never a desired performance outcome."""
    if not isinstance(value, dict):
        raise TypeError("measurement must be an object")
    record = cast(dict[str, object], value)
    command = record.get("command")
    raw_samples = record.get("times")
    raw_codes = record.get("exit_codes")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("measurement has no command label")
    if not isinstance(raw_samples, list) or not raw_samples:
        raise ValueError(f"{command}: no timed samples")
    if not isinstance(raw_codes, list) or len(raw_codes) != len(raw_samples):
        raise ValueError(f"{command}: each sample needs an exit receipt")
    samples = tuple(finite_duration(item) for item in cast(list[object], raw_samples))
    codes: list[int] = []
    for code in cast(list[object], raw_codes):
        if isinstance(code, bool) or not isinstance(code, int):
            raise TypeError(f"{command}: exit receipt must be an integer")
        codes.append(code)
    expected = {
        "mean": statistics.mean(samples),
        "median": statistics.median(samples),
        "min": min(samples),
        "max": max(samples),
    }
    if len(samples) > 1:
        expected["stddev"] = statistics.stdev(samples)
    elif record.get("stddev") is not None:
        raise ValueError(f"{command}: one sample cannot establish standard deviation")
    for field, actual in expected.items():
        reported = finite_duration(record.get(field))
        if not math.isclose(reported, actual, rel_tol=1e-8, abs_tol=1e-12):
            raise ValueError(f"{command}: {field} does not match raw samples")
    return Measurement(
        command,
        samples,
        tuple(codes),
        finite_duration(record.get("user")),
        finite_duration(record.get("system")),
    )


def validate_results(source: Path, required: tuple[str, ...] = ()) -> list[str]:
    """Check samples and exits without requiring a preferred performance outcome."""
    errors: list[str] = []
    present = [name for name in SCENARIOS if (source / f"{name}.json").is_file()]
    if not present:
        errors.append(f"no hyperfine JSON in {source}")
        return errors

    expected = required or (() if present == ["update"] else ("search",))
    for name in expected:
        if name not in present:
            errors.append(f"{name}.json missing in {source}")

    for name in present:
        try:
            with (source / f"{name}.json").open("rb") as handle:
                content = handle.read(1048577)
            if len(content) > 1048576:
                errors.append(f"{name}: measurement file exceeds 1 MiB")
                continue
            payload: object = json.loads(content)
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"{name}: cannot read measurements: {error}")
            continue
        if not isinstance(payload, dict):
            errors.append(f"{name}: expected an object")
            continue
        results = cast(dict[str, object], payload).get("results")
        if not isinstance(results, list) or not results:
            errors.append(f"{name}: no measurements")
            continue
        seen: set[str] = set()
        for result in cast(list[object], results):
            try:
                measurement = parse_measurement(result)
            except (TypeError, ValueError) as error:
                errors.append(f"{name}: {error}")
                continue
            if measurement.command in seen:
                errors.append(f"{name}: duplicate command label {measurement.command}")
            seen.add(measurement.command)
            if any(code != 0 for code in measurement.exit_codes):
                errors.append(
                    f"{name}/{measurement.command}: non-zero exit in timed runs"
                )
    return errors


def render_latest_md(meta: dict, source: Path) -> str:
    git = meta["git"]
    host = meta["host"]
    lines = [
        "# OMG benchmark — latest recorded run",
        "",
        f"- **Record:** [`{meta['id']}`](records/{meta['id']}/)",
        f"- **When:** {meta['timestamp']}",
        f"- **Commit:** `{git.get('commit', '')}` (`{git.get('describe', '')}`)",
        f"- **Dirty tree:** {'yes' if git.get('dirty') else 'no'}",
        (
            f"- **Host:** {host.get('cpu') or host.get('machine')}, "
            f"Linux {host.get('release')}, {host.get('ram_gib')} GiB RAM"
        ),
        f"- **Hyperfine:** {meta.get('hyperfine', 'unknown')}",
        (
            f"- **Flags:** `--shell=none --output=pipe`, warmup={meta.get('warmup')}, "
            f"min-runs={meta.get('min_runs')}, max-runs={meta.get('max_runs')}"
        ),
        "",
        "Scratch output is gitignored (`benchmark_results/`). Canonical copies of the",
        "full hyperfine JSON (every run, every exit code) live under `benchmarks/records/`.",
        "",
        "## Preflight",
        "",
        "Each timed command was executed once before hyperfine. Search and info had to",
        "print `firefox`. Explicit count had to be a positive integer. Status had to",
        "succeed. Runs with a non-zero exit are rejected.",
        "",
    ]
    preflight = meta.get("preflight") or {}
    if preflight:
        lines.append("| Check | Evidence |")
        lines.append("|---|---|")
        for key, value in preflight.items():
            if isinstance(value, dict) and "bytes" in value:
                shown = f"{value['bytes']} bytes, {value.get('lines', 0)} lines"
            else:
                shown = value
            lines.append(f"| `{key}` | {shown} |")
        lines.append("")

    lines.extend(["## Results", ""])
    for name in SCENARIOS:
        md_path = source / f"{name}.md"
        json_path = source / f"{name}.json"
        if not md_path.is_file() and not json_path.is_file():
            continue
        lines.append(f"### {name}")
        lines.append("")
        if md_path.is_file():
            lines.append(md_path.read_text().rstrip())
            lines.append("")
        payload = load_json(json_path)
        if payload:
            daemon = daemon_result(payload)
            native = native_result(payload)
            if daemon and native and ms(daemon) > 0:
                speedup = ms(native) / ms(daemon)
                lines.append(
                    f"Daemon mean **{ms(daemon):.1f} ms** vs "
                    f"{native['command']} **{ms(native):.1f} ms** "
                    f"({speedup:.1f}×). Median {ms(daemon, 'median'):.1f} ms "
                    f"({len(cast(list[object], daemon.get('times') or []))} runs)."
                )
                lines.append("")

    lines.extend(
        [
            "## Reproduce",
            "",
            "```bash",
            "./benchmark-hyperfine.sh",
            "```",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        default="benchmark_results",
        help="Directory containing hyperfine JSON/MD (default: benchmark_results)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--validate-only",
        action="store_true",
        help="Check measurements without creating records or changing metadata",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=SCENARIOS,
        default=[],
        help="Require this scenario (repeatable); useful for scoped guest measurements",
    )
    mode.add_argument(
        "--update-gate",
        action="store_true",
        help="Also write benchmarks/summary.json from this reviewed run",
    )
    parser.add_argument(
        "--id", default="", help="Record id (default: UTC timestamp + short sha)"
    )
    parser.add_argument("--warmup", type=int, default=None)
    parser.add_argument("--min-runs", type=int, default=None)
    parser.add_argument("--max-runs", type=int, default=None)
    args = parser.parse_args()

    root = repo_root()
    source = Path(args.source)
    if not source.is_absolute():
        source = (root / source).resolve()
    if not source.is_dir():
        print(f"No hyperfine output directory at {source}", file=sys.stderr)
        return 1

    errors = validate_results(source, tuple(args.scenario))
    if errors:
        print(
            "Benchmark record rejected — invalid or failed measurements:",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    if args.validate_only:
        print("Measurement validation passed (not a workload-equivalence assertion)")
        return 0

    git = git_capture(root)
    host = host_capture()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    record_id = args.id or f"{stamp}-{git.get('commit_short') or 'nogit'}"
    records_dir = root / "benchmarks" / "records" / record_id
    records_dir.mkdir(parents=True, exist_ok=True)

    copied = []
    for path in sorted(source.glob("*")):
        if path.suffix in {".json", ".md"} and path.is_file():
            shutil.copy2(path, records_dir / path.name)
            copied.append(path.name)

    preflight = load_json(source / "preflight.json") or {}
    try:
        hyperfine = subprocess.check_output(
            ["hyperfine", "--version"], text=True
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        hyperfine = "unknown"

    scenarios = {}
    for name in SCENARIOS:
        payload = load_json(source / f"{name}.json")
        if payload:
            scenarios[name] = summarize_scenario(payload)

    search = load_json(source / "search.json") or {}
    daemon = daemon_result(search)
    pacman = native_result(search)
    status = load_json(source / "status.json") or {}
    status_daemon = daemon_result(status)
    search_ms = round(ms(daemon), 1) if daemon else None
    status_ms = round(ms(status_daemon), 1) if status_daemon else None
    speedup = None
    if daemon and pacman and ms(daemon) > 0:
        speedup = f"{ms(pacman) / ms(daemon):.1f}x"

    meta = {
        "id": record_id,
        "timestamp": timestamp,
        "git": git,
        "host": host,
        "hyperfine": hyperfine,
        "warmup": args.warmup,
        "min_runs": args.min_runs,
        "max_runs": args.max_runs,
        "source_files": copied,
        "preflight": preflight,
        "scenarios": scenarios,
        "headline": {
            "search_mean_ms": search_ms,
            "search_median_ms": round(ms(daemon, "median"), 1) if daemon else None,
            "pacman_search_mean_ms": round(ms(pacman), 1) if pacman else None,
            "status_mean_ms": status_ms,
            "speedup": speedup,
        },
    }
    (records_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    latest = root / "benchmarks" / "latest.md"
    latest.write_text(render_latest_md(meta, source))

    if search_ms is not None:
        badge = {
            "schemaVersion": 1,
            "label": "search",
            "message": (
                f"{search_ms}ms ({speedup} faster)" if speedup else f"{search_ms}ms"
            ),
            "color": "brightgreen",
        }
        (root / "benchmarks" / "badge.json").write_text(
            json.dumps(badge, indent=2) + "\n"
        )

    if args.update_gate:
        if search_ms is None or status_ms is None or not speedup:
            print(
                "Cannot update gate: missing daemon search, daemon status, or pacman result",
                file=sys.stderr,
            )
            return 1
        summary = {
            "timestamp": timestamp,
            "search_ms": search_ms,
            "status_ms": status_ms,
            "speedup": speedup,
            "commit": git.get("commit", ""),
            "record": record_id,
        }
        (root / "benchmarks" / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n"
        )

    index_path = root / "benchmarks" / "records" / "INDEX.md"
    index_lines = [
        "# Benchmark records",
        "",
        "Newest first. Each folder is a full hyperfine export plus `meta.json`.",
        "",
        "| Record | Commit | Search mean | vs pacman | Host |",
        "|---|---|---:|---|---|",
    ]
    rows = []
    for entry in sorted((root / "benchmarks" / "records").iterdir(), reverse=True):
        meta_path = entry / "meta.json"
        if not meta_path.is_file():
            continue
        item = json.loads(meta_path.read_text())
        headline = item.get("headline") or {}
        git_info = item.get("git") or {}
        host_info = item.get("host") or {}
        rows.append(
            f"| [`{entry.name}`]({entry.name}/) | `{git_info.get('commit_short', '')}` | "
            f"{headline.get('search_mean_ms', '')} ms | {headline.get('speedup', '')} | "
            f"{(host_info.get('cpu') or '')[:40]} |"
        )
    index_path.write_text("\n".join(index_lines + rows) + "\n")

    print(f"Recorded {record_id}")
    print(f"  search mean: {search_ms} ms  speedup: {speedup}")
    print(f"  files: {records_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
